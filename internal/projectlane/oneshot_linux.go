//go:build linux

package projectlane

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

// The operator's standing decision per project (ticket 1686): the projects the operator put on the one-shot route. One reader and
// one writer, here, for the lane, `list`, `add` and `remove`. The store is the file `one-shot-projects.json` in the operator's
// established run directory, <home>/.config/safe/run:
//
//   - the chain of directories below the home is opened one name at a time through held descriptors, never following a link; each
//     must belong to the user and not be writable by group or others;
//   - the file is opened relative to the held run directory without following a link; it is validated and read on THE SAME open
//     descriptor (a regular file of the user, not writable by group or others, no set-id or sticky bit);
//   - a writer holds an exclusive lock over read, change and rename, so two writers cannot undo each other, and a change is
//     reported only once it is committed.
//
// An entry is the physical path of a project directory (the bytes, as the lane has them) with its device and inode. A decision can
// only WEAKEN the route, so a store that cannot be trusted is "no project pinned", never an error that would raise a question.
const (
	OneShotStoreFile = "one-shot-projects.json"
	oneShotLockFile  = "one-shot-projects.lock"
	oneShotLimit     = 1 << 20
)

// OneShotStore is the store below one home directory (the anchor every operator store hangs from).
type OneShotStore struct{ Home string }

// OneShotEntry is one pinned project.
type OneShotEntry struct {
	Added string `json:"added"`
	Dev   uint64 `json:"dev"`
	Inode uint64 `json:"inode"`
}

type oneShotDocument struct {
	Projects map[string]OneShotEntry `json:"projects"`
}

// OneShotPlan is a directory as the operator is shown it: what a commit will verify again.
type OneShotPlan struct {
	Path  string `json:"path"`
	Dev   uint64 `json:"dev"`
	Inode uint64 `json:"inode"`
}

// OneShotRow is one line of a listing.
type OneShotRow struct {
	Path  string `json:"path"`
	Added string `json:"added"`
	Dev   uint64 `json:"dev"`
	Inode uint64 `json:"inode"`
	State string `json:"state"`
}

// The three states of a pin as the lane reads it.
const (
	OneShotPinned   = 0
	OneShotNotPin   = 1
	OneShotReplaced = 2
)

var (
	oneShotEUID = os.Geteuid
	// afterChain, when set (tests), runs after the directory chain is held and before the file is read.
	afterChain func()
	// afterRead, when set (tests), runs inside the writer's lock after the document is read.
	afterRead func()
)

func oneShotOwned(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == oneShotEUID()
}

func oneShotCheckDir(handle *dirHandle, what string) error {
	info, err := handle.f.Stat()
	if err != nil {
		return err
	}
	if !oneShotOwned(info) {
		return fmt.Errorf("%s is not owned by this user", what)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is writable by group or others", what)
	}
	return nil
}

// openRun opens the run directory through the verified chain. The home itself is the anchor: it is resolved once, as every other
// store's root is, and everything below it must be a plain directory of the user.
func (s OneShotStore) openRun(create bool) (*dirHandle, error) {
	if !strings.HasPrefix(s.Home, "/") {
		return nil, errors.New("the home directory is not absolute")
	}
	home, err := filepath.EvalSymlinks(s.Home)
	if err != nil {
		return nil, err
	}
	current, err := openDirPath(home)
	if err != nil {
		return nil, err
	}
	if err := oneShotCheckDir(current, "the home directory"); err != nil {
		current.Close()
		return nil, err
	}
	for _, name := range []string{".config", "safe", "run"} {
		next, err := current.openDirNoFollow(name)
		if err != nil && create && errors.Is(err, os.ErrNotExist) {
			if merr := current.mkdir(name, 0o700); merr != nil && !errors.Is(merr, os.ErrExist) {
				current.Close()
				return nil, merr
			}
			next, err = current.openDirNoFollow(name)
		}
		current.Close()
		if err != nil {
			return nil, err
		}
		if err := oneShotCheckDir(next, "the directory "+name); err != nil {
			next.Close()
			return nil, err
		}
		current = next
	}
	return current, nil
}

// readStore reads and validates the store file on one open descriptor. A missing file is an empty document.
func readOneShotFile(run *dirHandle) (oneShotDocument, bool, error) {
	empty := oneShotDocument{Projects: map[string]OneShotEntry{}}
	fd, err := syscall.Openat(run.fd(), OneShotStoreFile, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return empty, false, nil
		}
		return empty, false, &os.PathError{Op: "openat", Path: OneShotStoreFile, Err: err}
	}
	file := os.NewFile(uintptr(fd), OneShotStoreFile)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return empty, false, err
	}
	if !info.Mode().IsRegular() {
		return empty, false, errors.New("the store is not a regular file")
	}
	if !oneShotOwned(info) {
		return empty, false, errors.New("the store is not owned by this user")
	}
	if info.Mode().Perm()&0o022 != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return empty, false, errors.New("the store is writable by group or others")
	}
	if info.Size() > oneShotLimit {
		return empty, false, errors.New("the store is too large")
	}
	raw, err := io.ReadAll(io.LimitReader(file, oneShotLimit+1))
	if err != nil {
		return empty, false, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var doc oneShotDocument
	if err := decoder.Decode(&doc); err != nil || decoder.More() {
		return empty, false, errors.New("the store is not a valid document")
	}
	if doc.Projects == nil {
		doc.Projects = map[string]OneShotEntry{}
	}
	return doc, true, nil
}

func (s OneShotStore) read() (oneShotDocument, error) {
	run, err := s.openRun(false)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return oneShotDocument{Projects: map[string]OneShotEntry{}}, nil
		}
		return oneShotDocument{}, err
	}
	defer run.Close()
	if afterChain != nil {
		afterChain()
	}
	doc, _, err := readOneShotFile(run)
	return doc, err
}

func identityOf(path string) (OneShotPlan, error) {
	var stat syscall.Stat_t
	if err := syscall.Lstat(path, &stat); err != nil {
		return OneShotPlan{}, err
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return OneShotPlan{}, fmt.Errorf("%s is not a directory", path)
	}
	return OneShotPlan{Path: path, Dev: uint64(stat.Dev), Inode: uint64(stat.Ino)}, nil
}

// Check says whether the physical path of a project directory is pinned: pinned and honoured, not pinned (anything that cannot
// be trusted included), or pinned but the directory was replaced.
func (s OneShotStore) Check(project string) int {
	doc, err := s.read()
	if err != nil {
		return OneShotNotPin
	}
	entry, ok := doc.Projects[project]
	if !ok {
		return OneShotNotPin
	}
	now, err := identityOf(project)
	if err != nil || now.Dev != entry.Dev || now.Inode != entry.Inode {
		return OneShotReplaced
	}
	return OneShotPinned
}

// List reads the whole store for a listing. A store that cannot be trusted is an error the listing reports (and nothing is pinned).
func (s OneShotStore) List() ([]OneShotRow, error) {
	doc, err := s.read()
	if err != nil {
		return nil, err
	}
	rows := make([]OneShotRow, 0, len(doc.Projects))
	for path, entry := range doc.Projects {
		row := OneShotRow{Path: path, Added: entry.Added, Dev: entry.Dev, Inode: entry.Inode, State: "honoured"}
		if now, err := identityOf(path); errors.Is(err, os.ErrNotExist) {
			row.State = "directory gone"
		} else if err != nil || now.Dev != entry.Dev || now.Inode != entry.Inode {
			row.State = "not honoured (directory replaced)"
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Path < rows[j].Path })
	return rows, nil
}

// Resolve gives the physical path and identity of each directory argument, as the operator will be shown them. needManifest
// requires a regular package.json in the directory (only an npm project goes on the route).
func Resolve(dirs []string, needManifest bool) ([]OneShotPlan, error) {
	plans := make([]OneShotPlan, 0, len(dirs))
	for _, dir := range dirs {
		abs := dir
		if !filepath.IsAbs(abs) {
			cwd, err := os.Getwd()
			if err != nil {
				return nil, err
			}
			abs = filepath.Join(cwd, abs)
		}
		physical, err := filepath.EvalSymlinks(abs)
		if err != nil {
			return nil, fmt.Errorf("cannot read the directory %q: %w", dir, err)
		}
		if err := oneShotPathOK(physical); err != nil {
			return nil, err
		}
		plan, err := identityOf(physical)
		if err != nil {
			return nil, err
		}
		if needManifest {
			info, err := os.Lstat(filepath.Join(physical, "package.json"))
			if err != nil || !info.Mode().IsRegular() {
				return nil, fmt.Errorf("no package.json in %q: only an npm project can be put on the one-shot route", physical)
			}
		}
		plans = append(plans, plan)
	}
	return plans, nil
}

func oneShotPathOK(path string) error {
	if !utf8.ValidString(path) {
		return fmt.Errorf("the path %q is not valid UTF-8, so it cannot be recorded exactly", path)
	}
	if strings.ContainsRune(path, '\n') {
		return fmt.Errorf("the path %q contains a newline: the lane cannot capture such a path exactly, so it is never pinned", path)
	}
	return nil
}

// lockedChange runs a read-modify-write of the store under an exclusive lock and renames the result into place. The new document
// is produced by change from the document read on the same descriptor; nothing is reported by this function before the rename.
func (s OneShotStore) lockedChange(change func(oneShotDocument) (oneShotDocument, error)) error {
	run, err := s.openRun(true)
	if err != nil {
		return err
	}
	defer run.Close()
	lockFD, err := syscall.Openat(run.fd(), oneShotLockFile, syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return &os.PathError{Op: "openat", Path: oneShotLockFile, Err: err}
	}
	lock := os.NewFile(uintptr(lockFD), oneShotLockFile)
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	doc, _, err := readOneShotFile(run)
	if err != nil {
		return fmt.Errorf("the store is not the operator's own (%w): fix or remove it first", err)
	}
	if afterRead != nil {
		afterRead()
	}
	next, err := change(doc)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	name, err := randomName()
	if err != nil {
		return err
	}
	tmp := OneShotStoreFile + "." + name
	if _, err := run.createExclusive(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := renameat2(run, tmp, run, OneShotStoreFile, 0); err != nil {
		_ = run.remove(tmp)
		return err
	}
	if err := run.f.Sync(); err != nil {
		return err
	}
	return nil
}

// Add commits the planned directories, each verified again at the commit: the identity the operator was shown is the one
// recorded, or nothing is.
func (s OneShotStore) Add(plans []OneShotPlan) error {
	return s.lockedChange(func(doc oneShotDocument) (oneShotDocument, error) {
		now := time.Now().Format(time.RFC3339)
		for _, plan := range plans {
			if err := oneShotPathOK(plan.Path); err != nil {
				return doc, err
			}
			physical, err := filepath.EvalSymlinks(plan.Path)
			if err != nil || physical != plan.Path {
				return doc, fmt.Errorf("%q is not the physical path of a directory any more: nothing was recorded", plan.Path)
			}
			id, err := identityOf(plan.Path)
			if err != nil || id.Dev != plan.Dev || id.Inode != plan.Inode {
				return doc, fmt.Errorf("%q changed since it was shown: nothing was recorded", plan.Path)
			}
			doc.Projects[plan.Path] = OneShotEntry{Added: now, Dev: plan.Dev, Inode: plan.Inode}
		}
		return doc, nil
	})
}

// Remove withdraws projects, each named by its exact stored key or by a directory that resolves to one; all or nothing. It
// returns the keys removed (only after the commit).
func (s OneShotStore) Remove(args []string) ([]string, error) {
	var removed []string
	err := s.lockedChange(func(doc oneShotDocument) (oneShotDocument, error) {
		removed = nil
		for _, arg := range args {
			key := ""
			if _, ok := doc.Projects[arg]; ok {
				key = arg
			} else if plans, err := Resolve([]string{arg}, false); err == nil {
				if _, ok := doc.Projects[plans[0].Path]; ok {
					key = plans[0].Path
				}
			}
			if key == "" {
				return doc, fmt.Errorf("%q is not on the one-shot route (by its stored path or its physical path): nothing was changed", arg)
			}
			delete(doc.Projects, key)
			removed = append(removed, key)
		}
		return doc, nil
	})
	if err != nil {
		return nil, err
	}
	return removed, nil
}
