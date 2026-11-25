//go:build linux

package projectlane

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/superbiche/safe/internal/strictjson"
)

// The operator's standing decision per project (ticket 1690): the projects on which the lane is off, so that their npm commands
// take today's gate (the one-shot route). ONE reader and ONE writer, here, for the lane, `list`, `add` and `remove`. The store is
// the file `one-shot-projects.json` in the operator's established run directory, <home>/.config/safe/run:
//
//   - the chain of directories below the home is opened one name at a time through held descriptors, never following a link;
//     each must belong to the user and not be writable by group or others;
//   - the file is opened relative to the held run directory without following a link, validated and read on THE SAME descriptor
//     (a regular file of the user, one link, mode exactly 0600, no set-id or sticky bit), as ONE strict, bounded document;
//   - a writer holds an exclusive lock (a file checked like the data file) over read, change and rename; the staged file is
//     created with its final mode; the change is reported only once it is committed.
//
// An entry is the physical path of a project directory (its bytes) with its device and inode. A decision can only WEAKEN the route,
// so a store that cannot be trusted is "no project pinned", never an error that would raise a question.
const (
	OneShotStoreFile = "one-shot-projects.json"
	oneShotLockFile  = "one-shot-projects.lock"
	// OneShotLimit bounds the document: the reader refuses a larger one and the writer refuses to publish one.
	OneShotLimit = 64 << 10
	// OneShotSchema is the version of the document.
	OneShotSchema = 1
)

// OneShotEntry is one pinned project.
type OneShotEntry struct {
	Path  string `json:"path"`
	Dev   uint64 `json:"dev"`
	Inode uint64 `json:"inode"`
	Added string `json:"added"`
}

type oneShotDocument struct {
	SchemaVersion int            `json:"schema_version"`
	Projects      []OneShotEntry `json:"projects"`
}

// OneShotStore is the store below one home directory (the anchor every operator store hangs from).
type OneShotStore struct{ Home string }

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

// Results of a lookup.
const (
	OneShotPinned   = 0 // a directory the question names is a stored pin by identity
	OneShotNotPin   = 1 // none (and nothing that cannot be trusted)
	OneShotReplaced = 2 // a stored path is here, but another directory stands on it now
)

// ErrNotRecorded: a failure BEFORE the rename: nothing changed. ErrDurabilityUncertain: the rename succeeded (the change is
// visible) and the directory sync that follows failed: the change may not survive a crash.
var (
	ErrNotRecorded         = errors.New("the change was NOT recorded")
	ErrDurabilityUncertain = errors.New("the change is committed and visible, but its durability is uncertain (the directory sync failed)")
)

var (
	oneShotEUID = os.Geteuid
	// test seams
	afterChain  func()
	afterRead   func()
	afterRename func()
	dirSync     = func(d *dirHandle) error { return d.f.Sync() }
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

// openRun opens the run directory through the verified chain.
func (s OneShotStore) openRun(create bool) (*dirHandle, error) {
	if !strings.HasPrefix(s.Home, "/") {
		return nil, errors.New("the home directory is not absolute")
	}
	current, err := openDirPath(s.Home)
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

// checkOneShotFile validates an open file as the operator's own private regular file.
func checkOneShotFile(file *os.File, what string, limit int64) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", what)
	}
	if !oneShotOwned(info) {
		return fmt.Errorf("%s is not owned by this user", what)
	}
	if info.Mode().Perm() != 0o600 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return fmt.Errorf("%s does not have mode 0600", what)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Nlink != 1 {
		return fmt.Errorf("%s has more than one link", what)
	}
	if limit > 0 && info.Size() > limit {
		return fmt.Errorf("%s is larger than %d bytes", what, limit)
	}
	return nil
}

// decodeOneShot is THE strict reader: exactly one document, members given once (compared exactly), no second spelling, no unknown
// member, nothing after it, the right schema, unique paths. Anything else is not a document safe wrote.
func decodeOneShot(raw []byte) (oneShotDocument, error) {
	var doc oneShotDocument
	members, err := strictjson.ParseObject(raw)
	if err != nil {
		return doc, err
	}
	if err := strictjson.RejectVariants(members, "schema_version", "projects"); err != nil {
		return doc, err
	}
	var rows []json.RawMessage
	if err := json.Unmarshal(members["projects"], &rows); err != nil || rows == nil {
		return doc, errors.New("projects is not a list")
	}
	for _, row := range rows {
		entry, err := strictjson.ParseObject(row)
		if err != nil {
			return doc, err
		}
		if err := strictjson.RejectVariants(entry, "path", "dev", "inode", "added"); err != nil {
			return doc, err
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&doc); err != nil || decoder.More() || doc.SchemaVersion != OneShotSchema {
		return oneShotDocument{}, errors.New("the store is not a version 1 document")
	}
	seen := map[string]struct{}{}
	for _, entry := range doc.Projects {
		if _, dup := seen[entry.Path]; dup {
			return oneShotDocument{}, fmt.Errorf("the path %q is stored twice", entry.Path)
		}
		seen[entry.Path] = struct{}{}
		if err := oneShotPathOK(entry.Path); err != nil || !strings.HasPrefix(entry.Path, "/") {
			return oneShotDocument{}, errors.New("a stored path cannot be a project path")
		}
	}
	return doc, nil
}

// readOneShotFile reads and validates the store file on one open descriptor. A missing file is an empty document.
func readOneShotFile(run *dirHandle) (oneShotDocument, error) {
	empty := oneShotDocument{SchemaVersion: OneShotSchema, Projects: []OneShotEntry{}}
	fd, err := syscall.Openat(run.fd(), OneShotStoreFile, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return empty, nil
		}
		return empty, &os.PathError{Op: "openat", Path: OneShotStoreFile, Err: err}
	}
	file := os.NewFile(uintptr(fd), OneShotStoreFile)
	defer file.Close()
	if err := checkOneShotFile(file, "the store", OneShotLimit); err != nil {
		return empty, err
	}
	raw, err := io.ReadAll(io.LimitReader(file, OneShotLimit+1))
	if err != nil {
		return empty, err
	}
	if len(raw) > OneShotLimit {
		return empty, errors.New("the store is too large")
	}
	doc, err := decodeOneShot(raw)
	if err != nil {
		return empty, err
	}
	if doc.Projects == nil {
		doc.Projects = []OneShotEntry{}
	}
	return doc, nil
}

func (s OneShotStore) read() (oneShotDocument, error) {
	run, err := s.openRun(false)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return oneShotDocument{SchemaVersion: OneShotSchema, Projects: []OneShotEntry{}}, nil
		}
		return oneShotDocument{}, err
	}
	defer run.Close()
	if afterChain != nil {
		afterChain()
	}
	return readOneShotFile(run)
}

// dirIdentity is what an open directory is: its kernel-reported physical path and its identity.
func dirIdentity(file *os.File) (OneShotPlan, error) {
	info, err := file.Stat()
	if err != nil {
		return OneShotPlan{}, err
	}
	if !info.IsDir() {
		return OneShotPlan{}, errors.New("not a directory")
	}
	physical, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", file.Fd()))
	if err != nil {
		return OneShotPlan{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return OneShotPlan{}, errors.New("no identity")
	}
	return OneShotPlan{Path: physical, Dev: uint64(stat.Dev), Inode: uint64(stat.Ino)}, nil
}

// openDirAsGiven hands the operand to the KERNEL exactly as given (never a textual clean: `link/..` is the parent of what the
// link leads to), and reports what it opened.
func openDirAsGiven(path string) (OneShotPlan, error) {
	file, err := os.Open(path)
	if err != nil {
		return OneShotPlan{}, err
	}
	defer file.Close()
	return dirIdentity(file)
}

func (doc oneShotDocument) lookup(plan OneShotPlan) (found, replaced bool) {
	for _, entry := range doc.Projects {
		if entry.Path == plan.Path {
			if entry.Dev == plan.Dev && entry.Inode == plan.Inode {
				return true, false
			}
			replaced = true
		}
	}
	return false, replaced
}

// CheckHere is the first question of the lane, on data alone: is the process's own directory, or one of its ancestors, a stored
// pin by identity? When none is, nothing more happens (no npm is run).
func (s OneShotStore) CheckHere() int {
	doc, err := s.read()
	if err != nil || len(doc.Projects) == 0 {
		return OneShotNotPin
	}
	current, err := os.Open(".")
	if err != nil {
		return OneShotNotPin
	}
	result := OneShotNotPin
	for depth := 0; depth < 4096; depth++ {
		plan, err := dirIdentity(current)
		if err != nil {
			break
		}
		if found, replaced := doc.lookup(plan); found {
			current.Close()
			return OneShotPinned
		} else if replaced {
			result = OneShotReplaced
		}
		if plan.Path == "/" {
			break
		}
		parent, err := os.Open(fmt.Sprintf("/proc/self/fd/%d/..", current.Fd()))
		current.Close()
		if err != nil {
			return result
		}
		current = parent
	}
	current.Close()
	return result
}

// VerifyRoot is the second question: the line npm printed for `npm root`. It is honoured only when it is exactly one line, ends in
// /node_modules, and the directory it names (opened here, never taken as text) is itself a stored pin by identity.
func (s OneShotStore) VerifyRoot(output []byte) int {
	text := string(output)
	text = strings.TrimSuffix(text, "\n")
	if text == "" || strings.ContainsAny(text, "\n\r\x00") || !strings.HasSuffix(text, "/node_modules") || !strings.HasPrefix(text, "/") {
		return OneShotNotPin
	}
	dir := strings.TrimSuffix(text, "/node_modules")
	if dir == "" {
		dir = "/"
	}
	doc, err := s.read()
	if err != nil {
		return OneShotNotPin
	}
	plan, err := openDirAsGiven(dir)
	if err != nil {
		return OneShotNotPin
	}
	if found, _ := doc.lookup(plan); found {
		return OneShotPinned
	}
	return OneShotNotPin
}

// List reads the whole store for a listing. A store that cannot be trusted is an error the listing reports (and nothing is pinned).
func (s OneShotStore) List() ([]OneShotRow, error) {
	doc, err := s.read()
	if err != nil {
		return nil, err
	}
	rows := make([]OneShotRow, 0, len(doc.Projects))
	for _, entry := range doc.Projects {
		row := OneShotRow{Path: entry.Path, Added: entry.Added, Dev: entry.Dev, Inode: entry.Inode, State: "honoured"}
		now, err := openDirAsGiven(entry.Path)
		switch {
		case errors.Is(err, os.ErrNotExist):
			row.State = "directory gone"
		case err != nil || now.Path != entry.Path || now.Dev != entry.Dev || now.Inode != entry.Inode:
			row.State = "not honoured (directory replaced)"
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Path < rows[j].Path })
	return rows, nil
}

func oneShotPathOK(path string) error {
	if !utf8.ValidString(path) {
		return fmt.Errorf("the path %q is not valid UTF-8, so it cannot be recorded exactly", path)
	}
	if strings.ContainsAny(path, "\n\r\x00") {
		return fmt.Errorf("the path %q contains a control character: the lane cannot capture such a path exactly, so it is never pinned", path)
	}
	return nil
}

// Resolve gives the physical path and identity of each directory operand, as the operator will be shown them. needManifest
// requires a regular package.json in the directory (only an npm project goes on the route).
func Resolve(dirs []string, needManifest bool) ([]OneShotPlan, error) {
	plans := make([]OneShotPlan, 0, len(dirs))
	for _, dir := range dirs {
		file, err := os.Open(dir)
		if err != nil {
			return nil, fmt.Errorf("cannot read the directory %q: %w", dir, err)
		}
		plan, err := dirIdentity(file)
		if err == nil {
			err = oneShotPathOK(plan.Path)
		}
		if err == nil && needManifest {
			// relative to the OPEN directory (its descriptor), the last component never followed
			if info, serr := os.Lstat(fmt.Sprintf("/proc/self/fd/%d/package.json", file.Fd())); serr != nil || !info.Mode().IsRegular() {
				err = fmt.Errorf("no package.json in %q: only an npm project can be put on the one-shot route", plan.Path)
			}

		}
		file.Close()
		if err != nil {
			return nil, err
		}
		plans = append(plans, plan)
	}
	return plans, nil
}

// lockedChange runs a read-modify-write of the store under an exclusive lock and renames the result into place. It reports
// ErrNotRecorded for any failure before the rename and ErrDurabilityUncertain when only the directory sync after it failed.
func (s OneShotStore) lockedChange(change func(oneShotDocument) (oneShotDocument, error)) error {
	run, err := s.openRun(true)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNotRecorded, err)
	}
	defer run.Close()
	lockFD, err := syscall.Openat(run.fd(), oneShotLockFile, syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNotRecorded, &os.PathError{Op: "openat", Path: oneShotLockFile, Err: err})
	}
	lock := os.NewFile(uintptr(lockFD), oneShotLockFile)
	defer lock.Close()
	if err := checkOneShotFile(lock, "the lock file", 0); err != nil {
		return fmt.Errorf("%w: %v", ErrNotRecorded, err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("%w: %v", ErrNotRecorded, err)
	}
	doc, err := readOneShotFile(run)
	if err != nil {
		return fmt.Errorf("%w: the store is not the operator's own (%v): fix or remove it first", ErrNotRecorded, err)
	}
	if afterRead != nil {
		afterRead()
	}
	next, err := change(doc)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNotRecorded, err)
	}
	next.SchemaVersion = OneShotSchema
	raw, err := json.Marshal(next)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNotRecorded, err)
	}
	raw = append(raw, '\n')
	if len(raw) > OneShotLimit {
		return fmt.Errorf("%w: the store would be larger than %d bytes; the previous document is kept", ErrNotRecorded, OneShotLimit)
	}
	name, err := randomName()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNotRecorded, err)
	}
	tmp := OneShotStoreFile + "." + name
	if _, err := run.createExclusiveMode(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("%w: %v", ErrNotRecorded, err)
	}
	if err := renameat2(run, tmp, run, OneShotStoreFile, 0); err != nil {
		_ = run.remove(tmp)
		return fmt.Errorf("%w: %v", ErrNotRecorded, err)
	}
	if afterRename != nil {
		afterRename()
	}
	if err := dirSync(run); err != nil {
		return fmt.Errorf("%w: %v", ErrDurabilityUncertain, err)
	}
	return nil
}

// Add commits the planned directories, each verified again at the commit: the identity the operator was shown is the one
// recorded, or nothing is.
func (s OneShotStore) Add(plans []OneShotPlan) error {
	return s.lockedChange(func(doc oneShotDocument) (oneShotDocument, error) {
		now := time.Now().UTC().Format(time.RFC3339)
		for _, plan := range plans {
			if err := oneShotPathOK(plan.Path); err != nil {
				return doc, err
			}
			id, err := openDirAsGiven(plan.Path)
			if err != nil || id.Path != plan.Path || id.Dev != plan.Dev || id.Inode != plan.Inode {
				return doc, fmt.Errorf("%q changed since it was shown: nothing was recorded", plan.Path)
			}
			kept := doc.Projects[:0:0]
			for _, entry := range doc.Projects {
				if entry.Path != plan.Path {
					kept = append(kept, entry)
				}
			}
			doc.Projects = append(kept, OneShotEntry{Path: plan.Path, Dev: plan.Dev, Inode: plan.Inode, Added: now})
		}
		sort.Slice(doc.Projects, func(i, j int) bool { return doc.Projects[i].Path < doc.Projects[j].Path })
		return doc, nil
	})
}

// RemoveKeys are the stored keys a Remove would withdraw, each operand named by its exact stored key or by a directory that the
// kernel resolves to one. Nothing is changed.
func (s OneShotStore) RemoveKeys(args []string) ([]string, error) {
	doc, err := s.read()
	if err != nil {
		return nil, err
	}
	return removeKeys(doc, args)
}

func removeKeys(doc oneShotDocument, args []string) ([]string, error) {
	keys := make([]string, 0, len(args))
	for _, arg := range args {
		key := ""
		for _, entry := range doc.Projects {
			if entry.Path == arg {
				key = arg
			}
		}
		if key == "" {
			if plan, err := openDirAsGiven(arg); err == nil {
				for _, entry := range doc.Projects {
					if entry.Path == plan.Path {
						key = plan.Path
					}
				}
			}
		}
		if key == "" {
			return nil, fmt.Errorf("%q is not on the one-shot route (by its stored path or its physical path): nothing was changed", arg)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// Remove withdraws projects; all or nothing. It returns the keys removed (only after the commit).
func (s OneShotStore) Remove(args []string) ([]string, error) {
	var removed []string
	err := s.lockedChange(func(doc oneShotDocument) (oneShotDocument, error) {
		keys, err := removeKeys(doc, args)
		if err != nil {
			return doc, err
		}
		removed = keys
		drop := map[string]struct{}{}
		for _, key := range keys {
			drop[key] = struct{}{}
		}
		kept := doc.Projects[:0:0]
		for _, entry := range doc.Projects {
			if _, gone := drop[entry.Path]; !gone {
				kept = append(kept, entry)
			}
		}
		doc.Projects = kept
		return doc, nil
	})
	if err != nil && !errors.Is(err, ErrDurabilityUncertain) {
		return nil, err
	}
	return removed, err
}
