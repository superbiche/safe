//go:build linux

package projectlane

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// The recorded baselines (spec 1625, Baseline): safe keeps, per canonical project
// path, THE LOCKFILES IT JUDGED CLEAR on complete evidence, each under its own digest:
//
//	<state>/project-baseline/<sha256 of the canonical project path>/<lockfile name>/<sha256 of the bytes>
//
// A record is the lockfile's bytes. A lockfile on disk whose bytes are a trusted
// record is a baseline, whenever and however it came to be on disk (a failed
// installation, a restored file, an old commit checked out): the advisories it carries
// are ones the project already had or ones that were judged when they came in. That is
// a property of the content and of the judgement it went through, not of when it was
// written.
//
// A record is trusted ONLY when the bytes read hash to the digest it is stored under
// and it is a regular file of mode exactly 0600 owned by the user. Anything else is
// IGNORED (and named, so it can be reported once): ignoring a record can only make more
// of the graph be judged. The chain of directories is outside the project, held by
// descriptor, owned by the user, not writable by group or others and never a link.
// Writing is atomic (a private temporary name, renamed into place); writing a record
// that already exists is a no-op that refreshes its time (its modification time is the
// order records are kept in). A bounded number of the most recent records is kept per
// project and name: older ones are pruned when one is written.

const (
	baselineDir     = "project-baseline"
	baselineMaxSize = 256 << 20
	// BaselineKeep is the number of the most recent records kept per project and name.
	BaselineKeep = 16
)

var recordDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

func baselineNameOK(name string) bool {
	if name == "" || len(name) > 64 || name[0] == '.' || name[0] == '-' {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

// canonicalProject refuses anything but an absolute, clean, link-free directory path:
// the key is the path the lane resolved when it took its lock.
func canonicalProject(project string) error {
	if !strings.HasPrefix(project, "/") || filepath.Clean(project) != project {
		return errors.New("the project path must be canonical and absolute")
	}
	real, err := filepath.EvalSymlinks(project)
	if err != nil || real != project {
		return errors.New("the project path is not canonical")
	}
	return nil
}

// recordDir opens (and with create, makes) the private directory of a project's
// records of one lockfile name.
func recordDir(stateDir, project, name string, create bool) (*dirHandle, error) {
	if !baselineNameOK(name) {
		return nil, fmt.Errorf("%q is not a lockfile name", name)
	}
	if err := canonicalProject(project); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(stateDir, "/") {
		return nil, errors.New("the state directory must be an absolute path")
	}
	state, err := filepath.EvalSymlinks(stateDir)
	if err != nil {
		return nil, err
	}
	root, err := openDirPath(state)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if err := checkPrivate(root, "the state directory"); err != nil {
		return nil, err
	}
	open := func(parent *dirHandle, child, what string) (*dirHandle, error) {
		if create {
			return openPrivateChild(parent, child, what)
		}
		handle, err := parent.openDirNoFollow(child)
		if err != nil {
			return nil, err
		}
		if err := checkPrivate(handle, what); err != nil {
			handle.Close()
			return nil, err
		}
		return handle, nil
	}
	sub, err := open(root, baselineDir, "the baseline directory")
	if err != nil {
		return nil, err
	}
	defer sub.Close()
	key := sha256.Sum256([]byte(project))
	byProject, err := open(sub, hex.EncodeToString(key[:]), "this project's baseline directory")
	if err != nil {
		return nil, err
	}
	defer byProject.Close()
	return open(byProject, name, "this lockfile's baseline directory")
}

// readTrusted reads one record and returns its bytes when, and only when, they are
// trusted. why is empty for a trusted record.
func readTrusted(dir *dirHandle, digest string) (content []byte, why string) {
	raw, info, err := dir.readRegular(digest, baselineMaxSize)
	if err != nil {
		return nil, "it cannot be read as a regular file (" + err.Error() + ")"
	}
	if !ownedByUs(info) || info.Mode()&(os.ModePerm|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0o600 {
		return nil, "it is not a private (0600) file of this user"
	}
	sum := sha256.Sum256(raw)
	if len(raw) == 0 || hex.EncodeToString(sum[:]) != digest {
		return nil, "its bytes do not hash to the digest it is stored under"
	}
	return raw, ""
}

// Ignored names a record that was not trusted and why.
type Ignored struct{ Digest, Why string }

// RecordBaseline stores a lockfile judged clear. Idempotent: an existing trusted record
// is only refreshed. keep bounds the records kept (older ones are pruned).
func RecordBaseline(stateDir, project, name string, content []byte, keep int) error {
	if len(content) == 0 || len(content) > baselineMaxSize {
		return errors.New("the lockfile to record is empty or too large")
	}
	if keep < 1 {
		return errors.New("keep at least one record")
	}
	dir, err := recordDir(stateDir, project, name, true)
	if err != nil {
		return err
	}
	defer dir.Close()
	sum := sha256.Sum256(content)
	digest := hex.EncodeToString(sum[:])
	if existing, why := readTrusted(dir, digest); why == "" && string(existing) == string(content) {
		// a failure to refresh the time is not a failure to record
		_ = os.Chtimes(dir.procPath(digest), time.Time{}, time.Now())
	} else {
		random, rerr := randomName()
		if rerr != nil {
			return rerr
		}
		temp := ".new-" + random
		if _, cerr := dir.createExclusive(temp, content, 0o600); cerr != nil {
			return cerr
		}
		ferr := fault("baseline:rename")
		if ferr == nil {
			ferr = renameat2(dir, temp, dir, digest, 0)
		}
		if ferr != nil {
			_ = dir.remove(temp)
			return ferr
		}
	}
	return prune(dir, keep, digest)
}

type recordInfo struct {
	digest string
	mtime  time.Time
}

func listRecords(dir *dirHandle) ([]recordInfo, error) {
	names, err := dir.names()
	if err != nil {
		return nil, err
	}
	var out []recordInfo
	for _, name := range names {
		if !recordDigest.MatchString(name) {
			continue
		}
		info, err := dir.lstat(name)
		if err != nil {
			continue
		}
		out = append(out, recordInfo{name, info.ModTime()})
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].mtime.Equal(out[j].mtime) {
			return out[i].mtime.After(out[j].mtime)
		}
		return out[i].digest > out[j].digest
	})
	return out, nil
}

// prune removes the records beyond the keep most recent; the one just written stays.
func prune(dir *dirHandle, keep int, keepDigest string) error {
	records, err := listRecords(dir)
	if err != nil {
		return err
	}
	for i, record := range records {
		if i < keep || record.digest == keepDigest {
			continue
		}
		_ = dir.remove(record.digest)
	}
	return nil
}

// ReadRecorded returns the recorded lockfile stored under digest, when trusted.
func ReadRecorded(stateDir, project, name, digest string) (content []byte, found bool, ignored []Ignored, err error) {
	if !recordDigest.MatchString(digest) {
		return nil, false, nil, errors.New("not a sha256 digest")
	}
	dir, derr := recordDir(stateDir, project, name, false)
	if derr != nil {
		return nil, false, notTrusted(derr), nil
	}
	defer dir.Close()
	if _, lerr := dir.lstat(digest); lerr != nil {
		return nil, false, nil, nil
	}
	raw, why := readTrusted(dir, digest)
	if why != "" {
		return nil, false, []Ignored{{digest, why}}, nil
	}
	return raw, true, nil, nil
}

// LatestRecorded returns the most recently written trusted record.
func LatestRecorded(stateDir, project, name string) (content []byte, found bool, ignored []Ignored, err error) {
	dir, derr := recordDir(stateDir, project, name, false)
	if derr != nil {
		return nil, false, notTrusted(derr), nil
	}
	defer dir.Close()
	records, lerr := listRecords(dir)
	if lerr != nil {
		return nil, false, []Ignored{{"", lerr.Error()}}, nil
	}
	for _, record := range records {
		raw, why := readTrusted(dir, record.digest)
		if why != "" {
			ignored = append(ignored, Ignored{record.digest, why})
			continue
		}
		return raw, true, ignored, nil
	}
	return nil, false, ignored, nil
}

// A directory that is simply not there means nothing was recorded; any other failure
// of the chain (not private, a link, ...) means nothing in it is trusted.
func notTrusted(err error) []Ignored {
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return []Ignored{{"", "the record directory is not trusted: " + err.Error()}}
}
