//go:build linux

package projectlane

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

// The stored baseline (spec 1625, Baseline): the lockfile safe itself judged on
// complete evidence and published (or whose materialisation it verified) at the
// end of its own last command in a project. It is kept OUTSIDE the project, in
// safe's own state directory, so that nothing the project's content or a
// command it runs can steer it:
//
//	<state>/project-baseline/<sha256 of the canonical project path>/<name>.json
//
// every directory of that chain is held by descriptor, belongs to the user, is
// not writable by group or others and is never a link. The record holds the
// lockfile itself and its digest, the canonical project path and the identity
// (device, inode) of the project directory it was taken in: a different
// directory at the same path (a fresh clone) is a different project and has no
// stored baseline. A record whose digest does not match its content, whose shape
// is not exactly the one written, or which is not a regular private file, is
// UNREADABLE: never trusted, never read as an empty baseline.
//
// Writing is atomic: the record is written whole to a private temporary name in
// the same directory and renamed over the previous one.

const (
	baselineDir     = "project-baseline"
	baselineSchema  = 1
	baselineMaxSize = 256 << 20
)

// StoredStatus is what a read found.
type StoredStatus int

const (
	// StoredFound: a trusted stored baseline was read.
	StoredFound StoredStatus = iota
	// StoredAbsent: safe stored none for this project (a record kept for
	// another incarnation of the directory counts as none).
	StoredAbsent
)

type baselineRecord struct {
	Schema     int    `json:"schema"`
	Project    string `json:"project"`
	Dev        uint64 `json:"dev"`
	Ino        uint64 `json:"ino"`
	Name       string `json:"name"`
	Digest     string `json:"digest"`
	LockfileB6 string `json:"lockfile_base64"`
}

var baselineName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// baselineHandle opens (and with create, makes) the private directory of a
// project's record, checking every directory of the chain.
func baselineHandle(stateDir, project string, create bool) (*dirHandle, fileID, error) {
	if !filepath.IsAbs(stateDir) || !filepath.IsAbs(project) || filepath.Clean(project) != project {
		return nil, fileID{}, errors.New("the state directory and the project must be canonical absolute paths")
	}
	if real, err := filepath.EvalSymlinks(project); err != nil || real != project {
		return nil, fileID{}, errors.New("the project path is not canonical")
	}
	info, err := os.Lstat(project)
	if err != nil || !info.IsDir() {
		return nil, fileID{}, errors.New("the project directory cannot be read")
	}
	projectID := idOf(info)
	state, err := filepath.EvalSymlinks(stateDir)
	if err != nil {
		return nil, fileID{}, err
	}
	root, err := openDirPath(state)
	if err != nil {
		return nil, fileID{}, err
	}
	defer root.Close()
	if err := checkPrivate(root, "the state directory"); err != nil {
		return nil, fileID{}, err
	}
	open := func(parent *dirHandle, name, what string) (*dirHandle, error) {
		if create {
			return openPrivateChild(parent, name, what)
		}
		child, err := parent.openDirNoFollow(name)
		if err != nil {
			return nil, err
		}
		if err := checkPrivate(child, what); err != nil {
			child.Close()
			return nil, err
		}
		return child, nil
	}
	sub, err := open(root, baselineDir, "the baseline directory")
	if err != nil {
		return nil, fileID{}, err
	}
	defer sub.Close()
	key := sha256.Sum256([]byte(project))
	dir, err := open(sub, hex.EncodeToString(key[:]), "this project's baseline directory")
	if err != nil {
		return nil, fileID{}, err
	}
	return dir, projectID, nil
}

// ReadBaseline returns the lockfile safe stored for the project under name.
// StoredAbsent with no error: none stored. An error: something is stored (or
// in the way) and cannot be trusted.
func ReadBaseline(stateDir, project, name string) ([]byte, StoredStatus, error) {
	if !baselineName.MatchString(name) {
		return nil, StoredAbsent, fmt.Errorf("%q is not a lockfile name", name)
	}
	dir, projectID, err := baselineHandle(stateDir, project, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil, StoredAbsent, nil
	}
	if err != nil {
		return nil, StoredAbsent, err
	}
	defer dir.Close()
	raw, info, err := dir.readRegular(name+".json", baselineMaxSize*2)
	if errors.Is(err, os.ErrNotExist) {
		return nil, StoredAbsent, nil
	}
	if err != nil {
		return nil, StoredAbsent, fmt.Errorf("the stored baseline cannot be read: %w", err)
	}
	if !ownedByUs(info) || info.Mode().Perm()&0o077 != 0 {
		return nil, StoredAbsent, errors.New("the stored baseline is not a private file of this user")
	}
	var record baselineRecord
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil || decoder.More() {
		return nil, StoredAbsent, errors.New("the stored baseline is not a record safe wrote")
	}
	if record.Schema != baselineSchema || record.Name != name || record.Project != project {
		return nil, StoredAbsent, errors.New("the stored baseline is for another project or name")
	}
	content, err := base64.StdEncoding.Strict().DecodeString(record.LockfileB6)
	if err != nil || len(content) == 0 || record.Digest != digestOf(content) {
		return nil, StoredAbsent, errors.New("the stored baseline does not match its digest")
	}
	if record.Dev != projectID.dev || record.Ino != projectID.ino {
		// Another directory at this path: a different project, with no baseline.
		return nil, StoredAbsent, nil
	}
	return content, StoredFound, nil
}

// WriteBaseline stores content as the project's baseline under name, atomically.
func WriteBaseline(stateDir, project, name string, content []byte) error {
	if !baselineName.MatchString(name) {
		return fmt.Errorf("%q is not a lockfile name", name)
	}
	if len(content) == 0 || len(content) > baselineMaxSize {
		return errors.New("the baseline is empty or too large")
	}
	dir, projectID, err := baselineHandle(stateDir, project, true)
	if err != nil {
		return err
	}
	defer dir.Close()
	record, err := json.Marshal(baselineRecord{
		Schema: baselineSchema, Project: project, Dev: projectID.dev, Ino: projectID.ino, Name: name,
		Digest: digestOf(content), LockfileB6: base64.StdEncoding.EncodeToString(content),
	})
	if err != nil {
		return err
	}
	random, err := randomName()
	if err != nil {
		return err
	}
	temp := ".new-" + random
	if _, err := dir.createExclusive(temp, append(record, '\n'), 0o600); err != nil {
		return err
	}
	err = fault("baseline:rename")
	if err == nil {
		err = renameat2(dir, temp, dir, name+".json", 0)
	}
	if err != nil {
		_ = dir.remove(temp)
		return err
	}
	return nil
}
