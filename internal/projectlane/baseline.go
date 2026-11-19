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
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/superbiche/safe/internal/strictjson"
)

// The stored baseline (spec 1625, Baseline): the lockfile safe itself judged on
// complete evidence and published at the end of its own last command in a project.
// It is kept OUTSIDE the project, in safe's own state directory, so that nothing
// the project's content or a command it runs can steer it:
//
//	<state>/project-baseline/<sha256 of the canonical project path>/<name>.json          current
//	<state>/project-baseline/<sha256 of the canonical project path>/<name>.pending.json  pending
//
// Every directory of that chain is held by descriptor, belongs to the user, is not
// writable by group or others and is never a link.
//
// WHOSE RECORD IT IS. Both operations are given the DESCRIPTOR of the project
// directory the gate holds locked, never a pathname to look up again: the record is
// read and written for the very directory the lock, the judgement and the
// publication were about. A record carries the identity of that directory: its
// device, its inode and its BIRTH TIME. An ordinary edit keeps all three; deleting
// and recreating the directory changes the birth time even when the inode is
// recycled. An identity that cannot be established (a filesystem without birth
// time), a record that lacks any of the three, or one that differs in any of them,
// is UNREADABLE: never "none stored". Where no identity can be established nothing
// can be stored (ErrNoIdentity) and nothing is, so the baseline is the committed
// one or empty.
//
// STATES. The record that counts is the CURRENT one. A command that is about to
// publish first writes the intended baseline as PENDING (same format, same
// protections), and after a committed publication CONFIRMS it (the pending record
// replaces the current one by an atomic rename). The next run settles a pending
// record it finds (see the gate): it is the only way a publication that went
// through while the record did not follow is noticed.
//
// FORMAT. One exact JSON document, mode exactly 0600, every member required with
// its exact name and type, no other member, no second spelling, no trailing
// content; the lockfile is base64 and its digest must match.

const (
	baselineDir     = "project-baseline"
	baselineSchema  = 1
	baselineMaxSize = 256 << 20
)

// RecordKind says which of the two records of a project and name is meant.
type RecordKind string

const (
	RecordCurrent RecordKind = "current"
	RecordPending RecordKind = "pending"
)

// StoredStatus is what a read found.
type StoredStatus int

const (
	// StoredFound: a trusted record was read.
	StoredFound StoredStatus = iota
	// StoredAbsent: none is stored for this project and kind.
	StoredAbsent
)

// ErrNoIdentity: the project directory's identity (birth time) cannot be
// established on this filesystem, so no record can be tied to it.
var ErrNoIdentity = errors.New("the project directory's identity (its birth time) cannot be established on this filesystem, so no baseline can be tied to it")

// DirIdentity is what tells one incarnation of a directory from another.
type DirIdentity struct {
	Dev, Ino  uint64
	BtimeSec  int64
	BtimeNsec uint32
}

// identityOfFD reads the identity of the directory a descriptor holds.
func identityOfFD(fd int) (DirIdentity, error) {
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return DirIdentity{}, err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return DirIdentity{}, errors.New("the descriptor is not a directory")
	}
	id := DirIdentity{Dev: uint64(st.Dev), Ino: uint64(st.Ino)}
	if statxNumber == 0 {
		return id, ErrNoIdentity
	}
	const (
		atEmptyPath = 0x1000
		statxBtime  = 0x800
	)
	var buf [256]byte
	empty, _ := syscall.BytePtrFromString("")
	_, _, errno := syscall.Syscall6(statxNumber, uintptr(fd), uintptr(unsafe.Pointer(empty)), atEmptyPath, statxBtime,
		uintptr(unsafe.Pointer(&buf[0])), 0)
	if errno != 0 {
		return id, ErrNoIdentity
	}
	mask := *(*uint32)(unsafe.Pointer(&buf[0]))
	if mask&statxBtime == 0 {
		return id, ErrNoIdentity
	}
	id.BtimeSec = *(*int64)(unsafe.Pointer(&buf[80]))
	id.BtimeNsec = *(*uint32)(unsafe.Pointer(&buf[88]))
	return id, nil
}

// identityOf is identityOfFD; a test replaces it to stand for a filesystem without birth time.
var identityOf = identityOfFD

// pathOfFD is the canonical path of the directory a descriptor holds.
func pathOfFD(fd int) (string, error) {
	target, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(target, "/") || strings.HasSuffix(target, " (deleted)") {
		return "", errors.New("the project directory has no path (it was removed)")
	}
	return target, nil
}

type baselineRecord struct {
	Schema   int
	Project  string
	Identity DirIdentity
	Name     string
	Digest   string
	Lockfile []byte
}

func recordFile(name string, kind RecordKind) string {
	if kind == RecordPending {
		return name + ".pending.json"
	}
	return name + ".json"
}

// baselineHandle opens (and with create, makes) the private directory of the
// record of the project the descriptor holds.
func baselineHandle(stateDir string, projectFD int, create bool) (*dirHandle, string, DirIdentity, error) {
	project, err := pathOfFD(projectFD)
	if err != nil {
		return nil, "", DirIdentity{}, err
	}
	id, idErr := identityOf(projectFD)
	if idErr != nil && !errors.Is(idErr, ErrNoIdentity) {
		return nil, "", DirIdentity{}, idErr
	}
	if !strings.HasPrefix(stateDir, "/") {
		return nil, "", DirIdentity{}, errors.New("the state directory must be an absolute path")
	}
	state, err := resolveDir(stateDir)
	if err != nil {
		return nil, "", DirIdentity{}, err
	}
	root, err := openDirPath(state)
	if err != nil {
		return nil, "", DirIdentity{}, err
	}
	defer root.Close()
	if err := checkPrivate(root, "the state directory"); err != nil {
		return nil, "", DirIdentity{}, err
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
		return nil, "", DirIdentity{}, err
	}
	defer sub.Close()
	key := sha256.Sum256([]byte(project))
	dir, err := open(sub, hex.EncodeToString(key[:]), "this project's baseline directory")
	if err != nil {
		return nil, "", DirIdentity{}, err
	}
	return dir, project, id, idErr
}

// resolveDir canonicalises the state directory path (it may itself sit below a link
// the operator made; the chain below it is what is held and checked).
func resolveDir(path string) (string, error) {
	handle, err := openDirPath(path)
	if err != nil {
		return "", err
	}
	defer handle.Close()
	return pathOfFD(handle.fd())
}

// decodeRecord is the strict reader: the exact document, every member required with
// its exact name and type, nothing else.
func decodeRecord(raw []byte) (baselineRecord, error) {
	bad := func(format string, args ...any) (baselineRecord, error) {
		return baselineRecord{}, fmt.Errorf("the stored baseline is not a record safe wrote: "+format, args...)
	}
	members, err := strictjson.ParseObject(bytes.TrimSuffix(raw, []byte("\n")))
	if err != nil || !bytes.HasSuffix(raw, []byte("\n")) || bytes.Count(raw, []byte("\n")) != 1 {
		return bad("not exactly one document")
	}
	names := []string{"schema", "project", "dev", "ino", "btime_sec", "btime_nsec", "name", "digest", "lockfile_base64"}
	if len(members) != len(names) {
		return bad("members differ from the ones safe writes")
	}
	if err := strictjson.RejectVariants(members, names...); err != nil {
		return bad("%v", err)
	}
	for _, name := range names {
		value, ok := members[name]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return bad("member %q is missing", name)
		}
	}
	var rec baselineRecord
	var content string
	typed := []struct {
		name string
		into any
	}{
		{"schema", &rec.Schema}, {"project", &rec.Project}, {"dev", &rec.Identity.Dev}, {"ino", &rec.Identity.Ino},
		{"btime_sec", &rec.Identity.BtimeSec}, {"btime_nsec", &rec.Identity.BtimeNsec}, {"name", &rec.Name},
		{"digest", &rec.Digest}, {"lockfile_base64", &content},
	}
	for _, item := range typed {
		decoder := json.NewDecoder(bytes.NewReader(members[item.name]))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(item.into); err != nil {
			return bad("member %q has the wrong type", item.name)
		}
	}
	if rec.Schema != baselineSchema || rec.Identity.Ino == 0 {
		return bad("schema or identity")
	}
	rec.Lockfile, err = base64.StdEncoding.Strict().DecodeString(content)
	if err != nil || len(rec.Lockfile) == 0 || rec.Digest != digestOf(rec.Lockfile) {
		return bad("the lockfile does not match its digest")
	}
	return rec, nil
}

// ReadBaseline returns the lockfile of the record of the given kind kept for the
// project the descriptor holds. StoredAbsent with no error: none stored. An error:
// something is stored (or in the way, or the identity cannot be established) and
// cannot be trusted.
func ReadBaseline(stateDir string, projectFD int, name string, kind RecordKind) ([]byte, StoredStatus, error) {
	if !baselineNameOK(name) {
		return nil, StoredAbsent, fmt.Errorf("%q is not a lockfile name", name)
	}
	dir, project, id, idErr := baselineHandle(stateDir, projectFD, false)
	if dir == nil {
		if errors.Is(idErr, os.ErrNotExist) {
			return nil, StoredAbsent, nil
		}
		return nil, StoredAbsent, idErr
	}
	defer dir.Close()
	raw, info, rerr := dir.readRegular(recordFile(name, kind), baselineMaxSize*2)
	if errors.Is(rerr, os.ErrNotExist) {
		return nil, StoredAbsent, nil
	}
	if rerr != nil {
		return nil, StoredAbsent, fmt.Errorf("the stored baseline cannot be read: %w", rerr)
	}
	if !ownedByUs(info) || info.Mode().Perm() != 0o600 {
		return nil, StoredAbsent, errors.New("the stored baseline is not a private (0600) file of this user")
	}
	rec, derr := decodeRecord(raw)
	if derr != nil {
		return nil, StoredAbsent, derr
	}
	if rec.Name != name || rec.Project != project {
		return nil, StoredAbsent, errors.New("the stored baseline is for another project or name")
	}
	if idErr != nil {
		return nil, StoredAbsent, idErr
	}
	if rec.Identity != id {
		return nil, StoredAbsent, errors.New("the stored baseline was taken in another incarnation of this project directory (its device, inode or birth time differ)")
	}
	return rec.Lockfile, StoredFound, nil
}

var baselineNameRE = func() func(string) bool {
	return func(name string) bool {
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
}()

func baselineNameOK(name string) bool { return baselineNameRE(name) }

// WriteBaseline stores content as the record of the given kind for the project the
// descriptor holds, atomically (written whole to a private temporary name and
// renamed over the previous record). ErrNoIdentity: nothing can be stored here.
func WriteBaseline(stateDir string, projectFD int, name string, kind RecordKind, content []byte) error {
	if !baselineNameOK(name) {
		return fmt.Errorf("%q is not a lockfile name", name)
	}
	if len(content) == 0 || len(content) > baselineMaxSize {
		return errors.New("the baseline is empty or too large")
	}
	dir, project, id, idErr := baselineHandle(stateDir, projectFD, true)
	if dir == nil {
		return idErr
	}
	defer dir.Close()
	if idErr != nil {
		return idErr
	}
	document, merr := json.Marshal(struct {
		Schema   int    `json:"schema"`
		Project  string `json:"project"`
		Dev      uint64 `json:"dev"`
		Ino      uint64 `json:"ino"`
		BSec     int64  `json:"btime_sec"`
		BNsec    uint32 `json:"btime_nsec"`
		Name     string `json:"name"`
		Digest   string `json:"digest"`
		Lockfile string `json:"lockfile_base64"`
	}{baselineSchema, project, id.Dev, id.Ino, id.BtimeSec, id.BtimeNsec, name, digestOf(content), base64.StdEncoding.EncodeToString(content)})
	if merr != nil {
		return merr
	}
	random, rerr := randomName()
	if rerr != nil {
		return rerr
	}
	temp := ".new-" + random
	if _, cerr := dir.createExclusive(temp, append(document, '\n'), 0o600); cerr != nil {
		return cerr
	}
	ferr := fault("baseline:rename")
	if ferr == nil {
		ferr = renameat2(dir, temp, dir, recordFile(name, kind), 0)
	}
	if ferr != nil {
		_ = dir.remove(temp)
		return ferr
	}
	return nil
}

// ConfirmBaseline makes the pending record the current one (an atomic rename), after
// reading it as strictly as any other read. StoredAbsent: there is no pending record.
func ConfirmBaseline(stateDir string, projectFD int, name string) (StoredStatus, error) {
	if _, status, rerr := ReadBaseline(stateDir, projectFD, name, RecordPending); rerr != nil || status == StoredAbsent {
		return status, rerr
	}
	dir, _, _, idErr := baselineHandle(stateDir, projectFD, false)
	if dir == nil {
		return StoredAbsent, idErr
	}
	defer dir.Close()
	if ferr := fault("baseline:confirm"); ferr != nil {
		return StoredFound, ferr
	}
	if rerr := renameat2(dir, recordFile(name, RecordPending), dir, recordFile(name, RecordCurrent), 0); rerr != nil {
		return StoredFound, rerr
	}
	return StoredFound, nil
}

// DropPending removes the pending record, if any.
func DropPending(stateDir string, projectFD int, name string) error {
	if !baselineNameOK(name) {
		return fmt.Errorf("%q is not a lockfile name", name)
	}
	dir, _, _, idErr := baselineHandle(stateDir, projectFD, false)
	if dir == nil {
		if errors.Is(idErr, os.ErrNotExist) {
			return nil
		}
		return idErr
	}
	defer dir.Close()
	if rerr := dir.remove(recordFile(name, RecordPending)); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
		return rerr
	}
	return nil
}
