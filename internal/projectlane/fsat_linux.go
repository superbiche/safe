//go:build linux

package projectlane

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// Descriptor-relative filesystem access for the binding transaction.
//
// The transaction holds directory descriptors (the locked project directory,
// the staging directory, the trees it moves) and works RELATIVE to them, so
// that what it checked is what it operates on, whatever happens to the
// pathnames above them meanwhile. Every lookup is a single name below a held
// directory, opened with O_NOFOLLOW: no symbolic link is followed at any
// component (the openat2 RESOLVE_NO_SYMLINKS fallback the design allows, one
// component at a time). Operations that have no descriptor-relative form in
// the standard library (lstat, unlink, rmdir) go through /proc/self/fd/<n>/<name>,
// whose first part is the held directory itself and whose last part is never
// followed.

// fileID is the identity of a filesystem object.
type fileID struct{ dev, ino uint64 }

func idOf(info os.FileInfo) fileID {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return fileID{uint64(stat.Dev), uint64(stat.Ino)}
	}
	return fileID{}
}

// dirHandle owns a directory descriptor.
type dirHandle struct{ f *os.File }

func (d *dirHandle) fd() int { return int(d.f.Fd()) }

func (d *dirHandle) Close() {
	if d != nil && d.f != nil {
		d.f.Close()
	}
}

// procPath names an entry below a held directory.
func (d *dirHandle) procPath(name string) string {
	if name == "" {
		return "/proc/self/fd/" + strconv.Itoa(d.fd())
	}
	return "/proc/self/fd/" + strconv.Itoa(d.fd()) + "/" + name
}

func validName(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "/\x00")
}

func newHandle(fd int, label string) *dirHandle {
	return &dirHandle{f: os.NewFile(uintptr(fd), label)}
}

// openDirPath opens a directory by a path the caller trusts.
func openDirPath(path string) (*dirHandle, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return newHandle(fd, path), nil
}

// dupHandle duplicates a caller's descriptor (close-on-exec): the same open
// file description, so the same flock, owned separately.
func dupHandle(fd int) (*dirHandle, error) {
	dup, err := fcntlDupCloexec(fd)
	if err != nil {
		return nil, err
	}
	return newHandle(dup, "dup"), nil
}

func fcntlDupCloexec(fd int) (int, error) {
	const fDupfdCloexec = 1030
	r, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), fDupfdCloexec, 3)
	if errno != 0 {
		return -1, errno
	}
	return int(r), nil
}

// openDirNoFollow opens the directory called name below d. A symbolic link, a
// file or a missing name is an error; ENOENT stays distinguishable.
func (d *dirHandle) openDirNoFollow(name string) (*dirHandle, error) {
	if !validName(name) {
		return nil, fmt.Errorf("%q is not a plain name", name)
	}
	fd, err := syscall.Openat(d.fd(), name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "openat", Path: name, Err: err}
	}
	return newHandle(fd, name), nil
}

// walk opens a directory by a relative path, one component at a time, never
// following a link. An empty path returns a duplicate of d.
func (d *dirHandle) walk(rel string) (*dirHandle, error) {
	current, err := dupHandle(d.fd())
	if err != nil {
		return nil, err
	}
	if rel == "" {
		return current, nil
	}
	for _, part := range strings.Split(rel, "/") {
		next, err := current.openDirNoFollow(part)
		current.Close()
		if err != nil {
			return nil, err
		}
		current = next
	}
	return current, nil
}

func (d *dirHandle) lstat(name string) (os.FileInfo, error) {
	if !validName(name) {
		return nil, fmt.Errorf("%q is not a plain name", name)
	}
	return os.Lstat(d.procPath(name))
}

func (d *dirHandle) id() (fileID, error) {
	info, err := d.f.Stat()
	if err != nil {
		return fileID{}, err
	}
	return idOf(info), nil
}

// mountID reads the mount a descriptor lives on. Two directories of one
// device can still be on different mounts (a bind mount): the device number
// alone does not say.
func (d *dirHandle) mountID() (string, error) {
	file, err := os.Open("/proc/self/fdinfo/" + strconv.Itoa(d.fd()))
	if err != nil {
		return "", err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if value, ok := strings.CutPrefix(scanner.Text(), "mnt_id:"); ok {
			return strings.TrimSpace(value), nil
		}
	}
	return "", errors.New("no mnt_id in fdinfo")
}

// readRegular reads a regular file below d without following a link, refusing
// anything else and anything with set-id or sticky bits.
func (d *dirHandle) readRegular(name string, limit int64) ([]byte, os.FileInfo, error) {
	if !validName(name) {
		return nil, nil, fmt.Errorf("%q is not a plain name", name)
	}
	fd, err := syscall.Openat(d.fd(), name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, &os.PathError{Op: "openat", Path: name, Err: err}
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, info, fmt.Errorf("%s is not a regular file", name)
	}
	if info.Size() > limit {
		return nil, info, fmt.Errorf("%s is larger than %d bytes", name, limit)
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, info, err
	}
	if int64(len(raw)) > limit {
		return nil, info, fmt.Errorf("%s is larger than %d bytes", name, limit)
	}
	return raw, info, nil
}

// createExclusive creates name below d, failing if it exists, with the
// creation mask applied (mode 0666 &^ umask) unless perm is non-zero, in
// which case the file gets exactly that mode (fchmod: the mask does not apply).
func (d *dirHandle) createExclusive(name string, content []byte, perm os.FileMode) (fileID, error) {
	if !validName(name) {
		return fileID{}, fmt.Errorf("%q is not a plain name", name)
	}
	fd, err := syscall.Openat(d.fd(), name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o666)
	if err != nil {
		return fileID{}, &os.PathError{Op: "openat", Path: name, Err: err}
	}
	file := os.NewFile(uintptr(fd), name)
	fail := func(err error) (fileID, error) {
		file.Close()
		_ = os.Remove(d.procPath(name))
		return fileID{}, err
	}
	if _, err := file.Write(content); err != nil {
		return fail(err)
	}
	if perm != 0 {
		if err := file.Chmod(perm); err != nil {
			return fail(err)
		}
	}
	if err := file.Sync(); err != nil {
		return fail(err)
	}
	info, err := file.Stat()
	if err != nil {
		return fail(err)
	}
	return idOf(info), file.Close()
}

// afterCreateMode is a test seam: called with the file the moment it exists, before anything else is done to it.
var afterCreateMode func(*os.File)

// createExclusiveMode creates name below d, failing if it exists, with exactly the final mode perm from the first moment (the
// mode is given to the creating call, so the file is never wider than it will stay; the creation mask can only narrow it, and
// the mode is then set to perm). It writes content, syncs and closes.
func (d *dirHandle) createExclusiveMode(name string, content []byte, perm os.FileMode) (fileID, error) {
	if !validName(name) {
		return fileID{}, fmt.Errorf("%q is not a plain name", name)
	}
	fd, err := syscall.Openat(d.fd(), name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, uint32(perm.Perm()))
	if err != nil {
		return fileID{}, &os.PathError{Op: "openat", Path: name, Err: err}
	}
	file := os.NewFile(uintptr(fd), name)
	fail := func(err error) (fileID, error) {
		file.Close()
		_ = os.Remove(d.procPath(name))
		return fileID{}, err
	}
	if afterCreateMode != nil {
		afterCreateMode(file)
	}
	if err := file.Chmod(perm.Perm()); err != nil {
		return fail(err)
	}
	if _, err := file.Write(content); err != nil {
		return fail(err)
	}
	if err := file.Sync(); err != nil {
		return fail(err)
	}
	info, err := file.Stat()
	if err != nil {
		return fail(err)
	}
	return idOf(info), file.Close()
}

func (d *dirHandle) mkdir(name string, perm uint32) error {
	if !validName(name) {
		return fmt.Errorf("%q is not a plain name", name)
	}
	return syscall.Mkdirat(d.fd(), name, perm)
}

// remove unlinks a file, or removes an empty directory; a link is removed, not
// followed.
func (d *dirHandle) remove(name string) error {
	if !validName(name) {
		return fmt.Errorf("%q is not a plain name", name)
	}
	return os.Remove(d.procPath(name))
}

const (
	renameNoReplace = 1
	renameExchange  = 2
)

// renameat2 moves or exchanges two entries given as (directory, name) pairs.
func renameat2(oldDir *dirHandle, oldName string, newDir *dirHandle, newName string, flags uintptr) error {
	if renameat2Number == 0 {
		return syscall.ENOSYS
	}
	if !validName(oldName) || !validName(newName) {
		return fmt.Errorf("not plain names: %q, %q", oldName, newName)
	}
	from, err := syscall.BytePtrFromString(oldName)
	if err != nil {
		return err
	}
	to, err := syscall.BytePtrFromString(newName)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(renameat2Number, uintptr(oldDir.fd()), uintptr(unsafe.Pointer(from)),
		uintptr(newDir.fd()), uintptr(unsafe.Pointer(to)), flags, 0)
	if errno != 0 {
		return &os.LinkError{Op: "renameat2", Old: oldName, New: newName, Err: errno}
	}
	return nil
}

func exchange(aDir *dirHandle, aName string, bDir *dirHandle, bName string) error {
	return renameat2(aDir, aName, bDir, bName, renameExchange)
}

func moveNoReplace(aDir *dirHandle, aName string, bDir *dirHandle, bName string) error {
	return renameat2(aDir, aName, bDir, bName, renameNoReplace)
}

// removeAllAt removes the directory name below parent and everything in it
// without following a link and without leaving the mount it started on: a
// directory on another device or another mount (a bind mount of the same
// device included) stops the removal and is reported, never entered.
func removeAllAt(parent *dirHandle, name string, rootDev fileID, rootMount string) error {
	child, err := parent.openDirNoFollow(name)
	if err != nil {
		return err
	}
	defer child.Close()
	id, err := child.id()
	if err != nil {
		return err
	}
	mount, err := child.mountID()
	if err != nil {
		return err
	}
	if id.dev != rootDev.dev || mount != rootMount {
		return fmt.Errorf("%s is on another mount or device", name)
	}
	// A read-only directory (npm leaves some) must be writable to be emptied.
	_ = syscall.Fchmod(child.fd(), 0o700)
	entries, err := child.f.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		info, err := child.lstat(entry.Name())
		if err != nil {
			return err
		}
		if info.IsDir() {
			if err := removeAllAt(child, entry.Name(), rootDev, rootMount); err != nil {
				return err
			}
			continue
		}
		if err := child.remove(entry.Name()); err != nil {
			return err
		}
	}
	return parent.remove(name)
}

// names lists the entries of the directory, through a fresh open file
// description (a duplicated descriptor shares its read offset with its owner).
func (d *dirHandle) names() ([]string, error) {
	fd, err := syscall.Openat(d.fd(), ".", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	listing := newHandle(fd, "listing")
	defer listing.Close()
	entries, err := listing.f.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names, nil
}

// hasNo reports that nothing is named so in the directory.
func (d *dirHandle) hasNo(name string) bool {
	_, err := d.lstat(name)
	return errors.Is(err, os.ErrNotExist)
}
