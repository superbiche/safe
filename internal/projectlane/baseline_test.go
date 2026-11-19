//go:build linux

package projectlane

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type heldProject struct {
	state, path string
	file        *os.File
}

func (h heldProject) fd() int { return int(h.file.Fd()) }

func holdProject(t *testing.T, state string) heldProject {
	t.Helper()
	path := evalDir(t)
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { file.Close() })
	return heldProject{state: state, path: path, file: file}
}

func baselineFx(t *testing.T) (string, heldProject) {
	t.Helper()
	state := evalDir(t)
	if err := os.Chmod(state, 0o700); err != nil {
		t.Fatal(err)
	}
	return state, holdProject(t, state)
}

func recordPath(state, project, name string, kind RecordKind) string {
	key := sha256.Sum256([]byte(project))
	return filepath.Join(state, baselineDir, hex.EncodeToString(key[:]), recordFile(name, kind))
}

const lockName = "package-lock.json"

func TestBaselineRoundTripReplacementAndKinds(t *testing.T) {
	state, p := baselineFx(t)
	if _, status, err := ReadBaseline(state, p.fd(), lockName, RecordCurrent); err != nil || status != StoredAbsent {
		t.Fatalf("empty store: %v, %v", status, err)
	}
	if err := WriteBaseline(state, p.fd(), lockName, RecordCurrent, []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	got, status, err := ReadBaseline(state, p.fd(), lockName, RecordCurrent)
	if err != nil || status != StoredFound || string(got) != `{"a":1}` {
		t.Fatalf("read: %q %v %v", got, status, err)
	}
	// the pending record is another record
	if _, status, err := ReadBaseline(state, p.fd(), lockName, RecordPending); err != nil || status != StoredAbsent {
		t.Fatalf("pending before: %v %v", status, err)
	}
	if err := WriteBaseline(state, p.fd(), lockName, RecordPending, []byte(`{"b":2}`)); err != nil {
		t.Fatal(err)
	}
	got, _, _ = ReadBaseline(state, p.fd(), lockName, RecordCurrent)
	if string(got) != `{"a":1}` {
		t.Fatalf("a pending record replaced the current one: %q", got)
	}
	info, _ := os.Stat(recordPath(state, p.path, lockName, RecordPending))
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v", info.Mode())
	}
	// confirm: the pending record becomes the current one and is gone as pending
	if status, err := ConfirmBaseline(state, p.fd(), lockName); err != nil || status != StoredFound {
		t.Fatalf("confirm: %v %v", status, err)
	}
	got, _, _ = ReadBaseline(state, p.fd(), lockName, RecordCurrent)
	if string(got) != `{"b":2}` {
		t.Fatalf("confirmed: %q", got)
	}
	if _, status, _ := ReadBaseline(state, p.fd(), lockName, RecordPending); status != StoredAbsent {
		t.Fatal("the pending record survived its confirmation")
	}
	if status, err := ConfirmBaseline(state, p.fd(), lockName); err != nil || status != StoredAbsent {
		t.Fatalf("confirm with nothing pending: %v %v", status, err)
	}
	// drop
	if err := WriteBaseline(state, p.fd(), lockName, RecordPending, []byte(`{"c":3}`)); err != nil {
		t.Fatal(err)
	}
	if err := DropPending(state, p.fd(), lockName); err != nil {
		t.Fatal(err)
	}
	if err := DropPending(state, p.fd(), lockName); err != nil {
		t.Fatalf("dropping nothing: %v", err)
	}
	entries, _ := os.ReadDir(filepath.Dir(recordPath(state, p.path, lockName, RecordCurrent)))
	if len(entries) != 1 {
		t.Fatalf("leftover entries: %v", entries)
	}
	// another name and another project are other records
	if _, status, _ := ReadBaseline(state, p.fd(), "other.json", RecordCurrent); status != StoredAbsent {
		t.Fatal("another name found a baseline")
	}
	other := holdProject(t, state)
	if _, status, err := ReadBaseline(state, other.fd(), lockName, RecordCurrent); err != nil || status != StoredAbsent {
		t.Fatalf("another project: %v %v", status, err)
	}
}

// The record belongs to the directory the descriptor holds: a different directory at the
// same path is NOT "none stored", it is unreadable evidence, whatever the inode it got.
func TestBaselineOfAnotherIncarnationOfTheDirectoryIsUnreadable(t *testing.T) {
	state, p := baselineFx(t)
	if err := WriteBaseline(state, p.fd(), lockName, RecordCurrent, []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	// An ordinary edit of the directory (a file made and removed in it) keeps the identity.
	if err := os.WriteFile(filepath.Join(p.path, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(p.path, "f"))
	if _, status, err := ReadBaseline(state, p.fd(), lockName, RecordCurrent); err != nil || status != StoredFound {
		t.Fatalf("an edit changed the identity: %v %v", status, err)
	}
	// Delete and recreate it at the same path, until the filesystem hands the same inode back.
	old := p.file
	oldID, _ := identityOfFD(int(old.Fd()))
	old.Close() // the old inode is free to be handed out again
	reused := false
	for i := 0; i < 400; i++ {
		if err := os.Remove(p.path); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(p.path, 0o755); err != nil {
			t.Fatal(err)
		}
		fresh, err := os.Open(p.path)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := identityOfFD(int(fresh.Fd()))
		content, status, rerr := ReadBaseline(state, int(fresh.Fd()), lockName, RecordCurrent)
		if rerr == nil {
			fresh.Close()
			t.Fatalf("iteration %d: the old record was returned for a recreated directory (found %v, %q)", i, status, content)
		}
		if id.Dev == oldID.Dev && id.Ino == oldID.Ino {
			reused = true
			if id.BtimeSec == oldID.BtimeSec && id.BtimeNsec == oldID.BtimeNsec {
				fresh.Close()
				t.Fatal("the recreated directory has the very birth time of the old one")
			}
			fresh.Close()
			break
		}
		fresh.Close()
	}
	t.Logf("inode reused by the filesystem: %v", reused)
	if !reused {
		t.Log("the filesystem did not hand the inode back; the other-inode case was asserted instead")
	}
}

func TestBaselineRecordForAnotherBirthTimeIsUnreadable(t *testing.T) {
	state, p := baselineFx(t)
	if err := WriteBaseline(state, p.fd(), lockName, RecordCurrent, []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	record := recordPath(state, p.path, lockName, RecordCurrent)
	raw, _ := os.ReadFile(record)
	edited := strings.Replace(string(raw), `"btime_nsec":`, `"btime_nsec":1`, 1)
	if edited == string(raw) {
		t.Fatal("fixture")
	}
	if err := os.WriteFile(record, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadBaseline(state, p.fd(), lockName, RecordCurrent); err == nil {
		t.Fatal("a record with another birth time was trusted")
	}
}

func TestBaselineWithoutAnEstablishedIdentityStoresNothingAndReadsNothingItHolds(t *testing.T) {
	state, p := baselineFx(t)
	if err := WriteBaseline(state, p.fd(), lockName, RecordCurrent, []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	identityOf = func(fd int) (DirIdentity, error) {
		id, _ := identityOfFD(fd)
		return id, ErrNoIdentity
	}
	t.Cleanup(func() { identityOf = identityOfFD })
	if err := WriteBaseline(state, p.fd(), lockName, RecordPending, []byte(`{"b":1}`)); !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("write: %v", err)
	}
	// a record exists and the identity cannot be compared: unreadable, never "none stored"
	if _, _, err := ReadBaseline(state, p.fd(), lockName, RecordCurrent); err == nil {
		t.Fatal("a record was trusted without an identity")
	}
	// nothing is stored at all: absent, no error
	other := holdProject(t, state)
	if _, status, err := ReadBaseline(state, other.fd(), lockName, RecordCurrent); err != nil || status != StoredAbsent {
		t.Fatalf("nothing stored: %v %v", status, err)
	}
	if _, err := os.Stat(recordPath(state, other.path, lockName, RecordPending)); err == nil {
		t.Fatal("a record was written without an identity")
	}
}

// Every malformation is an error: none is "none stored", none is trusted.
func TestBaselineStrictReader(t *testing.T) {
	good := func(t *testing.T, state string, p heldProject) (string, map[string]string) {
		if err := WriteBaseline(state, p.fd(), lockName, RecordCurrent, []byte(`{"a":1}`)); err != nil {
			t.Fatal(err)
		}
		record := recordPath(state, p.path, lockName, RecordCurrent)
		raw, _ := os.ReadFile(record)
		fields := map[string]string{}
		for _, part := range strings.Split(strings.Trim(strings.TrimSpace(string(raw)), "{}"), ",\"") {
			part = strings.TrimPrefix(part, `"`)
			key, value, _ := strings.Cut(part, `":`)
			fields[key] = value
		}
		return record, fields
	}
	rebuild := func(fields map[string]string, order ...string) string {
		var parts []string
		for _, key := range order {
			parts = append(parts, fmt.Sprintf("%q:%s", key, fields[key]))
		}
		return "{" + strings.Join(parts, ",") + "}\n"
	}
	order := []string{"schema", "project", "dev", "ino", "btime_sec", "btime_nsec", "name", "digest", "lockfile_base64"}
	cases := map[string]func(t *testing.T, record string, fields map[string]string){
		"missing dev": func(t *testing.T, record string, f map[string]string) {
			put := rebuild(f, []string{"schema", "project", "ino", "btime_sec", "btime_nsec", "name", "digest", "lockfile_base64"}...)
			_ = os.WriteFile(record, []byte(put), 0o600)
		},
		"missing ino": func(t *testing.T, record string, f map[string]string) {
			_ = os.WriteFile(record, []byte(rebuild(f, []string{"schema", "project", "dev", "btime_sec", "btime_nsec", "name", "digest", "lockfile_base64"}...)), 0o600)
		},
		"missing birth time": func(t *testing.T, record string, f map[string]string) {
			_ = os.WriteFile(record, []byte(rebuild(f, []string{"schema", "project", "dev", "ino", "name", "digest", "lockfile_base64"}...)), 0o600)
		},
		"null member": func(t *testing.T, record string, f map[string]string) {
			f["ino"] = "null"
			_ = os.WriteFile(record, []byte(rebuild(f, order...)), 0o600)
		},
		"wrong type": func(t *testing.T, record string, f map[string]string) {
			f["dev"] = `"7"`
			_ = os.WriteFile(record, []byte(rebuild(f, order...)), 0o600)
		},
		"a second spelling of a member": func(t *testing.T, record string, f map[string]string) {
			raw, _ := os.ReadFile(record)
			_ = os.WriteFile(record, []byte(strings.Replace(string(raw), `"dev":`, `"Dev":0,"dev":`, 1)), 0o600)
		},
		"a repeated member": func(t *testing.T, record string, f map[string]string) {
			raw, _ := os.ReadFile(record)
			_ = os.WriteFile(record, []byte(strings.Replace(string(raw), `"ino":`, `"ino":0,"ino":`, 1)), 0o600)
		},
		"an extra member": func(t *testing.T, record string, f map[string]string) {
			raw, _ := os.ReadFile(record)
			_ = os.WriteFile(record, []byte(strings.Replace(string(raw), `{`, `{"extra":1,`, 1)), 0o600)
		},
		"trailing content": func(t *testing.T, record string, f map[string]string) {
			raw, _ := os.ReadFile(record)
			_ = os.WriteFile(record, append(raw, []byte(`{"second":1}`+"\n")...), 0o600)
		},
		"trailing garbage": func(t *testing.T, record string, f map[string]string) {
			raw, _ := os.ReadFile(record)
			_ = os.WriteFile(record, append(raw, []byte("x")...), 0o600)
		},
		"an executable mode": func(t *testing.T, record string, f map[string]string) { _ = os.Chmod(record, 0o700) },
		"a readable mode":    func(t *testing.T, record string, f map[string]string) { _ = os.Chmod(record, 0o644) },
		"a read-only mode":   func(t *testing.T, record string, f map[string]string) { _ = os.Chmod(record, 0o400) },
		"empty":              func(t *testing.T, record string, f map[string]string) { _ = os.WriteFile(record, nil, 0o600) },
		"not JSON": func(t *testing.T, record string, f map[string]string) {
			_ = os.WriteFile(record, []byte("garbage"), 0o600)
		},
		"another digest": func(t *testing.T, record string, f map[string]string) {
			f["digest"] = `"sha256:` + strings.Repeat("0", 64) + `"`
			_ = os.WriteFile(record, []byte(rebuild(f, order...)), 0o600)
		},
		"another lockfile under the digest": func(t *testing.T, record string, f map[string]string) {
			f["lockfile_base64"] = `"` + base64.StdEncoding.EncodeToString([]byte("{}")) + `"`
			_ = os.WriteFile(record, []byte(rebuild(f, order...)), 0o600)
		},
		"another project": func(t *testing.T, record string, f map[string]string) {
			f["project"] = `"/elsewhere"`
			_ = os.WriteFile(record, []byte(rebuild(f, order...)), 0o600)
		},
		"another name": func(t *testing.T, record string, f map[string]string) {
			f["name"] = `"other.json"`
			_ = os.WriteFile(record, []byte(rebuild(f, order...)), 0o600)
		},
		"a link": func(t *testing.T, record string, f map[string]string) {
			raw, _ := os.ReadFile(record)
			target := record + ".real"
			_ = os.WriteFile(target, raw, 0o600)
			_ = os.Remove(record)
			if err := os.Symlink(target, record); err != nil {
				t.Fatal(err)
			}
		},
		"a directory": func(t *testing.T, record string, f map[string]string) {
			_ = os.Remove(record)
			_ = os.Mkdir(record, 0o700)
		},
		"directory writable by others": func(t *testing.T, record string, f map[string]string) { _ = os.Chmod(filepath.Dir(record), 0o777) },
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			state, p := baselineFx(t)
			record, fields := good(t, state, p)
			tamper(t, record, fields)
			content, status, err := ReadBaseline(state, p.fd(), lockName, RecordCurrent)
			if err == nil {
				t.Fatalf("trusted or taken for absent: %q %v", content, status)
			}
		})
	}
	t.Run("baseline directory a link", func(t *testing.T) {
		state, p := baselineFx(t)
		good(t, state, p)
		real := filepath.Join(state, "moved")
		_ = os.Rename(filepath.Join(state, baselineDir), real)
		if err := os.Symlink(real, filepath.Join(state, baselineDir)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := ReadBaseline(state, p.fd(), lockName, RecordCurrent); err == nil {
			t.Fatal("trusted through a link")
		}
	})
	// the same strictness for a pending record, and confirmation reads it as strictly
	t.Run("a pending record is read as strictly", func(t *testing.T) {
		state, p := baselineFx(t)
		if err := WriteBaseline(state, p.fd(), lockName, RecordPending, []byte(`{"a":1}`)); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(recordPath(state, p.path, lockName, RecordPending), 0o700)
		if _, _, err := ReadBaseline(state, p.fd(), lockName, RecordPending); err == nil {
			t.Fatal("a pending record with an executable mode was trusted")
		}
		if _, err := ConfirmBaseline(state, p.fd(), lockName); err == nil {
			t.Fatal("an untrusted pending record was confirmed")
		}
	})
}

func TestBaselineStateDirectoryThatIsNotPrivateRefusesBothWays(t *testing.T) {
	state, p := baselineFx(t)
	if err := os.Chmod(state, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := WriteBaseline(state, p.fd(), lockName, RecordCurrent, []byte(`{}`)); err == nil {
		t.Fatal("wrote to a state directory others can write")
	}
	if _, _, err := ReadBaseline(state, p.fd(), lockName, RecordCurrent); err == nil {
		t.Fatal("read from a state directory others can write")
	}
}

func TestBaselineWriteAndConfirmAreAtomic(t *testing.T) {
	state, p := baselineFx(t)
	if err := WriteBaseline(state, p.fd(), lockName, RecordCurrent, []byte(`{"old":1}`)); err != nil {
		t.Fatal(err)
	}
	faultHook = func(op string) error {
		if op == "baseline:rename" {
			return errors.New("disk on fire")
		}
		return nil
	}
	t.Cleanup(func() { faultHook = nil })
	if err := WriteBaseline(state, p.fd(), lockName, RecordCurrent, []byte(`{"new":1}`)); err == nil {
		t.Fatal("a failed write reported success")
	}
	faultHook = nil
	got, status, err := ReadBaseline(state, p.fd(), lockName, RecordCurrent)
	if err != nil || status != StoredFound || string(got) != `{"old":1}` {
		t.Fatalf("the previous baseline did not survive: %q %v %v", got, status, err)
	}
	entries, _ := os.ReadDir(filepath.Dir(recordPath(state, p.path, lockName, RecordCurrent)))
	if len(entries) != 1 {
		t.Fatalf("a temporary file is left: %v", entries)
	}
	// a failed confirmation leaves both records as they were
	if err := WriteBaseline(state, p.fd(), lockName, RecordPending, []byte(`{"pending":1}`)); err != nil {
		t.Fatal(err)
	}
	faultHook = func(op string) error {
		if op == "baseline:confirm" {
			return errors.New("disk on fire")
		}
		return nil
	}
	if _, err := ConfirmBaseline(state, p.fd(), lockName); err == nil {
		t.Fatal("a failed confirmation reported success")
	}
	faultHook = nil
	if got, _, _ := ReadBaseline(state, p.fd(), lockName, RecordCurrent); string(got) != `{"old":1}` {
		t.Fatalf("current after a failed confirmation: %q", got)
	}
	if got, status, _ := ReadBaseline(state, p.fd(), lockName, RecordPending); status != StoredFound || string(got) != `{"pending":1}` {
		t.Fatalf("pending after a failed confirmation: %q %v", got, status)
	}
}

func TestBaselineRefusesWhatIsNotAValidNameOrContent(t *testing.T) {
	state, p := baselineFx(t)
	for _, n := range []string{"", "../x", "a/b", ".hidden", "-x", strings.Repeat("a", 80)} {
		if err := WriteBaseline(state, p.fd(), n, RecordCurrent, []byte(`{}`)); err == nil {
			t.Fatalf("accepted name %q", n)
		}
	}
	if err := WriteBaseline(state, p.fd(), lockName, RecordCurrent, nil); err == nil {
		t.Fatal("accepted an empty baseline")
	}
	// a descriptor that is not a directory
	file, _ := os.Open(filepath.Join(state, "..", filepath.Base(state)))
	_ = file
	regular, err := os.CreateTemp(state, "x")
	if err != nil {
		t.Fatal(err)
	}
	defer regular.Close()
	if err := WriteBaseline(state, int(regular.Fd()), lockName, RecordCurrent, []byte(`{}`)); err == nil {
		t.Fatal("accepted a descriptor that is not a directory")
	}
}

// The birth time is available on this machine's filesystems; the test says so rather than assume.
func TestBaselineBirthTimeIsAvailableHere(t *testing.T) {
	_, p := baselineFx(t)
	id, err := identityOfFD(p.fd())
	if err != nil {
		t.Skipf("no birth time on this filesystem: %v", err)
	}
	if id.BtimeSec == 0 && id.BtimeNsec == 0 {
		t.Fatal("a zero birth time")
	}
}
