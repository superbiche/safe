//go:build linux

package projectlane

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func baselineFx(t *testing.T) (state, project string) {
	t.Helper()
	state = evalDir(t)
	if err := os.Chmod(state, 0o700); err != nil {
		t.Fatal(err)
	}
	return state, evalDir(t)
}

func recordPath(state, project, name string) string {
	key := sha256.Sum256([]byte(project))
	return filepath.Join(state, baselineDir, hex.EncodeToString(key[:]), name+".json")
}

func TestBaselineRoundTripAndReplacement(t *testing.T) {
	state, project := baselineFx(t)
	if _, status, err := ReadBaseline(state, project, "package-lock.json"); err != nil || status != StoredAbsent {
		t.Fatalf("empty store: %v, %v", status, err)
	}
	if err := WriteBaseline(state, project, "package-lock.json", []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	got, status, err := ReadBaseline(state, project, "package-lock.json")
	if err != nil || status != StoredFound || string(got) != `{"a":1}` {
		t.Fatalf("read: %q %v %v", got, status, err)
	}
	if err := WriteBaseline(state, project, "package-lock.json", []byte(`{"b":2}`)); err != nil {
		t.Fatal(err)
	}
	got, _, _ = ReadBaseline(state, project, "package-lock.json")
	if string(got) != `{"b":2}` {
		t.Fatalf("replaced: %q", got)
	}
	info, _ := os.Stat(recordPath(state, project, "package-lock.json"))
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v", info.Mode())
	}
	entries, _ := os.ReadDir(filepath.Dir(recordPath(state, project, "package-lock.json")))
	if len(entries) != 1 {
		t.Fatalf("leftover entries: %v", entries)
	}
	// another name and another project are other records
	if _, status, _ := ReadBaseline(state, project, "other.json"); status != StoredAbsent {
		t.Fatal("another name found a baseline")
	}
	_, other := baselineFx(t)
	if _, status, err := ReadBaseline(state, other, "package-lock.json"); err != nil || status != StoredAbsent {
		t.Fatalf("another project: %v %v", status, err)
	}
}

func TestBaselineOfAnotherIncarnationOfTheDirectoryIsNone(t *testing.T) {
	state, project := baselineFx(t)
	if err := WriteBaseline(state, project, "package-lock.json", []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	// the directory is removed and a new one made at the same path (a fresh clone)
	if err := os.Remove(project); err != nil {
		t.Fatal(err)
	}
	// keep the old inode busy so the new directory cannot reuse it
	keep, _ := os.CreateTemp(filepath.Dir(project), "x")
	defer keep.Close()
	if err := os.Mkdir(project, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, status, err := ReadBaseline(state, project, "package-lock.json"); err != nil || status != StoredAbsent {
		t.Skipf("the filesystem reused the inode (%v, %v)", status, err)
	}
}

func TestBaselineThatCannotBeTrustedIsAnErrorNotAnEmptyBaseline(t *testing.T) {
	cases := map[string]func(t *testing.T, state, project, record string){
		"content edited": func(t *testing.T, _, _, record string) {
			raw, _ := os.ReadFile(record)
			edited := strings.Replace(string(raw), `"digest":"`, `"digest":"sha256:00`, 1)
			if err := os.WriteFile(record, []byte(edited), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"lockfile replaced under the digest": func(t *testing.T, _, _, record string) {
			raw, _ := os.ReadFile(record)
			// another valid base64 body: "{}"
			edited := strings.Replace(string(raw), `"lockfile_base64":"`, `"lockfile_base64":"e30=`, 1)
			if err := os.WriteFile(record, []byte(edited), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"not JSON": func(t *testing.T, _, _, record string) { _ = os.WriteFile(record, []byte("garbage"), 0o600) },
		"empty":    func(t *testing.T, _, _, record string) { _ = os.WriteFile(record, nil, 0o600) },
		"unknown member": func(t *testing.T, _, _, record string) {
			raw, _ := os.ReadFile(record)
			_ = os.WriteFile(record, []byte(strings.Replace(string(raw), `{`, `{"extra":1,`, 1)), 0o600)
		},
		"readable by others": func(t *testing.T, _, _, record string) { _ = os.Chmod(record, 0o644) },
		"a link": func(t *testing.T, _, _, record string) {
			raw, _ := os.ReadFile(record)
			target := record + ".real"
			_ = os.WriteFile(target, raw, 0o600)
			_ = os.Remove(record)
			if err := os.Symlink(target, record); err != nil {
				t.Fatal(err)
			}
		},
		"a directory": func(t *testing.T, _, _, record string) {
			_ = os.Remove(record)
			_ = os.Mkdir(record, 0o700)
		},
		"another project's record": func(t *testing.T, state, project, record string) {
			other := filepath.Join(evalDir(t), "other")
			_ = os.Mkdir(other, 0o755)
			if err := WriteBaseline(state, other, "package-lock.json", []byte(`{"z":1}`)); err != nil {
				t.Fatal(err)
			}
			raw, _ := os.ReadFile(recordPath(state, other, "package-lock.json"))
			_ = os.WriteFile(record, raw, 0o600)
		},
		"directory writable by others": func(t *testing.T, _, _, record string) { _ = os.Chmod(filepath.Dir(record), 0o777) },
		"baseline directory a link": func(t *testing.T, state, _, record string) {
			real := filepath.Join(state, "moved")
			_ = os.Rename(filepath.Join(state, baselineDir), real)
			if err := os.Symlink(real, filepath.Join(state, baselineDir)); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			state, project := baselineFx(t)
			if err := WriteBaseline(state, project, "package-lock.json", []byte(`{"a":1}`)); err != nil {
				t.Fatal(err)
			}
			tamper(t, state, project, recordPath(state, project, "package-lock.json"))
			content, status, err := ReadBaseline(state, project, "package-lock.json")
			if err == nil {
				t.Fatalf("trusted: %q %v", content, status)
			}
		})
	}
}

func TestBaselineStateDirectoryThatIsNotPrivateRefusesBothWays(t *testing.T) {
	state, project := baselineFx(t)
	if err := os.Chmod(state, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := WriteBaseline(state, project, "package-lock.json", []byte(`{}`)); err == nil {
		t.Fatal("wrote to a state directory others can write")
	}
	if _, _, err := ReadBaseline(state, project, "package-lock.json"); err == nil {
		t.Fatal("read from a state directory others can write")
	}
}

func TestBaselineWriteIsAtomic(t *testing.T) {
	state, project := baselineFx(t)
	if err := WriteBaseline(state, project, "package-lock.json", []byte(`{"old":1}`)); err != nil {
		t.Fatal(err)
	}
	faultHook = func(op string) error {
		if op == "baseline:rename" {
			return errors.New("disk on fire")
		}
		return nil
	}
	t.Cleanup(func() { faultHook = nil })
	if err := WriteBaseline(state, project, "package-lock.json", []byte(`{"new":1}`)); err == nil {
		t.Fatal("a failed write reported success")
	}
	faultHook = nil
	got, status, err := ReadBaseline(state, project, "package-lock.json")
	if err != nil || status != StoredFound || string(got) != `{"old":1}` {
		t.Fatalf("the previous baseline did not survive: %q %v %v", got, status, err)
	}
	entries, _ := os.ReadDir(filepath.Dir(recordPath(state, project, "package-lock.json")))
	if len(entries) != 1 {
		t.Fatalf("a temporary file is left: %v", entries)
	}
}

func TestBaselineRefusesWhatIsNotACanonicalProjectOrName(t *testing.T) {
	state, project := baselineFx(t)
	link := filepath.Join(evalDir(t), "link")
	if err := os.Symlink(project, link); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{link, "relative", project + "/../" + filepath.Base(project)} {
		if err := WriteBaseline(state, p, "package-lock.json", []byte(`{}`)); err == nil {
			t.Fatalf("accepted project %q", p)
		}
	}
	for _, n := range []string{"", "../x", "a/b", ".hidden", strings.Repeat("a", 80)} {
		if err := WriteBaseline(state, project, n, []byte(`{}`)); err == nil {
			t.Fatalf("accepted name %q", n)
		}
	}
	if err := WriteBaseline(state, project, "package-lock.json", nil); err == nil {
		t.Fatal("accepted an empty baseline")
	}
}
