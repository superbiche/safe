//go:build linux

package projectlane

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const lockName = "package-lock.json"

func baselineFx(t *testing.T) (state, project string) {
	t.Helper()
	state = evalDir(t)
	if err := os.Chmod(state, 0o700); err != nil {
		t.Fatal(err)
	}
	return state, evalDir(t)
}

func digestHex(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

func recordDirPath(state, project string) string {
	key := sha256.Sum256([]byte(project))
	return filepath.Join(state, baselineDir, hex.EncodeToString(key[:]), lockName)
}

func recordFilePath(state, project, content string) string {
	return filepath.Join(recordDirPath(state, project), digestHex(content))
}

func mustRecord(t *testing.T, state, project, content string, keep int) {
	t.Helper()
	if err := RecordBaseline(state, project, lockName, []byte(content), keep); err != nil {
		t.Fatal(err)
	}
}

func TestRecordedBaselineRoundTripAndLatest(t *testing.T) {
	state, project := baselineFx(t)
	if _, found, ignored, err := LatestRecorded(state, project, lockName); err != nil || found || len(ignored) != 0 {
		t.Fatalf("nothing recorded: %v %v %v", found, ignored, err)
	}
	mustRecord(t, state, project, `{"a":1}`, BaselineKeep)
	got, found, ignored, err := ReadRecorded(state, project, lockName, digestHex(`{"a":1}`))
	if err != nil || !found || string(got) != `{"a":1}` || len(ignored) != 0 {
		t.Fatalf("read by digest: %q %v %v %v", got, found, ignored, err)
	}
	info, _ := os.Stat(recordFilePath(state, project, `{"a":1}`))
	if info.Mode() != 0o600 {
		t.Fatalf("mode = %v", info.Mode())
	}
	// the digest of something never recorded
	if _, found, _, _ := ReadRecorded(state, project, lockName, digestHex("other")); found {
		t.Fatal("found a record that was never written")
	}
	// the most recently written one is the latest, and writing a known one again refreshes its time
	past := time.Now().Add(-time.Hour)
	_ = os.Chtimes(recordFilePath(state, project, `{"a":1}`), past, past)
	mustRecord(t, state, project, `{"b":2}`, BaselineKeep)
	if got, _, _, _ := LatestRecorded(state, project, lockName); string(got) != `{"b":2}` {
		t.Fatalf("latest = %q", got)
	}
	_ = os.Chtimes(recordFilePath(state, project, `{"b":2}`), past.Add(-time.Hour), past.Add(-time.Hour))
	mustRecord(t, state, project, `{"a":1}`, BaselineKeep) // a no-op that refreshes its time
	if got, _, _, _ := LatestRecorded(state, project, lockName); string(got) != `{"a":1}` {
		t.Fatalf("latest after refresh = %q", got)
	}
	entries, _ := os.ReadDir(recordDirPath(state, project))
	if len(entries) != 2 {
		t.Fatalf("entries: %v", entries)
	}
	// another project and another name have their own records
	_, other := baselineFx(t)
	if _, found, _, _ := LatestRecorded(state, other, lockName); found {
		t.Fatal("another project found a record")
	}
	if _, found, _, _ := LatestRecorded(state, project, "other.json"); found {
		t.Fatal("another name found a record")
	}
}

func TestRecordedBaselinePrunesTheOldest(t *testing.T) {
	state, project := baselineFx(t)
	base := time.Now().Add(-10 * time.Hour)
	for i := 0; i < 6; i++ {
		content := fmt.Sprintf(`{"n":%d}`, i)
		mustRecord(t, state, project, content, 3)
		at := base.Add(time.Duration(i) * time.Hour)
		_ = os.Chtimes(recordFilePath(state, project, content), at, at)
	}
	mustRecord(t, state, project, `{"n":6}`, 3)
	entries, _ := os.ReadDir(recordDirPath(state, project))
	if len(entries) != 3 {
		t.Fatalf("kept %d records, want 3", len(entries))
	}
	for _, want := range []string{`{"n":6}`, `{"n":5}`, `{"n":4}`} {
		if _, err := os.Stat(recordFilePath(state, project, want)); err != nil {
			t.Fatalf("the most recent record %s was pruned", want)
		}
	}
	if _, err := os.Stat(recordFilePath(state, project, `{"n":0}`)); err == nil {
		t.Fatal("the oldest record was kept")
	}
}

// A record that is not trusted is IGNORED, named, and never an error.
func TestRecordedBaselineIgnoresWhatItCannotTrust(t *testing.T) {
	content := `{"a":1}`
	cases := map[string]func(t *testing.T, path string){
		"bytes do not hash to the name": func(t *testing.T, path string) { _ = os.WriteFile(path, []byte(`{"a":2}`), 0o600) },
		"truncated":                     func(t *testing.T, path string) { _ = os.WriteFile(path, []byte(`{"a"`), 0o600) },
		"empty":                         func(t *testing.T, path string) { _ = os.WriteFile(path, nil, 0o600) },
		"a link": func(t *testing.T, path string) {
			real := path + ".real"
			_ = os.Rename(path, real)
			if err := os.Symlink(real, path); err != nil {
				t.Fatal(err)
			}
		},
		"a directory":        func(t *testing.T, path string) { _ = os.Remove(path); _ = os.Mkdir(path, 0o700) },
		"readable by others": func(t *testing.T, path string) { _ = os.Chmod(path, 0o644) },
		"executable":         func(t *testing.T, path string) { _ = os.Chmod(path, 0o700) },
		"read-only":          func(t *testing.T, path string) { _ = os.Chmod(path, 0o400) },
		"sticky bit":         func(t *testing.T, path string) { _ = os.Chmod(path, os.ModeSticky|0o600) },
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			state, project := baselineFx(t)
			mustRecord(t, state, project, content, BaselineKeep)
			tamper(t, recordFilePath(state, project, content))
			got, found, ignored, err := ReadRecorded(state, project, lockName, digestHex(content))
			if err != nil || found || len(ignored) != 1 || ignored[0].Digest != digestHex(content) {
				t.Fatalf("by digest: %q found=%v ignored=%v err=%v", got, found, ignored, err)
			}
			_, found, ignored, err = LatestRecorded(state, project, lockName)
			if err != nil || found || len(ignored) != 1 {
				t.Fatalf("latest: found=%v ignored=%v err=%v", found, ignored, err)
			}
		})
	}
	// an untrusted newer record does not hide a trusted older one
	state, project := baselineFx(t)
	mustRecord(t, state, project, `{"good":1}`, BaselineKeep)
	past := time.Now().Add(-time.Hour)
	_ = os.Chtimes(recordFilePath(state, project, `{"good":1}`), past, past)
	mustRecord(t, state, project, `{"bad":1}`, BaselineKeep)
	_ = os.WriteFile(recordFilePath(state, project, `{"bad":1}`), []byte("x"), 0o600)
	got, found, ignored, _ := LatestRecorded(state, project, lockName)
	if !found || string(got) != `{"good":1}` || len(ignored) != 1 {
		t.Fatalf("latest = %q %v %v", got, found, ignored)
	}
}

func TestRecordedBaselineStateDirectoryThatCannotBeTrusted(t *testing.T) {
	state, project := baselineFx(t)
	mustRecord(t, state, project, `{"a":1}`, BaselineKeep)
	if err := os.Chmod(state, 0o770); err != nil {
		t.Fatal(err)
	}
	// writing refuses (the command then refuses before publishing) ...
	if err := RecordBaseline(state, project, lockName, []byte(`{"b":1}`), BaselineKeep); err == nil {
		t.Fatal("recorded into a state directory others can write")
	}
	// ... reading trusts nothing in it, without an error
	got, found, ignored, err := LatestRecorded(state, project, lockName)
	if err != nil || found || len(ignored) == 0 {
		t.Fatalf("read: %q %v %v %v", got, found, ignored, err)
	}
	// a linked baseline directory is the same
	state, project = baselineFx(t)
	mustRecord(t, state, project, `{"a":1}`, BaselineKeep)
	moved := filepath.Join(state, "moved")
	_ = os.Rename(filepath.Join(state, baselineDir), moved)
	if err := os.Symlink(moved, filepath.Join(state, baselineDir)); err != nil {
		t.Fatal(err)
	}
	if _, found, _, _ := LatestRecorded(state, project, lockName); found {
		t.Fatal("trusted through a link")
	}
	if err := RecordBaseline(state, project, lockName, []byte(`{"b":1}`), BaselineKeep); err == nil {
		t.Fatal("recorded through a link")
	}
}

func TestRecordedBaselineWriteIsAtomic(t *testing.T) {
	state, project := baselineFx(t)
	mustRecord(t, state, project, `{"old":1}`, BaselineKeep)
	faultHook = func(op string) error {
		if op == "baseline:rename" {
			return errors.New("disk on fire")
		}
		return nil
	}
	t.Cleanup(func() { faultHook = nil })
	if err := RecordBaseline(state, project, lockName, []byte(`{"new":1}`), BaselineKeep); err == nil {
		t.Fatal("a failed write reported success")
	}
	faultHook = nil
	if got, found, _, _ := LatestRecorded(state, project, lockName); !found || string(got) != `{"old":1}` {
		t.Fatalf("the previous record did not survive: %q", got)
	}
	entries, _ := os.ReadDir(recordDirPath(state, project))
	if len(entries) != 1 {
		t.Fatalf("a temporary file is left: %v", entries)
	}
}

func TestRecordedBaselineRefusesWhatIsNotAValidNameProjectOrContent(t *testing.T) {
	state, project := baselineFx(t)
	for _, n := range []string{"", "../x", "a/b", ".hidden", "-x", strings.Repeat("a", 80)} {
		if err := RecordBaseline(state, project, n, []byte(`{}`), BaselineKeep); err == nil {
			t.Fatalf("accepted name %q", n)
		}
	}
	link := filepath.Join(evalDir(t), "link")
	if err := os.Symlink(project, link); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{link, "relative", project + "/../" + filepath.Base(project)} {
		if err := RecordBaseline(state, p, lockName, []byte(`{}`), BaselineKeep); err == nil {
			t.Fatalf("accepted project %q", p)
		}
	}
	if err := RecordBaseline(state, project, lockName, nil, BaselineKeep); err == nil {
		t.Fatal("accepted an empty lockfile")
	}
	if _, _, _, err := ReadRecorded(state, project, lockName, "nothex"); err == nil {
		t.Fatal("accepted a digest that is not a digest")
	}
}

// Two names for one directory are two stores: a missing record only makes more be judged.
func TestRecordedBaselineIsKeyedByThePathTheLaneResolved(t *testing.T) {
	state, project := baselineFx(t)
	mustRecord(t, state, project, `{"a":1}`, BaselineKeep)
	renamed := project + "-renamed"
	if err := os.Rename(project, renamed); err != nil {
		t.Fatal(err)
	}
	if _, found, _, _ := LatestRecorded(state, renamed, lockName); found {
		t.Fatal("a renamed directory inherited a record")
	}
}
