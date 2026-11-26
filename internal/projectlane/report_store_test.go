//go:build linux

package projectlane

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func reportData(t *testing.T) (ReportStore, string) {
	t.Helper()
	data, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(data, "project-lane", "reports"), 0o700); err != nil {
		t.Fatal(err)
	}
	return ReportStore{Data: data}, data
}

func projectReports(t *testing.T, data, project string) []string {
	t.Helper()
	key, _ := ReportKey(project)
	entries, err := os.ReadDir(filepath.Join(data, "project-lane", "reports", key))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

func TestReportStoreWritesPrivateFileInPrivateDirectory(t *testing.T) {
	store, data := reportData(t)
	result, err := store.Write("/work/p1", []byte("{}\n"), reportTime)
	if err != nil || result != ReportWritten {
		t.Fatalf("%q %v", result, err)
	}
	key, _ := ReportKey("/work/p1")
	dir := filepath.Join(data, "project-lane", "reports", key)
	info, _ := os.Stat(dir)
	names := projectReports(t, data, "/work/p1")
	file, _ := os.Stat(filepath.Join(dir, names[0]))
	if info.Mode().Perm() != 0o700 || file.Mode().Perm() != 0o600 || len(names) != 1 || !reportName.MatchString(names[0]) || !strings.HasPrefix(names[0], "20261126T041500Z-") {
		t.Fatalf("dir %v file %v names %v", info.Mode(), file.Mode(), names)
	}
	if strings.Contains(strings.Join(names, ""), "p1") {
		t.Fatalf("the project is in a file name: %v", names)
	}
}

func TestReportStoreKeepsTheLastFiftyOldestFirstAndOnlyOwnFiles(t *testing.T) {
	store, data := reportData(t)
	project := "/work/p"
	key, _ := ReportKey(project)
	dir := filepath.Join(data, "project-lane", "reports", key)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	// what pruning must never touch: a foreign file, a directory with the pattern's name, a link with the pattern's name
	// (to a file outside and to a directory outside), and a file of the pattern that is newer than all
	foreign := filepath.Join(dir, "notes.txt")
	patternDir := filepath.Join(dir, "20200101T000000Z-1-00000000.json")
	patternLink := filepath.Join(dir, "20200101T000001Z-1-00000001.json")
	dirLink := filepath.Join(dir, "20200101T000002Z-1-00000002.json")
	os.WriteFile(foreign, []byte("mine"), 0o600)
	os.Mkdir(patternDir, 0o700)
	os.WriteFile(filepath.Join(patternDir, "inside"), []byte("x"), 0o600)
	os.Symlink(outside, patternLink)
	outDir := t.TempDir()
	os.WriteFile(filepath.Join(outDir, "keep"), []byte("k"), 0o600)
	os.Symlink(outDir, dirLink)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 60; i++ {
		if _, err := store.Write(project, []byte(fmt.Sprintf("{%d}\n", i)), base.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	var regular []string
	for _, name := range projectReports(t, data, project) {
		info, _ := os.Lstat(filepath.Join(dir, name))
		if reportName.MatchString(name) && info.Mode().IsRegular() {
			regular = append(regular, name)
		}
	}
	if len(regular) != ReportsKept || !strings.HasPrefix(regular[0], "20260101T000010Z-") || !strings.HasPrefix(regular[49], "20260101T000059Z-") {
		t.Fatalf("kept %d: first %s last %s", len(regular), regular[0], regular[len(regular)-1])
	}
	for _, path := range []string{foreign, filepath.Join(patternDir, "inside"), outside, filepath.Join(outDir, "keep")} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("%s was touched: %v", path, err)
		}
	}
	for _, path := range []string{patternLink, dirLink} {
		if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Errorf("%s was removed or replaced: %v", path, err)
		}
	}
}

func TestReportStoreTwoCommandsOfOneSecondAndTwoProjectsLoseNothing(t *testing.T) {
	store, data := reportData(t)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			project := "/work/a"
			if i%2 == 1 {
				project = "/work/b"
			}
			if _, err := store.Write(project, []byte(fmt.Sprintf("{%d}\n", i)), reportTime); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	for _, project := range []string{"/work/a", "/work/b"} {
		if names := projectReports(t, data, project); len(names) != 10 {
			t.Errorf("%s holds %d reports, not 10", project, len(names))
		}
	}
	// a project at its bound loses only its own oldest when another project writes
	for i := 0; i < 60; i++ {
		store.Write("/work/a", []byte("{}\n"), reportTime.Add(time.Duration(i+1)*time.Second))
	}
	store.Write("/work/b", []byte("{}\n"), reportTime.Add(time.Hour))
	if a, b := len(projectReports(t, data, "/work/a")), len(projectReports(t, data, "/work/b")); a != ReportsKept || b != 11 {
		t.Fatalf("a %d, b %d", a, b)
	}
}

func TestReportStoreRefusesALinkOnTheWayAndAnOpenDirectory(t *testing.T) {
	store, data := reportData(t)
	elsewhere := t.TempDir()
	// the reports directory is a link
	reports := filepath.Join(data, "project-lane", "reports")
	os.Remove(reports)
	os.Symlink(elsewhere, reports)
	if _, err := store.Write("/work/p", []byte("{}\n"), reportTime); err == nil {
		t.Fatal("a link as the reports directory was followed")
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
		t.Fatalf("something was written through the link: %v", entries)
	}
	os.Remove(reports)
	os.Mkdir(reports, 0o700)
	// the project's directory is a link
	key, _ := ReportKey("/work/p")
	os.Symlink(elsewhere, filepath.Join(reports, key))
	if _, err := store.Write("/work/p", []byte("{}\n"), reportTime); err == nil {
		t.Fatal("a link as the project's directory was followed")
	}
	os.Remove(filepath.Join(reports, key))
	// a directory open to others
	os.Mkdir(filepath.Join(reports, key), 0o755)
	os.Chmod(filepath.Join(reports, key), 0o755)
	if _, err := store.Write("/work/p", []byte("{}\n"), reportTime); err == nil {
		t.Fatal("a directory open to others was used")
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
		t.Fatalf("something was written elsewhere: %v", entries)
	}
	// a data directory that is itself missing the lane's directory is not created
	store2 := ReportStore{Data: t.TempDir()}
	if _, err := store2.Write("/work/p", []byte("{}\n"), reportTime); err == nil {
		t.Fatal("the lane's directory was made by the writer")
	}
}

func TestReportStoreRefusesWhatIsPastTheBoundAndWritesNothing(t *testing.T) {
	store, data := reportData(t)
	result, err := store.Write("/work/p", make([]byte, MaxReportBytes+1), reportTime)
	if err != nil || result != ReportTooLarge {
		t.Fatalf("%q %v", result, err)
	}
	if entries, _ := os.ReadDir(filepath.Join(data, "project-lane", "reports")); len(entries) != 0 {
		t.Fatalf("a directory was made for a document that was not written: %v", entries)
	}
	if _, err := store.Write("work/relative", []byte("{}\n"), reportTime); err == nil {
		t.Fatal("a relative project was accepted")
	}
}
