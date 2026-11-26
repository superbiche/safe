//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/superbiche/safe/internal/projectlane"
)

const reportTestDecision = `{"schema_version":1,"baseline":{"source":"graph","error":""},"difference":{"added":[],"removed":[],"changed":[],"introduced":[],"dropped":[]},
"advisories":{"fixed":[],"already_present":[],"introduced":[]},"malice":[],"coverage":[],"outcome":{"status":"clear","class":"","exit":0},"adverse":[]}`

func reportArgs(data, project, scratch, lock string, extra ...string) []string {
	return append([]string{"project-report", "write", "--data", data, "--project", project, "--scratch", scratch, "--lockfile", lock, "--verb", "install",
		"--status", "0", "--version", "1.2.3", "--published", "tree", "--asked", "0", "--ended", "none"}, extra...)
}

func TestProjectReportWritesAndChecksOneDocument(t *testing.T) {
	data, scratch := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(data, "project-lane", "reports"), 0o700); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(t.TempDir(), "package-lock.json")
	os.WriteFile(lock, []byte("{}\n"), 0o600)
	// no decision report: nothing is written, and the word says so
	if code, stdout, _ := runWithStdin("", reportArgs(data, "/work/p", scratch, lock)...); code != 3 || strings.TrimSpace(stdout) != "no-decision" {
		t.Fatalf("no decision: %d %q", code, stdout)
	}
	os.WriteFile(filepath.Join(scratch, "report.json"), []byte(reportTestDecision), 0o600)
	os.WriteFile(filepath.Join(scratch, "bind.json"), []byte(`{"schema_version":1,"outcome":"published","exit":0}`), 0o600)
	code, stdout, stderr := runWithStdin("", reportArgs(data, "/work/p", scratch, lock)...)
	if code != 0 || strings.TrimSpace(stdout) != "written" {
		t.Fatalf("write: %d %q %q", code, stdout, stderr)
	}
	key, _ := os.ReadDir(filepath.Join(data, "project-lane", "reports"))
	files, _ := os.ReadDir(filepath.Join(data, "project-lane", "reports", key[0].Name()))
	path := filepath.Join(data, "project-lane", "reports", key[0].Name(), files[0].Name())
	if code, _, _ := runWithStdin("", "project-report", "check", path); code != 0 {
		t.Fatalf("the document written does not check")
	}
	// a document that was edited is not a report
	raw, _ := os.ReadFile(path)
	os.WriteFile(path, []byte(strings.Replace(string(raw), `"end": "published"`, `"end": "published!"`, 1)), 0o600)
	if code, _, _ := runWithStdin("", "project-report", "check", path); code != 3 {
		t.Fatalf("an edited document checked")
	}
	// usage
	for _, args := range [][]string{{"project-report"}, {"project-report", "write"}, {"project-report", "check"}, {"project-report", "nope"},
		reportArgs(data, "/work/p", scratch, lock, "--status", "1")} {
		if code, _, _ := runWithStdin("", args...); code != 2 {
			t.Errorf("%v: code %d, not usage", args, code)
		}
	}
	// a piece that is a link is not read: no binder, so the end is not a publication
	os.Remove(filepath.Join(scratch, "bind.json"))
	elsewhere := filepath.Join(t.TempDir(), "bind.json")
	os.WriteFile(elsewhere, []byte(`{"schema_version":1,"outcome":"published","exit":0}`), 0o600)
	os.Symlink(elsewhere, filepath.Join(scratch, "bind.json"))
	if code, _, _ := runWithStdin("", reportArgs(data, "/work/q", scratch, lock)...); code != 0 {
		t.Fatalf("write with a link piece: %d", code)
	}
	qkey, _ := projectlane.ReportKey("/work/q")
	qfiles, _ := os.ReadDir(filepath.Join(data, "project-lane", "reports", qkey))
	qraw, _ := os.ReadFile(filepath.Join(data, "project-lane", "reports", qkey, qfiles[0].Name()))
	if !strings.Contains(string(qraw), `"end": "bind_unreadable"`) || strings.Contains(string(qraw), `"passed": true`) {
		t.Fatalf("a binder piece that is a link was read:\n%s", qraw)
	}
}
