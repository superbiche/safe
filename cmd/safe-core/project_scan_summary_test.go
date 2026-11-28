package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProjectScanSummaryPrintsCountsAndNamesOfTheKnownSet(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "scan.json")
	doc := `{"audit_totals":{"critical":4,"by_ecosystem":{"npm":{"critical":2},"python":{"critical":1},"ghp_token":{"critical":1}}},` +
		`"tool_status":{"syft":{"status":"error","note":"a note with a token ghp_secret"}}}`
	if err := os.WriteFile(file, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runWithStdin("", "project-scan-summary", "--result", file)
	if code != 0 || stderr != "" {
		t.Fatalf("code %d, stderr %q", code, stderr)
	}
	if strings.Contains(stdout, "ghp_") {
		t.Fatalf("free text reached the summary: %s", stdout)
	}
	var got struct {
		Critical     map[string]int `json:"critical"`
		Unattributed int            `json:"unattributed"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatal(err)
	}
	if got.Critical["npm"] != 2 || got.Critical["python"] != 1 || got.Unattributed != 1 {
		t.Fatalf("summary: %s", stdout)
	}
}

func TestProjectScanSummaryRefusesWhatIsNotAResult(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(write("real.json", `{"audit_totals":{"critical":0}}`), link); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"missing":   {"project-scan-summary", "--result", filepath.Join(dir, "none.json")},
		"malformed": {"project-scan-summary", "--result", write("bad.json", "{")},
		"no totals": {"project-scan-summary", "--result", write("empty.json", "{}")},
		"null":      {"project-scan-summary", "--result", write("null.json", `{"audit_totals":{"critical":null}}`)},
		"a link":    {"project-scan-summary", "--result", link},
		"a dir":     {"project-scan-summary", "--result", dir},
	} {
		if code, stdout, _ := runWithStdin("", args...); code != 3 || stdout != "" {
			t.Errorf("%s: code %d, stdout %q", name, code, stdout)
		}
	}
	if code, _, _ := runWithStdin("", "project-scan-summary"); code != 2 {
		t.Errorf("usage: code %d", code)
	}
}
