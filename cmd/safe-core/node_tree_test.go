package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNodeTreeExitCodes(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "node_modules", "a"), 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"package-lock.json":           `{"lockfileVersion":3,"packages":{"":{},"node_modules/a":{"version":"1.0.0"}}}`,
		"node_modules/a/package.json": `{"name":"a","version":"1.0.0"}`,
		"broken/package-lock.json":    `{not json`,
	}
	for rel, content := range files {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	var stdout, stderr bytes.Buffer
	if got := run([]string{"node-tree", "--lockfile", filepath.Join(dir, "package-lock.json")}, strings.NewReader(""), &stdout, &stderr); got != 2 {
		t.Fatalf("missing flags: exit %d, want 2", got)
	}

	stdout.Reset()
	args := []string{"node-tree", "--lockfile", filepath.Join(dir, "package-lock.json"), "--source", dir, "--target", dir, "--modules", "node_modules"}
	if got := run(args, strings.NewReader(""), &stdout, &stderr); got != 0 {
		t.Fatalf("exit %d, want 0: %s", got, stderr.String())
	}
	var report struct {
		Schema    int      `json:"schema"`
		Format    string   `json:"format"`
		Installed int      `json:"installed"`
		Problems  []string `json:"problems"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("report is not JSON: %v", err)
	}
	if report.Schema != 1 || report.Format != "npm" || report.Installed != 1 || report.Problems == nil || len(report.Problems) != 0 {
		t.Fatalf("report = %+v", report)
	}

	// An unreadable lockfile is missing evidence (exit 3), never a report.
	stdout.Reset()
	args[2] = filepath.Join(dir, "broken", "package-lock.json")
	if got := run(args, strings.NewReader(""), &stdout, &stderr); got != 3 || stdout.Len() != 0 {
		t.Fatalf("broken lockfile: exit %d, stdout %q; want 3 and nothing", got, stdout.String())
	}
}
