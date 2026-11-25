package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A direct call of the writer from a session that is not the operator's terminal is refused BEFORE the store is touched: a cold
// home stays cold (the defect found at c731124: the terminal check lived in the shell only).
func TestAddAndRemoveRefuseWithoutAnOperatorTerminal(t *testing.T) {
	home := t.TempDir()
	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "package.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()
	for _, verb := range []string{"add", "remove"} {
		var out, errOut bytes.Buffer
		if code := run([]string{"one-shot-store", verb, "--home", home, project}, devnull, &out, &errOut); code != 102 {
			t.Fatalf("%s from /dev/null: %d (%s)", verb, code, errOut.String())
		}
		if !strings.Contains(errOut.String(), "operator terminal") || out.Len() != 0 {
			t.Fatalf("%s: %q %q", verb, errOut.String(), out.String())
		}
	}
	// a reader that is not even a file
	var out, errOut bytes.Buffer
	if code := run([]string{"one-shot-store", "add", "--home", home, project}, strings.NewReader("y\n"), &out, &errOut); code != 102 {
		t.Fatalf("add from a pipe: %d", code)
	}
	entries, _ := os.ReadDir(home)
	if len(entries) != 0 {
		t.Fatalf("a refused call touched the home: %v", entries)
	}
}

func TestOperatorTerminalNeedsATerminalAndNoMarker(t *testing.T) {
	if operatorTerminal(strings.NewReader(""), func(string) string { return "" }) {
		t.Fatal("a reader that is not a file is no terminal")
	}
	devnull, _ := os.Open(os.DevNull)
	defer devnull.Close()
	if operatorTerminal(devnull, func(string) string { return "" }) {
		t.Fatal("/dev/null is no terminal")
	}
	want := []string{"CODEX_THREAD_ID", "CODEX_CI", "CLAUDECODE", "OPENCODE"}
	if strings.Join(operatorMarkers, ",") != strings.Join(want, ",") {
		t.Fatalf("the markers are %v", operatorMarkers)
	}
}

func TestListOnAColdHomeCreatesNothing(t *testing.T) {
	home := t.TempDir()
	var out, errOut bytes.Buffer
	if code := run([]string{"one-shot-store", "list", "--home", home}, strings.NewReader(""), &out, &errOut); code != 0 || strings.TrimSpace(out.String()) != "[]" {
		t.Fatalf("%d %q %q", code, out.String(), errOut.String())
	}
	if entries, _ := os.ReadDir(home); len(entries) != 0 {
		t.Fatalf("list created %v", entries)
	}
}

func TestListSaysCannotTellWithAStatusOfItsOwn(t *testing.T) {
	home := t.TempDir()
	run0 := filepath.Join(home, ".config", "safe", "run")
	if err := os.MkdirAll(run0, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(run0, "one-shot-projects.json"), []byte(`{"projects":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"one-shot-store", "list", "--home", home}, strings.NewReader(""), &out, &errOut); code != 3 {
		t.Fatalf("an untrusted store: %d", code)
	}
	if code := run([]string{"one-shot-store", "check", "--home", home}, strings.NewReader(""), &out, &errOut); code != 1 {
		t.Fatalf("an untrusted store pins nothing: %d", code)
	}
}
