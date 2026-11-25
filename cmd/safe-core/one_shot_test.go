package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A direct call of the writer from a session that is not the operator's terminal is refused BEFORE the store is touched: a cold
// home stays cold (the defect found at c731124: the terminal check lived in the shell only).
func TestAddAndRemoveRefuseWithoutAnOperatorTerminal(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
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
		if code := run([]string{"one-shot-store", verb, project}, devnull, &out, &errOut); code != 102 {
			t.Fatalf("%s from /dev/null: %d (%s)", verb, code, errOut.String())
		}
		if !strings.Contains(errOut.String(), "operator terminal") || out.Len() != 0 {
			t.Fatalf("%s: %q %q", verb, errOut.String(), out.String())
		}
	}
	// a reader that is not even a file
	var out, errOut bytes.Buffer
	if code := run([]string{"one-shot-store", "add", project}, strings.NewReader("y\n"), &out, &errOut); code != 102 {
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
	t.Setenv("HOME", home)
	var out, errOut bytes.Buffer
	if code := run([]string{"one-shot-store", "list"}, strings.NewReader(""), &out, &errOut); code != 0 || strings.TrimSpace(out.String()) != "[]" {
		t.Fatalf("%d %q %q", code, out.String(), errOut.String())
	}
	if entries, _ := os.ReadDir(home); len(entries) != 0 {
		t.Fatalf("list created %v", entries)
	}
}

func TestListSaysCannotTellWithAStatusOfItsOwn(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	run0 := filepath.Join(home, ".config", "safe", "run")
	if err := os.MkdirAll(run0, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(run0, "one-shot-projects.json"), []byte(`{"projects":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"one-shot-store", "list"}, strings.NewReader(""), &out, &errOut); code != 3 {
		t.Fatalf("an untrusted store: %d", code)
	}
	if code := run([]string{"one-shot-store", "check"}, strings.NewReader(""), &out, &errOut); code != 1 {
		t.Fatalf("an untrusted store pins nothing: %d", code)
	}
}

// `--home` is no anchor: the only home is $HOME. A listing that names another store reads nothing of it.
func TestThereIsNoWayToNameAnotherHome(t *testing.T) {
	mine, other := t.TempDir(), t.TempDir()
	t.Setenv("HOME", mine)
	run0 := filepath.Join(other, ".config", "safe", "run")
	if err := os.MkdirAll(run0, 0o700); err != nil {
		t.Fatal(err)
	}
	doc := `{"schema_version":1,"projects":[{"path":"/tmp","dev":1,"inode":2,"added":"x"}]}`
	if err := os.WriteFile(filepath.Join(run0, "one-shot-projects.json"), []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"one-shot-store", "list", "--home", other}, strings.NewReader(""), &out, &errOut); code != 0 || strings.TrimSpace(out.String()) != "[]" {
		t.Fatalf("--home read another store: %d %q", code, out.String())
	}
}

// Any read error is a failed read: a partial `y` returned together with end of input is no answer.
func TestAPartialAnswerWithEndOfInputIsAFailedRead(t *testing.T) {
	for name, input := range map[string]string{"y without a newline": "y", "empty": "", "Y without a newline": "Y"} {
		if answer, ok := readAnswerFrom(strings.NewReader(input)); ok {
			t.Fatalf("%s was read as %q", name, answer)
		}
	}
	if answer, ok := readAnswerFrom(strings.NewReader("y\n")); !ok || answer != "y" {
		t.Fatalf("control: %q %v", answer, ok)
	}
	// an error with data: the reader returns bytes AND an error
	if _, ok := readAnswerFrom(partialReader{}); ok {
		t.Fatal("a partial answer returned with an error reached the commit")
	}
}

type partialReader struct{}

func (partialReader) Read(p []byte) (int, error) {
	copy(p, "y")
	return 1, io.ErrUnexpectedEOF
}
