package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunUsageAndParseFailuresDoNotWritePartialJSON(t *testing.T) {
	t.Run("usage", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		if got := run(nil, &stdout, &stderr); got != 2 {
			t.Fatalf("run() = %d, want 2", got)
		}
		if stdout.Len() != 0 || !strings.Contains(stderr.String(), "usage") {
			t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
		}
	})

	t.Run("parse failure", func(t *testing.T) {
		dir := t.TempDir()
		bad := filepath.Join(dir, "bad.json")
		good := filepath.Join(dir, "good.json")
		if err := os.WriteFile(bad, []byte(`{"lockfileVersion":1}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(good, []byte(`{"lockfileVersion":3,"packages":{}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		if got := run([]string{"lockdiff", bad, good}, &stdout, &stderr); got != 3 {
			t.Fatalf("run() = %d, want 3", got)
		}
		if stdout.Len() != 0 || !strings.Contains(stderr.String(), "lockfileVersion 1") {
			t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
		}
	})
}

func TestRunWritesOnlyOneJSONDocument(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "old.json")
	new := filepath.Join(dir, "new.json")
	for path, contents := range map[string]string{
		old: `{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1.0.0"}}}`,
		new: `{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"2.0.0"}}}`,
	} {
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var stdout, stderr bytes.Buffer
	if got := run([]string{"lockdiff", old, new}, &stdout, &stderr); got != 0 {
		t.Fatalf("run() = %d, stderr=%q", got, stderr.String())
	}
	if stdout.String() != "{\"schema\":1,\"added\":[],\"removed\":[],\"changed\":[{\"name\":\"a\",\"from\":\"1.0.0\",\"to\":\"2.0.0\",\"source\":\"unknown\"}]}\n" {
		t.Fatalf("stdout=%q", stdout.String())
	}
}

func TestRunRegistryHostOption(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "old.json")
	new := filepath.Join(dir, "new.json")
	for path, contents := range map[string]string{
		old: `{"lockfileVersion":3,"packages":{}}`,
		new: `{"lockfileVersion":3,"packages":{"node_modules/alias":{"name":"private-pkg","version":"1.0.0","resolved":"https://registry.example.test/private-pkg/-/private-pkg-1.0.0.tgz"}}}`,
	} {
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var stdout, stderr bytes.Buffer
	if got := run([]string{"lockdiff", "--registry-host", "registry.example.test", old, new}, &stdout, &stderr); got != 0 {
		t.Fatalf("run() = %d, stderr=%q", got, stderr.String())
	}
	if stdout.String() != "{\"schema\":1,\"added\":[{\"name\":\"private-pkg\",\"version\":\"1.0.0\",\"source\":\"registry\"}],\"removed\":[],\"changed\":[]}\n" {
		t.Fatalf("stdout=%q", stdout.String())
	}
}
