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
		if got := run(nil, strings.NewReader(""), &stdout, &stderr); got != 2 {
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
		if got := run([]string{"lockdiff", bad, good}, strings.NewReader(""), &stdout, &stderr); got != 3 {
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
	if got := run([]string{"lockdiff", old, new}, strings.NewReader(""), &stdout, &stderr); got != 0 {
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
	if got := run([]string{"lockdiff", "--registry-host", "registry.example.test", old, new}, strings.NewReader(""), &stdout, &stderr); got != 0 {
		t.Fatalf("run() = %d, stderr=%q", got, stderr.String())
	}
	if stdout.String() != "{\"schema\":1,\"added\":[{\"name\":\"private-pkg\",\"version\":\"1.0.0\",\"source\":\"registry\"}],\"removed\":[],\"changed\":[]}\n" {
		t.Fatalf("stdout=%q", stdout.String())
	}
}

// The decision layer is only as trustworthy as its decode boundary. These go
// through the real JSON path rather than constructing typed structs, because
// the defects they guard against are ones the decoder silently accepts:
// missing keys and explicit nulls both yield zero values (review F1).
func TestPackageVerdictRejectsUnusableEvidence(t *testing.T) {
	for _, tc := range []struct {
		name     string
		evidence string
	}{
		{
			"socket ok with a null class",
			`{"resolution":{"ok":true,"primary_version":"1.0.0","label":"1.0.0"},
			  "socket":{"status":"ok","available":true,"score":"90","class":null},
			  "osv":{"status":"ok"},"blocklist":{"readable":true}}`,
		},
		{
			"socket ok with the class key absent",
			`{"resolution":{"ok":true,"primary_version":"1.0.0","label":"1.0.0"},
			  "socket":{"status":"ok","available":true,"score":"90"},
			  "osv":{"status":"ok"},"blocklist":{"readable":true}}`,
		},
		{
			"socket ok with an unrecognized class",
			`{"resolution":{"ok":true,"primary_version":"1.0.0","label":"1.0.0"},
			  "socket":{"status":"ok","available":true,"score":"90","class":"probably_fine"},
			  "osv":{"status":"ok"},"blocklist":{"readable":true}}`,
		},
		{
			"sibling ok with an unrecognized class",
			`{"resolution":{"ok":true,"primary_version":"1.0.0","label":"1.0.0"},
			  "socket":{"status":"ok","available":true,"score":"90","class":"clean"},
			  "socket_siblings":[{"version":"2.0.0","status":"ok","class":""}],
			  "osv":{"status":"ok"},"blocklist":{"readable":true}}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			got := run([]string{"package-verdict"}, strings.NewReader(tc.evidence), &stdout, &stderr)
			if got != 3 {
				t.Fatalf("run() = %d, want 3 (stdout=%q)", got, stdout.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("emitted a verdict on unusable evidence: %q", stdout.String())
			}
		})
	}
}

// A malware record must decide the verdict on the strength of the list alone.
// Before the count was derived, a zeroed or absent affecting_count made this
// entire branch unreachable while the evidence still named the MAL record.
func TestPackageVerdictBlocksMalwareWithoutAnyCountField(t *testing.T) {
	evidence := `{"resolution":{"ok":true,"primary_version":"1.0.0","label":"1.0.0"},
	  "socket":{"status":"ok","available":true,"score":"90","class":"clean"},
	  "osv":{"status":"ok","total_count":1,
	         "affecting":[{"id":"MAL-2026-1","severity":"unknown","malware":true}]},
	  "blocklist":{"readable":true},"block_severities":[]}`

	var stdout, stderr bytes.Buffer
	if got := run([]string{"package-verdict"}, strings.NewReader(evidence), &stdout, &stderr); got != 0 {
		t.Fatalf("run() = %d, stderr=%q", got, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"verdict":"BLOCK"`) {
		t.Fatalf("want BLOCK, got %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "osv_malware") {
		t.Fatalf("want the malware cause, got %s", stdout.String())
	}
}
