package main

import (
	"bytes"
	"encoding/json"
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

// completeEvidence is a minimal but SHAPE-COMPLETE document: every key the
// decision reads, present and non-null. Tests mutate one field at a time, so a
// rejection is attributable to that mutation rather than to an omission.
const completeEvidence = `{
  "resolution": {"ok": true, "primary_version": "1.0.0", "label": "1.0.0"},
  "socket": {"status": "ok", "available": true, "note": "", "reason": "",
             "score": "90", "class": "clean",
             "cache_stale_score": "", "cache_stale_age_days": ""},
  "socket_siblings": [],
  "osv": {"status": "ok", "affecting": [], "remediated_count": 0,
          "total_count": 0, "historical_critical": false,
          "historical_malware_ids": ""},
  "release": {"rc": 0, "age": 30, "primary_age": "30", "version": "1.0.0",
              "cooldown_days": 3, "security_fix_ids": "",
              "cooldown_security_fix": "exempt"},
  "custom_source": false,
  "blocklist": {"readable": true, "reason": "", "path": "/etc/safe/blocked.json"},
  "block_severities": ["critical"]
}`

// setEvidenceKey rewrites one JSON path in the complete document. A nil value
// becomes an explicit JSON null; use dropEvidenceKey for the absent case.
func setEvidenceKey(t *testing.T, path string, value any) string {
	t.Helper()
	return editEvidence(t, path, value, true)
}

// dropEvidenceKey removes one JSON path entirely.
func dropEvidenceKey(t *testing.T, path string) string {
	t.Helper()
	return editEvidence(t, path, nil, false)
}

func editEvidence(t *testing.T, path string, value any, keep bool) string {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(completeEvidence), &doc); err != nil {
		t.Fatalf("base evidence is not valid JSON: %v", err)
	}
	parts := strings.Split(path, ".")
	node := doc
	for _, p := range parts[:len(parts)-1] {
		next, ok := node[p].(map[string]any)
		if !ok {
			t.Fatalf("path %q: %q is not an object", path, p)
		}
		node = next
	}
	last := parts[len(parts)-1]
	if keep {
		node[last] = value
	} else {
		delete(node, last)
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	return string(out)
}

func runVerdict(t *testing.T, evidence string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run([]string{"package-verdict"}, strings.NewReader(evidence), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// The base document must decide cleanly, or every rejection test below would
// pass for the wrong reason.
func TestCompleteEvidenceDecidesGO(t *testing.T) {
	code, stdout, stderr := runVerdict(t, completeEvidence)
	if code != 0 {
		t.Fatalf("run() = %d, stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, `"verdict":"GO"`) {
		t.Fatalf("want GO, got %s", stdout)
	}
}

// encoding/json cannot tell an absent adverse fact from a benign zero: an
// omitted `malware` flag demotes a MAL record to an ordinary advisory, a null
// `socket_siblings` erases ranged-update coverage, an absent `cooldown_days`
// disables the cooldown. None is detectable after decoding, so an incomplete
// document must be refused before it (delta review F1).
func TestPackageVerdictRefusesIncompleteEvidence(t *testing.T) {
	for _, path := range []string{
		"osv.affecting", "osv.status", "osv.historical_critical",
		"osv.historical_malware_ids", "osv.total_count",
		"socket_siblings", "socket.class", "socket.status", "socket.available",
		"release.rc", "release.cooldown_days", "release.cooldown_security_fix",
		"custom_source", "blocklist.readable", "blocklist.reason",
		"block_severities", "resolution.ok",
	} {
		for _, mode := range []string{"absent", "null"} {
			t.Run(path+"/"+mode, func(t *testing.T) {
				doc := dropEvidenceKey(t, path)
				if mode == "null" {
					doc = setEvidenceKey(t, path, nil)
				}
				code, stdout, _ := runVerdict(t, doc)
				if code != 3 {
					t.Fatalf("run() = %d, want 3 (stdout=%q)", code, stdout)
				}
				if stdout != "" {
					t.Fatalf("emitted a verdict on incomplete evidence: %q", stdout)
				}
			})
		}
	}
}

// A malware record inside the affecting list must BLOCK on the strength of the
// list alone, with no count field anywhere in the document.
func TestPackageVerdictBlocksMalwareFromListAlone(t *testing.T) {
	doc := setEvidenceKey(t, "osv.affecting", []any{
		map[string]any{"id": "MAL-2026-1", "severity": "unknown", "malware": true},
	})
	doc = strings.Replace(doc, `"total_count":0`, `"total_count":1`, 1)
	code, stdout, stderr := runVerdict(t, doc)
	if code != 0 {
		t.Fatalf("run() = %d, stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, `"verdict":"BLOCK"`) || !strings.Contains(stdout, "osv_malware") {
		t.Fatalf("want a malware BLOCK, got %s", stdout)
	}
}

// An advisory missing its malware flag is exactly the erasure delta F1 named.
func TestPackageVerdictRefusesAdvisoryMissingMalwareFlag(t *testing.T) {
	doc := setEvidenceKey(t, "osv.affecting", []any{
		map[string]any{"id": "MAL-2026-1", "severity": "unknown"},
	})
	if code, stdout, _ := runVerdict(t, doc); code != 3 || stdout != "" {
		t.Fatalf("run() = %d stdout=%q, want 3 with no verdict", code, stdout)
	}
}

// Validation must not reject a document the real producer can emit.
func TestPackageVerdictRejectsUnusableEvidence(t *testing.T) {
	for _, tc := range []struct {
		name  string
		path  string
		value any
	}{
		{"socket ok with a null class", "socket.class", nil},
		{"socket ok with an unrecognized class", "socket.class", "probably_fine"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := setEvidenceKey(t, tc.path, tc.value)
			if code, stdout, _ := runVerdict(t, doc); code != 3 || stdout != "" {
				t.Fatalf("run() = %d stdout=%q, want 3 with no verdict", code, stdout)
			}
		})
	}
}

func TestPackageVerdictRejectsSiblingWithUnknownClass(t *testing.T) {
	doc := setEvidenceKey(t, "socket_siblings", []any{
		map[string]any{"version": "2.0.0", "status": "ok", "class": ""},
	})
	if code, stdout, _ := runVerdict(t, doc); code != 3 || stdout != "" {
		t.Fatalf("run() = %d stdout=%q, want 3 with no verdict", code, stdout)
	}
}
