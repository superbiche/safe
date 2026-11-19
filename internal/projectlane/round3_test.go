package projectlane

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func reasonsOf(v Bindability, path string) []string {
	var out []string
	for _, u := range v.Unbound {
		if u.Path == path {
			out = append(out, u.Reason)
		}
	}
	return out
}

// Within ONE registry occurrence every reason is reported: a missing integrity or an own shrinkwrap
// marker never hides an identity that cannot stand in a URL (which the router refuses on).
func TestCheckBindableReportsEveryReasonOfAnOccurrence(t *testing.T) {
	lock := writeLock(t, map[string]map[string]any{
		"node_modules/a": with(entry("a", "^1.0.0"), map[string]any{"integrity": nil, "hasShrinkwrap": true}),
	})
	graph, err := LoadGraph(lock, Hosts{})
	if err != nil {
		t.Fatal(err)
	}
	got := reasonsOf(CheckBindable(graph, nil), "node_modules/a")
	has := map[string]bool{}
	for _, r := range got {
		has[r] = true
	}
	if !has[ReasonIdentityInvalid] || !has[ReasonIntegrityMissing] || !has[ReasonOwnShrinkwrap] {
		t.Fatalf("reasons = %v, want identity_invalid, integrity_missing and own_shrinkwrap together", got)
	}
}

// A link target that looks inside the project in the lockfile's text but resolves, through a link
// of the filesystem, outside it, is link_outside_project.
func TestCheckLinksInRootResolvesThePhysicalTarget(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "project")
	outside := filepath.Join(base, "outside")
	for _, dir := range []string{root, outside, filepath.Join(root, "packages", "real")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, filepath.Join(root, "packages", "sneaky")); err != nil {
		t.Fatal(err)
	}
	lock := writeLock(t, map[string]map[string]any{
		"node_modules/real":   {"resolved": "packages/real", "link": true},
		"node_modules/sneaky": {"resolved": "packages/sneaky", "link": true},
		"node_modules/later":  {"resolved": "packages/not/yet/there", "link": true},
		"packages/real":       {"name": "real", "version": "1.0.0"},
	})
	graph, err := LoadGraph(lock, Hosts{})
	if err != nil {
		t.Fatal(err)
	}
	lexical := CheckBindable(graph, nil)
	if got := reasonsOf(lexical, "node_modules/sneaky"); len(got) != 0 {
		t.Fatalf("the lexical check should not see it: %v", got)
	}
	physical, err := CheckLinksInRoot(graph, lexical, root)
	if err != nil {
		t.Fatal(err)
	}
	if got := reasonsOf(physical, "node_modules/sneaky"); len(got) != 1 || got[0] != ReasonLinkOutsideProject {
		t.Fatalf("sneaky = %v", got)
	}
	for _, ok := range []string{"node_modules/real", "node_modules/later"} {
		if got := reasonsOf(physical, ok); len(got) != 0 {
			t.Fatalf("%s should stay inside: %v", ok, got)
		}
	}
}

// The admission of a lockfile does not depend on its declared version: a version 1 or version 4
// document with a package map is judged by the same rules (the legacy fallback is the gate's
// recognition of a legacy lockfile, never a way past these checks).
func TestAdmitLockfileFindingsIgnoresTheDeclaredVersion(t *testing.T) {
	for _, version := range []string{"1", "4", "99"} {
		doc := []byte(`{"lockfileVersion":` + version + `,"packages":{"":{},"node_modules/l":{"resolved":"packages/l","link":true},"../outside/pkg":{"version":"1.0.0"}}}`)
		var reasons []string
		for _, f := range AdmitLockfileFindings(doc) {
			reasons = append(reasons, f.Reason)
		}
		if len(reasons) != 2 || reasons[0] != ReasonLinksNotSupported || reasons[1] != ReasonLockfilePathsOutside {
			t.Fatalf("version %s: findings = %v", version, reasons)
		}
	}
	// the tree verifier still judges versions 2 and 3 only
	if _, err := parseJudgedLockfile([]byte(`{"lockfileVersion":1,"packages":{}}`), false); err == nil {
		t.Fatal("the tree verifier must keep its version rule")
	}
}

func TestLoadGraphAnyVersionReadsAPackageMapOfAnyVersion(t *testing.T) {
	dir := t.TempDir()
	doc, _ := json.Marshal(map[string]any{"lockfileVersion": 1, "packages": map[string]any{
		"":                   map[string]any{},
		"node_modules/l":     map[string]any{"resolved": "../escape", "link": true},
		"node_modules/other": entry("other", "1.0.0"),
	}})
	path := filepath.Join(dir, "package-lock.json")
	if err := os.WriteFile(path, doc, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadGraph(path, Hosts{}); err == nil {
		t.Fatal("LoadGraph must keep refusing a version 1 lockfile")
	}
	graph, err := LoadGraphAnyVersion(path, Hosts{})
	if err != nil {
		t.Fatal(err)
	}
	if got := reasonsOf(CheckBindable(graph, nil), "node_modules/l"); len(got) != 1 || got[0] != ReasonLinkOutsideProject {
		t.Fatalf("reasons = %v", got)
	}
}
