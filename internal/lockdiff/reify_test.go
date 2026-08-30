package lockdiff

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// otherPlatform names a platform this machine is not, whatever it is running
// on: a fixture hardcoding "linux" would assert nothing on a darwin runner.
func otherPlatform(current string) string {
	if current == "linux" {
		return "darwin"
	}
	return "linux"
}

// writeManifest materializes an installed package the way a real tree carries
// it: a directory at the lockfile's path key holding a package.json.
func writeManifest(t *testing.T, root, path, body string) {
	t.Helper()
	dir := filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeLockfile(t *testing.T, root, body string) string {
	t.Helper()
	path := filepath.Join(root, "package-lock.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func loadEntriesForTest(t *testing.T, lockfile string) []Entry {
	t.Helper()
	entries, err := LoadEntries(lockfile, nil)
	if err != nil {
		t.Fatalf("LoadEntries() error = %v", err)
	}
	return entries
}

func TestReifyCandidatesReadsTheTreeNotTheLockDelta(t *testing.T) {
	root := t.TempDir()
	registry := func(name, version string) string {
		return fmt.Sprintf(`"version":%q,"resolved":"https://registry.npmjs.org/%s/-/%s-%s.tgz","integrity":"sha512-%s"`,
			version, name, name, version, name)
	}
	lockfile := writeLockfile(t, root, fmt.Sprintf(`{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "reify-test", "version": "1.0.0"},
	    "packages/workspace-source": {"name": "workspace-source", "version": "1.0.0"},
	    "node_modules/present": {%s},
	    "node_modules/gone": {%s},
	    "node_modules/stale": {%s},
	    "node_modules/linked": {"resolved": "packages/workspace-source", "link": true},
	    "node_modules/dev-only": {%s, "dev": true},
	    "node_modules/optional-elsewhere": {%s, "optional": true, "os": [%q]},
	    "node_modules/optional-here": {%s, "optional": true, "os": [%q]},
	    "node_modules/required-elsewhere": {%s, "os": [%q]},
	    "node_modules/from-git": {"version": "1.0.0", "resolved": "git+https://example.invalid/from-git.git#deadbeef", "integrity": "sha512-git"},
	    "node_modules/outer/node_modules/inner": {%s}
	  }
	}`,
		registry("present", "1.0.0"),
		registry("gone", "1.0.0"),
		registry("stale", "1.0.0"),
		registry("dev-only", "1.0.0"),
		registry("optional-elsewhere", "1.0.0"), otherPlatform(currentOS),
		registry("optional-here", "1.0.0"), currentOS,
		registry("required-elsewhere", "1.0.0"), otherPlatform(currentOS),
		registry("inner", "1.0.0"),
	))

	writeManifest(t, root, "node_modules/present", `{"name":"present","version":"1.0.0"}`)
	writeManifest(t, root, "node_modules/stale", `{"name":"stale","version":"0.9.0"}`)

	want := []Candidate{
		{Path: "node_modules/dev-only", Name: "dev-only", Version: "1.0.0", Source: "registry", Integrity: "sha512-dev-only", Reason: ReasonMissing},
		{Path: "node_modules/from-git", Name: "from-git", Version: "1.0.0", Source: "git", Integrity: "sha512-git", Reason: ReasonMissing},
		{Path: "node_modules/gone", Name: "gone", Version: "1.0.0", Source: "registry", Integrity: "sha512-gone", Reason: ReasonMissing},
		{Path: "node_modules/optional-here", Name: "optional-here", Version: "1.0.0", Source: "registry", Integrity: "sha512-optional-here", Reason: ReasonMissing},
		{Path: "node_modules/outer/node_modules/inner", Name: "inner", Version: "1.0.0", Source: "registry", Integrity: "sha512-inner", Reason: ReasonMissing},
		{Path: "node_modules/required-elsewhere", Name: "required-elsewhere", Version: "1.0.0", Source: "registry", Integrity: "sha512-required-elsewhere", Reason: ReasonMissing},
		{Path: "node_modules/stale", Name: "stale", Version: "1.0.0", Source: "registry", Integrity: "sha512-stale", Reason: ReasonVersionMismatch},
	}
	got := ReifyCandidates(loadEntriesForTest(t, lockfile), root)
	if got.Schema != 1 {
		t.Fatalf("ReifyCandidates() schema = %d, want 1", got.Schema)
	}
	if !reflect.DeepEqual(got.Candidates, want) {
		t.Fatalf("ReifyCandidates() = %#v, want %#v", got.Candidates, want)
	}
}

// An empty candidate set must serialize as [] rather than null: the gate
// schema-validates this document, and a null candidates member would read as
// audit-infrastructure breakage on every healthy project.
func TestReifyCandidatesEmptySetSerializesAsAnArray(t *testing.T) {
	root := t.TempDir()
	lockfile := writeLockfile(t, root, `{"lockfileVersion":3,"packages":{"":{"name":"reify-test","version":"1.0.0"}}}`)

	encoded, err := json.Marshal(ReifyCandidates(loadEntriesForTest(t, lockfile), root))
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"schema":1,"candidates":[]}`; string(encoded) != want {
		t.Fatalf("ReifyCandidates() encoded = %s, want %s", encoded, want)
	}
}

func TestReifyCandidatesTreatsAnUnreadableManifestAsMissing(t *testing.T) {
	root := t.TempDir()
	lockfile := writeLockfile(t, root, `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "reify-test", "version": "1.0.0"},
	    "node_modules/truncated": {"version": "1.0.0"},
	    "node_modules/versionless": {"version": "1.0.0"}
	  }
	}`)
	writeManifest(t, root, "node_modules/truncated", `{"name":"truncated","ver`)
	writeManifest(t, root, "node_modules/versionless", `{"name":"versionless"}`)

	got := ReifyCandidates(loadEntriesForTest(t, lockfile), root)
	want := []Candidate{
		{Path: "node_modules/truncated", Name: "truncated", Version: "1.0.0", Source: "unknown", Reason: ReasonMissing},
		{Path: "node_modules/versionless", Name: "versionless", Version: "1.0.0", Source: "unknown", Reason: ReasonMissing},
	}
	if !reflect.DeepEqual(got.Candidates, want) {
		t.Fatalf("ReifyCandidates() = %#v, want %#v", got.Candidates, want)
	}
}

// A path key that climbs out of the project is never read: it is not evidence
// about this tree, and a package.json found up there must not vouch for it.
func TestReifyCandidatesNeverReadsOutsideTheProject(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "project")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	writeManifest(t, parent, "elsewhere/node_modules/escape", `{"name":"escape","version":"1.0.0"}`)
	// A prefix climbing out of the project keeps a perfectly valid package
	// name, so the parser accepts the key; containment is decided here.
	lockfile := writeLockfile(t, root, `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "reify-test", "version": "1.0.0"},
	    "../elsewhere/node_modules/escape": {"version": "1.0.0"}
	  }
	}`)

	got := ReifyCandidates(loadEntriesForTest(t, lockfile), root)
	if len(got.Candidates) != 1 || got.Candidates[0].Reason != ReasonMissing {
		t.Fatalf("ReifyCandidates() = %#v, want one missing candidate", got.Candidates)
	}
}

func TestMatchesPlatformFollowsNpmCheckList(t *testing.T) {
	tests := []struct {
		name  string
		list  []string
		value string
		want  bool
	}{
		{name: "no constraint matches everything", list: nil, value: "linux", want: true},
		{name: "any matches everything", list: []string{"any"}, value: "linux", want: true},
		{name: "positive list naming the platform matches", list: []string{"darwin", "linux"}, value: "linux", want: true},
		{name: "positive list not naming the platform does not match", list: []string{"darwin", "win32"}, value: "linux", want: false},
		{name: "negation of the platform does not match", list: []string{"!linux"}, value: "linux", want: false},
		{name: "negations of other platforms match", list: []string{"!darwin", "!win32"}, value: "linux", want: true},
		{name: "mixed list needs a positive hit", list: []string{"!darwin", "win32"}, value: "linux", want: false},
		{name: "mixed list with a positive hit matches", list: []string{"!darwin", "linux"}, value: "linux", want: true},
		{name: "negation wins over a positive naming the same platform", list: []string{"linux", "!linux"}, value: "linux", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchesPlatform(tt.list, tt.value); got != tt.want {
				t.Fatalf("matchesPlatform(%q, %q) = %v, want %v", tt.list, tt.value, got, tt.want)
			}
		})
	}
}

// npm reads the one-value spelling too, and a shape neither spelling covers
// must read as no constraint at all — the over-auditing direction.
func TestStringListReadsBothNpmSpellings(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{name: "array", raw: `["linux","!darwin"]`, want: []string{"linux", "!darwin"}},
		{name: "bare string", raw: `"linux"`, want: []string{"linux"}},
		{name: "unreadable shape reads as absent", raw: `{"os":"linux"}`, want: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := stringList(json.RawMessage(tt.raw)); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("stringList(%s) = %#v, want %#v", tt.raw, got, tt.want)
			}
		})
	}
}

func TestNpmPlatformNamesMapGoSpellings(t *testing.T) {
	osTests := map[string]string{"linux": "linux", "darwin": "darwin", "windows": "win32", "solaris": "sunos", "freebsd": "freebsd"}
	for goos, want := range osTests {
		if got := npmOS(goos); got != want {
			t.Fatalf("npmOS(%q) = %q, want %q", goos, got, want)
		}
	}

	cpuTests := map[string]string{"amd64": "x64", "386": "ia32", "arm64": "arm64", "arm": "arm", "s390x": "s390x"}
	for goarch, want := range cpuTests {
		if got := npmCPU(goarch); got != want {
			t.Fatalf("npmCPU(%q) = %q, want %q", goarch, got, want)
		}
	}
}

func TestLoadEntriesKeepsPathsAndInstallDecisionFields(t *testing.T) {
	root := t.TempDir()
	lockfile := writeLockfile(t, root, `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "reify-test", "version": "1.0.0"},
	    "node_modules/linked": {"resolved": "packages/local", "link": true},
	    "node_modules/optional": {"version": "1.0.0", "optional": true, "dev": true, "os": ["darwin"], "cpu": "arm64"}
	  }
	}`)

	want := []Entry{
		{Path: "node_modules/linked", Link: true},
		{
			Path:     "node_modules/optional",
			Package:  Package{Name: "optional", Version: "1.0.0", Source: "unknown"},
			Optional: true,
			Dev:      true,
			OS:       []string{"darwin"},
			CPU:      []string{"arm64"},
		},
	}
	if got := loadEntriesForTest(t, lockfile); !reflect.DeepEqual(got, want) {
		t.Fatalf("LoadEntries() = %#v, want %#v", got, want)
	}
}
