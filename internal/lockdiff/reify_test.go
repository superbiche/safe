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
	got := ReifyCandidates(loadEntriesForTest(t, lockfile), root, Platform{})
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

	encoded, err := json.Marshal(ReifyCandidates(loadEntriesForTest(t, lockfile), root, Platform{}))
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"schema":1,"candidates":[]}`; string(encoded) != want {
		t.Fatalf("ReifyCandidates() encoded = %s, want %s", encoded, want)
	}
}

// npm replaces a symlinked actual node with the projected ordinary package
// during reify, so a symlink carrying the locked version is a materialization
// the tree cannot vouch for (r1 review F1: the tree read as complete, and
// npm prune turned the symlink into a directory).
func TestReifyCandidatesTreatsSymlinkedEntriesAsCandidates(t *testing.T) {
	root := t.TempDir()
	// The link target sits outside node_modules the way `npm link` leaves it.
	writeManifest(t, root, "local/artifact", `{"name":"artifact","version":"1.0.0"}`)
	writeManifest(t, root, "local/node_modules/nested", `{"name":"nested","version":"1.0.0"}`)
	if err := os.MkdirAll(filepath.Join(root, "node_modules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "local", "artifact"), filepath.Join(root, "node_modules", "artifact")); err != nil {
		t.Fatal(err)
	}
	// A symlinked PARENT component hides the same substitution one level down.
	if err := os.Symlink(filepath.Join(root, "local"), filepath.Join(root, "node_modules", "parent")); err != nil {
		t.Fatal(err)
	}
	lockfile := writeLockfile(t, root, `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "reify-test", "version": "1.0.0"},
	    "node_modules/artifact": {"version": "1.0.0", "resolved": "file:../artifact/artifact-1.0.0.tgz", "integrity": "sha512-file"},
	    "node_modules/parent/node_modules/nested": {"version": "1.0.0"}
	  }
	}`)

	want := []Candidate{
		{Path: "node_modules/artifact", Name: "artifact", Version: "1.0.0", Source: "file", Integrity: "sha512-file", Reason: ReasonSymlinked},
		{Path: "node_modules/parent/node_modules/nested", Name: "nested", Version: "1.0.0", Source: "unknown", Reason: ReasonSymlinked},
	}
	got := ReifyCandidates(loadEntriesForTest(t, lockfile), root, Platform{})
	if !reflect.DeepEqual(got.Candidates, want) {
		t.Fatalf("ReifyCandidates() = %#v, want %#v", got.Candidates, want)
	}
}

// A workspace member is a symlink on disk by construction. It stays skipped:
// npm creates that link rather than fetching anything, so the symlink rule
// must sit behind the link:true skip, not in front of it.
func TestReifyCandidatesStillSkipsLinkEntriesThatAreSymlinks(t *testing.T) {
	root := t.TempDir()
	writeManifest(t, root, "packages/member", `{"name":"member","version":"1.0.0"}`)
	if err := os.MkdirAll(filepath.Join(root, "node_modules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "packages", "member"), filepath.Join(root, "node_modules", "member")); err != nil {
		t.Fatal(err)
	}
	lockfile := writeLockfile(t, root, `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "reify-test", "version": "1.0.0"},
	    "packages/member": {"name": "member", "version": "1.0.0"},
	    "node_modules/member": {"resolved": "packages/member", "link": true}
	  }
	}`)

	if got := ReifyCandidates(loadEntriesForTest(t, lockfile), root, Platform{}); len(got.Candidates) != 0 {
		t.Fatalf("ReifyCandidates() = %#v, want no candidates", got.Candidates)
	}
}

// One lstat per path prefix, not per entry: a real tree carries thousands of
// entries under a handful of shared components.
func TestTreeProbeMemoizesEachPathComponentOnce(t *testing.T) {
	root := t.TempDir()
	writeManifest(t, root, "local/first", `{"name":"first","version":"1.0.0"}`)
	writeManifest(t, root, "local/second", `{"name":"second","version":"1.0.0"}`)
	if err := os.MkdirAll(filepath.Join(root, "node_modules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "local"), filepath.Join(root, "node_modules", "shared")); err != nil {
		t.Fatal(err)
	}

	probe := newTreeProbe(root)
	for _, path := range []string{"node_modules/shared/first", "node_modules/shared/second"} {
		reason, ok := probe.reason(Entry{Path: path, Package: Package{Name: filepath.Base(path), Version: "1.0.0"}})
		if !ok || reason != ReasonSymlinked {
			t.Fatalf("reason(%q) = %q, %v, want %q, true", path, reason, ok, ReasonSymlinked)
		}
	}
	want := map[string]bool{"node_modules": false, "node_modules/shared": true}
	if !reflect.DeepEqual(probe.symlinks, want) {
		t.Fatalf("probe.symlinks = %#v, want %#v", probe.symlinks, want)
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

	got := ReifyCandidates(loadEntriesForTest(t, lockfile), root, Platform{})
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

	got := ReifyCandidates(loadEntriesForTest(t, lockfile), root, Platform{})
	if len(got.Candidates) != 1 || got.Candidates[0].Reason != ReasonMissing {
		t.Fatalf("ReifyCandidates() = %#v, want one missing candidate", got.Candidates)
	}
}

func otherCPU(current string) string {
	if current == "x64" {
		return "arm64"
	}
	return "x64"
}

// npm resolves optional os/cpu against its EFFECTIVE target, and --os/--cpu
// move it (r1 review F2: npm prune --os=aix installed an aix-only optional
// that the host-platform exemption had skipped).
func TestReifyCandidatesFollowsTheTargetPlatform(t *testing.T) {
	root := t.TempDir()
	elsewhereOS, elsewhereCPU := otherPlatform(currentOS), otherCPU(currentCPU)
	lockfile := writeLockfile(t, root, fmt.Sprintf(`{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "reify-test", "version": "1.0.0"},
	    "node_modules/os-bound": {"version": "1.0.0", "optional": true, "os": [%q]},
	    "node_modules/cpu-bound": {"version": "1.0.0", "optional": true, "cpu": [%q]}
	  }
	}`, elsewhereOS, elsewhereCPU))
	entries := loadEntriesForTest(t, lockfile)

	paths := func(candidates []Candidate) []string {
		found := make([]string, 0, len(candidates))
		for _, candidate := range candidates {
			found = append(found, candidate.Path)
		}
		return found
	}

	tests := []struct {
		name     string
		platform Platform
		want     []string
	}{
		{name: "host platform exempts both", platform: Platform{}, want: []string{}},
		{name: "os override makes the os-bound entry reachable", platform: Platform{OS: elsewhereOS}, want: []string{"node_modules/os-bound"}},
		{name: "cpu override makes the cpu-bound entry reachable", platform: Platform{CPU: elsewhereCPU}, want: []string{"node_modules/cpu-bound"}},
		{
			name:     "both overrides reach both entries",
			platform: Platform{OS: elsewhereOS, CPU: elsewhereCPU},
			want:     []string{"node_modules/cpu-bound", "node_modules/os-bound"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := paths(ReifyCandidates(entries, root, tt.platform).Candidates); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ReifyCandidates(%+v) = %v, want %v", tt.platform, got, tt.want)
			}
		})
	}
}

// An override arrives from npm's own argv, so it is already in npm's
// namespace: translating it would turn the operator's exact target into a
// different one.
func TestReifyCandidatesUsesOverridesVerbatim(t *testing.T) {
	root := t.TempDir()
	lockfile := writeLockfile(t, root, `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "reify-test", "version": "1.0.0"},
	    "node_modules/win-only": {"version": "1.0.0", "optional": true, "os": ["win32"]}
	  }
	}`)
	entries := loadEntriesForTest(t, lockfile)

	if got := ReifyCandidates(entries, root, Platform{OS: "win32"}).Candidates; len(got) != 1 {
		t.Fatalf("ReifyCandidates(win32) = %#v, want one candidate", got)
	}
	// Go's spelling of that platform is not npm's, and nothing translates it.
	if got := ReifyCandidates(entries, root, Platform{OS: "windows"}).Candidates; len(got) != 0 {
		t.Fatalf("ReifyCandidates(windows) = %#v, want no candidates", got)
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
