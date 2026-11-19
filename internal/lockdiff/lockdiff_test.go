package lockdiff

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLoadFixtures(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
		want    []Package
		wantErr string
	}{
		{
			name:    "v2 extracts nested and scoped registry packages",
			fixture: "v2.json",
			want: []Package{
				{Name: "@scope/nested", Version: "2.0.0", Source: "unknown"},
				{Name: "left-pad", Version: "1.3.0", Source: "unknown"},
			},
		},
		{
			name:    "v3 skips workspace locals and links",
			fixture: "v3-workspaces.json",
			want: []Package{
				{Name: "@scope/registry", Version: "3.0.0", Source: "unknown"},
				{Name: "plain", Version: "4.0.0", Source: "unknown"},
			},
		},
		{
			// npm aliases ("foo": "npm:real-pkg@1") record the real registry
			// identity in .name; the audit must vouch for that identity,
			// never the alias path segment.
			name:    "aliased entry reports the real registry identity",
			fixture: "v3-alias.json",
			want: []Package{
				{Name: "plain", Version: "4.0.0", Source: "unknown"},
				{Name: "real-registry-pkg", Version: "1.2.3", Source: "registry", Integrity: "sha512-alias"},
			},
		},
		{
			name:    "source classes retain only registry aliases",
			fixture: "v3-sources.json",
			want: []Package{
				{Name: "file-alias", Version: "1.0.0", Source: "file", Integrity: "sha512-file"},
				{Name: "git-alias", Version: "1.0.0", Source: "git", Integrity: "sha512-git"},
				{Name: "real-registry", Version: "1.0.0", Source: "registry", Integrity: "sha512-registry"},
				{Name: "remote-alias", Version: "1.0.0", Source: "remote", Integrity: "sha512-remote"},
				{Name: "unknown", Version: "1.0.0", Source: "unknown"},
			},
		},
		{
			name:    "non-registry aliases keep their install-path name",
			fixture: "v3-nonregistry-alias.json",
			want: []Package{
				{Name: "alias", Version: "1.3.0", Source: "git", Integrity: "sha512-git"},
			},
		},
		{
			name:    "v1 is an exit-3 parse class",
			fixture: "malformed-v1.json",
			wantErr: "lockfileVersion 1",
		},
		{
			name:    "registry package missing version is an exit-3 parse class",
			fixture: "malformed-missing-version.json",
			wantErr: "missing a string version",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Load(filepath.Join("testdata", tt.fixture))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Load() error = %v, want substring %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("Load() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestCompareFixtures(t *testing.T) {
	oldPackages, err := Load(filepath.Join("testdata", "diff-old.json"))
	if err != nil {
		t.Fatal(err)
	}
	newPackages, err := Load(filepath.Join("testdata", "diff-new.json"))
	if err != nil {
		t.Fatal(err)
	}

	want := Diff{
		Schema: 1,
		Added: []Package{
			{Name: "added", Version: "1.0.0", Source: "unknown"},
		},
		Removed: []Package{
			{Name: "removed", Version: "1.0.0", Source: "unknown"},
		},
		Changed: []Change{
			{Name: "changed", From: "1.0.0", To: "2.0.0", Source: "unknown"},
		},
	}
	if got := Compare(oldPackages, newPackages); !reflect.DeepEqual(got, want) {
		t.Fatalf("Compare() = %#v, want %#v", got, want)
	}
}

func TestComparePreservesAmbiguousMultiplicityAsAddedAndRemoved(t *testing.T) {
	got := Compare(
		[]Package{{Name: "duplicate", Version: "1.0.0", Source: "unknown"}, {Name: "duplicate", Version: "1.0.0", Source: "unknown"}},
		[]Package{{Name: "duplicate", Version: "2.0.0", Source: "unknown"}, {Name: "duplicate", Version: "2.0.0", Source: "unknown"}},
	)
	want := Diff{
		Schema: 1,
		Added: []Package{
			{Name: "duplicate", Version: "2.0.0", Source: "unknown"},
			{Name: "duplicate", Version: "2.0.0", Source: "unknown"},
		},
		Removed: []Package{
			{Name: "duplicate", Version: "1.0.0", Source: "unknown"},
			{Name: "duplicate", Version: "1.0.0", Source: "unknown"},
		},
		Changed: []Change{},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Compare() = %#v, want %#v", got, want)
	}
}

func TestCompareSourceAndIntegrityChangesAreVisible(t *testing.T) {
	oldPackages, err := Load(filepath.Join("testdata", "source-change-old.json"))
	if err != nil {
		t.Fatal(err)
	}
	newPackages, err := Load(filepath.Join("testdata", "source-change-new.json"))
	if err != nil {
		t.Fatal(err)
	}

	want := Diff{
		Schema:  1,
		Added:   []Package{},
		Removed: []Package{},
		Changed: []Change{{Name: "left-pad", From: "1.3.0", To: "1.3.0", Source: "git", Integrity: "sha512-git"}},
	}
	if got := Compare(oldPackages, newPackages); !reflect.DeepEqual(got, want) {
		t.Fatalf("Compare() = %#v, want %#v", got, want)
	}
}

func TestLoadRegistryHostProvenance(t *testing.T) {
	path := filepath.Join("testdata", "v3-registry-hosts.json")
	tests := []struct {
		name  string
		hosts []string
		want  []Package
	}{
		{
			name:  "configured private registry matches case-insensitively",
			hosts: []string{"REGISTRY.EXAMPLE.TEST"},
			want: []Package{
				{Name: "evil-alias", Version: "1.3.0", Source: "remote", Integrity: "sha512-evil"},
				{Name: "real-npmjs", Version: "2.0.0", Source: "registry", Integrity: "sha512-npmjs"},
				{Name: "real-private", Version: "1.0.0", Source: "registry", Integrity: "sha512-private"},
			},
		},
		{
			name: "non-matching HTTP source remains remote while npmjs magic stays registry",
			want: []Package{
				{Name: "evil-alias", Version: "1.3.0", Source: "remote", Integrity: "sha512-evil"},
				{Name: "private-alias", Version: "1.0.0", Source: "remote", Integrity: "sha512-private"},
				{Name: "real-npmjs", Version: "2.0.0", Source: "registry", Integrity: "sha512-npmjs"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := LoadWithRegistryHosts(path, tt.hosts)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("LoadWithRegistryHosts() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestLoadRecordsKeepsTheFactsLoadEntriesDrops(t *testing.T) {
	file := writeLockfile(t, t.TempDir(), `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "root", "version": "1.0.0"},
	    "node_modules/alias": {"name": "real", "version": "2.0.0", "resolved": "https://registry.npmjs.org/real/-/real-2.0.0.tgz", "integrity": "sha512-x", "hasShrinkwrap": true},
	    "node_modules/p/node_modules/inner": {"version": "1.0.0", "inBundle": true},
	    "node_modules/linked": {"resolved": "packages/local", "link": true}
	  }
	}`)
	records, err := LoadRecords(file, nil)
	if err != nil {
		t.Fatalf("LoadRecords() error = %v", err)
	}
	want := []Record{
		{Path: "node_modules/alias", Name: "real", Alias: "alias", DeclaredName: "real", Version: "2.0.0",
			Resolved: "https://registry.npmjs.org/real/-/real-2.0.0.tgz", Integrity: "sha512-x", Source: "registry", HasShrinkwrap: true},
		{Path: "node_modules/linked", Link: true, LinkTarget: "packages/local"},
		{Path: "node_modules/p/node_modules/inner", Name: "inner", Version: "1.0.0", Source: "unknown", InBundle: true},
	}
	if !reflect.DeepEqual(records, want) {
		t.Fatalf("LoadRecords() = %#v, want %#v", records, want)
	}
}

func TestLoadEntriesIgnoresALinkResolvedThatIsNotAString(t *testing.T) {
	// The reify lane never reads a link's target. A reader it shares with the
	// project lane must keep accepting what it always accepted.
	file := writeLockfile(t, t.TempDir(), `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "root"},
	    "node_modules/linked": {"link": true, "resolved": 7},
	    "node_modules/plain": {"version": "1.0.0"}
	  }
	}`)
	entries, err := LoadEntries(file, nil)
	if err != nil {
		t.Fatalf("LoadEntries() error = %v, want the link accepted as before", err)
	}
	if len(entries) != 2 || !entries[0].Link || entries[0].Path != "node_modules/linked" {
		t.Fatalf("entries = %#v", entries)
	}
	records, err := LoadRecords(file, nil)
	if err != nil || !records[0].Link || records[0].LinkTarget != "" {
		t.Fatalf("LoadRecords() = %#v, %v", records, err)
	}
}

func TestLoadLocalPackagesReadsOnlyWhatALinkPointsAt(t *testing.T) {
	file := writeLockfile(t, t.TempDir(), `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "root", "version": "9.9.9"},
	    "node_modules/ws": {"link": true, "resolved": "packages/ws"},
	    "node_modules/noname": {"link": true, "resolved": "packages/noname"},
	    "node_modules/gone": {"link": true, "resolved": "packages/gone"},
	    "packages/ws": {"name": "ws", "version": "1.2.3"},
	    "packages/noname": {"version": "0.1.0"},
	    "packages/unlinked": {"name": "unlinked", "version": "5.0.0"}
	  }
	}`)
	got, err := LoadLocalPackages(file)
	if err != nil {
		t.Fatal(err)
	}
	want := []LocalPackage{{Path: "packages/noname", Name: "noname", Version: "0.1.0"}, {Path: "packages/ws", Name: "ws", Version: "1.2.3"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("LoadLocalPackages() = %#v, want %#v", got, want)
	}
}

func TestLoadRecordsKeepsTheDeclaredNameOfADescriptorlessEntryWhileLoadEntriesDoesNot(t *testing.T) {
	file := writeLockfile(t, t.TempDir(), `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "root"},
	    "node_modules/p/node_modules/alias": {"name": "real", "version": "1.0.0", "inBundle": true}
	  }
	}`)
	records, err := LoadRecords(file, nil)
	if err != nil || len(records) != 1 || records[0].Name != "alias" || records[0].DeclaredName != "real" {
		t.Fatalf("LoadRecords() = %#v, %v", records, err)
	}
	entries, err := LoadEntries(file, nil)
	if err != nil || len(entries) != 1 || entries[0].Package.Name != "alias" {
		t.Fatalf("LoadEntries() = %#v, %v; want the mount name, as before", entries, err)
	}
}

// A lockfile entry is read by exact, case-sensitive member names, as npm reads
// it: a second spelling of a field that matters, a repeated member and content
// after the document are refused, in every member order; unrelated npm members
// stay allowed.
func TestLoadRefusesAmbiguousLockfiles(t *testing.T) {
	const canonical = "https://registry.npmjs.org/p/-/p-1.0.0.tgz"
	const elsewhere = "https://evil.example/p-1.0.0.tgz"
	doc := func(entry string) string {
		return `{"lockfileVersion":3,"packages":{"":{"name":"root"},"node_modules/p":` + entry + `}}`
	}
	refused := map[string]string{
		"a differently cased resolved after the real one":                          doc(`{"version":"1.0.0","resolved":"` + elsewhere + `","Resolved":"` + canonical + `"}`),
		"a differently cased resolved before the real one":                         doc(`{"version":"1.0.0","Resolved":"` + canonical + `","resolved":"` + elsewhere + `"}`),
		"an upper case integrity":                                                  doc(`{"version":"1.0.0","resolved":"` + canonical + `","INTEGRITY":"sha512-x"}`),
		"a Unicode fold of link (Kelvin sign is not in it, long s is in inBundle)": doc(`{"version":"1.0.0","inBundle":true,"inBundle":false}`),
		"a repeated resolved":                                                      doc(`{"version":"1.0.0","resolved":"` + canonical + `","resolved":"` + elsewhere + `"}`),
		"a repeated packages":                                                      `{"lockfileVersion":3,"packages":{},"packages":{}}`,
		"a second spelling of packages":                                            `{"lockfileVersion":3,"packages":{},"Packages":{}}`,
		"a second spelling of lockfileVersion":                                     `{"lockfileVersion":3,"LockfileVersion":2,"packages":{}}`,
		"a stray closing brace":                                                    doc(`{"version":"1.0.0"}`) + `}`,
		"a second document":                                                        doc(`{"version":"1.0.0"}`) + doc(`{"version":"1.0.0"}`),
	}
	for name, content := range refused {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "package-lock.json")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadRecords(path, nil); err == nil {
				t.Fatal("LoadRecords() error = nil")
			}
			if _, err := LoadEntries(path, nil); err == nil {
				t.Fatal("LoadEntries() error = nil")
			}
		})
	}
	allowed := doc(`{"version":"1.0.0","resolved":"` + canonical + `","Funding":{"url":"x"},"funding":{"url":"y"},"engines":{"node":">=1"}}`)
	path := filepath.Join(t.TempDir(), "package-lock.json")
	if err := os.WriteFile(path, []byte(allowed), 0o600); err != nil {
		t.Fatal(err)
	}
	if records, err := LoadRecords(path, nil); err != nil || len(records) != 1 || records[0].Resolved != canonical {
		t.Fatalf("LoadRecords() = %+v, %v", records, err)
	}
}
