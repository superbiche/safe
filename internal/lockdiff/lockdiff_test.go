package lockdiff

import (
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
