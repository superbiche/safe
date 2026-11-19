package projectlane

import (
	"reflect"
	"testing"
)

func TestLoadGraphRecordsEveryField(t *testing.T) {
	packages := map[string]map[string]any{
		"node_modules/plain": entry("plain", "1.0.0"),
		"node_modules/alias": with(entry("real-name", "2.0.0"), map[string]any{"name": "real-name"}),
		"node_modules/dev":   with(entry("dev", "1.0.0"), map[string]any{"dev": true, "optional": true}),
		"node_modules/cred": with(entry("cred", "1.0.0"), map[string]any{
			"resolved": "https://user:secret@registry.npmjs.org/cred/-/cred-1.0.0.tgz",
		}),
		"node_modules/shrink":                    with(entry("shrink", "1.0.0"), map[string]any{"hasShrinkwrap": true}),
		"node_modules/shrink/node_modules/inner": {"version": "3.0.0", "inBundle": true},
		"node_modules/linked":                    {"resolved": "packages/local", "link": true},
	}
	graph := graphOf(t, packages)

	got := map[string]Occurrence{}
	for _, occurrence := range graph.Occurrences {
		occurrence.descriptor, occurrence.coverName, occurrence.coverVersion = "", "", "" // internals, not what is reported
		got[occurrence.Path] = occurrence
	}
	canonical := func(name, version string) Occurrence {
		return Occurrence{Name: name, Version: version, Origin: tarball(name, version), Integrity: integrityOf(name + "@" + version),
			Kind: KindRegistry, Host: DefaultRegistryHost, Public: true}
	}
	with := func(base Occurrence, path string, edit func(*Occurrence)) Occurrence {
		base.Path = path
		if edit != nil {
			edit(&base)
		}
		return base
	}
	shrink := canonical("shrink", "1.0.0")
	want := map[string]Occurrence{
		"node_modules/plain": with(canonical("plain", "1.0.0"), "node_modules/plain", nil),
		"node_modules/alias": with(canonical("real-name", "2.0.0"), "node_modules/alias", func(o *Occurrence) { o.Alias = "alias" }),
		"node_modules/dev":   with(canonical("dev", "1.0.0"), "node_modules/dev", func(o *Occurrence) { o.Dev, o.Optional = true, true }),
		// Credentials are redacted for the report; binding reads the original.
		"node_modules/cred":   with(canonical("cred", "1.0.0"), "node_modules/cred", nil),
		"node_modules/shrink": with(shrink, "node_modules/shrink", func(o *Occurrence) { o.Shrinkwrap = true }),
		"node_modules/shrink/node_modules/inner": {Path: "node_modules/shrink/node_modules/inner", Name: "inner", Version: "3.0.0",
			Kind: KindUnknown, Bundled: true, Host: DefaultRegistryHost, Public: true,
			CoveredBy: keyText(shrink.Key()), Member: "node_modules/inner"},
		"node_modules/linked": {Path: "node_modules/linked", Name: "linked", Origin: "packages/local", Kind: KindLink},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("occurrences =\n%#v\nwant\n%#v", got, want)
	}
	for i := 1; i < len(graph.Occurrences); i++ {
		if graph.Occurrences[i-1].Path >= graph.Occurrences[i].Path {
			t.Fatalf("occurrences are not sorted by path: %q before %q", graph.Occurrences[i-1].Path, graph.Occurrences[i].Path)
		}
	}
}

func TestLoadGraphRefusesWhatLockdiffRefuses(t *testing.T) {
	for name, content := range map[string]string{
		"version 1":   `{"lockfileVersion": 1, "dependencies": {}}`,
		"no packages": `{"lockfileVersion": 3}`,
		"not json":    `nope`,
	} {
		t.Run(name, func(t *testing.T) {
			file := t.TempDir() + "/lock.json"
			if err := writeFile(file, content); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadGraph(file, Hosts{}); err == nil {
				t.Fatal("LoadGraph() error = nil, want an error")
			}
		})
	}
	if _, err := LoadGraph(t.TempDir()+"/absent.json", Hosts{}); err == nil {
		t.Fatal("LoadGraph() on an absent file: error = nil, want an error")
	}
}

func TestPublicIdentities(t *testing.T) {
	graph := graphOf(t, map[string]map[string]any{
		"node_modules/a":                   entry("a", "1.0.0"),
		"node_modules/a/node_modules/a":    entry("a", "1.0.0"),
		"node_modules/b":                   entry("b", "2.0.0"),
		"node_modules/git":                 {"version": "1.0.0", "resolved": "git+ssh://git@github.com/x/y.git#abc"},
		"node_modules/linked":              {"resolved": "packages/local", "link": true},
		"node_modules/b/node_modules/bund": {"version": "1.0.0", "inBundle": true},
	})
	want := []Identity{{"a", "1.0.0"}, {"b", "2.0.0"}, {"bund", "1.0.0"}}
	if got := graph.Identities(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Identities() = %v, want %v", got, want)
	}
}

func TestStripCredentials(t *testing.T) {
	for in, want := range map[string]string{
		"https://u:p@host.example/a.tgz": "https://host.example/a.tgz",
		"https://token@host.example/a":   "https://host.example/a",
		"https://host.example/a":         "https://host.example/a",
		"registry.npmjs.org/a/-/a-1.tgz": "registry.npmjs.org/a/-/a-1.tgz",
		"git@github.com:x/y.git":         "git@github.com:x/y.git",
		"":                               "",
	} {
		if got := stripCredentials(in); got != want {
			t.Errorf("stripCredentials(%q) = %q, want %q", in, got, want)
		}
	}
}
