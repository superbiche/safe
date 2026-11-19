package projectlane

import (
	"reflect"
	"testing"
)

func TestDiff(t *testing.T) {
	changedOrigin := func(name, version string) map[string]any {
		return with(entry(name, version), map[string]any{"resolved": "https://registry.npmjs.org/" + name + "/-/" + name + "-" + version + ".tgz?x=1"})
	}
	changedHash := func(name, version string) map[string]any {
		return with(entry(name, version), map[string]any{"integrity": integrityOf("other")})
	}
	cases := []struct {
		name             string
		baseline, target map[string]map[string]any
		added, removed   []NameSet
		changed          []NameChange
		introduced       []Introduced
		dropped          []ArtifactKey
	}{
		{name: "empty baseline introduces the whole graph",
			target: pkgs("a", "1.0.0", "b", "2.0.0"),
			added:  []NameSet{{"a", []string{"1.0.0"}}, {"b", []string{"2.0.0"}}},
			introduced: []Introduced{
				{ArtifactKey: key("a", "1.0.0"), Reason: IntroducedNew, Occurrences: []string{"node_modules/a"}},
				{ArtifactKey: key("b", "2.0.0"), Reason: IntroducedNew, Occurrences: []string{"node_modules/b"}},
			}},
		{name: "identical graphs introduce nothing", baseline: pkgs("a", "1.0.0"), target: pkgs("a", "1.0.0")},
		{name: "bump is a change with one introduced and one dropped artifact",
			baseline: pkgs("a", "1.0.0"), target: pkgs("a", "1.1.0"),
			changed:    []NameChange{{"a", []string{"1.0.0"}, []string{"1.1.0"}}},
			introduced: []Introduced{{ArtifactKey: key("a", "1.1.0"), Reason: IntroducedNew, Occurrences: []string{"node_modules/a"}}},
			dropped:    []ArtifactKey{key("a", "1.0.0")}},
		{name: "removal", baseline: pkgs("a", "1.0.0", "b", "1.0.0"), target: pkgs("a", "1.0.0"),
			removed: []NameSet{{"b", []string{"1.0.0"}}}, dropped: []ArtifactKey{key("b", "1.0.0")}},
		{name: "same version, different origin is introduced",
			baseline: map[string]map[string]any{"node_modules/a": entry("a", "1.0.0")},
			target:   map[string]map[string]any{"node_modules/a": changedOrigin("a", "1.0.0")},
			changed:  []NameChange{{"a", []string{"1.0.0"}, []string{"1.0.0"}}},
			introduced: []Introduced{{
				ArtifactKey: ArtifactKey{"a", "1.0.0", tarball("a", "1.0.0") + "?x=1", integrityOf("a@1.0.0")},
				Reason:      IntroducedOrigin, Occurrences: []string{"node_modules/a"}}},
			dropped: []ArtifactKey{key("a", "1.0.0")}},
		{name: "same version, different hash is introduced",
			baseline: map[string]map[string]any{"node_modules/a": entry("a", "1.0.0")},
			target:   map[string]map[string]any{"node_modules/a": changedHash("a", "1.0.0")},
			changed:  []NameChange{{"a", []string{"1.0.0"}, []string{"1.0.0"}}},
			introduced: []Introduced{{
				ArtifactKey: ArtifactKey{"a", "1.0.0", tarball("a", "1.0.0"), integrityOf("other")},
				Reason:      IntroducedIntegrity, Occurrences: []string{"node_modules/a"}}},
			dropped: []ArtifactKey{key("a", "1.0.0")}},
		{name: "same artifact at another path is not introduced",
			baseline: pkgs("a", "1.0.0"),
			target: map[string]map[string]any{
				"node_modules/a":                entry("a", "1.0.0"),
				"node_modules/b":                entry("b", "1.0.0"),
				"node_modules/b/node_modules/a": entry("a", "1.0.0"),
			},
			added:      []NameSet{{"b", []string{"1.0.0"}}},
			introduced: []Introduced{{ArtifactKey: key("b", "1.0.0"), Reason: IntroducedNew, Occurrences: []string{"node_modules/b"}}}},
		{name: "package at several versions: a second version is a change",
			baseline: pkgs("a", "1.0.0"),
			target: map[string]map[string]any{
				"node_modules/a":                entry("a", "1.0.0"),
				"node_modules/b":                entry("b", "1.0.0"),
				"node_modules/b/node_modules/a": entry("a", "2.0.0"),
			},
			added:   []NameSet{{"b", []string{"1.0.0"}}},
			changed: []NameChange{{"a", []string{"1.0.0"}, []string{"1.0.0", "2.0.0"}}},
			introduced: []Introduced{
				{ArtifactKey: key("a", "2.0.0"), Reason: IntroducedNew, Occurrences: []string{"node_modules/b/node_modules/a"}},
				{ArtifactKey: key("b", "1.0.0"), Reason: IntroducedNew, Occurrences: []string{"node_modules/b"}},
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Diff(graphOf(t, tc.baseline), graphOf(t, tc.target))
			check := func(label string, got, want any) {
				if !reflect.DeepEqual(got, want) {
					t.Errorf("%s = %#v, want %#v", label, got, want)
				}
			}
			check("added", nonNilSets(got.Added), nonNilSets(tc.added))
			check("removed", nonNilSets(got.Removed), nonNilSets(tc.removed))
			if len(got.Changed) != len(tc.changed) || (len(tc.changed) > 0 && !reflect.DeepEqual(got.Changed, tc.changed)) {
				t.Errorf("changed = %#v, want %#v", got.Changed, tc.changed)
			}
			if len(got.Introduced) != len(tc.introduced) || (len(tc.introduced) > 0 && !reflect.DeepEqual(got.Introduced, tc.introduced)) {
				t.Errorf("introduced = %#v, want %#v", got.Introduced, tc.introduced)
			}
			droppedKeys := []ArtifactKey{}
			for _, dropped := range got.Dropped {
				droppedKeys = append(droppedKeys, dropped.ArtifactKey)
			}
			if len(droppedKeys) != len(tc.dropped) || (len(tc.dropped) > 0 && !reflect.DeepEqual(droppedKeys, tc.dropped)) {
				t.Errorf("dropped = %#v, want %#v", droppedKeys, tc.dropped)
			}
		})
	}
}

func nonNilSets(sets []NameSet) []NameSet {
	if sets == nil {
		return []NameSet{}
	}
	return sets
}

// key is the artifact key of a canonical entry.
func key(name, version string) ArtifactKey {
	return ArtifactKey{Name: name, Version: version, Origin: tarball(name, version), Integrity: integrityOf(name + "@" + version)}
}
