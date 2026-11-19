package projectlane

import (
	"reflect"
	"testing"
)

// Regressions for the second review of the judging core (PR 221). Each test is
// built on the reviewer's input.

const mirror = "npm.internal.example"

func mirrorEntry(name, version string) map[string]any {
	return with(entry(name, version), map[string]any{"resolved": "https://" + mirror + "/" + name + "/-/" + name + "-" + version + ".tgz"})
}

func TestIndependentlyBoundBundledChildKeepsItsOwnSource(t *testing.T) {
	bound := func(t *testing.T, graph Graph, hosts Hosts) {
		t.Helper()
		if got := CheckBindable(graph, hosts.Registry); !got.Bound {
			t.Fatalf("bindability = %+v, want bound", got)
		}
	}
	t.Run("private parent, public child with a critical advisory", func(t *testing.T) {
		packages := map[string]map[string]any{
			"node_modules/p":                 mirrorEntry("p", "1.0.0"),
			"node_modules/p/node_modules/in": with(entry("in", "1.0.0"), map[string]any{"inBundle": true}),
		}
		hosts := Hosts{Registry: []string{mirror}}
		graph := loadWith(t, packages, hosts)
		bound(t, graph, hosts)
		if got := graph.Identities(); !reflect.DeepEqual(got, []Identity{{"in", "1.0.0"}}) {
			t.Fatalf("Identities() = %v, want the public child alone", got)
		}
		report := decideWith(t, nil, packages, hosts, evidenceOf(read("in", "1.0.0", hit("TEST-A", "critical"))))
		if report.Outcome.Status != "stopped" || report.Outcome.Class != ClassBlockingAdvisory || report.Outcome.Exit != ExitBlock {
			t.Fatalf("outcome = %+v, want Blocking advisory 104", report.Outcome)
		}
		if len(report.Coverage) != 0 {
			t.Fatalf("coverage = %+v", report.Coverage)
		}
	})
	t.Run("public parent, private child: public evidence does not gate the child", func(t *testing.T) {
		packages := map[string]map[string]any{
			"node_modules/p":                 entry("p", "1.0.0"),
			"node_modules/p/node_modules/in": with(mirrorEntry("in", "1.0.0"), map[string]any{"inBundle": true}),
		}
		hosts := Hosts{Registry: []string{mirror}}
		graph := loadWith(t, packages, hosts)
		bound(t, graph, hosts)
		if got := graph.Identities(); !reflect.DeepEqual(got, []Identity{{"p", "1.0.0"}}) {
			t.Fatalf("Identities() = %v, want the public parent alone", got)
		}
		report := decideWith(t, nil, packages, hosts, evidenceOf(read("p", "1.0.0"), read("in", "1.0.0", hit("TEST-A", "critical"))))
		if report.Outcome.Status != "clear" {
			t.Fatalf("outcome = %+v, want the private child left to the private lane", report.Outcome)
		}
	})
	t.Run("an unchanged independent child under a parent whose hash changes is not introduced", func(t *testing.T) {
		child := func() map[string]any { return with(entry("in", "1.0.0"), map[string]any{"inBundle": true}) }
		before := map[string]map[string]any{"node_modules/p": entry("p", "1.0.0"), "node_modules/p/node_modules/in": child()}
		after := map[string]map[string]any{
			"node_modules/p":                 with(entry("p", "1.0.0"), map[string]any{"integrity": integrityOf("other")}),
			"node_modules/p/node_modules/in": child(),
		}
		diff := Diff(graphOf(t, before), graphOf(t, after))
		if len(diff.Introduced) != 1 || diff.Introduced[0].Name != "p" || len(diff.Dropped) != 1 {
			t.Fatalf("diff = introduced %+v dropped %+v, want only the parent", diff.Introduced, diff.Dropped)
		}
	})
}

func TestApprovalOfAStandaloneArtifactDoesNotClearAdvisoryOnBundledBytes(t *testing.T) {
	packages := map[string]map[string]any{
		"node_modules/p":                 entry("p", "1.0.0"),
		"node_modules/p/node_modules/in": {"version": "1.0.0", "inBundle": true},
	}
	base := evidenceOf(read("p", "1.0.0"), read("in", "1.0.0", hit("TEST-A", "critical")))

	standalone := decideWith(t, nil, packages, Hosts{}, base.accepting(accept(AcceptLocalExact, "in", "1.0.0")))
	if standalone.Outcome.Status != "stopped" || standalone.Outcome.Class != ClassBlockingAdvisory || standalone.Outcome.Exit != ExitBlock {
		t.Fatalf("outcome = %+v, want 104: an approval of the standalone in@1.0.0 has no authority over bytes p carries", standalone.Outcome)
	}
	cover := decideWith(t, nil, packages, Hosts{}, base.accepting(accept(AcceptLocalExact, "p", "1.0.0")))
	if cover.Outcome.Status != "clear" {
		t.Fatalf("outcome = %+v, want clear: the covering artifact's approval covers its bytes", cover.Outcome)
	}
	// The cover's approval must match its host too.
	wrongHost := base.accepting(Acceptance{Kind: AcceptLocalExact, Name: "p", Version: "1.0.0", Host: "other.example", Advisories: []string{}})
	if got := decideWith(t, nil, packages, Hosts{}, wrongHost); got.Outcome.Status == "clear" {
		t.Fatalf("outcome = %+v, want a host mismatch to clear nothing", got.Outcome)
	}
}

func TestDescriptorlessBundledAliasIsReadUnderItsDeclaredName(t *testing.T) {
	packages := map[string]map[string]any{
		"node_modules/p":                    entry("p", "1.0.0"),
		"node_modules/p/node_modules/alias": {"name": "real", "version": "1.0.0", "inBundle": true},
	}
	graph := loadWith(t, packages, Hosts{})
	if got := graph.Identities(); !reflect.DeepEqual(got, []Identity{{"p", "1.0.0"}, {"real", "1.0.0"}}) {
		t.Fatalf("Identities() = %v, want real@1.0.0 in place of alias@1.0.0", got)
	}
	var member Occurrence
	for _, occurrence := range graph.Occurrences {
		if occurrence.Bundled {
			member = occurrence
		}
	}
	if member.Name != "real" || member.Alias != "alias" {
		t.Fatalf("member = %+v, want name real and alias alias", member)
	}
	report := decideWith(t, nil, packages, Hosts{}, evidenceOf(read("p", "1.0.0"), read("real", "1.0.0", hit("TEST-A", "critical"))))
	if report.Outcome.Class != ClassBlockingAdvisory {
		t.Fatalf("outcome = %+v, want the hit on the real package to gate", report.Outcome)
	}
	// A declared name that cannot stand in a registry path is not bound.
	bad := map[string]map[string]any{
		"node_modules/p":                    entry("p", "1.0.0"),
		"node_modules/p/node_modules/alias": {"name": "re!al", "version": "1.0.0", "inBundle": true},
	}
	if got := CheckBindable(graphOf(t, bad), nil); got.Bound || got.Unbound[0].Reason != ReasonIdentityInvalid {
		t.Fatalf("bindability = %+v", got)
	}
}
