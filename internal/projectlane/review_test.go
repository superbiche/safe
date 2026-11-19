package projectlane

import (
	"reflect"
	"strings"
	"testing"
)

// Regressions for the review of the judging core (PR 221). Each test names the
// reproduction it pins.

func decideWith(t *testing.T, baseline, target map[string]map[string]any, hosts Hosts, evidence Evidence) Report {
	t.Helper()
	input := Input{Target: loadWith(t, target, hosts), Evidence: evidence, RegistryHosts: hosts.Registry}
	if baseline != nil {
		input.HasBaseline = true
		input.Baseline = loadWith(t, baseline, hosts)
	}
	return Decide(input)
}

func loadWith(t *testing.T, packages map[string]map[string]any, hosts Hosts) Graph {
	t.Helper()
	graph, err := LoadGraph(writeLock(t, packages), hosts)
	if err != nil {
		t.Fatalf("LoadGraph() error = %v", err)
	}
	return graph
}

func TestBundledChildWithALocationOfItsOwnIsNotExemptedFromBindingOrCoverage(t *testing.T) {
	// p is canonical and hashed; its nested child is flagged inBundle but names
	// a foreign location. npm fetches such a child separately.
	target := map[string]map[string]any{
		"node_modules/p":                 entry("p", "1.0.0"),
		"node_modules/p/node_modules/in": {"version": "1.0.0", "inBundle": true, "resolved": "https://evil.example/in.tgz", "integrity": integrityOf("in")},
	}
	report := decideWith(t, nil, target, Hosts{}, evidenceOf(read("p", "1.0.0")))
	if report.Bindability.Bound || len(report.Bindability.Unbound) != 1 || report.Bindability.Unbound[0].Reason != ReasonKindNotAdmitted {
		t.Fatalf("bindability = %+v, want the child unbound", report.Bindability)
	}
	if report.Outcome.Status == "clear" {
		t.Fatalf("outcome = %+v, want not clear", report.Outcome)
	}
	// The child is a public identity: its reading is owed.
	if len(report.Coverage) != 1 || report.Coverage[0].Name != "in" {
		t.Fatalf("coverage = %+v, want a gap for the child", report.Coverage)
	}
}

func TestBundledEntryIsAPublicIdentityLikeAnyOtherArtifact(t *testing.T) {
	target := map[string]map[string]any{
		"node_modules/p":                 entry("p", "1.0.0"),
		"node_modules/p/node_modules/in": {"version": "2.0.0", "inBundle": true},
	}
	graph := loadWith(t, target, Hosts{})
	if got := graph.Identities(); !reflect.DeepEqual(got, []Identity{{"in", "2.0.0"}, {"p", "1.0.0"}}) {
		t.Fatalf("Identities() = %v", got)
	}
	// Malice and advisories apply to it.
	report := decideWith(t, nil, target, Hosts{}, evidenceOf(read("p", "1.0.0"), read("in", "2.0.0", mal("MAL-2026-9"))))
	if report.Outcome.Class != ClassMalice {
		t.Fatalf("outcome = %+v, want malice on the bundled entry", report.Outcome)
	}
}

func TestOriginIsRedactedForTheReportButBindingReadsTheOriginal(t *testing.T) {
	packages := map[string]map[string]any{
		"node_modules/a": with(entry("a", "1.0.0"), map[string]any{"resolved": "https://user:secret@registry.npmjs.org/a/-/a-1.0.0.tgz"}),
	}
	graph := loadWith(t, packages, Hosts{})
	if got := graph.Occurrences[0].Origin; strings.Contains(got, "secret") || got != tarball("a", "1.0.0") {
		t.Fatalf("Origin = %q, want the credentials removed", got)
	}
	if bound := CheckBindable(graph, nil); bound.Bound || bound.Unbound[0].Reason != ReasonOriginNotCanonical {
		t.Fatalf("bindability = %+v, want the credentialed descriptor unbound", bound)
	}
}

func TestDecideClassAndAcceptanceArePerArtifact(t *testing.T) {
	t.Run("a critical carrier and a high carrier of one advisory owe a class each", func(t *testing.T) {
		// TEST-A is critical at p@1 and high at p@2. A local exact approval of
		// p@1 and a followed override that covers only an unrelated advisory at
		// p@2 must not clear the high carrier.
		target := map[string]map[string]any{
			"node_modules/p":                entry("p", "1.0.0"),
			"node_modules/q":                entry("q", "1.0.0"),
			"node_modules/q/node_modules/p": entry("p", "2.0.0"),
		}
		evidence := evidenceOf(
			read("p", "1.0.0", hit("TEST-A", "critical")),
			read("p", "2.0.0", hit("TEST-A", "high"), hit("TEST-B", "critical")),
			read("q", "1.0.0"),
		).accepting(
			accept(AcceptLocalExact, "p", "1.0.0"),
			accept(AcceptFollowedOverride, "p", "2.0.0", "TEST-B"),
		)
		report := decideWith(t, nil, target, Hosts{}, evidence)
		if report.Outcome.Status != "stopped" || report.Outcome.Class != ClassAdverseAdvisory || report.Outcome.Exit != ExitPolicy {
			t.Fatalf("outcome = %+v, want the high carrier left to the adverse class", report.Outcome)
		}
		var blocking, adverse []IntroducedAdvice
		for _, item := range report.Advisories.Introduced {
			if item.ID != "TEST-A" {
				continue
			}
			if item.Class == AdvisoryBlocking {
				blocking = append(blocking, item)
			} else {
				adverse = append(adverse, item)
			}
		}
		if len(blocking) != 1 || !blocking[0].Cleared || !reflect.DeepEqual(blocking[0].Versions, []string{"1.0.0"}) ||
			len(adverse) != 1 || adverse[0].Cleared || !reflect.DeepEqual(adverse[0].Versions, []string{"2.0.0"}) {
			t.Fatalf("items = blocking %+v adverse %+v", blocking, adverse)
		}
	})

	t.Run("a followed override is checked against the introduced blocking advisories only", func(t *testing.T) {
		// p@1 carries critical TEST-A in the baseline; p@2 carries TEST-A (already
		// present, never gates) and a new critical TEST-B. An override that
		// covers TEST-B clears the artifact.
		evidence := evidenceOf(
			read("p", "1.0.0", hit("TEST-A", "critical")),
			read("p", "2.0.0", hit("TEST-A", "critical"), hit("TEST-B", "critical")),
		).accepting(accept(AcceptFollowedOverride, "p", "2.0.0", "TEST-B"))
		report := decideWith(t, pkgs("p", "1.0.0"), pkgs("p", "2.0.0"), Hosts{}, evidence)
		if report.Outcome.Status != "clear" {
			t.Fatalf("outcome = %+v, want clear; report %+v", report.Outcome, report.Advisories)
		}
		if len(report.Advisories.AlreadyPresent) != 1 || report.Advisories.AlreadyPresent[0].ID != "TEST-A" {
			t.Fatalf("already present = %+v", report.Advisories.AlreadyPresent)
		}
	})

	t.Run("an override that leaves out an introduced blocking advisory clears none", func(t *testing.T) {
		evidence := evidenceOf(read("p", "2.0.0", hit("TEST-A", "critical"), hit("TEST-B", "critical"))).
			accepting(accept(AcceptFollowedOverride, "p", "2.0.0", "TEST-B"))
		report := decideWith(t, nil, pkgs("p", "2.0.0"), Hosts{}, evidence)
		if report.Outcome.Class != ClassBlockingAdvisory {
			t.Fatalf("outcome = %+v, want blocking left", report.Outcome)
		}
	})
}

func TestBindingHostsAndPublicEvidenceHostsAreDistinctInputs(t *testing.T) {
	mirror := "npm.internal.example"
	private := func() map[string]map[string]any {
		return map[string]map[string]any{
			"node_modules/p": with(entry("p", "1.0.0"), map[string]any{"resolved": "https://" + mirror + "/p/-/p-1.0.0.tgz"}),
			"node_modules/q": entry("q", "1.0.0"),
			// A bundled descendant follows its covering artifact.
			"node_modules/p/node_modules/in": {"version": "1.0.0", "inBundle": true},
		}
	}
	hosts := Hosts{Registry: []string{mirror}}

	graph := loadWith(t, private(), hosts)
	if bound := CheckBindable(graph, hosts.Registry); !bound.Bound {
		t.Fatalf("bindability = %+v, want the private-host artifact bound", bound)
	}
	if got := graph.Identities(); !reflect.DeepEqual(got, []Identity{{"q", "1.0.0"}}) {
		t.Fatalf("Identities() = %v, want only the public artifact in the evidence request", got)
	}
	// Public findings for the same name and version never decide it.
	report := decideWith(t, nil, private(), hosts, evidenceOf(
		read("p", "1.0.0", hit("TEST-A", "critical")), read("in", "1.0.0", mal("MAL-2026-7")), read("q", "1.0.0")))
	if report.Outcome.Status != "clear" || len(report.Advisories.Introduced) != 0 || len(report.Malice) != 0 {
		t.Fatalf("report = %+v, want public findings ignored for the private artifact and its descendant", report)
	}

	// The same host named as eligible for public evidence is decided on it.
	hosts.PublicEvidence = []string{mirror}
	graph = loadWith(t, private(), hosts)
	if got := graph.Identities(); len(got) != 3 {
		t.Fatalf("Identities() = %v, want all three once the host is eligible", got)
	}
}

func TestBundledEntryIsKeyedByItsCoveringArtifact(t *testing.T) {
	child := func() map[string]any { return map[string]any{"version": "1.0.0", "inBundle": true} }
	t.Run("a parent that changes at the same version introduces its bundled entry", func(t *testing.T) {
		before := map[string]map[string]any{"node_modules/p": entry("p", "1.0.0"), "node_modules/p/node_modules/in": child()}
		after := map[string]map[string]any{
			"node_modules/p":                 with(entry("p", "1.0.0"), map[string]any{"integrity": integrityOf("other")}),
			"node_modules/p/node_modules/in": child(),
		}
		diff := Diff(graphOf(t, before), graphOf(t, after))
		reasons := map[string]string{}
		for _, introduced := range diff.Introduced {
			reasons[introduced.Name] = introduced.Reason
		}
		if reasons["p"] != IntroducedIntegrity || reasons["in"] != IntroducedCovering || len(diff.Introduced) != 2 {
			t.Fatalf("introduced = %+v", diff.Introduced)
		}
	})
	t.Run("the same child identity bundled by two parents is two artifacts", func(t *testing.T) {
		one := map[string]map[string]any{"node_modules/p": entry("p", "1.0.0"), "node_modules/p/node_modules/in": child()}
		both := map[string]map[string]any{
			"node_modules/p":                 entry("p", "1.0.0"),
			"node_modules/p/node_modules/in": child(),
			"node_modules/r":                 entry("r", "1.0.0"),
			"node_modules/r/node_modules/in": child(),
		}
		diff := Diff(graphOf(t, one), graphOf(t, both))
		if len(diff.Introduced) != 2 || len(diff.Dropped) != 0 {
			t.Fatalf("diff = %+v, want r and r's own copy of the child introduced", diff)
		}
		var childOfR *Introduced
		for i := range diff.Introduced {
			if diff.Introduced[i].Name == "in" {
				childOfR = &diff.Introduced[i]
			}
		}
		if childOfR == nil || !strings.HasPrefix(childOfR.CoveredBy, "r@1.0.0") || childOfR.Member != "node_modules/in" {
			t.Fatalf("introduced = %+v, want the child keyed by r", diff.Introduced)
		}
	})
	t.Run("an unchanged parent leaves its bundled entry alone", func(t *testing.T) {
		packages := map[string]map[string]any{"node_modules/p": entry("p", "1.0.0"), "node_modules/p/node_modules/in": child()}
		if diff := Diff(graphOf(t, packages), graphOf(t, packages)); len(diff.Introduced) != 0 || len(diff.Dropped) != 0 {
			t.Fatalf("diff = %+v", diff)
		}
	})
}

func TestWorkspaceMemberVersionChangeShowsInTheDifference(t *testing.T) {
	member := func(version string) map[string]map[string]any {
		return map[string]map[string]any{
			"node_modules/ws": {"resolved": "packages/ws", "link": true},
			"packages/ws":     {"name": "ws", "version": version},
		}
	}
	graph := graphOf(t, member("1.0.0"))
	if len(graph.Occurrences) != 2 {
		t.Fatalf("occurrences = %+v, want the link and its local target kept apart", graph.Occurrences)
	}
	diff := Diff(graph, graphOf(t, member("1.0.1")))
	if len(diff.Changed) != 1 || diff.Changed[0].Name != "ws" ||
		!reflect.DeepEqual(diff.Changed[0].Before, []string{"", "1.0.0"}) || !reflect.DeepEqual(diff.Changed[0].After, []string{"", "1.0.1"}) {
		t.Fatalf("changed = %+v", diff.Changed)
	}
	if got := graph.Identities(); len(got) != 0 {
		t.Fatalf("Identities() = %v, want a local member to be no public identity", got)
	}
}

func TestReadEvidenceRefusesASecondSpellingOfASchemaField(t *testing.T) {
	// U+017F (long s) folds to "s" in encoding/json's field matching but not
	// under strings.ToLower, so it slips the repeated-member guard; the exact
	// allowlist is what refuses it.
	cases := map[string]string{
		"top level":    `{"schema_version":1,"policy":{"block_severities":["critical"]},"identities":[],"blocklist":[],"acceptances":[],"identitieſ":[]}`,
		"policy":       `{"schema_version":1,"policy":{"block_severities":["critical"],"block_ſeverities":[]},"identities":[],"blocklist":[],"acceptances":[]}`,
		"upper case":   `{"schema_version":1,"policy":{"block_severities":["critical"],"Block_Severities":[]},"identities":[],"blocklist":[],"acceptances":[]}`,
		"in a list":    `{"schema_version":1,"policy":{"block_severities":[]},"identities":[{"name":"p","version":"1","coverage":"complete","gap":"","advisories":[],"Name":"q"}],"blocklist":[],"acceptances":[]}`,
		"kelvin sign":  `{"schema_version":1,"policy":{"block_severities":[]},"identities":[],"blocklist":[{"name":"p","reaſon":"x","reason":"y"}],"acceptances":[]}`,
		"advisory hit": `{"schema_version":1,"policy":{"block_severities":[]},"identities":[{"name":"p","version":"1","coverage":"complete","gap":"","advisories":[{"id":"A-1","severity":"low","malware":false,"ſeverity":"critical"}]}],"blocklist":[],"acceptances":[]}`,
	}
	for name, document := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ReadEvidence([]byte(document))
			if err == nil {
				t.Fatal("ReadEvidence() error = nil, want a refusal")
			}
			// The ASCII-case spellings are caught by the repeated-member guard
			// already; the Unicode folds only by the exact allowlist.
			if strings.ContainsRune(document, 'ſ') && !strings.Contains(err.Error(), "not part of the schema") {
				t.Fatalf("ReadEvidence() error = %v, want a stray-key refusal", err)
			}
		})
	}
}
