package projectlane

import (
	"reflect"
	"testing"
)

func hit(id, severity string) AdvisoryHit { return AdvisoryHit{ID: id, Severity: severity} }
func mal(id string) AdvisoryHit {
	return AdvisoryHit{ID: id, Severity: SeverityCritical, Malware: true}
}

func read(name, version string, hits ...AdvisoryHit) IdentityEvidence {
	return IdentityEvidence{Name: name, Version: version, Coverage: CoverageComplete, Advisories: orEmpty(hits)}
}

func gap(name, version string, hits ...AdvisoryHit) IdentityEvidence {
	return IdentityEvidence{Name: name, Version: version, Coverage: CoverageMissing, Gap: "OSV batch query failed", Advisories: orEmpty(hits)}
}

func orEmpty(hits []AdvisoryHit) []AdvisoryHit {
	if hits == nil {
		return []AdvisoryHit{}
	}
	return hits
}

func evidenceOf(identities ...IdentityEvidence) Evidence {
	return Evidence{
		SchemaVersion: EvidenceSchema, Policy: Policy{BlockSeverities: []string{SeverityCritical}},
		Identities: identities, Blocklist: []BlocklistHit{}, Acceptances: []Acceptance{},
	}
}

func (e Evidence) blocklisted(names ...string) Evidence {
	for _, name := range names {
		e.Blocklist = append(e.Blocklist, BlocklistHit{Name: name, Reason: "operator blocklist"})
	}
	return e
}

func (e Evidence) accepting(acceptances ...Acceptance) Evidence {
	e.Acceptances = append(e.Acceptances, acceptances...)
	return e
}

func (e Evidence) blocking(severities ...string) Evidence {
	e.Policy.BlockSeverities = severities
	return e
}

func accept(kind, name, version string, advisories ...string) Acceptance {
	if advisories == nil {
		advisories = []string{}
	}
	return Acceptance{Kind: kind, Name: name, Version: version, Host: DefaultRegistryHost, Advisories: advisories}
}

type outcomeWant struct {
	status, class string
	exit          int
}

func TestDecide(t *testing.T) {
	cases := []struct {
		name             string
		baseline, target map[string]map[string]any
		noBaseline       bool
		baselineError    string
		evidence         Evidence
		want             outcomeWant
		check            func(t *testing.T, r Report)
	}{
		{name: "an update that fixes a critical passes and reports the fix",
			baseline: pkgs("p", "1.0.0"), target: pkgs("p", "1.1.0"),
			evidence: evidenceOf(read("p", "1.0.0", hit("GHSA-a", "critical")), read("p", "1.1.0")),
			want:     outcomeWant{"clear", "", 0},
			check: func(t *testing.T, r Report) {
				if len(r.Advisories.Fixed) != 1 || r.Advisories.Fixed[0].ID != "GHSA-a" || r.Advisories.Fixed[0].Severity != "critical" {
					t.Fatalf("fixed = %+v", r.Advisories.Fixed)
				}
			}},
		{name: "an advisory still present on a bumped package never gates",
			baseline: pkgs("p", "1.0.0"), target: pkgs("p", "1.1.0"),
			evidence: evidenceOf(read("p", "1.0.0", hit("GHSA-a", "critical")), read("p", "1.1.0", hit("GHSA-a", "critical"))),
			want:     outcomeWant{"clear", "", 0},
			check: func(t *testing.T, r Report) {
				if len(r.Advisories.AlreadyPresent) != 1 || !r.Advisories.AlreadyPresent[0].ExposureChanged ||
					len(r.Advisories.Introduced) != 0 {
					t.Fatalf("advisories = %+v", r.Advisories)
				}
			}},
		{name: "an advisory present at one version stays present when a second version is added",
			baseline: pkgs("p", "1.0.0"),
			target: map[string]map[string]any{
				"node_modules/p":                entry("p", "1.0.0"),
				"node_modules/q":                entry("q", "1.0.0"),
				"node_modules/q/node_modules/p": entry("p", "1.0.1"),
			},
			evidence: evidenceOf(read("p", "1.0.0", hit("GHSA-a", "critical")), read("p", "1.0.1", hit("GHSA-a", "critical")), read("q", "1.0.0")),
			want:     outcomeWant{"clear", "", 0},
			check: func(t *testing.T, r Report) {
				present := r.Advisories.AlreadyPresent
				if len(present) != 1 || !reflect.DeepEqual(present[0].VersionsBefore, []string{"1.0.0"}) ||
					!reflect.DeepEqual(present[0].VersionsAfter, []string{"1.0.0", "1.0.1"}) ||
					present[0].OccurrencesBefore != 1 || present[0].OccurrencesAfter != 2 || !present[0].ExposureChanged {
					t.Fatalf("already present = %+v", present)
				}
			}},
		{name: "an unchanged advisory is not flagged as changed exposure",
			baseline: pkgs("p", "1.0.0"), target: pkgs("p", "1.0.0"),
			evidence: evidenceOf(read("p", "1.0.0", hit("GHSA-a", "high"))),
			want:     outcomeWant{"clear", "", 0},
			check: func(t *testing.T, r Report) {
				if len(r.Advisories.AlreadyPresent) != 1 || r.Advisories.AlreadyPresent[0].ExposureChanged {
					t.Fatalf("already present = %+v", r.Advisories.AlreadyPresent)
				}
			}},
		{name: "a new critical blocks",
			baseline: pkgs("a", "1.0.0"), target: pkgs("a", "1.0.0", "p", "1.0.0"),
			evidence: evidenceOf(read("a", "1.0.0"), read("p", "1.0.0", hit("GHSA-a", "critical"))),
			want:     outcomeWant{"stopped", ClassBlockingAdvisory, ExitBlock}},
		{name: "a new high is adverse",
			baseline: pkgs("a", "1.0.0"), target: pkgs("a", "1.0.0", "p", "1.0.0"),
			evidence: evidenceOf(read("a", "1.0.0"), read("p", "1.0.0", hit("GHSA-a", "high"))),
			want:     outcomeWant{"stopped", ClassAdverseAdvisory, ExitPolicy}},
		{name: "a new unreadable severity is adverse",
			target:     pkgs("p", "1.0.0"),
			evidence:   evidenceOf(read("p", "1.0.0", hit("GHSA-a", "unknown"))),
			noBaseline: true,
			want:       outcomeWant{"stopped", ClassAdverseAdvisory, ExitPolicy}},
		{name: "a new moderate informs and never gates",
			target: pkgs("p", "1.0.0"), noBaseline: true,
			evidence: evidenceOf(read("p", "1.0.0", hit("GHSA-a", "moderate"), hit("GHSA-b", "low"))),
			want:     outcomeWant{"clear", "", 0},
			check: func(t *testing.T, r Report) {
				for _, item := range r.Advisories.Introduced {
					if item.Class != AdvisoryBelowHigh || !item.Cleared {
						t.Fatalf("introduced = %+v", r.Advisories.Introduced)
					}
				}
				if len(r.Advisories.Introduced) != 2 {
					t.Fatalf("introduced = %+v", r.Advisories.Introduced)
				}
			}},
		{name: "block_severities widens what blocks",
			target: pkgs("p", "1.0.0"), noBaseline: true,
			evidence: evidenceOf(read("p", "1.0.0", hit("GHSA-a", "high"))).blocking(SeverityCritical, SeverityHigh),
			want:     outcomeWant{"stopped", ClassBlockingAdvisory, ExitBlock}},
		{name: "an empty block set leaves a critical adverse, not blocking",
			target: pkgs("p", "1.0.0"), noBaseline: true,
			evidence: evidenceOf(read("p", "1.0.0", hit("GHSA-a", "critical"))).blocking(),
			want:     outcomeWant{"stopped", ClassAdverseAdvisory, ExitPolicy}},
		{name: "an introduced finding alongside a fix is refused",
			baseline: pkgs("p", "1.0.0"), target: pkgs("p", "1.1.0"),
			evidence: evidenceOf(read("p", "1.0.0", hit("GHSA-old", "critical")), read("p", "1.1.0", hit("GHSA-new", "critical"))),
			want:     outcomeWant{"stopped", ClassBlockingAdvisory, ExitBlock},
			check: func(t *testing.T, r Report) {
				if len(r.Advisories.Fixed) != 1 || r.Advisories.Fixed[0].ID != "GHSA-old" ||
					len(r.Advisories.Introduced) != 1 || r.Advisories.Introduced[0].ID != "GHSA-new" {
					t.Fatalf("advisories = %+v", r.Advisories)
				}
			}},
		{name: "aliased package is judged under its real name",
			target:     map[string]map[string]any{"node_modules/al": with(entry("real", "1.0.0"), map[string]any{"name": "real"})},
			noBaseline: true,
			evidence:   evidenceOf(read("real", "1.0.0", hit("GHSA-a", "critical"))),
			want:       outcomeWant{"stopped", ClassBlockingAdvisory, ExitBlock}},

		// Missing evidence.
		{name: "missing coverage on the target side is missing evidence",
			baseline: pkgs("p", "1.0.0"), target: pkgs("p", "1.1.0"),
			evidence: evidenceOf(read("p", "1.0.0"), gap("p", "1.1.0")),
			want:     outcomeWant{"stopped", ClassMissingEvidence, ExitOperator}},
		{name: "missing coverage on the baseline side is missing evidence",
			baseline: pkgs("p", "1.0.0"), target: pkgs("p", "1.1.0"),
			evidence: evidenceOf(gap("p", "1.0.0"), read("p", "1.1.0")),
			want:     outcomeWant{"stopped", ClassMissingEvidence, ExitOperator},
			check: func(t *testing.T, r Report) {
				if len(r.Coverage) != 1 || !reflect.DeepEqual(r.Coverage[0].Sides, []string{"baseline"}) {
					t.Fatalf("coverage = %+v", r.Coverage)
				}
			}},
		{name: "an identity with no reading at all is missing, never clean",
			target: pkgs("p", "1.0.0"), noBaseline: true, evidence: evidenceOf(),
			want: outcomeWant{"stopped", ClassMissingEvidence, ExitOperator}},
		{name: "a block read from the part that was read still stands",
			baseline: pkgs("a", "1.0.0"), target: pkgs("a", "1.0.0", "p", "1.0.0"),
			evidence: evidenceOf(read("a", "1.0.0"), gap("p", "1.0.0", hit("GHSA-a", "critical"))),
			want:     outcomeWant{"stopped", ClassBlockingAdvisory, ExitBlock},
			check: func(t *testing.T, r Report) {
				if len(r.Coverage) != 1 || len(r.Advisories.Introduced) != 1 {
					t.Fatalf("report = %+v", r)
				}
			}},
		{name: "an advisory the unread part of the baseline might hold is not called introduced",
			baseline: map[string]map[string]any{
				"node_modules/p":                entry("p", "1.0.0"),
				"node_modules/q":                entry("q", "1.0.0"),
				"node_modules/q/node_modules/p": entry("p", "2.0.0"),
			},
			target:   pkgs("p", "3.0.0"),
			evidence: evidenceOf(read("p", "1.0.0"), gap("p", "2.0.0"), read("p", "3.0.0", hit("GHSA-a", "critical")), read("q", "1.0.0")),
			want:     outcomeWant{"stopped", ClassMissingEvidence, ExitOperator},
			check: func(t *testing.T, r Report) {
				if len(r.Advisories.Introduced) != 0 {
					t.Fatalf("introduced = %+v", r.Advisories.Introduced)
				}
			}},
		{name: "an advisory the read part of the baseline holds is already present",
			baseline: map[string]map[string]any{
				"node_modules/p":                entry("p", "1.0.0"),
				"node_modules/q":                entry("q", "1.0.0"),
				"node_modules/q/node_modules/p": entry("p", "2.0.0"),
			},
			target:   pkgs("p", "3.0.0"),
			evidence: evidenceOf(read("p", "1.0.0", hit("GHSA-a", "critical")), gap("p", "2.0.0"), read("p", "3.0.0", hit("GHSA-a", "critical")), read("q", "1.0.0")),
			want:     outcomeWant{"stopped", ClassMissingEvidence, ExitOperator},
			check: func(t *testing.T, r Report) {
				if len(r.Advisories.AlreadyPresent) != 1 || len(r.Advisories.Introduced) != 0 {
					t.Fatalf("advisories = %+v", r.Advisories)
				}
			}},
		{name: "missing coverage of a package the command removes is not owed",
			baseline: pkgs("a", "1.0.0", "gone", "1.0.0"), target: pkgs("a", "1.0.0"),
			evidence: evidenceOf(read("a", "1.0.0"), gap("gone", "1.0.0")),
			want:     outcomeWant{"clear", "", 0}},
		{name: "a baseline that cannot be read is missing evidence, never an empty baseline",
			target: pkgs("p", "1.0.0"), baselineError: "read: permission denied",
			evidence: evidenceOf(read("p", "1.0.0", hit("GHSA-a", "critical"))),
			want:     outcomeWant{"stopped", ClassMissingEvidence, ExitOperator},
			check: func(t *testing.T, r Report) {
				if r.Baseline.Source != "unreadable" || len(r.Advisories.Introduced) != 0 {
					t.Fatalf("report = %+v", r)
				}
			}},

		// Malice.
		{name: "a blocklist hit on a target package is malice",
			baseline: pkgs("a", "1.0.0"), target: pkgs("a", "1.0.0", "evil", "1.0.0"),
			evidence: evidenceOf(read("a", "1.0.0"), read("evil", "1.0.0")).blocklisted("evil"),
			want:     outcomeWant{"stopped", ClassMalice, ExitBlock}},
		{name: "a blocklist hit on a removed package does not block",
			baseline: pkgs("a", "1.0.0", "evil", "1.0.0"), target: pkgs("a", "1.0.0"),
			evidence: evidenceOf(read("a", "1.0.0"), read("evil", "1.0.0")).blocklisted("evil"),
			want:     outcomeWant{"clear", "", 0}},
		{name: "a blocklist hit on a package already in the baseline is still malice",
			baseline: pkgs("evil", "1.0.0"), target: pkgs("evil", "1.0.0"),
			evidence: evidenceOf(read("evil", "1.0.0")).blocklisted("evil"),
			want:     outcomeWant{"stopped", ClassMalice, ExitBlock}},
		{name: "a known-malware record without a score on an untouched package blocks",
			baseline: pkgs("p", "1.0.0"), target: pkgs("p", "1.0.0"),
			evidence: evidenceOf(read("p", "1.0.0", mal("MAL-2026-1"))),
			want:     outcomeWant{"stopped", ClassMalice, ExitBlock},
			check: func(t *testing.T, r Report) {
				if len(r.Malice) != 1 || r.Malice[0].Signal != "malware_record" || r.Malice[0].ID != "MAL-2026-1" ||
					!reflect.DeepEqual(r.Malice[0].Versions, []string{"1.0.0"}) {
					t.Fatalf("malice = %+v", r.Malice)
				}
				if len(r.Advisories.AlreadyPresent) != 0 || len(r.Advisories.Introduced) != 0 {
					t.Fatalf("a malware record is not a differential advisory: %+v", r.Advisories)
				}
			}},
		{name: "malice is read whatever the advisory reading's coverage",
			target: pkgs("p", "1.0.0"), noBaseline: true,
			evidence: evidenceOf(gap("p", "1.0.0", mal("MAL-2026-1"))),
			want:     outcomeWant{"stopped", ClassMalice, ExitBlock}},
		{name: "malice is read when the baseline cannot be read",
			target: pkgs("p", "1.0.0"), baselineError: "unreadable",
			evidence: evidenceOf(read("p", "1.0.0")).blocklisted("p"),
			want:     outcomeWant{"stopped", ClassMalice, ExitBlock}},
		{name: "malware on a package the command removes does not block",
			baseline: pkgs("p", "1.0.0"), target: pkgs("q", "1.0.0"),
			evidence: evidenceOf(read("p", "1.0.0", mal("MAL-2026-1")), read("q", "1.0.0")),
			want:     outcomeWant{"clear", "", 0}},
		{name: "malice is never cleared by a standing acceptance",
			target: pkgs("p", "1.0.0"), noBaseline: true,
			evidence: evidenceOf(read("p", "1.0.0", mal("MAL-2026-1"))).accepting(
				accept(AcceptLocalExact, "p", "1.0.0"), accept(AcceptFollowedGrant, "p", "1.0.0")),
			want: outcomeWant{"stopped", ClassMalice, ExitBlock}},

		// Standing acceptances.
		{name: "a local exact approval clears a blocking advisory",
			target: pkgs("p", "1.0.0"), noBaseline: true,
			evidence: evidenceOf(read("p", "1.0.0", hit("GHSA-a", "critical"))).accepting(accept(AcceptLocalExact, "p", "1.0.0")),
			want:     outcomeWant{"clear", "", 0},
			check: func(t *testing.T, r Report) {
				if got := r.Advisories.Introduced[0]; !got.Cleared || !reflect.DeepEqual(got.ClearedBy, []string{AcceptLocalExact}) {
					t.Fatalf("introduced = %+v", got)
				}
			}},
		{name: "a followed install allowance does not clear a blocking advisory",
			target: pkgs("p", "1.0.0"), noBaseline: true,
			evidence: evidenceOf(read("p", "1.0.0", hit("GHSA-a", "critical"))).accepting(accept(AcceptFollowedInstall, "p", "1.0.0")),
			want:     outcomeWant{"stopped", ClassBlockingAdvisory, ExitBlock}},
		{name: "a followed grant does not clear a blocking advisory",
			target: pkgs("p", "1.0.0"), noBaseline: true,
			evidence: evidenceOf(read("p", "1.0.0", hit("GHSA-a", "critical"))).accepting(accept(AcceptFollowedGrant, "p", "1.0.0")),
			want:     outcomeWant{"stopped", ClassBlockingAdvisory, ExitBlock}},
		{name: "a followed advisory override covering every blocking advisory clears it",
			target: pkgs("p", "1.0.0"), noBaseline: true,
			evidence: evidenceOf(read("p", "1.0.0", hit("GHSA-a", "critical"), hit("GHSA-b", "critical"))).accepting(
				accept(AcceptFollowedOverride, "p", "1.0.0", "GHSA-a", "GHSA-b")),
			want: outcomeWant{"clear", "", 0}},
		{name: "a followed advisory override missing one blocking advisory clears none",
			target: pkgs("p", "1.0.0"), noBaseline: true,
			evidence: evidenceOf(read("p", "1.0.0", hit("GHSA-a", "critical"), hit("GHSA-b", "critical"))).accepting(
				accept(AcceptFollowedOverride, "p", "1.0.0", "GHSA-a")),
			want: outcomeWant{"stopped", ClassBlockingAdvisory, ExitBlock}},
		{name: "a followed advisory override must also cover a blocking advisory that was already present",
			baseline: pkgs("p", "1.0.0"), target: pkgs("p", "1.0.0", "q", "1.0.0"),
			evidence: evidenceOf(read("p", "1.0.0"), read("q", "1.0.0", hit("GHSA-a", "critical"))).accepting(
				accept(AcceptFollowedOverride, "q", "1.0.0")),
			want: outcomeWant{"stopped", ClassBlockingAdvisory, ExitBlock}},
		{name: "an acceptance of another version, host or name clears nothing",
			target: pkgs("p", "1.0.0"), noBaseline: true,
			evidence: evidenceOf(read("p", "1.0.0", hit("GHSA-a", "critical"))).accepting(
				accept(AcceptLocalExact, "p", "1.0.1"), accept(AcceptLocalExact, "q", "1.0.0"),
				Acceptance{Kind: AcceptLocalExact, Name: "p", Version: "1.0.0", Host: "other.example", Advisories: []string{}}),
			want: outcomeWant{"stopped", ClassBlockingAdvisory, ExitBlock}},
		{name: "every authority of the adverse row clears an adverse advisory",
			target: pkgs("p", "1.0.0", "q", "1.0.0", "r", "1.0.0"), noBaseline: true,
			evidence: evidenceOf(
				read("p", "1.0.0", hit("GHSA-a", "high")), read("q", "1.0.0", hit("GHSA-b", "high")), read("r", "1.0.0", hit("GHSA-c", "high")),
			).accepting(accept(AcceptLocalExact, "p", "1.0.0"), accept(AcceptFollowedGrant, "q", "1.0.0"), accept(AcceptFollowedInstall, "r", "1.0.0")),
			want: outcomeWant{"clear", "", 0}},
		{name: "an advisory override does not clear an adverse advisory",
			target: pkgs("p", "1.0.0"), noBaseline: true,
			evidence: evidenceOf(read("p", "1.0.0", hit("GHSA-a", "high"))).accepting(accept(AcceptFollowedOverride, "p", "1.0.0", "GHSA-a")),
			want:     outcomeWant{"stopped", ClassAdverseAdvisory, ExitPolicy}},
		{name: "accepting one class never accepts another",
			target: pkgs("p", "1.0.0", "q", "1.0.0"), noBaseline: true,
			evidence: evidenceOf(read("p", "1.0.0", hit("GHSA-a", "critical")), read("q", "1.0.0", hit("GHSA-b", "high"))).accepting(
				accept(AcceptLocalExact, "p", "1.0.0")),
			want: outcomeWant{"stopped", ClassAdverseAdvisory, ExitPolicy}},
		{name: "an acceptance clears none of a missing reading",
			target: pkgs("p", "1.0.0"), noBaseline: true,
			evidence: evidenceOf(gap("p", "1.0.0", hit("GHSA-a", "critical"))).accepting(accept(AcceptLocalExact, "p", "1.0.0")),
			want:     outcomeWant{"stopped", ClassMissingEvidence, ExitOperator}},

		// Precedence.
		{name: "precedence is malice, blocking, adverse, missing",
			target: pkgs("m", "1.0.0", "b", "1.0.0", "a", "1.0.0", "x", "1.0.0"), noBaseline: true,
			evidence: evidenceOf(read("m", "1.0.0", mal("MAL-1")), read("b", "1.0.0", hit("GHSA-b", "critical")),
				read("a", "1.0.0", hit("GHSA-a", "high")), gap("x", "1.0.0")),
			want: outcomeWant{"stopped", ClassMalice, ExitBlock},
			check: func(t *testing.T, r Report) {
				got := []string{}
				for _, class := range r.Classes {
					if class.Outstanding != 1 {
						t.Fatalf("class %s outstanding = %d", class.Class, class.Outstanding)
					}
					got = append(got, class.Class)
				}
				want := []string{ClassMalice, ClassBlockingAdvisory, ClassAdverseAdvisory, ClassMissingEvidence}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("classes = %v, want %v", got, want)
				}
			}},
		{name: "the first class left decides the exit",
			target: pkgs("a", "1.0.0", "x", "1.0.0"), noBaseline: true,
			evidence: evidenceOf(read("a", "1.0.0", hit("GHSA-a", "high")), gap("x", "1.0.0")),
			want:     outcomeWant{"stopped", ClassAdverseAdvisory, ExitPolicy}},

		// Bindability.
		{name: "a graph safe cannot bind is refused whatever else is clear",
			target:     map[string]map[string]any{"node_modules/p": with(entry("p", "1.0.0"), map[string]any{"integrity": nil})},
			noBaseline: true,
			evidence:   evidenceOf(read("p", "1.0.0")),
			want:       outcomeWant{"unbound", "", ExitOperator},
			check: func(t *testing.T, r Report) {
				if r.Bindability.Bound || len(r.Bindability.Unbound) != 1 {
					t.Fatalf("bindability = %+v", r.Bindability)
				}
			}},
		{name: "a malice signal is decided before a graph safe cannot bind",
			target: map[string]map[string]any{
				"node_modules/p": with(entry("p", "1.0.0"), map[string]any{"integrity": nil}),
				"node_modules/m": entry("m", "1.0.0"),
			},
			noBaseline: true,
			evidence:   evidenceOf(read("p", "1.0.0"), read("m", "1.0.0", mal("MAL-2026-2"))),
			want:       outcomeWant{"stopped", ClassMalice, ExitBlock}},
		{name: "a blocking advisory is decided before a graph safe cannot bind",
			target: map[string]map[string]any{
				"node_modules/p": with(entry("p", "1.0.0"), map[string]any{"integrity": nil}),
				"node_modules/c": entry("c", "1.0.0"),
			},
			noBaseline: true,
			evidence:   evidenceOf(read("p", "1.0.0"), read("c", "1.0.0", hit("GHSA-c", "critical"))),
			want:       outcomeWant{"stopped", ClassBlockingAdvisory, ExitBlock}},
		{name: "an adverse advisory does not hide a graph safe cannot bind",
			target: map[string]map[string]any{
				"node_modules/p": with(entry("p", "1.0.0"), map[string]any{"integrity": nil}),
				"node_modules/h": entry("h", "1.0.0"),
			},
			noBaseline: true,
			evidence:   evidenceOf(read("p", "1.0.0"), read("h", "1.0.0", hit("GHSA-h", "high"))),
			want:       outcomeWant{"unbound", "", ExitOperator}},
		{name: "a clean graph from an empty baseline is clear and introduces everything",
			target: pkgs("p", "1.0.0"), noBaseline: true, evidence: evidenceOf(read("p", "1.0.0")),
			want: outcomeWant{"clear", "", 0},
			check: func(t *testing.T, r Report) {
				if r.Baseline.Source != "empty" || len(r.Difference.Introduced) != 1 {
					t.Fatalf("report = %+v", r)
				}
			}},
		{name: "a bundled entry is judged under its own public identity",
			target: map[string]map[string]any{
				"node_modules/p":                 entry("p", "1.0.0"),
				"node_modules/p/node_modules/in": {"version": "2.0.0", "inBundle": true},
			}, noBaseline: true,
			evidence: evidenceOf(read("p", "1.0.0"), read("in", "2.0.0", hit("GHSA-a", "critical"))),
			want:     outcomeWant{"stopped", ClassBlockingAdvisory, ExitBlock}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := Input{Target: graphOf(t, tc.target), Evidence: tc.evidence, BaselineError: tc.baselineError}
			if tc.baselineError == "" && !tc.noBaseline {
				input.HasBaseline = true
				input.Baseline = graphOf(t, tc.baseline)
			}
			report := Decide(input)
			got := outcomeWant{report.Outcome.Status, report.Outcome.Class, report.Outcome.Exit}
			if got != tc.want {
				t.Fatalf("outcome = %+v, want %+v\nreport = %+v", got, tc.want, report)
			}
			if tc.check != nil {
				tc.check(t, report)
			}
		})
	}
}

func TestDecideIsDeterministic(t *testing.T) {
	target := pkgs("a", "1.0.0", "b", "1.0.0", "c", "1.0.0")
	evidence := evidenceOf(read("a", "1.0.0", hit("GHSA-1", "high"), hit("GHSA-2", "critical")),
		read("b", "1.0.0", hit("GHSA-3", "moderate")), gap("c", "1.0.0"))
	first := Decide(Input{Target: graphOf(t, target), Evidence: evidence})
	for i := 0; i < 20; i++ {
		if again := Decide(Input{Target: graphOf(t, target), Evidence: evidence}); !reflect.DeepEqual(first, again) {
			t.Fatalf("Decide is not deterministic:\n%+v\n%+v", first, again)
		}
	}
}
