package projectlane

import (
	"reflect"
	"strings"
	"testing"
)

func tolerance(name, version string, causes ...string) Acceptance {
	return Acceptance{Kind: AcceptLocalTolerance, Name: name, Version: version, Host: DefaultRegistryHost, Advisories: []string{}, Causes: causes}
}

func installRecordsOf(report Report) []string {
	out := []string{}
	for _, item := range report.Records {
		out = append(out, item.Verdict+" "+item.Name+"@"+item.Version)
	}
	return out
}

// A standing tolerance clears what today's auto_allow_tolerate clears: a WARN cause (a young release, a Socket result short
// of a block) when EVERY cause of the item is listed; never an advisory, never a consent ask or a pending score.
func TestALocalToleranceClearsAWaitAndAWarnOnlyWhenEveryCauseIsListed(t *testing.T) {
	young := releasesOf(3, SecurityFixExempt, reading("pk", "1.0.0", 10))
	ev := evidenceOf(read("pk", "1.0.0"))
	if r := decideCooldown(t, nil, pkgs("pk", "1.0.0"), young, ev); r.Outcome.Class != ClassWait {
		t.Fatalf("control: %+v", r.Outcome)
	}
	if r := decideCooldown(t, nil, pkgs("pk", "1.0.0"), young, ev.accepting(tolerance("pk", "1.0.0", "release_too_new"))); r.Outcome.Status != "clear" || r.Cooldown.Waits[0].ClearedBy[0] != AcceptLocalTolerance {
		t.Fatalf("a listed cause: %+v", r.Outcome)
	}
	if r := decideCooldown(t, nil, pkgs("pk", "1.0.0"), young, ev.accepting(tolerance("pk", "1.0.0", "socket_low_score"))); r.Outcome.Class != ClassWait {
		t.Fatalf("another cause: %+v", r.Outcome)
	}
	// Socket: the causes of the root, all of them
	low := sroot("pk", "1.0.0", SocketAdverse)
	low.Causes = []string{"socket_low_score", "socket_high_alert"}
	for name, c := range map[string]struct {
		acceptance Acceptance
		clear      bool
	}{
		"all listed":  {tolerance("pk", "1.0.0", "socket_low_score", "socket_high_alert"), true},
		"one missing": {tolerance("pk", "1.0.0", "socket_low_score"), false},
		"followed":    {accept(AcceptFollowedInstall, "pk", "1.0.0"), true},
	} {
		r := decideSocket(t, nil, pkgs("pk", "1.0.0"), socketOf(low), ev.accepting(c.acceptance))
		if (r.Outcome.Status == "clear") != c.clear {
			t.Errorf("%s: %+v", name, r.Outcome)
		}
	}
	consent := sroot("pk", "1.0.0", SocketConsentRequired)
	if r := decideSocket(t, nil, pkgs("pk", "1.0.0"), socketOf(consent), ev.accepting(tolerance("pk", "1.0.0", "socket_low_score"))); r.Outcome.Class != ClassSocketRoot {
		t.Fatalf("a consent ask is not a WARN: %+v", r.Outcome)
	}
	// never an advisory
	adv := evidenceOf(read("pk", "1.0.0", hit("GHSA-1", SeverityHigh))).accepting(tolerance("pk", "1.0.0", "osv_affecting"))
	if r := Decide(Input{Target: graphOf(t, pkgs("pk", "1.0.0")), Evidence: adv}); r.Outcome.Class != ClassAdverseAdvisory {
		t.Fatalf("a tolerance cleared an advisory: %+v", r.Outcome)
	}
}

func TestReadAcceptancesKnowsTheToleranceAndNothingElseListsCauses(t *testing.T) {
	good := `{"schema_version":1,"acceptances":[{"kind":"local_tolerance","name":"a","version":"1.0.0","host":"registry.npmjs.org","advisories":[],"causes":["release_too_new"]}]}`
	if _, err := ReadAcceptances([]byte(good)); err != nil {
		t.Fatal(err)
	}
	for name, doc := range map[string]string{
		"no causes member":  strings.Replace(good, `,"causes":["release_too_new"]`, ``, 1),
		"tolerance no list": strings.Replace(good, `"causes":["release_too_new"]`, `"causes":[]`, 1),
		"approval causes":   strings.Replace(good, `local_tolerance`, `local_exact_approval`, 1),
		"bad cause":         strings.Replace(good, `release_too_new`, `Too New!`, 1),
	} {
		if _, err := ReadAcceptances([]byte(doc)); err == nil {
			t.Errorf("%s: read", name)
		}
	}
}

// The records of a clear decision: what the artifact's own evidence shows, nothing it only inherits.
func TestRecordsAreOnlyForIntroducedArtifactsWithTheirOwnCleanEvidence(t *testing.T) {
	ev := evidenceOf(read("kept", "1.0.0", hit("GHSA-old", SeverityHigh)), read("new", "1.0.0"), read("low", "1.0.0", hit("GHSA-low", SeverityLow)),
		read("carry", "2.0.0", hit("GHSA-old2", SeverityHigh)), read("carry", "1.0.0", hit("GHSA-old2", SeverityHigh)), gap("blind", "1.0.0"))
	base := pkgs("kept", "1.0.0", "carry", "1.0.0")
	target := pkgs("kept", "1.0.0", "new", "1.0.0", "low", "1.0.0", "carry", "2.0.0")
	roots := socketOf(sroot("new", "1.0.0", SocketClear), sroot("low", "1.0.0", SocketClear), sroot("carry", "2.0.0", SocketClear), sroot("kept", "1.0.0", SocketClear))
	report := Decide(Input{Baseline: graphOf(t, base), HasBaseline: true, Target: graphOf(t, target), Evidence: ev, Socket: roots})
	if report.Outcome.Status != "clear" {
		t.Fatalf("%+v", report.Outcome)
	}
	// kept is not introduced; carry@2.0.0 is introduced but carries an advisory at high that was already present: not recorded
	want := []string{"GO low@1.0.0", "GO new@1.0.0"}
	if got := installRecordsOf(report); !reflect.DeepEqual(got, want) {
		t.Fatalf("records = %v, want %v", got, want)
	}
	// nobody named them: the same decision with no named root records nothing, whatever the evidence
	if unnamed := Decide(Input{Baseline: graphOf(t, base), HasBaseline: true, Target: graphOf(t, target), Evidence: ev, Socket: socketOf()}); len(unnamed.Records) != 0 {
		t.Fatalf("unnamed artifacts were recorded: %v", installRecordsOf(unnamed))
	}
	if nosocket := Decide(Input{Baseline: graphOf(t, base), HasBaseline: true, Target: graphOf(t, target), Evidence: ev}); len(nosocket.Records) != 0 {
		t.Fatalf("a decision with no Socket reading recorded: %v", installRecordsOf(nosocket))
	}
	// a decision that is not clear records nothing
	stopped := Decide(Input{Target: graphOf(t, pkgs("new", "1.0.0", "bad", "1.0.0")), Evidence: evidenceOf(read("new", "1.0.0"), read("bad", "1.0.0", hit("GHSA-x", SeverityHigh)))})
	if stopped.Outcome.Status == "clear" || len(stopped.Records) != 0 {
		t.Fatalf("%+v / %v", stopped.Outcome, stopped.Records)
	}
}

func TestRecordsFollowWhoClearedTheArtifact(t *testing.T) {
	young := releasesOf(3, SecurityFixExempt, reading("pk", "1.0.0", 10), reading("fol", "1.0.0", 10))
	ev := evidenceOf(read("pk", "1.0.0"), read("fol", "1.0.0"))
	// tolerated: a WARN_TOLERATED record carrying the cause
	r := Decide(Input{Target: graphOf(t, pkgs("pk", "1.0.0")), Evidence: ev.accepting(tolerance("pk", "1.0.0", "release_too_new")), Releases: young, Socket: socketOf(sroot("pk", "1.0.0", SocketClear))})
	if got := installRecordsOf(r); !reflect.DeepEqual(got, []string{"WARN_TOLERATED pk@1.0.0"}) {
		t.Fatalf("tolerated: %v %v", got, r.Records)
	}
	// cleared by a followed authority: another origin's decision, never recorded (and so never exported again)
	r = Decide(Input{Target: graphOf(t, pkgs("fol", "1.0.0")), Evidence: ev.accepting(accept(AcceptFollowedInstall, "fol", "1.0.0")), Releases: young, Socket: socketOf(sroot("fol", "1.0.0", SocketClear))})
	if r.Outcome.Status != "clear" || len(r.Records) != 0 {
		t.Fatalf("followed: %+v %v", r.Outcome, r.Records)
	}
	// a local approval: stored already, not a new record
	r = Decide(Input{Target: graphOf(t, pkgs("fol", "1.0.0")), Evidence: ev.accepting(accept(AcceptLocalExact, "fol", "1.0.0")), Releases: young, Socket: socketOf(sroot("fol", "1.0.0", SocketClear))})
	if len(r.Records) != 0 {
		t.Fatalf("local approval recorded: %v", r.Records)
	}
	// a named root whose Socket result is clear is recorded GO with the socket reason; one cleared by a followed allowance is not
	root := Decide(Input{Target: graphOf(t, pkgs("pk", "1.0.0")), Evidence: ev, Socket: socketOf(sroot("pk", "1.0.0", SocketClear))})
	if got := installRecordsOf(root); !reflect.DeepEqual(got, []string{"GO pk@1.0.0"}) {
		t.Fatalf("root: %v %v", got, root.Records)
	}
	root = Decide(Input{Target: graphOf(t, pkgs("pk", "1.0.0")), Evidence: ev.accepting(accept(AcceptFollowedInstall, "pk", "1.0.0")), Socket: socketOf(sroot("pk", "1.0.0", SocketConsentRequired))})
	if root.Outcome.Status != "clear" || len(root.Records) != 0 {
		t.Fatalf("followed root: %+v %v", root.Outcome, root.Records)
	}
	// bundled members are not records of their own
	bundled := map[string]map[string]any{"node_modules/b": entry("b", "2.0.0"), "node_modules/b/node_modules/bund": {"version": "1.0.0", "inBundle": true}}
	r = Decide(Input{Target: graphOf(t, bundled), Evidence: evidenceOf(read("b", "2.0.0"), read("bund", "1.0.0")), Socket: socketOf(sroot("b", "2.0.0", SocketClear))})
	if got := installRecordsOf(r); !reflect.DeepEqual(got, []string{"GO b@2.0.0"}) {
		t.Fatalf("bundled: %v", got)
	}
}

func TestACoveringClearanceByTheFollowedOverrideAndTheApprovalMatchTheTable(t *testing.T) {
	blocking := evidenceOf(read("pk", "1.0.0", hit("GHSA-c1", SeverityCritical), hit("GHSA-c2", SeverityCritical)))
	for name, c := range map[string]struct {
		acceptance Acceptance
		clear      bool
	}{
		"local approval":             {accept(AcceptLocalExact, "pk", "1.0.0"), true},
		"followed install allowance": {accept(AcceptFollowedInstall, "pk", "1.0.0"), false},
		"followed grant":             {accept(AcceptFollowedGrant, "pk", "1.0.0"), false},
		"override covering all":      {accept(AcceptFollowedOverride, "pk", "1.0.0", "GHSA-c1", "GHSA-c2"), true},
		"override covering only one": {accept(AcceptFollowedOverride, "pk", "1.0.0", "GHSA-c1"), false},
		"tolerance":                  {tolerance("pk", "1.0.0", "osv_affecting"), false},
	} {
		r := Decide(Input{Target: graphOf(t, pkgs("pk", "1.0.0")), Evidence: blocking.accepting(c.acceptance)})
		if (r.Outcome.Status == "clear") != c.clear {
			t.Errorf("%s: %+v", name, r.Outcome)
		}
	}
	// nothing clears malice, a missing reading or an unbound graph
	for name, ev := range map[string]Evidence{
		"malware":   evidenceOf(read("pk", "1.0.0", mal("MAL-1"))),
		"blocklist": evidenceOf(read("pk", "1.0.0")).blocklisted("pk"),
		"gap":       evidenceOf(gap("pk", "1.0.0")),
	} {
		all := ev.accepting(accept(AcceptLocalExact, "pk", "1.0.0"), accept(AcceptFollowedGrant, "pk", "1.0.0"), accept(AcceptFollowedInstall, "pk", "1.0.0"), tolerance("pk", "1.0.0", "release_too_new"))
		if r := Decide(Input{Target: graphOf(t, pkgs("pk", "1.0.0")), Evidence: all}); r.Outcome.Status == "clear" {
			t.Errorf("%s was cleared", name)
		}
	}
}

// Bundled bytes: an acceptance is for the artifact whose bytes carry the advisory, and must cover all of them.
func TestBundledBytesAreJudgedUnderTheirCoveringArtifact(t *testing.T) {
	target := map[string]map[string]any{"node_modules/clean": entry("clean", "2.0.0"), "node_modules/clean/node_modules/bund": {"version": "1.0.0", "inBundle": true}}
	ev := evidenceOf(read("clean", "2.0.0"), read("bund", "1.0.0", hit("GHSA-b1", SeverityCritical), hit("GHSA-b2", SeverityCritical)))
	for name, c := range map[string]struct {
		acceptance Acceptance
		clear      bool
	}{
		"local approval of the covering artifact":       {accept(AcceptLocalExact, "clean", "2.0.0"), true},
		"override of the covering artifact, all":        {accept(AcceptFollowedOverride, "clean", "2.0.0", "GHSA-b1", "GHSA-b2"), true},
		"override of the covering artifact, one of two": {accept(AcceptFollowedOverride, "clean", "2.0.0", "GHSA-b1"), false},
		"approval of a standalone namesake":             {accept(AcceptLocalExact, "bund", "1.0.0"), false},
	} {
		r := Decide(Input{Target: graphOf(t, target), Evidence: ev.accepting(c.acceptance)})
		if (r.Outcome.Status == "clear") != c.clear {
			t.Errorf("%s: %+v", name, r.Outcome)
		}
	}
	r := Decide(Input{Target: graphOf(t, target), Evidence: ev})
	if len(r.Wanted) != 1 || r.Wanted[0].Name != "clean" || r.Wanted[0].Version != "2.0.0" || !reflect.DeepEqual(r.Wanted[0].BlockingAdvisories, []string{"GHSA-b1", "GHSA-b2"}) {
		t.Fatalf("the acceptance reader is asked about the covering artifact with every advisory under its bytes: %+v", r.Wanted)
	}
	// a root whose bytes carry a high advisory is not eligible for a record, introduced or already present
	member := evidenceOf(read("clean", "2.0.0"), read("bund", "1.0.0", hit("GHSA-h", SeverityHigh)))
	base := map[string]map[string]any{"node_modules/clean": entry("clean", "1.0.0"), "node_modules/clean/node_modules/bund": {"version": "1.0.0", "inBundle": true}}
	member.Identities = append(member.Identities, read("clean", "1.0.0"))
	r = Decide(Input{Baseline: graphOf(t, base), HasBaseline: true, Target: graphOf(t, target), Evidence: member, Socket: socketOf(sroot("clean", "2.0.0", SocketClear))})
	if r.Outcome.Status != "clear" || len(r.Records) != 0 {
		t.Fatalf("an inherited advisory in the bytes: %+v %v", r.Outcome, r.Records)
	}
}

// Today's tolerance applies only to an artifact with no affecting advisory.
func TestAToleranceNeedsAnArtifactWithNoAdvisoryAtAll(t *testing.T) {
	low := sroot("pk", "1.0.0", SocketAdverse)
	low.Causes = []string{"socket_low_score"}
	moderate := evidenceOf(read("pk", "1.0.0", hit("GHSA-m", SeverityModerate))).accepting(tolerance("pk", "1.0.0", "socket_low_score"))
	if r := decideSocket(t, nil, pkgs("pk", "1.0.0"), socketOf(low), moderate); r.Outcome.Status == "clear" {
		t.Fatalf("a tolerance cleared a Socket warning on an artifact with an affecting advisory: %+v", r.Outcome)
	}
	clean := evidenceOf(read("pk", "1.0.0")).accepting(tolerance("pk", "1.0.0", "socket_low_score"))
	if r := decideSocket(t, nil, pkgs("pk", "1.0.0"), socketOf(low), clean); r.Outcome.Status != "clear" {
		t.Fatalf("control: %+v", r.Outcome)
	}
}

func TestTheDecisionNamesTheIdentitiesItFoundAdverseEvidenceOn(t *testing.T) {
	ev := evidenceOf(read("a", "1.0.0", hit("GHSA-c", SeverityCritical)), read("b", "1.0.0", hit("GHSA-h", SeverityHigh)), read("c", "1.0.0"), read("m", "1.0.0")).blocklisted("m")
	r := Decide(Input{Target: graphOf(t, pkgs("a", "1.0.0", "b", "1.0.0", "c", "1.0.0", "m", "1.0.0")), Evidence: ev, Socket: socketOf(sroot("c", "1.0.0", SocketAdverse))})
	got := []string{}
	for _, identity := range r.Adverse {
		got = append(got, identity.Name+"@"+identity.Version)
	}
	if !reflect.DeepEqual(got, []string{"a@1.0.0", "b@1.0.0", "c@1.0.0", "m@1.0.0"}) {
		t.Fatalf("adverse = %v", got)
	}
}
