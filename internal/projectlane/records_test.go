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
	report := Decide(Input{Baseline: graphOf(t, base), HasBaseline: true, Target: graphOf(t, target), Evidence: ev})
	if report.Outcome.Status != "clear" {
		t.Fatalf("%+v", report.Outcome)
	}
	// kept is not introduced; carry@2.0.0 is introduced but carries an advisory at high that was already present: not recorded
	want := []string{"GO low@1.0.0", "GO new@1.0.0"}
	if got := installRecordsOf(report); !reflect.DeepEqual(got, want) {
		t.Fatalf("records = %v, want %v", got, want)
	}
	for _, item := range report.Records {
		if item.Name == "low" && !reflect.DeepEqual(item.Reasons, []string{"osv_below_high_only", "socket_not_scored_by_the_lane", "blocklist_pass"}) {
			t.Errorf("reasons = %v", item.Reasons)
		}
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
	r := Decide(Input{Target: graphOf(t, pkgs("pk", "1.0.0")), Evidence: ev.accepting(tolerance("pk", "1.0.0", "release_too_new")), Releases: young})
	if got := installRecordsOf(r); !reflect.DeepEqual(got, []string{"WARN_TOLERATED pk@1.0.0"}) || !reflect.DeepEqual(r.Records[0].Reasons, []string{"release_too_new"}) {
		t.Fatalf("tolerated: %v %v", got, r.Records)
	}
	// cleared by a followed authority: another origin's decision, never recorded (and so never exported again)
	r = Decide(Input{Target: graphOf(t, pkgs("fol", "1.0.0")), Evidence: ev.accepting(accept(AcceptFollowedInstall, "fol", "1.0.0")), Releases: young})
	if r.Outcome.Status != "clear" || len(r.Records) != 0 {
		t.Fatalf("followed: %+v %v", r.Outcome, r.Records)
	}
	// a local approval: stored already, not a new record
	r = Decide(Input{Target: graphOf(t, pkgs("fol", "1.0.0")), Evidence: ev.accepting(accept(AcceptLocalExact, "fol", "1.0.0")), Releases: young})
	if len(r.Records) != 0 {
		t.Fatalf("local approval recorded: %v", r.Records)
	}
	// a named root whose Socket result is clear is recorded GO with the socket reason; one cleared by a followed allowance is not
	root := Decide(Input{Target: graphOf(t, pkgs("pk", "1.0.0")), Evidence: ev, Socket: socketOf(sroot("pk", "1.0.0", SocketClear))})
	if got := installRecordsOf(root); !reflect.DeepEqual(got, []string{"GO pk@1.0.0"}) || root.Records[0].Reasons[1] != "socket_ok" {
		t.Fatalf("root: %v %v", got, root.Records)
	}
	root = Decide(Input{Target: graphOf(t, pkgs("pk", "1.0.0")), Evidence: ev.accepting(accept(AcceptFollowedInstall, "pk", "1.0.0")), Socket: socketOf(sroot("pk", "1.0.0", SocketConsentRequired))})
	if root.Outcome.Status != "clear" || len(root.Records) != 0 {
		t.Fatalf("followed root: %+v %v", root.Outcome, root.Records)
	}
	// bundled members are not records of their own
	bundled := map[string]map[string]any{"node_modules/b": entry("b", "2.0.0"), "node_modules/b/node_modules/bund": {"version": "1.0.0", "inBundle": true}}
	r = Decide(Input{Target: graphOf(t, bundled), Evidence: evidenceOf(read("b", "2.0.0"), read("bund", "1.0.0"))})
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
