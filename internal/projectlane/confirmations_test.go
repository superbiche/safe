package projectlane

import (
	"reflect"
	"strings"
	"testing"
)

func confirmationsOf(malice []Identity, gap bool, socket []Identity) Confirmations {
	if malice == nil {
		malice = []Identity{}
	}
	if socket == nil {
		socket = []Identity{}
	}
	return Confirmations{SchemaVersion: ConfirmationsSchema, Malice: malice, EvidenceGap: gap, Socket: socket}
}

func TestReadConfirmationsIsStrict(t *testing.T) {
	good := `{"schema_version":1,"malice":[{"name":"a","version":"1.0.0"}],"evidence_gap":true,"socket":[]}`
	if got, err := ReadConfirmations([]byte(good)); err != nil || !got.EvidenceGap || len(got.Malice) != 1 {
		t.Fatalf("%+v %v", got, err)
	}
	for name, doc := range map[string]string{
		"not json":        `nope`,
		"unknown member":  strings.Replace(good, `"socket":[]`, `"socket":[],"extra":1`, 1),
		"repeated":        strings.Replace(good, `"evidence_gap":true`, `"evidence_gap":true,"evidence_gap":false`, 1),
		"missing socket":  `{"schema_version":1,"malice":[],"evidence_gap":false}`,
		"another schema":  strings.Replace(good, `"schema_version":1`, `"schema_version":2`, 1),
		"item no version": strings.Replace(good, `"version":"1.0.0"`, `"version":""`, 1),
		"item not object": strings.Replace(good, `[{"name":"a","version":"1.0.0"}]`, `["a@1.0.0"]`, 1),
		"two documents":   good + good,
	} {
		if _, err := ReadConfirmations([]byte(doc)); err == nil {
			t.Errorf("%s: read", name)
		}
	}
}

// A typed override clears the malice of the exact artifact it names, for this command, and nothing else; a confirmed evidence gap
// clears missing evidence only; and neither clears the other classes.
func TestConfirmationsClearOnlyWhatTheyName(t *testing.T) {
	ev := evidenceOf(read("a", "1.0.0"), read("b", "1.0.0")).blocklisted("a")
	target := graphOf(t, pkgs("a", "1.0.0", "b", "1.0.0"))
	if r := Decide(Input{Target: target, Evidence: ev}); r.Outcome.Class != ClassMalice {
		t.Fatalf("control: %+v", r.Outcome)
	}
	typed := confirmationsOf([]Identity{{Name: "a", Version: "1.0.0"}}, false, nil)
	if r := Decide(Input{Target: target, Evidence: ev, Confirmations: typed}); r.Outcome.Status != "clear" || !r.Malice[0].Overridden || len(r.Records) != 0 {
		t.Fatalf("typed override: %+v %+v", r.Outcome, r.Malice)
	}
	other := confirmationsOf([]Identity{{Name: "a", Version: "2.0.0"}}, false, nil)
	if r := Decide(Input{Target: target, Evidence: ev, Confirmations: other}); r.Outcome.Class != ClassMalice {
		t.Fatalf("an override of another version cleared malice: %+v", r.Outcome)
	}
	// the gap confirmation does not clear malice, nor an advisory
	gapOnly := confirmationsOf(nil, true, nil)
	if r := Decide(Input{Target: target, Evidence: ev, Confirmations: gapOnly}); r.Outcome.Class != ClassMalice {
		t.Fatalf("a gap confirmation cleared malice: %+v", r.Outcome)
	}
	hi := evidenceOf(read("a", "1.0.0", hit("GHSA-h", SeverityHigh)), gap("b", "1.0.0"))
	r := Decide(Input{Target: target, Evidence: hi, Confirmations: gapOnly})
	if r.Outcome.Class != ClassAdverseAdvisory || !r.GapConfirmed {
		t.Fatalf("the gap is confirmed, the advisory is not: %+v gap=%v", r.Outcome, r.GapConfirmed)
	}
	if g := Decide(Input{Target: target, Evidence: evidenceOf(read("a", "1.0.0"), gap("b", "1.0.0")), Confirmations: gapOnly}); g.Outcome.Status != "clear" || !g.GapConfirmed || len(g.Coverage) == 0 {
		t.Fatalf("a confirmed gap stays listed and the command goes on: %+v", g)
	}
}

func TestAConfirmedSocketOutageClearsOnlyAnOutage(t *testing.T) {
	ev := evidenceOf(read("pk", "1.0.0"))
	c := confirmationsOf(nil, false, []Identity{{Name: "pk", Version: "1.0.0"}})
	for outcome, want := range map[string]bool{SocketUnavailable: true, SocketAdverse: false, SocketRateLimited: false, SocketConsentRequired: false, SocketPending: false} {
		r := Decide(Input{Target: graphOf(t, pkgs("pk", "1.0.0")), Evidence: ev, Socket: socketOf(sroot("pk", "1.0.0", outcome)), Confirmations: c})
		if (r.Outcome.Status == "clear") != want {
			t.Errorf("%s: %+v", outcome, r.Outcome)
		}
	}
	// a root cleared for this command is not a record
	r := Decide(Input{Target: graphOf(t, pkgs("pk", "1.0.0")), Evidence: ev, Socket: socketOf(sroot("pk", "1.0.0", SocketUnavailable)), Confirmations: c})
	if len(r.Records) != 0 {
		t.Fatalf("a root confirmed for this command was made eligible for a record: %v", r.Records)
	}
}

// The decision says what is outstanding, class by class in its own order, with the artifact whose bytes carry each advisory.
func TestOutstandingFollowsTheDecisionsOrderAndTheCoveringArtifact(t *testing.T) {
	target := bundledGraph("parent", "member")
	target["node_modules/solo"] = entry("solo", "1.0.0")
	ev := evidenceOf(read("parent", "2.0.0"), read("member", "2.0.0", hit("GHSA-c1", SeverityCritical)), read("solo", "1.0.0", hit("GHSA-h1", SeverityHigh)), gap("zzz", "1.0.0"))
	target["node_modules/zzz"] = entry("zzz", "1.0.0")
	r := Decide(Input{Target: graphOf(t, target), Evidence: ev})
	var order []string
	for _, class := range r.Outstanding {
		order = append(order, class.Class)
	}
	if !reflect.DeepEqual(order, []string{ClassBlockingAdvisory, ClassAdverseAdvisory, ClassMissingEvidence}) || r.Outstanding[0].Class != r.Outcome.Class {
		t.Fatalf("order = %v, first class left = %s", order, r.Outcome.Class)
	}
	blocking := r.Outstanding[0].Items
	if len(blocking) != 1 || blocking[0].Name != "parent" || !reflect.DeepEqual(blocking[0].Advisories, []string{"GHSA-c1"}) || !reflect.DeepEqual(blocking[0].Carried, []string{"member@2.0.0"}) {
		t.Fatalf("the blocking item is the covering artifact: %+v", blocking)
	}
	if adverse := r.Outstanding[1].Items; len(adverse) != 1 || adverse[0].Name != "solo" || adverse[0].Severity != SeverityHigh {
		t.Fatalf("%+v", adverse)
	}
}
