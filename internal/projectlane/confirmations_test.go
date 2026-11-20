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
	return Confirmations{SchemaVersion: ConfirmationsSchema, Malice: malice, EvidenceGap: gap, Socket: socket, Answered: []Answered{}}
}

func TestReadConfirmationsIsStrict(t *testing.T) {
	good := `{"schema_version":1,"malice":[{"name":"a","version":"1.0.0"}],"evidence_gap":true,"socket":[],"answered":[{"name":"a","version":"1.0.0","class":"wait","token":""}]}`
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
		"no answered":     strings.Replace(good, `,"answered":[{"name":"a","version":"1.0.0","class":"wait","token":""}]`, ``, 1),
		"unknown class":   strings.Replace(good, `"class":"wait"`, `"class":"malice"`, 1),
		"unknown token":   strings.Replace(good, `"token":""`, `"token":"GO"`, 1),
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

// Within one command an answer clears its own class only: the approval it writes is a standing acceptance for the NEXT command.
func TestAnAnswerGivenDuringTheCommandClearsItsOwnClassOnly(t *testing.T) {
	young := releasesOf(3, SecurityFixExempt, reading("pk", "1.0.0", 10))
	ev := evidenceOf(read("pk", "1.0.0", hit("GHSA-h", SeverityHigh)))
	approval := accept(AcceptLocalExact, "pk", "1.0.0")
	run := func(answered ...Answered) Report {
		e := ev.accepting(approval)
		e.Answered = answered
		return Decide(Input{Target: graphOf(t, pkgs("pk", "1.0.0")), Evidence: e, Releases: young, Confirmations: Confirmations{SchemaVersion: 1, Answered: answered, Malice: []Identity{}, Socket: []Identity{}}})
	}
	// a standing approval (no answer behind it) clears both the advisory and the wait
	if r := run(); r.Outcome.Status != "clear" {
		t.Fatalf("standing: %+v", r.Outcome)
	}
	// the approval was written by the answer to the advisory: the wait is still shown
	r := run(Answered{Name: "pk", Version: "1.0.0", Class: ClassAdverseAdvisory})
	if r.Outcome.Class != ClassWait || len(r.Outstanding) != 1 || r.Outstanding[0].Class != ClassWait {
		t.Fatalf("advisory answered: %+v %+v", r.Outcome, r.Outstanding)
	}
	// both answered: clear
	if r := run(Answered{Name: "pk", Version: "1.0.0", Class: ClassAdverseAdvisory}, Answered{Name: "pk", Version: "1.0.0", Class: ClassWait}); r.Outcome.Status != "clear" {
		t.Fatalf("both: %+v", r.Outcome)
	}
	// a pending Socket score on the same root is shown after the advisory answer too
	e := evidenceOf(read("pk", "1.0.0", hit("GHSA-h", SeverityHigh))).accepting(approval)
	e.Answered = []Answered{{Name: "pk", Version: "1.0.0", Class: ClassAdverseAdvisory}}
	r = Decide(Input{Target: graphOf(t, pkgs("pk", "1.0.0")), Evidence: e, Socket: socketOf(sroot("pk", "1.0.0", SocketPending))})
	if r.Outcome.Class != ClassSocketRoot {
		t.Fatalf("pending after the advisory answer: %+v", r.Outcome)
	}
}

// The prompt lists what is unresolved in its own class: one advisory over two versions with a standing approval for one lists one.
func TestOutstandingListsOnlyTheUnresolvedOccurrencesOfItsClass(t *testing.T) {
	target := map[string]map[string]any{"node_modules/a": entry("a", "1.0.0"), "node_modules/b/node_modules/a": entry("a", "2.0.0"), "node_modules/b": entry("b", "1.0.0")}
	ev := evidenceOf(read("a", "1.0.0", hit("GHSA-c", SeverityCritical)), read("a", "2.0.0", hit("GHSA-c", SeverityCritical)), read("b", "1.0.0")).accepting(accept(AcceptLocalExact, "a", "1.0.0"))
	r := Decide(Input{Target: graphOf(t, target), Evidence: ev})
	if len(r.Outstanding) != 1 || len(r.Outstanding[0].Items) != 1 || r.Outstanding[0].Items[0].Version != "2.0.0" {
		t.Fatalf("%+v", r.Outstanding)
	}
	// a Socket block is malice only; a pending root is the Socket class; the blocked row is not in it
	sock := socketOf(sroot("a", "1.0.0", SocketBlocked), sroot("b", "1.0.0", SocketPending))
	r = Decide(Input{Target: graphOf(t, pkgs("a", "1.0.0", "b", "1.0.0")), Evidence: evidenceOf(read("a", "1.0.0"), read("b", "1.0.0")), Socket: sock})
	var order []string
	for _, class := range r.Outstanding {
		order = append(order, class.Class)
		if class.Class == ClassSocketRoot && (len(class.Items) != 1 || class.Items[0].Name != "b") {
			t.Fatalf("the Socket class holds the blocked row: %+v", class.Items)
		}
	}
	if !reflect.DeepEqual(order, []string{ClassMalice, ClassSocketRoot}) {
		t.Fatalf("order = %v", order)
	}
}

// One question per artifact with every signal shown, and an artifact with malice and a blocking advisory is a mixed block.
func TestMaliceIsOneQuestionPerArtifactAndAMixedBlockIsMarked(t *testing.T) {
	ev := evidenceOf(read("a", "1.0.0", mal("MAL-1"), hit("GHSA-c", SeverityCritical))).blocklisted("a")
	r := Decide(Input{Target: graphOf(t, pkgs("a", "1.0.0")), Evidence: ev, Socket: socketOf(sroot("a", "1.0.0", SocketBlocked))})
	if len(r.Outstanding[0].Items) != 1 || len(r.Outstanding[0].Items[0].Signals) != 3 {
		t.Fatalf("malice items: %+v", r.Outstanding[0].Items)
	}
	// the malice answered, the blocking advisory that remains is a mixed block
	c := confirmationsOf([]Identity{{Name: "a", Version: "1.0.0"}}, false, nil)
	r = Decide(Input{Target: graphOf(t, pkgs("a", "1.0.0")), Evidence: ev, Socket: socketOf(sroot("a", "1.0.0", SocketBlocked)), Confirmations: c})
	if r.Outcome.Class != ClassBlockingAdvisory || !r.Outstanding[0].Items[0].Mixed {
		t.Fatalf("%+v %+v", r.Outcome, r.Outstanding)
	}
}

// The records of a confirmed root come from the final decision, with the command-wide exclusions.
func TestConfirmedRecordsComeFromTheFinalDecision(t *testing.T) {
	approval := accept(AcceptLocalExact, "a", "1.0.0")
	base := func() Evidence {
		e := evidenceOf(read("a", "1.0.0", hit("GHSA-h", SeverityHigh)), read("b", "1.0.0")).accepting(approval)
		e.Answered = []Answered{{Name: "a", Version: "1.0.0", Class: ClassAdverseAdvisory, Token: "WARN_TTY_OVERRIDE"}}
		return e
	}
	target := graphOf(t, pkgs("a", "1.0.0", "b", "1.0.0"))
	socket := socketOf(sroot("a", "1.0.0", SocketClear), sroot("b", "1.0.0", SocketClear))
	decide := func(e Evidence, c Confirmations) Report {
		c.Answered = e.Answered
		return Decide(Input{Target: target, Evidence: e, Socket: socket, Confirmations: c})
	}
	r := decide(base(), confirmationsOf(nil, false, nil))
	if len(r.ConfirmedRecords) != 1 || r.ConfirmedRecords[0].Token != "WARN_TTY_OVERRIDE" || r.ConfirmedRecords[0].GateExit != 10 {
		t.Fatalf("control: %+v", r.ConfirmedRecords)
	}
	// a command confirmed on missing evidence on another root records nothing, neither kind
	gapped := base()
	gapped.Identities = []IdentityEvidence{read("a", "1.0.0", hit("GHSA-h", SeverityHigh)), gap("b", "1.0.0")}
	if r := decide(gapped, confirmationsOf(nil, true, nil)); len(r.ConfirmedRecords) != 0 || len(r.Records) != 0 || !r.Unjudged {
		t.Fatalf("a confirmed gap: %+v %v unjudged=%v", r.ConfirmedRecords, r.Records, r.Unjudged)
	}
	// a malice override, a block override, a Socket outage: the same
	mal := base().blocklisted("b")
	if r := decide(mal, confirmationsOf([]Identity{{Name: "b", Version: "1.0.0"}}, false, nil)); len(r.ConfirmedRecords) != 0 {
		t.Fatalf("a malice override: %+v", r.ConfirmedRecords)
	}
	blk := base()
	blk.Answered = append(blk.Answered, Answered{Name: "b", Version: "1.0.0", Class: ClassBlockingAdvisory})
	if r := decide(blk, confirmationsOf(nil, false, nil)); len(r.ConfirmedRecords) != 0 || len(r.Records) != 0 {
		t.Fatalf("a block override: %+v", r.ConfirmedRecords)
	}
	outage := socketOf(sroot("a", "1.0.0", SocketClear), sroot("b", "1.0.0", SocketUnavailable))
	out := Decide(Input{Target: target, Evidence: base(), Socket: outage, Confirmations: Confirmations{SchemaVersion: 1, Malice: []Identity{}, Socket: []Identity{{Name: "b", Version: "1.0.0"}}, Answered: base().Answered}})
	if len(out.ConfirmedRecords) != 0 || !out.Unjudged {
		t.Fatalf("an outage: %+v unjudged=%v", out.ConfirmedRecords, out.Unjudged)
	}
	// a root that relies on a followed authority in another class is not recorded; one not introduced is not either
	foll := base().accepting(accept(AcceptFollowedGrant, "a", "1.0.0"))
	young := releasesOf(3, SecurityFixExempt, reading("a", "1.0.0", 10))
	fr := Decide(Input{Target: target, Evidence: func() Evidence {
		e := foll
		e.Acceptances = []Acceptance{accept(AcceptFollowedGrant, "a", "1.0.0")}
		e.Answered = nil
		return e
	}(), Socket: socket, Releases: young, Confirmations: confirmationsOf(nil, false, nil)})
	if len(fr.ConfirmedRecords) != 0 {
		t.Fatalf("followed: %+v", fr.ConfirmedRecords)
	}
}
