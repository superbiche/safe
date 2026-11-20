package projectlane

import (
	"strings"
	"testing"
)

func sroot(name, version, outcome string) SocketRoot {
	exit := socketGateExit[outcome]
	line := map[string]string{
		SocketClear: "PASS (score=95)", SocketAdverse: "WARN (score=40)", SocketUnavailable: "WARN (socket authentication required)",
		SocketRateLimited: "WARN (socket rate-limited, retry later)", SocketConsentRequired: "CONSENT (fresh release 0d old)",
		SocketPending: "PENDING (fresh release 1.0.0, 0d old — Socket scan not yet complete)", SocketBlocked: "BLOCK (critical supply-chain-risk alert)",
	}[outcome]
	causes := []string{}
	if outcome == SocketBlocked {
		causes = []string{"socket_malware"}
	}
	return SocketRoot{Name: name, Version: version, Outcome: outcome, GateExit: exit, Line: line, Causes: causes}
}

func socketOf(roots ...SocketRoot) *SocketEvidence {
	return &SocketEvidence{SchemaVersion: SocketSchema, Roots: roots, CachedBlocks: []SocketBlock{}}
}

func decideSocket(t *testing.T, baseline, target map[string]map[string]any, sock *SocketEvidence, ev Evidence) Report {
	t.Helper()
	in := Input{Target: graphOf(t, target), Evidence: ev, Socket: sock}
	if baseline != nil {
		in.Baseline, in.HasBaseline = graphOf(t, baseline), true
	}
	return Decide(in)
}

// Each Socket result of a named root has today's exit: an adverse finding is policy (100), every other state that is not
// clear is the operator's (102); a blocking result is malice (104). Nothing is decided for a clear result.
func TestSocketOnANamedRootKeepsTodaysExits(t *testing.T) {
	ev := evidenceOf(read("pk", "1.0.0"))
	for _, c := range []struct {
		outcome string
		status  string
		class   string
		exit    int
	}{
		{SocketClear, "clear", "", 0},
		{SocketAdverse, "stopped", ClassSocketRoot, ExitPolicy},
		{SocketUnavailable, "stopped", ClassSocketRoot, ExitOperator},
		{SocketRateLimited, "stopped", ClassSocketRoot, ExitOperator},
		{SocketConsentRequired, "stopped", ClassSocketRoot, ExitOperator},
		{SocketPending, "stopped", ClassSocketRoot, ExitOperator},
		{SocketBlocked, "stopped", ClassMalice, ExitBlock},
	} {
		report := decideSocket(t, nil, pkgs("pk", "1.0.0"), socketOf(sroot("pk", "1.0.0", c.outcome)), ev)
		if report.Outcome.Status != c.status || report.Outcome.Class != c.class || report.Outcome.Exit != c.exit {
			t.Errorf("%s: %+v", c.outcome, report.Outcome)
		}
		if len(report.Socket.Roots) != 1 || report.Socket.Roots[0].Outcome != c.outcome {
			t.Errorf("%s: report %+v", c.outcome, report.Socket)
		}
	}
	// an adverse finding outranks the operator's states for the class's exit
	report := decideSocket(t, nil, pkgs("a", "1.0.0", "b", "1.0.0"), socketOf(sroot("a", "1.0.0", SocketRateLimited), sroot("b", "1.0.0", SocketAdverse)), evidenceOf(read("a", "1.0.0"), read("b", "1.0.0")))
	if report.Outcome.Class != ClassSocketRoot || report.Outcome.Exit != ExitPolicy {
		t.Fatalf("%+v", report.Outcome)
	}
}

// A blocking Socket result already in the cache counts for any artifact of the target graph, named or not; one for an
// identity the target does not carry does not.
func TestACachedBlockCountsForAnyArtifactOfTheTarget(t *testing.T) {
	sock := socketOf()
	sock.CachedBlocks = []SocketBlock{{Name: "dep", Version: "2.0.0", Line: "BLOCK (critical supply-chain-risk alert)"}, {Name: "gone", Version: "1.0.0", Line: "BLOCK (critical supply-chain-risk alert)"}}
	report := decideSocket(t, nil, pkgs("pk", "1.0.0", "dep", "2.0.0"), sock, evidenceOf(read("pk", "1.0.0"), read("dep", "2.0.0")))
	if report.Outcome.Class != ClassMalice || report.Outcome.Exit != ExitBlock {
		t.Fatalf("%+v", report.Outcome)
	}
	if len(report.Malice) != 1 || report.Malice[0].Signal != "socket_block" || report.Malice[0].Name != "dep" {
		t.Fatalf("malice %+v", report.Malice)
	}
	// no standing acceptance clears malice
	cleared := decideSocket(t, nil, pkgs("pk", "1.0.0", "dep", "2.0.0"), sock,
		evidenceOf(read("pk", "1.0.0"), read("dep", "2.0.0")).accepting(accept(AcceptLocalExact, "dep", "2.0.0")))
	if cleared.Outcome.Class != ClassMalice {
		t.Fatalf("an acceptance cleared malice: %+v", cleared.Outcome)
	}
	// a block of a package the baseline already carried is still malice of the target graph
	carried := decideSocket(t, pkgs("dep", "2.0.0"), pkgs("pk", "1.0.0", "dep", "2.0.0"), sock, evidenceOf(read("pk", "1.0.0"), read("dep", "2.0.0")))
	if carried.Outcome.Class != ClassMalice {
		t.Fatalf("%+v", carried.Outcome)
	}
}

// Only the named roots are scored: a root the projected graph does not carry is ignored, and the report lists the roots only.
func TestOnlyNamedRootsCarriedByTheTargetAreJudged(t *testing.T) {
	sock := socketOf(sroot("pk", "1.0.0", SocketAdverse), sroot("elsewhere", "1.0.0", SocketAdverse))
	report := decideSocket(t, nil, pkgs("pk", "1.0.0"), sock, evidenceOf(read("pk", "1.0.0")))
	if len(report.Socket.Roots) != 1 || report.Socket.Roots[0].Name != "pk" {
		t.Fatalf("%+v", report.Socket.Roots)
	}
}

// The order: after the Wait class, before missing evidence; a standing acceptance clears a root's class item as today
// (local exact approval, followed grant, followed install allowance), never a followed advisory override.
func TestSocketClassOrderAndClearing(t *testing.T) {
	young := releasesOf(3, SecurityFixExempt, reading("pk", "1.0.0", 10))
	ev := evidenceOf(read("pk", "1.0.0"))
	in := Input{Target: graphOf(t, pkgs("pk", "1.0.0")), Evidence: ev, Releases: young, Socket: socketOf(sroot("pk", "1.0.0", SocketRateLimited))}
	report := Decide(in)
	if report.Outcome.Class != ClassWait {
		t.Fatalf("the wait comes first: %+v", report.Outcome)
	}
	order := []string{}
	for _, class := range report.Classes {
		order = append(order, class.Class)
	}
	if strings.Join(order, ",") != "malice,blocking_advisory,adverse_advisory,wait,socket_root,missing_evidence" {
		t.Fatalf("class order %v", order)
	}
	// missing evidence comes after
	gap := decideSocket(t, nil, pkgs("pk", "1.0.0"), socketOf(sroot("pk", "1.0.0", SocketRateLimited)), evidenceOf(gap("pk", "1.0.0")))
	if gap.Outcome.Class != ClassSocketRoot {
		t.Fatalf("the Socket class comes before missing evidence: %+v", gap.Outcome)
	}
	for _, kind := range []string{AcceptLocalExact, AcceptFollowedGrant, AcceptFollowedInstall} {
		cleared := decideSocket(t, nil, pkgs("pk", "1.0.0"), socketOf(sroot("pk", "1.0.0", SocketConsentRequired)), evidenceOf(read("pk", "1.0.0")).accepting(accept(kind, "pk", "1.0.0")))
		if cleared.Outcome.Status != "clear" || !cleared.Socket.Roots[0].Cleared || cleared.Socket.Roots[0].ClearedBy[0] != kind {
			t.Errorf("%s did not clear: %+v / %+v", kind, cleared.Outcome, cleared.Socket)
		}
	}
	uncleared := decideSocket(t, nil, pkgs("pk", "1.0.0"), socketOf(sroot("pk", "1.0.0", SocketConsentRequired)), evidenceOf(read("pk", "1.0.0")).accepting(accept(AcceptFollowedOverride, "pk", "1.0.0")))
	if uncleared.Outcome.Class != ClassSocketRoot {
		t.Fatalf("an advisory override cleared a Socket result: %+v", uncleared.Outcome)
	}
}

// A cache that could not be read is missing evidence, and an established block still comes first.
func TestAnUnreadCacheIsMissingEvidenceAfterBlocks(t *testing.T) {
	sock := socketOf()
	sock.CacheGap = "the Socket cache could not be read"
	report := decideSocket(t, nil, pkgs("pk", "1.0.0"), sock, evidenceOf(read("pk", "1.0.0")))
	if report.Outcome.Class != ClassMissingEvidence || report.Outcome.Exit != ExitOperator || !strings.Contains(report.Coverage[0].Gap, "socket cache not read") {
		t.Fatalf("%+v / %+v", report.Outcome, report.Coverage)
	}
	blocked := decideSocket(t, nil, pkgs("pk", "1.0.0"), sock, evidenceOf(read("pk", "1.0.0")).blocklisted("pk"))
	if blocked.Outcome.Class != ClassMalice {
		t.Fatalf("%+v", blocked.Outcome)
	}
}

// No Socket evidence given: the class does not exist and nothing about Socket is judged.
func TestNoSocketEvidenceNoClass(t *testing.T) {
	report := decideSocket(t, nil, pkgs("pk", "1.0.0"), nil, evidenceOf(read("pk", "1.0.0")))
	if report.Socket != nil || len(report.Classes) != 4 {
		t.Fatalf("%+v", report.Classes)
	}
}

func TestReadSocketIsStrict(t *testing.T) {
	good := `{"schema_version":1,"roots":[{"name":"a","version":"1.0.0","outcome":"adverse","gate_exit":10,"line":"WARN (score=40)","causes":["socket_low_score"],"cached":false}],"cached_blocks":[{"name":"b","version":"2.0.0","line":"BLOCK (critical supply-chain-risk alert)"}],"cache_gap":""}`
	if _, err := ReadSocket([]byte(good)); err != nil {
		t.Fatalf("a good document was refused: %v", err)
	}
	for name, doc := range map[string]string{
		"not json":             `nope`,
		"unknown member":       strings.Replace(good, `"cache_gap"`, `"extra":1,"cache_gap"`, 1),
		"repeated member":      strings.Replace(good, `"cache_gap":""`, `"cache_gap":"","cache_gap":"x"`, 1),
		"another schema":       strings.Replace(good, `"schema_version":1`, `"schema_version":2`, 1),
		"unknown outcome":      strings.Replace(good, `"outcome":"adverse"`, `"outcome":"mostly clear"`, 1),
		"exit not the outcome": strings.Replace(good, `"gate_exit":10`, `"gate_exit":0`, 1),
		"bad cause":            strings.Replace(good, `"socket_low_score"`, `"low score"`, 1),
		"line break":           strings.Replace(good, `WARN (score=40)`, `WARN\nPASS`, 1),
		"empty line":           strings.Replace(good, `"line":"WARN (score=40)"`, `"line":""`, 1),
		"missing member":       strings.Replace(good, `,"cached":false`, ``, 1),
		"duplicate root":       strings.Replace(good, `"cached_blocks"`, `"cached_blocks"`, 1) + ` `,
	} {
		if name == "duplicate root" {
			doc = strings.Replace(good, `"roots":[`, `"roots":[{"name":"a","version":"1.0.0","outcome":"clear","gate_exit":0,"line":"PASS (score=95)","causes":[],"cached":false},`, 1)
		}
		if _, err := ReadSocket([]byte(doc)); err == nil {
			t.Errorf("%s: the document was read", name)
		}
	}
}

// A bundled member's public standing comes from its parent: a block cached for it is malice of the target like any other.
func TestACachedBlockCountsForABundledMemberOfTheTarget(t *testing.T) {
	sock := socketOf()
	sock.CachedBlocks = []SocketBlock{{Name: "bund", Version: "1.0.0", Line: "BLOCK (critical supply-chain-risk alert)"}}
	target := map[string]map[string]any{
		"node_modules/b":                   entry("b", "2.0.0"),
		"node_modules/b/node_modules/bund": {"version": "1.0.0", "inBundle": true},
	}
	report := decideSocket(t, nil, target, sock, evidenceOf(read("b", "2.0.0"), read("bund", "1.0.0")))
	if report.Outcome.Class != ClassMalice || report.Outcome.Exit != ExitBlock || len(report.Malice) != 1 || report.Malice[0].Name != "bund" {
		t.Fatalf("%+v / %+v", report.Outcome, report.Malice)
	}
}
