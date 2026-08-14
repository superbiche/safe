package verdict

import (
	"slices"
	"strings"
	"testing"
)

// clean is a fully-passing evidence document. Each test mutates one field, so
// any verdict other than GO is attributable to that mutation alone.
func clean() Evidence {
	return Evidence{
		Resolution: Resolution{OK: true, PrimaryVersion: "1.2.3", Label: "1.2.3"},
		Socket: Socket{
			Status: "ok", Available: true, Score: "88", Class: "clean",
		},
		OSV:             OSV{Status: "ok"},
		Release:         Release{RC: 0, Age: 30, Version: "1.2.3", CooldownDays: 3, CooldownSecurityFix: "exempt"},
		Blocklist:       Blocklist{Readable: true, Path: "/etc/safe/blocked.json"},
		BlockSeverities: []string{"critical"},
	}
}

func TestCleanEvidenceGoes(t *testing.T) {
	got := Decide(clean())
	if got.Verdict != GO {
		t.Fatalf("verdict = %q, want GO (causes=%v)", got.Verdict, got.Causes)
	}
	if len(got.Causes) != 0 {
		t.Fatalf("causes = %v, want none", got.Causes)
	}
	if got.Lines.Socket != "PASS (score=88)" {
		t.Errorf("socket line = %q", got.Lines.Socket)
	}
	if got.Lines.OSV != "PASS (no known advisories for 1.2.3)" {
		t.Errorf("osv line = %q", got.Lines.OSV)
	}
}

// Absence of evidence is never clean: every way of NOT getting a behavioral
// signal must warn, each under its own distinguishable cause.
func TestSocketAbsenceNeverPasses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Evidence)
		cause  string
	}{
		{"policy skip", func(e *Evidence) { e.Socket.Status = "skipped"; e.Socket.Note = "disabled" }, "socket_disabled"},
		{"cli missing", func(e *Evidence) { e.Socket.Available = false }, "socket_unavailable"},
		{"rate limited", func(e *Evidence) { e.Socket.Status = "error"; e.Socket.Reason = "rate_limited" }, "socket_rate_limited"},
		{"auth", func(e *Evidence) { e.Socket.Status = "error"; e.Socket.Reason = "auth" }, "socket_auth_failed"},
		{"timeout", func(e *Evidence) { e.Socket.Status = "error"; e.Socket.Reason = "timeout" }, "socket_error"},
		{"unbounded", func(e *Evidence) { e.Socket.Status = "error"; e.Socket.Reason = "unbounded" }, "socket_error"},
		{"not found", func(e *Evidence) { e.Socket.Status = "error"; e.Socket.Reason = "not_found" }, "socket_not_found"},
		{"unknown reason", func(e *Evidence) { e.Socket.Status = "error"; e.Socket.Reason = "wat" }, "socket_error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev := clean()
			tc.mutate(&ev)
			got := Decide(ev)
			if got.Verdict != WARN {
				t.Fatalf("verdict = %q, want WARN", got.Verdict)
			}
			if !hasCause(got.Causes, tc.cause) {
				t.Fatalf("causes = %v, want %q", got.Causes, tc.cause)
			}
		})
	}
}

func TestSocketClassMapping(t *testing.T) {
	for _, tc := range []struct {
		class   string
		verdict string
		cause   string
	}{
		{"malware", BLOCK, "socket_malware"},
		{"unmapped", WARN, "socket_error"},
		{"critical_cve", WARN, "socket_critical_cve"},
		{"high", WARN, "socket_high_alert"},
		{"low_score", WARN, "socket_low_score"},
		{"clean", GO, ""},
	} {
		t.Run(tc.class, func(t *testing.T) {
			ev := clean()
			ev.Socket.Class = tc.class
			got := Decide(ev)
			if got.Verdict != tc.verdict {
				t.Fatalf("verdict = %q, want %q", got.Verdict, tc.verdict)
			}
			if tc.cause != "" && !hasCause(got.Causes, tc.cause) {
				t.Fatalf("causes = %v, want %q", got.Causes, tc.cause)
			}
		})
	}
}

// The defect that motivated sibling scanning: a clean primary must not carry a
// malicious sibling in on a ranged update.
func TestMaliciousSiblingBlocksCleanPrimary(t *testing.T) {
	ev := clean()
	ev.SocketSiblings = []SocketSibling{{Version: "2.5.0", Status: "ok", Class: "malware"}}
	got := Decide(ev)
	if got.Verdict != BLOCK {
		t.Fatalf("verdict = %q, want BLOCK", got.Verdict)
	}
	if !strings.Contains(got.Lines.Socket, "BLOCK 2.5.0") {
		t.Errorf("socket line = %q, want the sibling named", got.Lines.Socket)
	}
}

func TestUnscorableSiblingIsNotAssumedClean(t *testing.T) {
	ev := clean()
	ev.SocketSiblings = []SocketSibling{{Version: "2.5.0", Status: "error"}}
	got := Decide(ev)
	if got.Verdict != WARN {
		t.Fatalf("verdict = %q, want WARN", got.Verdict)
	}
	if !hasCause(got.Causes, "socket_error") {
		t.Fatalf("causes = %v, want socket_error", got.Causes)
	}
}

// A not_found sibling is an absence of behavioral data, not an outage: it warns
// under socket_not_found (independently tolerable), never socket_error, so a
// ranged install in an ecosystem Socket has not indexed can be overridden the
// same way its primary can.
func TestNotFoundSiblingIsDistinctFromOutage(t *testing.T) {
	ev := clean()
	ev.SocketSiblings = []SocketSibling{{Version: "2.5.0", Status: "error", Reason: "not_found"}}
	got := Decide(ev)
	if got.Verdict != WARN {
		t.Fatalf("verdict = %q, want WARN", got.Verdict)
	}
	if !hasCause(got.Causes, "socket_not_found") {
		t.Fatalf("causes = %v, want socket_not_found", got.Causes)
	}
	if hasCause(got.Causes, "socket_error") {
		t.Fatalf("causes = %v, must not conflate not_found with an outage", got.Causes)
	}
}

// not_found must be separable from real outages so an operator can tolerate the
// coverage gap without also tolerating a Socket outage.
func TestNotFoundIsNotSocketError(t *testing.T) {
	ev := clean()
	ev.Socket.Status = "error"
	ev.Socket.Reason = "not_found"
	got := Decide(ev)
	if hasCause(got.Causes, "socket_error") {
		t.Fatalf("causes = %v, not_found must not map to socket_error", got.Causes)
	}
}

// Adverse advisory evidence must survive a partial OSV outage rather than being
// demoted to a host-allowable osv_unavailable WARN.
func TestMalwareSurvivesPartialOSVOutage(t *testing.T) {
	ev := clean()
	ev.OSV = OSV{
		Status:     "error",
		Affecting:  []Advisory{{ID: "MAL-2026-1", Severity: "unknown", Malware: true}},
		TotalCount: 1,
	}
	got := Decide(ev)
	if got.Verdict != BLOCK {
		t.Fatalf("verdict = %q, want BLOCK", got.Verdict)
	}
	if !hasCause(got.Causes, "osv_malware") {
		t.Fatalf("causes = %v, want osv_malware", got.Causes)
	}
	if !hasCause(got.Causes, "osv_unavailable") {
		t.Fatalf("causes = %v, want the outage disclosed too", got.Causes)
	}
}

// Malware blocks regardless of block_severities: severity policy is not malware
// policy, and MAL-* records usually carry no CVSS at all.
func TestMalwareIgnoresBlockSeverityPolicy(t *testing.T) {
	ev := clean()
	ev.BlockSeverities = []string{}
	ev.OSV = OSV{
		Status:     "ok",
		Affecting:  []Advisory{{ID: "MAL-2026-1", Severity: "unknown", Malware: true}},
		TotalCount: 1,
	}
	if got := Decide(ev); got.Verdict != BLOCK {
		t.Fatalf("verdict = %q, want BLOCK even with no block severities", got.Verdict)
	}
}

func TestAffectingSummaryTruncatesLoudly(t *testing.T) {
	ev := clean()
	ev.OSV = OSV{
		Status: "ok",
		Affecting: []Advisory{
			{ID: "CVE-1", Severity: "high"}, {ID: "CVE-2", Severity: "high"},
			{ID: "CVE-3", Severity: "high"}, {ID: "CVE-4", Severity: "high"},
		},
		TotalCount: 9,
	}
	got := Decide(ev)
	if !strings.Contains(got.Lines.OSV, "+1 more") {
		t.Fatalf("osv line = %q, want the truncation disclosed", got.Lines.OSV)
	}
	if strings.Contains(got.Lines.OSV, "CVE-4") {
		t.Fatalf("osv line = %q, want only three ids shown", got.Lines.OSV)
	}
}

func TestUnresolvedVersionWithMalwareHistoryBlocks(t *testing.T) {
	ev := clean()
	ev.Resolution.OK = false
	ev.OSV = OSV{Status: "ok", TotalCount: 4, HistoricalMalwareIDs: "MAL-2026-9"}
	got := Decide(ev)
	if got.Verdict != BLOCK {
		t.Fatalf("verdict = %q, want BLOCK", got.Verdict)
	}
	if !hasCause(got.Causes, "version_unresolved") || !hasCause(got.Causes, "osv_malware") {
		t.Fatalf("causes = %v", got.Causes)
	}
}

func TestCooldownWaivedOnlyForSecurityFixWhenExempt(t *testing.T) {
	base := clean()
	base.Release = Release{RC: 0, Age: 1, Version: "1.2.3", CooldownDays: 3, CooldownSecurityFix: "exempt"}

	t.Run("young release warns", func(t *testing.T) {
		if got := Decide(base); got.Verdict != WARN || !hasCause(got.Causes, "release_too_new") {
			t.Fatalf("verdict=%q causes=%v", got.Verdict, got.Causes)
		}
	})

	t.Run("security fix waives", func(t *testing.T) {
		ev := base
		ev.Release.SecurityFixIDs = "CVE-2026-1"
		got := Decide(ev)
		if got.Verdict != GO {
			t.Fatalf("verdict = %q, want GO", got.Verdict)
		}
		if !got.ReleaseExempt {
			t.Error("ReleaseExempt = false, want true")
		}
	})

	t.Run("enforce keeps the wait", func(t *testing.T) {
		ev := base
		ev.Release.SecurityFixIDs = "CVE-2026-1"
		ev.Release.CooldownSecurityFix = "enforce"
		got := Decide(ev)
		if got.Verdict != WARN || !hasCause(got.Causes, "release_too_new") {
			t.Fatalf("verdict=%q causes=%v", got.Verdict, got.Causes)
		}
		if !strings.Contains(got.Lines.Release, "cooldown_security_fix=enforce") {
			t.Errorf("release line = %q, want the enforce posture disclosed", got.Lines.Release)
		}
	})
}

func TestUnreadableBlocklistIsNotNotBlocked(t *testing.T) {
	ev := clean()
	ev.Blocklist = Blocklist{Readable: false, Path: "/etc/safe/blocked.json"}
	got := Decide(ev)
	if got.Verdict != WARN || !hasCause(got.Causes, "blocklist_unreadable") {
		t.Fatalf("verdict=%q causes=%v", got.Verdict, got.Causes)
	}
	if !strings.Contains(got.Lines.Block, "/etc/safe/blocked.json") {
		t.Errorf("block line = %q, want the path named", got.Lines.Block)
	}
}

// A pending Socket score may leave a GO only when nothing else is adverse.
func TestPendingScoreOnlySurvivesAnOtherwiseCleanCheck(t *testing.T) {
	t.Run("otherwise clean stays GO", func(t *testing.T) {
		ev := clean()
		ev.Socket.Status = "pending"
		ev.Release.PrimaryAge = "1"
		got := Decide(ev)
		if got.Verdict != GO {
			t.Fatalf("verdict = %q, want GO (causes=%v)", got.Verdict, got.Causes)
		}
		if !got.SocketPending {
			t.Error("SocketPending = false, want true")
		}
	})

	for _, tc := range []struct {
		name   string
		mutate func(*Evidence)
	}{
		{"osv outage", func(e *Evidence) { e.OSV.Status = "error" }},
		{"unresolved", func(e *Evidence) { e.Resolution.OK = false }},
		{"affecting advisory", func(e *Evidence) {
			e.OSV.Affecting = []Advisory{{ID: "CVE-1", Severity: "low"}}
			e.OSV.TotalCount = 1
		}},
		{"blocklisted", func(e *Evidence) { e.Blocklist.Reason = "operator" }},
		{"custom source", func(e *Evidence) { e.CustomSource = true }},
	} {
		t.Run(tc.name+" adds pending cause", func(t *testing.T) {
			ev := clean()
			ev.Socket.Status = "pending"
			ev.Release.PrimaryAge = "1"
			tc.mutate(&ev)
			got := Decide(ev)
			if got.Verdict == GO {
				t.Fatalf("verdict = GO, want raised (causes=%v)", got.Causes)
			}
			if !hasCause(got.Causes, "socket_score_pending") {
				t.Fatalf("causes = %v, want socket_score_pending", got.Causes)
			}
		})
	}
}

// Monotonicity: no stage may lower a verdict an earlier stage raised.
func TestVerdictIsMonotonic(t *testing.T) {
	ev := clean()
	ev.Socket.Class = "malware" // BLOCK in the first stage
	// Every later stage reports clean.
	ev.OSV = OSV{Status: "ok", TotalCount: 0}
	ev.Release = Release{RC: 0, Age: 90, CooldownDays: 3, CooldownSecurityFix: "exempt"}
	ev.Blocklist = Blocklist{Readable: true}
	if got := Decide(ev); got.Verdict != BLOCK {
		t.Fatalf("verdict = %q, want BLOCK — a later clean signal must not launder it", got.Verdict)
	}
}

func TestCauseOrderFollowsStageOrder(t *testing.T) {
	ev := clean()
	ev.Socket.Status = "skipped"
	ev.Socket.Note = "disabled"
	ev.OSV = OSV{Status: "error"}
	ev.Release = Release{RC: 0, Age: 1, CooldownDays: 3, CooldownSecurityFix: "exempt"}
	ev.CustomSource = true
	ev.Blocklist = Blocklist{Readable: false, Path: "/x"}

	want := []string{"socket_disabled", "osv_unavailable", "release_too_new", "custom_source", "blocklist_unreadable"}
	got := Decide(ev)
	if len(got.Causes) != len(want) {
		t.Fatalf("causes = %v, want %v", got.Causes, want)
	}
	for i := range want {
		if got.Causes[i] != want[i] {
			t.Fatalf("causes = %v, want %v", got.Causes, want)
		}
	}
}

func hasCause(causes []string, want string) bool {
	return slices.Contains(causes, want)
}
