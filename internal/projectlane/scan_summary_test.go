package projectlane

import (
	"reflect"
	"testing"
)

func TestScanSummaryReadsTheVerdictAndTheProducersStatusAndKeepsNoFreeText(t *testing.T) {
	doc := `{"audit_totals":{"critical":8,"high":46,"by_ecosystem":{"npm":{"critical":5},"python":{"critical":2},"mystery":{"critical":1},"go":{"critical":0}}},
	 "tool_status":{"grype":{"status":"ok"},"syft":{"status":"skipped","note":"leaked token abc"},"osv-scanner":{"status":"partial","note":"it could not read"},"x y":{"status":"error"},"odd":{"status":"degraded"},"quiet":{}},
	 "ecosystem_audits":[{"scanner":"npm-audit","status":"error"},{"scanner":"pip-audit","status":"ok"},{"scanner":"Bad Name!","status":"error"},{"status":"error"}]}`
	got, err := ReadScanSummary([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	want := ScanSummary{SchemaVersion: 1, CriticalTotal: 8, Critical: map[string]int{"npm": 5, "python": 2}, Unattributed: 1,
		CoverageGaps: []ScanGap{{"npm-audit", "error"}, {"osv-scanner", "partial"}, {"syft", "skipped"}}, CoverageOther: 4}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%+v\nwant %+v", got, want)
	}
}

// The producer's own rule (bin/safe-audit): a scanner whose status is not "ok" is a gap, whatever its note says; a note is never read.
func TestScanSummaryNeverReadsANoteAndTakesEveryNonOkStatusAsAGap(t *testing.T) {
	for _, status := range []string{"partial", "skipped", "unavailable", "error", "unsupported"} {
		got, err := ReadScanSummary([]byte(`{"audit_totals":{"critical":0},"ecosystem_audits":[],"tool_status":{"syft":{"status":"` + status + `","note":"all fine, nothing to see"}}}`))
		if err != nil || len(got.CoverageGaps) != 1 || got.CoverageGaps[0].Status != status || got.CoverageUnreadable {
			t.Fatalf("%s: %+v %v", status, got, err)
		}
	}
	got, _ := ReadScanSummary([]byte(`{"audit_totals":{"critical":0},"ecosystem_audits":[],"tool_status":{"syft":{"status":"ok","note":"it failed with an error"}}}`))
	if len(got.CoverageGaps) != 0 || got.CoverageOther != 0 || got.CoverageUnreadable {
		t.Fatalf("a note was read: %+v", got)
	}
}

// A coverage section that is there and cannot be read is not zero gaps.
func TestScanSummaryCoverageThatCannotBeReadIsUnreadableNotZero(t *testing.T) {
	for name, doc := range map[string]string{
		"a list for the tools":      `{"audit_totals":{"critical":0},"tool_status":[1]}`,
		"a string":                  `{"audit_totals":{"critical":0},"tool_status":"ok"}`,
		"null":                      `{"audit_totals":{"critical":0},"tool_status":null}`,
		"a tool that is a string":   `{"audit_totals":{"critical":0},"tool_status":{"syft":"error"}}`,
		"a status that is a number": `{"audit_totals":{"critical":0},"tool_status":{"syft":{"status":3}}}`,
		"audits that are an object": `{"audit_totals":{"critical":0},"ecosystem_audits":{"a":1}}`,
		"an audit that is a number": `{"audit_totals":{"critical":0},"ecosystem_audits":[1]}`,
	} {
		got, err := ReadScanSummary([]byte(doc))
		if err != nil || !got.CoverageUnreadable {
			t.Errorf("%s: %+v %v", name, got, err)
		}
	}
	// a result with no coverage section is coverage nobody can read (the producer writes both on every result)
	for name, doc := range map[string]string{
		"neither section":     `{"audit_totals":{"critical":0}}`,
		"no tool status":      `{"audit_totals":{"critical":0},"ecosystem_audits":[]}`,
		"no ecosystem audits": `{"audit_totals":{"critical":0},"tool_status":{}}`,
	} {
		if got, _ := ReadScanSummary([]byte(doc)); !got.CoverageUnreadable {
			t.Errorf("%s read as complete coverage: %+v", name, got)
		}
	}
	if got, _ := ReadScanSummary([]byte(`{"audit_totals":{"critical":0},"tool_status":{},"ecosystem_audits":[]}`)); got.CoverageUnreadable || len(got.CoverageGaps) != 0 {
		t.Errorf("two empty sections are no gap: %+v", got)
	}
}

func TestScanSummaryBreakdownThatDoesNotAddUpIsUnattributed(t *testing.T) {
	for name, doc := range map[string]string{
		"no breakdown":   `{"audit_totals":{"critical":3}}`,
		"does not add":   `{"audit_totals":{"critical":3,"by_ecosystem":{"npm":{"critical":1}}}}`,
		"not an object":  `{"audit_totals":{"critical":3,"by_ecosystem":[1]}}`,
		"negative count": `{"audit_totals":{"critical":3,"by_ecosystem":{"npm":{"critical":-3}}}}`,
	} {
		got, err := ReadScanSummary([]byte(doc))
		if err != nil || got.Unattributed != 3 || len(got.Critical) != 0 {
			t.Fatalf("%s: %+v %v", name, got, err)
		}
	}
	// the cve_scan total is read when audit_totals has none (the gate's own fallback)
	if got, err := ReadScanSummary([]byte(`{"cve_scan":{"critical":2}}`)); err != nil || got.CriticalTotal != 2 || got.Unattributed != 2 {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestScanSummaryWithoutAVerdictIsNoSummary(t *testing.T) {
	for _, doc := range []string{``, `[]`, `{`, `{}`, `{"audit_totals":{"critical":"2"}}`, `{"audit_totals":{"critical":-1}}`, `{"audit_totals":{"critical":null}}`,
		`{"audit_totals":{"critical":1},"audit_totals":{"critical":2}}`, "\xef\xbb\xbf"} {
		if _, err := ReadScanSummary([]byte(doc)); err == nil {
			t.Fatalf("%q was read as a verdict", doc)
		}
	}
}

func TestScanSummaryBoundsTheFailureNames(t *testing.T) {
	status := `{`
	for i := 0; i < 30; i++ {
		if i > 0 {
			status += ","
		}
		status += `"s` + string(rune('a'+i%26)) + string(rune('a'+i/26)) + `":{"status":"error"}`
	}
	status += `}`
	got, err := ReadScanSummary([]byte(`{"audit_totals":{"critical":0},"tool_status":` + status + `}`))
	if err != nil || len(got.CoverageGaps) != maxScanFailures || got.CoverageOther != 10 {
		t.Fatalf("%d %d %v", len(got.CoverageGaps), got.CoverageOther, err)
	}
}
