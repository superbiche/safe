package projectlane

import (
	"reflect"
	"testing"
)

func TestScanSummaryReadsTheVerdictAndKeepsNoFreeText(t *testing.T) {
	doc := `{"audit_totals":{"critical":8,"high":46,"by_ecosystem":{"npm":{"critical":5},"python":{"critical":2},"mystery":{"critical":1},"go":{"critical":0}}},
	 "tool_status":{"grype":{"status":"ok"},"syft":{"status":"error","note":"leaked token abc"},"osv-scanner":{"status":"degraded","note":"it FAILED"},"x y":{"status":"error"}},
	 "ecosystem_audits":[{"scanner":"npm-audit","status":"error"},{"scanner":"pip-audit","status":"ok"},{"scanner":"Bad Name!","status":"error"},{"status":"error"}]}`
	got, err := ReadScanSummary([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	want := ScanSummary{SchemaVersion: 1, CriticalTotal: 8, Critical: map[string]int{"npm": 5, "python": 2}, Unattributed: 1,
		CoverageFailures: []string{"npm-audit", "osv-scanner", "syft", "unknown"}, CoverageOther: 2}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%+v\nwant %+v", got, want)
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
	if err != nil || len(got.CoverageFailures) != maxScanFailures || got.CoverageOther != 10 {
		t.Fatalf("%d %d %v", len(got.CoverageFailures), got.CoverageOther, err)
	}
}
