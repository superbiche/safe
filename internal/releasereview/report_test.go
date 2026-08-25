package releasereview

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSeverityOrdering(t *testing.T) {
	if !(GO < WARN && WARN < ERROR && ERROR < BLOCK) {
		t.Fatal("severity ordering must be GO < WARN < ERROR < BLOCK")
	}
}

func TestExitCodes(t *testing.T) {
	cases := map[Severity]int{GO: 0, WARN: 10, BLOCK: 20, ERROR: 30}
	for severity, want := range cases {
		if got := severity.ExitCode(); got != want {
			t.Fatalf("%s exits %d, want %d", severity, got, want)
		}
	}
}

func TestSeverityMarshalsAsName(t *testing.T) {
	encoded, err := json.Marshal(struct {
		Verdict Severity `json:"verdict"`
	}{Verdict: ERROR})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(encoded) != `{"verdict":"ERROR"}` {
		t.Fatalf("encoded %s, want {\"verdict\":\"ERROR\"}", encoded)
	}
}

func TestWorst(t *testing.T) {
	cases := []struct {
		a, b, want Severity
	}{
		{GO, GO, GO},
		{GO, WARN, WARN},
		{WARN, GO, WARN},
		{WARN, ERROR, ERROR},
		{ERROR, WARN, ERROR},
		{ERROR, BLOCK, BLOCK},
		{BLOCK, ERROR, BLOCK},
		{BLOCK, GO, BLOCK},
	}
	for _, testCase := range cases {
		if got := worst(testCase.a, testCase.b); got != testCase.want {
			t.Fatalf("worst(%s, %s) = %s, want %s", testCase.a, testCase.b, got, testCase.want)
		}
	}
}

// The advisory cap applies at aggregation only: a check entry keeps its own
// verdict so a report never hides what an advisory check actually found.
func TestAggregate(t *testing.T) {
	type check struct {
		verdict  Severity
		advisory bool
	}
	cases := []struct {
		name   string
		checks []check
		want   Severity
	}{
		{"all clean", []check{{GO, false}, {GO, false}}, GO},
		{"required warn", []check{{GO, false}, {WARN, false}}, WARN},
		{"required error", []check{{GO, false}, {ERROR, false}}, ERROR},
		{"required block", []check{{WARN, false}, {BLOCK, false}}, BLOCK},
		{"block dominates error", []check{{ERROR, false}, {BLOCK, false}}, BLOCK},
		{"error outranks warn", []check{{WARN, false}, {ERROR, false}}, ERROR},
		{"advisory block caps to warn", []check{{BLOCK, true}}, WARN},
		{"advisory error caps to warn", []check{{ERROR, true}}, WARN},
		{"advisory warn stays warn", []check{{WARN, true}}, WARN},
		{"advisory go stays go", []check{{GO, true}}, GO},
		{"advisory block does not mask required error", []check{{BLOCK, true}, {ERROR, false}}, ERROR},
		{"required block beats advisory anything", []check{{BLOCK, true}, {BLOCK, false}}, BLOCK},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			verdict := GO
			for _, entry := range testCase.checks {
				effective := entry.verdict
				if entry.advisory {
					effective = effective.capAdvisory()
				}
				verdict = worst(verdict, effective)
			}
			if verdict != testCase.want {
				t.Fatalf("aggregated %s, want %s", verdict, testCase.want)
			}
		})
	}
}

func TestReviewAppliesAdvisoryCapOnlyAtTopLevel(t *testing.T) {
	dir := t.TempDir()
	artifact := writeFile(t, dir, "tool.tar.gz", "payload")
	checksums := writeFile(t, dir, "checksums.txt", "0000000000000000000000000000000000000000000000000000000000000000  tool.tar.gz\n")

	spec := Spec{
		SpecVersion: SpecVersion,
		Subject:     Subject{Repo: "o/r", Version: "v1"},
		Artifacts: []Artifact{{
			Path:      artifact,
			AssetName: "tool.tar.gz",
			Evidence:  Evidence{ChecksumFile: checksums},
		}},
		Checks: &Checks{Checksum: &CheckConfig{Enabled: true, Advisory: true}},
	}

	report := Review(spec)
	if report.Verdict != WARN {
		t.Fatalf("top-level verdict %s, want WARN (advisory cap)", report.Verdict)
	}
	if len(report.Checks) != 1 {
		t.Fatalf("report carries %d checks, want 1", len(report.Checks))
	}
	if report.Checks[0].Verdict != BLOCK {
		t.Fatalf("check verdict %s, want BLOCK (uncapped)", report.Checks[0].Verdict)
	}
	if !report.Checks[0].Advisory {
		t.Fatal("check entry lost its advisory marking")
	}
}

func TestReviewEnvelope(t *testing.T) {
	dir := t.TempDir()
	artifact := writeFile(t, dir, "tool.tar.gz", "payload")
	checksums := writeFile(t, dir, "checksums.txt", sha256Of("payload")+"  tool.tar.gz\n")

	spec := Spec{
		SpecVersion: SpecVersion,
		Subject:     Subject{Repo: "o/r", Version: "v9"},
		Artifacts: []Artifact{{
			Path:      artifact,
			AssetName: "tool.tar.gz",
			Evidence: Evidence{
				ChecksumFile: checksums,
				Signature:    &SignatureEvidence{Bundle: "b", Identity: "i", OIDCIssuer: "u"},
			},
		}},
	}

	encoded, err := json.Marshal(Review(spec))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"schema_version":1,"subject":{"repo":"o/r","version":"v9"},"verdict":"WARN",` +
		`"checks":[{"id":"checksum","advisory":false,"verdict":"WARN","reasons":[` +
		`{"code":"checksum_only_verification",` +
		`"message":"tool.tar.gz matched its checksum, but no enabled signature check vouched for it",` +
		`"data":{"artifact":"tool.tar.gz"}}]}]}`
	if string(encoded) != want {
		t.Fatalf("report encoded as\n%s\nwant\n%s", encoded, want)
	}
}

// A clean check carries an empty reasons list, and the encoding of one is
// pinned directly: a nil slice would serialize as null and change the schema.
func TestEmptyReasonsEncodeAsArray(t *testing.T) {
	encoded, err := json.Marshal(CheckResult{ID: CheckChecksum, Reasons: []Reason{}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"id":"checksum","advisory":false,"verdict":"GO","reasons":[]}`
	if string(encoded) != want {
		t.Fatalf("encoded %s, want %s", encoded, want)
	}
}

// Dispatch is total over check ids: an id with no implementation arm is
// reported as a broken review, never as a check that found nothing.
//
// Every check the schema names now has an arm, so no spec reaches this — which
// is exactly why it is driven directly. The backstop exists for a disagreement
// between validation and the dispatcher, and a disagreement that fails closed
// is the whole point of keeping it.
func TestDispatchBackstopsAnUnimplementedCheck(t *testing.T) {
	spec := Spec{
		SpecVersion: SpecVersion,
		Subject:     Subject{Repo: "o/r", Version: "v1"},
		Artifacts:   []Artifact{{Path: "a", AssetName: "a"}},
		Checks:      &Checks{},
	}

	result := runCheck("provenance", spec, nil, CheckResult{})
	if result.Verdict != ERROR {
		t.Fatalf("verdict %s, want ERROR", result.Verdict)
	}
	if len(result.Reasons) != 1 || result.Reasons[0].Code != "check_not_implemented" {
		t.Fatalf("unexpected reasons: %+v", result.Reasons)
	}
	if !strings.Contains(result.Reasons[0].Message, `"provenance"`) {
		t.Fatalf("message %q does not name the check", result.Reasons[0].Message)
	}
}
