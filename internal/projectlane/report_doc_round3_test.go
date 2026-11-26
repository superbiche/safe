package projectlane

import (
	"strings"
	"testing"
)

// Two hosts bundle the same member: the rows say which artifact supplies each, and the dropped artifacts are counted.
func TestReportABundledMembersRowNamesWhatSuppliesItsBytes(t *testing.T) {
	report := `{"schema_version":1,"baseline":{"source":"graph"},"difference":{"added":[],"removed":[],"changed":[],"dropped":[{"name":"old","version":"1.0.0","origin":"","integrity":""},{"name":"older","version":"1.0.0","origin":"","integrity":""}],
 "introduced":[{"name":"member","version":"1.0.0","origin":"","integrity":"","covered_by":"alpha@2.0.0` + "\\u0000https://registry.npmjs.org/alpha/-/alpha-2.0.0.tgz\\u0000sha512-a" + `","reason":"covering_changed"},
               {"name":"member","version":"1.0.0","origin":"","integrity":"","covered_by":"beta@2.0.0` + "\\u0000https://registry.npmjs.org/beta/-/beta-2.0.0.tgz\\u0000sha512-b" + `","reason":"covering_changed"},
               {"name":"odd","version":"1.0.0","origin":"","integrity":"","covered_by":"not a package","reason":"covering_changed"}]},
"advisories":{"fixed":[],"already_present":[],"introduced":[]},"malice":[],"coverage":[],"outcome":{"status":"clear","class":"","exit":0}}`
	doc := mustBuild(t, baseInputs(report))
	d := doc.Decision.Difference
	if len(d.Introduced) != 2 || d.Introduced[0].CoveredBy != "alpha@2.0.0" || d.Introduced[1].CoveredBy != "beta@2.0.0" || d.Other != 1 || d.DroppedCount != 2 || d.IntroducedCount != 3 {
		t.Fatalf("%+v", d)
	}
	raw, _ := MarshalReportDocument(doc)
	if strings.Contains(string(raw), "sha512") || strings.Contains(string(raw), "https://") {
		t.Fatalf("an integrity or a location reached the document: %s", raw)
	}
}

// A waiver keeps the advisories it remediates and its date; a wait keeps them too.
func TestReportAWaiverKeepsItsAdvisoriesAndItsDate(t *testing.T) {
	report := `{"schema_version":1,"baseline":{"source":"graph"},"difference":{},"advisories":{"fixed":[],"already_present":[],"introduced":[]},"malice":[],"coverage":[],
"cooldown":{"days":3,"security_fix":"enforce","checked":2,"waits":[{"name":"w","version":"1.0.0","published":"2026-11-25T01:02:03Z","installable":"2026-11-28T01:02:03Z","root":true,"remediates":["GHSA-aaaa-0001"],"enforced":true}],
            "waived":[{"name":"fix","version":"2.0.0","published":"2026-11-24T00:00:00Z","remediates":["GHSA-bbbb-0002","CVE-2026-1"]},{"name":"bad","version":"2.0.0","published":"2026-11-24T00:00:00Z","remediates":["not an id"]}],"missing":[]},
"outcome":{"status":"clear","class":"","exit":0}}`
	doc := mustBuild(t, baseInputs(report))
	c := doc.Decision.Cooldown
	if len(c.Waived) != 1 || c.Waived[0].Published != "2026-11-24T00:00:00Z" || strings.Join(c.Waived[0].Remediates, ",") != "GHSA-bbbb-0002,CVE-2026-1" || c.Other != 1 {
		t.Fatalf("waived: %+v other %d", c.Waived, c.Other)
	}
	if len(c.Waits) != 1 || c.Waits[0].Remediates[0] != "GHSA-aaaa-0001" {
		t.Fatalf("waits: %+v", c.Waits)
	}
}

func TestReportASkippedCooldownReadingIsSaidAsSuch(t *testing.T) {
	report := strings.Replace(clearReport, `"coverage":[]`, `"coverage":[],"cooldown":{"days":3,"security_fix":"exempt","checked":0,"waits":[],"waived":[],"missing":[],"skipped":2}`, 1)
	doc := mustBuild(t, baseInputs(report))
	if c := doc.Decision.Cooldown; c.Skipped != 2 || c.Checked != 0 || c.Missing != 0 {
		t.Fatalf("%+v", c)
	}
}

// A piece that could not be read is named, and what came from it is not a value: null, never zero.
func TestReportALostPieceIsNamedAndItsCountIsNotZero(t *testing.T) {
	in := baseInputs(clearReport)
	in.Expected = []byte("bind\nscripts\nscan\n")
	in.Graph = []byte(`{`)
	in.Judged = nil
	in.Scripts, in.Scan = nil, nil
	doc := mustBuild(t, in)
	if doc.Decision.Entries != nil || doc.Scripts != nil || doc.Scan != nil || strings.Join(doc.PiecesUnread, ",") != "graph,judged,scan,scripts" {
		t.Fatalf("entries %v scripts %v scan %v unread %v", doc.Decision.Entries, doc.Scripts, doc.Scan, doc.PiecesUnread)
	}
	// the same pieces, not expected (a command that never got to them) and not there: nothing is lost
	in = baseInputs(clearReport)
	in.Graph = []byte(`{"graph":{"occurrences":[]}}`)
	in.Scripts, in.Scan = nil, nil
	doc = mustBuild(t, in)
	if doc.Decision.Entries == nil || *doc.Decision.Entries != 0 || len(doc.PiecesUnread) != 0 {
		t.Fatalf("an empty graph is zero entries, and nothing is unread: %v %v", doc.Decision.Entries, doc.PiecesUnread)
	}
	// a graph that holds no occurrences member is not an empty graph
	in.Graph = []byte(`{"graph":{}}`)
	if doc := mustBuild(t, in); doc.Decision.Entries != nil {
		t.Fatalf("a graph without occurrences read as zero")
	}
}

// A binder piece lost after a publication the lane established still gives a document, and says so.
func TestReportALostBinderPieceAfterAPublicationStillGivesADocument(t *testing.T) {
	in := baseInputs(clearReport)
	in.Bind = nil
	in.Expected = []byte("bind\n")
	doc := mustBuild(t, in)
	if doc.End != "published" || !doc.Passed || doc.Binder == nil || doc.Binder.Outcome != "unreadable" || strings.Join(doc.PiecesUnread, ",") != "binder" {
		t.Fatalf("%s %v %+v %v", doc.End, doc.Passed, doc.Binder, doc.PiecesUnread)
	}
	// without the lane's own word that it published, the lost piece is no publication
	in.Published, in.Status = "", 1
	if doc := mustBuild(t, in); doc.End != "bind_unreadable" || doc.Passed {
		t.Fatalf("%s", doc.End)
	}
}

// A signal on a dry run after the decision is an interruption, not a refusal.
func TestReportASignalOnADryRunIsAnInterruption(t *testing.T) {
	for _, status := range []int{129, 130, 143} {
		in := baseInputs(clearReport)
		in.DryRun, in.Published, in.Bind, in.Status = true, "", nil, status
		if doc := mustBuild(t, in); doc.End != "interrupted" || doc.Passed {
			t.Errorf("%d: %s", status, doc.End)
		}
	}
}

// A scan that was stopped by a signal is a scan that did not complete for a reason of its own.
func TestReportAScanInterruptedByASignalHasItsOwnReason(t *testing.T) {
	in := baseInputs(clearReport)
	in.Status = 143
	in.Scan = []byte(`{"status":"not_completed","reason":"interrupted","summary":null,"lockfile_published":true}`)
	doc := mustBuild(t, in)
	if doc.Scan == nil || doc.Scan.Status != "not_completed" || doc.Scan.Reason != "interrupted" || doc.End != "interrupted" {
		t.Fatalf("%+v %s", doc.Scan, doc.End)
	}
	in.Scan = []byte(`{"status":"not_completed","reason":"made up","summary":null,"lockfile_published":true}`)
	if doc := mustBuild(t, in); doc.Scan != nil {
		t.Fatalf("a reason outside the list was kept")
	}
}
