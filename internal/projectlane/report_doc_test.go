package projectlane

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

var reportTime = time.Date(2026, 11, 26, 4, 15, 0, 0, time.UTC)

func baseInputs(report string) ReportInputs {
	return ReportInputs{Now: reportTime, SafeVersion: "1.2.3", Verb: "install", Status: 0, Published: "tree", Ended: "none",
		LockfileDigest: "sha256:" + strings.Repeat("a", 64), Report: []byte(report)}
}

const clearReport = `{"schema_version":1,"baseline":{"source":"graph","error":""},"difference":{"added":[{"name":"a","versions":["1.0.0"]}],"removed":[],"changed":[],"introduced":[],"dropped":[]},
"advisories":{"fixed":[],"already_present":[{"name":"vuln","id":"GHSA-aaaa-bbbb-cccc","severity":"critical","exposure_changed":true}],"introduced":[]},
"malice":[],"coverage":[],"outcome":{"status":"clear","class":"","exit":0},"adverse":[]}`

func mustBuild(t *testing.T, in ReportInputs) ReportDocument {
	t.Helper()
	doc, err := BuildReportDocument(in)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalReportDocument(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckReportDocument(raw); err != nil {
		t.Fatalf("the document does not check: %v\n%s", err, raw)
	}
	return doc
}

func TestReportPassAndEnds(t *testing.T) {
	in := baseInputs(clearReport)
	in.Bind = []byte(`{"schema_version":1,"outcome":"published","exit":0}`)
	doc := mustBuild(t, in)
	if doc.End != "published" || !doc.Passed || doc.Decision.PresentBy["critical"] != 1 || !doc.Decision.AlreadyPresent[0].ExposureChanged {
		t.Fatalf("pass: %+v", doc)
	}
	// published on the binder's word, but the lane established nothing: not a pass
	in.Published = ""
	if doc := mustBuild(t, in); doc.End != "bind_unreadable" || doc.Passed {
		t.Fatalf("a publication nobody established: %+v", doc.End)
	}
	in.Published = "lockfile"
	if doc := mustBuild(t, in); doc.End != "published_lockfile" || !doc.Passed {
		t.Fatalf("lockfile-only: %s", doc.End)
	}
	for outcome, end := range map[string]string{"install_failed": "install_failed", "verification_failed": "verification_failed", "inputs_changed": "inputs_changed",
		"interrupted": "interrupted", "publication_failed": "publication_failed", "install_unsettled": "install_unsettled", "refused": "bind_refused"} {
		in := baseInputs(clearReport)
		in.Status = 31
		in.Bind = []byte(fmt.Sprintf(`{"schema_version":1,"outcome":%q,"exit":%d}`, outcome, bindOutcomes[outcome]))
		doc := mustBuild(t, in)
		if doc.End != end || doc.Passed {
			t.Errorf("%s: end %s passed %v", outcome, doc.End, doc.Passed)
		}
	}
	// a binder result that disagrees with itself is unreadable, never a pass
	in = baseInputs(clearReport)
	in.Bind = []byte(`{"schema_version":1,"outcome":"published","exit":31}`)
	if doc := mustBuild(t, in); doc.End != "bind_unreadable" || doc.Passed {
		t.Fatalf("a contradicting binder: %s", doc.End)
	}
	in.Bind = []byte(`{`)
	if doc := mustBuild(t, in); doc.End != "bind_unreadable" || doc.Passed {
		t.Fatalf("a malformed binder: %s", doc.End)
	}
}

func TestReportDeclinedAndRefusedAreNotPasses(t *testing.T) {
	stopped := `{"schema_version":1,"baseline":{"source":"graph"},"difference":{},"advisories":{"fixed":[],"already_present":[],"introduced":[{"name":"dirty","id":"GHSA-crit-0001","severity":"critical","class":"blocking","cleared":false}]},
"malice":[],"coverage":[],"outcome":{"status":"stopped","class":"blocking_advisory","exit":104}}`
	in := baseInputs(stopped)
	in.Status, in.Published, in.Asked, in.Ended = 104, "", 1, "declined"
	doc := mustBuild(t, in)
	if doc.End != "declined" || doc.Passed || doc.Status != 104 || doc.Prompts.Asked != 1 || doc.Binder != nil {
		t.Fatalf("declined: %+v", doc)
	}
	in.Ended, in.Status, in.Asked = "unread", 102, 1
	if doc := mustBuild(t, in); doc.End != "unread_answer" || doc.Passed {
		t.Fatalf("unread: %s", doc.End)
	}
	in.Ended, in.Asked, in.Status = "none", 0, 104
	if doc := mustBuild(t, in); doc.End != "refused" || doc.Passed {
		t.Fatalf("refused: %s", doc.End)
	}
	// a status of 0 with no publication is still no pass
	in = baseInputs(clearReport)
	in.Published, in.DryRun = "", true
	if doc := mustBuild(t, in); doc.End != "dry_run" || doc.Passed {
		t.Fatalf("dry run: %s", doc.End)
	}
	in.DryRun = false
	if doc := mustBuild(t, in); doc.End != "stopped" || doc.Passed {
		t.Fatalf("a clear decision that ended before the binder: %s", doc.End)
	}
}

func TestReportKeepsNoFreeTextAndNoLocation(t *testing.T) {
	hostile := `{"schema_version":1,"baseline":{"source":"graph","error":"ghp_tokenvalue in a message"},
"difference":{"added":[],"removed":[],"changed":[],"introduced":[],"dropped":[]},
"advisories":{"fixed":[{"name":"bad\u001b[31mname","id":"GHSA-x","severity":"critical"}],
 "already_present":[{"name":"ok","id":"CVE-2020-1","severity":"<script>","exposure_changed":false},{"name":"ok","id":"id with space","severity":"high"}],
 "introduced":[{"name":"https://user:pw@evil.example/x?token=abc","id":"GHSA-y","severity":"high","class":"adverse"}]},
"malice":[{"signal":"blocklist","name":"m","versions":["1.0.0","1.0.0\nx"],"id":"ID","reason":"ghp_reasontoken"},{"signal":"blocklist","name":"m","versions":["2.0.0"],"id":"ID2","reason":"free text"}],
"coverage":[{"name":"x","version":"1.0.0","sides":["target"],"gap":"registry message carrying token ghp_registrytoken"}],
"cooldown":{"days":3,"checked":2,"waits":[{"name":"w","version":"1.0.0"},{"name":"w\u0007","version":"1.0.0"}],"missing":[{"gap":"ghp_gap"}]},
"socket":{"roots":[{"name":"s","version":"1.0.0","outcome":"adverse","line":"ghp_socketline"}],"cache_gap":"ghp_cachegap"},
"adverse":[{"name":"a","version":"1.0.0","host":"registry.npmjs.org"},{"name":"a","version":"1.0.0","host":"user:pw@host/path?x=1"}],
"outcome":{"status":"stopped","class":"malice","exit":104}}`
	doc := mustBuild(t, baseInputs(hostile))
	raw, _ := MarshalReportDocument(doc)
	for _, leak := range []string{"ghp_", "evil.example", "user:pw", "token=", "\u001b", "<script>", "free text", "id with space", "/path"} {
		if strings.Contains(string(raw), leak) {
			t.Errorf("%q reached the document:\n%s", leak, raw)
		}
	}
	d := doc.Decision
	if len(d.Fixed) != 0 || len(d.IntroducedAdv) != 0 || d.AdvisoriesOther != 3 {
		t.Errorf("advisories: %+v", d)
	}
	if len(d.AlreadyPresent) != 1 || d.AlreadyPresent[0].Severity != "unknown" {
		t.Errorf("a severity outside the list is unknown: %+v", d.AlreadyPresent)
	}
	if len(d.Malice) != 1 || d.Malice[0].ID != "ID2" || d.MaliceOther != 1 {
		t.Errorf("malice: %+v", d.Malice)
	}
	if len(d.Cooldown.Waits) != 1 || d.Cooldown.Other != 1 || d.Cooldown.Missing != 1 {
		t.Errorf("cooldown: %+v", d.Cooldown)
	}
	if len(d.Adverse) != 1 || d.AdverseOther != 1 || d.Adverse[0].Host != "registry.npmjs.org" {
		t.Errorf("adverse: %+v", d.Adverse)
	}
	if len(d.Socket) != 1 || d.Socket[0].Outcome != "adverse" || d.CoverageGaps != 1 {
		t.Errorf("socket/coverage: %+v", d)
	}
}

func TestReportScriptsAndScanAreSummariesOfTheirOwnGrammar(t *testing.T) {
	in := baseInputs(clearReport)
	in.Scripts = []byte(`{"schema_version":3,"source":"tree","previous":"read","total":2,"packages":[
 {"path":"node_modules/a","name":"a","version":"1.0.0","rebuild_path":"node_modules/a","events":["postinstall"],"gyp":false,"declared":true},
 {"path":"node_modules/b\u001b","name":"b\u001b","version":"1.0.0","rebuild_path":"x","events":["postinstall"],"gyp":false,"declared":true},
 {"path":"node_modules/c","name":"c","version":"1.0.0","rebuild_path":"x","events":["curl | sh"],"gyp":false,"declared":true},
 {"path":"node_modules/d/node_modules/e","name":"e","version":"1.0.0","host":"d@1.0.0","rebuild_path":"node_modules/d","events":[],"gyp":true,"declared":false}],
 "unread_total":1,"unread":[{"path":"p","name":"u","version":"1.0.0","rebuild_path":"p","events":[],"gyp":false,"declared":false}],"root":{"events":["prepare"],"gyp":false}}`)
	in.Scan = []byte(`{"status":"completed","reason":"","summary":{"schema_version":1,"critical_total":4,"critical":{"npm":2,"mystery":1},"unattributed":1,"coverage_failures":["syft","bad name\u001b"],"coverage_other":0},
 "lockfile_sha256":"sha256:` + strings.Repeat("b", 64) + `","lockfile_stable":true}`)
	doc := mustBuild(t, in)
	raw, _ := MarshalReportDocument(doc)
	if strings.Contains(string(raw), "node_modules") || strings.Contains(string(raw), "curl") || strings.Contains(string(raw), "\u001b") || strings.Contains(string(raw), "mystery") {
		t.Fatalf("what is not an identity or a closed word reached the document:\n%s", raw)
	}
	s := doc.Scripts
	if len(s.Packages) != 2 || s.Other != 2 || s.Packages[1].Host != "d@1.0.0" || s.Root == nil || len(s.Unread) != 1 {
		t.Errorf("scripts: %+v", s)
	}
	sc := doc.Scan
	if sc.Summary.Critical["npm"] != 2 || sc.Summary.Unattributed != 2 || len(sc.Summary.CoverageFailures) != 1 || sc.Summary.CoverageOther != 1 {
		t.Errorf("scan: %+v", sc.Summary)
	}
	// a scan piece that is not a summary of this schema is absent, not half a summary
	in.Scan = []byte(`{"status":"completed","reason":"","summary":null,"lockfile_sha256":"x","lockfile_stable":true}`)
	if doc := mustBuild(t, in); doc.Scan != nil {
		t.Errorf("a malformed scan summary was kept: %+v", doc.Scan)
	}
}

func TestReportCiKeepsCountsAndTheDigestNotTheEntries(t *testing.T) {
	var entries []string
	for i := 0; i < 1000; i++ {
		entries = append(entries, fmt.Sprintf(`{"name":"pkg-%d","versions":["1.0.%d"]}`, i, i))
	}
	report := `{"schema_version":1,"baseline":{"source":"graph"},"difference":{"added":[` + strings.Join(entries, ",") + `],"removed":[],"changed":[],"introduced":[],"dropped":[]},
"advisories":{"fixed":[],"already_present":[],"introduced":[]},"malice":[],"coverage":[],"outcome":{"status":"clear","class":"","exit":0}}`
	in := baseInputs(report)
	in.Verb = "ci"
	doc := mustBuild(t, in)
	raw, _ := MarshalReportDocument(doc)
	if doc.Decision.Added != 1000 || strings.Contains(string(raw), "pkg-5") || doc.LockfileSHA256 != in.LockfileDigest || len(raw) > 4096 {
		t.Fatalf("ci: added %d, %d bytes", doc.Decision.Added, len(raw))
	}
}

// The bound on one document, from a measure: a 1000-entry install with an advisory on every entry.
func TestReportBoundIsFarAboveTheLargestDocumentMeasured(t *testing.T) {
	var present []string
	for i := 0; i < 1000; i++ {
		present = append(present, fmt.Sprintf(`{"name":"package-with-a-long-name-%d","id":"GHSA-%04d-abcd-efgh","severity":"high","exposure_changed":true}`, i, i))
	}
	report := `{"schema_version":1,"baseline":{"source":"graph"},"difference":{"added":[],"removed":[],"changed":[],"introduced":[],"dropped":[]},
"advisories":{"fixed":[],"already_present":[` + strings.Join(present, ",") + `],"introduced":[]},"malice":[],"coverage":[],"outcome":{"status":"clear","class":"","exit":0}}`
	doc := mustBuild(t, baseInputs(report))
	raw, _ := MarshalReportDocument(doc)
	t.Logf("a document with 1000 advisories: %d bytes (bound %d)", len(raw), MaxReportBytes)
	if len(raw) > MaxReportBytes/3 {
		t.Fatalf("the bound is not far above what was measured: %d bytes", len(raw))
	}
}

func TestReportCheckRefusesWhatIsNotTheCanonicalDocument(t *testing.T) {
	in := baseInputs(clearReport)
	in.Bind = []byte(`{"schema_version":1,"outcome":"published","exit":0}`)
	doc := mustBuild(t, in)
	raw, _ := MarshalReportDocument(doc)
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	mutate := func(f func(m map[string]any)) []byte {
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		f(m)
		out, _ := json.MarshalIndent(m, "", "  ")
		return append(out, '\n')
	}
	for name, doc := range map[string][]byte{
		"an extra member":    mutate(func(m map[string]any) { m["project_key"] = "abc" }),
		"an unknown end":     mutate(func(m map[string]any) { m["end"] = "fine" }),
		"a pass that is not": mutate(func(m map[string]any) { m["end"] = "declined" }),
		"a free-text verb":   mutate(func(m map[string]any) { m["command"].(map[string]any)["verb"] = "install; rm" }),
		"a repeated member":  []byte(strings.Replace(string(raw), `"status": 0,`, `"status": 0, "status": 1,`, 1)),
		"two documents":      append(append([]byte{}, raw...), raw...),
		"not the canon form": []byte(strings.ReplaceAll(string(raw), "  ", "\t")),
		"a longer digest":    mutate(func(m map[string]any) { m["lockfile_sha256"] = "sha256:" + strings.Repeat("a", 65) }),
	} {
		if err := CheckReportDocument(doc); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestReportPassNeedsStatusZeroAndADecisionNeedsToBeOne(t *testing.T) {
	in := baseInputs(clearReport)
	in.Bind = []byte(`{"schema_version":1,"outcome":"published","exit":0}`)
	in.Status = 3
	if doc := mustBuild(t, in); doc.End != "published" || doc.Passed {
		t.Fatalf("a publication with a status of 3 is a pass: %+v", doc.End)
	}
	for name, report := range map[string]string{"empty": `{}`, "not json": `{`, "another schema": `{"schema_version":2,"outcome":{"status":"clear"}}`,
		"no outcome": `{"schema_version":1}`, "an outcome outside the list": `{"schema_version":1,"outcome":{"status":"fine"}}`} {
		in := baseInputs(report)
		if _, err := BuildReportDocument(in); err != ErrNoDecision {
			t.Errorf("%s: %v", name, err)
		}
	}
	// a signal that ended the command before the binder reported is its own end, whatever else the pieces say
	for _, bind := range []string{"", `{`} {
		in := baseInputs(clearReport)
		in.Status, in.Published = 143, ""
		if bind != "" {
			in.Bind = []byte(bind)
		}
		if doc := mustBuild(t, in); doc.End != "interrupted" || doc.Passed {
			t.Errorf("bind %q: %s", bind, doc.End)
		}
	}
}
