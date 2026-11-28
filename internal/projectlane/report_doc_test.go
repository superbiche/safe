package projectlane

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

var reportTime = time.Date(2026, 11, 26, 4, 15, 0, 0, time.UTC)

const judgedPiece = `{"target":"sha256:` + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + `","baseline":"sha256:` + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" + `"}`

func baseInputs(report string) ReportInputs {
	return ReportInputs{Now: reportTime, SafeVersion: "1.2.3", Verb: "install", Status: 0, Published: "tree", Report: []byte(report), Judged: []byte(judgedPiece), Graph: []byte(`{"graph":{"occurrences":[{},{}]}}`),
		Bind: []byte(`{"schema_version":1,"outcome":"published","exit":0}`)}
}

const clearReport = `{"schema_version":1,"baseline":{"source":"graph","error":""},"difference":{"added":[{"name":"a","versions":["1.0.0"]}],"removed":[{"name":"gone","versions":["2.0.0"]}],
"changed":[{"name":"c","before":["1.0.0"],"after":["1.1.0"]}],"introduced":[{"name":"a","version":"1.0.0","origin":"https://registry.npmjs.org/a/-/a-1.0.0.tgz","integrity":"sha512-x","reason":"new"}],"dropped":[]},
"advisories":{"fixed":[],"already_present":[{"name":"vuln","id":"GHSA-aaaa-bbbb-cccc","severity":"critical","exposure_changed":true}],"introduced":[]},
"malice":[],"coverage":[],"classes":[{"class":"malice","exit":104,"at_stake":0,"outstanding":0}],"outcome":{"status":"clear","class":"","exit":0},"adverse":[]}`

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
	// the digests are the judged ones, from the piece, never from anywhere else
	if doc.Lockfiles.TargetSHA256 != "sha256:"+strings.Repeat("a", 64) || doc.Lockfiles.BaselineSHA256 != "sha256:"+strings.Repeat("b", 64) {
		t.Fatalf("digests: %+v", doc.Lockfiles)
	}
	in.Judged = nil
	if doc := mustBuild(t, in); doc.Lockfiles.TargetSHA256 != "unreadable" || doc.Lockfiles.BaselineSHA256 != "unreadable" {
		t.Fatalf("a digest nobody took is unreadable, not a guess: %+v", doc.Lockfiles)
	}
	in.Judged = []byte(judgedPiece)
	// published on the binder's word, but the lane established nothing: not a pass
	in.Published, in.Status = "", 1
	if doc := mustBuild(t, in); doc.End != "bind_unreadable" || doc.Passed {
		t.Fatalf("a publication nobody established: %+v", doc.End)
	}
	in.Published, in.Status = "lockfile", 0
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
	in.Status = 1
	in.Bind = []byte(`{"schema_version":1,"outcome":"published","exit":31}`)
	if doc := mustBuild(t, in); doc.End != "bind_unreadable" || doc.Passed {
		t.Fatalf("a contradicting binder: %s", doc.End)
	}
	in.Bind = []byte(`{`)
	if doc := mustBuild(t, in); doc.End != "bind_unreadable" || doc.Passed {
		t.Fatalf("a malformed binder: %s", doc.End)
	}
}

// An end that reads as a pass exists only with status 0 (the validation holds it, and so does the building); a dry run that ends in a
// refusal is a refusal.
func TestReportAPassEndNeedsStatusZeroAndNoOtherEndHasIt(t *testing.T) {
	in := baseInputs(clearReport)
	in.DryRun, in.Published, in.Status, in.Bind = true, "", 100, nil
	if doc := mustBuild(t, in); doc.End != "refused" || doc.Passed {
		t.Fatalf("a dry run refused late: %s", doc.End)
	}
	in.Status = 0
	if doc := mustBuild(t, in); doc.End != "dry_run" || doc.Passed {
		t.Fatalf("a clean dry run: %s", doc.End)
	}
	in = baseInputs(clearReport)
	in.Bind = []byte(`{"schema_version":1,"outcome":"published","exit":0}`)
	in.Status = 3
	if doc := mustBuild(t, in); doc.End != "stopped" || doc.Passed {
		t.Fatalf("a publication with a status of 3: %s", doc.End)
	}
	good := mustBuild(t, baseInputs(clearReport))
	for name, mutate := range map[string]func(d *ReportDocument){
		"a dry run with a status":       func(d *ReportDocument) { d.End, d.Status = "dry_run", 100 },
		"a published end with a status": func(d *ReportDocument) { d.End, d.Status, d.Passed = "published", 1, false },
		"a refusal with status 0":       func(d *ReportDocument) { d.End, d.Status, d.Passed = "refused", 0, false },
		"a declined end with status 0":  func(d *ReportDocument) { d.End, d.Status, d.Passed = "declined", 0, false },
	} {
		d := good
		mutate(&d)
		if ValidateReportDocument(d) == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	// the public status: the reserved status is the caller's to normalise before it writes; a status above 255 is no status
	in = baseInputs(clearReport)
	in.Status = 253
	if doc, err := BuildReportDocument(in); err == nil && doc.Status == 253 && doc.End == "dry_run" {
		t.Fatalf("253 read as a pass")
	}
}

func TestReportPromptsAreClassesAndHowTheyEnded(t *testing.T) {
	stopped := `{"schema_version":1,"baseline":{"source":"graph"},"difference":{},"advisories":{"fixed":[],"already_present":[],"introduced":[{"name":"dirty","id":"GHSA-crit-0001","severity":"critical","class":"blocking","cleared":false}]},
"malice":[],"coverage":[],"outcome":{"status":"stopped","class":"blocking_advisory","exit":104}}`
	in := baseInputs(stopped)
	in.Status, in.Published, in.Bind = 104, "", nil
	in.Prompts = []byte("blocking_advisory\tdeclined\n")
	doc := mustBuild(t, in)
	if doc.End != "declined" || doc.Passed || doc.Status != 104 || len(doc.Prompts) != 1 || doc.Prompts[0] != (ReportPrompt{"blocking_advisory", "declined"}) || doc.Binder != nil {
		t.Fatalf("declined: %+v", doc)
	}
	in.Prompts = []byte("malice\taccepted\nmissing_evidence\taccepted\nsocket_root\tunread\nnot_a_class\taccepted\nmalice\tmaybe\n")
	in.Status = 102
	doc = mustBuild(t, in)
	if doc.End != "unread_answer" || len(doc.Prompts) != 3 || doc.Prompts[0].Class != "malice" || doc.Prompts[1].Class != "missing_evidence" {
		t.Fatalf("answers by class: %+v end %s", doc.Prompts, doc.End)
	}
	in.Prompts, in.Status = nil, 104
	if doc := mustBuild(t, in); doc.End != "refused" || doc.Passed || len(doc.Prompts) != 0 {
		t.Fatalf("refused: %s", doc.End)
	}
	in = baseInputs(clearReport)
	in.Published, in.DryRun, in.Bind = "", true, nil
	if doc := mustBuild(t, in); doc.End != "dry_run" || doc.Passed {
		t.Fatalf("dry run: %s", doc.End)
	}
	in.DryRun = false
	in.Status = 1
	if doc := mustBuild(t, in); doc.End != "stopped" {
		t.Fatalf("a clear decision that ended before the binder: %s", doc.End)
	}
}

func TestReportKeepsTheJudgedEvidenceAsTypedValues(t *testing.T) {
	report := `{"schema_version":1,"baseline":{"source":"graph","error":""},
"difference":{"added":[{"name":"new","versions":["1.0.0"]}],"removed":[{"name":"old","versions":["0.9.0"]}],"changed":[{"name":"c","before":["1.0.0"],"after":["2.0.0","2.0.1"]}],
 "introduced":[{"name":"new","version":"1.0.0","origin":"https://user:pw@registry.npmjs.org:443/new/-/new-1.0.0.tgz?token=abc#frag","integrity":"sha512-x","reason":"new"},
               {"name":"mirror","version":"1.0.0","origin":"https://mirror.example/mirror/-/mirror-1.0.0.tgz","integrity":"sha512-y","reason":"origin_changed"},
               {"name":"odd","version":"1.0.0","origin":"https://x.example/","integrity":"","reason":"anything we like"}],"dropped":[]},
"advisories":{"fixed":[{"name":"f","id":"GHSA-fixd-0000-0001","severity":"high","versions":["1.0.0"]}],"already_present":[],"introduced":[{"name":"new","id":"GHSA-high-0001","severity":"high","class":"adverse","cleared":true}]},
"malice":[{"signal":"socket_block","name":"blocked","versions":["1.0.0"],"id":"SOCKET-1","overridden":false}],
"coverage":[{"name":"p","version":"1.0.0","sides":["target"],"gap":"free text ghp_x","cause":"advisory_reading"},{"name":"q","version":"2.0.0","sides":["baseline","target"],"gap":"x","cause":"advisory_reading"},
            {"name":"","version":"","sides":["target"],"gap":"y","cause":"socket_cache"},{"name":"r","version":"1.0.0","sides":["target"],"gap":"z","cause":"publish_time"},
            {"name":"s","version":"1.0.0","sides":["target"],"gap":"z","cause":"invented"}],
"cooldown":{"days":3,"security_fix":"exempt","checked":4,"waits":[{"name":"young","version":"1.2.3","published":"2026-11-25T01:02:03.456789Z","age_days":1,"installable":"2026-11-28T01:02:03Z","root":true,"bounded":false,"cleared":false}],
            "waived":[{"name":"fix","version":"2.0.0","published":"2026-11-24T00:00:00Z","age_days":2,"remediates":["GHSA-fix"]}],"missing":[{"name":"m","version":"1.0.0","gap":"ghp_t"}]},
"socket":{"roots":[{"name":"blocked","version":"1.0.0","outcome":"blocked","exit":20,"line":"ghp_line","cached":false,"cleared":false},{"name":"ok","version":"1.0.0","outcome":"clear","exit":0,"line":"","cached":true,"cleared":true},
                   {"name":"weird","version":"1.0.0","outcome":"shrug","exit":0,"line":"","cached":false,"cleared":false}],"cache_gap":"ghp_gap"},
"classes":[{"class":"malice","exit":104,"at_stake":1,"outstanding":1},{"class":"wait","exit":102,"at_stake":1,"outstanding":1},{"class":"socket_root","exit":102,"at_stake":1,"outstanding":1},{"class":"bogus","exit":1,"at_stake":1,"outstanding":1}],
"outcome":{"status":"stopped","class":"malice","exit":104},"adverse":[{"name":"new","version":"1.0.0","host":"registry.npmjs.org"}]}`
	in := baseInputs(report)
	in.Status, in.Published, in.Bind = 104, "", nil
	doc := mustBuild(t, in)
	raw, _ := MarshalReportDocument(doc)
	for _, leak := range []string{"ghp_", "user:pw", "token=", "frag", ":443", "free text", "https://", "anything we like"} {
		if strings.Contains(string(raw), leak) {
			t.Errorf("%q reached the document:\n%s", leak, raw)
		}
	}
	d := doc.Decision
	if len(d.Difference.Added) != 1 || d.Difference.Added[0].Name != "new" || len(d.Difference.Removed) != 1 || len(d.Difference.Changed) != 1 || d.Difference.Changed[0].After[1] != "2.0.1" {
		t.Errorf("the differential's identities: %+v", d.Difference)
	}
	if len(d.Difference.Introduced) != 2 || d.Difference.Introduced[0].Host != "registry.npmjs.org" || d.Difference.Introduced[1].Host != "mirror.example" || d.Difference.Other != 1 || d.Difference.IntroducedCount != 3 {
		t.Errorf("introduced: %+v", d.Difference)
	}
	if len(d.Fixed) != 1 || len(d.IntroducedAdv) != 1 || !d.IntroducedAdv[0].Cleared {
		t.Errorf("advisories: %+v", d)
	}
	if len(d.Classes) != 3 || d.Classes[1].Class != "wait" {
		t.Errorf("classes: %+v", d.Classes)
	}
	if len(d.Cooldown.Waits) != 1 || d.Cooldown.Waits[0].Published != "2026-11-25T01:02:03.456789Z" || d.Cooldown.Waits[0].Installable != "2026-11-28T01:02:03Z" || !d.Cooldown.Waits[0].Root ||
		len(d.Cooldown.Waived) != 1 || d.Cooldown.Waived[0].Name != "fix" || d.Cooldown.Missing != 1 || d.Cooldown.SecurityFix != "exempt" {
		t.Errorf("cooldown: %+v", d.Cooldown)
	}
	// a Socket block on a named root is in the document as one
	if len(d.Socket) != 2 || d.Socket[0].Outcome != "blocked" || d.Socket[1].Outcome != "clear" || d.SocketOther != 1 {
		t.Errorf("socket: %+v other %d", d.Socket, d.SocketOther)
	}
	if len(d.Malice) != 1 || d.Malice[0].Signal != "socket_block" {
		t.Errorf("malice: %+v", d.Malice)
	}
	// coverage: per cause, a count and the first identities
	if d.Coverage.Gaps != 5 || d.Coverage.Other != 1 || len(d.Coverage.Causes) != 3 {
		t.Fatalf("coverage: %+v", d.Coverage)
	}
	for _, c := range d.Coverage.Causes {
		switch c.Cause {
		case "advisory_reading":
			if c.Count != 2 || len(c.First) != 2 || c.First[1].Sides[0] != "baseline" {
				t.Errorf("advisory reading: %+v", c)
			}
		case "socket_cache":
			if c.Count != 1 || c.First[0].Name != "" {
				t.Errorf("socket cache: %+v", c)
			}
		}
	}
	// the first identities are bounded, the count is not
	var gaps []string
	for i := 0; i < 12; i++ {
		gaps = append(gaps, fmt.Sprintf(`{"name":"p%d","version":"1.0.0","sides":["target"],"gap":"x","cause":"advisory_reading"}`, i))
	}
	many := strings.Replace(clearReport, `"coverage":[]`, `"coverage":[`+strings.Join(gaps, ",")+`]`, 1)
	doc = mustBuild(t, baseInputs(many))
	if c := doc.Decision.Coverage.Causes[0]; c.Count != 12 || len(c.First) != maxFirstGaps {
		t.Errorf("first identities: %+v", c)
	}
}

func TestReportScriptsAreOneReadingAndKeepWhatTheLaneAdmitted(t *testing.T) {
	long := "1.0.0-" + strings.Repeat("a", 65)
	in := baseInputs(clearReport)
	in.Scripts = []byte(`{"schema_version":3,"source":"tree","previous":"read","total":3,"packages":[
 {"path":"node_modules/a","name":"a","version":"1.0.0","rebuild_path":"node_modules/a","events":["postinstall"],"gyp":false,"declared":true},
 {"path":"node_modules/long","name":"long","version":"` + long + `","rebuild_path":"node_modules/long","events":["install"],"gyp":false,"declared":true},
 {"path":"node_modules/b\u001b","name":"b\u001b","version":"1.0.0","rebuild_path":"x","events":["postinstall"],"gyp":false,"declared":true},
 {"path":"node_modules/c","name":"c","version":"1.0.0","rebuild_path":"x","events":["curl | sh"],"gyp":false,"declared":true},
 {"path":"node_modules/d/node_modules/e","name":"e","version":"1.0.0","host":"d@1.0.0","rebuild_path":"node_modules/d","events":[],"gyp":true,"declared":false}],
 "unread_total":1,"unread":[{"path":"p","name":"u","version":"1.0.0","rebuild_path":"p","events":[],"gyp":false,"declared":false}],"root":{"events":["prepare"],"gyp":false}}`)
	doc := mustBuild(t, in)
	raw, _ := MarshalReportDocument(doc)
	if strings.Contains(string(raw), "node_modules") || strings.Contains(string(raw), "curl") || strings.Contains(string(raw), "\u001b") {
		t.Fatalf("what is not an identity or a closed word reached the document:\n%s", raw)
	}
	s := doc.Scripts
	if len(s.Packages) != 3 || s.Packages[1].Version != long || s.Other != 2 || s.Packages[2].Host != "d@1.0.0" || s.Root == nil || len(s.Unread) != 1 {
		t.Errorf("scripts: %+v", s)
	}
}

func TestReportScanIsASummaryOfItsOwnGrammar(t *testing.T) {
	in := baseInputs(clearReport)
	in.Scan = []byte(`{"status":"completed","reason":"","summary":{"schema_version":1,"critical_total":4,"critical":{"npm":2,"mystery":1},"unattributed":1,
 "coverage_gaps":[{"scanner":"syft","status":"skipped"},{"scanner":"bad name\u001b","status":"skipped"},{"scanner":"osv-scanner","status":"fine"}],"coverage_other":0,"coverage_unreadable":true},"lockfile_published":false}`)
	doc := mustBuild(t, in)
	raw, _ := MarshalReportDocument(doc)
	if strings.Contains(string(raw), "mystery") || strings.Contains(string(raw), "\u001b") || strings.Contains(string(raw), "fine") {
		t.Fatalf("what is not in the known set reached the document:\n%s", raw)
	}
	sc := doc.Scan
	if sc.Summary.Critical["npm"] != 2 || sc.Summary.Unattributed != 2 || len(sc.Summary.CoverageGaps) != 1 || sc.Summary.CoverageOther != 2 || !sc.Summary.CoverageUnreadable || sc.LockfilePublished {
		t.Errorf("scan: %+v %+v", sc, sc.Summary)
	}
	// a scan piece that is not a summary of this schema is absent, not half a summary
	in.Scan = []byte(`{"status":"completed","reason":"","summary":null,"lockfile_published":true}`)
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
	if doc.Decision.Difference.AddedCount != 1000 || doc.Decision.Difference.Listed || strings.Contains(string(raw), "pkg-5") || doc.Lockfiles.TargetSHA256 == "unreadable" || len(raw) > 4096 {
		t.Fatalf("ci: %+v, %d bytes", doc.Decision.Difference, len(raw))
	}
	in.Verb = "install"
	if doc := mustBuild(t, in); !doc.Decision.Difference.Listed || len(doc.Decision.Difference.Added) != 1000 {
		t.Fatalf("an install lists what it adds")
	}
}

// The bound on one document, from a measure: a command that introduces 1000 packages, each with an advisory, a cooldown wait and a
// script, as the largest document the lane is expected to write.
func TestReportBoundIsFarAboveTheLargestDocumentMeasured(t *testing.T) {
	var added, introduced, present, waits, packages []string
	for i := 0; i < 1000; i++ {
		name := fmt.Sprintf("package-with-a-long-name-%d", i)
		added = append(added, fmt.Sprintf(`{"name":%q,"versions":["1.0.%d"]}`, name, i))
		introduced = append(introduced, fmt.Sprintf(`{"name":%q,"version":"1.0.%d","origin":"https://registry.npmjs.org/%s/-/x.tgz","integrity":"sha512-x","reason":"new"}`, name, i, name))
		present = append(present, fmt.Sprintf(`{"name":%q,"id":"GHSA-%04d-abcd-efgh","severity":"high","exposure_changed":true}`, name, i))
		waits = append(waits, fmt.Sprintf(`{"name":%q,"version":"1.0.%d","published":"2026-11-25T01:02:03.123456789Z","installable":"2026-11-28T01:02:03Z","root":false,"bounded":false,"cleared":false}`, name, i))
		packages = append(packages, fmt.Sprintf(`{"path":"node_modules/%s","name":%q,"version":"1.0.%d","rebuild_path":"node_modules/%s","events":["preinstall","install","postinstall"],"gyp":true,"declared":true}`, name, name, i, name))
	}
	report := `{"schema_version":1,"baseline":{"source":"graph"},"difference":{"added":[` + strings.Join(added, ",") + `],"removed":[],"changed":[],"introduced":[` + strings.Join(introduced, ",") +
		`],"dropped":[]},"advisories":{"fixed":[],"already_present":[` + strings.Join(present, ",") + `],"introduced":[]},"malice":[],"coverage":[],` +
		`"cooldown":{"days":3,"security_fix":"exempt","checked":1000,"waits":[` + strings.Join(waits, ",") + `],"waived":[],"missing":[]},"outcome":{"status":"clear","class":"","exit":0}}`
	in := baseInputs(report)
	in.Scripts = []byte(`{"schema_version":3,"source":"tree","previous":"none","total":1000,"packages":[` + strings.Join(packages, ",") + `],"unread_total":0,"unread":[]}`)
	doc := mustBuild(t, in)
	raw, _ := MarshalReportDocument(doc)
	t.Logf("a document that introduces 1000 packages, each with an advisory, a wait and scripts: %d bytes (bound %d)", len(raw), MaxReportBytes)
	if len(raw) > MaxReportBytes/8 {
		t.Fatalf("the bound is not far above what was measured: %d bytes", len(raw))
	}
}

func TestReportCheckRefusesWhatIsNotTheCanonicalDocument(t *testing.T) {
	in := baseInputs(clearReport)
	in.Bind = []byte(`{"schema_version":1,"outcome":"published","exit":0}`)
	doc := mustBuild(t, in)
	raw, _ := MarshalReportDocument(doc)
	mutate := func(f func(m map[string]any)) []byte {
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		f(m)
		out, _ := json.Marshal(m)
		return append(out, '\n')
	}
	for name, doc := range map[string][]byte{
		"an extra member":    mutate(func(m map[string]any) { m["project_key"] = "abc" }),
		"an unknown end":     mutate(func(m map[string]any) { m["end"] = "fine" }),
		"a pass that is not": mutate(func(m map[string]any) { m["end"] = "declined" }),
		"a free-text verb":   mutate(func(m map[string]any) { m["command"].(map[string]any)["verb"] = "install; rm" }),
		"a repeated member":  []byte(strings.Replace(string(raw), `"status":0,`, `"status":0,"status":1,`, 1)),
		"two documents":      append(append([]byte{}, raw...), raw...),
		"not the canon form": []byte(strings.Replace(string(raw), `{"schema_version"`, "{ \"schema_version\"", 1)),
		"a longer digest": mutate(func(m map[string]any) {
			m["lockfiles"].(map[string]any)["target_sha256"] = "sha256:" + strings.Repeat("a", 65)
		}),
	} {
		if err := CheckReportDocument(doc); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// A signal that came in after the publication, while the scan ran, ends the command with the signal: the document says interrupted.
func TestReportASignalAfterThePublicationIsAnInterruption(t *testing.T) {
	in := baseInputs(clearReport)
	in.Status = 143
	if doc := mustBuild(t, in); doc.End != "interrupted" || doc.Passed || doc.Binder == nil || doc.Binder.Outcome != "published" {
		t.Fatalf("%s %v", doc.End, doc.Passed)
	}
}

func TestReportADecisionThatIsNotOneIsNoDecision(t *testing.T) {
	for name, report := range map[string]string{"empty": `{}`, "not json": `{`, "another schema": `{"schema_version":2,"outcome":{"status":"clear"}}`,
		"no outcome": `{"schema_version":1}`, "an outcome outside the list": `{"schema_version":1,"outcome":{"status":"fine"}}`} {
		if _, err := BuildReportDocument(baseInputs(report)); err != ErrNoDecision {
			t.Errorf("%s: %v", name, err)
		}
	}
	// a signal that ended the command before the binder reported is its own end, whatever else the pieces say
	for _, bind := range []string{"", `{`} {
		in := baseInputs(clearReport)
		in.Status, in.Published, in.Bind = 143, "", nil
		if bind != "" {
			in.Bind = []byte(bind)
		}
		if doc := mustBuild(t, in); doc.End != "interrupted" || doc.Passed {
			t.Errorf("bind %q: %s", bind, doc.End)
		}
	}
}
