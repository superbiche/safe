package projectlane

import (
	"strings"
	"testing"
	"time"
)

var cooldownNow = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

func ago(hours int) string {
	return cooldownNow.Add(-time.Duration(hours) * time.Hour).Format(time.RFC3339)
}

func reading(name, version string, hoursOld int) ReleaseReading {
	return ReleaseReading{Name: name, Version: version, Host: DefaultRegistryHost, Status: ReadingRead, Published: ago(hoursOld), Remediates: []string{}}
}

func releasesOf(days int, fix string, readings ...ReleaseReading) *Releases {
	return &Releases{
		SchemaVersion: ReleasesSchema, Now: cooldownNow.Format(time.RFC3339),
		Policy: ReleasePolicy{CooldownDays: days, SecurityFix: fix}, Identities: readings,
	}
}

func (r ReleaseReading) root() ReleaseReading { r.Root = true; return r }
func (r ReleaseReading) fixes(ids ...string) ReleaseReading {
	r.Remediates = ids
	return r
}
func (r ReleaseReading) unreadable(gap string) ReleaseReading {
	r.Status, r.Published, r.Gap = ReadingUnreadable, "", gap
	return r
}

func decideCooldown(t *testing.T, baseline, target map[string]map[string]any, rel *Releases, ev Evidence) Report {
	t.Helper()
	in := Input{Target: graphOf(t, target), Evidence: ev, Releases: rel}
	if baseline != nil {
		in.Baseline, in.HasBaseline = graphOf(t, baseline), true
	}
	return Decide(in)
}

func TestCooldownWaitNamesPackageVersionAndDate(t *testing.T) {
	// the version was published 20 hours ago: inside a 3-day cooldown, installable 52 hours from now
	rel := releasesOf(3, SecurityFixExempt, reading("young", "1.0.0", 20), reading("old", "2.0.0", 24*10))
	report := decideCooldown(t, nil, pkgs("young", "1.0.0", "old", "2.0.0"),
		rel, evidenceOf(read("young", "1.0.0"), read("old", "2.0.0")))
	if report.Outcome.Status != "stopped" || report.Outcome.Class != ClassWait || report.Outcome.Exit != ExitPolicy {
		t.Fatalf("outcome %+v", report.Outcome)
	}
	waits := report.Cooldown.Waits
	if len(waits) != 1 || waits[0].Name != "young" || waits[0].Version != "1.0.0" || waits[0].Cleared {
		t.Fatalf("waits %+v", waits)
	}
	if waits[0].Installable != "2026-11-22T16:00Z" || waits[0].AgeDays != 0 {
		t.Fatalf("installable %s age %d", waits[0].Installable, waits[0].AgeDays)
	}
	if report.Cooldown.Checked != 2 || len(report.Cooldown.Unreadable) != 0 {
		t.Fatalf("cooldown %+v", report.Cooldown)
	}
}

func TestCooldownBoundaryIsWholeDays(t *testing.T) {
	// 2.9 days old is two days old: inside a 3-day cooldown; exactly 3 days old is outside it
	for _, c := range []struct {
		hours int
		young bool
	}{{24*3 - 1, true}, {24 * 3, false}, {24*3 + 1, false}, {0, true}, {-5, true}} {
		report := decideCooldown(t, nil, pkgs("pk", "1.0.0"), releasesOf(3, SecurityFixExempt, reading("pk", "1.0.0", c.hours)), evidenceOf(read("pk", "1.0.0")))
		if got := len(report.Cooldown.Waits) == 1; got != c.young {
			t.Fatalf("%d hours old: young=%v, want %v", c.hours, got, c.young)
		}
	}
}

func TestCooldownJudgesWhatTheCommandIntroducesNotTheBaseline(t *testing.T) {
	// ruled (coordinator's default for the spec's question 1): a young version already in the baseline is not checked,
	// whoever locked it; the same version introduced is
	rel := releasesOf(3, SecurityFixExempt, reading("young", "1.0.0", 5))
	ev := evidenceOf(read("young", "1.0.0"))
	inBaseline := decideCooldown(t, pkgs("young", "1.0.0"), pkgs("young", "1.0.0"), rel, ev)
	if inBaseline.Outcome.Status != "clear" || inBaseline.Cooldown.Checked != 0 {
		t.Fatalf("a baseline entry was judged: %+v / %+v", inBaseline.Outcome, inBaseline.Cooldown)
	}
	introduced := decideCooldown(t, pkgs(), pkgs("young", "1.0.0"), rel, ev)
	if introduced.Outcome.Class != ClassWait || introduced.Cooldown.Checked != 1 {
		t.Fatalf("an introduced entry was not judged: %+v", introduced.Outcome)
	}
	// a young entry that is in the lockfile on disk and not in the baseline is introduced: judged
	atDisk := decideCooldown(t, pkgs("old", "1.0.0"), pkgs("old", "1.0.0", "young", "1.0.0"), releasesOf(3, SecurityFixExempt, reading("young", "1.0.0", 5), reading("old", "1.0.0", 24*100)), evidenceOf(read("young", "1.0.0"), read("old", "1.0.0")))
	if atDisk.Outcome.Class != ClassWait {
		t.Fatalf("a young entry of the lockfile on disk was not caught: %+v", atDisk.Outcome)
	}
	// the candidate predicate is the one place the answer lives: the whole target would be the other answer
	graph := graphOf(t, pkgs("young", "1.0.0"))
	if got := CooldownCandidates(Diff(graph, graph), graph); len(got) != 0 {
		t.Fatalf("candidates over an unchanged graph: %v", got)
	}
}

func TestCooldownCatchesAnotherYoungVersionOfANamedName(t *testing.T) {
	// the caller named young@1.0.0 (a root, excluded from npm's filter by name); the closure also carries young@1.1.0,
	// which nobody named: it is a wait of its own, whatever the root's standing
	target := pkgs("young", "1.0.0")
	target["node_modules/dep/node_modules/young"] = entry("young", "1.1.0")
	target["node_modules/dep"] = entry("dep", "2.0.0")
	rel := releasesOf(3, SecurityFixExempt,
		reading("young", "1.0.0", 30).root().fixes("GHSA-fix1"), reading("young", "1.1.0", 30), reading("dep", "2.0.0", 24*30))
	report := decideCooldown(t, nil, target, rel, evidenceOf(read("young", "1.0.0"), read("young", "1.1.0"), read("dep", "2.0.0")))
	if len(report.Cooldown.Waived) != 1 || report.Cooldown.Waived[0].Version != "1.0.0" {
		t.Fatalf("the named fix must be waived: %+v", report.Cooldown.Waived)
	}
	if len(report.Cooldown.Waits) != 1 || report.Cooldown.Waits[0].Version != "1.1.0" || report.Outcome.Class != ClassWait {
		t.Fatalf("the other young version must wait: %+v", report.Cooldown.Waits)
	}
}

func TestSecurityFixExemptionBelongsToTheNamedExactVersion(t *testing.T) {
	ev := evidenceOf(read("pk", "1.0.0"))
	young := reading("pk", "1.0.0", 10).fixes("GHSA-a", "GHSA-b")
	// exempt + named + fixes: waived, with the advisories named
	waived := decideCooldown(t, nil, pkgs("pk", "1.0.0"), releasesOf(3, SecurityFixExempt, young.root()), ev)
	if waived.Outcome.Status != "clear" || len(waived.Cooldown.Waived) != 1 || strings.Join(waived.Cooldown.Waived[0].Remediates, ",") != "GHSA-a,GHSA-b" {
		t.Fatalf("exempt: %+v / %+v", waived.Outcome, waived.Cooldown)
	}
	// enforce: the wait stays, and says the version remediates and that the setting caused it
	enforced := decideCooldown(t, nil, pkgs("pk", "1.0.0"), releasesOf(3, SecurityFixEnforce, young.root()), ev)
	if enforced.Outcome.Class != ClassWait || len(enforced.Cooldown.Waits) != 1 || !enforced.Cooldown.Waits[0].Enforced || len(enforced.Cooldown.Waits[0].Remediates) != 2 {
		t.Fatalf("enforce: %+v / %+v", enforced.Outcome, enforced.Cooldown)
	}
	// a young fix nobody named is not selected: no exemption without the root flag
	unnamed := decideCooldown(t, nil, pkgs("pk", "1.0.0"), releasesOf(3, SecurityFixExempt, young), ev)
	if unnamed.Outcome.Class != ClassWait || len(unnamed.Cooldown.Waived) != 0 {
		t.Fatalf("an unnamed fix was exempted: %+v", unnamed.Cooldown)
	}
	// a named version that fixes nothing waits
	plain := decideCooldown(t, nil, pkgs("pk", "1.0.0"), releasesOf(3, SecurityFixExempt, reading("pk", "1.0.0", 10).root()), ev)
	if plain.Outcome.Class != ClassWait {
		t.Fatalf("a named feature release was exempted: %+v", plain.Cooldown)
	}
}

func TestAnUnreadablePublishTimeIsDisclosedAndDoesNotStop(t *testing.T) {
	rel := releasesOf(3, SecurityFixExempt, reading("pk", "1.0.0", 1).unreadable("the registry's packument has no publish time for this version"))
	report := decideCooldown(t, nil, pkgs("pk", "1.0.0", "other", "1.0.0"), rel, evidenceOf(read("pk", "1.0.0"), read("other", "1.0.0")))
	if report.Outcome.Status != "clear" {
		t.Fatalf("an unreadable time stopped the command: %+v", report.Outcome)
	}
	// pk has a reading that is a gap; other has no reading at all: both are disclosed, neither is "old"
	if len(report.Cooldown.Unreadable) != 2 || report.Cooldown.Unreadable[0].Name != "other" || !strings.Contains(report.Cooldown.Unreadable[1].Gap, "no publish time") {
		t.Fatalf("unreadable %+v", report.Cooldown.Unreadable)
	}
}

func TestCooldownDisabledJudgesNothing(t *testing.T) {
	report := decideCooldown(t, nil, pkgs("pk", "1.0.0"), releasesOf(0, SecurityFixExempt), evidenceOf(read("pk", "1.0.0")))
	if report.Outcome.Status != "clear" || report.Cooldown.Checked != 0 {
		t.Fatalf("%+v / %+v", report.Outcome, report.Cooldown)
	}
}

func TestPrivateAndBundledEntriesAreNotReadFromAPublicRegistry(t *testing.T) {
	target := pkgs("pub", "1.0.0")
	target["node_modules/priv"] = with(entry("priv", "1.0.0"), map[string]any{"resolved": "https://npm.corp.example/priv/-/priv-1.0.0.tgz"})
	target["node_modules/pub/node_modules/bun"] = with(entry("bun", "1.0.0"), map[string]any{"inBundle": true, "resolved": nil, "integrity": nil})
	graph := graphOf(t, target)
	got := CooldownCandidates(Diff(Graph{}, graph), graph)
	if len(got) != 1 || got[0].Name != "pub" {
		t.Fatalf("candidates %v", got)
	}
}

func TestAStandingAcceptanceClearsAWaitOfItsOwnArtifactOnly(t *testing.T) {
	rel := releasesOf(3, SecurityFixExempt, reading("pk", "1.0.0", 10), reading("other", "1.0.0", 10))
	ev := evidenceOf(read("pk", "1.0.0"), read("other", "1.0.0")).accepting(accept(AcceptLocalExact, "pk", "1.0.0"))
	report := decideCooldown(t, nil, pkgs("pk", "1.0.0", "other", "1.0.0"), rel, ev)
	if report.Outcome.Class != ClassWait || len(report.Cooldown.Waits) != 2 {
		t.Fatalf("%+v", report.Outcome)
	}
	for _, wait := range report.Cooldown.Waits {
		if wait.Cleared != (wait.Name == "pk") {
			t.Fatalf("wait %s cleared=%v", wait.Name, wait.Cleared)
		}
	}
	// a followed advisory override clears no wait: it is not an authority over a release age
	ev = evidenceOf(read("pk", "1.0.0")).accepting(accept(AcceptFollowedOverride, "pk", "1.0.0"))
	report = decideCooldown(t, nil, pkgs("pk", "1.0.0"), releasesOf(3, SecurityFixExempt, reading("pk", "1.0.0", 10)), ev)
	if report.Outcome.Class != ClassWait {
		t.Fatalf("an advisory override cleared a wait: %+v", report.Outcome)
	}
}

func TestWaitIsResolvedAfterTheAdvisoryClassesAndBeforeMissingEvidence(t *testing.T) {
	rel := releasesOf(3, SecurityFixExempt, reading("pk", "1.0.0", 10))
	// a blocking advisory is decided before the wait
	report := decideCooldown(t, nil, pkgs("pk", "1.0.0"), rel, evidenceOf(read("pk", "1.0.0", hit("GHSA-x", SeverityCritical))))
	if report.Outcome.Class != ClassBlockingAdvisory {
		t.Fatalf("blocking first: %+v", report.Outcome)
	}
	// the wait is decided before missing evidence
	report = decideCooldown(t, nil, pkgs("pk", "1.0.0"), rel, evidenceOf(gap("pk", "1.0.0")))
	if report.Outcome.Class != ClassWait {
		t.Fatalf("wait before missing evidence: %+v", report.Outcome)
	}
	order := []string{}
	for _, class := range report.Classes {
		order = append(order, class.Class)
	}
	if strings.Join(order, ",") != "malice,blocking_advisory,adverse_advisory,wait,missing_evidence" {
		t.Fatalf("class order %v", order)
	}
	// with no reading given the cooldown is not judged and there is no wait class
	none := decideCooldown(t, nil, pkgs("pk", "1.0.0"), nil, evidenceOf(read("pk", "1.0.0")))
	if none.Cooldown != nil || len(none.Classes) != 4 {
		t.Fatalf("no reading: %+v", none.Classes)
	}
}

func TestReadReleasesIsStrict(t *testing.T) {
	good := `{"schema_version":1,"now":"2026-11-20T12:00:00Z","policy":{"cooldown_days":3,"security_fix":"exempt"},"identities":[
	  {"name":"a","version":"1.0.0","host":"registry.npmjs.org","root":false,"status":"read","published":"2026-11-19T10:00:00Z","gap":"","remediates":[],"remediation_gap":""},
	  {"name":"b","version":"1.0.0","host":"registry.npmjs.org","root":true,"status":"unreadable","published":"","gap":"HTTP 500","remediates":[],"remediation_gap":""}]}`
	if _, err := ReadReleases([]byte(good)); err != nil {
		t.Fatalf("a good document was refused: %v", err)
	}
	for name, doc := range map[string]string{
		"not json":          `nope`,
		"unknown member":    strings.Replace(good, `"now":`, `"extra":1,"now":`, 1),
		"repeated member":   strings.Replace(good, `"now":"2026-11-20T12:00:00Z"`, `"now":"2026-11-20T12:00:00Z","now":"2030-01-01T00:00:00Z"`, 1),
		"another schema":    strings.Replace(good, `"schema_version":1`, `"schema_version":2`, 1),
		"bad mode":          strings.Replace(good, `"exempt"`, `"waive"`, 1),
		"negative days":     strings.Replace(good, `"cooldown_days":3`, `"cooldown_days":-1`, 1),
		"read without time": strings.Replace(good, `"published":"2026-11-19T10:00:00Z"`, `"published":""`, 1),
		"gap with a time":   strings.Replace(good, `"gap":"HTTP 500"`, `"gap":""`, 1),
		"bad status":        strings.Replace(good, `"status":"read"`, `"status":"old"`, 1),
		"missing member":    strings.Replace(good, `"remediation_gap":""}]}`, `}]}`, 1),
		"bad advisory id": strings.Replace(good, `"remediates":[],"remediation_gap":""},
	  {"name":"b"`, `"remediates":["x y"],"remediation_gap":""},
	  {"name":"b"`, 1),
		"now not a date": strings.Replace(good, `"now":"2026-11-20T12:00:00Z"`, `"now":"yesterday"`, 1),
	} {
		if _, err := ReadReleases([]byte(doc)); err == nil {
			t.Errorf("%s: the document was read", name)
		}
	}
}

func TestReadReleaseRequestIsStrict(t *testing.T) {
	good := `{"schema_version":1,"policy":{"cooldown_days":3,"security_fix":"exempt"},"roots":[{"name":"a","version":"1.0.0"}],"identities":[{"name":"a","version":"1.0.0","host":"registry.npmjs.org"}]}`
	if _, err := ReadReleaseRequest([]byte(good)); err != nil {
		t.Fatal(err)
	}
	for name, doc := range map[string]string{
		"no host":      strings.Replace(good, `,"host":"registry.npmjs.org"`, ``, 1),
		"unknown":      strings.Replace(good, `"roots"`, `"x":1,"roots"`, 1),
		"null roots":   strings.Replace(good, `"roots":[{"name":"a","version":"1.0.0"}]`, `"roots":null`, 1),
		"another mode": strings.Replace(good, `"exempt"`, `"x"`, 1),
	} {
		if _, err := ReadReleaseRequest([]byte(doc)); err == nil {
			t.Errorf("%s: the request was read", name)
		}
	}
}
