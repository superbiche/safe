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
	return ReleaseReading{Name: name, Version: version, Host: DefaultRegistryHost, Status: ReadingRead, Published: ago(hoursOld)}
}

func releasesOf(days int, fix string, readings ...ReleaseReading) *Releases {
	return &Releases{
		SchemaVersion: ReleasesSchema, Now: cooldownNow.Format(time.RFC3339),
		Policy: ReleasePolicy{CooldownDays: days, SecurityFix: fix}, Identities: readings,
	}
}

func (r ReleaseReading) root() ReleaseReading { r.Root = true; return r }

// bounded is a reading whose version the document lists without a time of its own: the last-modified time stands in
func (r ReleaseReading) bounded(hoursOld int) ReleaseReading {
	r.Status, r.Published, r.Gap = ReadingBounded, ago(hoursOld), ""
	return r
}
func (r ReleaseReading) missing(gap string) ReleaseReading {
	r.Status, r.Published, r.Gap = ReadingMissing, "", gap
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
	if waits[0].Installable != "2026-11-22T16:00:00Z" || waits[0].AgeDays != 0 {
		t.Fatalf("installable %s age %d", waits[0].Installable, waits[0].AgeDays)
	}
	if report.Cooldown.Checked != 2 {
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
	// the caller named young@1.0.0 (a root, excluded from npm's filter by name), which replaces the baseline's
	// young@0.9.0 and removes its advisory; the closure also carries young@1.1.0, which nobody named: it is a wait of
	// its own, whatever the root's standing
	target := pkgs("young", "1.0.0")
	target["node_modules/dep/node_modules/young"] = entry("young", "1.1.0")
	target["node_modules/dep"] = entry("dep", "2.0.0")
	rel := releasesOf(3, SecurityFixExempt,
		reading("young", "1.0.0", 30).root(), reading("young", "1.1.0", 30), reading("dep", "2.0.0", 24*30))
	report := decideCooldown(t, pkgs("young", "0.9.0"), target, rel,
		evidenceOf(read("young", "0.9.0", hit("GHSA-fix1", SeverityHigh)), read("young", "1.0.0"), read("young", "1.1.0"), read("dep", "2.0.0")))
	if len(report.Cooldown.Waived) != 1 || report.Cooldown.Waived[0].Version != "1.0.0" {
		t.Fatalf("the named fix must be waived: %+v", report.Cooldown.Waived)
	}
	if len(report.Cooldown.Waits) != 1 || report.Cooldown.Waits[0].Version != "1.1.0" || report.Outcome.Class != ClassWait {
		t.Fatalf("the other young version must wait: %+v", report.Cooldown.Waits)
	}
}

// The security-fix waiver is differential and local: the named exact version must REPLACE, at the same place in the graph, a
// baseline version of the same package that an advisory affects, and that advisory must be gone from the result.
func TestSecurityFixWaiverFollowsTheReplacedVersion(t *testing.T) {
	young := func(mode string, root bool) *Releases {
		r := reading("pk", "2.0.0", 10)
		r.Root = root
		return releasesOf(3, mode, r)
	}
	affected := evidenceOf(read("pk", "1.0.0", hit("GHSA-a", SeverityHigh), hit("GHSA-b", SeverityModerate)), read("pk", "2.0.0"))
	unaffected := evidenceOf(read("pk", "1.0.0"), read("pk", "2.0.0"))
	// the reviewer's shape: the direct version is unaffected and is replaced by the named one; an AFFECTED nested version of
	// the package disappears with its parent. The advisory is fixed, the named version removed no exposure.
	nested := pkgs("pk", "1.0.0", "dep", "1.0.0")
	nested["node_modules/dep/node_modules/pk"] = entry("pk", "0.9.0")
	nestedEvidence := evidenceOf(read("pk", "1.0.0"), read("pk", "0.9.0", hit("GHSA-a", SeverityHigh)), read("pk", "2.0.0"), read("dep", "1.0.0"))
	// a true affected replacement beside another version that stays: the named version replaces the affected direct one
	beside := pkgs("pk", "1.0.0", "dep", "1.0.0")
	beside["node_modules/dep/node_modules/pk"] = entry("pk", "0.8.0")
	besideTarget := pkgs("pk", "2.0.0", "dep", "1.0.0")
	besideTarget["node_modules/dep/node_modules/pk"] = entry("pk", "0.8.0")
	besideEvidence := evidenceOf(read("pk", "1.0.0", hit("GHSA-a", SeverityHigh), hit("GHSA-b", SeverityModerate)), read("pk", "0.8.0"), read("pk", "2.0.0"), read("dep", "1.0.0"))
	// an alias: the baseline holds pk (registry name) under another install name; the named version replaces it at that place
	aliased := func(version string) map[string]map[string]any {
		return map[string]map[string]any{"node_modules/other": with(entry("pk", version), map[string]any{"name": "pk"})}
	}
	cases := []struct {
		name             string
		baseline, target map[string]map[string]any
		rel              *Releases
		ev               Evidence
		waived           bool
		enforced         bool
	}{
		{"an affected upgrade is waived and names what it removes", pkgs("pk", "1.0.0"), pkgs("pk", "2.0.0"), young(SecurityFixExempt, true), affected, true, false},
		{"a downgrade that removes the advisory is waived", pkgs("pk", "3.0.0"), pkgs("pk", "2.0.0"),
			young(SecurityFixExempt, true), evidenceOf(read("pk", "3.0.0", hit("GHSA-a", SeverityHigh), hit("GHSA-b", SeverityModerate)), read("pk", "2.0.0")), true, false},
		{"an affected replacement beside another version is waived", beside, besideTarget, young(SecurityFixExempt, true), besideEvidence, true, false},
		{"an affected NESTED version disappearing while the named one replaces an unaffected direct one waits", nested, pkgs("pk", "2.0.0", "dep", "1.0.0"),
			young(SecurityFixExempt, true), nestedEvidence, false, false},
		{"an unaffected upgrade waits", pkgs("pk", "1.0.0"), pkgs("pk", "2.0.0"), young(SecurityFixExempt, true), unaffected, false, false},
		{"a fresh add waits", pkgs("kept", "1.0.0"), pkgs("pk", "2.0.0"), young(SecurityFixExempt, true), evidenceOf(read("kept", "1.0.0"), read("pk", "2.0.0")), false, false},
		{"an advisory the reading no longer carries (withdrawn) waits", pkgs("pk", "1.0.0"), pkgs("pk", "2.0.0"), young(SecurityFixExempt, true), unaffected, false, false},
		{"enforce keeps the wait and says the version fixes", pkgs("pk", "1.0.0"), pkgs("pk", "2.0.0"), young(SecurityFixEnforce, true), affected, false, true},
		{"a version nobody named is not waived", pkgs("pk", "1.0.0"), pkgs("pk", "2.0.0"), young(SecurityFixExempt, false), affected, false, false},
		{"no baseline: nothing is replaced", nil, pkgs("pk", "2.0.0"), young(SecurityFixExempt, true), affected, false, false},
		{"the advisory is still present in another version: nothing is fixed", pkgs("pk", "1.0.0", "dep", "1.0.0"), func() map[string]map[string]any {
			t := pkgs("pk", "2.0.0", "dep", "1.0.0")
			t["node_modules/dep/node_modules/pk"] = entry("pk", "1.0.0")
			return t
		}(), young(SecurityFixExempt, true), evidenceOf(read("pk", "1.0.0", hit("GHSA-a", SeverityHigh)), read("pk", "2.0.0"), read("dep", "1.0.0")), false, false},
		{"installed at a second place that replaced nothing: the relation cannot be told, it waits", pkgs("pk", "1.0.0"), func() map[string]map[string]any {
			t := pkgs("pk", "2.0.0", "dep", "1.0.0")
			t["node_modules/dep/node_modules/pk"] = entry("pk", "2.0.0")
			return t
		}(), young(SecurityFixExempt, true), evidenceOf(read("pk", "1.0.0", hit("GHSA-a", SeverityHigh)), read("pk", "2.0.0"), read("dep", "1.0.0")), false, false},
		{"an alias is matched by registry identity at the same place", aliased("1.0.0"), aliased("2.0.0"), young(SecurityFixExempt, true),
			evidenceOf(read("pk", "1.0.0", hit("GHSA-a", SeverityHigh), hit("GHSA-b", SeverityModerate)), read("pk", "2.0.0")), true, false},
		{"the same alias but the named version installed elsewhere waits", aliased("1.0.0"), pkgs("pk", "2.0.0"), young(SecurityFixExempt, true), affected, false, false},
	}
	for _, c := range cases {
		report := decideCooldown(t, c.baseline, c.target, c.rel, c.ev)
		if c.waived {
			if report.Outcome.Status != "clear" || len(report.Cooldown.Waived) != 1 || strings.Join(report.Cooldown.Waived[0].Remediates, ",") != "GHSA-a,GHSA-b" {
				t.Errorf("%s: %+v / %+v", c.name, report.Outcome, report.Cooldown)
			}
			continue
		}
		if report.Outcome.Class != ClassWait || len(report.Cooldown.Waived) != 0 || len(report.Cooldown.Waits) != 1 || report.Cooldown.Waits[0].Enforced != c.enforced {
			t.Errorf("%s: %+v / %+v", c.name, report.Outcome, report.Cooldown)
		}
		if c.enforced && strings.Join(report.Cooldown.Waits[0].Remediates, ",") != "GHSA-a,GHSA-b" {
			t.Errorf("%s: the wait does not name what the version fixes: %+v", c.name, report.Cooldown.Waits[0])
		}
	}
}

// There is no gap that lets a version pass unread: anything but one complete reading is missing evidence (102), and a
// reading nobody made is missing too. A version the document lists without a time of its own is judged by the
// last-modified time: old enough when that is older than the cooldown, otherwise it waits until the bound is.
func TestNoPublishTimeIsLetPassUnread(t *testing.T) {
	for name, rel := range map[string]*Releases{
		"a failed reading": releasesOf(3, SecurityFixExempt, reading("pk", "1.0.0", 1).missing("the registry could not be reached")),
		"no reading":       releasesOf(3, SecurityFixExempt),
	} {
		report := decideCooldown(t, nil, pkgs("pk", "1.0.0", "other", "1.0.0"), rel, evidenceOf(read("pk", "1.0.0"), read("other", "1.0.0")))
		if report.Outcome.Status != "stopped" || report.Outcome.Class != ClassMissingEvidence || report.Outcome.Exit != ExitOperator || len(report.Cooldown.Missing) == 0 {
			t.Errorf("%s: %+v / %+v", name, report.Outcome, report.Cooldown)
		}
		if len(report.Coverage) != len(report.Cooldown.Missing) {
			t.Errorf("%s: the missing readings are not in the coverage: %+v", name, report.Coverage)
		}
	}
	// bounded: the document's last-modified time is older than the cooldown: old enough
	old := decideCooldown(t, nil, pkgs("pk", "1.0.0"), releasesOf(3, SecurityFixExempt, reading("pk", "1.0.0", 0).bounded(24*10)), evidenceOf(read("pk", "1.0.0")))
	if old.Outcome.Status != "clear" || len(old.Cooldown.Waits) != 0 {
		t.Fatalf("a bound older than the cooldown: %+v / %+v", old.Outcome, old.Cooldown)
	}
	// bounded: the last-modified time is younger: the age cannot be told, it waits until the bound is old enough
	young := decideCooldown(t, nil, pkgs("pk", "1.0.0"), releasesOf(3, SecurityFixExempt, reading("pk", "1.0.0", 0).bounded(5)), evidenceOf(read("pk", "1.0.0")))
	if young.Outcome.Class != ClassWait || len(young.Cooldown.Waits) != 1 || !young.Cooldown.Waits[0].Bounded {
		t.Fatalf("a bound younger than the cooldown: %+v / %+v", young.Outcome, young.Cooldown)
	}
	if young.Cooldown.Waits[0].Installable != installableText(cooldownNow.Add(-5*time.Hour), 3) {
		t.Fatalf("the retry time is the bound plus the cooldown: %+v", young.Cooldown.Waits[0])
	}
	// the established blocks come first: a blocking advisory is decided before missing evidence
	rel := releasesOf(3, SecurityFixExempt, reading("pk", "1.0.0", 1).missing("the registry could not be reached"))
	report := decideCooldown(t, nil, pkgs("pk", "1.0.0"), rel, evidenceOf(read("pk", "1.0.0", hit("GHSA-x", SeverityCritical))))
	if report.Outcome.Class != ClassBlockingAdvisory || report.Outcome.Exit != ExitBlock {
		t.Fatalf("a block must outrank the reader's failure: %+v", report.Outcome)
	}
	report = decideCooldown(t, nil, pkgs("pk", "1.0.0"), rel, evidenceOf(read("pk", "1.0.0")).blocklisted("pk"))
	if report.Outcome.Class != ClassMalice || report.Outcome.Exit != ExitBlock {
		t.Fatalf("a blocklist hit must outrank the reader's failure: %+v", report.Outcome)
	}
}

func TestTheRetryTimeIsNeverEarlierThanEligibilityAndKeepsFractionalSeconds(t *testing.T) {
	published := time.Date(2026, 11, 2, 17, 5, 43, 359_000_000, time.UTC)
	if got := installableText(published, 598); got != "2028-06-22T17:05:44Z" {
		t.Fatalf("installable %s (the instant is 17:05:43.359: the printed time rounds up)", got)
	}
	if got := installableText(time.Date(2026, 11, 2, 17, 5, 43, 0, time.UTC), 1); got != "2026-11-03T17:05:43Z" {
		t.Fatalf("a whole second is printed as it is: %s", got)
	}
	// the last fraction of a second does not pass early: published 3 days minus 0.2 s ago is still young
	now := cooldownNow
	rel := releasesOf(3, SecurityFixExempt, ReleaseReading{Name: "pk", Version: "1.0.0", Host: DefaultRegistryHost, Status: ReadingRead,
		Published: now.Add(-72*time.Hour + 200*time.Millisecond).Format(time.RFC3339Nano)})
	rel.Now = now.Format(time.RFC3339Nano)
	report := decideCooldown(t, nil, pkgs("pk", "1.0.0"), rel, evidenceOf(read("pk", "1.0.0")))
	if report.Outcome.Class != ClassWait {
		t.Fatalf("0.2 s early passed: %+v", report.Cooldown)
	}
	rel.Identities[0].Published = now.Add(-72 * time.Hour).Format(time.RFC3339Nano)
	if report := decideCooldown(t, nil, pkgs("pk", "1.0.0"), rel, evidenceOf(read("pk", "1.0.0"))); report.Outcome.Status != "clear" {
		t.Fatalf("exactly 3 days old is eligible: %+v", report.Cooldown)
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
	good := `{"schema_version":1,"now":"2026-11-20T12:00:00.5Z","policy":{"cooldown_days":3,"security_fix":"exempt"},"identities":[
	  {"name":"a","version":"1.0.0","host":"registry.npmjs.org","root":false,"status":"read","published":"2026-11-19T10:00:00.359Z","gap":""},
	  {"name":"b","version":"1.0.0","host":"registry.npmjs.org","root":true,"status":"missing","published":"","gap":"HTTP 500"},
	  {"name":"c","version":"1.0.0","host":"registry.npmjs.org","root":false,"status":"bounded","published":"2026-11-19T11:00:00.5Z","gap":""}]}`
	if _, err := ReadReleases([]byte(good)); err != nil {
		t.Fatalf("a good document was refused: %v", err)
	}
	for name, doc := range map[string]string{
		"not json":               `nope`,
		"unknown member":         strings.Replace(good, `"now":`, `"extra":1,"now":`, 1),
		"repeated member":        strings.Replace(good, `"now":"2026-11-20T12:00:00.5Z"`, `"now":"2026-11-20T12:00:00.5Z","now":"2030-01-01T00:00:00Z"`, 1),
		"another schema":         strings.Replace(good, `"schema_version":1`, `"schema_version":2`, 1),
		"bad mode":               strings.Replace(good, `"exempt"`, `"waive"`, 1),
		"negative days":          strings.Replace(good, `"cooldown_days":3`, `"cooldown_days":-1`, 1),
		"days above limit":       strings.Replace(good, `"cooldown_days":3`, `"cooldown_days":36501`, 1),
		"read without time":      strings.Replace(good, `"published":"2026-11-19T10:00:00.359Z"`, `"published":""`, 1),
		"gap with a time":        strings.Replace(good, `"gap":"HTTP 500"`, `"gap":""`, 1),
		"old status":             strings.Replace(good, `"status":"missing"`, `"status":"unreadable"`, 1),
		"bad status":             strings.Replace(good, `"status":"read"`, `"status":"old"`, 1),
		"missing member":         strings.Replace(good, `,"gap":""}]}`, `}]}`, 1),
		"foreign member":         strings.Replace(good, `"published":"2026-11-19T11:00:00.5Z","gap":""}`, `"published":"2026-11-19T11:00:00.5Z","gap":"","remediates":[]}`, 1),
		"no_time is gone":        strings.Replace(good, `"status":"bounded"`, `"status":"no_time"`, 1),
		"bounded without a time": strings.Replace(good, `"published":"2026-11-19T11:00:00.5Z","gap":""}`, `"published":"","gap":""}`, 1),
		"bounded with a gap":     strings.Replace(good, `"published":"2026-11-19T11:00:00.5Z","gap":""}`, `"published":"2026-11-19T11:00:00.5Z","gap":"x"}`, 1),
		"now not a date":         strings.Replace(good, `"now":"2026-11-20T12:00:00.5Z"`, `"now":"yesterday"`, 1),
	} {
		if _, err := ReadReleases([]byte(doc)); err == nil {
			t.Errorf("%s: the document was read", name)
		}
	}
	if _, err := ReadReleases([]byte(strings.Replace(good, `"cooldown_days":3`, `"cooldown_days":36500`, 1))); err != nil {
		t.Errorf("the longest window was refused: %v", err)
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

// A reading that was not made (an established block ended the command first) is neither judged nor missing evidence.
func TestCooldownASkippedReadingIsNotJudgedAndNotMissing(t *testing.T) {
	skipped := reading("young", "1.0.0", 20)
	skipped.Status, skipped.Published, skipped.Gap = ReadingSkipped, "", "the publish time could not be read (not read)"
	rel := releasesOf(3, SecurityFixExempt, skipped)
	if err := rel.validate(); err != nil {
		t.Fatalf("a skipped reading is a valid reading: %v", err)
	}
	report := decideCooldown(t, nil, pkgs("young", "1.0.0"), rel, evidenceOf(read("young", "1.0.0")))
	c := report.Cooldown
	if c.Skipped != 1 || c.Checked != 0 || len(c.Missing) != 0 || len(c.Waits) != 0 {
		t.Fatalf("cooldown %+v", c)
	}
	for _, gap := range report.Coverage {
		if gap.Cause == GapPublishTime {
			t.Fatalf("a skipped reading is a coverage gap: %+v", gap)
		}
	}
	// the failed reading, by contrast, is missing evidence
	failed := reading("young", "1.0.0", 20).missing("registry unreachable")
	report = decideCooldown(t, nil, pkgs("young", "1.0.0"), releasesOf(3, SecurityFixExempt, failed), evidenceOf(read("young", "1.0.0")))
	if report.Cooldown.Skipped != 0 || len(report.Cooldown.Missing) != 1 || report.Cooldown.Checked != 1 {
		t.Fatalf("cooldown %+v", report.Cooldown)
	}
}
