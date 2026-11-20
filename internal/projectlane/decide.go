package projectlane

import (
	"sort"
	"strings"
)

// ReportSchema is the version of the report document.
const ReportSchema = 1

// Decision classes, in the order they are resolved. A command goes on only
// when every class is cleared, and clearing one never clears another.
const (
	ClassMalice           = "malice"
	ClassBlockingAdvisory = "blocking_advisory"
	ClassAdverseAdvisory  = "adverse_advisory"
	ClassMissingEvidence  = "missing_evidence"
)

// Exit statuses of a class left outstanding after a decline or in an
// unattended session (the gate's contract: 100 policy, 102 operator terminal
// needed, 104 audit BLOCK). A graph safe cannot bind has no class: it is
// refused before anything is written, with the operator's deliberate route,
// so it reads as 102. That route leads to the one-shot lane, which does not
// judge the closure: a malice signal or a blocking advisory already known
// here is therefore decided first, and the unbound outcome only after them.
const (
	ExitPolicy   = 100
	ExitOperator = 102
	ExitBlock    = 104
)

// Advisory classes of an introduced advisory.
const (
	AdvisoryBlocking  = "blocking"
	AdvisoryAdverse   = "adverse"
	AdvisoryBelowHigh = "below_high"
)

// Baseline sources of a report.
const (
	baselineGraph      = "graph"
	baselineEmpty      = "empty"
	baselineUnreadable = "unreadable"
)

// Input is everything the decision reads.
type Input struct {
	// Baseline is the graph the command starts from; the zero Graph is the
	// empty baseline. BaselineError is set instead when a baseline exists and
	// could not be read: introduction then cannot be told.
	Baseline      Graph
	BaselineError string
	HasBaseline   bool
	Target        Graph
	Evidence      Evidence
	RegistryHosts []string
	// Releases is the publish-time reading of the cooldown (nil: the cooldown
	// is not judged and the report has no wait class).
	Releases *Releases
}

// Report is the decision document: everything found, classed, with what is
// left outstanding. It is the one document the gate prints from and keeps.
type Report struct {
	SchemaVersion int            `json:"schema_version"`
	Baseline      BaselineStatus `json:"baseline"`
	Difference    Difference     `json:"difference"`
	Bindability   Bindability    `json:"bindability"`
	Advisories    AdvisoryReport `json:"advisories"`
	Malice        []MaliceItem   `json:"malice"`
	Coverage      []CoverageGap  `json:"coverage"`
	// Cooldown is the release-age judgement, present when a reading was given.
	Cooldown *CooldownReport `json:"cooldown,omitempty"`
	Classes  []ClassOutcome  `json:"classes"`
	Outcome  Outcome         `json:"outcome"`
}

// BaselineStatus says what the difference was taken against.
type BaselineStatus struct {
	// Source is "graph" (a lockfile), "empty" (no baseline: the whole target
	// graph is introduced) or "unreadable" (a baseline exists and could not be
	// read: nothing about introduction is established).
	Source string `json:"source"`
	Error  string `json:"error"`
}

// AdvisoryReport is the differential over (package name, advisory id).
type AdvisoryReport struct {
	Fixed          []FixedAdvisory    `json:"fixed"`
	AlreadyPresent []PresentAdvisory  `json:"already_present"`
	Introduced     []IntroducedAdvice `json:"introduced"`
}

// FixedAdvisory is present before only.
type FixedAdvisory struct {
	Name     string   `json:"name"`
	ID       string   `json:"id"`
	Severity string   `json:"severity"`
	Versions []string `json:"versions"`
}

// PresentAdvisory is in both. It never gates; the report shows when the
// versions or the number of occurrences carrying it changed, so an unchanged
// identity does not hide a larger exposure.
type PresentAdvisory struct {
	Name              string   `json:"name"`
	ID                string   `json:"id"`
	Severity          string   `json:"severity"`
	VersionsBefore    []string `json:"versions_before"`
	VersionsAfter     []string `json:"versions_after"`
	OccurrencesBefore int      `json:"occurrences_before"`
	OccurrencesAfter  int      `json:"occurrences_after"`
	ExposureChanged   bool     `json:"exposure_changed"`
}

// IntroducedAdvice is after only. Class says whether it gates (blocking,
// adverse) or only informs (below_high). Cleared and ClearedBy say whether a
// standing acceptance covers every artifact that carries it.
type IntroducedAdvice struct {
	Name      string   `json:"name"`
	ID        string   `json:"id"`
	Severity  string   `json:"severity"`
	Versions  []string `json:"versions"`
	Class     string   `json:"class"`
	Cleared   bool     `json:"cleared"`
	ClearedBy []string `json:"cleared_by"`
}

// MaliceItem is a malice signal on the target graph. Signals are never
// differential and never cleared by a standing acceptance.
type MaliceItem struct {
	// Signal is "blocklist" or "malware_record".
	Signal   string   `json:"signal"`
	Name     string   `json:"name"`
	Versions []string `json:"versions"`
	ID       string   `json:"id"`
	Reason   string   `json:"reason"`
}

// CoverageGap is a package whose advisory reading is missing on a side, so
// that what the command introduces for it cannot be told. Sides is "baseline",
// "target" or both.
type CoverageGap struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Sides   []string `json:"sides"`
	Gap     string   `json:"gap"`
}

// ClassOutcome is one class of the decision table.
type ClassOutcome struct {
	Class       string `json:"class"`
	Exit        int    `json:"exit"`
	AtStake     int    `json:"at_stake"`
	Outstanding int    `json:"outstanding"`
}

// Outcome is where the decision stands before any prompt: "clear" (nothing
// outstanding), "stopped" (the first class left, and the exit of a decline or
// an unattended session) or "unbound" (a graph safe cannot bind).
type Outcome struct {
	Status string `json:"status"`
	Class  string `json:"class"`
	Exit   int    `json:"exit"`
}

// Decide judges what the target graph introduces over the baseline.
//
// Precedence and scope, from the spec's decision table:
//
//   - Malice is read on the target graph only, whatever the baseline holds and
//     whether or not the advisory reading is complete: a blocklist hit on a
//     package in the target graph, a known-malware record on a target
//     identity. A blocklist hit on a package the target drops does not block.
//   - An advisory is judged by (package name, advisory id). Present in both
//     graphs it never gates, whatever its severity and whether or not the
//     command bumps the package, or carries it at more versions. Introduced
//     (target only) it blocks when its severity is in the policy's block set,
//     is adverse at high or unreadable severity, and only informs below high.
//   - Where the reading is missing for a package of the target on either
//     side, introduction cannot be told for it: Missing evidence. What the
//     part that was read establishes stands: an advisory read on the target
//     and absent from a complete baseline reading of that package is
//     introduced; one the baseline's partial reading already holds is present.
//   - A baseline that exists and cannot be read establishes nothing about
//     introduction: only malice and bindability are judged, and the baseline
//     is Missing evidence.
//
// Standing acceptances clear a class item by authority: Malice and Missing
// evidence have none; a Blocking advisory is cleared by a local exact approval
// of the artifact or a followed advisory override covering every blocking
// advisory of it, and never by a followed install allowance; an Adverse
// advisory by a local exact approval, a followed grant or a followed install
// allowance.
func Decide(in Input) Report {
	evidence := indexEvidence(in.Evidence)

	report := Report{
		SchemaVersion: ReportSchema,
		Bindability:   CheckBindable(in.Target, in.RegistryHosts),
		Advisories:    AdvisoryReport{Fixed: []FixedAdvisory{}, AlreadyPresent: []PresentAdvisory{}, Introduced: []IntroducedAdvice{}},
		Malice:        []MaliceItem{},
		Coverage:      []CoverageGap{},
	}
	baseline := in.Baseline
	switch {
	case in.BaselineError != "":
		baseline = Graph{}
		report.Baseline = BaselineStatus{Source: baselineUnreadable, Error: in.BaselineError}
	case in.HasBaseline:
		report.Baseline = BaselineStatus{Source: baselineGraph}
	default:
		report.Baseline = BaselineStatus{Source: baselineEmpty}
	}
	report.Difference = Diff(baseline, in.Target)

	report.Malice = maliceItems(in.Target, in.Evidence, evidence)

	if in.BaselineError != "" {
		report.Coverage = append(report.Coverage, CoverageGap{
			Name: "", Version: "", Sides: []string{"baseline"}, Gap: "baseline unreadable: " + in.BaselineError,
		})
	} else {
		differential(&report, baseline, in.Target, evidence, in.Evidence)
	}
	sort.Slice(report.Coverage, func(i, j int) bool {
		a, b := report.Coverage[i], report.Coverage[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Version < b.Version
	})

	report.Classes = []ClassOutcome{
		{Class: ClassMalice, Exit: ExitBlock, AtStake: len(report.Malice), Outstanding: len(report.Malice)},
		classCount(ClassBlockingAdvisory, ExitBlock, report.Advisories.Introduced, AdvisoryBlocking),
		classCount(ClassAdverseAdvisory, ExitPolicy, report.Advisories.Introduced, AdvisoryAdverse),
	}
	if in.Releases != nil {
		cooldown, err := judgeCooldown(in, baseline, &report)
		if err != nil {
			// A reading that cannot be judged is not an empty one: it is missing evidence.
			cooldown = CooldownReport{Days: in.Releases.Policy.CooldownDays, SecurityFix: in.Releases.Policy.SecurityFix,
				Waits: []CooldownWait{}, Waived: []CooldownWaiver{}, Missing: []CooldownGap{{Gap: err.Error()}}}
		}
		// A publish time that could not be read is missing evidence like an advisory reading that could not be.
		for _, missing := range cooldown.Missing {
			report.Coverage = append(report.Coverage, CoverageGap{
				Name: missing.Name, Version: missing.Version, Sides: []string{"target"}, Gap: "publish time not read: " + missing.Gap,
			})
		}
		report.Cooldown = &cooldown
		report.Classes = append(report.Classes, waitClass(cooldown))
	}
	report.Classes = append(report.Classes,
		ClassOutcome{Class: ClassMissingEvidence, Exit: ExitOperator, AtStake: len(report.Coverage), Outstanding: len(report.Coverage)})
	report.Outcome = Outcome{Status: "clear"}
	for _, class := range report.Classes {
		if class.Outstanding == 0 {
			continue
		}
		if class.Exit != ExitBlock && !report.Bindability.Bound {
			break
		}
		report.Outcome = Outcome{Status: "stopped", Class: class.Class, Exit: class.Exit}
		return report
	}
	if !report.Bindability.Bound {
		report.Outcome = Outcome{Status: "unbound", Exit: ExitOperator}
	}
	return report
}

func classCount(class string, exit int, items []IntroducedAdvice, advisoryClass string) ClassOutcome {
	outcome := ClassOutcome{Class: class, Exit: exit}
	for _, item := range items {
		if item.Class != advisoryClass {
			continue
		}
		outcome.AtStake++
		if !item.Cleared {
			outcome.Outstanding++
		}
	}
	return outcome
}

// evidenceIndex answers reads by exact identity.
type evidenceIndex map[Identity]IdentityEvidence

func indexEvidence(evidence Evidence) evidenceIndex {
	index := make(evidenceIndex, len(evidence.Identities))
	for _, identity := range evidence.Identities {
		index[Identity{Name: identity.Name, Version: identity.Version}] = identity
	}
	return index
}

// side is one graph's view of one package name: the public identities it holds
// at that name and how many occurrences carry each.
type side struct {
	occurrences map[Identity]int
}

func sideOf(graph Graph) map[string]*side {
	out := map[string]*side{}
	for _, occurrence := range graph.Occurrences {
		if !occurrence.Public {
			continue
		}
		s := out[occurrence.Name]
		if s == nil {
			s = &side{occurrences: map[Identity]int{}}
			out[occurrence.Name] = s
		}
		s.occurrences[occurrence.Identity()]++
	}
	return out
}

// advisoryFacts is what one side reads for one (name, advisory id): the
// severity it has at each version that carries it, and how many occurrences
// carry it.
type advisoryFacts struct {
	severities map[string]struct{}
	versions   map[string]string // version -> severity at that version
	count      int
}

// read returns the non-malware advisories a side holds for a name, by id, and
// whether every identity of the name was read completely.
func (s *side) read(evidence evidenceIndex) (map[string]*advisoryFacts, bool, []Identity) {
	facts := map[string]*advisoryFacts{}
	complete := true
	var gaps []Identity
	if s == nil {
		return facts, true, nil
	}
	for identity, occurrences := range s.occurrences {
		read, ok := evidence[identity]
		if !ok || read.Coverage != CoverageComplete {
			complete = false
			gaps = append(gaps, identity)
		}
		for _, hit := range read.Advisories {
			if hit.Malware {
				continue
			}
			fact := facts[hit.ID]
			if fact == nil {
				fact = &advisoryFacts{severities: map[string]struct{}{}, versions: map[string]string{}}
				facts[hit.ID] = fact
			}
			fact.severities[hit.Severity] = struct{}{}
			fact.versions[identity.Version] = hit.Severity
			fact.count += occurrences
		}
	}
	return facts, complete, gaps
}

func (f *advisoryFacts) versionList() []string {
	versions := make([]string, 0, len(f.versions))
	for version := range f.versions {
		versions = append(versions, version)
	}
	sort.Strings(versions)
	return versions
}

func differential(report *Report, baseline, target Graph, evidence evidenceIndex, doc Evidence) {
	before := sideOf(baseline)
	after := sideOf(target)

	names := map[string]struct{}{}
	for name := range before {
		names[name] = struct{}{}
	}
	for name := range after {
		names[name] = struct{}{}
	}
	sortedNames := make([]string, 0, len(names))
	for name := range names {
		sortedNames = append(sortedNames, name)
	}
	sort.Strings(sortedNames)

	blockSet := map[string]struct{}{}
	for _, severity := range doc.Policy.BlockSeverities {
		blockSet[severity] = struct{}{}
	}

	for _, name := range sortedNames {
		beforeFacts, beforeComplete, beforeGaps := before[name].read(evidence)
		afterFacts, afterComplete, afterGaps := after[name].read(evidence)
		_, inTarget := after[name]

		// Coverage only matters for a package the target carries: a package the
		// command drops introduces nothing, whatever was read of it.
		if inTarget {
			report.Coverage = append(report.Coverage, coverageGaps(name, beforeGaps, afterGaps, evidence)...)
		}

		// The differential identity is (name, advisory id): which advisories are
		// introduced is settled on the name. What each introduced advisory
		// means is then settled per artifact, below.
		introduced := map[string]*advisoryFacts{}
		for _, id := range sortedFactIDs(afterFacts) {
			fact := afterFacts[id]
			if previous, present := beforeFacts[id]; present {
				report.Advisories.AlreadyPresent = append(report.Advisories.AlreadyPresent, presentAdvisory(name, id, previous, fact))
				continue
			}
			if !beforeComplete {
				// Not told apart from an advisory the unread part of the
				// baseline holds: that is the coverage gap's to carry.
				continue
			}
			introduced[id] = fact
		}
		report.Advisories.Introduced = append(report.Advisories.Introduced,
			introducedAdvisories(name, introduced, target, doc, blockSet)...)
		if afterComplete {
			for _, id := range sortedFactIDs(beforeFacts) {
				if _, still := afterFacts[id]; !still {
					fact := beforeFacts[id]
					report.Advisories.Fixed = append(report.Advisories.Fixed, FixedAdvisory{
						Name: name, ID: id, Severity: maxSeverity(fact.severities), Versions: fact.versionList(),
					})
				}
			}
		}
	}
}

func sortedFactIDs(facts map[string]*advisoryFacts) []string {
	ids := make([]string, 0, len(facts))
	for id := range facts {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func presentAdvisory(name, id string, before, after *advisoryFacts) PresentAdvisory {
	item := PresentAdvisory{
		Name: name, ID: id, Severity: maxSeverity(after.severities),
		VersionsBefore: before.versionList(), VersionsAfter: after.versionList(),
		OccurrencesBefore: before.count, OccurrencesAfter: after.count,
	}
	item.ExposureChanged = !equalStrings(item.VersionsBefore, item.VersionsAfter) || before.count != after.count
	return item
}

func coverageGaps(name string, beforeGaps, afterGaps []Identity, evidence evidenceIndex) []CoverageGap {
	sides := map[Identity]map[string]struct{}{}
	for _, identity := range beforeGaps {
		if sides[identity] == nil {
			sides[identity] = map[string]struct{}{}
		}
		sides[identity]["baseline"] = struct{}{}
	}
	for _, identity := range afterGaps {
		if sides[identity] == nil {
			sides[identity] = map[string]struct{}{}
		}
		sides[identity]["target"] = struct{}{}
	}
	var gaps []CoverageGap
	for identity, which := range sides {
		gap := "no advisory reading was supplied for this identity"
		if read, ok := evidence[identity]; ok {
			gap = read.Gap
		}
		gaps = append(gaps, CoverageGap{Name: name, Version: identity.Version, Sides: sortedIDs(which), Gap: gap})
	}
	return gaps
}

// severityRank orders the ladder; an unreadable severity ranks above moderate
// because it is not provably below high.
func severityRank(severity string) int {
	switch severity {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityUnknown:
		return 3
	case SeverityModerate:
		return 2
	case SeverityLow:
		return 1
	}
	return 3
}

func maxSeverity(set map[string]struct{}) string {
	best := ""
	for severity := range set {
		if best == "" || severityRank(severity) > severityRank(best) {
			best = severity
		}
	}
	return best
}

// severityClass is what a severity means for the install: blocking when the
// policy lists it, adverse at high or unreadable, below high otherwise.
func severityClass(severity string, blockSet map[string]struct{}) string {
	if _, blocks := blockSet[severity]; blocks {
		return AdvisoryBlocking
	}
	if severityRank(severity) >= severityRank(SeverityUnknown) {
		return AdvisoryAdverse
	}
	return AdvisoryBelowHigh
}

// introducedAdvisories turns the introduced (name, advisory id) pairs of one
// package name into report items, one per advisory and class. The class is a
// property of the artifact that carries the advisory, not of the aggregate: an
// advisory that is critical at one version and high at another is a blocking
// item for the first and an adverse item for the second, each cleared (or
// not) by an authority of its own class and only for the artifacts it names.
func introducedAdvisories(name string, introduced map[string]*advisoryFacts, target Graph, doc Evidence, blockSet map[string]struct{}) []IntroducedAdvice {
	// The introduced blocking advisories of each version: what a followed
	// advisory override must cover for that artifact. An advisory already
	// present never gates and is never demanded.
	blockingAt := map[string]map[string]struct{}{}
	for id, fact := range introduced {
		for version, severity := range fact.versions {
			if severityClass(severity, blockSet) == AdvisoryBlocking {
				if blockingAt[version] == nil {
					blockingAt[version] = map[string]struct{}{}
				}
				blockingAt[version][id] = struct{}{}
			}
		}
	}

	ids := make([]string, 0, len(introduced))
	for id := range introduced {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var items []IntroducedAdvice
	for _, id := range ids {
		fact := introduced[id]
		byClass := map[string]map[string]struct{}{}
		severities := map[string]map[string]struct{}{}
		for version, severity := range fact.versions {
			class := severityClass(severity, blockSet)
			if byClass[class] == nil {
				byClass[class] = map[string]struct{}{}
				severities[class] = map[string]struct{}{}
			}
			byClass[class][version] = struct{}{}
			severities[class][severity] = struct{}{}
		}
		for _, class := range []string{AdvisoryBlocking, AdvisoryAdverse, AdvisoryBelowHigh} {
			versions, ok := byClass[class]
			if !ok {
				continue
			}
			item := IntroducedAdvice{
				Name: name, ID: id, Severity: maxSeverity(severities[class]), Versions: sortedIDs(versions),
				Class: class, ClearedBy: []string{},
			}
			if class == AdvisoryBelowHigh {
				item.Cleared = true
				items = append(items, item)
				continue
			}
			used := map[string]struct{}{}
			carried := 0
			cleared := true
			seen := map[string]struct{}{}
			for _, occurrence := range target.Occurrences {
				if occurrence.Name != name || !occurrence.Public {
					continue
				}
				if _, carries := versions[occurrence.Version]; !carries {
					continue
				}
				marker := keyText(occurrence.Key()) + "\x00" + occurrence.Host + "\x00" + occurrence.CoveredBy + "\x00" + occurrence.Member
				if _, dup := seen[marker]; dup {
					continue
				}
				seen[marker] = struct{}{}
				carried++
				kind, ok := clearingAcceptance(class, occurrence, doc, blockingAt[occurrence.Version])
				if !ok {
					cleared = false
					continue
				}
				used[kind] = struct{}{}
			}
			item.Cleared = cleared && carried > 0
			if item.Cleared {
				item.ClearedBy = sortedIDs(used)
			}
			items = append(items, item)
		}
	}
	return items
}

// clearingAcceptance finds the standing acceptance that clears one artifact
// for an advisory class, by the class's own authority list. introducedBlocking
// is the introduced blocking advisories of the artifact: what a followed
// advisory override has to cover.
func clearingAcceptance(class string, occurrence Occurrence, doc Evidence, introducedBlocking map[string]struct{}) (string, bool) {
	// A covered member's bytes are its covering artifact's: only an acceptance
	// of that artifact (its name, version and host) has authority over them,
	// never one of a standalone artifact that merely shares the member's name
	// and version.
	name, version := occurrence.Name, occurrence.Version
	if occurrence.CoveredBy != "" {
		name, version = occurrence.coverName, occurrence.coverVersion
	}
	for _, acceptance := range doc.Acceptances {
		if acceptance.Name != name || acceptance.Version != version ||
			occurrence.Host == "" || !strings.EqualFold(acceptance.Host, occurrence.Host) {
			continue
		}
		switch class {
		case AdvisoryBlocking:
			switch acceptance.Kind {
			case AcceptLocalExact:
				return acceptance.Kind, true
			case AcceptFollowedOverride:
				if covers(acceptance.Advisories, introducedBlocking) {
					return acceptance.Kind, true
				}
			}
			// A followed install allowance, and a followed grant, never clear a
			// blocking advisory.
		case AdvisoryAdverse:
			switch acceptance.Kind {
			case AcceptLocalExact, AcceptFollowedGrant, AcceptFollowedInstall:
				return acceptance.Kind, true
			}
		}
	}
	return "", false
}

func covers(listed []string, required map[string]struct{}) bool {
	have := map[string]struct{}{}
	for _, id := range listed {
		have[id] = struct{}{}
	}
	for id := range required {
		if _, ok := have[id]; !ok {
			return false
		}
	}
	return true
}

// maliceItems reads malice on the target graph alone and independently of the
// advisory reading: the operator's blocklist by name and known-malware records
// by exact identity, kept even where the identity's reading is incomplete.
func maliceItems(target Graph, doc Evidence, evidence evidenceIndex) []MaliceItem {
	items := []MaliceItem{}
	versionsByName := map[string]map[string]struct{}{}
	for _, occurrence := range target.Occurrences {
		if versionsByName[occurrence.Name] == nil {
			versionsByName[occurrence.Name] = map[string]struct{}{}
		}
		versionsByName[occurrence.Name][occurrence.Version] = struct{}{}
	}
	seen := map[string]struct{}{}
	for _, hit := range doc.Blocklist {
		versions, inTarget := versionsByName[hit.Name]
		if _, dup := seen[hit.Name]; !inTarget || dup {
			continue
		}
		seen[hit.Name] = struct{}{}
		items = append(items, MaliceItem{Signal: "blocklist", Name: hit.Name, Versions: sortedIDs(versions), Reason: hit.Reason})
	}
	for _, identity := range target.Identities() {
		for _, hit := range evidence[identity].Advisories {
			if hit.Malware {
				items = append(items, MaliceItem{
					Signal: "malware_record", Name: identity.Name, Versions: []string{identity.Version}, ID: hit.ID,
				})
			}
		}
	}
	sort.Slice(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Signal != b.Signal {
			return a.Signal < b.Signal
		}
		return a.ID < b.ID
	})
	return items
}
