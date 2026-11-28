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
	// Socket is the Socket evidence of the named roots and the cached blocks (nil:
	// Socket is not judged and the report has no socket_root class).
	Socket *SocketEvidence
	// Confirmations are the operator's answers for THIS command alone (see confirmations.go).
	Confirmations Confirmations
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
	// Socket is the Socket judgement of the named roots, present when evidence was given.
	Socket  *SocketReport  `json:"socket,omitempty"`
	Classes []ClassOutcome `json:"classes"`
	Outcome Outcome        `json:"outcome"`
	// Records are the named roots of a clear decision that are eligible for an install record. It is a FILTER, necessary and
	// not sufficient: the gate asks today's auditor to audit each of them after a verified publication, and that audit
	// records, or does not, by its own evidence (see records.go). Empty unless the decision is clear.
	Records []RecordItem `json:"records"`
	// Adverse are the exact identities the decision established adverse evidence on (malice, a blocking or adverse
	// advisory, a Socket finding): the gate asks today's audit to look at them, so that a receipt the evidence supersedes
	// is revoked by today's own rule.
	Adverse []AdverseItem `json:"adverse"`
	// Wanted are the artifacts whose standing acceptances the decision would use, by the relation the decision clears
	// with: the artifact whose bytes carry the item, and every blocking advisory introduced under those bytes.
	Wanted []WantedAcceptance `json:"wanted"`
	// Outstanding are the classes the decision leaves at stake, in its order, with what the operator is asked about.
	Outstanding []OutstandingClass `json:"outstanding"`
	// ConfirmedRecords are the named roots whose outcome the operator confirmed at the terminal and that the final decision
	// leaves eligible for the record today's operator-terminal path writes after a verified publication.
	ConfirmedRecords []ConfirmedRecord `json:"confirmed_records"`
	// Unjudged is true when this command went on with something that could not be judged (missing evidence, a Socket outage)
	// on the operator's confirmation: nothing of it is recorded, and the lockfile is not recorded as judged.
	Unjudged bool `json:"unjudged"`
	// GapConfirmed is true when the operator confirmed missing evidence for this command: the gaps stay listed, and nothing
	// of this command may be recorded as judged (the baseline is not advanced).
	GapConfirmed bool `json:"gap_confirmed"`

	coverBlocking map[string]map[string]struct{}
}

// AdverseItem is an exact artifact (name, version, source host) a receipt of which the decision's evidence supersedes: the
// identity the evidence is on and the artifact whose bytes carry it.
type AdverseItem struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Host    string `json:"host"`
}

// WantedAcceptance is one artifact an acceptance reader is asked about.
type WantedAcceptance struct {
	Name               string   `json:"name"`
	Version            string   `json:"version"`
	Host               string   `json:"host"`
	BlockingAdvisories []string `json:"blocking_advisories"`
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
	// Overridden is true when the operator typed an override of every artifact it names, for this command.
	Overridden bool `json:"overridden"`
}

// CoverageGap is a package whose advisory reading is missing on a side, so
// that what the command introduces for it cannot be told. Sides is "baseline",
// "target" or both.
type CoverageGap struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Sides   []string `json:"sides"`
	Gap     string   `json:"gap"`
	// Cause is the closed reason of the gap, set where the gap is made (never read back from Gap, which is text for people).
	Cause string `json:"cause"`
}

// Causes of a coverage gap.
const (
	GapAdvisoryReading    = "advisory_reading"
	GapPublishTime        = "publish_time"
	GapSocketUntied       = "socket_untied"
	GapSocketCache        = "socket_cache"
	GapBaselineUnreadable = "baseline_unreadable"
)

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
		SchemaVersion:    ReportSchema,
		Bindability:      CheckBindable(in.Target, in.RegistryHosts),
		Advisories:       AdvisoryReport{Fixed: []FixedAdvisory{}, AlreadyPresent: []PresentAdvisory{}, Introduced: []IntroducedAdvice{}},
		Malice:           []MaliceItem{},
		Coverage:         []CoverageGap{},
		Records:          []RecordItem{},
		Adverse:          []AdverseItem{},
		Wanted:           []WantedAcceptance{},
		Outstanding:      []OutstandingClass{},
		ConfirmedRecords: []ConfirmedRecord{},
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
	for i := range report.Malice {
		report.Malice[i].Overridden = in.Confirmations.maliceOverridden(report.Malice[i])
	}
	var socketClass *ClassOutcome
	if in.Socket != nil {
		blocks, socketReport, class := judgeSocket(in)
		report.Malice = append(report.Malice, blocks...)
		sort.Slice(report.Malice, func(i, j int) bool {
			a, b := report.Malice[i], report.Malice[j]
			if a.Name != b.Name {
				return a.Name < b.Name
			}
			if a.Signal != b.Signal {
				return a.Signal < b.Signal
			}
			return a.ID < b.ID
		})
		report.Socket, socketClass = &socketReport, &class
		for _, untied := range in.Socket.Untied {
			report.Coverage = append(report.Coverage, CoverageGap{Name: "", Version: "", Sides: []string{"target"},
				Gap: "socket root not tied: " + untied.Name + "@" + untied.Version + " names no package the projected lockfile holds", Cause: GapSocketUntied})
		}
		if in.Socket.CacheGap != "" {
			report.Coverage = append(report.Coverage, CoverageGap{Name: "", Version: "", Sides: []string{"target"}, Gap: "socket cache not read: " + in.Socket.CacheGap, Cause: GapSocketCache})
		}
	}

	for i := range report.Malice {
		report.Malice[i].Overridden = in.Confirmations.maliceOverridden(report.Malice[i])
	}

	if in.BaselineError != "" {
		report.Coverage = append(report.Coverage, CoverageGap{
			Name: "", Version: "", Sides: []string{"baseline"}, Gap: "baseline unreadable: " + in.BaselineError, Cause: GapBaselineUnreadable,
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
		{Class: ClassMalice, Exit: ExitBlock, AtStake: len(report.Malice), Outstanding: unconfirmedMalice(report.Malice)},
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
				Name: missing.Name, Version: missing.Version, Sides: []string{"target"}, Gap: "publish time not read: " + missing.Gap, Cause: GapPublishTime,
			})
		}
		report.Cooldown = &cooldown
		report.Classes = append(report.Classes, waitClass(cooldown))
	}
	if socketClass != nil {
		report.Classes = append(report.Classes, *socketClass)
	}
	report.Classes = append(report.Classes,
		ClassOutcome{Class: ClassMissingEvidence, Exit: ExitOperator, AtStake: len(report.Coverage), Outstanding: unconfirmedGaps(report.Coverage, in.Confirmations)})
	report.GapConfirmed = in.Confirmations.EvidenceGap && len(report.Coverage) > 0
	report.Outstanding = outstandingClasses(report, in)
	report.Adverse = adverseIdentities(report, in)
	report.Wanted = wantedAcceptances(report, in)
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
	report.Unjudged = report.GapConfirmed || (len(in.Confirmations.Socket) > 0 && report.Outcome.Status == "clear")
	report.Records = recordsFor(report, in, evidence)
	report.ConfirmedRecords = confirmedRecordsFor(report, in, evidence)
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

	type pendingName struct {
		name       string
		introduced map[string]*advisoryFacts
	}
	var pending []pendingName
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
		pending = append(pending, pendingName{name, introduced})
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
	// The blocking advisories introduced under the BYTES of each artifact (a bundled member's are its covering artifact's),
	// so that an acceptance of that artifact is asked to cover all of them, whatever the names of the members.
	report.coverBlocking = map[string]map[string]struct{}{}
	for _, item := range pending {
		for id, fact := range item.introduced {
			for version, severity := range fact.versions {
				if severityClass(severity, blockSet) != AdvisoryBlocking {
					continue
				}
				for _, occurrence := range target.Occurrences {
					if occurrence.Name != item.name || occurrence.Version != version || !occurrence.Public {
						continue
					}
					key := coverKey(occurrence)
					if report.coverBlocking[key] == nil {
						report.coverBlocking[key] = map[string]struct{}{}
					}
					report.coverBlocking[key][id] = struct{}{}
				}
			}
		}
	}
	// Once the blocking class is raised (by what is introduced) for an artifact's bytes, an override must cover EVERY blocking
	// advisory the target's evidence shows under them, inherited ones included: as today's reader requires of a follower.
	for _, occurrence := range target.Occurrences {
		if _, raised := report.coverBlocking[coverKey(occurrence)]; !raised || !occurrence.Public {
			continue
		}
		for _, hit := range evidence[occurrence.Identity()].Advisories {
			if !hit.Malware && severityClass(hit.Severity, blockSet) == AdvisoryBlocking {
				report.coverBlocking[coverKey(occurrence)][hit.ID] = struct{}{}
			}
		}
	}
	for _, item := range pending {
		report.Advisories.Introduced = append(report.Advisories.Introduced,
			introducedAdvisories(item.name, item.introduced, target, doc, blockSet, report.coverBlocking)...)
	}
}

// coverKey names the artifact whose bytes an occurrence is: its covering artifact for a bundled member, itself otherwise.
func coverKey(occurrence Occurrence) string {
	name, version := occurrence.Name, occurrence.Version
	if occurrence.CoveredBy != "" {
		name, version = occurrence.coverName, occurrence.coverVersion
	}
	return name + "@" + version + "\x00" + strings.ToLower(occurrence.Host)
}

// coverArtifact is the artifact an acceptance is for: the covering one for a bundled member.
func coverArtifact(occurrence Occurrence) (string, string) {
	if occurrence.CoveredBy != "" {
		return occurrence.coverName, occurrence.coverVersion
	}
	return occurrence.Name, occurrence.Version
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
		gaps = append(gaps, CoverageGap{Name: name, Version: identity.Version, Sides: sortedIDs(which), Gap: gap, Cause: GapAdvisoryReading})
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
func introducedAdvisories(name string, introduced map[string]*advisoryFacts, target Graph, doc Evidence, blockSet map[string]struct{}, coverBlocking map[string]map[string]struct{}) []IntroducedAdvice {
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
				kind, ok := clearingAcceptance(class, classOfAdvisory(class), occurrence, doc, coverBlocking[coverKey(occurrence)])
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
func clearingAcceptance(class, clearClass string, occurrence Occurrence, doc Evidence, introducedBlocking map[string]struct{}) (string, bool) {
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
		// An approval or pin written by an answer given DURING this command clears the class that answer was for, and no
		// other: within one command every class at stake is shown to the operator (the next command reuses it in full).
		if acceptance.Kind == AcceptLocalExact && !doc.answeredFor(name, version, clearClass) {
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

func (c Confirmations) maliceOverridden(item MaliceItem) bool {
	if len(item.Versions) == 0 {
		return false
	}
	for _, version := range item.Versions {
		if !c.has(c.Malice, Identity{Name: item.Name, Version: version}) {
			return false
		}
	}
	return true
}

func unconfirmedMalice(items []MaliceItem) int {
	n := 0
	for _, item := range items {
		if !item.Overridden {
			n++
		}
	}
	return n
}

func unconfirmedGaps(gaps []CoverageGap, c Confirmations) int {
	if c.EvidenceGap {
		return 0
	}
	return len(gaps)
}

// classOfAdvisory is the decision class of an advisory class.
func classOfAdvisory(class string) string {
	if class == AdvisoryBlocking {
		return ClassBlockingAdvisory
	}
	return ClassAdverseAdvisory
}

// answeredFor says whether an acceptance of this artifact may clear this class: true when no answer given during this command
// is behind it (a standing acceptance), or when one of those answers was for this class.
func (d Evidence) answeredFor(name, version, clearClass string) bool {
	fresh := false
	for _, answer := range d.Answered {
		if answer.Name == name && answer.Version == version {
			fresh = true
			if answer.Class == clearClass {
				return true
			}
		}
	}
	return !fresh
}
