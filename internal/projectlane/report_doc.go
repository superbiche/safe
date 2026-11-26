package projectlane

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/superbiche/safe/internal/strictjson"
)

// The report document of a lane command (ticket 1639): ONE document per command, written once at the end, for every end the lane
// controls at or after the decision. It is built here from typed readings of the pieces the run left (the decision report, the binder's
// result, the answers, the scripts, the scan's summary) and from nothing else: every string in it is a member of a closed list or has
// passed a grammar, and what does not is COUNTED, never kept. No text of npm, of the scanner, of a registry or of the environment is in
// it; a location is never in it (a host is the most a source can show; the packages' own identities are). The project's key is the
// name of the directory the document lives in, not a member. A killed command leaves none.

// ReportDocumentSchema is the schema of the document.
const ReportDocumentSchema = 1

// MaxReportBytes is the bound on one document. Past it the document is not written (never cut short). 8 MiB: measured on a
// document of an install that introduces 1000 packages, each with an advisory (the test that states the measure).
const MaxReportBytes = 8 << 20

// The closed lists.
var (
	reportVerbs  = map[string]bool{"install": true, "ci": true, "update": true, "dedupe": true, "prune": true}
	reportEnds   = map[string]bool{"published": true, "published_lockfile": true, "dry_run": true, "refused": true, "declined": true, "unread_answer": true, "stopped": true, "bind_refused": true, "install_failed": true, "verification_failed": true, "inputs_changed": true, "interrupted": true, "publication_failed": true, "install_unsettled": true, "bind_unreadable": true}
	bindOutcomes = map[string]int{"published": 0, "refused": 30, "install_failed": 31, "verification_failed": 32, "inputs_changed": 33, "interrupted": 34, "publication_failed": 35, "install_unsettled": 36}
	promptEnded  = map[string]bool{"accepted": true, "declined": true, "unread": true}
	severities   = map[string]bool{"critical": true, "high": true, "moderate": true, "low": true, "unknown": true}
	advClasses   = map[string]bool{AdvisoryBlocking: true, AdvisoryAdverse: true, AdvisoryBelowHigh: true}
	maliceSignal = map[string]bool{"blocklist": true, "malware_record": true, "socket_block": true}
	baselines    = map[string]bool{baselineGraph: true, baselineEmpty: true, baselineUnreadable: true}
	outcomeState = map[string]bool{"clear": true, "stopped": true, "unbound": true}
	classNames   = map[string]bool{ClassMalice: true, ClassBlockingAdvisory: true, ClassAdverseAdvisory: true, ClassMissingEvidence: true, "wait": true, ClassSocketRoot: true}
	socketOut    = map[string]bool{SocketClear: true, SocketAdverse: true, SocketUnavailable: true, SocketRateLimited: true, SocketConsentRequired: true, SocketPending: true, SocketBlocked: true}
	gapCauses    = map[string]bool{GapAdvisoryReading: true, GapPublishTime: true, GapSocketUntied: true, GapSocketCache: true, GapBaselineUnreadable: true}
	gapSides     = map[string]bool{"baseline": true, "target": true}
	introReasons = map[string]bool{IntroducedNew: true, IntroducedOrigin: true, IntroducedIntegrity: true, IntroducedBoth: true, IntroducedCovering: true}
	fixPolicies  = map[string]bool{SecurityFixExempt: true, SecurityFixEnforce: true, "": true}
	scriptEvents = map[string]bool{"preinstall": true, "install": true, "postinstall": true, "prepublish": true, "preprepare": true, "prepare": true, "postprepare": true}
	scanReasons  = map[string]bool{"": true, "no_audit": true, "no_timeout": true, "timeout": true, "failed": true, "no_result": true}
	// the ends that read as a pass of the command, and the ones that need a status other than 0
	passEnds = map[string]bool{"published": true, "published_lockfile": true, "dry_run": true}
)

const maxFirstGaps = 5

var (
	idGrammar     = regexp.MustCompile(`\A[A-Za-z0-9][A-Za-z0-9._:-]{0,95}\z`)
	digestGrammar = regexp.MustCompile(`\A(?:sha256:[0-9a-f]{64}|none|absent|unreadable)\z`)
	safeVersion   = regexp.MustCompile(`\A[0-9A-Za-z][0-9A-Za-z.+-]{0,31}\z`)
	timeGrammar   = regexp.MustCompile(`\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\z`)
	stampGrammar  = regexp.MustCompile(`\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z\z`)
	hostGrammar   = regexp.MustCompile(`\A[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\z`)
)

// The lane's own grammars for what it admits to a project: an identity the lane installed is an identity the report keeps.
func goodName(s string) bool    { return validPackageName(s) }
func goodVersion(s string) bool { return validVersion(s) }
func goodStamp(s string) bool   { return stampGrammar.MatchString(s) }

// reportHostOf is the host of a resolved location, from its parts and nothing else: userinfo, port, path, query and fragment are not kept.
func reportHostOf(origin string) string {
	if hostOf(origin) == "" {
		return ""
	}
	if !strings.Contains(origin, "://") {
		origin = "https://" + origin
	}
	u, err := url.Parse(origin)
	if err != nil {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if !hostGrammar.MatchString(host) {
		return ""
	}
	return host
}

// ReportDocument is the document.
type ReportDocument struct {
	SchemaVersion int             `json:"schema_version"`
	WrittenAt     string          `json:"written_at"`
	SafeVersion   string          `json:"safe_version"`
	Command       ReportCommand   `json:"command"`
	End           string          `json:"end"`
	Status        int             `json:"status"`
	Passed        bool            `json:"passed"`
	Lockfiles     ReportLockfiles `json:"lockfiles"`
	Decision      ReportDecision  `json:"decision"`
	Prompts       []ReportPrompt  `json:"prompts"`
	Binder        *ReportBinder   `json:"binder"`
	Scripts       *ReportScripts  `json:"scripts"`
	Scan          *ReportScan     `json:"scan"`
}

// ReportCommand is the command as the lane saw it, from closed values: the arguments of the command are not kept.
type ReportCommand struct {
	Verb            string `json:"verb"`
	DryRun          bool   `json:"dry_run"`
	PackageLockOnly bool   `json:"package_lock_only"`
}

// ReportLockfiles are the digests of the lockfiles the decision was made from, taken while the lane held them: the judged target, and the
// baseline ("none" when there was none).
type ReportLockfiles struct {
	TargetSHA256   string `json:"target_sha256"`
	BaselineSHA256 string `json:"baseline_sha256"`
}

// ReportDecision is what the decision found, as typed values.
type ReportDecision struct {
	Baseline        string           `json:"baseline"`
	Outcome         ReportOutcome    `json:"outcome"`
	Classes         []ReportClass    `json:"classes"`
	Entries         int              `json:"entries"`
	Difference      ReportDifference `json:"difference"`
	Fixed           []ReportAdvisory `json:"fixed"`
	AlreadyPresent  []ReportPresent  `json:"already_present"`
	PresentBy       map[string]int   `json:"already_present_by_severity"`
	IntroducedAdv   []ReportAdvisory `json:"introduced_advisories"`
	AdvisoriesOther int              `json:"advisories_other"`
	Malice          []ReportMalice   `json:"malice"`
	MaliceOther     int              `json:"malice_other"`
	Coverage        ReportCoverage   `json:"coverage"`
	Cooldown        ReportCooldown   `json:"cooldown"`
	Socket          []ReportSocket   `json:"socket"`
	SocketOther     int              `json:"socket_other"`
	Adverse         []ReportAdverse  `json:"adverse"`
	AdverseOther    int              `json:"adverse_other"`
	Unjudged        bool             `json:"unjudged"`
	GapConfirmed    bool             `json:"gap_confirmed"`
}

// ReportOutcome is where the decision stood.
type ReportOutcome struct {
	Status string `json:"status"`
	Class  string `json:"class"`
	Exit   int    `json:"exit"`
}

// ReportClass is one class of the decision table and what it came to.
type ReportClass struct {
	Class       string `json:"class"`
	Exit        int    `json:"exit"`
	AtStake     int    `json:"at_stake"`
	Outstanding int    `json:"outstanding"`
}

// ReportDifference is what the command changes in the graph: the identities, or for ci (whose entries are the whole lockfile) counts only.
type ReportDifference struct {
	Listed          bool               `json:"listed"`
	AddedCount      int                `json:"added_count"`
	RemovedCount    int                `json:"removed_count"`
	ChangedCount    int                `json:"changed_count"`
	IntroducedCount int                `json:"introduced_count"`
	Added           []ReportNameSet    `json:"added"`
	Removed         []ReportNameSet    `json:"removed"`
	Changed         []ReportChange     `json:"changed"`
	Introduced      []ReportIntroduced `json:"introduced"`
	Other           int                `json:"other"`
}

// ReportNameSet is a package name and the versions it is at.
type ReportNameSet struct {
	Name     string   `json:"name"`
	Versions []string `json:"versions"`
}

// ReportChange is a package at other versions after the command.
type ReportChange struct {
	Name   string   `json:"name"`
	Before []string `json:"before"`
	After  []string `json:"after"`
}

// ReportIntroduced is an artifact the command introduces: its identity and the host its bytes come from, never a location.
type ReportIntroduced struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Host    string `json:"host"`
	Reason  string `json:"reason"`
}

// ReportAdvisory is an advisory of a package.
type ReportAdvisory struct {
	Name     string `json:"name"`
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Class    string `json:"class"`
	Cleared  bool   `json:"cleared"`
}

// ReportPresent is an advisory the baseline already carries, and whether the exposure to it changed.
type ReportPresent struct {
	Name            string `json:"name"`
	ID              string `json:"id"`
	Severity        string `json:"severity"`
	ExposureChanged bool   `json:"exposure_changed"`
}

// ReportMalice is a malice fact of the target.
type ReportMalice struct {
	Signal     string   `json:"signal"`
	Name       string   `json:"name"`
	Versions   []string `json:"versions"`
	ID         string   `json:"id"`
	Overridden bool     `json:"overridden"`
}

// ReportCoverage is the missing evidence: per cause a count and the first identities.
type ReportCoverage struct {
	Gaps   int              `json:"gaps"`
	Causes []ReportGapCause `json:"causes"`
	Other  int              `json:"other"`
}

// ReportGapCause is one cause of missing evidence.
type ReportGapCause struct {
	Cause string           `json:"cause"`
	Count int              `json:"count"`
	First []ReportGapFirst `json:"first"`
}

// ReportGapFirst is an identity (empty for a gap of the whole reading) and the sides the reading is missing on.
type ReportGapFirst struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Sides   []string `json:"sides"`
}

// ReportCooldown is the release-age judgement.
type ReportCooldown struct {
	Days        int            `json:"days"`
	SecurityFix string         `json:"security_fix"`
	Checked     int            `json:"checked"`
	Waits       []ReportWait   `json:"waits"`
	Waived      []ReportWaiver `json:"waived"`
	Missing     int            `json:"missing"`
	Other       int            `json:"other"`
}

// ReportWait is a version inside the cooldown, with the dates.
type ReportWait struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Published   string `json:"published"`
	Installable string `json:"installable"`
	Root        bool   `json:"root"`
	Bounded     bool   `json:"bounded"`
	Cleared     bool   `json:"cleared"`
}

// ReportWaiver is a named version whose wait the security-fix exemption waived.
type ReportWaiver struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Published string `json:"published"`
}

// ReportSocket is the Socket judgement of a named root.
type ReportSocket struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Outcome string `json:"outcome"`
	Cleared bool   `json:"cleared"`
}

// ReportAdverse is an exact artifact the decision's evidence is on; the host is where its bytes came from, never a location.
type ReportAdverse struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Host    string `json:"host"`
}

// ReportPrompt is one class the operator was asked about, and how it ended.
type ReportPrompt struct {
	Class string `json:"class"`
	Ended string `json:"ended"`
}

// ReportBinder is what the binder said.
type ReportBinder struct {
	Outcome string `json:"outcome"`
	Exit    int    `json:"exit"`
}

// ReportScripts is the scripts the command left unrun: the identities and the closed events, no path. One reading, uncapped.
type ReportScripts struct {
	Source      string          `json:"source"`
	Previous    string          `json:"previous"`
	Total       int             `json:"total"`
	Packages    []ReportScriptP `json:"packages"`
	Other       int             `json:"packages_other"`
	UnreadTotal int             `json:"unread_total"`
	Unread      []ReportScriptP `json:"unread"`
	UnreadOther int             `json:"unread_other"`
	Root        *ReportRoot     `json:"root"`
}

// ReportScriptP is a package with install-time scripts.
type ReportScriptP struct {
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	Host     string   `json:"host"`
	Events   []string `json:"events"`
	Gyp      bool     `json:"gyp"`
	Declared bool     `json:"declared"`
}

// ReportRoot is the project's own install-time scripts.
type ReportRoot struct {
	Events []string `json:"events"`
	Gyp    bool     `json:"gyp"`
}

// ReportScan is the scan's summary, not its full result, and whether the lockfile it read (before and after) is the one this command
// published.
type ReportScan struct {
	Status            string       `json:"status"`
	Reason            string       `json:"reason"`
	Summary           *ScanSummary `json:"summary"`
	LockfilePublished bool         `json:"lockfile_published"`
}

// ReportInputs are the pieces of a run, as bytes (nil: absent).
type ReportInputs struct {
	Now             time.Time
	SafeVersion     string
	Verb            string
	DryRun          bool
	PackageLockOnly bool
	Status          int
	Published       string // "", "tree" or "lockfile": what the lane established after the binder
	Report          []byte
	Bind            []byte
	Prompts         []byte // class<TAB>ended per line
	Scripts         []byte
	Scan            []byte
	Graph           []byte
	Judged          []byte // the digests of the judged target and of the baseline
}

// ErrNoDecision: the run left no readable decision report: nothing is written, the command ended before it.
var ErrNoDecision = errors.New("the run left no readable decision report")

func capped(n int) int {
	if n < 0 {
		return 0
	}
	return n
}

// BuildReportDocument builds the document from the pieces. A piece that cannot be read is said in the document (the binder as
// "bind_unreadable", the digests as "unreadable", the scripts and the scan as absent); only the decision report is required.
func BuildReportDocument(in ReportInputs) (ReportDocument, error) {
	doc := ReportDocument{SchemaVersion: ReportDocumentSchema, WrittenAt: in.Now.UTC().Format("2006-01-02T15:04:05Z"), SafeVersion: in.SafeVersion,
		Command: ReportCommand{Verb: in.Verb, DryRun: in.DryRun, PackageLockOnly: in.PackageLockOnly}, Status: in.Status, Prompts: []ReportPrompt{}}
	var report Report
	if err := json.Unmarshal(in.Report, &report); err != nil || report.SchemaVersion != ReportSchema || !outcomeState[report.Outcome.Status] {
		return doc, ErrNoDecision
	}
	doc.Lockfiles = lockfilesOf(in.Judged)
	doc.Decision = decisionOf(report, in.Verb == "ci")
	doc.Decision.Entries = entriesOf(in.Graph)
	doc.Prompts = promptsOf(in.Prompts)
	if in.Bind != nil {
		doc.Binder = binderOf(in.Bind)
	}
	if in.Scripts != nil {
		doc.Scripts = scriptsOf(in.Scripts)
	}
	if in.Scan != nil {
		doc.Scan = scanOf(in.Scan)
	}
	doc.End = endOf(in, doc)
	doc.Passed = (doc.End == "published" || doc.End == "published_lockfile") && doc.Status == 0
	if err := ValidateReportDocument(doc); err != nil {
		return doc, fmt.Errorf("the document built is not valid: %w", err)
	}
	return doc, nil
}

func lockfilesOf(raw []byte) ReportLockfiles {
	out := ReportLockfiles{TargetSHA256: "unreadable", BaselineSHA256: "unreadable"}
	var j struct {
		Target   string `json:"target"`
		Baseline string `json:"baseline"`
	}
	if raw == nil || json.Unmarshal(raw, &j) != nil {
		return out
	}
	if digestGrammar.MatchString(j.Target) {
		out.TargetSHA256 = j.Target
	}
	if digestGrammar.MatchString(j.Baseline) {
		out.BaselineSHA256 = j.Baseline
	}
	return out
}

// entriesOf is the number of entries of the lockfile the command judged (the target graph), 0 when the graph cannot be read.
func entriesOf(raw []byte) int {
	var g struct {
		Graph struct {
			Occurrences []json.RawMessage `json:"occurrences"`
		} `json:"graph"`
	}
	if raw == nil || json.Unmarshal(raw, &g) != nil {
		return 0
	}
	return len(g.Graph.Occurrences)
}

// endOf says how the command ended, from the binder's word, the prompts, the decision and the PUBLIC status. An end that reads as a pass
// exists only with status 0.
func endOf(in ReportInputs, doc ReportDocument) string {
	end := rawEndOf(in, doc)
	if passEnds[end] && doc.Status != 0 {
		// a refusal that came after the decision (a final admission, a late reading) is a refusal, whatever the command asked for
		if end == "dry_run" || doc.Binder == nil {
			return "refused"
		}
		return "stopped"
	}
	return end
}

func rawEndOf(in ReportInputs, doc ReportDocument) string {
	// a signal ended the command before the binder reported anything usable
	// (a publication the binder reported and a signal after it, while the scan ran, is an interrupted command too: it ended on the signal)
	if in.Status > 128 && in.Status < 193 && !in.DryRun && (doc.Binder == nil || doc.Binder.Outcome == "unreadable" || doc.Binder.Outcome == "published") {
		return "interrupted"
	}
	if b := doc.Binder; b != nil {
		switch b.Outcome {
		case "unreadable":
			return "bind_unreadable"
		case "published":
			switch in.Published {
			case "tree":
				return "published"
			case "lockfile":
				return "published_lockfile"
			}
			return "bind_unreadable"
		case "refused":
			return "bind_refused"
		}
		return b.Outcome
	}
	if n := len(doc.Prompts); n > 0 {
		switch doc.Prompts[n-1].Ended {
		case "declined":
			return "declined"
		case "unread":
			return "unread_answer"
		}
	}
	switch {
	case doc.Decision.Outcome.Status != "clear":
		return "refused"
	case in.DryRun:
		return "dry_run"
	}
	return "stopped"
}

func versionsOK(versions []string) bool {
	for _, v := range versions {
		if !goodVersion(v) {
			return false
		}
	}
	return true
}

func decisionOf(r Report, countsOnly bool) ReportDecision {
	d := ReportDecision{Baseline: r.Baseline.Source, Outcome: ReportOutcome{Status: r.Outcome.Status, Class: r.Outcome.Class, Exit: r.Outcome.Exit},
		Classes: []ReportClass{}, Fixed: []ReportAdvisory{}, AlreadyPresent: []ReportPresent{}, PresentBy: map[string]int{}, IntroducedAdv: []ReportAdvisory{},
		Malice: []ReportMalice{}, Socket: []ReportSocket{}, Adverse: []ReportAdverse{}, Unjudged: r.Unjudged, GapConfirmed: r.GapConfirmed}
	d.Cooldown.Waits, d.Cooldown.Waived = []ReportWait{}, []ReportWaiver{}
	d.Difference = differenceOf(r.Difference, countsOnly)
	if !baselines[d.Baseline] {
		d.Baseline = baselineUnreadable
	}
	if r.Outcome.Class != "" && !classNames[r.Outcome.Class] {
		d.Outcome.Class = ""
	}
	d.Outcome.Exit = min(capped(d.Outcome.Exit), 255)
	for _, c := range r.Classes {
		if classNames[c.Class] {
			d.Classes = append(d.Classes, ReportClass{Class: c.Class, Exit: min(capped(c.Exit), 255), AtStake: capped(c.AtStake), Outstanding: capped(c.Outstanding)})
		}
	}
	for _, a := range r.Advisories.Fixed {
		if goodName(a.Name) && idGrammar.MatchString(a.ID) {
			d.Fixed = append(d.Fixed, ReportAdvisory{Name: a.Name, ID: a.ID, Severity: severityOf(a.Severity)})
		} else {
			d.AdvisoriesOther++
		}
	}
	for _, a := range r.Advisories.AlreadyPresent {
		if goodName(a.Name) && idGrammar.MatchString(a.ID) {
			sev := severityOf(a.Severity)
			d.AlreadyPresent = append(d.AlreadyPresent, ReportPresent{Name: a.Name, ID: a.ID, Severity: sev, ExposureChanged: a.ExposureChanged})
			d.PresentBy[sev]++
		} else {
			d.AdvisoriesOther++
		}
	}
	for _, a := range r.Advisories.Introduced {
		if goodName(a.Name) && idGrammar.MatchString(a.ID) {
			class := a.Class
			if !advClasses[class] {
				class = AdvisoryAdverse
			}
			d.IntroducedAdv = append(d.IntroducedAdv, ReportAdvisory{Name: a.Name, ID: a.ID, Severity: severityOf(a.Severity), Class: class, Cleared: a.Cleared})
		} else {
			d.AdvisoriesOther++
		}
	}
	for _, m := range r.Malice {
		if goodName(m.Name) && maliceSignal[m.Signal] && (m.ID == "" || idGrammar.MatchString(m.ID)) && versionsOK(m.Versions) {
			d.Malice = append(d.Malice, ReportMalice{Signal: m.Signal, Name: m.Name, Versions: append([]string{}, m.Versions...), ID: m.ID, Overridden: m.Overridden})
		} else {
			d.MaliceOther++
		}
	}
	d.Coverage = coverageOf(r.Coverage)
	if r.Cooldown != nil {
		c := r.Cooldown
		d.Cooldown.Days, d.Cooldown.Checked, d.Cooldown.Missing = capped(c.Days), capped(c.Checked), len(c.Missing)
		d.Cooldown.SecurityFix = c.SecurityFix
		if !fixPolicies[d.Cooldown.SecurityFix] {
			d.Cooldown.SecurityFix = ""
		}
		for _, w := range c.Waits {
			if goodName(w.Name) && goodVersion(w.Version) && goodStamp(w.Published) && goodStamp(w.Installable) {
				d.Cooldown.Waits = append(d.Cooldown.Waits, ReportWait{Name: w.Name, Version: w.Version, Published: w.Published, Installable: w.Installable,
					Root: w.Root, Bounded: w.Bounded, Cleared: w.Cleared})
			} else {
				d.Cooldown.Other++
			}
		}
		for _, w := range c.Waived {
			if goodName(w.Name) && goodVersion(w.Version) && goodStamp(w.Published) {
				d.Cooldown.Waived = append(d.Cooldown.Waived, ReportWaiver{Name: w.Name, Version: w.Version, Published: w.Published})
			} else {
				d.Cooldown.Other++
			}
		}
	}
	if r.Socket != nil {
		for _, s := range r.Socket.Roots {
			if goodName(s.Name) && goodVersion(s.Version) && socketOut[s.Outcome] {
				d.Socket = append(d.Socket, ReportSocket{Name: s.Name, Version: s.Version, Outcome: s.Outcome, Cleared: s.Cleared})
			} else {
				d.SocketOther++
			}
		}
	}
	for _, a := range r.Adverse {
		if goodName(a.Name) && goodVersion(a.Version) && hostGrammar.MatchString(a.Host) {
			d.Adverse = append(d.Adverse, ReportAdverse{Name: a.Name, Version: a.Version, Host: strings.ToLower(a.Host)})
		} else {
			d.AdverseOther++
		}
	}
	return d
}

func differenceOf(r Difference, countsOnly bool) ReportDifference {
	d := ReportDifference{Listed: !countsOnly, AddedCount: len(r.Added), RemovedCount: len(r.Removed), ChangedCount: len(r.Changed), IntroducedCount: len(r.Introduced),
		Added: []ReportNameSet{}, Removed: []ReportNameSet{}, Changed: []ReportChange{}, Introduced: []ReportIntroduced{}}
	if countsOnly {
		return d
	}
	for _, n := range r.Added {
		if goodName(n.Name) && versionsOK(n.Versions) {
			d.Added = append(d.Added, ReportNameSet{Name: n.Name, Versions: append([]string{}, n.Versions...)})
		} else {
			d.Other++
		}
	}
	for _, n := range r.Removed {
		if goodName(n.Name) && versionsOK(n.Versions) {
			d.Removed = append(d.Removed, ReportNameSet{Name: n.Name, Versions: append([]string{}, n.Versions...)})
		} else {
			d.Other++
		}
	}
	for _, c := range r.Changed {
		if goodName(c.Name) && versionsOK(c.Before) && versionsOK(c.After) {
			d.Changed = append(d.Changed, ReportChange{Name: c.Name, Before: append([]string{}, c.Before...), After: append([]string{}, c.After...)})
		} else {
			d.Other++
		}
	}
	for _, i := range r.Introduced {
		if goodName(i.Name) && goodVersion(i.Version) && introReasons[i.Reason] {
			d.Introduced = append(d.Introduced, ReportIntroduced{Name: i.Name, Version: i.Version, Host: reportHostOf(i.Origin), Reason: i.Reason})
		} else {
			d.Other++
		}
	}
	return d
}

func coverageOf(gaps []CoverageGap) ReportCoverage {
	out := ReportCoverage{Gaps: len(gaps), Causes: []ReportGapCause{}}
	byCause := map[string]*ReportGapCause{}
	for _, g := range gaps {
		if !gapCauses[g.Cause] {
			out.Other++
			continue
		}
		c := byCause[g.Cause]
		if c == nil {
			c = &ReportGapCause{Cause: g.Cause, First: []ReportGapFirst{}}
			byCause[g.Cause] = c
		}
		c.Count++
		if len(c.First) >= maxFirstGaps {
			continue
		}
		sides := []string{}
		ok := true
		for _, side := range g.Sides {
			if gapSides[side] {
				sides = append(sides, side)
			} else {
				ok = false
			}
		}
		if (g.Name == "" || goodName(g.Name)) && (g.Version == "" || goodVersion(g.Version)) && ok {
			c.First = append(c.First, ReportGapFirst{Name: g.Name, Version: g.Version, Sides: sides})
		}
	}
	causes := make([]string, 0, len(byCause))
	for cause := range byCause {
		causes = append(causes, cause)
	}
	sort.Strings(causes)
	for _, cause := range causes {
		out.Causes = append(out.Causes, *byCause[cause])
	}
	return out
}

func severityOf(s string) string {
	if severities[s] {
		return s
	}
	return "unknown"
}

// promptsOf reads the prompt log: one line per class the operator was asked about, in the order asked.
func promptsOf(raw []byte) []ReportPrompt {
	out := []ReportPrompt{}
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) == 2 && classNames[f[0]] && promptEnded[f[1]] {
			out = append(out, ReportPrompt{Class: f[0], Ended: f[1]})
		}
	}
	return out
}

func binderOf(raw []byte) *ReportBinder {
	var b struct {
		SchemaVersion int    `json:"schema_version"`
		Outcome       string `json:"outcome"`
		Exit          int    `json:"exit"`
	}
	if err := json.Unmarshal(raw, &b); err != nil || b.SchemaVersion != 1 {
		return &ReportBinder{Outcome: "unreadable", Exit: 0}
	}
	if code, ok := bindOutcomes[b.Outcome]; !ok || code != b.Exit {
		return &ReportBinder{Outcome: "unreadable", Exit: 0}
	}
	return &ReportBinder{Outcome: b.Outcome, Exit: b.Exit}
}

func eventsOf(in []string) ([]string, bool) {
	out := []string{}
	for _, e := range in {
		if !scriptEvents[e] {
			return nil, false
		}
		out = append(out, e)
	}
	return out, true
}

func hostPackageOK(host string) bool {
	if host == "" {
		return true
	}
	at := strings.LastIndex(host, "@")
	return at > 0 && goodName(host[:at]) && goodVersion(host[at+1:])
}

func scriptsOf(raw []byte) *ReportScripts {
	var s ScriptsReport
	if err := json.Unmarshal(raw, &s); err != nil || s.SchemaVersion != 3 || (s.Source != ScriptsLock && s.Source != ScriptsSource) {
		return nil
	}
	previous := s.Previous
	if previous != "read" && previous != "none" && previous != "unreadable" {
		return nil
	}
	out := &ReportScripts{Source: s.Source, Previous: previous, Total: capped(s.Total), UnreadTotal: capped(s.UnreadTotal), Packages: []ReportScriptP{}, Unread: []ReportScriptP{}}
	pack := func(in []ScriptPackage, dst *[]ReportScriptP, other *int) {
		for _, p := range in {
			events, ok := eventsOf(p.Events)
			if ok && goodName(p.Name) && goodVersion(p.Version) && hostPackageOK(p.Host) {
				*dst = append(*dst, ReportScriptP{Name: p.Name, Version: p.Version, Host: p.Host, Events: events, Gyp: p.Gyp, Declared: p.Declared})
			} else {
				*other++
			}
		}
	}
	pack(s.Packages, &out.Packages, &out.Other)
	pack(s.Unread, &out.Unread, &out.UnreadOther)
	if s.Root != nil {
		if events, ok := eventsOf(s.Root.Events); ok {
			out.Root = &ReportRoot{Events: events, Gyp: s.Root.Gyp}
		}
	}
	return out
}

func scanOf(raw []byte) *ReportScan {
	var s struct {
		Status            string       `json:"status"`
		Reason            string       `json:"reason"`
		Summary           *ScanSummary `json:"summary"`
		LockfilePublished bool         `json:"lockfile_published"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil
	}
	out := &ReportScan{Status: s.Status, Reason: s.Reason, LockfilePublished: s.LockfilePublished}
	if s.Summary != nil {
		in := *s.Summary
		clean := ScanSummary{SchemaVersion: 1, CriticalTotal: capped(in.CriticalTotal), Critical: map[string]int{}, Unattributed: capped(in.Unattributed),
			CoverageGaps: []ScanGap{}, CoverageOther: capped(in.CoverageOther), CoverageUnreadable: in.CoverageUnreadable}
		known := map[string]bool{}
		for _, e := range ScanEcosystems {
			known[e] = true
		}
		for k, v := range in.Critical {
			if known[k] && v > 0 {
				clean.Critical[k] = v
			} else {
				clean.Unattributed += capped(v)
			}
		}
		for _, g := range in.CoverageGaps {
			if scannerName.MatchString(g.Scanner) && ScanStatuses[g.Status] {
				clean.CoverageGaps = append(clean.CoverageGaps, g)
			} else {
				clean.CoverageOther++
			}
		}
		out.Summary = &clean
	}
	if (out.Status != "completed" && out.Status != "not_completed") || !scanReasons[out.Reason] || (out.Status == "completed") != (out.Summary != nil) {
		return nil
	}
	return out
}

func validNameVersions(sets []ReportNameSet) bool {
	for _, n := range sets {
		if !goodName(n.Name) || !versionsOK(n.Versions) {
			return false
		}
	}
	return true
}

// ValidateReportDocument holds every token of the document to its grammar or closed list, and the end to the status.
func ValidateReportDocument(d ReportDocument) error {
	bad := func(what string) error { return fmt.Errorf("%s is outside its grammar", what) }
	if d.SchemaVersion != ReportDocumentSchema {
		return bad("schema_version")
	}
	if !timeGrammar.MatchString(d.WrittenAt) || !safeVersion.MatchString(d.SafeVersion) || !digestGrammar.MatchString(d.Lockfiles.TargetSHA256) ||
		!digestGrammar.MatchString(d.Lockfiles.BaselineSHA256) {
		return bad("written_at, safe_version or a lockfile digest")
	}
	if !reportVerbs[d.Command.Verb] || !reportEnds[d.End] || d.Status < 0 || d.Status > 255 {
		return bad("verb, end or status")
	}
	if d.Passed != ((d.End == "published" || d.End == "published_lockfile") && d.Status == 0) {
		return errors.New("passed does not follow from the end and the status")
	}
	// an end that reads as a pass exists only with status 0, and every other end needs a status that is not 0
	if passEnds[d.End] != (d.Status == 0) {
		return errors.New("the end does not agree with the status")
	}
	dec := d.Decision
	if !baselines[dec.Baseline] || !outcomeState[dec.Outcome.Status] || (dec.Outcome.Class != "" && !classNames[dec.Outcome.Class]) || dec.Outcome.Exit < 0 || dec.Outcome.Exit > 255 {
		return bad("the decision's baseline or outcome")
	}
	for _, c := range dec.Classes {
		if !classNames[c.Class] || c.Exit < 0 || c.Exit > 255 || c.AtStake < 0 || c.Outstanding < 0 {
			return bad("a class")
		}
	}
	df := dec.Difference
	for _, n := range []int{dec.Entries, df.AddedCount, df.RemovedCount, df.ChangedCount, df.IntroducedCount, df.Other, dec.AdvisoriesOther, dec.MaliceOther, dec.Coverage.Gaps,
		dec.Coverage.Other, dec.Cooldown.Days, dec.Cooldown.Checked, dec.Cooldown.Other, dec.Cooldown.Missing, dec.SocketOther, dec.AdverseOther} {
		if n < 0 {
			return bad("a count")
		}
	}
	if !validNameVersions(df.Added) || !validNameVersions(df.Removed) {
		return bad("a name set")
	}
	for _, c := range df.Changed {
		if !goodName(c.Name) || !versionsOK(c.Before) || !versionsOK(c.After) {
			return bad("a changed package")
		}
	}
	for _, i := range df.Introduced {
		if !goodName(i.Name) || !goodVersion(i.Version) || !introReasons[i.Reason] || (i.Host != "" && !hostGrammar.MatchString(i.Host)) {
			return bad("an introduced artifact")
		}
	}
	if !df.Listed && (len(df.Added)+len(df.Removed)+len(df.Changed)+len(df.Introduced) > 0) {
		return errors.New("a difference that is counts only lists identities")
	}
	for _, a := range append(append([]ReportAdvisory{}, dec.Fixed...), dec.IntroducedAdv...) {
		if !goodName(a.Name) || !idGrammar.MatchString(a.ID) || !severities[a.Severity] || (a.Class != "" && !advClasses[a.Class]) {
			return bad("an advisory")
		}
	}
	for _, a := range dec.AlreadyPresent {
		if !goodName(a.Name) || !idGrammar.MatchString(a.ID) || !severities[a.Severity] {
			return bad("an advisory already present")
		}
	}
	for k, v := range dec.PresentBy {
		if !severities[k] || v < 0 {
			return bad("a severity count")
		}
	}
	for _, m := range dec.Malice {
		if !goodName(m.Name) || !maliceSignal[m.Signal] || (m.ID != "" && !idGrammar.MatchString(m.ID)) || !versionsOK(m.Versions) {
			return bad("a malice fact")
		}
	}
	for _, c := range dec.Coverage.Causes {
		if !gapCauses[c.Cause] || c.Count < 0 || len(c.First) > maxFirstGaps {
			return bad("a coverage cause")
		}
		for _, f := range c.First {
			if (f.Name != "" && !goodName(f.Name)) || (f.Version != "" && !goodVersion(f.Version)) {
				return bad("a coverage identity")
			}
			for _, side := range f.Sides {
				if !gapSides[side] {
					return bad("a coverage side")
				}
			}
		}
	}
	if !fixPolicies[dec.Cooldown.SecurityFix] {
		return bad("the cooldown's policy")
	}
	for _, w := range dec.Cooldown.Waits {
		if !goodName(w.Name) || !goodVersion(w.Version) || !goodStamp(w.Published) || !goodStamp(w.Installable) {
			return bad("a cooldown wait")
		}
	}
	for _, w := range dec.Cooldown.Waived {
		if !goodName(w.Name) || !goodVersion(w.Version) || !goodStamp(w.Published) {
			return bad("a cooldown waiver")
		}
	}
	for _, s := range dec.Socket {
		if !goodName(s.Name) || !goodVersion(s.Version) || !socketOut[s.Outcome] {
			return bad("a Socket root")
		}
	}
	for _, a := range dec.Adverse {
		if !goodName(a.Name) || !goodVersion(a.Version) || !hostGrammar.MatchString(a.Host) {
			return bad("an adverse artifact")
		}
	}
	for _, p := range d.Prompts {
		if !classNames[p.Class] || !promptEnded[p.Ended] {
			return bad("a prompt")
		}
	}
	if b := d.Binder; b != nil {
		if code, ok := bindOutcomes[b.Outcome]; !(ok && code == b.Exit) && !(b.Outcome == "unreadable" && b.Exit == 0) {
			return bad("the binder's outcome")
		}
	}
	if s := d.Scripts; s != nil {
		if (s.Source != ScriptsLock && s.Source != ScriptsSource) || (s.Previous != "read" && s.Previous != "none" && s.Previous != "unreadable") || s.Total < 0 || s.UnreadTotal < 0 ||
			s.Other < 0 || s.UnreadOther < 0 {
			return bad("the scripts' header")
		}
		for _, p := range append(append([]ReportScriptP{}, s.Packages...), s.Unread...) {
			if !goodName(p.Name) || !goodVersion(p.Version) || !hostPackageOK(p.Host) {
				return bad("a package with scripts")
			}
			for _, e := range p.Events {
				if !scriptEvents[e] {
					return bad("a script event")
				}
			}
		}
		if s.Root != nil {
			for _, e := range s.Root.Events {
				if !scriptEvents[e] {
					return bad("a root event")
				}
			}
		}
	}
	if s := d.Scan; s != nil {
		if (s.Status != "completed" && s.Status != "not_completed") || !scanReasons[s.Reason] || (s.Status == "completed") != (s.Summary != nil) {
			return bad("the scan's header")
		}
		if s.Summary != nil {
			known := map[string]bool{}
			for _, e := range ScanEcosystems {
				known[e] = true
			}
			for k, v := range s.Summary.Critical {
				if !known[k] || v < 0 {
					return bad("a scan ecosystem")
				}
			}
			for _, g := range s.Summary.CoverageGaps {
				if !scannerName.MatchString(g.Scanner) || !ScanStatuses[g.Status] {
					return bad("a scanner coverage gap")
				}
			}
		}
	}
	return nil
}

// MarshalReportDocument is the one byte form of a document: compact (jq shows it), one trailing newline.
func MarshalReportDocument(d ReportDocument) ([]byte, error) {
	raw, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

// CheckReportDocument reads a document back the way a reader must: exactly one document, no repeated member, no member this schema
// does not name, every token inside its grammar, and the bytes exactly the canonical form of what was read.
func CheckReportDocument(raw []byte) error {
	if len(raw) > MaxReportBytes {
		return errors.New("the document is past its bound")
	}
	if err := strictjson.ExactDocument(raw); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var d ReportDocument
	if err := dec.Decode(&d); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("more than one document")
	}
	if err := ValidateReportDocument(d); err != nil {
		return err
	}
	again, err := MarshalReportDocument(d)
	if err != nil || !bytes.Equal(again, raw) {
		return errors.New("the document is not in its canonical form")
	}
	return nil
}
