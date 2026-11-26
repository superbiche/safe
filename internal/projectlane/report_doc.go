package projectlane

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
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

// MaxReportBytes is the bound on one document. Past it the document is not written (never cut short). 1 MiB: measured on a
// document of a 1000-entry install with an advisory on every entry, which is 164 KB (the test that states the measure).
const MaxReportBytes = 1 << 20

// The closed lists.
var (
	reportVerbs  = map[string]bool{"install": true, "ci": true, "update": true, "dedupe": true, "prune": true}
	reportEnds   = map[string]bool{"published": true, "published_lockfile": true, "dry_run": true, "refused": true, "declined": true, "unread_answer": true, "stopped": true, "bind_refused": true, "install_failed": true, "verification_failed": true, "inputs_changed": true, "interrupted": true, "publication_failed": true, "install_unsettled": true, "bind_unreadable": true}
	bindOutcomes = map[string]int{"published": 0, "refused": 30, "install_failed": 31, "verification_failed": 32, "inputs_changed": 33, "interrupted": 34, "publication_failed": 35, "install_unsettled": 36}
	reportEnded  = map[string]bool{"none": true, "accepted": true, "declined": true, "unread": true}
	severities   = map[string]bool{"critical": true, "high": true, "moderate": true, "low": true, "unknown": true}
	advClasses   = map[string]bool{AdvisoryBlocking: true, AdvisoryAdverse: true, AdvisoryBelowHigh: true}
	maliceSignal = map[string]bool{"blocklist": true, "malware_record": true, "socket_block": true}
	baselines    = map[string]bool{baselineGraph: true, baselineEmpty: true, baselineUnreadable: true}
	outcomeState = map[string]bool{"clear": true, "stopped": true, "unbound": true}
	outcomeClass = map[string]bool{"": true, ClassMalice: true, ClassBlockingAdvisory: true, ClassAdverseAdvisory: true, ClassMissingEvidence: true, "wait": true, "socket_root": true}
	socketOut    = map[string]bool{SocketAdverse: true, "rate_limited": true, "consent_required": true, "pending": true, "unavailable": true, "clear": true, "ok": true}
	answerClass  = map[string]bool{ClassMalice: true, ClassBlockingAdvisory: true, ClassAdverseAdvisory: true, ClassMissingEvidence: true, "wait": true, "socket_root": true}
	scriptEvents = map[string]bool{"preinstall": true, "install": true, "postinstall": true, "prepublish": true, "preprepare": true, "prepare": true, "postprepare": true}
	scanReasons  = map[string]bool{"": true, "no_audit": true, "no_timeout": true, "timeout": true, "failed": true, "no_result": true}
)

var (
	nameGrammar    = regexp.MustCompile(`\A(?:@[A-Za-z0-9~][A-Za-z0-9._~-]{0,213}/)?[A-Za-z0-9~][A-Za-z0-9._~-]{0,213}\z`)
	versionGrammar = regexp.MustCompile(`\A[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.+-]{1,64})?\z`)
	idGrammar      = regexp.MustCompile(`\A[A-Za-z0-9][A-Za-z0-9._:-]{0,95}\z`)
	digestGrammar  = regexp.MustCompile(`\A(?:sha256:[0-9a-f]{64}|absent|unreadable)\z`)
	safeVersion    = regexp.MustCompile(`\A[0-9A-Za-z][0-9A-Za-z.+-]{0,31}\z`)
	timeGrammar    = regexp.MustCompile(`\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\z`)
	hostGrammar    = regexp.MustCompile(`\A[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\z`)
)

func goodName(s string) bool    { return nameGrammar.MatchString(s) }
func goodVersion(s string) bool { return versionGrammar.MatchString(s) }

// ReportDocument is the document.
type ReportDocument struct {
	SchemaVersion  int            `json:"schema_version"`
	WrittenAt      string         `json:"written_at"`
	SafeVersion    string         `json:"safe_version"`
	Command        ReportCommand  `json:"command"`
	End            string         `json:"end"`
	Status         int            `json:"status"`
	Passed         bool           `json:"passed"`
	LockfileSHA256 string         `json:"lockfile_sha256"`
	Decision       ReportDecision `json:"decision"`
	Prompts        ReportPrompts  `json:"prompts"`
	Binder         *ReportBinder  `json:"binder"`
	Scripts        *ReportScripts `json:"scripts"`
	Scan           *ReportScan    `json:"scan"`
}

// ReportCommand is the command as the lane saw it, from closed values: the arguments of the command are not kept.
type ReportCommand struct {
	Verb            string `json:"verb"`
	DryRun          bool   `json:"dry_run"`
	PackageLockOnly bool   `json:"package_lock_only"`
}

// ReportDecision is what the decision found. Counts for the difference (never the list of entries), identities for findings.
type ReportDecision struct {
	Baseline        string           `json:"baseline"`
	Outcome         ReportOutcome    `json:"outcome"`
	Entries         int              `json:"entries"`
	Added           int              `json:"added"`
	Changed         int              `json:"changed"`
	Removed         int              `json:"removed"`
	Introduced      int              `json:"introduced"`
	Fixed           []ReportAdvisory `json:"fixed"`
	AlreadyPresent  []ReportPresent  `json:"already_present"`
	PresentBy       map[string]int   `json:"already_present_by_severity"`
	IntroducedAdv   []ReportAdvisory `json:"introduced_advisories"`
	AdvisoriesOther int              `json:"advisories_other"`
	Malice          []ReportMalice   `json:"malice"`
	MaliceOther     int              `json:"malice_other"`
	CoverageGaps    int              `json:"coverage_gaps"`
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

// ReportCooldown is the release-age judgement.
type ReportCooldown struct {
	Days    int          `json:"days"`
	Checked int          `json:"checked"`
	Waits   []ReportWait `json:"waits"`
	Other   int          `json:"waits_other"`
	Missing int          `json:"missing"`
}

// ReportWait is a version inside the cooldown.
type ReportWait struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ReportSocket is the Socket judgement of a named root.
type ReportSocket struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Outcome string `json:"outcome"`
}

// ReportAdverse is an exact artifact the decision's evidence is on; the host is where its bytes came from, never a location.
type ReportAdverse struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Host    string `json:"host"`
}

// ReportPrompts is what the lane asked and how it ended.
type ReportPrompts struct {
	Asked    int            `json:"asked"`
	Ended    string         `json:"ended"`
	Answered []ReportAnswer `json:"answered"`
	Other    int            `json:"answered_other"`
}

// ReportAnswer is an answer the operator gave, as the lane recorded it.
type ReportAnswer struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Class   string `json:"class"`
}

// ReportBinder is what the binder said.
type ReportBinder struct {
	Outcome string `json:"outcome"`
	Exit    int    `json:"exit"`
}

// ReportScripts is the scripts the command left unrun: the identities and the closed events, no path.
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

// ReportScan is the scan's summary and the digest of the lockfile it read: not its full result.
type ReportScan struct {
	Status         string       `json:"status"`
	Reason         string       `json:"reason"`
	Summary        *ScanSummary `json:"summary"`
	LockfileSHA256 string       `json:"lockfile_sha256"`
	LockfileStable bool         `json:"lockfile_stable"`
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
	Asked           int
	Ended           string
	LockfileDigest  string
	Report          []byte
	Bind            []byte
	Answered        []byte
	Scripts         []byte
	Scan            []byte
	Graph           []byte
}

// ErrNoDecision: the run left no decision report: nothing is written, the command ended before it.
var ErrNoDecision = errors.New("the run left no readable decision report")

func capped(n int) int {
	if n < 0 {
		return 0
	}
	return n
}

// BuildReportDocument builds the document from the pieces. A piece that cannot be read is said in the document (the binder as
// "bind_unreadable", the scripts and the scan as absent); only the decision report is required.
func BuildReportDocument(in ReportInputs) (ReportDocument, error) {
	doc := ReportDocument{SchemaVersion: ReportDocumentSchema, WrittenAt: in.Now.UTC().Format("2006-01-02T15:04:05Z"), SafeVersion: in.SafeVersion,
		Command: ReportCommand{Verb: in.Verb, DryRun: in.DryRun, PackageLockOnly: in.PackageLockOnly}, Status: in.Status, LockfileSHA256: in.LockfileDigest}
	var report Report
	if err := json.Unmarshal(in.Report, &report); err != nil || report.SchemaVersion != ReportSchema || !outcomeState[report.Outcome.Status] {
		return doc, ErrNoDecision
	}
	doc.Decision = decisionOf(report)
	doc.Decision.Entries = entriesOf(in.Graph)
	doc.Prompts = promptsOf(in)
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

func endOf(in ReportInputs, doc ReportDocument) string {
	// a signal ended the command before the binder reported anything usable
	if in.Status > 128 && in.Status < 193 && !in.DryRun && (doc.Binder == nil || doc.Binder.Outcome == "unreadable") {
		return "interrupted"
	}
	if doc.Binder != nil {
		switch {
		case doc.Binder.Outcome == "unreadable":
			return "bind_unreadable"
		case doc.Binder.Outcome == "published":
			switch in.Published {
			case "tree":
				return "published"
			case "lockfile":
				return "published_lockfile"
			}
			return "bind_unreadable"
		case doc.Binder.Outcome == "refused":
			return "bind_refused"
		default:
			return doc.Binder.Outcome
		}
	}
	switch {
	case doc.Prompts.Ended == "declined":
		return "declined"
	case doc.Prompts.Ended == "unread":
		return "unread_answer"
	case doc.Decision.Outcome.Status != "clear":
		return "refused"
	case in.DryRun:
		return "dry_run"
	}
	return "stopped"
}

func decisionOf(r Report) ReportDecision {
	d := ReportDecision{Baseline: r.Baseline.Source, Outcome: ReportOutcome{Status: r.Outcome.Status, Class: r.Outcome.Class, Exit: r.Outcome.Exit},
		Added: len(r.Difference.Added), Changed: len(r.Difference.Changed), Removed: len(r.Difference.Removed), Introduced: len(r.Difference.Introduced),
		Fixed: []ReportAdvisory{}, AlreadyPresent: []ReportPresent{}, PresentBy: map[string]int{}, IntroducedAdv: []ReportAdvisory{},
		Malice: []ReportMalice{}, Socket: []ReportSocket{}, Adverse: []ReportAdverse{}, CoverageGaps: len(r.Coverage), Unjudged: r.Unjudged, GapConfirmed: r.GapConfirmed}
	d.Cooldown.Waits = []ReportWait{}
	if !baselines[d.Baseline] {
		d.Baseline = baselineUnreadable
	}
	if !outcomeClass[d.Outcome.Class] {
		d.Outcome.Class = ""
	}
	d.Outcome.Exit = capped(d.Outcome.Exit)
	if d.Outcome.Exit > 255 {
		d.Outcome.Exit = 255
	}
	for _, a := range r.Advisories.Fixed {
		if goodName(a.Name) && idGrammar.MatchString(a.ID) {
			d.Fixed = append(d.Fixed, ReportAdvisory{Name: a.Name, ID: a.ID, Severity: severityOf(a.Severity), Class: ""})
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
		versions := []string{}
		ok := goodName(m.Name) && maliceSignal[m.Signal] && (m.ID == "" || idGrammar.MatchString(m.ID))
		for _, v := range m.Versions {
			if !goodVersion(v) {
				ok = false
				break
			}
			versions = append(versions, v)
		}
		if ok {
			d.Malice = append(d.Malice, ReportMalice{Signal: m.Signal, Name: m.Name, Versions: versions, ID: m.ID, Overridden: m.Overridden})
		} else {
			d.MaliceOther++
		}
	}
	if r.Cooldown != nil {
		d.Cooldown.Days = capped(r.Cooldown.Days)
		d.Cooldown.Checked = capped(r.Cooldown.Checked)
		d.Cooldown.Missing = len(r.Cooldown.Missing)
		for _, w := range r.Cooldown.Waits {
			if goodName(w.Name) && goodVersion(w.Version) {
				d.Cooldown.Waits = append(d.Cooldown.Waits, ReportWait{Name: w.Name, Version: w.Version})
			} else {
				d.Cooldown.Other++
			}
		}
	}
	if r.Socket != nil {
		for _, s := range r.Socket.Roots {
			if goodName(s.Name) && goodVersion(s.Version) && socketOut[s.Outcome] {
				d.Socket = append(d.Socket, ReportSocket{Name: s.Name, Version: s.Version, Outcome: s.Outcome})
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

func severityOf(s string) string {
	if severities[s] {
		return s
	}
	return "unknown"
}

func promptsOf(in ReportInputs) ReportPrompts {
	p := ReportPrompts{Asked: capped(in.Asked), Ended: in.Ended, Answered: []ReportAnswer{}}
	if !reportEnded[p.Ended] {
		p.Ended = "none"
	}
	for _, line := range strings.Split(string(in.Answered), "\n") {
		if line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) >= 3 && goodName(f[0]) && goodVersion(f[1]) && answerClass[f[2]] {
			p.Answered = append(p.Answered, ReportAnswer{Name: f[0], Version: f[1], Class: f[2]})
		} else {
			p.Other++
		}
	}
	return p
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
			host := p.Host
			if host != "" {
				at := strings.LastIndex(host, "@")
				ok = ok && at > 0 && goodName(host[:at]) && goodVersion(host[at+1:])
			}
			if ok && goodName(p.Name) && goodVersion(p.Version) {
				*dst = append(*dst, ReportScriptP{Name: p.Name, Version: p.Version, Host: host, Events: events, Gyp: p.Gyp, Declared: p.Declared})
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
		Status         string       `json:"status"`
		Reason         string       `json:"reason"`
		Summary        *ScanSummary `json:"summary"`
		LockfileSHA256 string       `json:"lockfile_sha256"`
		LockfileStable bool         `json:"lockfile_stable"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil
	}
	out := &ReportScan{Status: s.Status, Reason: s.Reason, LockfileSHA256: s.LockfileSHA256, LockfileStable: s.LockfileStable}
	if s.Summary != nil {
		summary := *s.Summary
		clean := ScanSummary{SchemaVersion: 1, CriticalTotal: capped(summary.CriticalTotal), Critical: map[string]int{}, Unattributed: capped(summary.Unattributed),
			CoverageFailures: []string{}, CoverageOther: capped(summary.CoverageOther)}
		known := map[string]bool{}
		for _, e := range ScanEcosystems {
			known[e] = true
		}
		for k, v := range summary.Critical {
			if known[k] && v > 0 {
				clean.Critical[k] = v
			} else {
				clean.Unattributed += capped(v)
			}
		}
		for _, n := range summary.CoverageFailures {
			if scannerName.MatchString(n) {
				clean.CoverageFailures = append(clean.CoverageFailures, n)
			} else {
				clean.CoverageOther++
			}
		}
		sort.Strings(clean.CoverageFailures)
		out.Summary = &clean
	}
	if (out.Status != "completed" && out.Status != "not_completed") || !scanReasons[out.Reason] || !digestGrammar.MatchString(out.LockfileSHA256) ||
		(out.Status == "completed") != (out.Summary != nil) {
		return nil
	}
	return out
}

// ValidateReportDocument holds every token of the document to its grammar or closed list.
func ValidateReportDocument(d ReportDocument) error {
	bad := func(what string) error { return fmt.Errorf("%s is outside its grammar", what) }
	if d.SchemaVersion != ReportDocumentSchema {
		return bad("schema_version")
	}
	if !timeGrammar.MatchString(d.WrittenAt) || !safeVersion.MatchString(d.SafeVersion) || !digestGrammar.MatchString(d.LockfileSHA256) {
		return bad("written_at, safe_version or lockfile_sha256")
	}
	if !reportVerbs[d.Command.Verb] || !reportEnds[d.End] || d.Status < 0 || d.Status > 255 {
		return bad("verb, end or status")
	}
	if d.Passed != ((d.End == "published" || d.End == "published_lockfile") && d.Status == 0) {
		return errors.New("passed does not follow from the end and the status")
	}
	dec := d.Decision
	if !baselines[dec.Baseline] || !outcomeState[dec.Outcome.Status] || !outcomeClass[dec.Outcome.Class] || dec.Outcome.Exit < 0 || dec.Outcome.Exit > 255 {
		return bad("the decision's baseline or outcome")
	}
	for _, n := range []int{dec.Entries, dec.Added, dec.Changed, dec.Removed, dec.Introduced, dec.AdvisoriesOther, dec.MaliceOther, dec.CoverageGaps, dec.Cooldown.Days,
		dec.Cooldown.Checked, dec.Cooldown.Other, dec.Cooldown.Missing, dec.SocketOther, dec.AdverseOther, d.Prompts.Asked, d.Prompts.Other} {
		if n < 0 {
			return bad("a count")
		}
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
		if !goodName(m.Name) || !maliceSignal[m.Signal] || (m.ID != "" && !idGrammar.MatchString(m.ID)) {
			return bad("a malice fact")
		}
		for _, v := range m.Versions {
			if !goodVersion(v) {
				return bad("a malice version")
			}
		}
	}
	for _, w := range dec.Cooldown.Waits {
		if !goodName(w.Name) || !goodVersion(w.Version) {
			return bad("a cooldown wait")
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
	if !reportEnded[d.Prompts.Ended] {
		return bad("the end of the prompts")
	}
	for _, a := range d.Prompts.Answered {
		if !goodName(a.Name) || !goodVersion(a.Version) || !answerClass[a.Class] {
			return bad("an answer")
		}
	}
	if b := d.Binder; b != nil {
		if code, ok := bindOutcomes[b.Outcome]; !(ok && code == b.Exit) && !(b.Outcome == "unreadable" && b.Exit == 0) {
			return bad("the binder's outcome")
		}
	}
	if s := d.Scripts; s != nil {
		if (s.Source != ScriptsLock && s.Source != ScriptsSource) || (s.Previous != "read" && s.Previous != "none" && s.Previous != "unreadable") || s.Total < 0 || s.UnreadTotal < 0 {
			return bad("the scripts' header")
		}
		for _, p := range append(append([]ReportScriptP{}, s.Packages...), s.Unread...) {
			if !goodName(p.Name) || !goodVersion(p.Version) {
				return bad("a package with scripts")
			}
			if p.Host != "" {
				at := strings.LastIndex(p.Host, "@")
				if at <= 0 || !goodName(p.Host[:at]) || !goodVersion(p.Host[at+1:]) {
					return bad("a host package")
				}
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
		if (s.Status != "completed" && s.Status != "not_completed") || !scanReasons[s.Reason] || !digestGrammar.MatchString(s.LockfileSHA256) || (s.Status == "completed") != (s.Summary != nil) {
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
			for _, n := range s.Summary.CoverageFailures {
				if !scannerName.MatchString(n) {
					return bad("a scanner name")
				}
			}
		}
	}
	return nil
}

// MarshalReportDocument is the one byte form of a document: indented, one trailing newline.
func MarshalReportDocument(d ReportDocument) ([]byte, error) {
	raw, err := json.MarshalIndent(d, "", "  ")
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
