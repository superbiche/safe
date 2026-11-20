package projectlane

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/superbiche/safe/internal/strictjson"
)

// The cooldown of the project lane (spec 1625, "Cooldown").
//
// npm's release-age filter is on the projection's command line as a selection
// aid; it decides nothing. The decision is safe's own reading: the publish time
// of every artifact the command introduces, read from its registry per exact
// version (package internal/releases), judged here. An introduced version
// younger than install.cooldown_days is a wait: it names the package, the
// version and the date the version becomes installable.

// ReleasesSchema is the version of the releases document, the strict input of
// the cooldown reading, kept apart from the evidence (like the acceptances) so
// that nobody merges the two.
const ReleasesSchema = 1

// ClassWait is the decision class of an introduced version younger than the
// cooldown that is not exempt. It is resolved after the advisory classes and
// before missing evidence; its exit is the policy's (100), with the date.
const ClassWait = "wait"

// Security-fix modes of install.cooldown_security_fix.
const (
	SecurityFixExempt  = "exempt"
	SecurityFixEnforce = "enforce"
)

// Statuses of one publish-time reading.
//
//   - read: one complete answer gave the version's own publish time.
//   - bounded: one complete answer lists the version without a time of its own;
//     Published is the document's last-modified time, which no publish time in the
//     document can exceed. Older than the cooldown means old enough; younger, the
//     version's age cannot be told and it waits until the bound is old enough.
//   - missing: anything else (the registry unreachable, an error status, a time or
//     size limit, a reading never attempted, an abbreviated or truncated answer,
//     another package's answer, a version the answer does not list, no
//     last-modified time). Missing evidence: refuses 102. There is no gap that
//     lets a version pass unread.
const (
	ReadingRead    = "read"
	ReadingBounded = "bounded"
	ReadingMissing = "missing"
)

// MaxCooldownDays is the longest window the lane honours (100 years); a longer one
// is a configuration the lane refuses, never one it shortens.
const MaxCooldownDays = 36500

const day = 24 * time.Hour

// ReleasePolicy is the operator's cooldown policy: install.cooldown_days (0
// disables) and install.cooldown_security_fix.
type ReleasePolicy struct {
	CooldownDays int    `json:"cooldown_days"`
	SecurityFix  string `json:"security_fix"`
}

// NamedRoot is a version the caller named exactly on the command line.
type NamedRoot struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ReleaseQuery is one identity whose publish time is wanted, with the registry
// host it was resolved from.
type ReleaseQuery struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Host    string `json:"host"`
}

// ReleaseRequest is the input of the reading: the policy, the exact versions
// the caller named, and the identities to read (see CooldownCandidates).
type ReleaseRequest struct {
	SchemaVersion int            `json:"schema_version"`
	Policy        ReleasePolicy  `json:"policy"`
	Roots         []NamedRoot    `json:"roots"`
	Identities    []ReleaseQuery `json:"identities"`
}

// ReleaseReading is what was read for one identity. Status "read" carries the
// publish time (RFC 3339 with its fractional seconds); "bounded" the document's
// last-modified time in its place; "missing" the gap.
type ReleaseReading struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Host      string `json:"host"`
	Root      bool   `json:"root"`
	Status    string `json:"status"`
	Published string `json:"published"`
	Gap       string `json:"gap"`
}

// Releases is the strict, versioned input of the cooldown judgement.
type Releases struct {
	SchemaVersion int              `json:"schema_version"`
	Now           string           `json:"now"`
	Policy        ReleasePolicy    `json:"policy"`
	Identities    []ReleaseReading `json:"identities"`
}

// CooldownCandidate is an identity the cooldown judges, with the registry host
// its publish time is read from.
type CooldownCandidate struct {
	Identity
	Host string
}

// CooldownCandidates is THE place that says which artifacts the cooldown
// judges. The ruling in force (the coordinator's default for the spec's
// unresolved question 1): the cooldown applies to what the command INTRODUCES,
// not to the baseline. A version already in the committed (or recorded)
// lockfile is not checked for its age, whoever locked it; an entry a lockfile on
// disk carries that the baseline does not is introduced, and so is judged. The
// other answer (check every entry a command would fetch that this machine has
// not materialised) changes only this function: the reading, the judgement and
// the report take what it returns.
//
// Only registry artifacts of a public host are read: a private origin's
// versions are not asked of a public registry, and a bundled member's bytes are
// its covering artifact's.
func CooldownCandidates(diff Difference, target Graph) []CooldownCandidate {
	introduced := map[ArtifactKey]struct{}{}
	for _, item := range diff.Introduced {
		introduced[item.ArtifactKey] = struct{}{}
	}
	seen := map[CooldownCandidate]struct{}{}
	var out []CooldownCandidate
	for _, occurrence := range target.Occurrences {
		if _, isIntroduced := introduced[occurrence.Key()]; !isIntroduced {
			continue
		}
		if occurrence.Kind != KindRegistry || !occurrence.Public || occurrence.covered() || occurrence.Host == "" {
			continue
		}
		candidate := CooldownCandidate{Identity: occurrence.Identity(), Host: occurrence.Host}
		if _, dup := seen[candidate]; dup {
			continue
		}
		seen[candidate] = struct{}{}
		out = append(out, candidate)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		return a.Host < b.Host
	})
	return out
}

// CooldownReport is the cooldown's part of the decision report.
type CooldownReport struct {
	Days        int    `json:"days"`
	SecurityFix string `json:"security_fix"`
	// Checked is the number of introduced identities the cooldown judged.
	Checked int `json:"checked"`
	// Waits are the introduced versions inside the cooldown that are not
	// waived, each with the date it becomes installable.
	Waits []CooldownWait `json:"waits"`
	// Waived are the named exact versions inside the cooldown that remediate an
	// advisory, under install.cooldown_security_fix=exempt.
	Waived []CooldownWaiver `json:"waived"`
	// Missing are the identities whose publish time could not be read for any
	// other reason: missing evidence (also in the report's coverage), exit 102.
	Missing []CooldownGap `json:"missing"`
}

// CooldownWait is one version inside the cooldown.
type CooldownWait struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Published   string `json:"published"`
	AgeDays     int    `json:"age_days"`
	Installable string `json:"installable"`
	// Root is true for a version the caller named exactly.
	Root bool `json:"root"`
	// Bounded is true when Published is the registry document's last-modified time, an upper bound of the
	// version's publish time, because the document lists the version without a time of its own.
	Bounded bool `json:"bounded"`
	// Remediates names the advisories the version fixes when it is a named root
	// whose exemption install.cooldown_security_fix=enforce refuses.
	Remediates []string `json:"remediates"`
	Enforced   bool     `json:"enforced"`
	Cleared    bool     `json:"cleared"`
	ClearedBy  []string `json:"cleared_by"`
}

// CooldownWaiver is a named version whose wait the security-fix exemption waived.
type CooldownWaiver struct {
	Name       string   `json:"name"`
	Version    string   `json:"version"`
	Published  string   `json:"published"`
	AgeDays    int      `json:"age_days"`
	Remediates []string `json:"remediates"`
}

// CooldownGap is an identity with no publish time.
type CooldownGap struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Gap     string `json:"gap"`
}

// installable is the instant a version stops being inside the cooldown: its
// publish time plus the cooldown. Whole days, as the age is counted (a version
// published 2.9 days ago is two days old).
func installable(published time.Time, days int) time.Time {
	return published.Add(time.Duration(days) * day)
}

// installableText prints the instant a version becomes installable, rounded UP to
// the second: the printed time is never earlier than eligibility.
func installableText(published time.Time, days int) string {
	at := installable(published, days).UTC()
	if rounded := at.Truncate(time.Second); rounded.Before(at) {
		at = rounded.Add(time.Second)
	}
	return at.Format("2006-01-02T15:04:05Z")
}

// judgeCooldown applies the cooldown to the candidates. A candidate with no
// reading in the document is unreadable (disclosed), never old.
func judgeCooldown(in Input, baseline Graph, decided *Report) (CooldownReport, error) {
	rel := in.Releases
	diff := decided.Difference
	report := CooldownReport{
		Days: rel.Policy.CooldownDays, SecurityFix: rel.Policy.SecurityFix,
		Waits: []CooldownWait{}, Waived: []CooldownWaiver{}, Missing: []CooldownGap{},
	}
	// The security-fix exemption is differential and local: the lane's own advisory reading says which advisories
	// the command removes (the difference's fixed advisories), the baseline says which version each place in the
	// graph held, and the named version is waived only when it REPLACES, at the same place, a baseline version of
	// the same package that one of those advisories affects.
	fixedBy := map[string]map[string]struct{}{}
	for _, fixed := range decided.Advisories.Fixed {
		if fixedBy[fixed.Name] == nil {
			fixedBy[fixed.Name] = map[string]struct{}{}
		}
		fixedBy[fixed.Name][fixed.ID] = struct{}{}
	}
	evidence := indexEvidence(in.Evidence)
	waiverFixes := func(identity Identity) []string {
		held := map[string]Occurrence{} // path -> the baseline's registry occurrence of this package
		for _, occurrence := range baseline.Occurrences {
			if occurrence.Name == identity.Name && occurrence.Public && occurrence.Kind == KindRegistry && !occurrence.covered() {
				held[occurrence.Path] = occurrence
			}
		}
		removed := map[string]struct{}{}
		places := 0
		for _, occurrence := range in.Target.Occurrences {
			if occurrence.Name != identity.Name || occurrence.Version != identity.Version || !occurrence.Public || occurrence.Kind != KindRegistry || occurrence.covered() {
				continue
			}
			places++
			before, ok := held[occurrence.Path]
			if !ok || before.Version == identity.Version {
				// not a replacement at this place: the relation cannot be told, the version waits
				return nil
			}
			affected := 0
			for _, hit := range evidence[before.Identity()].Advisories {
				if _, gone := fixedBy[identity.Name][hit.ID]; gone && !hit.Malware {
					removed[hit.ID] = struct{}{}
					affected++
				}
			}
			if affected == 0 {
				return nil
			}
		}
		if places == 0 {
			return nil
		}
		return sortedIDs(removed)
	}
	if rel.Policy.CooldownDays <= 0 {
		return report, nil
	}
	now, err := time.Parse(time.RFC3339, rel.Now)
	if err != nil {
		return report, fmt.Errorf("releases: now is not a date")
	}
	readings := map[Identity]ReleaseReading{}
	for _, reading := range rel.Identities {
		readings[Identity{Name: reading.Name, Version: reading.Version}] = reading
	}
	done := map[Identity]struct{}{}
	for _, candidate := range CooldownCandidates(diff, in.Target) {
		if _, dup := done[candidate.Identity]; dup {
			continue
		}
		done[candidate.Identity] = struct{}{}
		report.Checked++
		reading, ok := readings[candidate.Identity]
		if !ok {
			// a reading nobody made is missing evidence, never an old version
			report.Missing = append(report.Missing, CooldownGap{Name: candidate.Name, Version: candidate.Version, Gap: "no publish time was supplied for this identity"})
			continue
		}
		switch reading.Status {
		case ReadingMissing:
			report.Missing = append(report.Missing, CooldownGap{Name: candidate.Name, Version: candidate.Version, Gap: reading.Gap})
			continue
		}
		published, err := time.Parse(time.RFC3339, reading.Published)
		if err != nil {
			return report, fmt.Errorf("releases: %s@%s: published is not a date", candidate.Name, candidate.Version)
		}
		age := int(now.Sub(published) / day)
		if age < 0 {
			age = 0
		}
		if age >= rel.Policy.CooldownDays {
			continue
		}
		when := installableText(published, rel.Policy.CooldownDays)
		stamp := published.UTC().Format(time.RFC3339Nano)
		// The exemption belongs to the exact version the caller named, and only where it replaces, at the same
		// place in the graph, a baseline version of the same package that a removed advisory affects. A young
		// version of a package the project does not have yet fixes nothing for this project and waits; so does
		// one whose relation to the baseline cannot be told; a young fix nobody named is not selected; another
		// young version of the same name is a wait of its own.
		var fixes []string
		if reading.Root {
			fixes = waiverFixes(candidate.Identity)
		}
		if len(fixes) > 0 && rel.Policy.SecurityFix == SecurityFixExempt {
			report.Waived = append(report.Waived, CooldownWaiver{
				Name: candidate.Name, Version: candidate.Version, Published: stamp, AgeDays: age, Remediates: fixes,
			})
			continue
		}
		wait := CooldownWait{
			Name: candidate.Name, Version: candidate.Version, Published: stamp, AgeDays: age, Installable: when,
			Root: reading.Root, Bounded: reading.Status == ReadingBounded, Remediates: []string{}, ClearedBy: []string{},
		}
		if len(fixes) > 0 {
			wait.Remediates, wait.Enforced = fixes, true
		}
		wait.Cleared, wait.ClearedBy = waitCleared(candidate.Identity, in)
		report.Waits = append(report.Waits, wait)
	}
	return report, nil
}

// waitCleared says whether a standing acceptance clears a wait on every
// artifact that carries the identity. The authorities are the adverse
// advisory's (a local exact approval, a followed grant, a followed install
// allowance): a release that is too young is a WARN cause of today's gate, which
// those clear.
func waitCleared(identity Identity, in Input) (bool, []string) {
	used := map[string]struct{}{}
	carried := 0
	seen := map[string]struct{}{}
	for _, occurrence := range in.Target.Occurrences {
		if occurrence.Name != identity.Name || occurrence.Version != identity.Version || !occurrence.Public {
			continue
		}
		marker := keyText(occurrence.Key()) + "\x00" + occurrence.Host + "\x00" + occurrence.CoveredBy + "\x00" + occurrence.Member
		if _, dup := seen[marker]; dup {
			continue
		}
		seen[marker] = struct{}{}
		carried++
		kind, ok := clearingAcceptance(AdvisoryAdverse, occurrence, in.Evidence, nil)
		if !ok {
			return false, []string{}
		}
		used[kind] = struct{}{}
	}
	if carried == 0 {
		return false, []string{}
	}
	return true, sortedIDs(used)
}

func sortedUnique(ids []string) []string {
	set := map[string]struct{}{}
	for _, id := range ids {
		set[id] = struct{}{}
	}
	return sortedIDs(set)
}

func waitClass(report CooldownReport) ClassOutcome {
	outcome := ClassOutcome{Class: ClassWait, Exit: ExitPolicy}
	for _, wait := range report.Waits {
		outcome.AtStake++
		if !wait.Cleared {
			outcome.Outstanding++
		}
	}
	return outcome
}

// ReadReleases decodes a releases document strictly, like the evidence: no
// repeated member, no unknown member, every member present, every value in its
// domain. A document that cannot be read is an error, never an empty reading.
func ReadReleases(raw []byte) (Releases, error) {
	if err := strictjson.RejectRepeatedMembers(raw); err != nil {
		return Releases{}, fmt.Errorf("releases: %w", err)
	}
	var shape map[string]any
	if err := json.Unmarshal(raw, &shape); err != nil || shape == nil {
		return Releases{}, fmt.Errorf("releases: not a JSON object")
	}
	if err := requireKeys(shape, "", "schema_version", "now", "policy", "identities"); err != nil {
		return Releases{}, fmt.Errorf("releases: %w", err)
	}
	if err := requireKeys(asObject(shape["policy"]), "policy.", "cooldown_days", "security_fix"); err != nil {
		return Releases{}, fmt.Errorf("releases: %w", err)
	}
	items, ok := shape["identities"].([]any)
	if !ok {
		return Releases{}, fmt.Errorf("releases: identities must be a list")
	}
	for i, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			return Releases{}, fmt.Errorf("releases: identities[%d] must be an object", i)
		}
		if err := requireKeys(object, fmt.Sprintf("identities[%d].", i), "name", "version", "host", "root", "status", "published", "gap"); err != nil {
			return Releases{}, fmt.Errorf("releases: %w", err)
		}
	}
	var releases Releases
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&releases); err != nil {
		return Releases{}, fmt.Errorf("releases: %w", err)
	}
	if decoder.More() {
		return Releases{}, fmt.Errorf("releases: more than one JSON document")
	}
	if err := releases.validate(); err != nil {
		return Releases{}, fmt.Errorf("releases: %w", err)
	}
	return releases, nil
}

func asObject(value any) map[string]any {
	object, _ := value.(map[string]any)
	if object == nil {
		return map[string]any{}
	}
	return object
}

func (p ReleasePolicy) validate() error {
	if p.CooldownDays < 0 || p.CooldownDays > MaxCooldownDays {
		return fmt.Errorf("policy.cooldown_days must be between 0 and %d", MaxCooldownDays)
	}
	if p.SecurityFix != SecurityFixExempt && p.SecurityFix != SecurityFixEnforce {
		return fmt.Errorf("policy.security_fix must be exempt or enforce")
	}
	return nil
}

func (r Releases) validate() error {
	if r.SchemaVersion != ReleasesSchema {
		return fmt.Errorf("unsupported schema_version %d (this reader knows %d)", r.SchemaVersion, ReleasesSchema)
	}
	if _, err := time.Parse(time.RFC3339, r.Now); err != nil {
		return fmt.Errorf("now is not a date")
	}
	if err := r.Policy.validate(); err != nil {
		return err
	}
	seen := map[Identity]struct{}{}
	for i, reading := range r.Identities {
		if reading.Name == "" || reading.Version == "" {
			return fmt.Errorf("identities[%d]: name and version are required", i)
		}
		key := Identity{Name: reading.Name, Version: reading.Version}
		if _, dup := seen[key]; dup {
			return fmt.Errorf("identities[%d]: %s@%s is given more than once", i, key.Name, key.Version)
		}
		seen[key] = struct{}{}
		switch reading.Status {
		case ReadingRead:
			if _, err := time.Parse(time.RFC3339, reading.Published); err != nil || reading.Gap != "" {
				return fmt.Errorf("identities[%d]: a reading carries a publish time and no gap", i)
			}
		case ReadingBounded:
			if _, err := time.Parse(time.RFC3339, reading.Published); err != nil || reading.Gap != "" {
				return fmt.Errorf("identities[%d]: a bounded reading carries the last-modified time and no gap", i)
			}
		case ReadingMissing:
			if reading.Published != "" || reading.Gap == "" {
				return fmt.Errorf("identities[%d]: a reading without a time carries a gap and no publish time", i)
			}
		default:
			return fmt.Errorf("identities[%d]: unknown status %q", i, reading.Status)
		}
	}
	return nil
}

// ReadReleaseRequest decodes the request of the reading strictly.
func ReadReleaseRequest(raw []byte) (ReleaseRequest, error) {
	if err := strictjson.RejectRepeatedMembers(raw); err != nil {
		return ReleaseRequest{}, fmt.Errorf("release request: %w", err)
	}
	var shape map[string]any
	if err := json.Unmarshal(raw, &shape); err != nil || shape == nil {
		return ReleaseRequest{}, fmt.Errorf("release request: not a JSON object")
	}
	if err := requireKeys(shape, "", "schema_version", "policy", "roots", "identities"); err != nil {
		return ReleaseRequest{}, fmt.Errorf("release request: %w", err)
	}
	var request ReleaseRequest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return ReleaseRequest{}, fmt.Errorf("release request: %w", err)
	}
	if request.SchemaVersion != ReleasesSchema {
		return ReleaseRequest{}, fmt.Errorf("release request: unsupported schema_version %d", request.SchemaVersion)
	}
	if err := request.Policy.validate(); err != nil {
		return ReleaseRequest{}, fmt.Errorf("release request: %w", err)
	}
	if request.Roots == nil || request.Identities == nil {
		return ReleaseRequest{}, fmt.Errorf("release request: roots and identities must be lists")
	}
	for i, item := range request.Identities {
		if item.Name == "" || item.Version == "" || item.Host == "" {
			return ReleaseRequest{}, fmt.Errorf("release request: identities[%d]: name, version and host are required", i)
		}
	}
	return request, nil
}
