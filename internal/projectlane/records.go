package projectlane

import (
	"sort"
	"strings"
)

// Install records (spec 1625, "Records and export").
//
// The decision says which artifacts the command may leave an install record for; the gate writes them, and only after the
// binder reports a verified, published tree. Records are for NAMED ROOTS only, as today's gate records a named install and
// never the transitive packages a project install brings: a record is exported as an install allowance, which lets a
// follower install that exact version by name in place of the Socket consent, pending and warning outcomes, so it must rest
// on a Socket reading of the artifact. The kinds that are eligible:
//
//   - a named root the command introduces whose OWN evidence is complete (its advisory reading, its publish time and its
//     Socket reading) and clean or below high (verdict GO);
//   - a named root cleared by the operator's local standing tolerance (verdict WARN_TOLERATED).
//
// Every introduced artifact nobody named is excluded, whatever its evidence; so is a root whose Socket reading is anything
// but clear or tolerated. A bare install, update, ci, dedupe or prune names no root and records nothing.
//
// A third kind, a named root whose outcome the operator CONFIRMED at a terminal, is the operator terminal's ticket (1684):
// it needs a prompt, and its place is here, next to the other two, as a record of the confirmed outcome.
//
// Never recorded: an artifact that passed only because its advisories were already present in the project (any advisory at
// high or above on the artifact itself, introduced or not, disqualifies it), one cleared by another authority (a local
// approval, a followed grant, a followed install allowance: that decision is already stored, or is another origin's and is
// never exported again), a command confirmed on missing evidence, a block override, the one-shot route.

// Record verdicts, the tokens `install-known.json` holds and the signed export reads. The gate does not write them: it asks
// today's auditor to audit the root, and that audit decides what it records.
const (
	RecordClean     = "GO"
	RecordTolerated = "WARN_TOLERATED"
)

// RecordItem is one named root the decision leaves eligible for an install record. It is a filter, never a verdict the
// gate takes to a store.
type RecordItem struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Host    string `json:"host"`
	Verdict string `json:"verdict"`
}

// recordsFor lists the eligible named roots of a CLEAR decision. It is empty for any other outcome.
func recordsFor(report Report, in Input, evidence evidenceIndex) []RecordItem {
	records := []RecordItem{}
	if report.Outcome.Status != "clear" || commandExcluded(report, in) {
		return records
	}
	introduced := map[ArtifactKey]struct{}{}
	for _, item := range report.Difference.Introduced {
		introduced[item.ArtifactKey] = struct{}{}
	}
	blockSet := map[string]struct{}{}
	for _, severity := range in.Evidence.Policy.BlockSeverities {
		blockSet[severity] = struct{}{}
	}
	waits := map[Identity]CooldownWait{}
	if report.Cooldown != nil {
		for _, wait := range report.Cooldown.Waits {
			waits[Identity{Name: wait.Name, Version: wait.Version}] = wait
		}
	}
	roots := map[Identity]SocketRootReport{}
	if report.Socket != nil {
		for _, root := range report.Socket.Roots {
			roots[Identity{Name: root.Name, Version: root.Version}] = root
		}
	}
	// with a cooldown set, the publish time of a root is part of its evidence: an exact reading of the registry's own record
	// (a bound from the document's last-modified time is not one). With the cooldown off (days 0) the operator has switched
	// age off, and a root is as eligible as today's gate makes it.
	needsPublishTime := in.Releases != nil && in.Releases.Policy.CooldownDays > 0
	published := map[Identity]struct{}{}
	if in.Releases != nil {
		for _, reading := range in.Releases.Identities {
			if reading.Status == ReadingRead {
				published[Identity{Name: reading.Name, Version: reading.Version}] = struct{}{}
			}
		}
	}
	seen := map[Identity]struct{}{}
	for _, occurrence := range in.Target.Occurrences {
		identity := occurrence.Identity()
		if _, dup := seen[identity]; dup || !occurrence.Public || occurrence.Kind != KindRegistry || occurrence.covered() || occurrence.Host == "" {
			continue
		}
		if _, isNew := introduced[occurrence.Key()]; !isNew {
			continue
		}
		seen[identity] = struct{}{}
		root, named := roots[identity]
		if !named {
			continue // nobody named it: no Socket reading, no record
		}
		// one eligibility rule for both writers, over the root and the bytes it carries (a bundled member is the root's own
		// bytes): nothing here is accepted by an answer, so any advisory at high or above on those bytes, introduced or not,
		// excludes the root
		if !rootBytesEligible(in, evidence, blockSet, identity, occurrence.Host, needsPublishTime, published, nil) {
			continue
		}
		tolerated := false
		if wait, waited := waits[identity]; waited {
			if !onlyTolerance(wait.ClearedBy) {
				continue
			}
			tolerated = true
		}
		switch {
		case root.Outcome == SocketClear:
		case onlyTolerance(root.ClearedBy):
			tolerated = true
		default:
			continue // cleared by another authority, or confirmed at a terminal (1684): not this ticket's record
		}
		item := RecordItem{Name: identity.Name, Version: identity.Version, Host: occurrence.Host, Verdict: RecordClean}
		if tolerated {
			item.Verdict = RecordTolerated
		}
		records = append(records, item)
	}
	return records
}

// rootBytes is the root and every member of the same source its bytes carry.
func rootBytes(in Input, identity Identity, host string) []Identity {
	out := []Identity{identity}
	for _, member := range in.Target.Occurrences {
		if member.CoveredBy != "" && member.coverName == identity.Name && member.coverVersion == identity.Version && strings.EqualFold(member.Host, host) {
			out = append(out, member.Identity())
		}
	}
	return out
}

// rootBytesEligible is THE eligibility rule of a record, ordinary or confirmed: the root's own evidence is complete, its publish
// time is read where a cooldown is set, and no advisory at high or above stands on any byte it carries unless `accepted` says the
// operator accepted that exact finding in this command (the ordinary writer accepts none).
func rootBytesEligible(in Input, evidence evidenceIndex, blockSet map[string]struct{}, identity Identity, host string, needsPublishTime bool, published map[Identity]struct{}, accepted func(member Identity, id string) bool) bool {
	read, ok := evidence[identity]
	if !ok || read.Coverage != CoverageComplete {
		return false
	}
	if _, read := published[identity]; needsPublishTime && !read {
		return false
	}
	for _, member := range rootBytes(in, identity, host) {
		for _, hit := range evidence[member].Advisories {
			if !hit.Malware && severityClass(hit.Severity, blockSet) == AdvisoryBelowHigh {
				continue
			}
			if accepted == nil || !accepted(member, hit.ID) {
				return false
			}
		}
	}
	return true
}

func onlyTolerance(kinds []string) bool {
	return len(kinds) == 1 && kinds[0] == AcceptLocalTolerance
}

// adverseIdentities lists the exact artifacts (name, version, source host) a receipt of which the decision's evidence
// supersedes, whatever the outcome: the identity the evidence is on (malice, a blocking or adverse introduced advisory, a
// Socket finding on a named root, a version inside the cooldown) AND the artifact whose bytes carry it (a bundled member's
// covering artifact). The gate removes those receipts locally; there is no limit on their number.
func adverseIdentities(report Report, in Input) []AdverseItem {
	set := map[Identity]struct{}{}
	for _, item := range report.Malice {
		for _, version := range item.Versions {
			set[Identity{Name: item.Name, Version: version}] = struct{}{}
		}
	}
	for _, item := range report.Advisories.Introduced {
		if item.Class == AdvisoryBlocking || item.Class == AdvisoryAdverse {
			for _, version := range item.Versions {
				set[Identity{Name: item.Name, Version: version}] = struct{}{}
			}
		}
	}
	if report.Socket != nil {
		for _, root := range report.Socket.Roots {
			if root.Outcome == SocketAdverse || root.Outcome == SocketBlocked {
				set[Identity{Name: root.Name, Version: root.Version}] = struct{}{}
			}
		}
	}
	if report.Cooldown != nil {
		for _, wait := range report.Cooldown.Waits {
			set[Identity{Name: wait.Name, Version: wait.Version}] = struct{}{}
		}
	}
	type key struct{ name, version, host string }
	items := map[key]struct{}{}
	for _, occurrence := range in.Target.Occurrences {
		if _, adverse := set[occurrence.Identity()]; !adverse || !occurrence.Public || occurrence.Host == "" {
			continue
		}
		host := strings.ToLower(occurrence.Host)
		items[key{occurrence.Name, occurrence.Version, host}] = struct{}{}
		coverName, coverVersion := coverArtifact(occurrence)
		items[key{coverName, coverVersion, host}] = struct{}{}
	}
	out := make([]AdverseItem, 0, len(items))
	for k := range items {
		out = append(out, AdverseItem{Name: k.name, Version: k.version, Host: k.host})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		if out[i].Version != out[j].Version {
			return out[i].Version < out[j].Version
		}
		return out[i].Host < out[j].Host
	})
	return out
}

// wantedAcceptances lists the artifacts whose standing acceptances the decision would use: for every item still
// outstanding, the artifact whose bytes carry it, with the blocking advisories introduced under those bytes.
func wantedAcceptances(report Report, in Input) []WantedAcceptance {
	type key struct{ name, version, host string }
	wanted := map[key]map[string]struct{}{}
	add := func(name, version string) {
		for _, occurrence := range in.Target.Occurrences {
			if occurrence.Name != name || occurrence.Version != version || !occurrence.Public || occurrence.Host == "" {
				continue
			}
			coverName, coverVersion := coverArtifact(occurrence)
			k := key{coverName, coverVersion, strings.ToLower(occurrence.Host)}
			if wanted[k] == nil {
				wanted[k] = map[string]struct{}{}
			}
			for id := range report.coverBlocking[coverKey(occurrence)] {
				wanted[k][id] = struct{}{}
			}
		}
	}
	for _, item := range report.Advisories.Introduced {
		if item.Class == AdvisoryBelowHigh || item.Cleared {
			continue
		}
		for _, version := range item.Versions {
			add(item.Name, version)
		}
	}
	if report.Cooldown != nil {
		for _, wait := range report.Cooldown.Waits {
			if !wait.Cleared {
				add(wait.Name, wait.Version)
			}
		}
	}
	if report.Socket != nil {
		for _, root := range report.Socket.Roots {
			if !root.Cleared {
				add(root.Name, root.Version)
			}
		}
	}
	out := make([]WantedAcceptance, 0, len(wanted))
	for k, ids := range wanted {
		out = append(out, WantedAcceptance{Name: k.name, Version: k.version, Host: k.host, BlockingAdvisories: sortedIDs(ids)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		if out[i].Version != out[j].Version {
			return out[i].Version < out[j].Version
		}
		return out[i].Host < out[j].Host
	})
	return out
}

// commandExcluded says whether this command may leave any install record at all: never a command confirmed on missing evidence
// or on a Socket outage, one that carries a malice override, or one that carries a block override (an answer to a blocking
// advisory): the command was not judged clean, whatever its other roots are.
func commandExcluded(report Report, in Input) bool {
	if in.Confirmations.EvidenceGap && len(report.Coverage) > 0 {
		return true
	}
	if len(in.Confirmations.Socket) > 0 {
		return true
	}
	for _, item := range report.Malice {
		if item.Overridden {
			return true
		}
	}
	for _, answer := range in.Evidence.Answered {
		if answer.Class == ClassBlockingAdvisory {
			return true
		}
	}
	return false
}

// ConfirmedRecord is a named root whose outcome the operator confirmed, with the token today's operator-terminal record path
// writes for it.
type ConfirmedRecord struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Token    string `json:"token"`
	GateExit int    `json:"gate_exit"`
}

var confirmedTokenRank = map[string]int{"WARN_TTY_OVERRIDE": 3, "GO_PENDING_CONFIRMED": 2, "GO_SOCKET_DECLINED": 1}
var confirmedTokenExit = map[string]int{"WARN_TTY_OVERRIDE": 10, "GO_PENDING_CONFIRMED": 14, "GO_SOCKET_DECLINED": 13}

// confirmedRecordsFor lists, from the FINAL decision, the named roots the operator confirmed that may be recorded after a
// verified publication: introduced by this command, a public registry artifact, named (it has a Socket row), not rested on a
// followed authority in any class, in a command nothing excludes.
func confirmedRecordsFor(report Report, in Input, evidence evidenceIndex) []ConfirmedRecord {
	out := []ConfirmedRecord{}
	if report.Outcome.Status != "clear" || commandExcluded(report, in) || report.Socket == nil {
		return out
	}
	introduced := map[Identity]struct{}{}
	introducedKeys := map[ArtifactKey]struct{}{}
	for _, item := range report.Difference.Introduced {
		introducedKeys[item.ArtifactKey] = struct{}{}
	}
	for _, occurrence := range in.Target.Occurrences {
		if _, isNew := introducedKeys[occurrence.Key()]; isNew && occurrence.Public && occurrence.Kind == KindRegistry && !occurrence.covered() {
			introduced[occurrence.Identity()] = struct{}{}
		}
	}
	roots := map[Identity]struct{}{}
	for _, root := range report.Socket.Roots {
		roots[Identity{Name: root.Name, Version: root.Version}] = struct{}{}
	}
	followed := func(kinds []string) bool {
		for _, kind := range kinds {
			if kind == AcceptFollowedGrant || kind == AcceptFollowedInstall || kind == AcceptFollowedOverride {
				return true
			}
		}
		return false
	}
	// the authority used for each occurrence on the root's bytes, through the covering relation: a member's followed advisory
	// clearance is the root's
	reliesOnFollowed := func(identity Identity, host string) bool {
		bytes := map[Identity]struct{}{}
		for _, member := range rootBytes(in, identity, host) {
			bytes[member] = struct{}{}
		}
		for _, item := range report.Advisories.Introduced {
			if !followed(item.ClearedBy) {
				continue
			}
			for _, version := range item.Versions {
				if _, carried := bytes[Identity{Name: item.Name, Version: version}]; carried {
					return true
				}
			}
		}
		if report.Cooldown != nil {
			for _, wait := range report.Cooldown.Waits {
				if _, carried := bytes[Identity{Name: wait.Name, Version: wait.Version}]; carried && followed(wait.ClearedBy) {
					return true
				}
			}
		}
		for _, root := range report.Socket.Roots {
			if _, carried := bytes[Identity{Name: root.Name, Version: root.Version}]; carried && followed(root.ClearedBy) {
				return true
			}
		}
		return false
	}
	blockSet := map[string]struct{}{}
	for _, severity := range in.Evidence.Policy.BlockSeverities {
		blockSet[severity] = struct{}{}
	}
	needsPublishTime := in.Releases != nil && in.Releases.Policy.CooldownDays > 0
	published := map[Identity]struct{}{}
	if in.Releases != nil {
		for _, reading := range in.Releases.Identities {
			if reading.Status == ReadingRead {
				published[Identity{Name: reading.Name, Version: reading.Version}] = struct{}{}
			}
		}
	}
	hostOfRoot := map[Identity]string{}
	for _, occurrence := range in.Target.Occurrences {
		if occurrence.Public && occurrence.Kind == KindRegistry && !occurrence.covered() {
			hostOfRoot[occurrence.Identity()] = occurrence.Host
		}
	}
	// the findings the operator accepted in this command: an introduced advisory of the adverse class, nothing followed
	// cleared, on bytes the answered root carries
	answeredAdverse := map[Identity]struct{}{}
	for _, answer := range in.Evidence.Answered {
		if answer.Class == ClassAdverseAdvisory {
			answeredAdverse[Identity{Name: answer.Name, Version: answer.Version}] = struct{}{}
		}
	}
	best := map[Identity]string{}
	for _, answer := range in.Evidence.Answered {
		if answer.Token == "" {
			continue
		}
		identity := Identity{Name: answer.Name, Version: answer.Version}
		if _, named := roots[identity]; !named {
			continue
		}
		if _, isNew := introduced[identity]; !isNew {
			continue
		}
		host := hostOfRoot[identity]
		if reliesOnFollowed(identity, host) {
			continue
		}
		accepted := func(member Identity, id string) bool {
			if _, answered := answeredAdverse[identity]; !answered {
				return false
			}
			for _, item := range report.Advisories.Introduced {
				if item.ID != id || item.Name != member.Name || item.Class != AdvisoryAdverse || followed(item.ClearedBy) {
					continue
				}
				for _, version := range item.Versions {
					if version == member.Version {
						return true
					}
				}
			}
			return false
		}
		if !rootBytesEligible(in, evidence, blockSet, identity, host, needsPublishTime, published, accepted) {
			continue
		}
		if confirmedTokenRank[answer.Token] > confirmedTokenRank[best[identity]] {
			best[identity] = answer.Token
		}
	}
	for identity, token := range best {
		out = append(out, ConfirmedRecord{Name: identity.Name, Version: identity.Version, Token: token, GateExit: confirmedTokenExit[token]})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Version < out[j].Version
	})
	return out
}
