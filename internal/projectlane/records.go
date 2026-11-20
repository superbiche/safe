package projectlane

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

// Record verdicts, the tokens `install-known.json` holds and the signed export reads.
const (
	RecordClean     = "GO"
	RecordTolerated = "WARN_TOLERATED"
)

// RecordItem is one artifact the command may leave an install record for.
type RecordItem struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Host    string   `json:"host"`
	Verdict string   `json:"verdict"`
	Reasons []string `json:"reasons"`
}

// recordsFor lists the eligible artifacts of a CLEAR decision. It is empty for any other outcome.
func recordsFor(report Report, in Input, evidence evidenceIndex) []RecordItem {
	records := []RecordItem{}
	if report.Outcome.Status != "clear" {
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
		read, ok := evidence[identity]
		if !ok || read.Coverage != CoverageComplete {
			continue
		}
		reasons := []string{"osv_clean_for_version"}
		eligible := true
		for _, hit := range read.Advisories {
			if hit.Malware || severityClass(hit.Severity, blockSet) != AdvisoryBelowHigh {
				eligible = false // the artifact itself carries an advisory at high or above, introduced or already present
				break
			}
			reasons = []string{"osv_below_high_only"}
		}
		if !eligible {
			continue
		}
		tolerated := []string{}
		if wait, waited := waits[identity]; waited {
			if !onlyTolerance(wait.ClearedBy) {
				continue
			}
			tolerated = append(tolerated, "release_too_new")
		}
		switch {
		case root.Outcome == SocketClear:
			reasons = append(reasons, "socket_ok")
		case onlyTolerance(root.ClearedBy):
			tolerated = append(tolerated, rootCauses(in, identity)...)
		default:
			continue // cleared by another authority, or confirmed at a terminal (1684): not this ticket's record
		}
		reasons = append(reasons, "blocklist_pass")
		item := RecordItem{Name: identity.Name, Version: identity.Version, Host: occurrence.Host, Verdict: RecordClean, Reasons: reasons}
		if len(tolerated) > 0 {
			item.Verdict, item.Reasons = RecordTolerated, sortedUnique(tolerated)
		}
		records = append(records, item)
	}
	return records
}

func onlyTolerance(kinds []string) bool {
	return len(kinds) == 1 && kinds[0] == AcceptLocalTolerance
}

func rootCauses(in Input, identity Identity) []string {
	if in.Socket != nil {
		for _, root := range in.Socket.Roots {
			if root.Name == identity.Name && root.Version == identity.Version {
				return root.Causes
			}
		}
	}
	return nil
}
