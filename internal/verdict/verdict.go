// Package verdict decides a package-audit verdict from gathered evidence.
//
// This is the decision layer only: every input is evidence somebody else
// already collected. Nothing here performs I/O, resolves a version range, or
// compares semver — advisory classification stays in bash precisely because it
// needs range matching, and keeping it there keeps this package stdlib-only.
//
// Two invariants carry the security properties and must survive any edit:
//
//   - The verdict is MONOTONIC. Every stage may raise it (GO -> WARN -> BLOCK)
//     and none may lower it. A later clean signal never launders an earlier
//     adverse one.
//   - Absence of evidence is never clean. An unavailable tier, an unscorable
//     sibling, a failed query and a policy skip all warn; only a signal that
//     actually reported clean passes.
package verdict

import (
	"fmt"
	"slices"
	"strings"
)

// Verdict levels, ordered by severity.
const (
	GO    = "GO"
	WARN  = "WARN"
	BLOCK = "BLOCK"
)

func rank(v string) int {
	switch v {
	case BLOCK:
		return 2
	case WARN:
		return 1
	default:
		return 0
	}
}

// Advisory is one OSV record already classified as affecting the resolved
// version. Severity is the ladder's label; Malware marks OpenSSF MAL-* records.
type Advisory struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Malware  bool   `json:"malware"`
}

// Resolution describes which versions the package manager would install.
type Resolution struct {
	OK             bool   `json:"ok"`
	PrimaryVersion string `json:"primary_version"`
	Label          string `json:"label"`
}

// Socket is the primary behavioral-tier result. Score is carried as text so
// the rendered line matches whatever the provider reported, byte for byte.
type Socket struct {
	Status            string `json:"status"`
	Available         bool   `json:"available"`
	Note              string `json:"note"`
	Reason            string `json:"reason"`
	Score             string `json:"score"`
	Class             string `json:"class"`
	CacheStaleScore   string `json:"cache_stale_score"`
	CacheStaleAgeDays string `json:"cache_stale_age_days"`
}

// SocketSibling is a non-primary resolved version that was scored separately.
type SocketSibling struct {
	Version string `json:"version"`
	Status  string `json:"status"`
	Class   string `json:"class"`
	Score   string `json:"score"`
}

// OSV carries the already-classified advisory evidence.
type OSV struct {
	Status               string     `json:"status"`
	Affecting            []Advisory `json:"affecting"`
	AffectingCount       int        `json:"affecting_count"`
	RemediatedCount      int        `json:"remediated_count"`
	TotalCount           int        `json:"total_count"`
	HistoricalCritical   bool       `json:"historical_critical"`
	HistoricalMalwareIDs string     `json:"historical_malware_ids"`
}

// Release carries publish-age evidence for the cooldown heuristic.
type Release struct {
	RC  int `json:"rc"`
	Age int `json:"age"`
	// PrimaryAge is text, not a number: it may be absent, and the pending line
	// renders it verbatim.
	PrimaryAge          string `json:"primary_age"`
	Version             string `json:"version"`
	CooldownDays        int    `json:"cooldown_days"`
	SecurityFixIDs      string `json:"security_fix_ids"`
	CooldownSecurityFix string `json:"cooldown_security_fix"`
}

// Blocklist is the operator's local blocklist state. Path is echoed in the
// unreadable-file line so the operator is told exactly what to repair.
type Blocklist struct {
	Readable bool   `json:"readable"`
	Reason   string `json:"reason"`
	Path     string `json:"path"`
}

// Evidence is the complete input to a decision.
type Evidence struct {
	Resolution      Resolution      `json:"resolution"`
	Socket          Socket          `json:"socket"`
	SocketSiblings  []SocketSibling `json:"socket_siblings"`
	OSV             OSV             `json:"osv"`
	Release         Release         `json:"release"`
	CustomSource    bool            `json:"custom_source"`
	Blocklist       Blocklist       `json:"blocklist"`
	BlockSeverities []string        `json:"block_severities"`
}

// Lines are the rendered per-tier summary lines.
type Lines struct {
	Socket  string `json:"socket"`
	OSV     string `json:"osv"`
	Release string `json:"release"`
	Block   string `json:"block"`
}

// Result is the decision.
type Result struct {
	Verdict       string   `json:"verdict"`
	Causes        []string `json:"causes"`
	Lines         Lines    `json:"lines"`
	SocketDetail  string   `json:"socket_detail"`
	SocketPending bool     `json:"socket_pending"`
	ReleaseExempt bool     `json:"release_exempt"`
}

// decision accumulates verdict and causes while the stages run.
type decision struct {
	verdict string
	causes  []string
}

// bump raises the verdict, never lowers it.
func (d *decision) bump(v string) {
	if rank(v) > rank(d.verdict) {
		d.verdict = v
	}
}

// warn is the common pairing: record a cause and raise to at least WARN.
func (d *decision) warn(cause string) {
	d.causes = append(d.causes, cause)
	d.bump(WARN)
}

// block records a cause and raises to BLOCK.
func (d *decision) block(cause string) {
	d.causes = append(d.causes, cause)
	d.bump(BLOCK)
}

// Decide runs every stage in order and returns the verdict, the ordered cause
// list, and the rendered lines. Stage order is load-bearing: it determines the
// order causes appear in receipts and refusal messages.
func Decide(ev Evidence) Result {
	d := &decision{verdict: GO}
	res := Result{
		Lines: Lines{
			Socket: "PASS (no behavioral anomalies)",
			Block:  "PASS (not blocked)",
		},
	}

	socketStage(ev, d, &res)
	socketSiblingStage(ev, d, &res)
	osvStage(ev, d, &res)
	releaseStage(ev, d, &res)
	sourceStage(ev, d)
	blocklistStage(ev, d, &res)
	pendingStage(ev, d, &res)

	res.Verdict = d.verdict
	res.Causes = d.causes
	if res.Causes == nil {
		res.Causes = []string{}
	}
	return res
}

// socketStage evaluates the primary behavioral tier.
//
// The branch order matters: a policy skip and an outage are distinguishable
// events carrying identical evidence (none), so each gets its own cause while
// both warn. Only the final branch — a tier that actually reported — can pass.
func socketStage(ev Evidence, d *decision, res *Result) {
	s := ev.Socket
	switch {
	case s.Status == "skipped":
		res.Lines.Socket = fmt.Sprintf("SKIP (%s)", s.Note)
		res.SocketDetail = orDefault(s.Note, "socket disabled by policy")
		d.warn("socket_disabled")

	case !s.Available:
		res.Lines.Socket = "SKIP (socket CLI not available)"
		res.SocketDetail = "socket CLI not available"
		d.warn("socket_unavailable")

	case s.Status == "pending":
		// Data availability, not an outage: a fresh release Socket has not
		// finished scanning. Resolved at the end, once every other signal is in.
		res.SocketPending = true
		res.Lines.Socket = fmt.Sprintf("PENDING (fresh release %s, %sd old — Socket scan not yet complete)",
			ev.Resolution.PrimaryVersion, ev.Release.PrimaryAge)
		res.SocketDetail = orDefault(s.Note, "Socket scan not yet complete")

	case s.Status != "ok":
		// Switch on the fixed reason code, never on prose: provider text never
		// reaches this layer. An unknown reason degrades to a generic error,
		// never to clean.
		var cause string
		switch s.Reason {
		case "rate_limited":
			res.Lines.Socket = "WARN (socket rate-limited, retry later)"
			cause = "socket_rate_limited"
		case "auth":
			res.Lines.Socket = "WARN (socket authentication required)"
			cause = "socket_auth_failed"
		case "timeout":
			res.Lines.Socket = "WARN (socket score timed out)"
			cause = "socket_error"
		case "unbounded":
			res.Lines.Socket = "WARN (socket score skipped: cannot be bounded)"
			cause = "socket_error"
		case "not_found":
			res.Lines.Socket = "WARN (socket has no record of this package version)"
			cause = "socket_error"
		default:
			res.Lines.Socket = "WARN (socket returned an unrecognized result)"
			cause = "socket_error"
		}
		if s.CacheStaleScore != "" && s.CacheStaleAgeDays != "" {
			res.Lines.Socket += fmt.Sprintf("; last complete score was %s, %sd ago",
				s.CacheStaleScore, s.CacheStaleAgeDays)
		}
		res.SocketDetail = orDefault(s.Note, "socket check failed")
		d.warn(cause)

	default:
		switch s.Class {
		case "malware":
			res.Lines.Socket = "BLOCK (critical supply-chain-risk alert)"
			d.block("socket_malware")
		case "unmapped":
			res.Lines.Socket = "WARN (critical alert in a category safe cannot classify — treated as unresolved, not clean)"
			res.SocketDetail = "unclassifiable critical alert category"
			d.warn("socket_error")
		case "critical_cve":
			res.Lines.Socket = "WARN (critical vulnerability alert)"
			d.warn("socket_critical_cve")
		case "high":
			res.Lines.Socket = "WARN (high-severity alert)"
			d.warn("socket_high_alert")
		case "low_score":
			res.Lines.Socket = fmt.Sprintf("WARN (score=%s)", s.Score)
			d.warn("socket_low_score")
		default:
			res.Lines.Socket = fmt.Sprintf("PASS (score=%s)", s.Score)
		}
	}
}

// socketSiblingStage covers every other version the operation could install.
//
// This exists because removing the previous behavioral tier silently dropped
// multi-version coverage: a clean primary could carry a malicious sibling in on
// a ranged update. A sibling that could not be scored is unproven, never clean.
func socketSiblingStage(ev Evidence, d *decision, res *Result) {
	for _, sib := range ev.SocketSiblings {
		if sib.Status != "ok" {
			res.Lines.Socket += fmt.Sprintf("; %s not scored (infrastructure failure)", sib.Version)
			d.warn("socket_error")
			continue
		}
		switch sib.Class {
		case "malware":
			res.Lines.Socket += fmt.Sprintf("; BLOCK %s (critical supply-chain-risk alert)", sib.Version)
			d.block("socket_malware")
		case "unmapped":
			res.Lines.Socket += fmt.Sprintf("; WARN %s (unclassifiable critical alert)", sib.Version)
			d.warn("socket_error")
		case "critical_cve":
			res.Lines.Socket += fmt.Sprintf("; WARN %s (critical vulnerability alert)", sib.Version)
			d.warn("socket_critical_cve")
		case "high":
			res.Lines.Socket += fmt.Sprintf("; WARN %s (high-severity alert)", sib.Version)
			d.warn("socket_high_alert")
		case "low_score":
			res.Lines.Socket += fmt.Sprintf("; WARN %s (score=%s)", sib.Version, sib.Score)
			d.warn("socket_low_score")
		}
	}
}

// osvStage applies advisory evidence.
//
// Adverse evidence outranks infrastructure failure: a partial outage must never
// demote a retained affecting/malware hit to a plain OSV-unavailable WARN,
// because that WARN is host-allowable and a known malware hit would ride
// through. Classify what was received first; the outage only adds a cause.
func osvStage(ev Evidence, d *decision, res *Result) {
	o := ev.OSV
	label := ev.Resolution.Label

	if !ev.Resolution.OK {
		if o.Status != "ok" {
			res.Lines.OSV = "WARN (version unresolved and OSV query failed)"
			d.causes = append(d.causes, "osv_unavailable")
		} else {
			res.Lines.OSV = fmt.Sprintf("WARN (version unresolved; %d historical advisories for package)", o.TotalCount)
		}
		d.warn("version_unresolved")
		if o.HistoricalCritical {
			d.bump(BLOCK)
		}
		// A package whose history carries a known-malware record never proceeds
		// on an unresolved version. A clean pinned version still GOes.
		if o.HistoricalMalwareIDs != "" {
			res.Lines.OSV = fmt.Sprintf("BLOCK (version unresolved; known-malware record in package history: %s)", o.HistoricalMalwareIDs)
			d.block("osv_malware")
		}
		return
	}

	switch {
	case o.AffectingCount > 0:
		summary := affectingSummary(o.Affecting, o.AffectingCount)
		res.Lines.OSV = fmt.Sprintf("WARN (%d of %d advisories affect %s: %s)",
			o.AffectingCount, o.TotalCount, label, summary)
		d.warn("osv_affecting")

		if countBlocked(o.Affecting, ev.BlockSeverities) > 0 {
			res.Lines.OSV = fmt.Sprintf("BLOCK (%d of %d advisories affect %s: %s)",
				o.AffectingCount, o.TotalCount, label, summary)
			d.bump(BLOCK)
		}
		// Malware records usually carry no CVSS, so the severity ladder ranks
		// them "unknown" — which block_severities would leave overridable.
		// Malware is never severity-policy business: BLOCK unconditionally.
		if ids := malwareIDs(o.Affecting); ids != "" {
			res.Lines.OSV = fmt.Sprintf("BLOCK (known-malware record affects %s: %s)", label, ids)
			d.block("osv_malware")
		}
		if o.Status != "ok" {
			res.Lines.OSV += "; OSV data incomplete (query failure)"
			d.causes = append(d.causes, "osv_unavailable")
		}

	case o.Status != "ok":
		// An outage previously counted as zero CVEs; fail closed instead.
		res.Lines.OSV = "WARN (OSV query failed; advisory data unavailable)"
		d.warn("osv_unavailable")

	case o.TotalCount > 0:
		if o.RemediatedCount > 0 {
			res.Lines.OSV = fmt.Sprintf("PASS (0 of %d advisories affect %s; %d fixed at or below it)",
				o.TotalCount, label, o.RemediatedCount)
		} else {
			res.Lines.OSV = fmt.Sprintf("PASS (0 of %d advisories affect %s)", o.TotalCount, label)
		}

	default:
		res.Lines.OSV = fmt.Sprintf("PASS (no known advisories for %s)", label)
	}
}

// releaseStage applies the publish-age cooldown.
//
// The cooldown is a heuristic, not advisory evidence, so a failed lookup is
// disclosed and skipped rather than refused. When the young release IS the
// remediation for a published advisory, waiting recreates the catch-22 the gate
// was built to end — so it is waived by default. `enforce` keeps the wait,
// because a compromised-maintainer release can carry a real fix as cover.
func releaseStage(ev Evidence, d *decision, res *Result) {
	r := ev.Release
	if !ev.Resolution.OK || r.CooldownDays <= 0 {
		return
	}
	switch r.RC {
	case 0:
		if r.Age >= r.CooldownDays {
			res.Lines.Release = fmt.Sprintf("PASS (published %dd ago)", r.Age)
			return
		}
		if r.SecurityFixIDs != "" && r.CooldownSecurityFix == "exempt" {
			res.ReleaseExempt = true
			res.Lines.Release = fmt.Sprintf(
				"PASS (%s published %dd ago — inside the %dd cooldown, waived: it remediates %s)",
				r.Version, r.Age, r.CooldownDays, r.SecurityFixIDs)
			return
		}
		res.Lines.Release = fmt.Sprintf("WARN (%s published %dd ago — younger than the %dd cooldown)",
			r.Version, r.Age, r.CooldownDays)
		if r.SecurityFixIDs != "" {
			res.Lines.Release += fmt.Sprintf("; it remediates %s but install.cooldown_security_fix=enforce", r.SecurityFixIDs)
		}
		d.warn("release_too_new")
	case 1:
		res.Lines.Release = "SKIP (publish date unavailable — cooldown not evaluated)"
	}
}

// sourceStage floors the verdict at WARN for a non-default registry: public
// advisory data covers the public registry identity, not whatever a private
// index serves under the same name@version.
func sourceStage(ev Evidence, d *decision) {
	if ev.CustomSource {
		d.warn("custom_source")
	}
}

// blocklistStage applies operator blocklist state. An unreadable file must not
// read as "not blocked" — local state breakage warns with its own cause.
func blocklistStage(ev Evidence, d *decision, res *Result) {
	if !ev.Blocklist.Readable {
		res.Lines.Block = fmt.Sprintf("WARN (blocklist file unreadable — repair or remove %s)", ev.Blocklist.Path)
		d.warn("blocklist_unreadable")
		return
	}
	if ev.Blocklist.Reason != "" {
		res.Lines.Block = fmt.Sprintf("BLOCKED (%s)", ev.Blocklist.Reason)
		d.bump(BLOCK)
	}
}

// pendingStage resolves a still-pending Socket score. It may leave a GO only
// when every independent signal already evaluated cleanly; otherwise the
// pending state is disclosed as its own cause.
func pendingStage(ev Evidence, d *decision, res *Result) {
	if !res.SocketPending {
		return
	}
	clean := d.verdict == GO &&
		ev.OSV.Status == "ok" &&
		ev.Resolution.OK &&
		ev.OSV.AffectingCount == 0 &&
		strings.HasPrefix(res.Lines.Block, "PASS")
	if !clean {
		d.warn("socket_score_pending")
	}
}

// affectingSummary renders at most three advisory ids, then says how many more
// exist rather than truncating silently.
func affectingSummary(affecting []Advisory, total int) string {
	shown := affecting
	if len(shown) > 3 {
		shown = shown[:3]
	}
	parts := make([]string, 0, len(shown))
	for _, a := range shown {
		parts = append(parts, fmt.Sprintf("%s (%s)", a.ID, a.Severity))
	}
	summary := strings.Join(parts, ", ")
	if total > 3 {
		summary += fmt.Sprintf(", +%d more", total-3)
	}
	return summary
}

func countBlocked(affecting []Advisory, blockSeverities []string) int {
	n := 0
	for _, a := range affecting {
		if slices.Contains(blockSeverities, a.Severity) {
			n++
		}
	}
	return n
}

func malwareIDs(affecting []Advisory) string {
	ids := make([]string, 0, len(affecting))
	for _, a := range affecting {
		if a.Malware {
			ids = append(ids, a.ID)
		}
	}
	return strings.Join(ids, ", ")
}

func orDefault(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
