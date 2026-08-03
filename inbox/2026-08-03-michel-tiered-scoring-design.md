# Tiered scoring: make Socket optional, not load-bearing (endorsed direction)

**Date:** 2026-08-03
**Source:** michel (ruled 2026-08-03: "the reasonable approach anyway", for
this machine and for potential users — safe should be practical without a
paid/quota'd Socket dependency; target: practical within days)
**Affects:** `bin/safe-audit` check verdict assembly; every gated install

## Problem

Every `safe audit check` calls Socket; the free tier (500 API units/hr)
429s under normal agent-driven use, degrading dozens of verdicts to
infra-WARN for hours (2026-08-02/03: two full days of it, including
blocking the npm 12 install). A tool whose default posture depends on a
quota nobody solo can buy is not practical for anyone else either.

## Design (three tiers, most-severe-of preserved)

1. **Tier 1 — always, free, unlimited:** OSV advisories (existing) + the
   OpenSSF `MAL-*` known-malware records OSV already serves. Verify during
   implementation: MAL records often carry no CVSS — confirm they rank as
   BLOCK-worthy in the severity ladder (unscored malware ≠ unscored CVE;
   a MAL hit is a blocklist-class signal, fail-closed).
2. **Tier 2 — the behavioral verdict:** GuardDog (Datadog, active, $0)
   local scan of the exact artifact, JSON output, cached per immutable
   `name@version` (+ integrity hash) under `~/.cache/safe/guarddog/` —
   each version ever published costs one scan, forever. Correlated
   findings (lifecycle hook + exfil pattern + obfuscation, etc.) map into
   the verdict ladder; calibrate thresholds against the existing check
   history to bound false positives.
3. **Tier 3 — Socket, rare:** only first-seen identities where GuardDog is
   ambiguous, plus operator-scoped cases (config knob). Socket outage then
   degrades only tier 3 — an infra-WARN on a rare path, never the default
   posture. Existing cause-specific breakage messaging stays.

Release-age cooldown (3–7 days for brand-new versions) worth considering
in the same slice — cheap, catches the compromised-release window.

## Status

Direction operator-endorsed; implementation NOT started (compaction
boundary). Next session: plan the slice (likely PR series: MAL-* handling
first, GuardDog tier second, Socket scoping third), orthogonal review per
the usual lanes.

## References

- Research: Socket pricing + alternatives survey (Codex terra, verified);
  ranked GuardDog + OSV MAL-* + cache as the best $0 substitute.
- Related: `2026-08-03-michel-socket-oss-team-upgrade.md` (parked quota
  bump; complementary, not a substitute).
