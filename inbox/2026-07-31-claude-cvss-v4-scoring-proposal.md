# CVSS v4-only advisories floor at "high" — scoring proposal needs a ruling

**Date:** 2026-07-31
**Source:** claude (safe overhaul session, PR#29 review finding 6 residual)
**Affects:** severity ladder in `safe audit check` (`vuln_sev` in bin/safe-audit)

## What was observed

The severity ladder computes CVSS v3.1 base scores (verified against the
FIRST spec, all 2,592 base combinations band-exact per the orthogonal
reviewer) and takes the most severe of {qualitative labels, computed v3
bands}. An advisory whose ONLY severity signal is a CVSS **v4** vector is
floored at "high" without scoring the vector — so a v4-only *critical*
(e.g. FIRST's 10.0 example vector) lands at high → WARN-overridable instead
of BLOCK under the default `block_severities: ["critical"]`.

The reviewer classified this ARCHITECTURAL (delta finding 6): closing it
properly means a verified v4 scorer, and the blunt alternative (blanket
BLOCK for unsupported v4 vectors) over-blocks genuine high/moderate cases —
a daily-UX regression that needs an operator ruling either way.

## Exposure today

Narrow: GHSA-sourced advisories (all of npm) carry a qualitative
`database_specific.severity`, which the ladder already uses. The gap is
advisories with standard `severity[]` v4 vectors and no qualitative label —
currently rare, will grow as v4 adoption spreads.

## Options for ruling

1. **Vendor a v4 scorer** (deterministic reference implementation, jq or a
   small vendored script): correct bands, no UX change. Cost: v4 MacroVector
   scoring is substantially more complex than v3 arithmetic; needs its own
   verification pass.
2. **Blanket BLOCK on unscored v4-only**: safe but over-blocks; needs the
   ruling explicitly because it can hard-block moderate advisories.
3. **Keep the high floor** (status quo): v4-only criticals stay
   WARN-overridable — an operator override still requires a pinned
   host-allow with a reason, so the residual is a conscious-override
   surface, not a silent pass.

No behavior change until ruled; option 3 is what ships in PR#29.
