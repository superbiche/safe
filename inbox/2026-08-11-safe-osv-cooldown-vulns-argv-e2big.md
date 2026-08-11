# osv_query_package_json: E2BIG on advisory-heavy packages (vulns via --argjson argv)

**Date:** 2026-08-11
**Source:** live `safe audit check pnpm@11.21.0 --ecosystem npm` during the
2026-08-10 host-allow digest review (safe 1.12.0 deployed).
**Affects:** `bin/safe-audit` `osv_query_package_json()` — every
`jq … --argjson v "$vulns"` write in it (final ok-write `bin/safe-audit:5766`
and the pagination/error writes above it).

## Evidence

```
/home/michel/.local/bin/safe-audit: line 5766: /usr/bin/jq: Argument list too long
```

emitted once, only on the `pnpm@11.21.0` run — the sole run inside the
release cooldown window. The cooldown security-fix exemption
(`bin/safe-audit:8355`) issues the PACKAGE-LEVEL query (`version=""` —
"every advisory ever filed"), and pnpm's full advisory corpus serialized
into `$vulns` exceeds Linux `MAX_ARG_STRLEN` (~128 KiB per argv element),
so the final `jq -cn --argjson v "$vulns" …` cannot exec. Version-scoped
queries (the main verdict path, `bin/safe-audit:8145`) stay small and were
unaffected; `pnpm@11.1.2` / `pnpm@11.20.0` runs emitted no error.

## Verified behavior (fail-closed, honest degrade)

- The redirection truncates `$cooldown_osv` before exec fails → empty file;
  the caller's `&& [[ "$(jq -r '.status' …)" == "ok" ]]` guard fails →
  `cooldown_fix_json` stays empty → no waiver → cooldown WARN stands.
- Main OSV verdict line unaffected (`OSV: PASS (no known advisories for
  11.21.0)` is genuine — version-scoped query, separate file).

Impact: (a) the security-fix cooldown waiver can never engage for
advisory-heavy packages — exactly the packages most likely to ship a fix
release — and it degrades SILENTLY (no note in the receipt, only a raw
bash stderr line leaking through the single-final-stderr-line contract);
(b) the same argv pattern in the merge loop caps how much advisory data any
package-level path can carry.

## Suggested action

Stop passing `$vulns` through argv: keep the accumulator in a scratch file
and use `--slurpfile` (the merge already reads pages that way), or emit
with `jq -c --slurpfile` from the file for the status/error writes too.
Sweep the function for every `--argjson … "$vulns"` site (defect class:
unbounded data through argv). Candidate rider for deferred slice 2
(fresh-release verdict nuance) — it reworks this exact cooldown/OSV lane.

## Resolution (2026-08-11)

Fixed by PR #73 (safe 1.14.0), as the rider on the fresh-release verdict
slice. `osv_query_package_json` now keeps the advisory accumulator in a
scratch file and emits every status/error/final write via `jq --slurpfile`
(`osv_write_package_query_result` helper) — no `$vulns` passes through argv
anywhere in the function, closing the whole defect class (unbounded data
through argv). The cooldown security-fix waiver therefore engages again for
advisory-heavy packages, and the stray bash stderr line is gone. Regression
evidence: tests/audit/check_version_aware.sh case with a package-level OSV
corpus above MAX_ARG_STRLEN asserting waiver engagement and no stderr leak
(267/267 on host).
