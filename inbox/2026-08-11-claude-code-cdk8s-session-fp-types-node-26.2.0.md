# Suspected false positive: @types/node@26.2.0

**Date:** 2026-08-11
**Source:** claude-code-cdk8s-session
**Affects:** safe audit verdict logic

## What was checked

```
safe audit check @types/node@26.2.0 --ecosystem npm
```

Exit code: `10`  ·  Verdict: **WARN**

## Resolution

Requested spec: `@types/node@26.2.0`
Resolved to: `26.2.0`
Method: `exact` (status `ok`)

## Why this looks wrong

No advisory is classified as affecting the resolved version, yet the command was refused — so the verdict did not come from the OSV classification. Check the GuardDog, Socket, and blocklist sections of the receipt.

Recorded WARN causes: `guarddog_error`

## Verdict inputs

- Socket: `ok`
- GuardDog: `partial` (scanned WITHOUT the kernel sandbox — weaker isolation) — infrastructure failure; raw details are in the receipt
- OSV: `ok`, 0 advisories fetched

## Receipt

Full evidence: `/home/michel/.local/share/safe/audit/checks/2026-08-11-types-node-26.2.0.json`

## Contract

This note IS the escalation. Nothing was auto-applied: no allowlist entry was
written, no verdict was changed, and the gate still refuses. The operator
validates before any behaviour changes.

## Resolution

**Date:** 2026-08-12 · **Status:** closed — confirmed tool defect, cause removed

Confirmed not a package problem: GuardDog's `metadata_mismatch` rule *crashes*
on scoped packages. The tier has been removed from the gate (safe 1.16.0, PR
"remove GuardDog, Socket becomes the primary behavioral tier").

Cause, reproduced directly on guarddog 3.1.0:

```
guarddog npm scan '@types/node' --version 26.2.0 --no-sandbox --output-format json
→ errors: {"metadata_mismatch": "failed to run rule metadata_mismatch:
   [Errno 2] No such file or directory: '/tmp/tmpnsf38q2n/@types-node/package/package.json'"}
→ risk_score: 0.0, label "no_risks_detected"
```

The extraction directory is created as `@types-node` (scope separator rewritten
to `-`) but the rule's lookup path does not match what is on disk. Verified the
contrast on an unscoped package: `brace-expansion@2.1.4` scans with zero errors.
Every scoped package — `@types/*` and most org-published tooling — was therefore
scanned with that rule permanently inert, while the scan reported success. safe
surfaced the rule error honestly as `guarddog_error` (infra WARN), which is why
this note exists rather than a silent pass.

Evidence — the same spec under the replacement tier, live against Socket:

```
./bin/safe-audit check @types/node@26.2.0 --ecosystem npm --json
rc=0  verdict=GO  warn_causes=[]
```

Socket scores it 80 with one `low` and one `middle` alert, no high or critical.

Verified in the same run that the replacement tier still blocks real malice:
`node-ipc@10.1.1` → `rc=20 verdict=BLOCK causes=["socket_malware","osv_affecting"]`.

An upstream bug report is drafted at `tmp/upstream-guarddog-scoped-path.md`,
pending operator approval to file against DataDog/guarddog.
