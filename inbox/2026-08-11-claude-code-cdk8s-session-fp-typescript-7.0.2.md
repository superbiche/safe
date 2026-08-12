# Suspected false positive: typescript@7.0.2

**Date:** 2026-08-11
**Source:** claude-code-cdk8s-session
**Affects:** safe audit verdict logic

## What was checked

```
safe audit check typescript@7.0.2 --ecosystem npm
```

Exit code: `10`  ·  Verdict: **WARN**

## Resolution

Requested spec: `typescript@7.0.2`
Resolved to: `7.0.2`
Method: `exact` (status `ok`)

## Why this looks wrong

No advisory is classified as affecting the resolved version, yet the command was refused — so the verdict did not come from the OSV classification. Check the GuardDog, Socket, and blocklist sections of the receipt.

Recorded WARN causes: `guarddog_findings`

## Verdict inputs

- Socket: `skipped_tier3` — deliberately not consulted (tier 3 policy skip); not a failure
- GuardDog: `ok` (scanned WITHOUT the kernel sandbox — weaker isolation) — rules: metadata_mismatch
- OSV: `ok`, 0 advisories fetched

## Receipt

Full evidence: `/home/michel/.local/share/safe/audit/checks/2026-08-11-typescript-7.0.2.json`

## Contract

This note IS the escalation. Nothing was auto-applied: no allowlist entry was
written, no verdict was changed, and the gate still refuses. The operator
validates before any behaviour changes.

## Resolution

**Date:** 2026-08-12 · **Status:** closed — confirmed false positive, cause removed

Confirmed a GuardDog false positive, and the tier that produced it has been
removed from the gate (safe 1.16.0, PR "remove GuardDog, Socket becomes the
primary behavioral tier").

Cause: `metadata_mismatch` fired on TypeScript 7's Go rewrite, which ships
per-platform native binaries as `optionalDependencies` — the same packaging
pattern esbuild and swc use. The rule reads that legitimate mechanism as a
manifest inconsistency. GuardDog's own `has_source_code_risks` was `false`.

This note is one of nine such acknowledgements in the host-allow store; that
chronicle is what carried the operator ruling to remove the tier entirely
(`inbox/2026-08-11-safe-kill-guarddog-ruling.md`).

Evidence — the same spec under the replacement tier, live against Socket:

```
./bin/safe-audit check typescript@7.0.2 --ecosystem npm --json
rc=0  verdict=GO  warn_causes=[]
```

Socket scores it 88 with two `low` alerts (`newAuthor`, `urlStrings`) and no
high or critical alert. No allowlist entry was ever written for it, and none
is needed now.

Verified in the same run that the replacement tier still blocks real malice:
`node-ipc@10.1.1` → `rc=20 verdict=BLOCK causes=["socket_malware","osv_affecting"]`.

A bug report for the underlying rule behaviour is drafted for
DataDog/guarddog (`tmp/upstream-guarddog-scoped-path.md` covers the sibling
scoped-package defect).
