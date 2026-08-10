# Suspected false positive: graphifyy@0.9.32

**Date:** 2026-08-03
**Source:** claude-code-smart-explore
**Affects:** safe audit verdict logic

## What was checked

```
safe audit check graphifyy@0.9.32 --ecosystem python
```

Exit code: `10`  ·  Verdict: **WARN**

## Resolution

Requested spec: `graphifyy@0.9.32`
Resolved to: `0.9.32`
Method: `exact` (status `ok`)

## Why this looks wrong

No advisory is classified as affecting the resolved version, yet the command was refused — so the verdict did not come from the OSV classification. Check the GuardDog, Socket, and blocklist sections of the receipt.

Recorded WARN causes: `guarddog_error`

## Verdict inputs

- Socket: `ok`
- GuardDog: `error` — infrastructure failure; raw details are in the receipt
- OSV: `ok`, 0 advisories fetched

## Receipt

Full evidence: `/home/michel/.local/share/safe/audit/checks/2026-08-03-graphifyy-0.9.32.json`

## Contract

This note IS the escalation. Nothing was auto-applied: no allowlist entry was
written, no verdict was changed, and the gate still refuses. The operator
validates before any behaviour changes.

## Resolution (2026-08-10)

The suspicion was correct: the WARN carried no package signal. Its recorded
cause `guarddog_error` was the GuardDog EFBIG infrastructure failure (the
RLIMIT_FSIZE leash killing scans), fixed in 1.10.2 (PR #66, `b80e4f1`) —
audit-infrastructure failure surfacing as a refusal per the standing
ruling, never a CVE signal.

Re-checked on safe 1.11.0 (2026-08-10): GuardDog scans cleanly and the
verdict is an honest behavioral WARN (`capability-filesystem-read`,
`threat-filesystem-read`, `threat-runtime-obfuscation-steganography`; OSV
clean, blocklist pass) — receipt
`~/.local/share/safe/audit/checks/2026-08-10-graphifyy-0.9.32.json`. The
operator has since granted a standing python host-allow entry for
`graphifyy@0.9.32` (kept in the 2026-08-10 host-allow digest), so the
operational need is covered; the remaining WARN is the gate working as
designed on behavioral findings.
