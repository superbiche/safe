# Operator ruling: remove GuardDog from the gate (full removal, not demotion)

**Date:** 2026-08-11
**Source:** operator ruling in session CC 4e132b92, on evidence assembled by a
sibling session (typescript@7.0.2 / @types/node@26.2.0 dig) and corroborated
by this session's record.
**Affects:** safe — verdict engine tiers, PR #67 ack lane, sandbox tooling,
host-allow store, doctor/install/config surfaces.

## Ruling

GuardDog leaves the gate entirely. CC concurred (equal-brain read): a
BLOCK-capable tier whose false-positive chronicle IS the host-allow reasons
column trains operators to wave findings through — negative security value.

## Evidence (condensed)

- typescript@7.0.2: metadata_mismatch flags TS7's per-platform
  optionalDependencies mechanism (the esbuild/swc pattern); 4 capability
  rules are substring matches on ordinary JS (regex .exec, Promise resolve,
  .timer, reading its own package.json). has_source_code_risks: false.
- @types/node@26.2.0: risk 0.0, blocked because metadata_mismatch CRASHES on
  scoped-package paths (@types/node -> @types-node ENOENT). Every scoped
  package is exposed to this.
- Fleet chronicle: playwright, pnpm, qwen-code, opencode, codex-acp,
  claude-agent-acp, dotenvx, graphifyy, agentmemory ("fuck safe") — every
  allow reason is a GuardDog FP acknowledgment. This session's own live
  check hit the same profile on pnpm@11.21.0.
- Two weeks of patching AROUND it: EFBIG/RLIMIT_FSIZE (PR #66), SELinux
  module for its sandbox, sandbox=auto fallback, the whole PR #67
  behavioral-ack lane.

## Kill-slice design considerations (for the next slice's brief)

1. Tier redesign: Socket becomes the primary behavioral tier, always
   consulted. Viable now BECAUSE of this week's fresh-scan patience +
   envelope fix + infra-WARN discipline (1.14.0). Socket-down windows
   degrade to OSV+blocklist with the honest infra WARN (standing ruling
   unchanged).
2. PR #67 behavioral-ack lane retires with GuardDog (it is a GuardDog-FP
   device). Socket high/critical alerts keep their own veto. Existing
   --acknowledge-behavioral entries in the trust store need a migration
   story (become plain host-allow? prune?).
3. Ordering: kill BEFORE the Go verdict-engine port (one less integration
   to port).
4. Surfaces to sweep: bin/safe-audit guarddog tier + cache + SRI helpers,
   sandbox plumbing, scanner.mjs / scanner-batch (PR #64) if they consult
   the guarddog lane, doctor probes, install.sh prereqs (uv tool guarddog),
   config keys (install.guarddog.*), agent contract + explain, tests
   (guarddog_tier.sh largely retires; salvage the Socket/ack-veto cases
   that survive as Socket-primary cases), machine-setup manifests
   (guarddog uv tool entry).
5. Cleanup: FP-reason host-allow entries become prunable post-kill (operator
   digest pass). Two upstream reports still owed as good citizenship:
   Landlock/_Py_HashRandomization_Init (2026-08-03 note) and the
   scoped-package path bug (2026-08-11 sibling note).
6. Interim unblocks (relayed to operator, TTY): host-allow add
   typescript@7.0.2 and @types/node@26.2.0 with the sibling's drafted
   reasons.

Review: verdict-affecting -> sol/xhigh.

## Resolution

**Date:** 2026-08-12 · **Status:** closed — ruling implemented in safe 1.16.0

GuardDog is out of the gate. Net diff ~3,500 deletions against ~350
insertions; `bin/safe-audit` alone lost 1,285 lines and
`tests/audit/guarddog_tier.sh` (1,923 lines) is deleted.

Against the six design points in the charter:

1. **Socket is the primary behavioral tier**, always consulted (`auto` and
   `always` now behave identically; `never` is the sole deliberate skip and
   raises no WARN cause). It gained the BLOCK capability it never had: a
   `critical` alert in category `supplyChainRisk` → `socket_malware` BLOCK.
   Socket's package-level `criticalCVE` WARNs only — OSV owns vulnerabilities
   and its classification is version-aware (operator ruling).
2. **The PR #67 ack lane is removed** — flag, parser, writer, receipt fields
   and verdict vetoes. Existing `behavioral_ack` keys are ignored by readers;
   the two entries carrying one (`@qwen-code/qwen-code@0.21.5`,
   `pnpm@11.20.0`) keep their ordinary host-allow grant. No migration script.
3. **Killed before the Go verdict port**, as ordered — one less tier to port.
4. Surface sweep complete. Two charter items were wrong and cost nothing:
   `share/scanner.mjs` and the scan-batch lane never consulted GuardDog, and
   `install.sh` had no prereq (it was a `safe doctor` probe). One surface the
   charter missed — `docs/command-reference.md` — documents the ack flag
   without using the word "guarddog", so a grep could not find it.
5. FP-reason host-allow entries are now prunable (operator digest pass).
6. Both upstream reports are drafted with fresh reproductions on guarddog
   3.1.0, pending operator approval to file:
   `tmp/upstream-guarddog-sandbox-entropy.md` (Landlock /
   `_Py_HashRandomization_Init`) and `tmp/upstream-guarddog-scoped-path.md`
   (scoped-package rule crash).

**Scope added beyond the charter (operator-ruled during the slice):** a TTL'd
Socket result cache (`install.socket.cache_ttl_days`, default 7). Without it
the kill would have traded a false-positive problem for a quota-outage
problem — Socket free allows 1,000 scans/month and 500 quota-units/hour, the
paid tier is $125/mo on a five-developer minimum, and measured volume here is
~397 checks/30d. Unlike GuardDog's cache, this one needs an expiry: Socket is
threat intelligence, so a package clean today can be flagged tomorrow, and an
unbounded cache would pin a clean verdict across exactly the event the gate
exists to catch. Expired entries are never a verdict — they may only be
disclosed in the WARN line during an outage.

Under a Socket 429 the verdict is WARN, never BLOCK and never a silent pass:
agents halt, and the operator rules go/no-go manually from Socket's UI. Key
rotation across a second account was considered and refused.

Evidence — the two false positives that carried this ruling, and a real
malicious package, under the replacement tier live against Socket:

```
@types/node@26.2.0   rc=0   verdict=GO     causes=[]
typescript@7.0.2     rc=0   verdict=GO     causes=[]
node-ipc@10.1.1      rc=20  verdict=BLOCK  causes=["socket_malware","osv_affecting"]
```

`bash tests/run-all.sh` → all 21 suites passed on the host, including the new
`tests/audit/socket_tier.sh` (50 cases). `tests/live/socket_envelope.sh` now
passes against the real API — it had been skipping permanently on an
`SOCKET_SECURITY_API_TOKEN` gate that does not match how the CLI
authenticates here, which is how an invented envelope shape survived in the
fixtures until a live capture caught it.
