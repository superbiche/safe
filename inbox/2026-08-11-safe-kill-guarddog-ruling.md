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
