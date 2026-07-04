# Make safe's npm shim refusals legible to agents (silent 127)

**Date:** 2026-07-05
**Source:** stack (unicstay cdk8s migration prep session)
**Affects:** safe — shim/interception UX for non-interactive agents (CC, Codex, qwen)

## Observed

In a non-interactive Claude Code session under `~/dev/unicstay/stack/cdk8s`:

- `npm --version` and `npm run synth -- dev` (volta-shimmed npm) → **exit 127, zero output** on both stdout and stderr. Indistinguishable from a missing/broken binary; `node --version` worked fine alongside.
- The agent concluded "volta's npm shim is broken on this machine", reported it to Michel as a machine issue, and worked around it by calling `./node_modules/.bin/ts-node` directly — a workaround that quietly bypasses whatever safe wanted to gate.
- Contrast: `npx tsc --noEmit` on the same day produced a fully legible refusal:
  `safe run: BLOCKED: tsc@latest is unknown and invocation is non-interactive` plus the allow-path hint (`safe run host-allow add ...`). That path is exactly right; the npm path is not.
- (`volta list node` also printed nothing — possibly the same silent interception.)

## Why it matters

- Agents hit these shims constantly and a silent 127 reads as toolchain breakage: wasted debugging detours, wrong "fix your volta" advice to the operator, and — worst — agents inventing bypasses (direct `node_modules/.bin` calls, alternate installers) that defeat the supply-chain protection entirely.
- A refusal is only teachable if it says who blocked, why, and how to allow. The npx message already proves the pattern works; the agent surfaced it to the operator instead of rabbit-holing.

## Suggested action

- Every interception path (npm, npx, volta passthroughs, any future shims) emits a one-line stderr refusal: `safe: BLOCKED <cmd> — <reason>; to allow: <command>` — never a bare, silent 127. Consider a distinctive documented exit code so scripts/agents can pattern-match a policy block vs a missing binary.
- Add an agent-facing contract: an `AGENTS.md` (or `safe explain` subcommand) describing what is gated, what the refusal looks like, and the human-approved allow flow — so harness instruction files can point at it and agents stop treating blocks as bugs.
- Non-interactive allow flow: a way for the operator to pre-approve or approve-on-request (e.g. `safe run host-allow add`) that an agent can *suggest verbatim* but not execute — keeping the human in the loop without the current opacity.
