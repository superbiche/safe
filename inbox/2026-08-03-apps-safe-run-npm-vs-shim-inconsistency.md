# `safe run npm` prompts for Podman sandbox while the npm shim path audits transparently

**Date:** 2026-08-03
**Source:** apps (AgentRH image-scan-gate slice, session CC 87dc6b60)
**Affects:** safe run UX / agent contract (npm lane)

## Observed
Two paths to the same operation behave differently (operator terminal, TTY):

- `safe run npm update brace-expansion ws` → "safe run: npm@latest is not in any
  list. Run in Podman sandbox? [y]es/[a]lways/[N]o" — the operator aborted (^C):
  the prompt asks about sandboxing *npm itself* instead of auditing the update
  targets.
- plain `npm update brace-expansion ws` (mise shim, safe-audit hooked) → full
  project scan + per-target `safe audit check` (brace-expansion@5.0.9 GO,
  ws@8.21.0 GO via override-pin) → proceeds cleanly with exactly the audit
  evidence one wants.

Agent-side (non-interactive) the same shim path hard-blocks on WARN verdicts
(correct fail-closed), including WARNs caused by Socket 429 rate-limits and by
same-day releases with no Socket score yet — several retries needed during an
advisory-wave day where the fixes ARE the fresh releases.

## Why it matters
The documented happy path (`safe run npm ...`, per my-safe-gate) is *worse* than
the shim path for npm: it interrogates about the package manager binary rather
than the targets, and the operator instinctively falls back to plain `npm` —
which happens to be the better-instrumented lane. Confusing contract: agents are
told to prefer `safe run`, operators learn to avoid it.

Secondary: same-day patch releases (advisory-wave fixes) systematically WARN
(no Socket score yet) and block non-interactive agents from applying the very
fixes a scanner demands — a catch-22 between the image-scan gate and the
install gate.

## Suggested action
Consider: (1) `safe run <known-pm> ...` delegating to the audited shim lane
instead of the unknown-binary sandbox prompt; (2) a verdict nuance for
"advisory-fix release, no score yet" (e.g. OSV-clean + fixes-a-known-CVE →
GO-with-note instead of WARN) so agents can apply security bumps
non-interactively; (3) document the shim lane as the primary npm path in the
agent contract.

## Resolution (2026-08-11)

Item 1 fixed by PR #72 (safe 1.13.0): bare `safe run npm ...` now silently
delegates to the gate-bound npm wrapper (exact `# safe-gate-wrapper v1
tool=npm` marker verified before exec), so both spellings land in the same
audited shim lane — no more sandbox prompt about npm itself. Evidence:
`tests/install/run.sh` delegation/canary cases + `tests/live/shim_delegation.sh`
(5/5 against this machine's real wrappers); all 19 suites green.
Item 2 (fresh-release verdict nuance / advisory-wave catch-22) is NOT in this
slice: operator-ruled IN SCOPE 2026-08-10 as its own deferred slice (next in
queue). Item 3 done: the agent contract now documents the delegation
(docs/contract/agent-contract.json, rendered docs/agents.md); the fleet-side
my-safe-gate skill update lands at deploy.

## Resolution — item 2 (2026-08-11)

Item 2 fixed by PR #73 (safe 1.14.0). Live probes showed "no Socket score
yet" is a blocking on-demand scan, not a distinct API state: safe now gives
a release younger than the cooldown window one bounded patience retry
(default 90s) — usually returning a REAL scored verdict — and if the scan
is still incomplete, an explicit PENDING state: GO with a disclosed note
when GuardDog + OSV + blocklist are all clean, WARN `socket_score_pending`
otherwise, always a veto for the behavioral-ack second opinion. Same-day
security-fix releases additionally regain the cooldown waiver via the
E2BIG fix (see inbox/2026-08-11-safe-osv-cooldown-vulns-argv-e2big.md).
Evidence: tests/audit/guarddog_tier.sh patience/pending regressions; Socket
live-probe evidence stands separately; host tests/run-all.sh green.
All three items of this note are now closed.
