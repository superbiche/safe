# Safe — shared agent instructions

Context marker: `safe:AGENTS.md`

Canonical shared rule source for this repo; vendor bridge files (`CLAUDE.md`, …) import it and add only harness-specific deltas.

## What this repo is

`safe` is a bash package-install security gate: `bin/safe` (CLI + explain), `bin/safe-audit` (verdicts: OSV/Socket/blocklist, version resolution), `bin/safe-run` (sandboxed exec + host-allow/blocklist), `lib/gate-lib.sh` (PATH-wrapper routing), `lib/install-wrappers.zsh` (legacy zsh shims). `install.sh` deploys gate wrappers to `~/.local/bin`.

## Live-vs-repo trap

The installed gate is a COPY: repo edits change nothing live until `install.sh` re-runs, and gated shells hold zsh function snapshots from their start. Two false "shipped bug" reports came from stale snapshots — before reporting a live-behavior bug, verify which version actually ran (`safe --version`, wrapper realpath).

## Operator rulings (standing)

- Never suggest, match, or allowlist `@latest`; allow entries are pinned to resolved versions.
- Audit-infrastructure failure (Socket auth/429/network/timeout) must read as breakage-to-fix with a recovery path, never as a CVE signal.
- Refusals: single final stderr line; exit 100 (policy) / 102 (operator TTY needed) / 104 (audit BLOCK); 0/10/20 are `safe audit check` verdict codes; 127 = genuinely missing command.
- Fail-closed stays for malice signals (blocklist, critical advisory affecting the resolved version, Socket BLOCK). Resolution that cannot be predicted degrades honestly (package-level WARN + pin hint), never silently passes.

## Contract and docs single-source

`docs/contract/agent-contract.json` is the only source for the agent contract. Rendered surfaces (`docs/agents.md` generated blocks, `safe explain`) regenerate via `scripts/render-contract.sh`; never hand-edit generated blocks. `tests/contract/drift.sh` enforces this.

## Releases

`VERSION` and the `SAFE_VERSION` constant in `bin/safe` move together (drift-suite guarded). Update `CHANGELOG.md` (`## Unreleased` section) with behavior changes in the same PR.

## Tests

Bash suites, no framework: `tests/install/run.sh`, `tests/audit/*.sh`, `tests/contract/drift.sh`. Run the suites touching your change before any PR; new behavior gets a case in the matching suite.

## Git

`main` is push-protected; land via squash-merge PRs. Non-default branches are fine to push.

## Inbox

`inbox/` holds dated capture notes (park lane). Closures append a dated `## Resolution` section with verifiable evidence and land via PR; notes are never deleted. `inbox/private/` is gitignored (local-only). `PROGRESS.md` is gitignored by design — local session-handoff notes, never committed.
