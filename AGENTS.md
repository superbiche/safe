# Safe — shared agent instructions

Context marker: `safe:AGENTS.md`

Canonical shared rule source for this repo; vendor bridge files (`CLAUDE.md`, …) import it and add only harness-specific deltas.

## What this repo is

`safe` is a bash package-install security gate: `bin/safe` (CLI + explain), `bin/safe-audit` (verdicts: OSV/Socket/blocklist, version resolution), `bin/safe-run` (sandboxed exec + host-allow/blocklist), `lib/gate-lib.sh` (PATH-wrapper routing), `lib/install-wrappers.zsh` (legacy zsh shims). `install.sh` deploys gate wrappers to `~/.local/bin`.

## Live-vs-repo trap

The installed gate is a COPY: repo edits change nothing live until `install.sh` re-runs, and gated shells hold zsh function snapshots from their start. Two false "shipped bug" reports came from stale snapshots — before reporting a live-behavior bug, verify which version actually ran (`safe --version`, wrapper realpath).

Running `install.sh` is pre-authorized whenever it makes the live gate better — after landing a fix, to close repo-vs-live skew, or to verify shipped behavior. Do it without asking; report what changed. It stays an ask only when the intent is anything other than improving the installed gate.

## Operator rulings (standing)

- Never suggest, match, or allowlist `@latest`; allow entries are pinned to resolved versions.
- Audit-infrastructure failure (Socket auth/429/network/timeout) must read as breakage-to-fix with a recovery path, never as a CVE signal.
- Refusals: single final stderr line; exit 100 (policy) / 102 (operator TTY needed) / 104 (audit BLOCK); 0/10/20 are `safe audit package-audit` verdict codes; 127 = genuinely missing command.
- Infra-only WARN override (ruled 2026-09-07): a gated WARN whose causes are ENTIRELY audit-infrastructure outages (the `GATE_INFRA_WARN_CAUSES`/`HOST_ALLOW_REVIEW_INFRA_CAUSES` set) is a missing signal, not a package finding — safe-audit signals it as gate exit 11. The install gates (`bin/safe`, `gate-lib`) offer a DELIBERATE per-instance TTY confirmation and, non-interactively, refuse 102 — never a host-allow package-vouch and never `--yes` (each would be the silent auto-pass the terminus ruling forbids). The two infra-cause sets stay byte-identical (drift-guarded). Open item (not yet ruled): a standing `install.auto_allow_tolerate` that lists an infra cause still auto-passes it BEFORE the exit-11 path — a silent standing pass the terminus ruling disfavors, left unchanged here because removing it is a breaking config change awaiting a separate operator decision.
- Adverse-WARN interactive override (ruled 2026-09-07): a gated WARN carrying a real package finding (Socket low score / critical / high / unclassifiable alert, or an affecting advisory — any cause OUTSIDE the infra set) exposes a deliberate operator override at an interactive terminal, not only the host-allow copy-paste hoop (exit 10). The install gates (`bin/safe`, `gate-lib`) print the finding, then offer `[y]` install once, `[a]` install and record a standing host-allow grant, or `[N]` cancel; `[a]` is offered only for npm/python (the ecosystems host-allow supports — a cargo/go/composer grant would mint a phantom npm entry, review F1), and its reason is CANNED — an acknowledgment ("I'm the operator and I accept the risk"), never a justification the operator types. host-allow is thereby repositioned: the operator's OWN interactive install uses the per-instance override; host-allow exists to pre-authorize packages AGENTS reinstall unattended. The agent/non-interactive path is deliberately unchanged (operator ruling: leave it): refuse 100 + host-allow hint, so an agent asks the operator to pre-authorize — exactly host-allow's purpose. The override reads /dev/tty, never stdin — `--yes` cannot reach it (no silent auto-pass). `[a]` on an adverse WARN re-confirms once: `safe run host-allow add` re-audits host-side, and granting host-execution trust to a flagged package earns its own confirm (kept over adding a bypass into the grant path). The infra override (exit 11) never offers `[a]` — a host-allow entry must not vouch for a non-event. Operator note: mise captures child stdio, so `mise upgrade` reaches the prompt only with `mise upgrade --raw` (the `-t` TTY test is kept as the honest agent/operator boundary rather than loosened to /dev/tty-openable, which would make agents launched from the operator's terminal hang on the prompt).
- Fail-closed stays for malice signals (blocklist, critical advisory affecting the resolved version, Socket BLOCK). Resolution that cannot be predicted degrades honestly (package-level WARN + pin hint), never silently passes.
- Operator override is mandatory at every terminus (ruled 2026-09-07). Anything that can end in refusal/BLOCK/REJECT — a verdict, gate, review heuristic, feature, or proposal — MUST expose a conscious operator-override entry (a TTY override / documented escape hatch, e.g. exit 102 "operator TTY needed"). A terminus that leaves the operator no override lane is itself the defect and is rejected. Fail-closed means the operator must override deliberately, never that there is no override; the only thing an override cannot do is turn into a silent auto-pass.

## Reviews (repo default, ruled 2026-08-03)

ONE orthogonal review round per PR: sol/xhigh for verdict-affecting changes,
terra/medium for routine. Corrective findings close in-slice; the closure
evidence is the regression test + green suite, not a re-review. A delta
round runs only when round 1 found a BLOCKER or a fix is non-mechanical.
Rationale (24h data, 2026-08-03): multi-round chains produced ~21%
fix-caused findings while every operator-blocking defect arrived from live
use, not review rounds.

Chain mechanics (added 2026-08-27, liaison D0428; the open verb is law since
2026-08-21): every review chain is OPENED through the engine BEFORE the
review turn — `liaison review open <slug> --stance coordinator-hands
--coordinator-actor cc --coordinator-model <id> --coordinator-effort <tier>
--lane routine|deep --criteria "<verbatim>"` — and completed at close with
`liaison review record <chain-dir> --verify-ref <evidence> --review-input
assembled`. A chain closed without its engine-minted record fails liaison's
`review.hygiene` gate permanently (a record cannot be engine-minted after
the fact). The 2026-08-21→27 unopened safe chains were amnestied ONCE by
name (D0428); no grace after.

## Contract and docs single-source

`docs/contract/agent-contract.json` is the only source for the agent contract. Rendered surfaces (`docs/agents.md` generated blocks, `safe explain`) regenerate via `scripts/render-contract.sh`; never hand-edit generated blocks. `tests/contract/drift.sh` enforces this.

## Releases

`VERSION` and the `SAFE_VERSION` constant in `bin/safe` move together (drift-suite guarded). Update `CHANGELOG.md` (`## Unreleased` section) with behavior changes in the same PR.

## Tests

Bash suites, no framework: `tests/install/run.sh`, `tests/audit/*.sh`, `tests/contract/drift.sh`. Run the suites touching your change before any PR; new behavior gets a case in the matching suite. `tests/run-all.sh` runs every hermetic suite in parallel (~2 min wall-clock) — use it when a change touches more than one surface.

Parity belt (Go migration law): a slice migrating a surface to Go ports that
surface's tests to Go in the same slice, AND the surface's existing bash suite
stays registered in `tests/run-all.sh` (`SUITES`) and stays green run against
the Go implementation until the commit that deletes the surface's bash
implementation — only that commit may remove the suite. Live instance today:
suites build the working-tree Go binary via `tests/lib/safe-core.sh` and point
`SAFE_CORE_BIN` at it. Binary-audit variant (resolved 1.34.0): the
`release-review` composite's parity evidence was a fixture corpus (same
releases through the bash sub-lanes and `release-review`, verdicts diffed)
while both lanes existed. The six bash sub-lanes are now deleted, so the corpus
is retired with them, and the verdict-affecting divergences are frozen as
in-process Go goldens (`internal/releasereview/ledger_test.go`), one case per
ledger entry. Belt-not-run is red: `tests/run-all.sh` exports
`SAFE_TEST_STRICT=1`, under which a missing Go toolchain fails
`tests/go/run.sh` instead of skipping. `tests/run-all.sh` refuses unregistered
suites: every `tests/*/*.sh` file must appear in `SUITES` or its explicit
exclusion list. The suite-to-surface mapping (which commit may drop which
suite) is deliberately law, not tooling, until the mixed-era binary shape is
ruled.

## Git

`main` is push-protected; land via squash-merge PRs. Non-default branches are fine to push.

## Inbox

`inbox/` holds dated capture notes (park lane). A note exists to be consumed, not kept: when the work it asks for is done, promote anything durable into `docs/` (or the relevant code comment) and DELETE the note — an inbox item is an ask, never a record (operator ruling 2026-08-13, aligning this repo with the fleet consumption contract). Nothing durable may cite a live inbox path; a doc that wants to link a capture is the signal to promote its content now. A closure that lands in the same PR as its fix may go straight to deletion; a closure whose evidence needs to be visible to the operator first appends a dated `## Resolution` section and is deleted on the next sweep. `inbox/private/` is gitignored (local-only). `PROGRESS.md` is gitignored by design — local session-handoff notes, never committed.
