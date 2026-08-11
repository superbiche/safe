# safe shim: `npm dedupe` mutates unaudited; ranged `npm update` audited as @latest

**Date:** 2026-08-03
**Source:** apps (AgentRH image-scan-gate slice, same session as the safe-run-npm capture)
**Affects:** safe npm shim — audit coverage + target resolution

## Observed
1. `npm update react-router` (package range ^7.x, would install 7.18.2) was audited as `react-router@latest` → resolved 8.3.0, a different MAJOR than what npm would actually install. The WARN/allow hint then points at 8.3.0 ("pin an exact version first"), which is useless for the in-range bump.
2. `npm dedupe` went straight through the shim with NO per-target audits (only the project scan) and applied "added 14, removed 36, changed 40" — including DOWNGRADES that violated package.json `overrides` (mailparser 3.9.14-override → 3.9.8 installed, linkify-it 5.0.1 → 5.0.0). The overrides-violation part is an npm dedupe bug, but the shim treated a 40-package tree mutation as audit-exempt.
3. Third Socket failure mode seen today: `safe audit timed out (fail closed)` — in addition to 429 rate-limit and the WARN-no-score catch-22.

## Why it matters
- The dedupe hole means a command that changes dozens of resolved versions bypasses exactly the per-target scrutiny `npm install`/`update` get.
- Ranged-update-audited-as-latest produces wrong verdicts in both directions: blocks a safe in-range bump because @latest is a new major with no score, and would conversely GO a bad in-range version if @latest happened to be clean.

## Suggested action
- Audit `npm dedupe`/`npm prune` by diffing the lockfile resolution (pre/post or --dry-run) and auditing changed targets, or at minimum flag them as mutating commands.
- For `npm update <pkg>`, resolve the audit target from the package.json range (npm's own `--dry-run` output), not the registry dist-tag.

## Resolution (2026-08-11)

All three observations are closed; two were already fixed before this note
was triaged, one drove a full slice.

**Item 1 — ranged `npm update` audited as `@latest`: ALREADY FIXED.** PR #29
(`92c71fe`, 2026-08-01, "version-aware verdicts + install gate") added the
`project-range` resolution method: for `--op update` with an unpinned target,
`bin/safe-audit` reads the declared range from `package.json` plus dependent
ranges from the lockfile and picks the max-satisfying version with npm's own
latest-tag preference. The note's exact scenario is a passing fixture case in
`tests/audit/check_version_aware.sh` (`^2.0.0` → 2.1.4, never 5.0.1).
Re-verified live 2026-08-10 from the AgentRH `apps` workspace root:
`safe audit check react-router --ecosystem npm --op update` resolves
**7.18.1 (project-range)**, in-range — not the 8.x dist-tag. The incident
predates the deployed fix (the note is dated 2 days after #29 landed; the
installed gate was a stale copy — the repo's standing live-vs-repo trap).

**Item 2 — `npm dedupe` mutating unaudited: FIXED.** PR #70 (`e979a1f`,
safe 1.12.0, 2026-08-11). `npm dedupe`/`ddp`/`prune` (and npm's unique
command prefixes for them) now project their lockfile mutation into a scratch
directory via the resolved real npm (`--package-lock-only --ignore-scripts`),
diff it with the new Go helper `safe-core lockdiff`, and audit **only the
identities the mutation would introduce** — pre-existing project findings
never block a dedupe, while an introduced blocklist/advisory hit refuses
before delegation. Non-registry artifacts (git/file/remote) refuse rather
than being audited under a registry namesake. A missing `node_modules`
refuses outright, because the real command would then materialize every
lockfile artifact with nothing to diff (operator ruling 2026-08-10; the
partial-tree residual is tracked in
`inbox/2026-08-10-safe-lockdiff-partial-tree-residual.md`).

**Item 3 — `safe audit timed out (fail closed)`: FIXED.** PR #65 (`c45e504`,
1.10.1) replaced the fixed audit leash with one computed from component
budgets (1150s default), so a slow-but-working scan no longer reads as a
timeout; PR #66 (`b80e4f1`, 1.10.2) removed the `RLIMIT_FSIZE` leash that was
killing GuardDog on tarballs over 16 MiB.

**Evidence:** `tests/install/run.sh` 157/157 (dedupe/prune lane cases),
`tests/live/npm_config_oracle.sh` 23/23 against real npm 12.0.2 through the
shipped helpers, `tests/run-all.sh` 18/18. Deployed end-to-end on 1.12.0:
ordinary `npm dedupe` proceeds with per-target audit evidence; absent
`node_modules` refuses with exit 100 and a single stderr line. Review chain
(5 rounds) archived at `~/.liaison/reviews/2026-08-10-safe-slice1-lockdiff/`.
