# zsh install-wrapper `npm exec`/`bun x` passthrough is cwd-only (misses hoisted monorepo bins)

**Date:** 2026-07-08
**Source:** follow-up from PR #19 (safe-run local-bin parent walk) + GPT 5.5 xhigh review
**Affects:** lib/install-wrappers.zsh — `npm exec`/`bun x` local-bin passthrough

## Observed

PR #19 fixed the `safe run` (npx/bunx binary) local-bin tier to walk parent
directories for `node_modules/.bin/<name>`, matching npm's own bin resolution,
so hoisted monorepo workspaces resolve their installed tools instead of
falling into the sandbox pipeline. Real repro that drove it: `npx envsub`
from `~/dev/agentrh/apps/apps/teams` with `envsub` hoisted to the workspace
root `node_modules/.bin`.

The zsh **install-wrapper** functions have the same passthrough logic on a
separate code path, and it was **not** touched by #19:

- `lib/install-wrappers.zsh:666` — `[[ -x "./node_modules/.bin/${positional}" ]]`
- `lib/install-wrappers.zsh:581` (comment) and the exec-gate call sites

So `npm exec envsub` / `bun x envsub` typed directly in zsh from a workspace
subdirectory still only checks `./node_modules/.bin` in the cwd. From
`apps/teams` (bin hoisted to the root) the bare-name passthrough misses, and
the exec gate audits it as if it were a remote fetch — the same false-positive
class #19 fixed for the npx path.

## Why it matters

- Same monorepo gap, different subsystem. Anyone running `npm exec <tool>` (as
  opposed to `npx <tool>`) from a workspace subdir with hoisted bins hits it.
- Parity: after #19 the two passthrough paths disagree about what "local"
  means, which is confusing and means the wrapper over-refuses where the
  binary would not.

## Suggested action

Give the exec-gate bare-name passthrough the same parent-directory walk as
`find_local_project_bin` in `bin/safe-run` (built-in-only: no external `pwd`
or `dirname`, seed from physical cwd, blocklist still first). Ideally factor
the walk so both subsystems share one definition, but the wrapper runs in the
degraded/healthy zsh function context where helper availability differs — so
it likely needs an inlined built-in-only version mirroring the binary's.
Add a regression test mirroring the #19 hoisted-parent case for the
`npm exec`/`bun x` wrapper path. Reference implementation and the security
constraints (physical cwd, no shadowable commands) are in
`bin/safe-run:find_local_project_bin` and PR #19's 3-round review.
