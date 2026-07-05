# Wrapper subcommand parsing: residual gaps

**Date:** 2026-07-06
**Source:** exec-gating implementation + GPT 5.5 xhigh review (PR #16)
**Affects:** lib/install-wrappers.zsh — argument parsing edge cases

## Remaining gap (accepted for now)

**Global flags before the subcommand bypass dispatch.** Wrappers detect the
subcommand as `$1`, so a global flag placed before it slips past routing:
`pnpm --package=evil dlx cmd`, `npm --loglevel=error install evil`,
`yarn --cwd sub add evil`. The fix is first-non-flag subcommand detection
with per-tool value-flag skip lists, touching the hot path of every wrapper;
it wants its own parser test matrix. This is the one real remaining bypass.

## Resolved since first captured

- Exec value-flag hiding the package (`npm exec --cache /x blockme`): fixed
  by the fail-closed parser — unknown space-form value flags now refuse
  instead of mis-auditing.
- `uv tool run --with`/`-w` extras no longer hide the tool package; `-w` is
  recognized as the short `--with` in both `uv run` and `uv tool run`.
- `go get` is still not gated. Go module fetch runs no code at fetch time
  (execution is at build with project code), so it is intentionally out of
  scope; revisit if the threat model changes.

## Suggested action

One small dedicated PR for the global-flags-before-subcommand parser, with a
per-tool test matrix. Everything else above is either resolved or an
accepted non-goal.
