# Wrapper subcommand parsing: residual gaps

**Date:** 2026-07-06
**Source:** exec-gating implementation (follow-up to PR #15 review High 1)
**Affects:** lib/install-wrappers.zsh — argument parsing edge cases

## Known residual gaps (accepted for now)

1. **Global flags before the subcommand bypass dispatch.** Wrappers detect
   the subcommand as `$1`, so `pnpm --package=evil dlx cmd` or
   `npm --loglevel=error install evil` fall through to passthrough. Fix
   would be first-non-flag subcommand detection with per-tool value-flag
   skip lists (touches the hot path of every wrapper; wants its own tests).
2. **`uv tool run --with <extra>` extras are not audited** — only `--from`
   or the positional package is. `--with-requirements` files likewise.
3. **`npm exec` flag values not in the skip list** (`-c|--call|-w|
   --workspace` are handled) could be mistaken for the positional package
   and get audited — false-positive friction, not a bypass.
4. **`go get` is not gated.** Go module fetch runs no hooks at fetch time;
   execution happens at build with project code. Revisit if threat model
   changes.

## Suggested action

Item 1 is the only real bypass and deserves a small dedicated PR with a
parser test matrix. Items 2–3 are refinements to fold in with it.
