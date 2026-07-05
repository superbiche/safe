# Gate exec-style subcommands and update aliases in healthy wrappers

**Date:** 2026-07-05
**Source:** GPT 5.5 xhigh adversarial review of PR #15 (tmp/agent-legibility-review-FINDINGS.md, High finding 1)
**Affects:** lib/install-wrappers.zsh — healthy-shell (non-degraded) gating

## Observed

In a healthy zsh with wrappers fully loaded, these reach the real tool with
zero audit — logged by the reviewer with stubbed tools, no AUDIT lines:

- `npm exec --package <pkg> -- <cmd>`, `npm x <pkg>`
- `npm update <pkg>` (and aliases `u`, `up`, `upgrade`), `npm it` / `npm install-test`
- `pnpm dlx <pkg>`, `bun x <pkg>`, `yarn dlx <pkg>`
- `uv run --with <pkg> <cmd>`, `uv tool run <pkg>`
- `go run <module>@<version>`
- `composer exec <pkg>`
- `volta run ...`

This is pre-existing (wrappers only ever gated install subcommands; the
npx/bunx/uvx binary symlinks don't cover these paths), but PR #15 made the
inconsistency visible: degraded mode refuses these, a healthy shell does
not. An agent can bypass the audit entirely via `pnpm dlx <pkg>`.

## Decision context

Ruled during PR #15 review reconciliation: keep PR #15 a legibility fix,
document the gap honestly (done — safe explain, docs/agents.md,
install-wrappers.md), and design healthy-mode gating as its own PR.

## Suggested action

- Route exec-style subcommands through `safe_install_check` (audit + refuse
  on WARN/BLOCK, fail closed non-TTY), or translate them to `safe run`
  sandbox execution where semantics allow.
- Gate update/install-test aliases the same way install is gated today.
- Weigh friction: `npm update` and `pnpm dlx` are daily commands; consider
  host-allow/sandbox-known integration so trusted flows stay fast.
- Add the healthy-vs-degraded parity test matrix the reviewer proposed
  (everything degraded blocks is either gated healthy or documented).
- Verify pnpm/yarn/bun alias sets against current manuals (reviewer only
  verified npm 11.14.1).
