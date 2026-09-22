# Agent unattended installs when every light is green

Date: 2026-09-22. Source: operator ruling in chat during the Socket-scope PR
session. Direction approved for AFTER the socket-scope PR lands; the safe
session owns the design then.

## Ask

Allow agents (non-interactive shells) to complete package installs without an
operator when every light is green:

- audit verdict GO with no warn causes,
- no affecting advisories, blocklist pass,
- release OUTSIDE the Socket fresh window — the scope rule means no Socket
  call and no consent prompt is needed at all. A release inside the window
  still needs the operator (consent prompt; 102 non-TTY), per the 2026-09-22
  Socket scope ruling.

## Where the block lives today (verified while implementing the scope PR)

- Wrapper lane (lib/gate-lib.sh): a GO audit proceeds straight to
  `safe_gate_exec_real` — agents already install unattended here on GO.
- cmd_install lane (bin/safe `safe install --host`): after a GO audit,
  `safe_install_confirm` still demands a TTY (refuse 102) unless `--yes`.
  This final confirm is the main surface the follow-up would relax for the
  all-green case.

## Design questions to settle when picked up

- Exact "all green" definition: zero warn causes, or GO-with-tolerated-causes
  excluded? (Recommendation: zero causes, strictest reading.)
- Whether the agent path gets a distinct receipt/log marker (e.g. install-known
  recorded with an agent-context field) so audits can tell unattended green
  installs from operator ones.
- Whether it extends beyond npm/python lanes (pip/uv/cargo wrappers already
  proceed on GO — verify lane by lane).
- Contract/docs updates: safe explain, agents.md, CHANGELOG.

## Constraint

This relaxes safe enforcement. Only the operator rules on it — this note IS
that direction; implementation waits for the socket-scope PR to land first.
