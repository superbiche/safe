# Trust-store hardening (parked consideration — not validated)

**Date:** 2026-08-03
**Source:** claude (PR #52 review chain, F1/F2 architectural findings; operator ruling: accepted as documented residual now, hardening parked as a consideration)
**Affects:** all operator trust surfaces (host-allow, scripts-allow, blocklist, config)

## The two confirmed properties (reviewer-verified, present since the initial commit)

1. **Synthetic PTY defeats TTY gating**: the operator-presence predicate is
   `[[ -t 0 && -t 1 ]]`; any process that allocates a pseudo-terminal
   (python pty, script, expect) satisfies it and can drive the y/N
   confirms. Exit 102 stops only callers that do not bother.
2. **Caller-selected trust store**: `SAFE_RUN_CONFIG_DIR`/`SAFE_CONFIG_DIR`
   env redirects every trust file to a directory the caller controls, and
   `SAFE_RUN_SEED_DIR` copies caller-selected content into missing stores.

Both are consistent with the documented seatbelt-not-jail doctrine
(cooperative agents), and docs no longer claim the TTY check proves
operator presence (corrected in PR #52).

## Hardening shapes IF ever validated

- Non-forgeable operator check: polkit action / `systemd-ask-password` /
  reauthentication against the login session, replacing bare TTY tests on
  `add`/`update` paths.
- Root-owned (or at least non-caller-writable) trust stores; refuse env
  overrides of the config root for trust-escalation subcommands.
- Signed trust entries (operator key), verified at consumption time.

## Status

Parked, not validated. Do not build without an explicit operator ruling.
Chain: `~/.liaison/reviews/2026-08-03-safe-pr52-scripts-allow/`.
