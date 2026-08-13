# Direction 2: give `safe run` a working unknown-package audit preflight (host-side)

**Date:** 2026-08-13
**Source:** safe (follow-up to the removed sandboxed-audit preflight)
**Affects:** `bin/safe-run` — the unknown-package path and `host-allow`/`scripts-allow` reason policy

## Context

The sandboxed audit preflight was removed (CHANGELOG 1.21.0): it fetched an
unpinned `safe-audit` from npm via `npx` inside a Podman sandbox — a name this
repo never published, so on every real machine the fetch 404'd, the check
returned "inconclusive," and execution continued. The removal was
behavior-neutral in production because the preflight had never once produced a
verdict there.

Two things that only ever worked against a *mocked* podman went away with it:

1. `safe run` on an unknown package could BLOCK before sandboxing on an audit
   verdict.
2. `host-allow add`/`update` and `scripts-allow add` could skip `--reason` when
   the audit returned a clean GO.

To keep #2 honest, `--reason` is now unconditionally required (matches
`block add`). This note is the ask to bring back a *real* preflight.

## The ask

Run the preflight **on the host**, reusing the installed `safe-audit` binary —
exactly how `host_allow_review_probe` (`bin/safe-run`, the
`"$SAFE_AUDIT_BIN" package-audit … --json` call with a `timeout` leash,
`SAFE_AUDIT_NO_INIT=1`, and closed stdin) already audits pinned entries. No
container, no npm fetch.

## Why it is a behavior change, not a cleanup (the dormant-gate caveat)

Because the old preflight never fired live, activating a working one is a real
gate activation, not a no-op:

- The unknown-package path gains the ability to `exit 104` on a package that
  always passed before — it can start **refusing installs that succeed today**.
- `host-allow add`/`update` and `scripts-allow add` gain the ability to
  block/prompt (and to restore the clean-verdict-skips-reason affordance).
- Podman-less machines are irrelevant here (host-side audit needs no podman),
  which is *better* than the old path — but it means the gate now fires
  everywhere, uniformly.

So this ships behind its own review and its own decision on how aggressive the
unknown-package BLOCK should be (hard refuse vs warn-and-continue), plus whether
to restore the audit-gated `--reason` skip. Do not fold it into a cleanup PR.

## Pointers

- Removal PR: the 1.21.0 change that deleted `safe_audit_check_spec`.
- Host-side precedent: `host_allow_review_probe` in `bin/safe-run`.
- The bare npm name `safe-audit` is being defensively held (operator-owned
  placeholder) so the removed vector cannot be exploited in the interim.
