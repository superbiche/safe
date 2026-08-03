# Recurring host-allow review: automated staleness check + operator digest

**Date:** 2026-08-02
**Source:** michel (inbox-sweep follow-up)
**Affects:** safe run host-allow lifecycle

## Problem

Host-allow entries accumulate and outlive their reason. Concrete case from
the sweep: `brace-expansion@2.1.4` was added during the CVE catch-22 (when
pinned entries were unmatchable) and is now dead weight — 2.1.4 audits GO
without any allow. Nothing ever re-examines the list; only a human who
happens to look finds the stale grants.

## Proposal

1. **`safe run host-allow review`** — for each entry, report: age, last
   matched / times used (audit-log join), and whether the pinned version now
   audits GO on its own (in which case the entry is removable). Output both
   human table and `--json`.
2. **Automation** — a systemd user timer (weekly/monthly) running the review;
   when it finds removable/stale/never-used entries, it produces a digest.
3. **Digest nudge** — deliver the digest to the operator rather than a log
   nobody reads: a dated note in the safe repo inbox is the natural fit
   (same park-lane conventions), optionally paired with a CalDav reminder à
   la `my-inbox` park-remind. Removal itself stays operator-only (TTY-gated),
   the digest just queues the decisions.

## Notes

- Same review shape could later cover `install-known.json` (TTL'd already)
  and the blocklist, but host-allow is the trust-bearing surface — start
  there.
- Immediate manual candidate once ruled: remove `brace-expansion@2.1.4`.

## Resolution (2026-08-03)

Shipped in 1.4.0 (PR #50, merge 05bc6f3; review chain
`~/.liaison/reviews/2026-08-03-safe-pr50-host-allow-review`, terra-high,
round1 FIX-FIRST → 2 deltas → SHIP):

1. `safe run host-allow review` — age, usage (execution log + install-gate
   overrides), re-audit per pinned entry (`removable` / `keep` /
   `review-urgent` / `unknown`); infra failure always `unknown`, never
   staleness evidence. `--json`, `--no-audit`.
2. `--digest` writes `inbox/<date>-safe-host-allow-digest.md` here when
   removable or review-urgent entries exist; never overwrites.
3. `install.sh --review-timer` (opt-in) installs the weekly systemd user
   timer; enabled on this machine 2026-08-03
   (`systemctl --user list-timers safe-host-allow-review.timer` → next
   Mon 09:17).

Deferred: CalDav pairing à la park-remind (digest note is the nudge for
now); extending the same review shape to install-known/blocklist.
Manual candidate once ruled: remove `brace-expansion@2.1.4` (currently
reports `unknown` under the Socket 429; expect `removable` when it clears).
