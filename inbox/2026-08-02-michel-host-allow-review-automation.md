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
