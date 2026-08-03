# Review-chain hygiene backfill: pr29–pr32 archives fail lint (parked)

**Date:** 2026-08-03
**Source:** claude (surfaced by a liaison check run relayed by michel;
`review.hygiene` FAILs on safe-lane chains)
**Affects:** `~/.liaison/reviews/2026-07-31-safe-pr29-verdict-core`,
`…-pr30-gate`, `…-pr31-mise`, `2026-08-01-safe-pr32-bulk-audit`

## Fixed in-session (2026-08-03)

pr6, pr7, pr55, pr56 chains now pass `liaison review lint`: attestation
lines placed in findings files (they lived only in CHAIN-NOTEs), pr6's
verbatim copies renamed `.md`→`.txt` per the pr50 convention, pr56
normalized (canonical R12 vocabulary, delta heading grammar, CHAIN-NOTE
written) with reviewer originals preserved verbatim as `*.txt`. All
attestations evidence-backed from rollout `turn_context` lines, briefs
matched by content. Incident logged in the pr56 CHAIN-NOTE: its delta turn
ran at xhigh despite an acked `set reasoning_effort medium` (another
D289/my-acpx regression datapoint).

## Parked residual

The four 2026-07-31/08-01 chains (pr29 verdict-core — 11 rounds, pr30
gate, pr31 mise, pr32 bulk-audit) predate the D341 grammar and naming
conventions: old `*-FINDINGS*.md` scheme, no CHAIN-NOTEs, free-text or
absent R12 tags, no attestations. Honest normalization requires
archaeology (per-turn model/effort evidence from the July-31 rollout
jsonls, per-finding grammar rewrite across ~30 files) — not mechanical,
and attestations must never be invented.

Options for the operator ruling:
1. Dedicated backfill session (archaeology + normalization, reviewer
   originals preserved verbatim).
2. Grandfather explicitly: record these four as pre-convention archives
   exempt from `review.hygiene` (needs a liaison-side exemption mechanism
   or ledger entry so the check stops failing).

## Resolution

(pending)
