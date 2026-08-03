# Socket OSS free Team upgrade — parked (email draft ready)

**Date:** 2026-08-03
**Source:** michel (ruling on the Socket pricing research; parked because the
tiered-scoring design is the reasonable approach regardless)
**Affects:** Socket API quota (free tier: 1,000 scans/mo, 500 API units/hr —
the 429 source)

## Context

Socket Team is $25/dev/mo with a 5-seat minimum ($125/mo floor); no solo
SKU exists (verified against socket.dev/pricing 2026-08-03). Socket grants
free Team upgrades to public OSS projects on request; safe is MIT/public.
Team = 5,000 scans/mo + 2,500 units/hr. Optional if tiered scoring lands —
Socket becomes a rare tier-3 signal — but a free quota bump costs one email.

## Ready-to-send draft (support@socket.dev)

> Subject: Free Team upgrade request for an open-source project (superbiche/safe)
>
> Hi — I maintain safe (https://github.com/superbiche/safe, MIT), an
> open-source package-install security gate that calls the Socket API for a
> per-package behavioral score as part of its install verdicts. It runs
> solo/single-seat, so the 5-seat Team minimum doesn't fit, and the free
> tier's hourly API quota rate-limits the gate during normal use (agents
> performing audited installs).
>
> Per your OSS program
> (https://socket.dev/blog/free-team-plan-upgrades-for-open-source-projects)
> I'd like to request a free Team upgrade for the GitHub account
> `superbiche` / project `superbiche/safe`. Happy to provide anything else
> you need.
>
> Thanks — Michel Tomas

Alternative if the OSS program declines: the rate-limit docs
(https://docs.socket.dev/reference/rate-limits) invite a quota-increase
request with expected request rate and reason.

## References

- Research report: session artifact (Codex terra, claims verified live);
  pricing + free-tier numbers re-verified 2026-08-03.
- Related: `2026-08-03-michel-tiered-scoring-design.md` (the durable fix).
