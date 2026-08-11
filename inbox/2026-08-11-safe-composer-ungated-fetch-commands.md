# composer reinstall / create-project are fetch-class commands outside the gated set

**Date:** 2026-08-11
**Source:** safe (abbreviation-sweep slice recon, session CC 4e132b92)
**Affects:** safe — composer lane gated-command set (lib/gate-lib.sh composer routing)

## Observed

While sweeping composer's symfony-console abbreviation dispatch (live
probes, composer 2.x on rainbow):

- `composer reinstall <pkg>` (and abbreviation `rei`) re-downloads package
  artifacts from the lockfile — a network fetch — and passes through the
  gate ungated (gated set is install/update/require + global require).
- `composer create-project <vendor/pkg>` fetches and materializes an
  arbitrary package tree (plus its dependencies, plus configured scripts)
  and is likewise ungated.

The abbreviation slice deliberately did NOT widen the gated set: routing
truncated spellings of already-gated commands is a bypass fix; adding new
commands to the gate is a policy change.

## Why it matters

Both commands import remote artifacts onto the machine without an audit.
`reinstall` is lockfile-pinned (lower risk — versions were previously
resolved, though artifacts are re-fetched), but `create-project` is the
composer equivalent of an unaudited bulk install and commonly the FIRST
command run in a new project.

## Suggested action

Operator ruling on scope: (1) gate `create-project` like an install-class
mutation (project scan of the materialized tree + per-target audit of the
root package, TTY semantics as usual); (2) decide whether `reinstall`
deserves the install lane's project scan or a disclosure-only note.
Whichever lands, the abbreviation classifier from the sweep slice should
cover the new names' prefixes for free.
