# doctor reports "no missing prerequisites" while a needed ecosystem tool is absent

**Date:** 2026-08-13
**Source:** claude-code (residual of the osv-scanner lockfile-coverage fix)
**Affects:** `safe doctor` prerequisite reporting

## Observed

In `~/dev/personal/memory-sync-mcp` (a Go repo), `repo-audit` reports:

- `rainbow missing project audit tools for discovered ecosystems: govulncheck`
- and refuses with exit 2 unless `--allow-missing-tools` is passed.

`safe doctor` on the same machine prints `missing prerequisites: none`.

Both are telling the truth about different lists. Doctor enumerates the
unconditional prerequisites (cosign, checksum tools, podman, …) and the newly
added osv lockfile-format probe; the ecosystem auditors — `govulncheck`,
`pip-audit`, `cargo-audit`, `composer` — are conditional on what a project
turns out to contain, so they are absent from doctor's model entirely.

## Why it matters

Doctor is where an operator goes to answer "is my install healthy". A Go
project on this machine cannot complete an audit without a flag, and the tool
whose whole job is to say what is missing says nothing is. The gap is not that
doctor is wrong — it is that "healthy" is being reported against a list that
cannot include the tier the operator is about to need.

This is the same shape as the defect that produced this note: coverage that is
absent reads as coverage that is fine.

## Suggested action

Undecided, and it needs an operator ruling on scope before code:

1. Doctor reports the ecosystem auditors as a separate, clearly conditional
   block ("not installed; needed only by projects using X") — honest, but adds
   permanent noise for ecosystems the operator does not use.
2. Doctor takes an optional path and reports prerequisites for THAT project's
   discovered ecosystems — precise, but makes doctor project-aware, which it
   has never been.
3. Leave doctor alone: the audit surface already refuses with the exact tool
   name, which is arguably the right place for a conditional prerequisite.

`govulncheck` on this machine is simply not installed; installing it is a
separate, unrelated action from deciding what doctor should say.
