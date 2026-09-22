# Both live npm oracles SKIP on a machine whose only npm is safe-gated

Date: 2026-09-17. Source: slice `tests-home-isolation` (chain
`~/Sync/liaison/reviews/2026-09-17-safe-tests-home-isolation/`).

## Observation
rainbow has no system npm since the `nodejs` DNF package was dropped (2026-09-16). The only npm is
the mise shim, whose delegate is safe-gated. Under the isolated release gate (scratch HOME) the gate
fails closed ("safe gate library not found … in <scratch>/.config/safe"), which is correct. So
`tests/live/npm_config_oracle.sh` and `tests/live/npm_abbrev_oracle.sh` both SKIP there: the release
gate gives no live npm coverage on the operator workstation. On main the abbreviation oracle FAILED
instead (it used the refusal text as a prefix path); the slice turned that into a reasoned SKIP.

## Decision needed (later, not blocking)
Either accept the gap (hermetic parity suites cover the classifier), or give the two oracles a
read-only way to reach a real npm under the scratch HOME (for example resolve the node install's
own `bin/npm` behind the mise shim, bypassing the wrapper for a read-only `--version`,
`config list`, `prefix -g`), without pointing any SAFE_* variable at the real home.
