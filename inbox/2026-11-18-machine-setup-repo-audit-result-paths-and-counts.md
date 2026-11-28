# repo-audit: `--result-out` still overwrites the machine's daily scan; no per-scanner package count; data dir ignores XDG

**Date:** 2026-11-18
**Source:** machine-setup (Hermes gate pnpm work, Fibery task https://superbiche.fibery.io/Superbiche/Tasks/1512; worker and Muse review)
**Affects:** `safe audit repo-audit`

## Observed (Safe 1.75.0, Rainbow)
- `safe audit repo-audit --deps-only --result-out <file>` on a staged directory also writes the per-machine
  daily result and SBOM (`results/<machine>/<date>-scan.json`). Each Hermes gate audit therefore overwrites
  Rainbow's daily Safe scan with the staged Hermes closure.
- The result carries `summary.ecosystems.npm` from syft only, over the whole scanned tree. There is no
  per-scanner, per-lockfile package count, so a caller cannot prove that osv-scanner (or grype) read a given
  lockfile. A lock the scanners read as zero packages is reported clean. The Hermes gate now compares syft's
  count with its own count of the lock, which covers syft only.
- With `XDG_DATA_HOME` and `XDG_CONFIG_HOME` redirected for an isolated run, Safe still wrote its scan cache
  under `~/.local/share/safe/` (Muse review probe). Related to the earlier capture on the gate-lib lookup
  under a redirected HOME.
- `safe audit`'s npm audit reports `unsupported` on a `pnpm-lock.yaml`; callers have to treat that as
  not-an-error by themselves.

## Suggested
A flag (or the presence of `--result-out`) that keeps a caller-directed audit out of the machine's daily
result; per-scanner counts per lockfile in the result; honour the XDG variables for the data directory.
