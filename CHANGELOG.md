# Changelog

## Unreleased

- Fix silent exit-127 wrapper failures in agent shells: rename
  `_safe_install_*` helpers to `safe_install_*` so harness shell snapshots
  (Claude Code strips single-underscore functions) keep them loaded.
- Add an inlined degraded-mode guard to every public wrapper: when helpers
  are missing, install/exec-ish subcommands refuse with a legible
  `safe: BLOCKED` line (exit 100) and everything else passes through.
- Standardize wrapper refusals to one stderr line — `safe: BLOCKED <cmd> —
  <reason>; to allow: <operator command>; details: safe explain` — with
  policy exit codes 100/102/104 instead of a generic 2.
- Add `safe explain`: prints the agent contract (gates, refusal format,
  exit codes, operator-only allow flows), plus a new Agent Contract docs
  page.
- Make `safe run host-allow add/update` operator-only: non-TTY invocations
  refuse with exit 102 so agents can suggest but never execute trust
  escalations.
- Document policy exit codes in `safe run` help and the command reference.

## 1.1.3 - 2026-06-29

- Make `safe audit scan` default to `source` mode: dependency evidence plus
  first-party source while skipping installed dependency trees and generated
  output.
- Add `safe audit scan --deps-only`, `--full`, and `--verbose` scan controls.
- Make project and default machine scans discover package ecosystems, require
  the matching audit tools, and fail closed instead of reporting missing tools
  as zero CVEs.
- Preserve valid `osv-scanner` JSON results when OSV exits nonzero because it
  found vulnerabilities.
- Fix scan result assembly for non-empty OSV and Grype findings.

## 1.1.2 - 2026-06-09

- Prefer `safe run`, `safe audit`, and `safe install` across docs, help,
  status, version, and wrapper output.
- Route install wrappers through the `safe audit` dispatcher command.
- Make `safe audit help` show audit help instead of erroring.

## 1.1.1 - 2026-06-08

- Preserve symlinked `.zshrc` files when installing, migrating, or uninstalling
  safe shell integration lines.

## 1.1.0 - 2026-06-04

- Add audited `safe install -g` host installs with confirmation before
  delegating to the package manager.
- Add global install translation for npm, pnpm, yarn, bun, and Composer.
- Add exact-version `--trust-host` support and post-install trust prompts for
  npm packages while refusing to trust `latest`, omitted versions, dist-tags,
  or ranges.
- Update help, completions, and docs to prefer `safe run` and `safe audit`
  over legacy hyphenated command names.

## 1.0.1 - 2026-06-02

- Harden `safe audit setup` so it no longer downloads scanner binaries, runs
  upstream installer scripts, or runs language package installers.
- Make scanner setup fail closed unless required scanners already exist or an
  explicit local scanner bundle is provided.
- Treat Socket CLI as optional for scanner setup.

## 1.0.0 - 2026-06-02

- Initial public release baseline.
