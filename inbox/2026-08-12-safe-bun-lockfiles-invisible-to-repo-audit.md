# bun lockfiles are invisible to repo audit — bun projects audit on zero dependency evidence

**Date:** 2026-08-12
**Source:** safe (found while grounding a package-manager recommendation)
**Affects:** `bin/safe-audit` repo/machine audit — lockfile discovery

## Observed
`bun.lock` and `bun.lockb` appear **zero times** in `bin/safe-audit` (10,606 lines).
The npm-family lockfile lists all stop at yarn:

- `lockfile_ecosystem()` (1405): `package-lock.json|npm-shrinkwrap.json|pnpm-lock.yaml|yarn.lock`
- `manifest_matches()` (1419), `lockfile_matches()` (1432), the SBOM discovery `find`
  (4354), and the remote `ssh_batch` discovery (1694) all carry the same four names.

Consequence for a bun-only project (`package.json` + `bun.lock`, no `package-lock.json`):
`package.json` is discovered as a manifest, but no lockfile is. The `npm_lockfiles == 0`
branch at 2819-2831 then fires — `npm audit` reports `"no lockfile: these npm
dependencies are not audited"` and the verdict degrades to WARN. The project is audited
with **no dependency CVE evidence from any scanner**, because osv-scanner is never
pointed at a lockfile either.

This is the honest-degradation path working as designed (it warns rather than returning a
false GO), but the warning reads as "this project has no lockfile" when the truth is
"safe does not know how to read this project's lockfile".

## Why it matters
safe already gates bun as an INSTALLER in depth — `bin/safe-audit:5869-5893` models bun's
npmrc loader order precisely, including where it diverges from npm. So the tool takes bun
seriously on the install path and then cannot see bun's dependencies on the audit path.
A bun project on a safe-gated machine gets install-time gating and no repo-audit
coverage, which is exactly the asymmetry the gate exists to prevent.

No project in `~/.agents/projects.json` currently uses bun, so this is latent, not live.

## Suggested action
Two separable pieces:
1. **Discovery** — add `bun.lock` (text, JSONC) and `bun.lockb` (binary) to the four
   lockfile lists above so the `npm_lockfiles == 0` false signal stops firing.
2. **Evidence** — check whether the pinned `osv-scanner` version parses `bun.lock`. If it
   does, bun lands in the same one-tier bucket as pnpm/yarn and the fix is discovery
   only. If it does not, discovery alone would silence the WARN without adding evidence —
   strictly worse than today — so the two pieces must land together, with an explicit
   `unsupported` record from osv-scanner rather than silence.

Do not land (1) without settling (2).
