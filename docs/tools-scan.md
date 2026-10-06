# tools-scan

`safe audit tools-scan` reports the High and Critical advisories that affect the
tools mise has installed on this machine. The install gate audits a package
before it is installed; tools-scan covers what was published after: a tool
version that was clean on install day and later gets an advisory, in the tool
itself or in a dependency it embeds.

```bash
safe audit tools-scan                       # print the report
safe audit tools-scan --publish             # write ~/Sync/state/tool-vulns/<host>.json, print nothing
safe audit tools-scan --publish --out <file> --host <name>
```

With `--publish` the command is silent unless it fails: the report is read
where Vigie surfaces it, not on a terminal. `install.sh --tools-scan-timer`
installs and enables `safe-tools-scan.timer`, a daily systemd user timer that
runs `safe audit tools-scan --publish`; `safe release follow` keeps the flag on
later installs.

## What is scanned

- **Scope.** Every installed mise tool version a tracked config still
  references: `mise ls --installed --json` minus `mise ls --prunable --json`.
  A version only an old project pinned stays in scope until `mise prune`
  would remove it.
- **Inventory.** One syft SBOM per version directory, with installed npm
  packages and cargo-auditable metadata cataloged and the GitHub workflow
  files that ship inside npm packages left out. SBOMs are cached under
  `~/.local/share/safe/audit/tools-scan/sbom/`, keyed by the directory, its
  modification time, the syft version and the cataloger selection; an SBOM no
  version in scope uses is deleted.
- **Matching.** `grype db update` once per run, then grype on each SBOM against
  that database, with automatic updates off so one run uses one database.

## Coverage limits

- A tool whose directory yields no component is listed in `unscanned`. These
  are mostly Rust binaries built without cargo-auditable, single-file bundles
  (bun, pkg) and binaries without section headers. Nothing about them is known.
- A Go binary whose main module carries a pseudo-version (`v0.0.0-…`) or
  `(devel)` is matched on its dependencies and Go toolchain only: grype does not
  compare those main-module versions, so an advisory against the tool itself
  is not seen.
- Findings are version matches, not reachability: an embedded dependency can
  be affected without the tool using the vulnerable code.

## Publication: `tool-vulns/1`

Written to `~/Sync/state/tool-vulns/<host>.json` (Vigie's `Sync/state` producer
contract): a temporary `.<host>.*` file renamed into place. Every key is always
present. `null` means unknown, never zero or clean.

| key | meaning |
|---|---|
| `schema` | `"tool-vulns/1"` |
| `generated_at` | run time, ISO 8601 UTC |
| `host` | short hostname, or `--host` |
| `producer` | `"safe-core <version>"` |
| `severity_floor` | `"High"`: only High and Critical advisories are published |
| `scanners.syft`, `scanners.grype` | versions; `null` when the scanner did not resolve |
| `db.built` | build time of the grype database used; `null` when unknown |
| `db.usable` | grype reports the database valid; `null` when not checked |
| `db.update_error` | why `grype db update` failed, or `null`; a failed update with a usable database still matches |
| `scope.in_scope`, `scope.prunable` | version counts; `scope` is `null` when mise could not be read |
| `tools` | one entry per scanned version (below); `null` when the run failed |
| `unscanned` | `tool@version` of versions with no component; `null` when the run failed |
| `errors` | per-version failures, `{tool, version, stage: "sbom"\|"match", message}`; such a version is in neither `tools` nor `unscanned`. When every version in scope failed, the run fails (`error` set) and `errors` is kept |
| `error` | why the run failed, or `null` |

A `tools` entry: `tool` (mise tool id), `version`, `components` (SBOM artifact
count), `critical`, `high`, and `advisories`, each `{id, severity, component,
component_version, fixed_in}`. `fixed_in` is `[]` when no fixed version is
known. An advisory matched more than once on the same component version is
listed once. Versions with no High or Critical advisory are listed with zero
counts and `[]`.

## Exit codes

- `0`: the report was produced; per-version failures are in `errors`.
- `2`: usage error.
- `3`: the run failed (missing scanner or mise, unusable database, every
  version in scope failed to scan, publication failure). With `--publish` the report carrying `error` is still written
  when possible, and the reason is the single stderr line.
