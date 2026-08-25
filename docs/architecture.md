# Architecture

`safe` is organized around one dispatcher and two direct component CLIs.

```text
safe
  run      -> sandboxed package runner
  audit    -> evidence and verdict engine
  install  -> audited npm host install, or safe run install with --sandbox
  vendor   -> safe vendor update
  setup    -> safe audit setup
  status   -> combined status
  doctor   -> local readiness diagnostics
```

The dispatcher forwards `safe run`, `safe audit`, `safe setup`, and unknown
runner invocations without changing their meaning. Direct binaries remain
installed for compatibility and for scripts that intentionally call `safe-run`
or `safe-audit`.

## Components

`safe run` decides how package execution is allowed:

- blocklist entries are refused;
- host allowlist entries run on the host with script execution suppressed where supported;
- unknown packages are sandboxed in Podman (after an interactive prompt);
- sandbox-known packages run in Podman without another prompt;
- unknown non-TTY execution blocks unless explicitly allowed by flags.

`safe audit` handles evidence gathering and verdicts:

- project and multi-machine scans;
- SBOM generation and vulnerability scans;
- package behavior checks;
- `release-review`, a composite that checks a downloaded release's checksums,
  signature, GitHub release and advisory metadata, TUF bootstrap material, and
  networkless execution;
- IOC updates and scans.

`safe install -g` runs `safe audit package-audit` for explicit package specs, prompts,
then delegates to the selected package manager. npm is the default; `--pnpm`,
`--yarn`, `--bun`, and `--composer` translate `-g` to each manager's native
global command. After successful installs of exact npm versions, interactive
runs can add that exact version to host-allow; `--trust-host` makes that step
explicit. `safe install --sandbox` keeps the isolated `safe run install` workflow.

Install wrappers are executable shims on PATH that exec `safe gate <tool>`.
The gate runs `safe audit package-audit` (install-gate mode) for package installs or
`safe audit repo-audit .` for project-local installs, then delegates to
the first non-wrapper executable of that name on PATH — so mise/asdf shims
and per-project tool versions keep working, in every shell.

`safe vendor update` wraps explicit vendor-native updater commands. It cannot
intercept in-process auto-updaters automatically, but it records a durable audit
trail for intentional updates that bypass package-manager safeguards.

## Direction: Go

`safe-core` (`cmd/safe-core`, with `internal/lockdiff`, `internal/verdict`, and
`internal/releasereview`) is the start of a gradual migration of `safe`'s logic
out of bash and into Go. New capability grows in Go, not bash, wherever the
choice exists.

Standing design constraint (operator ruling 2026-08-21): `binary-audit` moved
to Go composite-first — a single `release-review` command taking a release spec
and emitting one report, advertised under one capability key — rather than
porting the six sub-commands as-is. The composite was evaluated and dropped as a
bash slice: downloads and package-specific lanes stay consumer-side either way,
so the payoff only materialized as part of the Go migration. It shipped at
1.34.0, and the six bash sub-lanes it replaced are deleted.

`safe audit binary-audit release-review` is that composite; its spec, report,
taxonomy, and check status live in [Release Review](release-review.md).

## Trust Tiers

Packages move through four persistent tiers:

```text
blocked        never run
host-allow     pinned versions allowed on the host
sandbox-known  known enough for sandbox execution
unknown        prompt in TTY, block in non-TTY
```

`blocked.json` is shared by `safe run` and `safe audit package-audit`, so a package
blocked during audit is also refused by the runner.

## Data Flow

Runtime decisions and audit output are intentionally separated from config:

- config: policy and machine state under `~/.config/safe`;
- data: logs, SBOMs, scan results, package checks, and IOC output under `~/.local/share/safe`.

This keeps policy reviewable while allowing high-volume generated evidence to live in data directories.
