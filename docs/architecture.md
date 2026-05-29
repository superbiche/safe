# Architecture

`safe` is organized around one dispatcher and two direct component CLIs.

```text
safe
  run      -> safe-run
  audit    -> safe-audit
  install  -> safe-run install
  vendor   -> safe vendor update
  setup    -> safe-audit setup
  status   -> combined status
  doctor   -> local readiness diagnostics
```

The dispatcher forwards arguments without changing their meaning. Direct binaries remain installed for compatibility and for scripts that intentionally call `safe-run` or `safe-audit`.

## Components

`safe-run` decides how package execution is allowed:

- blocklist entries are refused;
- host allowlist entries run on the host with script execution suppressed where supported;
- unknown packages are checked through `safe-audit` when possible;
- sandbox-known packages run in Podman without another prompt;
- unknown non-TTY execution blocks unless explicitly allowed by flags.

`safe-audit` handles evidence gathering and verdicts:

- project and multi-machine scans;
- SBOM generation and vulnerability scans;
- package behavior checks;
- GitHub release and advisory review;
- release asset, Sigstore bundle, and TUF bootstrap verification;
- networkless binary execution;
- IOC updates and scans.

Install wrappers are zsh functions that shadow package-manager commands. They run `safe-audit check` for package installs or `safe-audit scan --project .` for project-local installs, then delegate to the real command with `command <tool> "$@"`.

`safe vendor update` wraps explicit vendor-native updater commands. It cannot
intercept in-process auto-updaters automatically, but it records a durable audit
trail for intentional updates that bypass package-manager safeguards.

## Trust Tiers

Packages move through four persistent tiers:

```text
blocked        never run
host-allow     pinned versions allowed on the host
sandbox-known  known enough for sandbox execution
unknown        prompt in TTY, block in non-TTY
```

`blocked.json` is shared by `safe-run` and `safe-audit check`, so a package blocked during audit is also refused by the runner.

## Data Flow

Runtime decisions and audit output are intentionally separated from config:

- config: policy and machine state under `~/.config/safe`;
- data: logs, SBOMs, scan results, package checks, and IOC output under `~/.local/share/safe`.

This keeps policy reviewable while allowing high-volume generated evidence to live in data directories.
