# Operations

## Readiness Checks

Human-readable:

```bash
safe doctor
```

Machine-readable:

```bash
safe doctor --json
```

`doctor` checks dispatcher parity, installed component paths, core tools, verifier dependencies, sandbox readiness, installed wrappers, completions, and linked runner state. It does not create config or data directories.

## Status

```bash
safe status
```

Status combines:

- top-level `safe` version;
- `safe run status`;
- `safe audit status`;
- install-wrapper installation state.

## Scanner Setup

Detect scanners on the local default machine:

```bash
safe audit setup
```

Configured machine:

```bash
safe audit setup remote-a
safe audit setup --machine remote-a,local
safe audit setup --all
```

`safe audit setup` does not download scanners or run upstream installer scripts.
Install scanner binaries manually after verification, or install from an audited
local bundle. See [External Dependencies](dependencies.md) for upstream project
links and the bootstrap policy.

Create a scanner bundle from an audited machine:

```bash
safe audit setup --create-bundle
safe audit setup --create-bundle ./scanners.tar.gz
safe audit setup --machine remote-a --bundle ./scanners.tar.gz
```

## Scan Modes

Default scans use `source` mode:

```bash
safe audit repo-audit .
safe audit machine-audit --machine remote-a
```

This scans dependency evidence plus first-party source and skips installed
dependency trees and generated output.

For a faster dependency-only pass:

```bash
safe audit repo-audit . --deps-only
```

For a deep scan that includes installed dependency trees:

```bash
safe audit repo-audit . --full
```

When validating scan scope, use verbose mode:

```bash
safe audit repo-audit . --verbose
```

## Diff Recent Results

```bash
safe audit diff --machine local --since 30d
safe audit diff --all --since 7d
```

## Logs And Evidence

Runner decisions:

```text
~/.local/share/safe/run/audit.log
```

Host-allow executions:

```text
~/.local/share/safe/audit/host-allow-log.jsonl
```

Audit check outputs:

```text
~/.local/share/safe/audit/checks/
```

Scan results and SBOMs:

```text
~/.local/share/safe/audit/results/<machine>/
~/.local/share/safe/audit/sbom/<machine>/
```

## Maintenance Checks

Before committing documentation or shell changes, run the smoke checks that match the touched area:

```bash
bash -n bin/safe bin/safe-run bin/safe-audit install.sh uninstall.sh
zsh -n lib/install-wrappers.zsh lib/completions/_safe
bash tests/integration/dispatcher.sh
bash tests/install/run.sh
bash tests/audit/smoke.sh
bash tests/run/safe_audit_integration.sh
git diff --check
```

Some tests require optional tools such as `zsh`, `curl`, `tar`, `sha256sum`, or `timeout`. `safe doctor` reports feature readiness for the same operational dependencies.
