# safe

`safe` is a Bash toolkit for safer package execution, dependency auditing, and guarded installs. It provides `safe-run`, `safe-audit`, and persistent install wrappers behind one dispatcher, one installer, one config tree, and one zsh completion entry point.

## Documentation

Full documentation is published at <https://superbiche.github.io/safe/>.

## Quick Start

```bash
git clone <repo-url> safe
cd safe
safe audit scan --project .
bash install.sh
safe audit setup
safe run link
safe status
safe install -g cowsay@1.6.0
```

If `safe` is not already available on the machine, inspect the clone and run
equivalent local scanners before installing. This project is not exempt from its
own zero-trust model: clone it, scan it, then install it.

The installer is idempotent. Reruns refresh binaries and wrappers while preserving existing config and audit data.

## Core Commands

```bash
safe run repomix@latest -- --help
safe audit scan --project .
safe audit check left-pad@1.3.0 --ecosystem npm
safe install -g cowsay@1.6.0
safe install --sandbox --allow-scripts native-addon@1.0.0
safe install --trust-host -g cowsay@1.6.0
safe setup
safe doctor --json
```

`safe run` protects ad hoc package execution. `safe audit` scans projects, machines, releases, binaries, and IOCs. `safe install -g` audits npm packages, asks for confirmation, then delegates to `npm install -g` with flags preserved. Exact npm versions can be added to `safe run` host-allow after install with the trust prompt or `--trust-host`; `latest`, omitted versions, and ranges are never trusted. Use `--manager` or shortcuts such as `--yarn` and `--composer` to translate `-g` for other supported package managers. The install wrappers shadow package-manager install commands in zsh and call `safe audit` before delegation.

## Requirements

Required: Bash 5+, `jq`, and zsh.

Recommended: Podman for sandboxed execution, `curl`, `tar`, `ssh`, and
user-managed scanner binaries such as `osv-scanner`, `grype`, `syft`,
`govulncheck`, and `cosign`.

`safe audit setup` detects already-installed scanners or installs scanners from an explicit local bundle. It does not download scanners or run upstream installer scripts.

Scanner dependency policy and upstream links are documented in
[`docs/dependencies.md`](docs/dependencies.md).

Run:

```bash
safe doctor
```

to see the local readiness of sandbox, audit, verifier, and wrapper features.

## Local Docs

Full MkDocs-ready documentation lives in [`docs/`](docs/index.md).

Build or serve it with MkDocs when available:

```bash
scripts/docs build
scripts/docs serve
```

Versioned GitHub Pages publishing is documented in
[`docs/publishing.md`](docs/publishing.md).

## Status

This is personal security tooling. It is designed to fail closed in the most sensitive paths, but it is not a substitute for reviewing what a package, binary, or installer will do on your machine.
