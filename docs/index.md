# safe

`safe` is a local security layer for package managers and external binaries.

It combines three workflows:

- `safe run`: sandboxed package execution for `npx`, `bunx`, `uvx`, and `pipx`-style workflows.
- `safe audit`: dependency, SBOM, release, binary, vulnerability, and IOC checks across local and SSH-accessible machines.
- install wrappers: executable PATH wrappers (`~/.local/bin/npm` and friends) that route every install, update, and exec-style fetch through `safe gate` in every shell — interactive or not — before the real command runs.

The repo installs a top-level `safe` dispatcher, direct component binaries, one config tree under `~/.config/safe` (including the gate routing library `gate-lib.sh`), one data tree under `~/.local/share/safe`, and one zsh completion file.

## Start Here

Clone, inspect, scan, then install:

```bash
git clone <repo-url> safe
cd safe
safe audit scan --project .
bash install.sh
```

If `safe` is not already available on the machine, run equivalent local scanners
before installing. The project is part of the same zero-trust model it enforces.

Check local readiness:

```bash
safe doctor
safe status
```

Run a package in a sandbox:

```bash
safe run repomix@latest -- --help
```

Scan the current project:

```bash
safe audit scan --project .
```

Project and machine scans default to dependency evidence plus first-party source
files, while skipping installed dependency trees such as `node_modules/` and
`vendor/`. Use `safe audit scan --deps-only --project .` for lockfile and
manifest evidence only, `safe audit scan --full --project .` for the complete
tree, and `safe audit scan --verbose --project .` to inspect the resolved scan
scope.

Guard persistent package installs. `install.sh` writes PATH wrappers to
`~/.local/bin`, so every shell — interactive or not — routes package managers
through the gate once that directory precedes the real tools on PATH:

```bash
safe install -g cowsay@1.6.0
safe status          # confirm: wrappers: ok (11/11 installed)
npm install express  # gated by ~/.local/bin/npm -> safe gate npm
```

## Main Safety Idea

Unknown package code should not get host access by default. `safe` prefers sandboxed execution, explicit pinned host allowlists, package checks before install, and auditable records of decisions.

For release binaries, `safe audit` separates source/release review, checksum or Sigstore verification, and networkless binary smoke execution.

For vendor-native tools that update themselves outside package managers, use
`safe vendor update` to record intent, command, rollback note, and binary hashes
before and after the updater runs.
