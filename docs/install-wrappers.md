# Install Wrappers

The install wrappers protect persistent host installs in **every shell** —
interactive zsh, `bash -c`, Makefile recipes, CI steps, and agent harnesses
alike. They are executables on PATH, installed by `install.sh` at:

```text
~/.local/bin/{npm,pnpm,pnpx,yarn,bun,pip,pip3,uv,cargo,go,composer}
```

Each one is a three-line shim:

```bash
#!/usr/bin/env bash
# safe-gate-wrapper v1 tool=npm
exec safe gate npm -- "$@"
```

All routing lives in `safe gate` (`~/.config/safe/gate-lib.sh`), so upgrading
safe upgrades the gate — the wrappers themselves never need rewriting.

They used to be zsh functions sourced from `.zshrc`. That only gated an
interactive zsh: a non-interactive shell went straight to the version-manager
shim and was never audited. `~/.config/safe/install-wrappers.zsh` still exists
and is still sourced (it now only warns, once, when an interactive shell finds
no wrapper installed), but it defines no wrapper functions.

An existing file of a wrapped name that does not carry the
`# safe-gate-wrapper` marker is never overwritten: `install.sh` reports it and
skips, leaving that tool ungated. `uninstall.sh` removes only marked wrappers.
Check the wiring with `safe status`, which reports one of five states per
tool: `installed`, `shadowed` (something earlier on PATH wins),
`not-on-path` (the wrapper exists but nothing resolves — the bin directory
is missing from PATH), `missing` (no wrapper file), or `foreign` (a file of
that name exists but safe does not own it).

## Behavior

A wrapper execs `safe gate <tool> -- "$@"`, which runs a check or scan, then
delegates to the real tool: the first executable of that name on PATH that is
not itself a wrapper. For node tools that is normally the mise/asdf shim, so
per-project tool versions keep resolving.

Package installs run:

```bash
safe audit check <package>@<version> --ecosystem <ecosystem>
```

Project-local installs run:

```bash
safe audit scan --project .
```

If `safe audit` is missing, wrappers warn once and continue. If package checks are available, package install checks fail closed: `WARN`, `BLOCK`, timeouts, and audit failures stop before the real install command runs.

Project scans are stricter for critical findings. Non-critical scan failures warn and continue.

## Wrapped Package Installs

Examples that trigger package checks:

```bash
npm install -g cowsay@1.6.0
npm install express
pnpm add lodash
yarn global add typescript
bun add -g cowsay
uv tool install ruff
uv pip install black==24.4.0
pip install black==24.4.0
pip3 install pytest==8.3.0
cargo install cargo-edit
go install golang.org/x/tools/cmd/stringer@latest
composer require vendor/package
```

## Wrapped Project Operations

Examples that trigger project scans when matching project files are present:

```bash
npm ci
pnpm install
yarn install
bun install
uv sync
uv pip install -r requirements.txt
pip install -r requirements.txt
cargo build
cargo test
go mod download
go test ./...
composer install
composer update
```

Non-install and non-exec commands pass through unchanged.

## Wrapped Exec and Update Commands

Exec-style subcommands that fetch and run registry packages are audited the
same way installs are — the named package goes through `safe audit check`
before the real tool runs:

```bash
npm exec create-vite        # bare name: passthrough if node_modules/.bin/create-vite exists (cwd or parent)
npm x cowsay
npm exec --package=cowsay -- cowsay hi
pnpm dlx cowsay@1.6.0
yarn dlx create-react-app
bun x cowsay
uv run --with rich script.py   # audits the --with / -w packages only
uv tool run ruff
go run example.com/cmd/tool@latest
```

The package is identified as the value of `--package`/`--from` (or the first
positional); `uv --with`/`-w` extras are audited too. An **unknown** bare
(space-form) flag before the command is ambiguous, so the wrapper **fails
closed** with a legible refusal — rewrite it as `--flag=value` to
disambiguate.

`npm exec` uses npm's greedy config parser, so a `--package` even *after* the
command still selects the fetched package and is audited; the command's own
flags after it are ignored. `--with-requirements <file>` (uv) names a file of
packages that cannot be vetted inline, so it fails closed with a legible
refusal. `go run` classifies build flags
the same way (value vs switch, validated against `go help build`) and fails
closed on an unrecognized flag before the run target, so a value flag like
`-C dir` or `-mod mode` cannot hide a later `module@version`.

The per-tool flag tables (which flags select a package, take a value, or are
switches) are validated against each tool's `--help` and are load-bearing:
an unknown flag fails closed, but a *misclassified* known flag can bypass (a
boolean wrongly listed as value-taking would consume the package). Keep the
tables in sync with upstream when adding tools or flags; the test suite pins
the known cases.

Update families are gated like project installs (scan, plus package checks
for named specs): `npm update|u|up|upgrade|udpate`, `npm it|install-test`,
`pnpm update|up|upgrade`, `bun update`, `yarn up|upgrade|upgrade-interactive`,
`yarn global upgrade`.

Passthrough by design — these never fetch registry packages: `pnpm exec`
and `composer exec` (project/vendor binaries only), `uv run` without
`--with`/`-w`, and `go run` of local paths.
`npm exec <tool>` / `bun x <tool>` pass through only for a **bare** command
name backed by `node_modules/.bin/<tool>` in the physical cwd or a parent
directory (npm's own bin resolution, covering hoisted monorepos); a versioned or aliased spec
(`tool@1.2.3`, `tool@npm:other`) can still resolve to a remote fetch, so it
is always audited even when a same-named local bin exists.

## Refusal Contract

Every gate refusal is a single stderr line in the shape:

```text
safe: BLOCKED <tool> <action> — <reason>; to allow: <operator command>; details: safe explain
```

Refusals exit with dedicated codes so callers can distinguish a policy block
from a missing binary (127): `100` policy block, `102` interactive operator
confirmation required, `104` `safe audit` BLOCK verdict. See the
[Agent Contract](agents.md) page and `safe explain`.

## Snapshot-stripped shells are no longer a special case

The zsh wrappers carried inlined "degraded mode" guards for harnesses that
snapshot interactive shell functions but strip helpers, which used to produce
a silent 127 mid-install. Executable wrappers have no such state: a wrapper
either exists on PATH and execs `safe gate`, or it does not exist and the tool
is ungated. Nothing can be half-loaded.

The one comparable failure — `safe gate` unable to find its routing tables
(`gate-lib.sh` missing) — fails closed with the usual `safe: BLOCKED` line and
exit 100, never a silent passthrough.

## Timeouts

Package checks are wrapped with `timeout` when it is available. Override the default 30 second timeout:

```bash
SAFE_INSTALL_TIMEOUT_SECONDS=60 npm install express
```
