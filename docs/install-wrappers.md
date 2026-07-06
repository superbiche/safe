# Install Wrappers

The install wrappers protect persistent host installs in zsh. They are installed at:

```text
~/.config/safe/install-wrappers.zsh
```

and loaded from `.zshrc` with:

```bash
source "$HOME/.config/safe/install-wrappers.zsh"
```

## Behavior

The wrappers shadow package-manager commands with zsh functions, run a check or scan, then delegate to the real command with `command <tool> "$@"`.

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
volta install pnpm@10.11.0
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
npm exec create-vite        # bare name: passthrough if ./node_modules/.bin/create-vite exists
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
refusal in both healthy and degraded modes.

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
and `composer exec` (project/vendor binaries only), `volta run` (official
runtimes only), `uv run` without `--with`/`-w`, and `go run` of local paths.
`npm exec <tool>` / `bun x <tool>` pass through only for a **bare** command
name backed by `./node_modules/.bin/<tool>`; a versioned or aliased spec
(`tool@1.2.3`, `tool@npm:other`) can still resolve to a remote fetch, so it
is always audited even when a same-named local bin exists.

## Refusal Contract

Every wrapper refusal is a single stderr line in the shape:

```text
safe: BLOCKED <tool> <action> — <reason>; to allow: <operator command>; details: safe explain
```

Refusals exit with dedicated codes so callers can distinguish a policy block
from a missing binary (127): `100` policy block, `102` interactive operator
confirmation required, `104` `safe audit` BLOCK verdict. See the
[Agent Contract](agents.md) page and `safe explain`.

## Degraded Mode (partial shell snapshots)

Some agent harnesses (Claude Code) snapshot interactive shell functions but
strip single-underscore names. The `safe_install_*` helpers deliberately
avoid a leading underscore so snapshots keep them, and every public wrapper
carries an inlined guard for the case where helpers are still missing:

- The audited subcommand families (installs, updates, exec-style
  fetch-and-run) refuse with a `safe: BLOCKED` line and exit 100 instead of
  failing with a silent 127.
- All other subcommands pass through, mirroring what healthy shells pass
  through by design: `pnpm exec`, `composer exec`, `volta run`.

Degraded guards cannot run the full argument parser, so they are
**conservative**: they refuse whenever a fetch *might* be requested and may
over-refuse a few non-fetch invocations. They never under-refuse a real
fetch. Concretely versus a healthy shell:

- `uv run` refuses if `--with`/`-w` appears anywhere (a healthy shell only
  audits `--with` before the command, so degraded may over-refuse a `--with`
  that is actually the program's own argument).
- `go run` refuses if any argument contains `@` (a healthy shell parses the
  run target, so degraded may over-refuse a local run whose program args
  contain `@`).
- `npm exec`/`bun x` of a local `./node_modules/.bin` tool is refused,
  because the guard cannot safely verify the local-bin condition.

Do not rename wrapper helpers to `_`-prefixed names; that reintroduces the
silent-127 failure inside harness snapshots.

## Timeouts

Package checks are wrapped with `timeout` when it is available. Override the default 30 second timeout:

```bash
SAFE_INSTALL_TIMEOUT_SECONDS=60 npm install express
```
