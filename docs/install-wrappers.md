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

Non-install commands pass through unchanged.

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

- Install/exec-ish subcommands (`npm install`, `npm exec|x|update`,
  `pnpm dlx`, `bun x`, `yarn dlx|upgrade`, `composer require`, `uv tool`,
  ...) refuse with a `safe: BLOCKED` line and exit 100 instead of failing
  with a silent 127.
- All other subcommands pass through to the real tool.

Degraded mode is deliberately stricter than a healthy shell: exec-style
subcommands (`pnpm dlx`, `npm exec`, `yarn dlx`, `uv run`) are not yet
audited by the healthy wrappers (a planned follow-up), but a degraded
environment cannot audit anything, so it refuses them outright.

Do not rename wrapper helpers to `_`-prefixed names; that reintroduces the
silent-127 failure inside harness snapshots.

## Timeouts

Package checks are wrapped with `timeout` when it is available. Override the default 30 second timeout:

```bash
SAFE_INSTALL_TIMEOUT_SECONDS=60 npm install express
```
