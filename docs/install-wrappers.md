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

## Timeouts

Package checks are wrapped with `timeout` when it is available. Override the default 30 second timeout:

```bash
SAFE_INSTALL_TIMEOUT_SECONDS=60 npm install express
```
