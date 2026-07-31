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

`mise` itself is wrapped too: backend package installs (`npm:*`, `pipx:*`,
`cargo:*`, `go:*`) are audited on `mise install`/`up`/`use` — bare
invocations preflight the configured tools and audit not-yet-installed (and,
on `up`, non-exactly-pinned; on `up --bump`, all) backend entries — and a
gated command behind `mise exec --` gets the routing/audit pass while mise
keeps the execution. `mise exec` also preflights configured tools unless
`exec_auto_install` is verifiably disabled, since exec installs missing
tools on demand. Bare shorthands (`mise install prettier`) resolve to their
effective backend via `mise registry` before the runtime-vs-package call is
made; audits run with mise's project `[env]` package-source variables
applied, so the verdict covers the source mise will actually install from.
Official runtime installs (`node@22`) pass through; non-registry backends
(aqua/ubi/gem) and source-bearing specs (`pipx:owner/repo` GitHub
shorthands, `git+`/URL forms) pass with an explicit notice that they are
not audit-gated — a public-registry audit must never vouch for them.
Every helper query safe makes (`registry`, `ls`, `env`, `settings`) runs
under the same context as the delegated command — `-C`, `-E`, and the
config/env-disabling switches (`--no-config`, `--no-env`, `--no-hooks`) —
and the audit itself runs from the `-C` directory, since directory-scoped
config files (`.npmrc`, Cargo config, pip config) are part of the source.
Flags that change the target set change what safe audits: `install --force`
audits every configured tool (it reinstalls installed ones), `upgrade
--exclude` drops the excluded tool from the audit set, and
`--minimum-release-age` refuses for non-exact targets because mise
deliberately selects an older release than safe would check. Tool options
are honored, not discarded: an identity-neutral option (`bin_path`, `exe`,
`platform`, `os`, …) keeps the audit, while any other option — including
`package_manager`, which selects an installer whose own registry inputs
differ — can change the source, so the spec takes the not-audit-gated
notice path instead of a verdict for a package that may come from
elsewhere. Configured tools carry options too, and `mise ls` does not show
them, so the bare preflight reads each entry's options with
`mise tool --json` before trusting `key@version`.

Advisory sources safe can resolve against today are npm, Python (PyPI), and
Go. When a Cargo, pipx, Composer, or Bun registry is selected — by mise's
own environment *or inherited from the surrounding shell*, and on the
`mise exec -- <tool>` route as well as direct installs — safe does not
pretend to have checked it: that spec takes the not-audit-gated notice
path rather than reporting a verdict computed against the default public
source. Selectors apply to the installer that actually reads them: bun's
registry variable affects a bun install, not an npm one, and an exported
but empty selector chooses nothing, so neither suppresses an audit safe
can honestly perform. Directory-scoped config files (Cargo's `config.toml`,
Composer's, bun's `bunfig.toml`) are not yet detected; extending the
audit's source derivation to those ecosystems is tracked separately.

An unversioned explicit `mise upgrade <tool>` is checked at each of the
tool's configured requests that can actually move — an exact pin cannot,
so it is not reported as a verdict for a no-op — while `upgrade --bump`
is checked at the target it will move to rather than the request it is
leaving.

Display-only invocations pass through untouched: `--help` (including a
leading global one), a bare `--version`, and `--dry-run`/`--dry-run-code`
install nothing. A `--help` *after* `--` belongs to the inner command and
does not disarm the gate, and a leading `--version` *followed by a
subcommand* is not display-only — mise still installs, so it is gated.

An unversioned explicit `mise upgrade <tool>` upgrades within the tool's
configured request, so safe checks that configured version rather than the
latest one; a target with no configured request is refused rather than
guessed.

Fail-closed refusals: enumeration or env-derivation failure (refused as
infrastructure breakage, never a package verdict — this includes a missing
required field in `mise ls` output, a non-string value for a source
variable, and a `-C` directory that does not exist), `mise exec -c '<shell
string>'` (rewrite as `mise exec -- <argv…>`), bare interactive `mise use`
(rerun as `mise use <tool>@<version>`), and scope-changing flags the
preflight cannot model (`--monorepo`, `--inactive`, `--local`; per-directory
`-C` is threaded and supported). A launcher first word behind `mise exec --`
(`env`, `sh`, wrapper scripts) is a documented residual, same class as
absolute-path invocation: this is a seatbelt for cooperative agents, not a
jail.

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
