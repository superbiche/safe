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

## Displaced binaries

That rule has one exception, because for some tools it would mean the tool can
never be gated at all. `uv` installs itself to `~/.local/bin/uv` — exactly the
path its wrapper needs — so skipping left `uv add` and `uv sync` permanently
outside the gate.

For those tools `install.sh` moves the real binary aside instead:

```text
~/.local/bin/uv            # the wrapper
~/.local/bin/uv.original   # the binary that was there
```

`safe gate` resolves the delegate by walking PATH and skipping its own
wrappers; when that walk finds nothing, it falls back to `<tool>.original`.
The fallback is genuinely last — a real tool further along PATH, such as a
mise shim, still wins, so per-project versions are never overridden by the
displaced copy.

Two safeguards apply. If a `<tool>.original` already exists, nothing is moved
or overwritten: `install.sh` reports the conflict and leaves the tool ungated,
because that file may not be ours. And `uninstall.sh` moves the displaced
binary back when it removes the wrapper — removing the gate must not uninstall
the tool.
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

The audit's source derivation covers every wrapped ecosystem: npm, Python
(pip/uv env and config), Go (GOPROXY), Cargo, Composer, and Bun — env
selectors, argv selectors, and the parseable config files each installer
reads. Cargo registry selection (`--registry`/`--index`, the
`registry.default` key via `CARGO_REGISTRY_DEFAULT`, or mise's
`cargo.registry_name` setting) resolves the selected name through its
`CARGO_REGISTRIES_<NAME>_INDEX` environment definition; a name whose index
safe cannot see becomes the opaque identity `cargo-registry:<name>`, which
floors the verdict like any custom source and can be trusted verbatim in
`install.trusted_registries`. Composer repositories declared in
`$COMPOSER_HOME/config.json` (composer merges them into every run, global
and per-project) are read directly, including the packagist-disable
shapes; `COMPOSER_AUTH` carries credentials, not a source, and floors
nothing. Bun reads its own chain — `BUN_CONFIG_REGISTRY`, then npm's env
forms upper-before-lower, then its two npmrc files (the user one under
`XDG_CONFIG_HOME` when set) — and the audit judges that chain when the
installer is bun: selectors apply to the installer that actually reads
them, so bun's registry variable affects a bun install, not an npm one,
and an exported but empty selector chooses nothing. mise's
`pipx.registry_url` reaches the installer as a normalized PEP-503
`/simple` index and is judged as that endpoint. Which installer runs an
npm-backend install comes from the environment first and then from mise's
own `npm.package_manager` setting (which `mise env --json` does not
export); an unreadable or unrecognized value refuses rather than assuming
npm. A tool with several configured version requests is not audited at
all but flagged: mise reports one option set per tool, so safe cannot
tell which request carries which source.

What stays outside the model is TOML config: Cargo's `config.toml`
(`[source]` replacement and `registry.default` are not env-settable, so a
config file is the only way to set them) and bun's `bunfig.toml`. Ambient
config files are operator-owned machine state under the reviewed
boundary, but per-invocation injection of those surfaces fails closed
instead of earning a default-source verdict: `cargo install --config …`
and bun's `--config=<file>` on gated subcommands are refused, and a
`CARGO_HOME` set on the mise route keeps the not-audit-gated notice,
since it swaps in a config.toml safe does not read.

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
safe audit scan --deps-only --project .
```

The preflight is deps-only on purpose: what an install is about to change is
the dependency evidence, and that mode is the one the scan cache can replay, so
a bare `npm ci` in an unchanged tree costs a cache hit rather than a full
scanner run. The source-level risk scan a `--full` scan performs is not part of
the preflight; run `safe audit scan --project .` for that.

If `safe audit` is missing, wrappers warn once and continue. If package checks are available, package install checks fail closed: `WARN`, `BLOCK`, timeouts, and audit failures stop before the real install command runs.

Project scans are stricter for critical findings. The preflight reads the
scan's **result document**, not its exit code — a scan that finds a critical
advisory still exits 0, since its verdict lives in the document — so a critical
count above zero prompts interactively and refuses with exit 102 in a
non-interactive shell. Non-critical scan failures warn and continue, and a
scanner that ran and failed is named in that warning rather than passing
silently: the install proceeds, but what was not checked is said out loud. The
same holds when no verdict can be read at all — an unwritable result
destination, or a scan that failed outright: the preflight says the project was
not audit-gated instead of treating silence as a clean result, and it never
describes infrastructure breakage as a vulnerability finding.

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

Package checks are wrapped with `timeout` when it is available. The leash is
computed so it always exceeds the audit's sequential worst case — Socket
score (15s under the gate, `SAFE_AUDIT_SOCKET_TIMEOUT`) times two attempts
(the auth-failure vault retry), the GuardDog wall-clock budget
(`install.guarddog.timeout_seconds`, default 120s) times its version probe
plus up to four resolved versions, the paginated OSV query budget (80s) per
resolved version plus the cooldown re-query, and a 120s allowance for the
remaining individually bounded registry fetches. With defaults that is
1150s. The number is deliberately generous: the component
budgets are the operative bounds, so a hanging component degrades to its own
legible infra WARN inside a completed audit, and the leash only fires as a
backstop against a component escaping its own bound — which previously meant
an indefinite hang.

`SAFE_INSTALL_TIMEOUT_SECONDS` overrides the computed leash absolutely:

```bash
SAFE_INSTALL_TIMEOUT_SECONDS=60 npm install express
```
