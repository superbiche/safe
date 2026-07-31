# Changelog

## Unreleased

- Gate `mise` backend installs: `mise install`/`up`/`use`/`exec` previously
  installed registry packages (`npm:*`, `pipx:*`, `cargo:*`, `go:*` backends,
  lifecycle scripts included) with no audit at all. A `mise` PATH wrapper now
  routes through `safe gate`: explicit backend specs are audited like any
  install; bare `mise install`/`up` preflights the configured tools (via
  `mise ls --current --json`) and audits not-yet-installed entries — plus
  floating-version entries on `up` (a pinned installed entry cannot change
  without a config edit, so a fully pinned manifest audits nothing); a gated
  command behind `mise exec --` gets the full routing/audit pass with the
  exec left to mise (which owns the tool env). Official runtime installs
  (`node@22`) pass through untouched; non-registry backends (aqua/ubi/gem)
  pass with an explicit not-audit-gated notice. Review round: bare
  shorthands (`mise install prettier`) resolve through `mise registry` to
  their effective backend before the runtime-vs-package call (registry
  shorthands were installing npm packages unaudited); the audited identity
  is canonicalized (tool `[options]` stripped; `pipx:owner/repo` GitHub
  shorthands and `git+`/URL forms take the notice path instead of a false
  registry audit); enumeration and env-derivation failures refuse as
  infrastructure breakage instead of falling open; install/up/use/exec get
  exact flag tables (a value flag's value no longer reads as a tool spec,
  `-C`/`-E` thread into the preflight, `--monorepo`-class scope flags
  refuse, unknown equals-forms fail closed, `--locked` and friends are
  legal); non-exact pins ("3", ranges) count as floating on `up` and
  `up --bump` audits everything; `mise exec` preflights configured tools
  unless `exec_auto_install` is verifiably off; audits run under mise's
  project `[env]` package-source variables; `mise exec -c` and bare
  interactive `mise use` fail closed with rewrite hints (launcher first
  words behind `exec --` stay a documented residual).

- Second review round (PR#29 delta findings): custom package sources
  (`--registry`, `--index-url`, `--find-links`, `--no-index`, composer
  `--repository`) now floor the verdict at WARN for every ecosystem — exact
  versions included — because public advisory data cannot vouch for a
  private artifact of the same name@version; the operator lifts the floor
  per source via `install.trusted_registries` (or per version via a pinned
  host-allow). `safe install` and the uv wrapper thread the same selectors.
  OSV pagination rejects non-string/repeated tokens (a malformed
  completeness token no longer reads as zero advisories). SemVer prerelease
  identifiers compare per spec (identifier-by-identifier, numeric before
  alphanumeric) instead of lexically, and version-qualified `overrides` keys
  (`"pkg@^2.0.0"`) degrade resolution like bare ones. An adverse advisory
  result revokes recorded clean install-known evidence even when a pinned
  host-allow permits the current invocation, and the stale readers use the
  canonical ecosystem key (cargo/composer entries are findable again).

- Install gating now works in **every shell**, not just interactive zsh. The
  zsh wrapper functions are retired and replaced by executable PATH wrappers
  (`~/.local/bin/{npm,pnpm,pnpx,yarn,bun,pip,pip3,uv,cargo,go,composer}`), each
  a three-line shim that execs the new `safe gate <tool> -- <args...>`
  subcommand. Previously `bash -c 'npm i evil'`, a Makefile recipe, a CI step,
  or an agent harness bypassed the gate entirely by hitting the version-manager
  shim directly. All routing lives in `lib/gate-lib.sh` (installed at
  `~/.config/safe/gate-lib.sh`), a faithful bash port of the reviewed zsh
  routing tables, so gate upgrades ship with `safe` and the wrappers are never
  rewritten. The real tool is the first non-wrapper executable of that name on
  PATH, so mise/asdf shims and per-project tool versions keep working.
  `install.sh` refuses to overwrite an unmarked file of a wrapped name (it
  reports and skips); `uninstall.sh` removes only marked wrappers.
  `safe status` and `safe doctor --json` now probe every wrapper in the set
  (`installed` / `shadowed` / `not-on-path` / `missing` / `foreign`) instead of
  shell function state, and report the set healthy only when every tool
  resolves to its own wrapper — `not-on-path` covers the cron/service shape
  where the wrapper files exist but `$SAFE_BIN_DIR` is not on PATH, so nothing
  is actually gated.
  `lib/install-wrappers.zsh` remains, as a stub that defines no wrappers and
  warns once in an interactive shell when gating is absent.
  Two consequences of the process model: the "safe audit not installed" warning
  is now once per command rather than once per shell, and the degraded-mode
  guards are gone — an executable wrapper cannot be half-loaded. The Volta
  wrapper is retired (no `volta` wrapper is installed). The version/help
  switches (`--version`, `-v`/`-V`, `--help`, `-h`) are now classified as the
  valueless switches they are, so `npm --version` and friends pass through
  instead of failing closed. Volta's dead shim-backup resolution is deleted
  from `bin/safe-run`; `safe run link` clears stale Volta runner paths and
  host-allow exec resolves the real runner through `mise which` at exec time.

- Orthogonal-review hardening of the version-aware gate (PR#29 findings):
  version-scoped OSV results are server-authoritative — the local range
  comparator annotates but can never downgrade a hit to GO; OSV pagination is
  followed (a token-only page no longer reads as zero advisories, anomalies
  fail closed); target-altering selectors are threaded into the audit
  (`--tag` → dist-tag resolution, `--registry` → packument source,
  `--prefix`/`--working-dir` → project dir; custom pip/uv/cargo/composer
  indexes degrade to the unresolved refusal instead of auditing the default
  registry); the npm resolver follows npm-pick-manifest's latest-tag
  preference, no longer globs range tokens against cwd files, and degrades
  when root `overrides` mention the package; a WARN/BLOCK check revokes any
  stale install-known entry for that version and the timeout fallback only
  accepts verdict-GO evidence; severity now normalizes from qualitative
  labels AND standard CVSS v3 vectors (computed base score, most severe
  wins; v4-only floors at high); `cargo`/`composer` ecosystem labels map to
  their resolvers and OSV names, and `cargo install --version X` audits the
  pinned crate.

- Version-aware install verdicts: `safe audit check` now resolves the version
  the package manager would actually install (exact spec as-is; npm dist-tag
  for installs; the **in-range** target from `package.json`/lockfile ranges
  for `--op update`; registry latest for pip/uv, cargo, composer, go) and
  matches OSV advisories against that exact version's affected ranges.
  Previously the query sent `version:"latest"`, OSV returned every advisory
  ever filed, and the verdict was a version-blind count — which WARN-blocked
  the very bumps that remediate a CVE (inbox 2026-07-31, third occurrence).
  Advisories are classified `affecting`/`remediated`/`unfixed`/`ambiguous`;
  only affecting ones drive the verdict, with `install.block_severities`
  (default critical) escalating to BLOCK. Resolution failure degrades to a
  package-level audit with a WARN floor (`version_unresolved`), and an OSV
  outage now fails closed (it used to count as zero CVEs). Exit codes and
  plain `check` semantics are unchanged for consumers.

- New install gate mode (`safe audit check --gate install`), used by the zsh
  wrappers and `safe install`: GO proceeds with no operator terminal and
  records the pinned resolved version in machine-written
  `~/.config/safe/run/install-known.json` (evidence pointing at the check
  receipt; consulted only as an offline fallback when the audit times out,
  within `install.auto_allow_ttl_days`). WARN proceeds only on a pinned
  host-allow entry matching the **resolved** version — fixing the dead end
  where `npm update` audited `pkg@latest` and a pinned allow could never
  match — or via the opt-in `install.auto_allow_tolerate` causes. Refusal
  hints are always pinned (`host-allow add <pkg>@<resolved>`); nothing ever
  suggests `@latest`. Socket scoring failures refuse with an explicit
  infrastructure-failure message and recovery path (`socket login`,
  `safe doctor` now reports the Socket CLI/token wiring), clearly
  distinguished from a package finding. Wrapper and `safe install` gate
  decisions now leave a persistent record in the safe-run audit log
  (`install:<ecosystem> | ... | GATE | ... | PROCEED/REFUSED_*`).

- Add `safe vendor update --preset <vendor>` for claude, gh, op, uv, and
  codex: fills `--name`, `--path` (auto-detected on PATH), and `--version-cmd`
  so a native vendor update needs only `--reason` and the command; explicit
  flags still override. New `docs/vendor.md` collects the recipes, the
  trust calculus, and per-tool auto-update disablement.

- Close a universal bypass in the zsh install wrappers: every wrapper read
  its subcommand as `$1`, so a leading global flag hid the real command
  (`npm --loglevel=error install evil`, `yarn --cwd sub add evil`,
  `pnpm --filter=x dlx cmd`) and slipped the whole gate. A shared resolver
  now finds the first non-flag token, skipping leading global flags:
  `=`-form flags are unambiguous, per-tool value/boolean tables are skipped
  correctly, and any unrecognized space-form flag fails closed with a
  legible exit-100 refusal (escapable as `--flag=value`). Tables are kept
  small and are load-bearing (a MISclassified flag bypasses; a gap only
  over-refuses); `go` accepts no pre-command flags so any leading flag fails
  closed. Degraded-mode guards are unchanged (they match `$1` only, the
  conservative broken-shell fallback).

- Wrapper parity with `safe run`: the `npm exec`/`bun x` bare-name local-bin
  passthrough now walks `node_modules/.bin` from the physical cwd upward
  (npm's own bin resolution), so hoisted monorepo tools pass through instead
  of being audited as remote fetches. Builtin-only walk, immune to shell
  function/PATH shadowing, mirroring `find_local_project_bin` in safe-run.

- Extend the `safe run` local-bin tier to walk parent directories for
  `node_modules/.bin/<name>` (nearest first), matching npm's own bin
  resolution so hoisted monorepo workspaces resolve their installed tools
  instead of falling into the sandbox pipeline (`npx envsub` from a
  workspace subdirectory previously prompted to sandbox and then failed to
  fetch under strict no-network). Guards unchanged: bare unversioned
  unscoped names only, blocklist first; the audit log records the resolved
  bin path.

- Fix a false positive that broke husky-era pre-commit hooks: `npx
  --no-install lint-staged ...` was parsed with the flag as the package name
  and refused as exit 103 "invalid package name". Runner-native flags are now
  handled explicitly: `--no-install`/`--no` run the local
  `./node_modules/.bin` binary or refuse legibly (modern npx ignores the flag
  and fetches anyway; `safe run` restores its never-fetch meaning),
  `-q`/`--quiet`/`--silent` are dropped, npm-exec selector flags
  (`--package`, `-c`, workspace flags) refuse with exit 100, and any other
  unrecognized flag before the package fails closed with a legible exit-100
  refusal instead of a bogus 103.
- Add a local-bin decision tier to `safe run` (npx/bunx): a bare, unversioned
  name backed by `./node_modules/.bin` runs the already-installed local
  binary directly with no fetch, mirroring the install-wrapper rule. The
  blocklist still wins, and versioned or scoped specs stay in the audit
  pipeline.
- Gate exec-style fetch-and-run subcommands in healthy wrappers: `npm
  exec|x`, `pnpm dlx`, `yarn dlx`, `bun x`, `uv run --with|-w`, `uv tool
  run`, and `go run <module>@<version>` now audit the named package via
  `safe audit check` before delegating (GO proceeds, WARN/BLOCK refuse with
  the BLOCKED contract).
- Identify the exec package by `--package`/`--from` value or the first
  positional (npm's greedy parser also honors `--package` after the command,
  so it is audited there too); an unrecognized space-form flag before the
  command fails closed with a legible refusal (rewrite as `--flag=value`).
  `uv --with`/`-w` extras are audited; `--with-requirements <file>` fails
  closed since its packages can't be vetted inline. Per-tool flag tables are
  validated against each tool's `--help` and are load-bearing (a
  misclassified known flag can bypass), so they must track upstream.
- Audit versioned/aliased exec specs (`tool@1.2.3`, `tool@npm:other`) even
  when a same-named `./node_modules/.bin` binary exists; only a bare command
  name backed by a local bin passes through.
- `go run` classifies build flags (value vs switch, per `go help build`) and
  fails closed on an unrecognized flag before the target, so a space-form
  value flag (`-C`, `-mod`, ...) cannot hide a later `module@version` fetch.
- Gate update families like project installs: `npm update|u|up|upgrade|udpate`,
  `npm it|install-test`, `pnpm update|up|upgrade`, `bun update`, `yarn
  up|upgrade|upgrade-interactive`, `yarn global upgrade`.
- Document passthrough-by-design commands that never fetch registry
  packages (`pnpm exec`, `composer exec`, `volta run`, `uv run` without
  `--with`, local `go run`). Degraded-mode guards are conservative but
  parity-aligned: `pnpm exec`/`composer exec`/`volta run` no longer blocked,
  `uv run` blocked only when `--with`/`-w` appears, `go run` only when an
  argument contains `@`.

- Fix silent exit-127 wrapper failures in agent shells: rename
  `_safe_install_*` helpers to `safe_install_*` so harness shell snapshots
  (Claude Code strips single-underscore functions) keep them loaded.
- Add an inlined degraded-mode guard to every public wrapper: when helpers
  are missing, install/exec-ish subcommands refuse with a legible
  `safe: BLOCKED` line (exit 100) and everything else passes through.
- Standardize wrapper refusals to one stderr line — `safe: BLOCKED <cmd> —
  <reason>; to allow: <operator command>; details: safe explain` — with
  policy exit codes 100/102/104 instead of a generic 2.
- Add `safe explain`: prints the agent contract (gates, refusal format,
  exit codes, operator-only allow flows), plus a new Agent Contract docs
  page.
- Make `safe run host-allow add/update` operator-only: non-TTY invocations
  refuse with exit 102 so agents can suggest but never execute trust
  escalations.
- Document policy exit codes in `safe run` help and the command reference.
- Apply the same refusal contract to `safe install` host installs: audit
  WARN/failure exit 100, audit BLOCK exits 104, non-TTY confirmation exits
  102, each with a `safe: BLOCKED` line (previously generic exit 1).
- Format `safe run` invalid-package-name rejections as `BLOCKED` with the
  `safe explain` pointer (still exit 103).
- Extend degraded-mode gated lists with update/exec aliases (`npm
  x|it|install-test|update|up|upgrade`, `pnpm update|up|upgrade`,
  `bun update`, `yarn up|upgrade|upgrade-interactive`).

## 1.1.3 - 2026-06-29

- Make `safe audit scan` default to `source` mode: dependency evidence plus
  first-party source while skipping installed dependency trees and generated
  output.
- Add `safe audit scan --deps-only`, `--full`, and `--verbose` scan controls.
- Make project and default machine scans discover package ecosystems, require
  the matching audit tools, and fail closed instead of reporting missing tools
  as zero CVEs.
- Preserve valid `osv-scanner` JSON results when OSV exits nonzero because it
  found vulnerabilities.
- Fix scan result assembly for non-empty OSV and Grype findings.

## 1.1.2 - 2026-06-09

- Prefer `safe run`, `safe audit`, and `safe install` across docs, help,
  status, version, and wrapper output.
- Route install wrappers through the `safe audit` dispatcher command.
- Make `safe audit help` show audit help instead of erroring.

## 1.1.1 - 2026-06-08

- Preserve symlinked `.zshrc` files when installing, migrating, or uninstalling
  safe shell integration lines.

## 1.1.0 - 2026-06-04

- Add audited `safe install -g` host installs with confirmation before
  delegating to the package manager.
- Add global install translation for npm, pnpm, yarn, bun, and Composer.
- Add exact-version `--trust-host` support and post-install trust prompts for
  npm packages while refusing to trust `latest`, omitted versions, dist-tags,
  or ranges.
- Update help, completions, and docs to prefer `safe run` and `safe audit`
  over legacy hyphenated command names.

## 1.0.1 - 2026-06-02

- Harden `safe audit setup` so it no longer downloads scanner binaries, runs
  upstream installer scripts, or runs language package installers.
- Make scanner setup fail closed unless required scanners already exist or an
  explicit local scanner bundle is provided.
- Treat Socket CLI as optional for scanner setup.

## 1.0.0 - 2026-06-02

- Initial public release baseline.
