# Changelog

## Unreleased

- `safe install` gains a project mode: with no package named and a manifest in
  the current directory (`package.json`, `requirements.txt`, `pyproject.toml`,
  `Cargo.toml`, `composer.json`, `go.mod`), it bulk-audits what the project
  already depends on instead of printing a usage error. `--project` forces the
  mode. It runs `safe audit scan --deps-only --project .` and prints a
  one-screen summary — audited manifests, package count, findings by severity,
  verdict, and the top critical/high findings with package and advisory id.
  The mode audits only and never runs a package manager. Critical findings
  refuse with exit 104 even under `--yes` (`--yes` accepts WARNs only); a WARN
  verdict prompts interactively and refuses with 102 in a non-interactive
  shell; a clean verdict exits 0 quietly there. A scan that fails or leaves no
  readable result document fails closed with exit 100 rather than reporting a
  clean project. Decisions are recorded in the safe-run audit log as
  `install:project`.

- Lockfile-keyed scan cache for `--deps-only` scans: when the dependency
  evidence hashes to a set already scanned within 24 hours, the recorded result
  is replayed (`[safe audit] scan cache hit (<age>)`) with the same verdict and
  exit code instead of re-running osv-scanner, syft, and grype — a repeat scan
  of an unchanged tree drops from tens of seconds to well under one. Entries
  live in `~/.local/share/safe/audit/scan-cache/`, keyed on machine, target,
  mode, and each evidence file's own hash, so touching any lockfile or manifest
  forces a real scan. `safe audit scan --no-cache` bypasses the lookup and
  `SAFE_AUDIT_SCAN_CACHE_TTL_SECONDS` overrides the TTL. The cache can only
  skip work, never invent a verdict: missing, expired, corrupt, or
  unrecognizable entries fall through to a real scan, evidence-free scans are
  never cached, and source/`--full` scans are excluded entirely (they stage
  arbitrary files the evidence hash does not capture).

- The wrapper project-scan preflight now runs `safe audit scan --deps-only`, so
  a bare `npm ci` / `pnpm install` in an unchanged tree costs a cache hit
  instead of a full scanner run.

- Scan results carry `audit_totals`: the CVE-scan counts plus every ecosystem
  audit that ran (`npm audit`, `composer audit`, `cargo-audit`, `govulncheck`,
  `pip-audit`), with a per-scanner breakdown. Those advisory counts previously
  reached the result document but no verdict — a critical only `npm audit` saw
  left the scan at `GO`. The verdict and `safe install --project` both read the
  aggregate now. The counts are scanner *reports*, not deduplicated advisories
  (only osv and grype carry comparable ids), so anything shown to a human is
  broken down per source rather than summed.

- Ecosystem audits are normalized properly, which wiring them into the verdict
  made load-bearing. Previously every runner emitted `status:"ok"` regardless
  of what happened: a scanner that could not reach its advisory database was
  reported as a successful zero-finding scan — indistinguishable from a clean
  project. Now each runner keeps the exit status and validates the output
  shape, and unreadable output is `status:"error"` (which also makes the scan
  verdict `WARN` and blocks caching). Counts moved from containers to
  advisories: `pip-audit` lists one entry per *dependency* with its advisories
  under `vulns`, so a clean Python project used to score one `medium` per
  installed package; `composer audit` keys advisories by package, so its
  findings were invisible; `cargo audit` severities now come from the CVSS
  vector RustSec actually ships; `govulncheck` findings are deduplicated by
  OSV id. A severity that cannot be determined counts as `unknown` — it warns,
  it does not invent a band. An unrecognized scanner name is a configuration
  error rather than a silent skip. The remote scan helper carries the same
  normalizers, and a test compares the two copies verbatim.

- Scan cache hardening. An entry stores its schema, key, machine, target and
  mode, and every field is validated against the current request before replay,
  so an entry belonging to another project — or written by a safe that scored
  verdicts differently — misses instead of answering. Validation happens in a
  single jq predicate: a malformed timestamp used to be read into bash
  arithmetic, where `08` is a fatal error, which aborted the scan (exit 1) and
  read to a PATH wrapper as a scan failure it was willing to proceed past.
  Evidence is re-hashed after the scanners finish, so a result whose lockfiles
  changed mid-scan is not filed under the key those lockfiles produced. Results
  including a `govulncheck` run are never cached at all: it reads Go source,
  which no evidence hash covers. Nor is anything cached when an ecosystem or
  core scanner did not return `ok` (missing coverage is not a cacheable
  answer), or when a project holds known evidence that discovery did not hash
  — a symlinked lockfile, for instance, which `npm audit` reads and the file
  walk skips. `npm-shrinkwrap.json` is recognized as evidence. Evidence paths
  enter the key relative to the scan root, so a remote scan (staged into a
  fresh temporary directory every run) can hit the cache at all. A malformed
  TTL disables the cache rather than silently defaulting.

- `safe audit scan --result-out <file>` hands the caller its own copy of the
  result document, and scans now assemble that document privately before
  publishing it. The per-machine result path is one file per day: a concurrent
  scan of another project could replace it between the scan and the read, so
  `safe install --project` grades its own copy instead of parsing a path out of
  the rendered summary.

- `safe install --project` no longer swallows an install request. Combining it
  with package arguments or with `-g`/`--host`/`--manager`/`--trust-host` is a
  usage error instead of an audit-only exit 0 that installs nothing;
  auto-detection applies only to a bare `safe install`. A scanner that ran and
  failed now refuses with exit 100 naming the scanner and a recovery path
  (`--yes` could previously accept it as an ordinary WARN), an unknown verdict
  string refuses instead of being treated as acceptable, and a missing
  `safe audit` refuses with the `BLOCKED` contract rather than a bare exit 1.
  Scanner diagnostics go to a log file named in the refusal, keeping refusals
  to the contractual single stderr line — as does the audit-log write, whose
  own failure could previously add a second line. The refusal names the actual
  failure (nonzero exit, absent result, unreadable verdict) rather than always
  claiming no result was produced, and a critical refusal attributes the
  advisories to the scanners that reported them.

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
  words behind `exec --` stay a documented residual). Second review round:
  every helper query (`registry`/`ls`/`env`/`settings`) runs under the
  delegate's full context, including `--no-config`/`--no-env`/`--no-hooks`,
  and the audit runs from the `-C` directory so directory-scoped config
  files count as source; tool options are allowlisted rather than
  discarded (`npm_args`-class options take the notice path instead of
  vouching for a redirected install); env values travel base64-framed with
  strict typing (a newline in one value could otherwise export a second
  variable, and a non-string source value now refuses instead of auditing
  the default); `mise ls` entries require their fields (a missing
  `installed` no longer reports a package verdict for unreadable output)
  and jq diagnostics stay internal; `install --force` audits every
  configured tool, `upgrade --exclude` drops excluded targets,
  `--minimum-release-age` refuses non-exact targets; `--help`/`--version`/
  `--dry-run` pass through; counted verbosity (`-vvv`) is legal again;
  Cargo/pipx/composer registry variables joined the source allowlist.
  Third review round: `package_manager` is no longer treated as
  identity-neutral (it selects an installer with different registry
  inputs), and the bare preflight reads each configured entry's options
  via `mise tool --json` since `mise ls` hides them; a mise-selected
  Cargo/pipx/Composer/Bun registry takes the not-audit-gated notice path
  instead of a verdict computed against the default public source (safe's
  effective-source derivation covers npm/Python/Go only — extending it is
  tracked separately); env values round-trip byte-exactly (a trailing
  newline was being stripped by command substitution) and a value that
  cannot survive intact refuses; `requested_version` is required rather
  than defaulted; exclusion matching is backend-aware so an npm scope is
  not mistaken for a version; `use` honors `--minimum-release-age` like
  install/upgrade; `upgrade --interactive` declines with an
  explicit-target hint (same class as bare `mise use`); a leading global
  `--help`/`--version` passes through; and an unusable `-C` directory
  refuses with a real one-line message instead of a silent exit.

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
