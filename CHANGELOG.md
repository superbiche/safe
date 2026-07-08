# Changelog

## Unreleased

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
