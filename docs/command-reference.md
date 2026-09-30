# Command Reference

## Dispatcher

```bash
safe run <args...>
safe audit <args...>
safe install [--project] [--yes]
safe install [-g|--global] [--yes] <pkg> [...]
safe install --manager npm|pnpm|yarn|bun|composer -g [--yes] [--trust-host] <pkg> [...]
safe install --sandbox [--allow-scripts] <pkg> [...]
safe install --reuse [--reuse-from <checkout>] [--dry-run]
safe vendor update --name NAME --path PATH --reason TEXT -- COMMAND...
safe release follow [--dry-run] [--checkout <dir>]
safe setup [<machine> | --all | --machine <csv>]
safe status
safe doctor [--json]
safe explain [--json]
safe report-fp <spec> [--ecosystem <eco>] [--source <agent>]
safe version
safe help
```

Unknown top-level commands are treated like `safe run <args...>`.

`safe explain` prints the agent contract: what is gated, the refusal
format, policy exit codes, version resolution, when to escalate, and the
operator-only allow flows. `--json` emits the same contract as data.

`safe report-fp <spec>` files a suspected false positive: it re-runs the
check, captures the evidence while it is still true, and writes a dated note
in safe's own `inbox/` for the operator to validate. It changes nothing —
no allowlist entry, no verdict, no trust state.

`safe status` includes one release-follow line: `release follow: <verdict>
<age>`, or `release follow: never run` when no non-dry pass has recorded state.

### Policy exit codes

The exit-code table is **generated** into [Agent Contract](agents.md) from
`docs/contract/agent-contract.json`, which is also what `safe explain`
renders. It is deliberately not repeated here: this page carried its own copy
and the two drifted.

## safe run

```bash
safe run [flags] <package>[@<version>] [-- args...]
safe run host-allow add <pkg>@<ver> --reason "..."
safe run host-allow update <pkg>@<new> --reason "..."
safe run host-allow remove <pkg>
safe run host-allow list
safe run host-allow review [--json] [--digest] [--no-audit]
safe run host-allow export [--json]
safe run host-allow import <file> [--dry-run]
safe run scripts-allow add <pkg>@<x.y.z> --reason "..."
safe run scripts-allow remove <pkg>
safe run scripts-allow list
safe run block add <pkg> --reason "..."
safe run block remove <pkg>
safe run block list
safe run block import <url-or-file>
safe run audit [--blocked] [--since 24h]
safe run status
safe run link [--force]
safe run unlink
safe run install [-w -n] [--allow-scripts] <pkg>...
```

Runner flags:

```text
--strict
-w, --write
-n, --network
-s, --allow-secrets
--node22
--py312
--proxy
-y, --yes
-h, --help
-v, --version
```

## safe audit

```bash
safe audit capabilities [--json]
safe audit machine-audit [--verbose] [--deps-only | --full] [--project <path>] [--all | --machine <csv>]
safe audit package-audit <pkg>@<version> [--ecosystem <name>] [--installer <name>] [--json]
safe audit repo-audit [<path>] [--verbose] [--deps-only | --full] [--no-cache] [--result-out <file>] [--allow-missing-tools]
safe audit binary-audit release-review --spec PATH   # whole-release composite; see docs/release-review.md
safe audit ioc <identifier> [--all | --machine <csv>]
safe audit ioc --list <ioc.json> [--all | --machine <csv>]
safe audit ioc --update [--since <duration>] [--all | --machine <csv>]
safe audit setup [<machine> | --all | --machine <csv>] [--bundle <scanners.tar.gz|latest>]
safe audit setup --create-bundle [<scanners.tar.gz>]
safe audit diff [--all | --machine <csv>] [--since <duration>]
safe audit lockfile-support [--json]
safe audit status
safe audit --version
```

`safe audit setup` detects existing scanner tools and can install scanners from
an explicit local bundle. It does not download upstream release assets, run
`curl | sh`, or run language package installers.

`safe audit machine-audit` defaults to `source` mode: dependency manifests and lockfiles
plus first-party source, while skipping installed dependency trees and generated
output. Use `--deps-only` for manifests and lockfiles only, `--full` to scan the
complete target tree, and `--verbose` to print project discovery, staged files,
and scanner inputs.

Missing required scanners or audit tools for discovered project ecosystems stop
the scan by default. If an interactive user explicitly continues, the missing
tool coverage is reported as `skipped` and the verdict is `WARN`, not zero CVEs.

## Vendor Updates

Package-manager wrappers cannot intercept binaries that update themselves from
inside their own process. Use `safe vendor update` when deliberately running a
vendor-native updater. A `--preset` (claude, gh, op, uv, codex) fills
`--name`, `--path`, and `--version-cmd` for a known vendor:

```bash
safe vendor update --preset codex --reason "needed for a specific fixed bug" \
  --rollback "reinstall previous pinned version" -- codex update
```

Or spell the fields out for a vendor without a preset:

```bash
safe vendor update \
  --name pulumi \
  --path "$(command -v pulumi)" \
  --version-cmd "version" \
  --reason "pin to 3.x" \
  -- pulumi plugin install ...
```

See [Vendor Updates](vendor.md) for recipes and per-tool auto-update
disablement.

The command records before/after SHA-256 hashes, optional version output, the
update command, exit code, reason, and rollback note in:

```text
~/.local/share/safe/vendor/audit.log
```

This is an audit trail for native vendor binaries, not a registry vulnerability
verdict. Prefer pinned target versions over `latest` when the vendor supports
them.

This command does not automatically block in-app auto-updaters. If a tool can
update itself while running, disable that tool's auto-update setting when
possible and run deliberate updates through `safe vendor update`.

## Install Wrapper Coverage

`safe install -g <pkg>` is the low-friction npm host-install path. It runs
`safe audit package-audit` for each explicit package, prompts before installing, and
then forwards to `npm install -g`. Use `--yes` to skip the final prompt after a
successful audit.

After a successful install of an exact npm version, interactive runs offer to add
that exact package version to `safe run` host-allow. Use `--trust-host` to make
that explicit in non-interactive workflows. `latest`, omitted versions, dist-tags,
and ranges are never trusted.

Use `--manager npm|pnpm|yarn|bun|composer` or shortcut flags such as `--yarn`
and `--composer` to translate `-g`:

```bash
safe install --pnpm -g cowsay@1.6.0
safe install --yarn -g typescript@5.0.0
safe install --bun -g cowsay@1.6.0
safe install --composer -g vendor/pkg:^1
safe install --trust-host -g cowsay@1.6.0
```

### Project mode (bulk audit)

With no package named and a manifest in the current directory — `package.json`,
`requirements.txt`, `pyproject.toml`, `Cargo.toml`, `composer.json`, or
`go.mod` — `safe install` bulk-audits what the project already depends on
instead of printing usage. `--project` forces the same mode.

```bash
safe install            # in a project directory
safe install --project
```

It runs `safe audit repo-audit . --deps-only` (so it benefits from the scan
cache) and prints a one-screen summary: audited manifests, package count,
finding counts by severity, verdict, and the top critical/high findings with
package and advisory id.

This mode **audits only** — it never runs a package manager, so there is
nothing to install afterwards; the confirmation records that an operator saw
the findings.

| Outcome | Interactive | Non-interactive |
| --- | --- | --- |
| Verdict `GO` | prompt to accept (exit 0 / 1 if declined) | exit 0, quietly |
| Verdict `WARN` | prompt to accept, or `--yes` | exit 102 unless `--yes` |
| Critical findings, or verdict `BLOCK` | exit 104 | exit 104 |
| Scan unreadable, failed, or unknown verdict | exit 100 | exit 100 |
| A scanner ran and failed | exit 100 | exit 100 |

Critical findings are the project-scale equivalent of a `BLOCK` verdict:
`--yes` accepts WARNs, never those. The count that decides is `audit_totals` —
the CVE scan plus every ecosystem audit that ran — so a critical only `npm
audit` or `composer audit` saw still refuses.

A scanner that ran and *failed* is broken infrastructure, not a finding: its
silence is not evidence of a clean project, so it refuses with exit 100, names
the scanner, and points at `safe doctor`. A scanner that is merely *absent* is
different — it is listed under `not run:` in the summary and leaves the verdict
at `WARN`, which still needs `--yes` or an operator. Evidence a scanner cannot
structurally read (`npm audit` facing a pnpm or Yarn lockfile) is reported the
same way but does not move the verdict at all.

Because it installs nothing, `--project` cannot be combined with package
arguments or with `-g`/`--host`/`--manager`/`--trust-host`/`--sandbox`; those
combinations are a usage error rather than a silent audit-only success. For the
same reason auto-detection only applies to a bare `safe install`: with any
install flag present and no package named, the usage error stands.

### Reuse of installed dependencies

A fresh git worktree has no `vendor/`. A normal `composer install` there is new
package ingress and is refused when the unchanged `composer.lock` carries
critical advisories — even though the exact same tree already sits in the main
checkout. `safe install --reuse` covers that case as its own operation: it
copies dependencies that are already on this machine. It runs no audit, no
`php`, no package manager and no network access, so its outcome is never an
audit result (operator rulings 2026-09-30).

```bash
cd <worktree>/<project>
safe install --reuse --dry-run     # verify and report, copy nothing
safe install --reuse               # source: first other checkout with the same lockfile
safe install --reuse --reuse-from /path/to/main/checkout
```

Identity is verified first. A mismatch means the tree is not this project's
dependencies, so it refuses with exit 100; the deliberate way through is the
normal install, with its own operator overrides at the terminal:

| Check | Refused when |
| --- | --- |
| Provenance | the source is not the same project path in a checkout of the same git repository, or its `vendor/` is a symlink or belongs to another user |
| Lockfile | `composer.lock` is not byte-identical (SHA-256) in both checkouts |
| Target | `vendor/` already exists and is not empty — reuse never overwrites, even if it appears during the copy |

The tree itself must be complete and self-contained. A gap here is an operator
decision: unattended shells and dry runs refuse with exit 102; at the
operator's terminal the gap is named and the operator may copy anyway, which
the receipt records as `operator_override`:

| Evidence | Gap when |
| --- | --- |
| Inventory | `vendor/composer/installed.json` does not list exactly the lockfile's packages (dev packages count when the source was installed with them), or is not in the Composer 2 format |
| Tree | a package has no install path, or its directory is missing or outside `vendor/` |
| Autoloader | `vendor/autoload.php` or `vendor/composer/autoload_real.php` is missing |
| Links | a symlink in the copied tree is absolute or leaves the project (also through another link in the target), or reaches a path repository that is absent in the target or whose package name or autoload rules differ there |
| Autoload rules | the root `autoload`/`autoload-dev` sections of `composer.json` differ, so the copied autoloader is wrong until `composer dump-autoload` runs |
| Integrity | the tree changed since its baseline (below), its baseline record is unreadable, or a file cannot be read and hashed |

Only what the inventory describes is copied: `vendor/composer`, the
autoloader and other top-level generated files, `vendor/bin`, and each
package's install path. Any other directory or link in `vendor/` is left
behind and listed as `skipped` in the output and the receipt. A path-repository
link is copied as a link, so in the target it reaches the target's own copy of
the package, as `composer install` would have made it.

Integrity is trust on first use. The first reuse from a source checkout records
a baseline: the SHA-256 of every file and the target of every link in its
`vendor/`. Later reuses from that checkout must match it; a changed file is a
gap, and an operator who accepts it re-records the baseline. A source
reinstalled with a new lockfile starts a new baseline. The first use is not
verified, and the receipt says which case applied. `--dry-run` hashes the
source and compares it with the baseline without recording anything (`baseline-recorded`,
`baseline-matched`, `baseline-re-recorded-new-lockfile`,
`baseline-re-recorded-by-operator`).

The copy uses `cp -a --reflink=auto` into a staging directory inside the
target: no hardlinks, so a test run that rewrites a vendored file never reaches
the source checkout. The staged copy is checked again, the lockfiles are
re-hashed, and the receipt and baseline are written before the copy is renamed
into place. One reuse per target runs at a time; an interrupted or refused
reuse removes its staging. If the receipt store under
`~/.local/share/safe/install/reuse/` is not writable, nothing is copied.

Every successful reuse ends as `reused-existing-vendor` with exit 0 (gate log
`REUSED_EXISTING`, or `REUSED_EXISTING_OPERATOR_OVERRIDE` after an accepted
gap). The receipt names the source checkout, the lockfile hash, the package
count, the integrity state and `audit: not run`. The copied dependencies keep
whatever advisories they had; audit them with `safe audit repo-audit .`.
Platform compatibility is not checked: the project's runtime (for example its
container image) decides it.

Same-machine reuse is a per-host rule. With `install.reuse.enabled: true` in
`~/.config/safe/run/config.json` it runs unattended, agents included. Without
it (the default) the operator confirms each reuse at an interactive terminal,
and a non-interactive or agent session refuses with exit 102. `--dry-run` works
either way.

Only Composer projects are covered. `--reuse` takes no package and cannot be
combined with `--project`, `--sandbox` or the host install flags.

`safe install --sandbox ...` preserves the isolated `safe run install` workflow.

The PATH-executable gate wrappers cover these command families:

```text
npm, pnpm, pnpx, yarn, bun
uv, pip, pip3
cargo
go
composer
mise
```

They run package checks for explicit package installs and project scans for lockfile or manifest based project operations.
