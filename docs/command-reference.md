# Command Reference

## Dispatcher

```bash
safe run <args...>
safe audit <args...>
safe install [--project] [--yes]
safe install [-g|--global] [--yes] <pkg> [...]
safe install --manager npm|pnpm|yarn|bun|composer -g [--yes] [--trust-host] <pkg> [...]
safe install --sandbox [--allow-scripts] <pkg> [...]
safe vendor update --name NAME --path PATH --reason TEXT -- COMMAND...
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

### Policy exit codes

The exit-code table is **generated** into [Agent Contract](agents.md) from
`docs/contract/agent-contract.json`, which is also what `safe explain`
renders. It is deliberately not repeated here: this page carried its own copy
and the two drifted.

## safe run

```bash
safe run [flags] <package>[@<version>] [-- args...]
safe run host-allow add <pkg>@<ver> [--reason "..."]
safe run host-allow update <pkg>@<new> [--reason "..."]
safe run host-allow remove <pkg>
safe run host-allow list
safe run host-allow review [--json] [--digest] [--no-audit]
safe run scripts-allow add <pkg>@<x.y.z> [--reason "..."]
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
safe audit scan [--verbose] [--deps-only | --full] [--project <path>] [--all | --machine <csv>]
safe audit check <pkg>@<version> [--ecosystem <name>] [--installer <name>] [--json]
safe audit release github --repo OWNER/REPO --version TAG --asset NAME [--tag-regex REGEX] [--json]
safe audit vuln github-release --repo OWNER/REPO --version TAG [--json]
safe audit verify release-asset --artifact PATH --checksum PATH [--certificate PATH --signature PATH --certificate-identity-regexp REGEX --certificate-oidc-issuer URL] [--require-signature] [--json]
safe audit verify sigstore-bundle --artifact PATH --bundle PATH --identity VALUE --oidc-issuer URL [--json]
safe audit verify tuf-bootstrap --mirror PATH --root PATH --root-checksum SHA256 --target NAME=PATH [--target NAME=PATH ...] [--json]
safe audit binary exec PATH [--timeout SECONDS] [--json] -- [ARGS...]
safe audit ioc <identifier> [--all | --machine <csv>]
safe audit ioc --list <ioc.json> [--all | --machine <csv>]
safe audit ioc --update [--since <duration>] [--all | --machine <csv>]
safe audit setup [<machine> | --all | --machine <csv>] [--bundle <scanners.tar.gz|latest>]
safe audit setup --create-bundle [<scanners.tar.gz>]
safe audit diff [--all | --machine <csv>] [--since <duration>]
safe audit status
safe audit --version
```

`safe audit setup` detects existing scanner tools and can install scanners from
an explicit local bundle. It does not download upstream release assets, run
`curl | sh`, or run language package installers.

`safe audit scan` defaults to `source` mode: dependency manifests and lockfiles
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
`safe audit check` for each explicit package, prompts before installing, and
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

It runs `safe audit scan --deps-only --project .` (so it benefits from the scan
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

`safe install --sandbox ...` preserves the isolated `safe run install` workflow.

The PATH-executable gate wrappers cover these command families:

```text
npm, pnpm, pnpx, yarn, bun
uv, pip, pip3
cargo
go
composer
```

They run package checks for explicit package installs and project scans for lockfile or manifest based project operations.
