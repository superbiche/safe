# Command Reference

## Dispatcher

```bash
safe run <args...>
safe audit <args...>
safe install [--allow-scripts] <pkg> [...]
safe vendor update --name NAME --path PATH --reason TEXT -- COMMAND...
safe setup [<machine> | --all | --machine <csv>]
safe status
safe doctor [--json]
safe version
safe help
```

Unknown top-level commands are treated like `safe run <args...>`.

## safe-run

```bash
safe-run [flags] <package>[@<version>] [-- args...]
safe-run host-allow add <pkg>@<ver> [--reason "..."]
safe-run host-allow update <pkg>@<new> [--reason "..."]
safe-run host-allow remove <pkg>
safe-run host-allow list
safe-run block add <pkg> --reason "..."
safe-run block remove <pkg>
safe-run block list
safe-run block import <url-or-file>
safe-run audit [--blocked] [--since 24h]
safe-run status
safe-run link [--force]
safe-run unlink
safe-run install [-w -n] [--allow-scripts] <pkg>...
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

## safe-audit

```bash
safe-audit capabilities [--json]
safe-audit scan [--project <path>] [--all | --machine <csv>]
safe-audit check <pkg>@<version> [--ecosystem <name>] [--json]
safe-audit release github --repo OWNER/REPO --version TAG --asset NAME [--tag-regex REGEX] [--json]
safe-audit vuln github-release --repo OWNER/REPO --version TAG [--json]
safe-audit verify release-asset --artifact PATH --checksum PATH [--certificate PATH --signature PATH --certificate-identity-regexp REGEX --certificate-oidc-issuer URL] [--require-signature] [--json]
safe-audit verify sigstore-bundle --artifact PATH --bundle PATH --identity VALUE --oidc-issuer URL [--json]
safe-audit verify tuf-bootstrap --mirror PATH --root PATH --root-checksum SHA256 --target NAME=PATH [--target NAME=PATH ...] [--json]
safe-audit binary exec PATH [--timeout SECONDS] [--json] -- [ARGS...]
safe-audit ioc <identifier> [--all | --machine <csv>]
safe-audit ioc --list <ioc.json> [--all | --machine <csv>]
safe-audit ioc --update [--since <duration>] [--all | --machine <csv>]
safe-audit setup [<machine> | --all | --machine <csv>] [--bundle <scanners.tar.gz|latest>]
safe-audit setup --create-bundle [<scanners.tar.gz>]
safe-audit diff [--all | --machine <csv>] [--since <duration>]
safe-audit status
safe-audit --version
```

## Vendor Updates

Package-manager wrappers cannot intercept binaries that update themselves from
inside their own process. Use `safe vendor update` when deliberately running a
vendor-native updater:

```bash
safe vendor update \
  --name codex \
  --path "$(command -v codex)" \
  --version-cmd "--version" \
  --reason "needed for a specific fixed bug" \
  --rollback "reinstall previous pinned version" \
  -- codex update
```

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

The zsh wrappers cover these command families:

```text
npm, pnpm, yarn, bun
uv, pip, pip3
cargo
go
composer
volta
```

They run package checks for explicit package installs and project scans for lockfile or manifest based project operations.
