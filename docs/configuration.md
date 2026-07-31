# Configuration

Unified config lives under:

```text
~/.config/safe/
  run/
    host-allow.json
    blocked.json
    sandbox-known.json
    install-known.json
    config.json
  audit/
    machines.json
    tools.json
  install-wrappers.zsh
```

Generated data lives under:

```text
~/.local/share/safe/
  run/
    audit.log
  audit/
    results/
    sbom/
    checks/
    ioc/
    host-allow-log.jsonl
    tool-bundles/
```

## Root Overrides

Move all config or data:

```bash
SAFE_CONFIG_DIR=/tmp/safe-config SAFE_DATA_DIR=/tmp/safe-data safe status
```

## Run Config

`host-allow.json` stores pinned package versions allowed to execute on the host.

`blocked.json` stores package names or patterns that should never run.

`sandbox-known.json` stores packages accepted for future sandbox execution.

`install-known.json` is machine-written by `safe audit check --gate install`:
one entry per `ecosystem:name` recording the pinned resolved version that
passed a clean version-aware check, the reasons, and a pointer to the check
receipt. It smooths the install gate only (offline/timeout fallback within
`install.auto_allow_ttl_days`); no `safe run` exec path consults it. Operator
host-execution trust stays in `host-allow.json`, which is TTY-gated and
unchanged.

`config.json` stores runtime defaults, linked runner paths, sandbox limits, warning behavior, and the install-gate policy:

```json
{
  "install": {
    "auto_allow": true,
    "auto_allow_tolerate": [],
    "trusted_registries": [],
    "auto_allow_ttl_days": 30,
    "block_severities": ["critical"]
  }
}
```

- `auto_allow`: record clean checks in `install-known.json` (GO still
  proceeds either way).
- `auto_allow_tolerate`: opt-in WARN causes (e.g. `socket_unavailable`) that
  may proceed when no advisory affects the resolved version. Default: none.
- `trusted_registries`: package sources (URL prefixes) the operator trusts
  like the default public registry. Any other custom source
  (`--registry`, `--index-url`, `--find-links`, `--no-index`,
  `--repository`) floors the verdict at WARN — public advisory data cannot
  vouch for a private artifact of the same name@version.
- `auto_allow_ttl_days`: freshness window for the offline/timeout fallback.
- `block_severities`: affecting-advisory severities that hard-BLOCK instead
  of WARN.

Common sandbox settings include:

```json
{
  "sandbox": {
    "pids_limit": 256,
    "memory": "2g",
    "cpus": "2",
    "nofile": "1024:1024",
    "timeout": 300
  }
}
```

## Audit Machine Config

Default machine config:

```json
{
  "machines": {
    "local": { "type": "local" },
    "remote-a": { "type": "ssh", "host": "remote-a" }
  }
}
```

Unknown machine names are treated as SSH host names.

`tools.json` records scanner paths per machine. `safe audit setup` updates it after installing or detecting scanners.

## Important Environment Variables

```text
SAFE_AUDIT_GRYPE_DB_MAX_AGE_DAYS
SAFE_AUDIT_GITHUB_RELEASE_MIN_AGE_DAYS
SAFE_AUDIT_GITHUB_HIGH_RISK_PATH_REGEX
SAFE_AUDIT_GITHUB_API_BASE_URL
GITHUB_TOKEN
SAFE_AUDIT_BINARY_IMAGE
SAFE_AUDIT_BINARY_TIMEOUT_SECONDS
SAFE_AUDIT_BINARY_STDIO_LIMIT
SAFE_AUDIT_BINARY_STDIO_LINES
SAFE_INSTALL_TIMEOUT_SECONDS
SAFE_ZSH_COMPLETION_DIR
SAFE_ZSHRC
SAFE_BIN_DIR
```

Use environment overrides for tests, temporary runs, or host-specific policy. Keep durable policy in config files.
