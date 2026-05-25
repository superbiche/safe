# Configuration

Unified config lives under:

```text
~/.config/safe/
  run/
    host-allow.json
    blocked.json
    sandbox-known.json
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

`config.json` stores runtime defaults, linked runner paths, sandbox limits, and warning behavior.

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
