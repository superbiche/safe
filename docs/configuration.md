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
    "block_severities": ["critical"],
    "cooldown_days": 3,
    "cooldown_security_fix": "exempt",
    "guarddog": {
      "enabled": true,
      "timeout_seconds": 120,
      "sandbox": "auto"
    },
    "socket": {
      "mode": "auto"
    }
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
  `--repository`, env selectors like `CARGO_REGISTRY_DEFAULT` or
  `BUN_CONFIG_REGISTRY`, and composer's global `config.json` repositories)
  floors the verdict at WARN — public advisory data cannot vouch for a
  private artifact of the same name@version. Non-URL identities are
  trusted verbatim: a cargo registry whose index URL safe cannot see is
  `cargo-registry:<name>`, and a disabled packagist is
  `local:packagist-disabled`.
- `auto_allow_ttl_days`: freshness window for the offline/timeout fallback.
- `block_severities`: affecting-advisory severities that hard-BLOCK instead
  of WARN.
- `cooldown_days`: WARN when any resolved version was published fewer than
  this many days ago (the compromised-release window; malicious versions are
  usually caught and yanked within days). Default: `3`; `0` disables. The
  WARN is overridable (exact host-allow pin, or `release_too_new` in
  `auto_allow_tolerate`); a failed publish-date lookup skips the check with
  a disclosed note, never a refusal.
- `cooldown_security_fix`: `exempt` (default) or `enforce`. A cooldown that
  blocks the release fixing a published CVE recreates the catch-22 this gate
  was built to end. When the resolved version IS the remediation — an
  advisory's `fixed` version equals it — `exempt` waives the cooldown and
  names the advisories it remediates, on the verdict line and in the
  receipt (`release.cooldown_waived`, `release.remediates`). `enforce`
  keeps the wait, on the reasoning that a compromised-maintainer release
  can carry a genuine fix as cover; the refusal then says the version does
  remediate and that this setting caused the refusal. The exemption only
  applies to advisories fixed AT a resolved version — it never waives the
  cooldown for an ordinary feature release.
- `socket.mode`: when to consult Socket. `auto` (default) is tier 3 —
  Socket runs only when the GuardDog behavioral tier produced no complete
  verdict (not installed, disabled, unsupported ecosystem, unresolved
  version, error/partial), so a Socket outage degrades only those rare
  consultations. `always` restores the pre-1.8 always-on behavior;
  `never` disables Socket entirely. A deliberate skip is recorded honestly
  in receipts and install-known reasons (`socket_skipped_tier3`, never
  `socket_ok`).
- `guarddog.enabled`: run GuardDog for exact resolved npm/PyPI versions.
  Default: `true`. A missing binary is reported as a non-adverse skip while
  Socket remains enabled in the current tiered-scoring slice.
- `guarddog.sandbox`: `auto` (default), `required`, or `off`. GuardDog
  extracts archives inside a kernel sandbox and refuses to scan when that
  sandbox is unavailable — on hosts where its sandboxed child cannot start,
  that means ZERO behavioral coverage rather than weaker coverage. `auto`
  retries once with `--no-sandbox`, discloses the weaker isolation on every
  surface (human output, receipt, `sandbox.fell_back`), and binds the result
  to a separate cache profile (`safe-nosandbox-v1`) so it can never replay
  as a sandboxed result. `required` keeps the hard failure (the tier then
  reports infrastructure breakage and Socket is consulted instead); `off`
  never sandboxes.
- `guarddog.timeout_seconds`: wall-clock limit for each GuardDog scan and its
  version probe. Default: `120`. Successful complete results are cached
  permanently under `~/.cache/safe/guarddog/`, keyed by the exact public
  registry artifact integrity, GuardDog version, and safe-owned scanner
  profile. Safe currently accepts GuardDog 3.1.0 and removes ambient
  `GUARDDOG_*` configuration before invoking it, so a caller cannot weaken a
  scan and seed reusable evidence. Override the cache root with
  `SAFE_AUDIT_GUARDDOG_CACHE_DIR` (primarily for tests). Because replay is
  permanent, GuardDog metadata-source updates alone do not invalidate an
  existing artifact/scanner/profile entry.

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
SAFE_AUDIT_SOCKET_TIMEOUT
SAFE_ZSH_COMPLETION_DIR
SAFE_ZSHRC
SAFE_BIN_DIR
```

Use environment overrides for tests, temporary runs, or host-specific policy. Keep durable policy in config files.
