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

### Trust is anchored to the canonical root

`SAFE_RUN_CONFIG_DIR` / `SAFE_CONFIG_DIR` relocate the config root, but the
**trust** decisions — host-allow host execution, `scripts-allow` lifecycle
scripts, and the trust-store writes (`host-allow add`/`update`/`import`,
`scripts-allow add`) — are honored only from the canonical
`~/.config/safe/run` store. This closes an escalation path: a process that can
run package managers only through `safe` cannot point it at a store it wrote
itself and thereby escape the sandbox. Against a redirected root safe **fails
safe** on reads (the grant is declined; the package still runs sandboxed) and
**refuses writes with exit 100**; the canonical blocklist is always consulted,
so a redirect can never hide a block.

If you genuinely relocate config and want trust to apply at the new location,
set `SAFE_RUN_TRUST_OVERRIDE=1` — it blesses the redirected store's **grants**
(host-allow host execution and `scripts-allow` lifecycle scripts) and lifts the
write refusal. It does **not** extend to the blocklist: that is a malice signal,
so the canonical blocklist is always unioned in regardless of the token — a
redirect, blessed or not, can only add blocks, never hide a canonical one. The
override is deliberately loud (it prints a warning on every honored grant) so
its use stands out. Note the bash-level limits: this guard
does not defend against a `HOME` redirection, and it is not a substitute for a
non-forgeable operator check or a root-owned store (both tracked for the Go
rewrite). It raises the bar and leaves a bright, greppable trail; it is not a
hard privilege boundary.

## Run Config

`host-allow.json` stores pinned package versions allowed to execute on the host.
Existing entries with retired metadata are ignored; newly written entries use
only the current pinned-version schema.

`blocked.json` stores package names or patterns that should never run.

`sandbox-known.json` stores packages accepted for future sandbox execution.

`install-known.json` is machine-written by `safe audit package-audit --gate install`:
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
    "socket": {
      "mode": "auto",
      "cache_ttl_days": 7,
      "cache_dir": "~/.cache/safe/socket"
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
- `socket.mode`: Socket is the primary behavioral tier. `auto` (default) and
  `always` both consult it for every check; `never` is the sole intentional
  skip. The skip is free — no request, no timeout — and is recorded as
  `socket_disabled`, distinct from the causes that mean the service failed.
  Because Socket is the only behavioral tier, a check that skipped it has no
  behavioral evidence, so `never` warns rather than passing on its own:
  advisories, blocklist, and release age still apply, and the result reflects
  what was actually gathered.
  If that posture is deliberate — an offline host, an exhausted quota, or a
  curated internal registry where advisories plus blocklist plus cooldown is
  the accepted policy — add `socket_disabled` to `auto_allow_tolerate`. The
  gate then passes and records `WARN_TOLERATED` rather than `GO`, so a
  tolerated skip is never later mistaken for a completed check.
- `socket.cache_ttl_days`: cache a validated successful Socket envelope for
  the exact ecosystem, package name, and resolved version. Default: `7`; `0`
  disables caching. Entries live under the cache dir (see `socket.cache_dir`),
  are private (`0700` directory, `0600` files), and are atomically replaced. On
  expiry, safe queries Socket again; if that query fails, the WARN line may
  disclose the last complete score and its age, but stale data never supplies a
  verdict.
- `socket.cache_dir`: the Socket cache root. Default: `~/.cache/safe/socket`; a
  leading `~/` expands to `$HOME`. Point it at a shared/synced location (e.g.
  `~/Sync/config/safe/socket-cache/`) to pay Socket's per-package scoring once
  across trusted machines instead of on every host. The cache is safe to share:
  entries are per-package JSON keyed by purl (no secrets — Socket scores are
  public), atomically written, and TTL-bounded, so concurrent writers and stale
  entries are already handled. The `SAFE_AUDIT_SOCKET_CACHE_DIR` env var
  overrides this (used by the test suite) and takes precedence over the config.

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
SAFE_INSTALL_TIMEOUT_SECONDS
SAFE_AUDIT_SOCKET_TIMEOUT
SAFE_AUDIT_SOCKET_CACHE_DIR
SAFE_ZSH_COMPLETION_DIR
SAFE_ZSHRC
SAFE_BIN_DIR
```

Use environment overrides for tests, temporary runs, or host-specific policy. Keep durable policy in config files.
