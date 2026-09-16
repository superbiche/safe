# Operations

## Readiness Checks

Human-readable:

```bash
safe doctor
```

Machine-readable:

```bash
safe doctor --json
```

`doctor` checks dispatcher parity, installed component paths, core tools, verifier dependencies, sandbox readiness, installed wrappers, completions, and linked runner state. It does not create config or data directories.

## Status

```bash
safe status
```

Status combines:

- top-level `safe` version;
- `safe run status`;
- `safe audit status`;
- install-wrapper installation state.

## Scanner Setup

Detect scanners on the local default machine:

```bash
safe audit setup
```

Configured machine:

```bash
safe audit setup remote-a
safe audit setup --machine remote-a,local
safe audit setup --all
```

`safe audit setup` does not download scanners or run upstream installer scripts.
Install scanner binaries manually after verification, or install from an audited
local bundle. See [External Dependencies](dependencies.md) for upstream project
links and the bootstrap policy.

Create a scanner bundle from an audited machine:

```bash
safe audit setup --create-bundle
safe audit setup --create-bundle ./scanners.tar.gz
safe audit setup --machine remote-a --bundle ./scanners.tar.gz
```

## Host Allowlist Replication

Bringing up a new machine also means reconciling its host-allow set — the pinned,
reviewed tools that run outside the sandbox. That set is per-machine by design;
rather than rediscovering the first machine's set one failed install at a time,
export it and apply it once, under review:

```bash
safe run host-allow export > allow.json        # machine 1: portable, no secrets
safe run host-allow import allow.json --dry-run # machine 2: preview the delta
safe run host-allow import allow.json           # machine 2: reviewed apply (TTY)
```

`import` re-validates and re-fetches integrity for every entry, never overwrites
a divergent local pin, and refuses in non-TTY shells (exit 102) unless
`--dry-run`. For unattended fleet followers, opt in to signed UNION replication:

```bash
# Follower provisioning: import and independently verify the operator's public
# GPG key, then pin its full primary fingerprint at an operator terminal.
safe run host-allow follow-signer add <full-primary-fingerprint>

# rainbow: operator terminal (GPG key/passphrase or hardware-token touch).
safe run host-allow export --sign

# agent-dev: unattended preview, then apply (no TTY required).
safe run host-allow follow --dry-run
safe run host-allow follow
```

Signed exports are `~/Sync/state/safe/host-allow.<short-hostname>.json` with
`.json.asc` signatures. Synchronize these two files, not `host-allow.json` or
`config.json`. Use `export --sign --out <dir>` and `follow --from <dir>` for a
custom transport directory. Optional `follow.signing_key` selects the origin's
GPG key; `follow.signers` is maintained by the TTY-only `follow-signer add|remove`
commands. Provision public keys locally first; follow never retrieves keys.
Revocation and expiry are honoured, including revoked/expired signature statuses
that GPG can report with exit 0. Revoked or expired primary keys cannot be pinned.
Distribute revocation certificates and updated public keys to every follower's
local keyring; there is no automatic keyserver refresh.

A user timer can invoke `safe run host-allow follow` daily. This change does not
install a timer or automatically sign after add. Own-host files are ignored;
verified statements add only absent grants after import validation, retaining
the original `added` date and recording `followed_from`. Dry-run validates the
whole plan without changing persistent state. A machine-local `follow-state.json`
beside the guard-selected trust store records the highest accepted `exported_at`
per origin. Only strictly newer ISO-8601 whole-second timestamps with a timezone
are accepted; equal or older documents (even through another `--from`) emit a
WARN, increment the freshness-skip count and return non-zero. Thus a timer
re-reading an unchanged export reports a stale generation, rather than exit 0.
Exit 0 means all eligible files were fresh and handled, or no eligible files
existed; non-zero also surfaces skipped signatures, invalid entries or pin conflicts. Valid files can still apply
alongside failures. A transport delivering mismatched JSON/signature generations
causes a safe rejection; rerun after both files have arrived.

For a skipped file, the operator can review it and run
`safe run host-allow import <file>` at a TTY. Conflicting pins need the usual
`safe run host-allow update <pkg>@<version> --reason "..."`. Signature failures
and counts are emitted by follow; there is no persistent doctor status in this
slice. Add/update/import/follow and removal share the host-store writer lock;
follow checks and atomically records a generation before adding its grants under
that lock. A validation failure or interruption consumes the generation, so
retry requires a newer signed export or deliberate TTY import. Dry-run never
creates or advances freshness state. Preserve this local file across restarts
and grant removal; do not sync it. Malformed state requires operator repair.

Unpinning/revoking a signer stops future acceptance, not existing grants.
Freshness prevents replay only for generations this machine already accepted:
initial bootstrap, a newer signed statement, or another authorized origin can
still authorize a previously removed grant. Retire those exports or revoke the
signer when withdrawing fleet-wide trust. Protect the signing key and provision
signer configuration through a trusted operator session;
TTY gating retains the existing cooperative-agent boundary.

See [Host Allowlist › Fleet replication](safe-run.md#fleet-replication-export--import)
for validation, signature-keyring and operator-override details.

## Scan Modes

Default scans use `source` mode:

```bash
safe audit repo-audit .
safe audit machine-audit --machine remote-a
```

This scans dependency evidence plus first-party source and skips installed
dependency trees and generated output.

For a faster dependency-only pass:

```bash
safe audit repo-audit . --deps-only
```

For a deep scan that includes installed dependency trees:

```bash
safe audit repo-audit . --full
```

When validating scan scope, use verbose mode:

```bash
safe audit repo-audit . --verbose
```

## Diff Recent Results

```bash
safe audit diff --machine local --since 30d
safe audit diff --all --since 7d
```

## Logs And Evidence

Runner decisions:

```text
~/.local/share/safe/run/audit.log
```

Host-allow executions:

```text
~/.local/share/safe/audit/host-allow-log.jsonl
```

Audit check outputs:

```text
~/.local/share/safe/audit/checks/
```

Scan results and SBOMs:

```text
~/.local/share/safe/audit/results/<machine>/
~/.local/share/safe/audit/sbom/<machine>/
```

## Maintenance Checks

Before committing documentation or shell changes, run the smoke checks that match the touched area:

```bash
bash -n bin/safe bin/safe-run bin/safe-audit install.sh uninstall.sh
zsh -n lib/install-wrappers.zsh lib/completions/_safe
bash tests/integration/dispatcher.sh
bash tests/install/run.sh
bash tests/audit/smoke.sh
bash tests/run/safe_audit_integration.sh
git diff --check
```

Some tests require optional tools such as `zsh`, `curl`, `tar`, `sha256sum`, or `timeout`. `safe doctor` reports feature readiness for the same operational dependencies.
