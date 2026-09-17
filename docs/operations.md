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

`add` and `update` verify the exact requested version and fetch its integrity
from the public registry before writing. `import` re-validates and re-fetches integrity for every entry, never overwrites
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
that GPG can report with exit 0. Key-level warnings about unrelated expired or
revoked subkeys do not reject a good signature. A signature actually made by an
expired/revoked key is still rejected. Revoked or expired primary keys cannot be pinned.
Distribute revocation certificates and updated public keys to every follower's
local keyring; there is no automatic keyserver refresh.

A user timer can invoke `safe run host-allow follow` daily. This change does not
install a timer or automatically sign after add. Own-host files are ignored;
verified statements add absent grants or replace a different local pin after
import validation when their generation is newer than the generation recorded
on that entry, retaining the signed entry's `added` date and recording
`followed_from` and `followed_generation`. Entries without a recorded generation
yield to a signed statement. The newest signed statement wins across origins; a
host-set pin yields to any signed statement. Replacements are recorded in the
run audit log and the origin's `replaced` ledger array. Dry-run validates the
whole plan without changing persistent state. A machine-local `follow-state.json` beside the
guard-selected trust store records each origin as
`{"accepted":"<exported_at>","applied":["<pkg>@<version>"],"replaced":["<pkg>@<old>-><new>"],"refused":["<pkg>@<version>"]}`. Older timestamps
warn, increment the freshness-skip count and return non-zero. Equal timestamps
retry only identities that never applied; successful entries stay skipped even
after operator removal. A local re-pin survives an equal generation and a newer
signed generation re-aligns it to the origin's pin. Generation-less refusals
are WARNed once, recorded in `refused`, and remain non-zero; same-generation
retries are quiet INFO skips that cannot replace a later TTY re-pin. A
generation-bearing refusal is re-derived against the incoming generation and
WARNed on every run. A hinted update to the refused version makes it present
and clears the refusal. A
registry outage is therefore retryable with the same signed file. Once complete, unchanged daily
runs return 0 with one quiet info line, no registry calls and no import
prescription. Verification still runs.
Generation-bearing refused identities are re-evaluated against the incoming
generation on every run; refusal memory short-circuits only entries whose local
generation is absent and cannot be compared.
A newer signed generation starts fresh applied and refused sets. After upgrading,
the first follow derives a missing `followed_generation` when `followed_from`
and the matching applied identity identify a prior followed entry. An entry
without that evidence yields once to a signed statement, then carries its
generation: TTY entries, and followed entries whose origin has since published
a newer generation without that package (the ledger no longer lists them). Timestamp comparisons normalize
timezone offsets.

Add/update/import/follow and removal share the host-store writer lock. Follow
fetches registry evidence outside it (10 seconds maximum per request), then
rechecks the generation, applied identities and local pins during its locked
commit. Lock waits are bounded to 10 seconds with a writer-busy recovery hint.
Valid files and entries can still apply alongside failures. A mismatched
JSON/signature pair during transport is safely rejected; retry after both arrive.

For an actual skip/error, the operator can review the file and run
`safe run host-allow import <file>` at a TTY. Unsigned imports keep their
conflict behavior and need the usual `safe run host-allow update
<pkg>@<version> --reason "..."`; signed follow replaces a different local pin
when its generation is newer. A stale signed statement is warned, counted as a
failure, and remains retryable for that identity until its origin publishes a
newer generation.
Signature and older
replay failures/counts are emitted by follow; there is no persistent doctor
status in this slice. Dry-run never creates or changes freshness state or its
lock file. Keep the ledger local and preserve it across restarts/removal.
Malformed records (including the earlier experimental generation-only format)
need operator review/migration; do not erase history to force a retry.

Each applied identity is marked immediately before publishing its grant, and a
reported write failure rolls back that mark. Interruption between the separate
atomic ledger/store renames may conservatively consume that one identity without
its grant; recover it with deliberate TTY import or a newer signed generation.
Registry failures and other unapplied entries remain retryable unattended.

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

### Running Tests

Run the contributor and release gate with:

```sh
bash tests/run-all.sh
```

The runner creates and removes a temporary HOME, XDG config/data/state/cache
roots, GnuPG home, and safe config/data/run/cache directories before starting
any suite. Every standalone suite applies the same setup through
`tests/lib/test-isolation.sh`; a contract check fails if a suite loses that
helper, marker, or call. The four live npm/Composer/shim probes stay in this
aggregate and set `SAFE_TEST_ISOLATION_KEEP_TOOLS=1` themselves so they retain
the real installed tools and mise shims on the original PATH. The npm probes
need a real npm (and the abbreviation probe needs its matching Node and global
npm command map), the Composer probe needs a real Composer, and the shim probe
needs the operator's gate-bound npm, Go, and mise targets. They are read-only
probes and may need network only where the real tool requires it. The opt
preserves those tool paths and mise roots only; HOME, XDG, SAFE state,
package-manager caches, and user/global config files remain scratch-isolated.
An inherited npm prefix may remain so npm can identify its installed tree; it
is not a cache or config write target. The socket-envelope and syft probes
remain opt-in because they require their own live services or installed tools.

For a before/after sentinel run, hash the real `MISE_CONFIG_DIR`,
`MISE_DATA_DIR`, and `MISE_CACHE_DIR` trees as well as the safe config/data
files. The four live probes inspect those real tool roots for discovery, so a
clean sentinel requires the mise hashes to remain identical.

To run one suite, invoke it directly; it creates its own temporary environment
before any fixture code runs:

```sh
bash tests/audit/smoke.sh
```

The runtime guard aborts with a `safe-test: FATAL` message if a safe config,
data, state, or guarded SAFE path resolves below the HOME that invoked the
suite.

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
