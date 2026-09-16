# safe run

`safe run` is the sandboxed package runner:

```bash
safe run cowsay@1.6.0
```

Compatibility binaries and runner-shaped symlinks remain installed for scripts
and command interception:

```text
safe-run
safe-npx
safe-bunx
safe-uvx
safe-pipx-run
```

After `safe run link`, host `npx`, `bunx`, and `uvx` can be routed through
`safe run`. `pipx` is not auto-linked; use `safe-pipx-run`.

## Sandbox Defaults

Strict mode is the default:

- no package network access;
- read-only project mount;
- dropped capabilities;
- no-new-privileges;
- resource limits from config;
- secret-like project files block non-TTY execution unless allowed.

Relaxations are explicit:

```bash
safe run --write eslint@9.0.0 -- --fix .
safe run --network create-vite@latest -- my-app
safe run --allow-secrets some-tool@1.2.3
safe run --proxy --network package-that-needs-proxy@1.0.0
```

Use alternate runtime images:

```bash
safe run --node22 eslint@9.0.0 -- --version
safe run --py312 ruff@latest -- --version
```

## Decision Order

`safe run` evaluates package requests in this order:

1. `blocked`: refuse and log.
2. `local bin`: a bare, unversioned name backed by `node_modules/.bin` in
   the current **or a parent** directory (npm's own bin resolution, so
   hoisted monorepo workspaces resolve their tools) runs the
   already-installed local binary directly — nothing is fetched. Versioned
   or scoped specs never use this tier.
3. `host-allow`: execute the pinned version on the host with scripts suppressed where supported.
4. `sandbox-known`: run in Podman without another prompt.
5. `unknown`: prompt in a TTY; block in non-TTY.

## Runner-Native Flags

When invoked as `npx`/`bunx`/`uvx`, flags that belong to the replaced runner
are handled explicitly instead of being mistaken for the package name:

- `--no-install` / `--no` — npx/bunx only, honored strictly: run the local
  `node_modules/.bin` binary (current or parent directory), or refuse with
  exit 100 if it is not installed. (Modern npx maps `--no-install` to a prompt setting and still
  resolves against the registry; `safe run` restores the flag's original
  never-fetch meaning.) This keeps husky-era `npx --no-install lint-staged`
  pre-commit hooks working. Via `uvx`/`pipx` the flag is refused through the
  unrecognized-flag path.
- `-q` / `--quiet` / `--silent` — accepted and dropped.
- `--package`, `-p`, `-c`/`--call`, `--workspace`, `--workspaces`,
  `--include-workspace-root` — refused with exit 100: they change what would
  execute, and the shim cannot honor them safely. Use the wrapped `npm exec`
  or `safe run <pkg> [-- args]` instead.
- Any other flag before the package name fails closed with a legible exit-100
  refusal — never a misleading exit-103 "invalid package name".

## Host Allowlist

Use host allow for pinned, reviewed tools that must execute outside the sandbox:

```bash
safe run host-allow add pnpm@10.11.0 --reason "daily package manager"
safe run host-allow update pnpm@10.12.0 --reason "reviewed update"
safe run host-allow list
safe run host-allow remove pnpm
```

`host-allow add` and `host-allow update` are operator-only trust escalations: they require an interactive terminal and refuse in non-TTY shells with exit 102, so a cooperative agent can suggest the command verbatim but not execute it. (The TTY check is a cooperative-agent boundary, not proof of operator presence — a process that allocates a pseudo-terminal can satisfy it; see the residual-risk note in `install-wrappers.md`.) Both require a `--reason` — the audit trail for bypassing the sandbox default — and refuse without one.

### Staleness review

Entries outlive their reason: a pin added to override a WARN keeps granting host
execution long after the pinned version audits clean on its own.

```bash
safe run host-allow review            # human table
safe run host-allow review --json     # machine-readable report
safe run host-allow review --digest   # + machine-local digest read by safe status
safe run host-allow review --no-audit # age/usage only, no re-audit probes
```

Per entry the review reports age, observed usage (host executions plus
install-gate overrides, joined from the audit logs), and a status from
re-auditing the pinned version:

- `removable` — audits GO on its own; the entry is dead weight.
- `keep` — still overriding a real WARN finding.
- `review-urgent` — the pinned version now audits BLOCK; standing host trust
  contradicts current knowledge.
- `unknown` — audit infrastructure failure (Socket/OSV outage, timeout). This
  is breakage to fix, never evidence of staleness; retry later.

The review is read-only — removal stays operator-only and TTY-gated. Each
re-audit probe is bounded (`SAFE_HOST_ALLOW_REVIEW_TIMEOUT`, default 90s).
`--digest` writes the report to `~/.config/safe/audit/host-allow-digest.json`
and renders it beside as `host-allow-digest.md`. Both are replaced on every
run, including a run that finds nothing actionable: the digest is a status
surface reflecting the latest review, not a queue of notes — a review that
found nothing has to clear yesterday's findings. Each file is staged beside its
target and renamed, so a concurrent reader never sees a half-written digest.

`safe run status` (and `safe status`, which includes it) reports the digest:
the removable and review-urgent counts with the review date when there is
something to act on, a one-liner with the date when there is not, and a line
saying no review has run yet when the file is absent. `safe run host-allow
remove <pkg>` drops that entry from the digest and recomputes the counts, so a
handled decision stops being reported without waiting for the next review — a
mechanical edit, with no re-audit and no network.

`install.sh --review-timer` installs a weekly systemd user timer
(`safe-host-allow-review.timer`) that runs `review --digest`.

### Fleet replication (export / import)

The allow set is per-machine by design — that boundary is a feature, not a gap.
But bringing up a second machine otherwise means rediscovering the first
machine's whole WARN-verdict allow set one failed install at a time. `export`
and `import` replace that discover-by-failure loop with one reviewed apply,
without weakening the boundary:

```bash
# On machine 1: dump the allow set as a portable, reviewable document.
safe run host-allow export > allow.json

# On machine 2: preview what a reviewed apply would change (read-only, no TTY).
safe run host-allow import allow.json --dry-run

# Then apply it in one explicit operator-run action (interactive terminal).
safe run host-allow import allow.json
```

The exported document (`schema: safe-host-allow-export/1`) carries only
`name@version`, ecosystem, the public registry integrity hash, the original
`--reason`, and the add date. There are no secrets in it.

`export --sign [--out <dir>]` requires an operator TTY and GPG. It writes
`host-allow.<hostname -s>.json` and its detached armored `.json.asc` signature
under `~/Sync/state/safe/` by default. Signed documents use schema
`safe-host-allow-export/2`, adding `host` and `exported_at`; unsigned stdout
exports stay at `/1`. Import accepts both schemas. Each file is atomically
renamed after signing succeeds; readers may briefly see mismatched generations
and must reject them. `follow.signing_key` in the run config selects the GPG
signing key; otherwise GPG selects its default key. Signing a redirected trust
store requires the same explicit trust override as a grant.

`import` is *"review this set and apply"*, never *"trust another machine"*:

- It is an operator-only trust escalation, TTY-gated exactly like `add`/`update`
  — a real apply refuses in non-TTY shells with exit 102, and it initializes no
  state before that gate. `--dry-run` is the one read-only exception (it touches
  nothing on a bare machine), so a cooperative agent can show the operator the
  delta.
- Every entry is re-validated (name, ecosystem, non-empty reason) as if it were
  typed into `add`; the file is treated as untrusted input, and a malformed
  document or a non-object entry is refused or skipped, never partially applied.
- Only an **exact** version pin is accepted — never a range (`^1`, `1.x`), a
  dist-tag (`latest`, `next`), or an npm source spec (`file:`, `git+…`, a URL or
  path). This is what stops a tampered export from turning `victim@file:/…` into
  a host-execution grant.
- Integrity is **re-fetched from the registry**, not trusted from the file. An
  entry is written only if its exact version resolves in the registry (returns
  an integrity); an unverifiable version is skipped, and a present-but-divergent
  hash (a mutated export, or a registry change) is skipped loudly.
- A package already pinned locally to a *different* version is never silently
  overwritten — the conflict is reported and left for an explicit
  `host-allow update`.
- The original grant date rides along, so a replicated pin keeps its true age in
  the staleness review rather than looking freshly added.

#### Signed follower import

For unattended followers, the operator can delegate acceptance to specific GPG
**primary-key fingerprints**. Import the operator's public key into the follower's
GPG keyring, verify its full fingerprint through a trusted channel, then at an
operator terminal run:

```bash
safe run host-allow follow-signer add <full-primary-fingerprint>
# Origin (operator TTY; optional --out selects another directory):
safe run host-allow export --sign
# Follower (no TTY required; optional --from selects another directory):
safe run host-allow follow --dry-run
safe run host-allow follow
# Revoke future acceptance (operator TTY):
safe run host-allow follow-signer remove <full-primary-fingerprint>
```

`follow-signer` is the TTY-gated setter for `follow.signers` in
`~/.config/safe/run/config.json`; there is no generic config setter. It accepts
full 40- or 64-hex primary fingerprints, requires the public key locally on add,
and never fetches keys. Signing subkeys certified by that primary are accepted.
Revoked or expired primary keys cannot be pinned. The two signer-management
operations and signed export refuse non-TTY callers
with exit 102. There is no `--yes` or `-y` override.

`follow` reads `host-allow.*.json` in `~/Sync/state/safe/` (or `--from`), ignoring
its own short-hostname file. It copies each document and `.json.asc` signature
into private temporary storage, verifies with GPG using an isolated keyring
built only from the pinned primary keys, and applies those same verified bytes.
It never downloads a key. Revocation and expiry are honoured: revoked/expired
primary keys are excluded from the verifier keyring, and verification requires
`GOODSIG` alongside the pinned-primary `VALIDSIG`, rejecting revoked-key,
expired-key and expired-signature status (`REVKEYSIG`, `EXPKEYSIG`, `EXPSIG`)
even when GPG exits successfully. `KEYEXPIRED`/`KEYREVOKED` are key-level
bookkeeping: they may concern unrelated subkeys and do not invalidate a good
signature. A healthy primary can therefore sign while an unrelated subkey has
expired; an expired signing subkey still cannot authorize a grant.
Import revocation certificates and updated public keys into each follower's
local GPG keyring; there is no automatic keyserver refresh.
Unknown/unavailable signers, missing signatures, invalid signatures, and invalid
signer configuration produce one WARN per file
and increment the signature-skip count. Signed `/2` metadata must identify the
host in the filename. The default directory being absent is a successful no-op.

The merge is **UNION**: missing grants pass the same name, ecosystem, reason,
exact-version and registry-integrity validator as `import`. Already-present
pins are no-ops, and a different local pin is replaced by the signed pin when
the statement's generation is newer than the generation recorded on that
entry. Entries without a recorded generation yield to a signed statement. The
newest signed statement wins across origins; a host-set pin yields to any signed
statement. The
replacement is recorded in the append-only run audit log and in the origin's
`replaced` ledger array; follow prints `followed <pkg>@<new> from <host> (replaced local pin @<old>)`.
No local grants are removed. Unsigned `import` keeps its current `CONFLICT`
behavior and requires an explicit update. Grant writes and
`host-allow remove` share one lock. Follow collects validated entries and performs
registry requests outside the lock, then rechecks its ledger and local pins under
the lock before writing. Each registry request has a 10-second timeout; each
lock acquisition waits at most 10 seconds and reports another writer is running
on timeout. An entry the validation loop had already observed as present is not
restored if the operator removes it during the run; an entry removed before its
turn in that loop can be written back by the same run (the generation still
authorizes it) — re-run `host-allow remove` in that case. New entries retain the origin's valid `added` date and record
`followed_from: <host>` and `followed_generation: <exported_at>`; invalid dates
fall back to today, as in import. The generation is the authority stamp for
cross-origin replacement ordering.
Neither import nor follow runs add's interactive audit preflight: the operator
review/signature authorizes the statement, while import validation rechecks the
exact registry identity. Missing local grants with invalid field types or
unverifiable integrity are skipped. `--dry-run` verifies and validates everything,
including replacement plans across source files, without changing persistent state.

A local `follow-state.json` beside the guard-selected trust store records each
origin's highest accepted `exported_at` and the identities already applied:

```json
{"origins":{"rainbow":{"accepted":"2026-09-16T14:00:00Z","applied":["fresh-pkg@1.2.3"],"replaced":["fresh-pkg@1.0.0->1.2.3"]}}}
```

Timestamps are real ISO-8601 whole-second instants with an explicit timezone;
equivalent timezone spellings compare equal. **Older** documents warn, increment
the freshness-skip count and return non-zero. An **equal** generation retries
only identities not in `applied`; applied identities stay skipped even if an
operator subsequently removed their local grants. Registry outages and invalid
entries are not marked applied, so an unchanged signed export can be retried
when the registry recovers. Successful siblings remain recorded. A local re-pin
survives an equal generation; a newer signed generation re-aligns it to the
publishing host's signed pin. A stale cross-origin statement is refused per
identity with a WARN, counted as a failure, and left retryable until that origin
publishes a newer generation. A newer signed generation starts a new applied set
and can authorize grants again.

Once all entries of an equal generation are applied, repeated timer runs and
previews return 0 with one quiet info line and no import hint or registry fetch.
Signatures are still verified on every run. `--dry-run` never creates or changes
the ledger or its lock file. Keep the ledger local and preserve it across
restarts/removal. Malformed records, including earlier experimental string-only
generation records, fail closed: an operator must review/migrate the applied
identities, including previously applied grants now removed, or use manual import.

The generation and individual identity marks are atomically published under the
shared lock. Each mark is written immediately before its local grant; a reported
grant-write failure rolls back that mark for retry. A process interruption between
the two file renames may conservatively leave that one identity marked without
its grant. Use operator-TTY import or a newer signed generation for that rare
recovery; unrelated identities and registry failures remain retryable. Store and
ledger are individually atomic, not a transactional two-file update.

Exit 0 means eligible files were handled (including current-generation no-ops),
or none existed. Exit 1 reports signature/older-generation skips, validation
failures, conflicts or operational errors; valid siblings can still apply.
The redirected-store write guard remains active (exit 100). An operator can
review any skipped file and deliberately apply it with the existing
`safe run host-allow import <file>` at a TTY; import still validates entries and
never overwrites a different pin. Resolve those pins with `host-allow update`.

Synchronize only signed exports and signatures, **not** the live trust store or
signer configuration. A timer may run `follow` unattended; export remains a
separate operator gesture. Removing a signer stops future imports but does not
remove grants already accepted. The freshness ledger prevents replay of accepted
generations, not cross-origin withdrawal: a newer statement or a statement from
another authorized origin may still include a removed grant. Retire those
exports or unpin their signer when withdrawing trust across the fleet. Existing
installs have no historical ledger until their first accepted follow; protect
and retain the local state file.
Protect the signing key (for example with a hardware token requiring touch).
TTY checks and user-writable configuration retain safe's existing cooperative
agent boundary; they are not an OS-level defense against a hostile same-user
process.

## Scripts Allowlist

`~/.npmrc` keeps `ignore-scripts=true` globally, so a package whose
functioning requires its install scripts (platform-binary postinstalls)
installs "successfully" but broken. A scripts-allow entry is an
operator-reviewed grant for one exact identity:

```bash
safe run scripts-allow add opencode-ai@0.5.0 --reason "fetches platform binary"
safe run scripts-allow list
safe run scripts-allow remove opencode-ai
```

`add` is operator-only (TTY, exit 102 otherwise; the same cooperative-agent
boundary as host-allow — see the residual-risk note in
`install-wrappers.md`), requires an exact version (never names, ranges, or
tags), requires a `--reason`, then fetches and **displays the package's
install-time lifecycle scripts** for review before asking for confirmation —
the grant is a statement that these scripts were seen. A registry fetch
failure refuses the grant: sight-unseen authorization is not an option. The
reviewed scripts and the registry integrity hash are snapshotted into the
entry.

Consumption: on a gated `npm install -g <pkg>@<granted-version>` (npm ≥ 12),
the gate injects npm's per-command policy for that one invocation —
`ignore-scripts=false`, `allow-scripts=<every source-verified granted
identity>`, `strict-allow-scripts=true` — so exactly the reviewed scripts
run and any script-bearing dependency outside the grant list fails the
install. Every identity entering the list is verified to resolve from the
default public registry (the source the add-time review fetched from);
identities bound elsewhere are excluded, and if the requested package
itself fails that binding, no injection happens at all. The global
`ignore-scripts` default never changes. With npm < 12 (no per-command
policy) the gate states the manual fallback and installs script-less as
before. An unpinned install of a granted package gets a hint naming the
pinned grant.

`safe audit package-audit --gate install` prints a hint when a resolved version
declares install scripts and no grant exists (`has_install_script` is also
recorded in the check receipt), so "installed but broken" has a visible
cause and the exact operator command to fix it.

## Blocklist

```bash
safe run block add bad-package --reason "known malicious package"
safe run block remove bad-package
safe run block list
safe run block import ./blocked-packages.txt
```

The blocklist supports JSON or newline-list imports and is shared with
`safe audit package-audit`.

## Host and Sandboxed Installs

`safe install -g` audits explicit npm package specs with `safe audit package-audit`,
asks for confirmation, then delegates to `npm install -g` with the original npm
flags preserved:

```bash
safe install -g cowsay@1.6.0
safe install --trust-host -g cowsay@1.6.0
safe install --host --yes --registry https://registry.example left-pad@1.3.0
```

After a successful install of an exact npm version, interactive runs offer to add
that exact package version to `safe run` host-allow. `--trust-host` performs that
step without a second prompt after install. `latest`, omitted versions, dist-tags,
and ranges are not trusted.

For other supported global package managers, select the manager explicitly and
`safe install` translates `-g` to the manager's native global command:

```bash
safe install --pnpm -g cowsay@1.6.0
safe install --yarn -g typescript@5.0.0
safe install --bun -g cowsay@1.6.0
safe install --composer -g vendor/pkg:^1
```

`safe install --sandbox` routes to `safe run install` for isolated install
workflows:

```bash
safe install --sandbox --allow-scripts cowsay@1.6.0
safe run install --write --network native-addon@1.0.0
```

Persistent package-manager commands typed directly in zsh are still covered by
the install wrappers.
