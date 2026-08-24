# Release Review

`release-review` judges a whole distributed release from a single spec and
emits a single report. It replaces the pattern of running the six `binary-audit`
sub-commands one after another and stitching their JSON together by hand.

```bash
safe audit binary-audit release-review --spec release.json
safe audit binary-audit release-review --spec -   # spec on stdin
```

The command is a thin bash forward: `safe-audit` verifies that the `safe-core`
beside it reports the same version it does, then `exec`s it. Every decision —
which checks run, how a spec is refused, what a verdict means — belongs to
`safe-core` (`internal/releasereview`).

Output is one JSON document on stdout and nothing else. There is no
human-rendered mode: the consumer of a release review is an agent or a CI step,
and both read the report.

## Status

**Slice 2 of 3: `checksum`, `signature`, `tuf`, `exec`.** This build implements
four of the six checks; `release` and `vuln` land in slice 3, which also
advertises the capability key. Enabling an unimplemented check is refused at
validation rather than silently skipped.

**Top-level `GO` is now reachable.** A digest that matched and a signature that
verified leaves nothing to warn about. A checksum-only spec still warns:
`checksum_only_verification` is suppressed only by an **enabled** signature
check that actually verified *that* artifact — advisory or not, since advisory
caps what a check contributes to the top-level verdict, not what it observed.

| Check | Implemented | What it decides |
| --- | --- | --- |
| `checksum` | yes | artifact sha256 against the release's checksum file |
| `signature` | yes | Sigstore bundle against an identity policy, via cosign |
| `release` | no | GitHub release metadata and age |
| `vuln` | no | advisories affecting the release |
| `tuf` | yes | TUF bootstrap material against a pinned root, via cosign |
| `exec` | yes | networkless execution under observation, via podman |

The composite is not advertised in `safe audit capabilities` while checks are
missing: a capability key is a promise that the surface behind it is whole.

## Invocation

`safe-core release-review --spec PATH`, where `PATH` may be `-` for stdin. No
other flags exist; anything else is a usage error.

Relative paths inside the spec resolve against the **process working
directory**, not the spec's directory. The spec is a consumer-side artifact —
usually generated next to a downloads directory — and resolving against the
caller's CWD is what lets the same spec be piped in from stdin, where there is
no spec directory to resolve against.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | verdict `GO` |
| 10 | verdict `WARN` |
| 20 | verdict `BLOCK` |
| 30 | verdict `ERROR`, or the report could not be written — the review broke, this is audit-infrastructure breakage and not a finding about the release |
| 2 | usage error |
| 3 | the spec is unreadable, fails strict decode, or fails validation — never a verdict |

Exit 3 is deliberately not a verdict. A review that cannot read what it was
asked to check has no evidence about the release, and emitting any verdict
there — including a warning one — would let a spec bug masquerade as a check
that ran.

The bash forward adds one more: a missing or version-skewed `safe-core` returns
30 with a single stderr line naming `rerun install.sh` as the recovery.

## Spec schema (`spec_version` 1)

```json
{
  "spec_version": 1,
  "subject": {"repo": "OWNER/REPO", "version": "TAG"},
  "artifacts": [
    {
      "path": "dist/foo.tar.gz",
      "asset_name": "foo.tar.gz",
      "evidence": {
        "checksum_file": "dist/checksums.txt",
        "signature": {
          "bundle": "dist/foo.tar.gz.sigstore",
          "identity": "exact-identity",
          "oidc_issuer": "https://token.actions.githubusercontent.com"
        }
      }
    }
  ],
  "checks": {
    "checksum":  {"enabled": true,  "advisory": false},
    "signature": {"enabled": false, "advisory": false},
    "release":   {"enabled": false, "advisory": false},
    "vuln":      {"enabled": false, "advisory": false},
    "tuf":       {"enabled": false, "advisory": false,
                  "mirror": "PATH-or-URL", "root": "PATH", "root_checksum": "SHA256",
                  "targets": {"name": "PATH"}},
    "exec":      {"enabled": false, "advisory": false,
                  "artifact": "dist/foo", "args": [], "timeout_seconds": 60}
  }
}
```

All six checks are named in the schema from day one, including the ones no
build implements yet, so a spec written today stays valid when they land.

Turning `signature` on is what makes a clean `GO` reachable — the evidence in
the example above already supports it:

```json
{
  "spec_version": 1,
  "subject": {"repo": "OWNER/REPO", "version": "TAG"},
  "artifacts": [
    {
      "path": "dist/foo.tar.gz",
      "evidence": {
        "checksum_file": "dist/checksums.txt",
        "signature": {
          "bundle": "dist/foo.tar.gz.sigstore",
          "identity_regexp": "^https://github\\.com/OWNER/REPO/\\.github/workflows/release\\.yml@refs/tags/.*$",
          "oidc_issuer": "https://token.actions.githubusercontent.com"
        }
      }
    }
  ],
  "checks": {
    "checksum":  {"enabled": true},
    "signature": {"enabled": true}
  }
}
```

An enabled `tuf` block names a local mirror, the root it is pinned to, and the
trust material to compare:

```json
{
  "spec_version": 1,
  "subject": {"repo": "sigstore/root-signing", "version": "v9"},
  "artifacts": [{"path": "trust/root.json"}],
  "checks": {
    "tuf": {
      "enabled": true,
      "mirror": "trust/mirror",
      "root": "trust/root.json",
      "root_checksum": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "targets": {"trusted_root.json": "trust/local/trusted_root.json"}
    }
  }
}
```

An enabled `exec` block names the executable to smoke — a free path, not an
`artifacts[]` entry:

```json
{
  "spec_version": 1,
  "subject": {"repo": "OWNER/REPO", "version": "TAG"},
  "artifacts": [{"path": "dist/foo.tar.gz"}],
  "checks": {
    "exec": {"enabled": true, "artifact": "dist/extracted/foo", "args": ["--version"], "timeout_seconds": 20}
  }
}
```

### Fields

- `spec_version` — must be exactly `1`.
- `subject.repo`, `subject.version` — required, non-empty. Echoed into the
  report so a stored report identifies itself without its spec.
- `artifacts` — required, at least one entry.
  - `path` — required.
  - `asset_name` — optional; defaults to the base name of `path`. This is the
    name checks match on, which matters when a downloaded file is renamed.
  - `evidence` — optional, and every field inside it is optional. An artifact
    may carry no evidence at all; what a check makes of that absence is the
    check's decision, not the schema's.
- `evidence.signature` — when present, requires `bundle`, `oidc_issuer`, and
  exactly one of `identity` (an exact match, as in the example above) or
  `identity_regexp` (a pattern, for tag-bound workflow identities that change
  every release). The two are mutually exclusive.
- `checks` — optional. Each check block is optional; an omitted block is a
  disabled check. **Omitting `checks` entirely enables `checksum` and nothing
  else** — the one check that needs no network and no external tool.

A check block's own configuration is validated **only when that check is
enabled**. A disabled block may carry whatever placeholder a generator left in
it, which is what keeps the schema example above valid.

- `checks.tuf` — when enabled:
  - `mirror` — required. A local directory path, or a `file://` URL, whose
    prefix is stripped. Any other `://` scheme is refused: the check serves the
    mirror itself and does not fetch one.
  - `root` — required. The pinned `root.json`.
  - `root_checksum` — required. A sha256 digest, with an optional lowercase
    `sha256:` prefix, in either case. Stored normalized (prefix stripped,
    lowercased).
  - `targets` — required, at least one entry, mapping a TUF target name to the
    local file that must match it. Every name and every path must be non-empty.
- `checks.exec` — when enabled:
  - `artifact` — required. A **free path**: the executable to smoke, typically
    something extracted from a distributed artifact. It need **not** name an
    `artifacts[]` entry, and it carries no asset name.
  - `args` — optional. Passed to the binary inside the sandbox.
  - `timeout_seconds` — optional, must not be negative. `0` or omitted means
    "use the default" (see [External tools](#external-tools)), not "no time at
    all".

### Strict decoding

Three shapes are refused at exit 3 before the spec's contents are looked at,
because each one means the document does not say one unambiguous thing:

- **Unknown fields, anywhere in the document.** A typo, a field from a newer
  schema, a check option a stale build does not know. The spec is the one place
  where a consumer and a `safe` build can disagree about vocabulary, and
  disagreeing there is much cheaper than disagreeing halfway through a review.
- **Anything after the first JSON document.** A second object appended to a
  spec — by a broken generator, or a careless `cat` of two files — would
  otherwise be read past and ignored.
- **A member repeated inside one object, at any depth.** JSON decoders keep the
  last occurrence, so a spec stating both `"spec_version": 2` and
  `"spec_version": 1` would quietly become whichever the writer put last.

Surrounding whitespace and the trailing newline every spec file ends with are
not documents, and do not trip the second rule.

### Refusals

Beyond decode and field validation, these spec conditions are refused:

- **An enabled check this build does not implement.** The refusal names the
  check and what the build does implement:
  `check "release" is not implemented by this build (implements: checksum, signature, tuf, exec) — upgrade safe or disable the check`.
  When several unimplemented checks are enabled, the refusal names the first in
  report order, so the line does not depend on JSON key order. A report whose
  checks were silently skipped would be worse than no report.
- **No enabled checks at all** (`"checks": {}`, or every block disabled). A
  review that runs no check decides nothing, and a `GO` carrying no evidence is
  exactly the silent pass this gate exists to prevent.
- **`checksum` enabled while no artifact carries `evidence.checksum_file`**, and
  **`signature` enabled while no artifact carries `evidence.signature`.** An
  enabled check with zero applicable artifacts is a contradiction in the spec,
  not a finding about the release.
- **A `tuf` block that cannot describe a bootstrap**: a mirror that is absent or
  names a scheme other than `file://`, an absent or non-sha256 `root_checksum`,
  an absent `root`, or a `targets` map that is empty or holds an empty name or
  path. A multi-target spec's refusal names targets in sorted order, so the line
  does not depend on JSON key order either.
- **An `exec` block naming no `artifact`, or a negative `timeout_seconds`.**

## Report schema (`schema_version` 1)

```json
{
  "schema_version": 1,
  "subject": {"repo": "...", "version": "..."},
  "verdict": "GO|WARN|BLOCK|ERROR",
  "checks": [
    {"id": "checksum", "advisory": false, "verdict": "GO|WARN|BLOCK|ERROR",
     "reasons": [{"code": "...", "message": "...", "data": {}}]}
  ]
}
```

- `checks` carries one entry per **enabled** check, in the fixed order
  `checksum, signature, release, vuln, tuf, exec` (enabled subset).
- A check entry's `verdict` is its **own** verdict, uncapped. `advisory` echoes
  the spec marking. The advisory cap applies only to the top-level verdict, so
  a report never hides what an advisory check actually found.
- `reasons` may be empty — that is a clean `GO`. `data` is optional per reason;
  when a reason concerns a specific artifact, its `data` carries
  `"artifact": "<asset_name>"`.

## Aggregation

Severity ordering, worst-of:

```text
GO < WARN < ERROR < BLOCK
```

`BLOCK` dominating `ERROR` is deliberate. Both fail closed, but they are
distinct signals with distinct recovery paths: `ERROR` says the review could
not run and must never read as a finding about the release, and a real malice
signal must never be downgraded to "our tooling broke".

- A check's verdict is the worst-of its occurrences' classes; a check that
  found no occurrence at all contributes `GO`. Every condition a check observes
  is reported, not only the first or the worst — an artifact that is unreadable
  *and* whose checksum file is missing carries both reasons, and the worst-of
  decides the verdict.
- The top-level verdict is the worst-of the enabled checks' **effective**
  verdicts.
- An **advisory** check's effective verdict is `min(own verdict, WARN)` — an
  advisory `BLOCK` and an advisory `ERROR` both contribute `WARN`.
- A **required** (non-advisory) check contributes its own verdict unchanged. A
  required check at `ERROR` therefore yields a top-level `ERROR` and exit 30,
  unless some required check `BLOCK`s.

## Reason taxonomy

### Scheme (contract)

- Codes are `lower_snake_case` and **check-scoped**: the stable key is the pair
  (check id, code). The same code under two checks is two different things.
- Codes are stable within a report `schema_version`. Adding a code is allowed;
  renaming or removing one is not.
- **Severity is never encoded in a code.** Severity lives in check verdicts. A
  code names what was observed, not how badly it went.
- The bash lanes' reason vocabulary is **not** ported wholesale. Some codes are
  redesigned (`checksum_failure`, `missing_asset`, `missing_trust_input` have no
  counterpart here), some are kept where the bash name already said the right
  thing (`policy_mismatch`, `bootstrap_failure`, `trust_material_mismatch`,
  `identity_mismatch`), and `missing_tool` becomes `tool_missing` under every
  check that can want one. Consumers translate once.

### `checksum`

| Code | Class | Data | Meaning |
| --- | --- | --- | --- |
| `artifact_missing` | BLOCK | `artifact` | the artifact file is not at its path |
| `checksum_file_missing` | BLOCK | `artifact`, `checksum_file` | the referenced checksum file is not at its path |
| `no_entry_for_artifact` | BLOCK | `artifact`, `checksum_file` | the checksum file is readable but has no usable entry for the asset |
| `digest_mismatch` | BLOCK | `artifact`, `expected_sha256`, `actual_sha256` | the artifact's sha256 differs from its entry |
| `no_checksum_evidence` | WARN | `artifact` | the check is enabled but this artifact carries no `checksum_file` |
| `checksum_only_verification` | WARN | `artifact` | the digest matched and no enabled signature check vouched for this artifact |
| `artifact_unreadable` | ERROR | `artifact`, `error`, and `checksum_file` when the failure was on the checksum file | an I/O failure while reading a file that exists — a broken review, not evidence |

`checksum_only_verification` is suppressed only when an enabled `signature`
check verified **that same artifact**, matched by position in `artifacts[]`
rather than by asset name or path, either of which a spec may repeat. Signature
evidence in the spec does **not** suppress it on its own: presence of metadata
is not verification, and a `signature` block naming a file that does not exist
would otherwise be enough to lift a release to `GO`.

`artifact_unreadable` covers both the artifact and its checksum file on
purpose. The distinction that matters is not *which* file failed but *why*: a
file that is absent or whose digest differs is evidence about the release
(BLOCK), while a file that exists and cannot be read is a broken review
(ERROR). Reporting a permission problem as a tampered artifact would be a
false malice signal.

Reasons accumulate per artifact. An artifact carrying no `checksum_file` is
still probed for presence, so a missing one reports both `artifact_missing`
and `no_checksum_evidence`; an unreadable artifact whose checksum file is also
missing reports both, and BLOCK wins the worst-of over the ERROR.

### `signature`

| Code | Class | Data | Meaning |
| --- | --- | --- | --- |
| `artifact_missing` | BLOCK | `artifact` | the artifact file is not at its path |
| `bundle_missing` | BLOCK | `artifact`, `bundle` | the referenced Sigstore bundle is not at its path |
| `bundle_invalid` | BLOCK | `artifact`, `bundle` | the bundle is readable but is not valid JSON |
| `signature_failure` | BLOCK | `artifact` | cosign could not verify the artifact against the bundle at all; the message is the first line of cosign's output |
| `identity_mismatch` | BLOCK | `artifact`, and `expected_identity` or `expected_identity_regexp` | the bundle verifies, but its signer identity is not the one the policy names |
| `issuer_mismatch` | BLOCK | `artifact`, `expected_oidc_issuer` | the bundle verifies, but its OIDC issuer is not the one the policy names |
| `no_signature_evidence` | WARN | `artifact` | the check is enabled but this artifact carries no `signature` block |
| `artifact_unreadable` | ERROR | `artifact`, `error` | the artifact exists and cannot be read |
| `bundle_unreadable` | ERROR | `artifact`, `bundle`, `error` | the bundle exists and cannot be read |
| `tool_missing` | ERROR | — | cosign is not installed; emitted **once** for the check, not per artifact |

A failed verification is only half an answer, so a failure is re-probed with
wildcard identity and issuer policies until the report can say which of three
things happened: the bundle does not verify at all (`signature_failure`), or it
verifies under a signer the policy does not allow. When both halves of the
policy are wrong, **both** `identity_mismatch` and `issuer_mismatch` are
emitted — a consumer who fixed only one would still be refused.

### `tuf`

| Code | Class | Data | Meaning |
| --- | --- | --- | --- |
| `trust_input_missing` | BLOCK | `missing` (comma-joined paths) | the mirror, the root, or a local target is not on disk |
| `trust_root_mismatch` | BLOCK | `root`, `expected_root_checksum`, `actual_root_checksum` | the root.json on disk is not the pinned root |
| `bootstrap_failure` | BLOCK | — | `cosign initialize` failed, or succeeded without caching trusted targets metadata, or cached metadata that cannot be read as TUF targets JSON |
| `policy_mismatch` | BLOCK | `target` | the trusted metadata does not name this target at all |
| `trusted_mirror_target_invalid` | BLOCK | `target`, `mirror_blob_path`, and `trusted_metadata_sha256`/`actual_mirror_blob_sha256` on a content mismatch | the mirror is missing the blob its own trusted metadata names, or serves one that does not hash to it |
| `trust_material_mismatch` | BLOCK | `target`, `local_sha256`, `trusted_sha256`, `trusted_length` | the caller's local copy is not the trusted target |
| `trust_root_unreadable` | ERROR | `root`, `error` | the root exists and cannot be hashed |
| `trust_target_unreadable` | ERROR | `target`, `error` | a local target exists and cannot be hashed |
| `mirror_unserveable` | ERROR | `mirror`, `error` | the loopback bridge could not be started |
| `scratch_unavailable` | ERROR | `error` | no scratch directory could be created for cosign's trust cache |
| `tool_missing` | ERROR | — | cosign is not installed |

What is answered when depends on what each answer genuinely needs. The root's
checksum needs nothing but the root, so it is reported even when the mirror or a
target is missing — whether the pinned root is the root on disk is the most
load-bearing fact this check has. Bootstrapping is the one place a sequential
gate is right rather than lazy: running `cosign initialize` against a root that
failed its checksum would perform the very act the pin exists to prevent.

Per target, the mirror-side facts (that the metadata names the target, that the
mirror's blob matches it) are facts about the *mirror*, so they are reported
even for a target whose local file the caller did not supply. Only the final
comparison needs that file, and a target already named in `trust_input_missing`
is not reported a second time.

A local target matches when its sha256 **and** size equal a trusted copy's —
either the file cosign materialized (offered only when it matches the mirror
blob) or the mirror blob itself. Text trust material may also match after
trailing CR/LF bytes are trimmed, but only when the target's name or path ends
in `.pub`, `.pem`, `.crt`, `.cer` or `.json`: editors and shell redirection
routinely add or drop a final newline, and refusing a release over that byte
would be a false positive. Binary targets get no such latitude.

Targets are always processed and reported in **sorted name order**, so a report
is reproducible byte-for-byte across runs.

### `exec`

| Code | Class | Data | Meaning |
| --- | --- | --- | --- |
| `artifact_missing` | BLOCK | `artifact_path` | there is no runnable regular file at `checks.exec.artifact` |
| `timeout` | WARN | `timeout_seconds` | the binary did not exit within the effective timeout |
| `runtime_failure` | WARN | `exit_code`, and `stdout_summary`/`stderr_summary` when non-empty | the binary exited nonzero inside the sandbox |
| `artifact_unreadable` | ERROR | `artifact_path`, `error` | the artifact path could not be resolved against the working directory |
| `tool_missing` | ERROR | — | podman is not installed |

Runtime observations are `WARN` because of what this check can and cannot say:
it watches one run of one binary with no network and no project mount. A binary
that exits nonzero, or hangs, is worth surfacing but does not decide a release —
plenty of tools exit nonzero with no arguments.

A timeout is decided by **the deadline**, never by an exit code. A container
killed by a signal reports `-1`, and a container that exits 137 on its own is a
runtime failure this review did not cause.

Output summaries are bounded to 40 lines and 4000 characters. A report carries a
summary, never a binary's unbounded output — and the capture itself is bounded
too: at most 64 KiB of each stream is held in memory, the rest discarded as it
arrives, so a binary that floods its output cannot grow the reviewer's memory
until the OOM killer takes it mid-review. This is divergence 9 in the ledger
below.

### Backstop

`check_not_implemented` (ERROR) is emitted if `Review` is ever reached with an
enabled check that has no implementation. Validation makes this unreachable;
it exists so that a disagreement between validation and the check registry
fails closed rather than reporting a check that found nothing.

## Checksum matching semantics

The artifact is hashed with Go's `crypto/sha256`. There is no external
`sha256sum`/`shasum` dependency and therefore no "missing tool" outcome, which
is one of the bash lane's failure modes that does not survive the port.

Three checksum-file entry formats are accepted. Digests are compared
lowercased; names are **not** — a checksum file distinguishes `Foo.tar.gz` from
`foo.tar.gz` and so does this. A `./` prefix on the name matches, and a `*`
binary marker before the name is stripped.

1. **Coreutils** — `<64hex> <name>`, one or more spaces or tabs, optional `*`
   before the name.
2. **BSD** — `SHA256 (<name>) = <64hex>`.
3. **Bare** — a line that is exactly `<64hex>`.

An entry naming the asset wins immediately.

### Single-entry fallback

When no entry names the asset, the file's digest still answers for it **only if
the file contains exactly one candidate digest**, counting candidates across
all three formats. One-artifact releases routinely ship a checksum file with no
name in it at all, and refusing those would be wrong. This is divergence 1 in
the ledger below.

## External tools

Two tools are shelled out to. Neither is fetched, installed or version-probed by
this command.

| Tool | Used by | Purpose |
| --- | --- | --- |
| `cosign` | `signature`, `tuf` | `verify-blob` against a Sigstore bundle; `initialize` against a pinned TUF root |
| `podman` | `exec` | the sandbox the release binary runs in |

**A missing tool is always `ERROR` (exit 30), never a verdict about the
release.** That is the standing rule for audit infrastructure: a tool that is
not installed is breakage with an install as its recovery, and reporting it as
`BLOCK` would put a "we could not check" in the same bucket as "we checked, and
it failed". Every one of these reasons names its recovery in the message.

Two environment variables tune the `exec` sandbox, matching the bash lane's:

- `SAFE_AUDIT_BINARY_IMAGE` — the container image, default
  `docker.io/library/alpine:3.22`.
- `SAFE_AUDIT_BINARY_TIMEOUT_SECONDS` — the fallback timeout when the spec does
  not set one, default `20`. A spec's own `timeout_seconds` wins over it.

The `tuf` check needs no HTTP mirror of its own: cosign speaks HTTP to a mirror,
so a loopback-only listener on an ephemeral port serves the spec's local
directory for the few seconds `cosign initialize` runs. cosign is given a fresh
scratch `HOME` so the review never reads — or overwrites — the invoking user's
own trust cache.

## Divergences from the bash sub-lanes

The composite is a redesign, not a transcription. These are every place its
behavior deliberately differs from the `binary-audit` sub-lane it replaces.

1. **Checksum single-entry fallback.** The bash lane falls back to the *first*
   digest of a file with any number of entries, which mislabels a no-entry case
   as a digest mismatch: "this release has no entry for that asset" and "that
   asset was tampered with" are two findings with very different follow-ups.
   Both paths refuse the release, so verdict parity holds.
2. **A missing `cosign` is `ERROR`, not `BLOCK`** (`signature` and `tuf`). See
   [External tools](#external-tools).
3. **A missing `podman` is `ERROR`, not `WARN`** (`exec`). Same reason, from the
   other direction: the bash lane's `WARN` understated a review that never ran.
4. **A missing `exec` artifact is `BLOCK`, not `WARN`.** The same observation —
   a release file that is not where the spec says it is — is `BLOCK` in the
   checksum check, and one composite must not classify one observation two ways.
5. **The python HTTP bridge is gone.** The mirror is served by Go's own stdlib,
   so the bash lane's "python3 or python is required" failure mode does not
   exist here.
6. **The sha256 tool preflight is gone.** Hashing is native, so the bash lane's
   "sha256sum or shasum is required" failure mode does not exist here either.
7. **The coreutils `timeout` dependency is gone.** The `exec` deadline is a Go
   context, with SIGTERM on expiry and a 5s kill delay — the same shape as
   `timeout --signal=TERM --kill-after=5s`. One consequence: a container that
   exits 137 *without* the deadline having fired now reads `runtime_failure`,
   where the bash lane read any 124/137 as a timeout. Both are `WARN`.
8. **Bundle certificate introspection is dropped.** The bash lane shells out to
   openssl to put the signer's certificate subject, issuer and SANs in its data
   payload. That is diagnostics, not a decision, and it is not worth an openssl
   dependency the composite otherwise does not need.
9. **The `exec` capture is memory-bounded, not disk-bounded.** The bash lane
   redirected both sandbox streams to scratch files and truncated afterwards, so
   an unbounded binary filled disk, not RAM. The Go composite keeps the capture
   in memory but caps it at 64 KiB per stream, discarding the rest as it
   arrives. Both bound the same report to the same 40-line / 4000-char summary;
   the divergence is only in what the flood costs while it happens — bounded
   disk there, bounded memory here.
