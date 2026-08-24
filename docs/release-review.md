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

**Slice 1 of 3: `checksum`.** This build implements one of the six checks;
the remaining checks land in slices 2 and 3, and the capability key is
advertised in slice 3. Enabling an unimplemented check is refused at validation
rather than silently skipped.

One consequence is worth stating plainly: **this build cannot return a
top-level `GO`.** A verified artifact still warns with
`checksum_only_verification`, because no implemented check verifies the
checksum file itself. Top-level `GO` becomes reachable when the `signature`
check lands and can actually verify a bundle.

| Check | Implemented | What it will decide |
| --- | --- | --- |
| `checksum` | yes | artifact sha256 against the release's checksum file |
| `signature` | no | Sigstore bundle against an identity policy |
| `release` | no | GitHub release metadata and age |
| `vuln` | no | advisories affecting the release |
| `tuf` | no | TUF bootstrap material against a pinned root |
| `exec` | no | networkless execution under observation |

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
  every release). The two are mutually exclusive. This is validated now even
  though no build verifies bundles.
- `checks` — optional. Each check block is optional; an omitted block is a
  disabled check. **Omitting `checks` entirely enables `checksum` and nothing
  else** — the one check that needs no network and no external tool.

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

Beyond decode and field validation, three spec conditions are refused:

- **An enabled check this build does not implement.** The refusal names the
  check and what the build does implement:
  `check "signature" is not implemented by this build (implements: checksum) — upgrade safe or disable the check`.
  When several unimplemented checks are enabled, the refusal names the first in
  report order, so the line does not depend on JSON key order. A report whose
  checks were silently skipped would be worse than no report.
- **No enabled checks at all** (`"checks": {}`, or every block disabled). A
  review that runs no check decides nothing, and a `GO` carrying no evidence is
  exactly the silent pass this gate exists to prevent.
- **`checksum` enabled while no artifact carries `evidence.checksum_file`.** An
  enabled check with zero applicable artifacts is a contradiction in the spec,
  not a finding about the release.

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
- The bash lanes' reason codes (`checksum_failure`, `missing_asset`,
  `policy_mismatch`, …) are **not** ported. This is a redesigned vocabulary;
  consumers translate once.

### `checksum`

| Code | Class | Data | Meaning |
| --- | --- | --- | --- |
| `artifact_missing` | BLOCK | `artifact` | the artifact file is not at its path |
| `checksum_file_missing` | BLOCK | `artifact`, `checksum_file` | the referenced checksum file is not at its path |
| `no_entry_for_artifact` | BLOCK | `artifact`, `checksum_file` | the checksum file is readable but has no usable entry for the asset |
| `digest_mismatch` | BLOCK | `artifact`, `expected_sha256`, `actual_sha256` | the artifact's sha256 differs from its entry |
| `no_checksum_evidence` | WARN | `artifact` | the check is enabled but this artifact carries no `checksum_file` |
| `checksum_only_verification` | WARN | `artifact` | the digest matched, but no implemented check verifies the checksum file itself, so verification remained checksum-only |
| `artifact_unreadable` | ERROR | `artifact`, `error`, and `checksum_file` when the failure was on the checksum file | an I/O failure while reading a file that exists — a broken review, not evidence |

`checksum_only_verification` is unconditional on a matched digest in this
build. Signature evidence in the spec does **not** suppress it: no check here
opens a bundle, so a `signature` block naming a file that does not even exist
would otherwise be enough to lift a release to `GO`. Presence of metadata is
not verification, and the slice that implements the signature check earns the
right to suppress this warning.

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

### Single-entry fallback (divergence from the bash lane)

When no entry names the asset, the file's digest still answers for it **only if
the file contains exactly one candidate digest**, counting candidates across
all three formats. One-artifact releases routinely ship a checksum file with no
name in it at all, and refusing those would be wrong.

The bash lane instead falls back to the **first** digest of a file with any
number of entries. That mislabels a no-entry case as a digest mismatch: "this
release has no entry for that asset" and "that asset was tampered with" are two
findings with very different follow-ups. Both paths refuse the release — the
verdict is `BLOCK` either way, so fixture-corpus verdict parity holds — but the
reason a consumer reads is different, and the Go behavior is the correct one.
