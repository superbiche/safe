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

**All six checks are implemented.** Enabling a check a build does not implement
is still refused at validation rather than silently skipped — that refusal is
what protects a consumer running an older `safe` against a spec written for a
newer one.

**Top-level `GO` is now reachable.** A digest that matched and a signature that
verified leaves nothing to warn about. A checksum-only spec still warns:
`checksum_only_verification` is suppressed only by an **enabled** signature
check that actually verified *that* artifact — advisory or not, since advisory
caps what a check contributes to the top-level verdict, not what it observed.

| Check | What it decides | Reaches the network |
| --- | --- | --- |
| `checksum` | artifact sha256 against the release's checksum file | no |
| `signature` | Sigstore bundle or detached cert+signature against an identity policy, via cosign | bundle no, detached yes |
| `release` | GitHub release metadata, age, history and tag signature | yes |
| `vuln` | advisories published against the repository | yes |
| `tuf` | TUF bootstrap material against a pinned root, via cosign | no |
| `exec` | networkless execution under observation, via podman | no |

Two checks read GitHub over HTTPS. Nothing under review is ever downloaded:
`release` and `vuln` read GitHub's own record *about* the release, while every
artifact and every piece of evidence a check compares is a file the caller
already placed on disk. See [GitHub access](#github-access).

**The composite is advertised** as `binary-audit.release-review` in `safe audit
capabilities` — a capability key is a promise that the surface behind it is
whole, and with all six checks live it is. The advertisement carries the
contract as well as the key:

```json
{
  "capabilities": {"binary-audit.release-review": true},
  "versions": {
    "binary-audit.release-review": {"spec_version": 2, "report_schema_version": 1}
  },
  "groups": {"binary-audit": {"release-review": true}}
}
```

A consumer preflights both numbers before writing a spec rather than
discovering them from a refusal. They are what `safe-core release-review
--versions` prints, and `tests/audit/release_review_forward.sh` fails if the
two ever disagree.

The six `binary-audit` sub-lanes the composite replaced (`release github`,
`vuln github-release`, the three `verify` lanes and `exec`) are deleted, and
their capability keys are withdrawn with them — a key is a promise the command
behind it exists. `binary-audit.release-review` is the one remaining
binary-audit capability.

## Invocation

`safe-core release-review --spec PATH`, where `PATH` may be `-` for stdin. The
only other accepted form is `--versions` (above), which prints the contract
numbers and takes no spec; the two are mutually exclusive, and anything else is
a usage error.

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

## Spec schema (`spec_version` 2)

```json
{
  "spec_version": 2,
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
    "release":   {"enabled": false, "advisory": false, "asset": "foo.tar.gz"},
    "vuln":      {"enabled": false, "advisory": false},
    "tuf":       {"enabled": false, "advisory": false,
                  "mirror": "PATH-or-URL", "root": "PATH", "root_checksum": "SHA256",
                  "targets": {"name": "PATH"}},
    "exec":      {"enabled": false, "advisory": false,
                  "artifact": "dist/foo", "args": [], "timeout_seconds": 60}
  }
}
```

All six checks were named in the schema from day one, including the ones no
build implemented yet, so specs written against the first release stayed valid
as the checks landed.

Turning `signature` on is what makes a clean `GO` reachable — the evidence in
the example above already supports it:

```json
{
  "spec_version": 2,
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

A release that signs its **checksum file** rather than shipping a per-artifact
bundle — the `<checksums>.pem` + `<checksums>.sig` shape — is expressed in
detached mode. The signature vouches for the artifact only through the digest
match, so the `checksum` check is enabled and the artifact carries its
`checksum_file`:

```json
{
  "spec_version": 2,
  "subject": {"repo": "OWNER/REPO", "version": "TAG"},
  "artifacts": [
    {
      "path": "dist/tool_1.0.0_linux_amd64.tar.gz",
      "evidence": {
        "checksum_file": "dist/tool_1.0.0_checksums.txt",
        "signature": {
          "certificate": "dist/tool_1.0.0_checksums.txt.pem",
          "signature": "dist/tool_1.0.0_checksums.txt.sig",
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

The two GitHub checks need no local evidence at all — they are answered from
`subject` — except that `release` must be told which asset the release has to
carry:

```json
{
  "spec_version": 2,
  "subject": {"repo": "OWNER/REPO", "version": "v1.2.3"},
  "artifacts": [{"path": "dist/foo.tar.gz"}],
  "checks": {
    "release": {"enabled": true, "asset": "foo.tar.gz"},
    "vuln":    {"enabled": true}
  }
}
```

An enabled `tuf` block names a local mirror, the root it is pinned to, and the
trust material to compare:

```json
{
  "spec_version": 2,
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
  "spec_version": 2,
  "subject": {"repo": "OWNER/REPO", "version": "TAG"},
  "artifacts": [{"path": "dist/foo.tar.gz"}],
  "checks": {
    "exec": {"enabled": true, "artifact": "dist/extracted/foo", "args": ["--version"], "timeout_seconds": 20}
  }
}
```

### Fields

- `spec_version` — must be exactly `2`.
- `subject.repo`, `subject.version` — required, non-empty. Echoed into the
  report so a stored report identifies itself without its spec.
- `artifacts` — required, at least one entry.
  - `path` — required.
  - `asset_name` — optional; defaults to the base name of `path`. This is the
    name checks match on, which matters when a downloaded file is renamed.
  - `evidence` — optional, and every field inside it is optional. An artifact
    may carry no evidence at all; what a check makes of that absence is the
    check's decision, not the schema's.
- `evidence.signature` — when present, carries the signing evidence in one of
  two mutually exclusive modes, plus the identity policy both share:
  - **Bundle mode** — `bundle` names a Sigstore bundle that signs the artifact
    itself and carries its own transparency-log proof, so it verifies offline.
  - **Detached mode** — `certificate` and `signature` (both required together,
    and neither may appear with `bundle`) are the `<checksums>.pem` and
    `<checksums>.sig` a release publishes beside its checksum file. They sign
    the **checksum file**, not the artifact: the digest the `checksum` check
    matches against that same file is what carries the trust the rest of the way
    to the artifact. So detached evidence requires the artifact to also carry
    `evidence.checksum_file` **and** the `checksum` check to be enabled — without
    the digest match the signature vouches for nothing about the artifact.
    Detached verification needs a live Sigstore/Rekor lookup (a bundle bakes
    that in), so unlike bundle mode it reaches the network.
  - Both modes require `oidc_issuer` and exactly one of `identity` (an exact
    match) or `identity_regexp` (a pattern, for tag-bound workflow identities
    that change every release). The two identity forms are mutually exclusive.
- `checks` — optional. Each check block is optional; an omitted block is a
  disabled check. **Omitting `checks` entirely enables `checksum` and nothing
  else** — the one check that needs no network and no external tool.

A check block's own configuration is validated **only when that check is
enabled**. A disabled block may carry whatever placeholder a generator left in
it, which is what keeps the schema example above valid.

- `checks.release` — when enabled:
  - `asset` — required. The name the GitHub release must carry. It has no
    default: falling back to the first artifact's name would let a spec that
    names the wrong file pass as if it had named the right one.
- `checks.vuln` — when enabled, needs nothing beyond `subject`.
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
    A name may contain `/` (TUF target names are path-like) but must be relative
    and carry no `..` segment: the name is joined onto the mirror's targets tree,
    where an absolute or climbing name would resolve out of it (divergence 16).
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

- **An enabled check this build does not implement.** This build implements all
  six, so only an older `safe` reading a spec written for a newer schema can
  reach it. The refusal names the check and what the build does implement —
  `check "…" is not implemented by this build (implements: …) — upgrade safe or
  disable the check` — and when several are enabled it names the first in report
  order, so the line does not depend on JSON key order. A report whose checks
  were silently skipped would be worse than no report.
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
  path — or a target name that is absolute or contains a `..` segment, which
  would escape the mirror's targets tree (divergence 16). A multi-target spec's
  refusal names targets in sorted order, so the line does not depend on JSON key
  order either.
- **A `release` block naming no `asset`.**
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
| `bundle_missing` | BLOCK | `artifact`, `bundle` | the referenced Sigstore bundle is not at its path (bundle mode) |
| `bundle_invalid` | BLOCK | `artifact`, `bundle` | the bundle is readable but is not valid JSON (bundle mode) |
| `certificate_missing` | BLOCK | `artifact`, `certificate` | the detached certificate is not at its path (detached mode) |
| `signature_missing` | BLOCK | `artifact`, `signature` | the detached signature is not at its path (detached mode) |
| `signature_failure` | BLOCK | `artifact` | cosign could not verify the signed blob at all; the message is cosign's error line, with the flag-deprecation notices it prints in detached mode filtered out |
| `identity_mismatch` | BLOCK | `artifact`, and `expected_identity` or `expected_identity_regexp` | the signature verifies, but its signer identity is not the one the policy names |
| `issuer_mismatch` | BLOCK | `artifact`, `expected_oidc_issuer` | the signature verifies, but its OIDC issuer is not the one the policy names |
| `no_signature_evidence` | WARN | `artifact` | the check is enabled but this artifact carries no `signature` block |
| `artifact_unreadable` | ERROR | `artifact`, `error` | the artifact exists and cannot be read |
| `bundle_unreadable` | ERROR | `artifact`, `bundle`, `error` | the bundle exists and cannot be read (bundle mode) |
| `certificate_unreadable` | ERROR | `artifact`, `certificate`, `error` | the detached certificate exists and cannot be read (detached mode) |
| `signature_unreadable` | ERROR | `artifact`, `signature`, `error` | the detached signature exists and cannot be read (detached mode) |
| `verification_timeout` | ERROR | `artifact` | cosign did not finish verifying the artifact within the subprocess deadline — the tool is present but never answered, which is breakage, not a signature failure |
| `verification_infrastructure_unavailable` | ERROR | `artifact`, `detail` | cosign's trust bootstrap (Sigstore TUF or Rekor) was unreachable, so verification could not run — breakage to retry, never a verdict about the release; reachable most often in detached mode, whose verification needs a live Rekor lookup a bundle carries with it |
| `tool_missing` | ERROR | — | cosign is not installed; emitted **once** for the check, not per artifact |

A failed verification is only half an answer, so a failure is re-probed with
wildcard identity and issuer policies until the report can say which of three
things happened: the signature does not verify at all (`signature_failure`), or
it verifies under a signer the policy does not allow. When both halves of the
policy are wrong, **both** `identity_mismatch` and `issuer_mismatch` are
emitted — a consumer who fixed only one would still be refused. A cosign that
cannot reach its own trust root at any step stops the cascade with
`verification_infrastructure_unavailable` rather than a `BLOCK`: an audit
outage is not a signer the policy disallows. A detached blob that is missing is
left to the `checksum` check, which owns that finding — the signature check does
not report it twice.

### `release`

Everything this check observes is a fact about the release, so every adverse
answer is `BLOCK`. The only thing it can report that is *not* about the release
is a GitHub it could not read, which is `ERROR` — see
[the 404 split](#github-access).

| Code | Class | Data | Meaning |
| --- | --- | --- | --- |
| `release_missing` | BLOCK | `repo`, `version` | GitHub has no such release; the message names the private-repository case |
| `release_channel` | BLOCK | `draft`, `prerelease` | the release is a draft or a prerelease |
| `release_age_unknown` | BLOCK | — | GitHub's metadata carries no publication timestamp this check can read |
| `release_too_new` | BLOCK | `age_days`, `minimum_days`, `published_at` | the release is younger than the minimum age |
| `asset_missing` | BLOCK | `asset` | the release does not carry the asset `checks.release.asset` names |
| `release_history_missing` | BLOCK | `repo` | GitHub publishes no release listing for the repository |
| `same_day_churn` | BLOCK | `count`, `published_day` | more than one non-draft release was published that day |
| `previous_release_unresolved` | BLOCK | `version` | no earlier release could be resolved, so there is nothing to compare against |
| `comparison_missing` | BLOCK | `previous_tag`, `version` | GitHub cannot compare the two tags |
| `high_risk_paths` | BLOCK | `previous_tag`, `paths`, `changed_files` | release machinery changed since the previous release |
| `tag_unresolved` | BLOCK | `version` | the git tag is absent, or does not resolve to one commit |
| `commit_missing` | BLOCK | `commit` | a tag names a commit GitHub does not serve |
| `commit_unverified` | BLOCK | `commit`, `reason` | GitHub does not report the tagged commit as signed |
| `release_history_capped` | GO | `pages`, `releases_read` | the listing was longer than the page cap, but the predecessor was resolved before it — recorded so a capped walk is never silent |
| `release_history_truncated` | ERROR | `pages`, `releases_read` | the page cap was reached before the release was found, so its predecessor could not be resolved |
| `high_risk_pattern_invalid` | ERROR | `error` | `SAFE_AUDIT_GITHUB_HIGH_RISK_PATH_REGEX` does not compile, so no path was classified |
| `metadata_unavailable` | ERROR | `endpoint` | GitHub could not be read — a transport failure, a timeout, a 5xx, a rate limit, or a body that is not the JSON this check expects |

The six endpoints are consulted independently and every answer is reported: a
release whose asset is missing *and* whose commit is unsigned says both, because
a consumer who fixed only the first one reported would still be refused. Three
lookups are conditional, because they have no question to ask otherwise: nothing
is compared when no predecessor was resolved, an annotated tag is dereferenced
only when the tag object is annotated rather than lightweight, and no commit is
asked about when the tag resolved to none.

`release_history_capped` and `release_history_truncated` are the same event told
apart by whether it mattered. A cap that stopped a walk after everything needed
was already resolved changed no verdict and says so at `GO`; a cap that stopped
it first is this review failing to run, and reporting *that* as
`previous_release_unresolved` would blame the repository for the reviewer's own
bound — so the BLOCK is suppressed when the ERROR fires.

### `vuln`

| Code | Class | Data | Meaning |
| --- | --- | --- | --- |
| `known_advisory_high_severity` | BLOCK | `advisory`, `severity`, `cve` | a high or critical advisory affects this version |
| `version_mapping_ambiguous` | BLOCK | `advisory`, `version` | an advisory names no affected range this check can read AND no usable `patched_versions` fallback, so whether it covers the version is unknown |
| `advisory_feed_missing` | BLOCK | `repo` | GitHub publishes no advisory feed for the repository; the message names the private-repository case |
| `known_advisory` | WARN | `advisory`, `severity`, `cve` | an advisory below high severity affects this version |
| `advisory_feed_unavailable` | ERROR | `repo` | the feed could not be read, so no advisory was checked |
| `advisory_feed_truncated` | ERROR | `repo`, `pages`, `advisories_read` | the feed was longer than the page cap, so an advisory affecting this version may not have been seen |

This is the one check with a genuine `WARN` tier. A low or moderate advisory
affecting the version is a real observation a consumer should see, but it does
not by itself refuse a release; a high or critical one does.

A repository that has published no advisories answers `200` with an empty array,
which is a clean `GO`. That is what makes `404` mean something else here — the
repository itself is not visible — and why it is `BLOCK` rather than `ERROR`,
the same reading `release` gives a 404.

An advisory whose ranges are read in order stops at the first match, so an
unreadable range listed *after* a matching one does not turn a decided advisory
into an undecided one. One listed before it is reported as well: it was read, it
decided nothing, and both facts are true.

Unlike the release history, a capped advisory walk has no early answer. An
advisory this check never read is an advisory it cannot rule out, so the cap is
always `ERROR` here.

### `tuf`

| Code | Class | Data | Meaning |
| --- | --- | --- | --- |
| `trust_input_missing` | BLOCK | `missing` (comma-joined paths) | the mirror, the root, or a local target is not on disk |
| `trust_root_mismatch` | BLOCK | `root`, `expected_root_checksum`, `actual_root_checksum` | the root.json on disk is not the pinned root |
| `bootstrap_failure` | BLOCK | — | `cosign initialize` failed, or succeeded without caching trusted targets metadata, or cached metadata that cannot be read as TUF targets JSON |
| `policy_mismatch` | BLOCK | `target` | the trusted metadata does not name this target at all |
| `trusted_mirror_target_invalid` | BLOCK | `target`, `mirror_blob_path`, and `trusted_metadata_sha256`/`actual_mirror_blob_sha256` on a content mismatch; only `target` and `trusted_metadata_sha256` when the trusted digest itself is not a sha256 | the mirror is missing the blob its own trusted metadata names, serves one that does not hash to it, or the trusted metadata's digest is not a sha256 (refused before it is joined into the blob path — divergence 16) |
| `trusted_mirror_target_escapes_tree` | BLOCK | `target`, `mirror_blob_path` | the mirror's entry for the target is a symlink whose resolution leaves the targets tree — physical containment beyond the lexical name/digest rules (divergence 16) |
| `trust_material_mismatch` | BLOCK | `target`, `local_sha256`, `trusted_sha256`, `trusted_length` | the caller's local copy is not the trusted target |
| `trust_root_unreadable` | ERROR | `root`, `error` | the root exists and cannot be hashed |
| `trust_target_unreadable` | ERROR | `target`, `error` | a local target exists and cannot be hashed |
| `mirror_unserveable` | ERROR | `mirror`, `error` | the loopback bridge could not be started |
| `scratch_unavailable` | ERROR | `error` | no scratch directory could be created for cosign's trust cache |
| `bootstrap_timeout` | ERROR | — | `cosign initialize` did not finish within the subprocess deadline |
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
| `artifact_path_unmappable` | ERROR | `artifact_path` | the artifact's directory path contains a `:`, which podman would mis-split in the `-v` mount, so the sandbox cannot be built (divergence 17) |
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
| `cosign` | `signature`, `tuf` | `verify-blob` against a Sigstore bundle or a detached certificate+signature; `initialize` against a pinned TUF root |
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

## GitHub access

`release` and `vuln` read the GitHub REST API over HTTPS. Seven endpoints, all
read-only:

| Endpoint | Read by | For |
| --- | --- | --- |
| `/repos/{repo}/releases/tags/{version}` | `release` | channel, age, assets |
| `/repos/{repo}/releases` | `release` | same-day churn, the previous tag |
| `/repos/{repo}/compare/{previous}...{version}` | `release` | what changed since the previous release |
| `/repos/{repo}/git/ref/tags/{version}` | `release` | the commit the tag names |
| `/repos/{repo}/git/tags/{sha}` | `release` | dereferencing an annotated tag to its commit |
| `/repos/{repo}/commits/{sha}` | `release` | whether that commit is signed |
| `/repos/{repo}/security-advisories` | `vuln` | advisories published against the repository |

Every request carries `Accept: application/vnd.github+json`,
`X-GitHub-Api-Version: 2022-11-28` and `User-Agent: safe-audit`, and nothing
else — except that when `GITHUB_TOKEN` is set it is sent as
`Authorization: Bearer …`. **That header is the token's only destination.** It
never enters a URL, a query string, a report, a reason's data, or an error
message, and the reason a failure names is built from the request URL alone.
A token is not required; it is what makes a private repository readable, and
what raises the rate limit.

The header is also **pinned to the base URL's origin** — scheme, host, and
effective port (an omitted `443`/`80` equals its spelled-out form). Two of the
requests above are made to absolute URLs the API itself hands back — a
`Link: rel="next"` target and the annotated tag object's address — and the token
is attached only when such a URL shares the base URL's origin; a compromised or
proxied response that named another origin receives the request without it. The
same pin governs redirects: the client installs its own redirect policy, because
Go's default copies the header onto any same-host **or subdomain** target by
hostname alone — keeping it across a port change or an https→http downgrade. On
any redirect hop the origin check would reject, the header is removed, and the
hop count is capped.

Three environment variables tune this:

- `SAFE_AUDIT_GITHUB_API_BASE_URL` — the API root, default
  `https://api.github.com`. This is what points the checks at a proxy or, in the
  suites, at a local server.
- `SAFE_AUDIT_GITHUB_RELEASE_MIN_AGE_DAYS` — the minimum age a release must
  have, default `3`. An override that is not a number is ignored: the knob tunes
  a threshold, and a typo in it must not decide a release.
- `SAFE_AUDIT_GITHUB_HIGH_RISK_PATH_REGEX` — which changed paths count as
  release machinery. An override that does not compile is `ERROR`, not an empty
  match: a pattern that classified nothing would read as a release that changed
  nothing risky.

Every request carries a 30-second deadline, every response body is bounded at
8 MiB, and a paginated listing follows at most 10 `Link: rel="next"` hops. A
review must not be held open, grown, or walked forever by an endpoint it does
not control.

### The 404 split

A `404` is GitHub *answering*: it looked, and what the spec named is not there.
That is evidence about the release, and it is `BLOCK` — under a code naming
what was absent, and with a message that names the other thing a 404 can mean,
because **GitHub answers 404 rather than 403 for a read it will not
authorize**. Without that sentence, a consumer with no token would read "this
release does not exist" about a private repository and believe it.

Every other failure — no route to the host, a timeout, a `5xx`, a `403` rate
limit, a `429`, a body that is not the JSON the check expects, a response past
the size bound — means the review could not run. Those are `ERROR` (exit 30),
never `BLOCK`. This is the composite's standing severity law, the same one that
makes a missing `cosign` an `ERROR`: "we could not check" must never land in the
same bucket as "we checked, and it failed".

## Divergences from the bash sub-lanes

The composite is a redesign, not a transcription. The six `binary-audit`
sub-lanes it replaced (`release github`, `vuln github-release`, the three
`verify` lanes and `exec`) have since been deleted, so this is no longer a live
parity contract against a running lane — it is the normative record of how the
composite behaves and why, at every point it deliberately differs from the bash
approach it grew out of. While both lanes existed, a parity corpus drove the
same fixtures through each and diffed the verdicts; with bash gone, the
verdict-affecting entries below (1–4, 10–13) are frozen as in-process goldens in
`internal/releasereview/ledger_test.go`, one case per entry, so a ledger entry
still cannot claim a behavior nothing checks.

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
10. **A GitHub that cannot be read is `ERROR`, not `BLOCK`** (`release` and
    `vuln`). The bash lanes collapsed every failed request into `BLOCK`
    (`metadata_unavailable`, `feed_unavailable`), so a rate limit, an expired
    token or a GitHub outage read as a finding about the release. Here only a
    `404` is evidence; everything else is the review failing to run. See
    [the 404 split](#the-404-split).
11. **Paginated listings are followed, and the cap is reported.** The bash lanes
    read only the first page of `per_page=100`, so on a repository with a long
    history the previous tag and the same-day count were computed from a
    truncated view — silently. Here the `Link: rel="next"` chain is followed up
    to 10 pages, and hitting that bound is always reported: at `GO` for a
    release history whose answer was already resolved, at `ERROR` when it was
    not, and at `ERROR` for an advisory feed, which has no early answer.
12. **An advisory naming no readable version range is ambiguous, not absent**
    (`vuln`). The bash lane dropped null and empty `vulnerable_version_range`
    entries before matching, so an advisory whose every entry carried one
    contributed nothing at all — it read as "does not affect this version",
    which is a fail-open in a check whose whole job is not to miss one. Here it
    is `version_mapping_ambiguous`, the same class as an advisory with no
    entries at all, and it fails closed. The bash lane's own quirks in the
    *range grammar* are ported exactly, including that `||` makes a range
    unreadable and that a range of only separators matches everything.

    Two refinements the bash lane never had (both `vuln`): the subject version
    is the GitHub *tag* — the `release` check looks it up as one — so before
    comparing it against advisory versions it is reduced to the single dotted
    version the tag contains (`rust-v0.149.1` → `0.149.1`; the `2` of a
    `tool2-v0.5.0` name is not a dotted version and does not count). A tag that
    names NO dotted version, or MORE than one — a version fused into a prefix
    (`tool-2.0-v0.5.0`), a trailing platform version (`tool-v0.5.0_linux-6.8`) —
    is unplaceable: which is the release version cannot be told, so the advisory
    is left ambiguous rather than comparing a guessed core. An unplaceable
    version is never fed to the version comparison at all, so it can never
    collate the wrong way and fail open. And when a range is
    unreadable, the entry's `patched_versions` is consulted as a second signal:
    a single, parseable fix version decides — a candidate at or above it is not
    affected, below it is — so an advisory whose *only* defect is an unparseable
    range no longer blocks every version forever. The fallback is a resolver,
    not a loosening: a readable range is always authoritative and is never
    overridden by `patched_versions`; a comma-separated patched list (several
    fixed branches, a branch-identity question this build does not answer) does
    not resolve; and a candidate with no numeric core does not resolve. When
    neither the range nor a usable patched version can place the advisory, it is
    still `version_mapping_ambiguous` and still fails closed.
13. **The `exec` sandbox runs the binary directly, with no shell.** The bash
    lane wrapped it in `sh -c 'exec /artifact/<name> "$@"' sh` to forward its
    arguments, which spliced a spec-supplied file name into shell program text:
    an artifact named `x|touch PWNED` ran the second half of its own name inside
    the container. Contained — the injected code ran under the same
    `--network=none --read-only --cap-drop=ALL` sandbox as the untrusted binary
    the check executes by design, so no boundary was crossed — but the name
    becomes attacker-chosen the day a consumer smokes a binary under the name an
    archive gave it. Go passes argv as argv, so the wrapper bought nothing; it
    is gone, and the binary is one argv entry followed by its arguments.
14. **`GITHUB_TOKEN` is pinned to the base URL's origin** (`release`, `vuln`). The
    bash lane's `github_api_get` sent the same `Authorization: Bearer` header to
    whatever URL it was handed, including the absolute URLs GitHub returns in a
    `Link` header and in an annotated tag object's `url`. Here the token is
    attached only when the target shares the base URL's origin — scheme, host and
    effective port — so a compromised or proxied response cannot steer the
    credential elsewhere. This covers both the direct absolute URL and the
    redirect hop: the client installs its own redirect policy, because Go's
    default forwards the header to any same-host-or-subdomain target by hostname
    alone, dropping scheme and port. One behaviour-visible edge: a proxy
    configured through
    `SAFE_AUDIT_GITHUB_API_BASE_URL` whose upstream `Link`/tag-object URLs escape
    the proxy's host loses auth on those hops, and an unauthenticated read of a
    private resource then answers `404` — which this composite treats as evidence
    (see [the 404 split](#the-404-split)). No corpus pair accompanies this: the
    pin changes a request property, not a verdict on identical fixture inputs the
    way divergences 10–13 do; the `github_test.go` two-host regression carries it.
15. **The `cosign` subprocesses carry a deadline** (`signature`, `tuf`). The bash
    lanes ran `cosign verify-blob` and `cosign initialize` with no timeout, so a
    cosign wedged on a network fetch held the whole review open indefinitely.
    Here each cosign invocation runs under the same Go-context deadline the
    `exec` check uses (SIGTERM on expiry, a 5s kill delay), and a run that
    exceeds it is `ERROR` — `verification_timeout` / `bootstrap_timeout` — not
    the `BLOCK` a genuine verification or bootstrap failure produces: a tool that
    never answered is the review failing to run, never a finding about the
    release. No corpus pair accompanies this either — a timeout is not reproducible
    through the fixture corpus without a deliberately hanging cosign; the Go unit
    tests drive it by lowering the deadline against a fake asked to sleep.
16. **A trust target name that escapes its directory is refused** (`tuf`). The
    target name is joined onto `<mirror>/targets` and onto the materialized
    targets directory to build the paths this check hashes, and `filepath.Join`
    runs `Clean`, which *resolves* a `..` rather than neutralizing it — so a name
    like `../../etc/passwd` (or an absolute one) would steer those reads out of
    the mirror. TUF names are path-like and legitimately contain `/`, so only the
    traversal shapes are refused: an absolute name or one carrying a `..` segment
    is rejected at spec validation (exit 3), before any check runs. The
    metadata-supplied digest is spliced into the same blob path, so a non-hex
    digest is refused at the check as `trusted_mirror_target_invalid` for the same
    reason. The bash lane joined both unchecked. Those rules are *lexical*, and
    `os.Stat`/`os.Open` follow symlinks, so they do not see through a mirror entry
    that is itself a symlink out of the tree; the mirror blob and the materialized
    candidate are therefore also read through an `os.Root` cage rooted at the
    targets tree, which refuses any resolution — at the blob, at a `targets`
    directory that is itself a symlink out of the mirror, or at any parent
    component of a path-like name — that leaves it. An escaping blob is
    `trusted_mirror_target_escapes_tree`; a resolution that fails for another
    reason (a missing blob, a symlink loop, a non-directory component) keeps the
    `trusted_mirror_target_invalid` missing-blob reason; an in-tree symlink
    (mirrors dedup content-addressed blobs) resolves normally, within the
    platform's symlink-resolution depth limit. No corpus pair: this refuses a
    hostile spec or mirror rather than changing a verdict on a legitimate one;
    `spec_test.go` and `tuf_test.go` carry the coverage.
17. **An artifact directory path containing `:` is refused** (`exec`). The
    artifact's directory is bind-mounted as `<dir>:/artifact:ro,z`, and podman
    splits a `-v` spec on `:`; a directory path with a colon would mis-split into
    a bogus source, destination and options. The sandbox this check depends on
    cannot then be built safely, so it is `ERROR` (`artifact_path_unmappable`) —
    the review failing to run — never a finding about the release, the same
    posture as a missing `podman` (divergence 3). The bash lane spliced the path
    into the `-v` argument unchecked. No corpus pair: it changes behavior only on
    a pathological path, not a verdict on a legitimate fixture; `exec_test.go`
    carries the coverage.
18. **Detached signatures sign the checksum file, and vouch only with the
    checksum check** (`signature`, `spec_version` 2). The deleted bash `verify
    release-asset --require-signature --certificate --signature` lane verified a
    detached `<checksums>.pem` + `<checksums>.sig` pair directly. The composite
    keeps that shape but ties its meaning to the rest of the review: the pair
    signs the checksum file, so a verified detached signature vouches for an
    artifact only through the digest the `checksum` check matches against that
    same file. Spec validation therefore refuses detached evidence unless the
    artifact carries `evidence.checksum_file` and the `checksum` check is
    enabled — a signature-only `GO` in bundle mode means *the artifact* verified,
    and detached mode must not let it mean less. `spec_test.go` and
    `signature_test.go` carry the coverage.
19. **A cosign trust-root outage is `ERROR`, not `BLOCK`** (`signature`). Bundle
    verification bakes its transparency-log proof in and verifies offline;
    detached verification needs a live Sigstore-TUF and Rekor lookup, so a review
    that runs while those are unreachable would fail cosign with a network error.
    That is audit-infrastructure breakage, never a signer the policy disallows,
    so the cascade classifies cosign's own client-bootstrap phrasing (TUF refresh
    / Rekor public-key / dial failures) as
    `verification_infrastructure_unavailable` (ERROR) and stops, at every step —
    the wildcard re-probes hit the same outage. The classifier reads only
    cosign's **fatal** line (`Error:` / `error during command execution:`), not
    the whole combined output: the "Could not fetch trusted_root … Continuing"
    line is a non-fatal warning cosign prints even on runs that go on to verify
    or reject, and cosign echoes the caller-supplied evidence path and the
    certificate's SAN into its output, so a whole-output substring match could be
    steered by an evidence path or SAN containing a network string. Fatal lines
    about the evidence itself — a certificate that would not load, or an identity
    that did not match — are excluded, leaving only the trust-bootstrap network
    chain, which nothing under an attacker's control reaches. An unrecognized
    fatal line falls through to `BLOCK` — the fail-closed direction, so a future
    cosign that rewords the bootstrap strings degrades to over-blocking, never a
    silent pass. The same classifier guards the bundle path, where
    a cold trust-root cache with no network is the same outage.
    `signature_test.go` drives it with a fake cosign emitting the captured
    offline output.
20. **Detached mode uses cosign's deprecated `--certificate`/`--signature`
    flags** (`signature`). Current cosign still verifies a detached pair through
    these flags but prints a deprecation notice steering toward
    `--bundle`/`--trusted-root`; the composite does not synthesize a bundle from
    the pair (that machinery is not worth its weight for one evidence shape) and
    does not pass `--insecure-ignore-tlog` (dropping the transparency-log check
    would weaken verification against a leaked short-lived key). If a future
    cosign removes the flags, detached verification fails closed as
    `verification_infrastructure_unavailable` or `signature_failure` rather than
    passing — a known risk parked with this feature, to revisit when a
    non-deprecated detached path exists.
