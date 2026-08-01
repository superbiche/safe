# safe audit

`safe audit` is the evidence and verdict engine for the ecosystem.

Call it through the dispatcher:

```bash
safe audit scan --project .
```

The compatibility `safe-audit` binary remains installed for scripts, but
documentation and examples use the dispatcher form.

## Capabilities

Use the machine-readable capability command when integrating with other scripts:

```bash
safe audit capabilities --json
```

The current capability groups cover:

- scan, check, diff, and status;
- GitHub release review;
- GitHub repository advisory checks;
- release asset verification;
- Sigstore bundle verification;
- TUF bootstrap verification;
- binary sandbox execution;
- IOC lookup, list scanning, and updates;
- machine setup and scanner bundle creation.

## Scanner Setup

`safe audit setup` detects already-installed scanner tools and can install
scanner binaries from an explicit local bundle. It does not download upstream
release assets, run `curl | sh`, or run language package installers.

Scanner dependency policy and upstream links are documented in
[External Dependencies](dependencies.md).

Create a bundle from an audited machine:

```bash
safe audit setup --create-bundle ./scanners.tar.gz
```

Install that bundle on a target machine:

```bash
safe audit setup local --bundle ./scanners.tar.gz
```

## Project And Machine Scans

Local project scan:

```bash
safe audit scan --project .
```

Verbose project scan:

```bash
safe audit scan --verbose --project .
```

Default project and machine scans use `source` mode. This is the normal
high-signal mode:

- audit dependency manifests and lockfiles;
- stage first-party source files for SBOM and source-risk checks;
- skip installed or generated dependency trees such as `node_modules/`,
  `vendor/`, virtualenvs, caches, and build output.

The staged source scan includes high-signal static checks for suspicious loaders
and credential/network use. A default machine scan discovers projects under the
configured scan root and scans those project roots; it does not fall back to
scanning every random source file under the whole root unless you pass an
explicit `--project` target or `--full`.

Scan modes:

| Mode | Flag | What it scans | Main use |
| --- | --- | --- | --- |
| `source` | default | Dependency evidence plus first-party source, excluding installed deps and generated trees. | Normal project and machine scans. |
| `deps` | `--deps-only` | Dependency manifests and lockfiles only. | Fast dependency check when source-risk scanning is not needed. |
| `full` | `--full` | Full target tree, including installed deps such as `node_modules/` and `vendor/`. | Deep investigation when speed is secondary. |

`--verbose` prints the resolved target, scan mode, project roots, lockfiles,
manifests, staged source files, and scanner inputs. Use it when confirming that
a scan is constrained to the intended project or machine root.

When required scanners (`osv-scanner`, `syft`, `grype`) or discovered project
ecosystems require audit commands that are missing (`npm`, `composer`,
`pip-audit`, `cargo-audit`, `govulncheck`), `safe audit scan` stops by default
and prints install guidance plus the rerun command. If you explicitly continue
with a partial audit, missing tools are reported as `skipped` and the scan
verdict is `WARN`; they are not presented as zero CVEs.

Dependency-only scan:

```bash
safe audit scan --deps-only --project .
```

### Scan cache (`--deps-only`)

A dependency-only scan reads exactly one thing: the dependency evidence
(lockfiles and manifests). When that evidence hashes to a set already scanned
within 24 hours, re-running the scanners cannot produce a different verdict, so
the recorded result is replayed instead:

```text
[safe audit] scan cache hit (17m) — dependency evidence unchanged; --no-cache forces a fresh scan
```

The verdict, counts, and exit code are the recorded ones. Entries live in
`~/.local/share/safe/audit/scan-cache/<sha256>.json`, keyed on the machine,
target, mode, and each evidence file's own hash — touch a lockfile or a
manifest and the next scan is a real one. `--no-cache` skips the lookup, and
`SAFE_AUDIT_SCAN_CACHE_TTL_SECONDS` overrides the 24h TTL.

The cache can only ever skip work, never invent a verdict: a missing, expired,
corrupt, or structurally unrecognizable entry falls through to a real scan, and
a scan with no dependency evidence at all is never cached. Source and `--full`
scans are never cached — they stage arbitrary files whose set the evidence hash
does not capture.

An entry is replayed only for the request that produced it. The stored envelope
records the schema, key, machine, target, and mode, and every field is checked
before replay; an entry belonging to another project, or written by a safe that
scored verdicts differently, is a miss. A malformed entry never aborts the scan
it was meant to accelerate — the failure mode of a cache must be slowness, not
an error a caller reads as "the scan failed".

A result is stored only when the scanner set that produced it is fully
represented by the key. Nothing is cached when:

- **govulncheck is involved at all.** It analyses `./...` — Go source, which no
  evidence hash covers. That holds even when it was merely absent, so
  installing it later is never masked by a replay of the run that lacked it.
- **any ecosystem audit did not return `ok`**, or any of osv-scanner, syft and
  grype is in a non-ok state. Missing coverage is not a cacheable answer.

Beyond the manifests and lockfiles discovery finds, the key also hashes the
per-root inputs that decide what a scanner *asks*: `.npmrc` (which registry
`npm audit` queries), `.safe-audit` (which ecosystems are audited at all), and
every known evidence name that exists as a **symlink** — discovery walks
regular files, but `npm audit` reads the link happily.

One input remains deliberately outside the key: **advisory databases**. OSV and
the ecosystem audits consult live data that can gain an advisory while an entry
is still fresh. That window is exactly the TTL, and it is the price of the
cache: lower `SAFE_AUDIT_SCAN_CACHE_TTL_SECONDS`, or pass `--no-cache`, when a
scan must reflect advisories published in the last hours. A replay always says
so on stdout, with the entry's age.

Evidence is re-hashed after the scanners finish: if a lockfile or manifest
changed while they ran, the result describes bytes that are no longer on disk
and is not cached. A file that is swapped out and restored inside that same
window is not detected — the residual is the same class as absolute-path
invocation, documented in [Install Wrappers](install-wrappers.md).

Evidence paths enter the key relative to the scan root, so a remote scan —
which stages its target into a fresh temporary directory on every run — hits
the cache like a local one.

### Ecosystem audits and `audit_totals`

Beside osv-scanner and grype, a scan runs each ecosystem's own auditor in the
project root: `npm audit`, `composer audit`, `cargo audit`, `govulncheck`,
`pip-audit`. Each reports in its own shape, and safe normalizes them to one
record with per-severity counts. Four rules govern that normalization:

- A scanner's **exit status is not trusted alone** — npm audit and pip-audit
  exit nonzero when they *find* something. Output that parses as a result is a
  result; anything else (empty, HTML from a proxy, an unknown shape) is
  `status: "error"`. "Ran, failed, found nothing" is never reported, because it
  is indistinguishable from a clean project.
- Counts are **advisories, not dependencies**. pip-audit lists every dependency
  with its own `vulns`, and composer keys advisories by package.
- A severity that cannot be determined is `unknown`, never `medium`.
  cargo-audit advisories usually carry only a CVSS vector, which safe scores.
- Evidence a scanner **structurally cannot read** is a third state, distinct
  from both a finding and a breakage: `npm audit` needs an npm lockfile, so a
  pnpm or Yarn project is reported as not run rather than as a broken scanner.
  It does not change the verdict — warning there would put every pnpm project
  behind an operator prompt for a tool that was never going to answer.

A scanner that is **absent** does warn (its coverage is genuinely missing), and
a scanner that **failed** warns and blocks caching. `pip-audit` audits every
declared target — `requirements.txt`, `requirements-dev.txt`, and a
`pyproject.toml` *by path* — because a bare `pip-audit` audits the active
Python environment rather than the project, and stopping at the first target
hid every dev-only advisory.

`safe audit scan --allow-missing-tools` turns a missing ecosystem auditor from
an abort into a reported gap. Callers that gate on the result document
(`safe install --project`, the PATH-wrapper preflight) pass it: without it, a
Rust project on a machine without cargo-audit could not be audited at all from
a non-interactive shell.

`audit_totals` is the aggregate every gating consumer reads: the CVE scan plus
each ecosystem audit that returned `ok`, with a per-scanner breakdown under
`.audit_totals.ecosystem`. These are **scanner reports, not distinct
advisories** (`deduplicated: false`): only osv and grype carry comparable ids,
so one advisory seen by three scanners counts three times. The aggregate
answers "is there a critical anywhere", which double counting cannot change;
anything showing a number to a human shows the per-scanner breakdown instead.

### `--result-out <file>`

Writes the result document to a caller-owned path. The published result lives
at `~/.local/share/safe/audit/results/<machine>/<date>-scan.json`, one file per
machine per day: a concurrent scan of another project replaces it. Any caller
that *decides* something from a scan (`safe install --project` does) must read
its own copy instead. Single-target scans only.

Full filesystem scan, including installed dependency trees:

```bash
safe audit scan --full --project .
```

Configured machine scan:

```bash
safe audit scan --machine remote-a --project /path/to/project
```

All configured machines:

```bash
safe audit scan --all
```

Results are written under:

```text
~/.local/share/safe/audit/results/<machine>/
~/.local/share/safe/audit/sbom/<machine>/
```

Remote scan strategies are selected from available tools and connectivity:

- remote direct scanner execution;
- remote SBOM generation with local vulnerability scanning;
- staged local scanning of copied source evidence.

Before trusting a remote Grype scan, `safe audit` checks `grype db status -o json -q`. The stale threshold defaults to 7 days and can be changed:

```bash
SAFE_AUDIT_GRYPE_DB_MAX_AGE_DAYS=14 safe audit scan --machine remote-a --project /path/to/project
```

## Package Checks

```bash
safe audit check express@4.21.0 --ecosystem npm
safe audit check express --ecosystem npm            # unpinned: resolves the target first
safe audit check ruff@0.11.0 --ecosystem python --json
```

Checks are **version-aware**: the command first resolves the version the
package manager would actually install, then matches OSV advisories against
that exact version's affected ranges.

- An exact version in the spec is used as-is (no network).
- An unpinned npm spec resolves through the registry packument: dist-tag for
  installs, and with `--op update` the **in-range** target derived from the
  project's `package.json` and lockfile ranges (what `npm update` would
  install, not the dist-tag).
- pip/uv, cargo, composer, and go unpinned specs resolve to the registry's
  latest release.
- When resolution fails (network, private registry, `||` ranges, git/workspace
  specs), the check degrades to a package-level audit with a WARN floor and
  reason `version_unresolved` — never a silent GO.

Advisories are classified per resolved version as `affecting`, `remediated`
(fixed at or below the resolved version), `unfixed`, or `ambiguous`. Only
**affecting** advisories drive the verdict: a bump that is itself the
remediation gets a PASS with a notice naming the fixed advisories. An
affecting advisory whose severity is listed in `install.block_severities`
(default: `critical`) produces BLOCK; other affecting advisories produce
WARN. An OSV outage produces WARN (fail closed), never a zero-CVE PASS.

Verdicts and exit codes are unchanged for consumers:

```text
GO    (exit 0)
WARN  (exit 10)
BLOCK (exit 20)
```

### Install gate mode

The shell install wrappers and `safe install` invoke the check as a gate:

```bash
safe audit check <pkg> --ecosystem npm --gate install --op install|update
```

Gate mode applies the allow policy itself and exits 0 when the install may
proceed:

- **GO** proceeds and records the pinned resolved version in
  `~/.config/safe/run/install-known.json` (machine-written evidence with a
  pointer to the check receipt) — no operator terminal involved.
- **WARN** proceeds only when a pinned `host-allow` entry matches the
  **resolved** version, or when every WARN cause is listed in the opt-in
  `install.auto_allow_tolerate` config and no advisory affects the resolved
  version. Otherwise it refuses (exit 10) with an actionable, always-pinned
  hint — suggestions never use `@latest`.
- **BLOCK** refuses (exit 20) and points at operator review.

A Socket scoring failure (missing CLI, auth, rate limit) is reported as an
infrastructure failure with a recovery path (`socket login`, `safe doctor`),
explicitly distinguished from a package finding. It still refuses by default:
fix the wiring rather than tolerating blind installs.

Socket improves behavioral scoring. Authenticate with:

```bash
socket login
```

For predictable repeated use, use a Socket account token. The practical token scope for `socket package score` is `packages:list`. `safe doctor` reports the Socket CLI and token wiring.

## Release Review

Review a GitHub release before downloading assets:

```bash
safe audit release github \
  --repo sigstore/cosign \
  --version v3.0.5 \
  --asset cosign-linux-amd64 \
  --json
```

Checks include release age, draft/prerelease status, asset presence, release churn, previous release comparison, high-risk path changes, tag-to-commit resolution, and GitHub commit verification status.

For repositories with multiple release streams:

```bash
safe audit release github \
  --repo scaleway/scaleway-cli \
  --version v2.55.0 \
  --asset scaleway-cli_2.55.0_linux_amd64 \
  --tag-regex '^v2\.'
```

## Advisory Review

```bash
safe audit vuln github-release --repo OWNER/REPO --version v1.2.3 --json
```

The command maps GitHub repository security advisory ranges to the supplied release version where possible. High or critical matches block. Ambiguous advisory mappings block instead of being ignored.

## Verification

Checksum-only release asset verification:

```bash
safe audit verify release-asset \
  --artifact ./tool-linux-amd64 \
  --checksum ./checksums.txt \
  --json
```

Checksum-only success returns `WARN` because no signature was verified. Add Sigstore certificate and signature data when available:

```bash
safe audit verify release-asset \
  --artifact ./tool-linux-amd64 \
  --checksum ./checksums.txt \
  --certificate ./checksums.txt.pem \
  --signature ./checksums.txt.sig \
  --certificate-identity-regexp '^https://github.com/OWNER/REPO/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --require-signature
```

Verify a Sigstore bundle:

```bash
safe audit verify sigstore-bundle \
  --artifact ./cosign-linux-amd64 \
  --bundle ./cosign-linux-amd64.sigstore.json \
  --identity keyless@projectsigstore.iam.gserviceaccount.com \
  --oidc-issuer https://accounts.google.com
```

Verify a local TUF bootstrap:

```bash
safe audit verify tuf-bootstrap \
  --mirror ./mirror \
  --root ./root.json \
  --root-checksum "$(sha256sum ./root.json | awk '{print $1}')" \
  --target artifact.pub=./trust/artifact.pub \
  --json
```

`verify tuf-bootstrap` requires `cosign`, a checksum tool, and `python3` or `python`. Local mirror inputs can be paths or `file://...` URLs. The verifier serves local mirror content through a temporary loopback `http://127.0.0.1:<port>` bridge before calling `cosign initialize`, because Cosign does not bootstrap correctly from `file://` mirrors.

## Binary Execution

Run an artifact in a networkless Podman sandbox:

```bash
safe audit binary exec ./tool --json -- --version
```

The sandbox uses a read-only artifact bind mount, no network, dropped capabilities, no-new-privileges, and tmpfs scratch space. Startup-shaped failures are classified with reason codes such as `missing_interpreter`, `missing_shared_library`, `sandbox_runtime_mismatch`, and `runtime_failure`.

## IOC Workflows

Lookup one advisory and scan the default machine:

```bash
safe audit ioc GHSA-example-id
```

Scan with a custom IOC JSON file:

```bash
safe audit ioc --list ./ioc.json --machine remote-a
```

Update the CISA KEV-derived IOC catalog and scan:

```bash
safe audit ioc --update --since 7d --all
```
