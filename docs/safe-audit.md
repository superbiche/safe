# safe audit

`safe audit` is the evidence and verdict engine for the ecosystem.

Call it through the dispatcher:

```bash
safe audit repo-audit .
```

The compatibility `safe-audit` binary remains installed for scripts, but
documentation and examples use the dispatcher form.

## Capabilities

Use the machine-readable capability command when integrating with other scripts:

```bash
safe audit capabilities --json
```

The current capability groups cover:

- `top_level`: package-audit, repo-audit, machine-audit, diff, and status;
- `binary-audit`: `release-review`, one composite command whose checks cover a
  release's checksums, signature, GitHub release metadata, repository
  advisories, TUF bootstrap material, and networkless sandbox execution;
- `ioc`: lookup, list scanning, and updates;
- `setup`: machine setup and scanner bundle creation.

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

### How a scanner is resolved

A scanner that does not resolve is reported missing, and a missing scanner
degrades the verdict to WARN — which looks exactly like a finding. Because
callers routinely arrive with a PATH that is not the machine's (agents, CI
steps, Makefile recipes, `bash -c` children), resolution goes through three
steps in this order:

1. **The caller's PATH.** An explicit PATH is an expressed preference: a mise
   shim, a project-local build or a test mock must keep winning.
2. **The machine's tool cache** (`~/.config/safe/audit/tools.json`), which
   records the absolute path of each scanner found at detection time. This is
   the step that makes a trimmed PATH survivable.
3. **The standard install directories** — `~/.local/bin`, `~/.npm-global/bin`,
   `~/go/bin`, `~/.cargo/bin`, `~/.local/share/mise/shims` — for a scanner
   installed since the last detection.

Detection (`safe audit setup`, and the automatic refresh) probes the same
directories, and it never erases a cached path that still resolves to an
executable file. Without that, a single probe from a trimmed environment would
rewrite the machine's cache to nulls and every later scan would report the
scanners missing until someone refreshed by hand. A tool that genuinely
disappeared is still dropped: claiming coverage safe does not have is the worse
failure.

The cache is shared state with many concurrent writers — every gated build's
repo-audit preflight refreshes detection — so two properties keep it
survivable. A replace is atomic: the new cache is staged in the config
directory and renamed into place, so a concurrent reader sees the old file or
the new one, never half of either. And a refresh that reproduces the cached
entry does not write at all, which makes the steady state quiet; a machine
whose PATH resolves a scanner somewhere other than the cache records still
writes on every scan.

A cache that cannot be *read* — a directory in its place, a file the config
directory will not let safe rewrite — is audit-infrastructure breakage, and
scans refuse on it with a repair hint. It is never reported as a missing
scanner: those are opposite facts, and conflating them sends an operator
reinstalling scanners that were installed the whole time.

## Project And Machine Scans

Local project scan:

```bash
safe audit repo-audit .
```

Verbose project scan:

```bash
safe audit repo-audit . --verbose
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
manifests, staged source files, skipped nested repositories, and scanner inputs.
Use it when confirming that a scan is constrained to the intended project or
machine root.

When required scanners (`osv-scanner`, `syft`, `grype`) or discovered project
ecosystems require audit commands that are missing (`npm`, `composer`,
`pip-audit`, `cargo-audit`, `govulncheck`), `safe audit machine-audit` stops by default
and prints install guidance plus the rerun command. If you explicitly continue
with a partial audit, missing tools are reported as `skipped` and the scan
verdict is `WARN`; they are not presented as zero CVEs.

Dependency-only scan:

```bash
safe audit repo-audit . --deps-only
```

### Nested repositories

A repository nested inside the target is skipped: linked git worktrees (a `.git`
file pointing into `<repo>/.git/worktrees/`) and independent clones (a `.git`
directory) are second copies of a codebase, and auditing them as part of the
target reports the same findings once per copy. A project with 11 worktrees
under `.task/` produced 4356 packages and 72 CVE criticals where 6 were real.

Git **submodules are kept**. Their `.git` file points into
`<repo>/.git/modules/`, their lockfiles are the parent project's dependencies,
and they are part of what the parent builds.

The rule is ancestry, not "carries a `.git`": a directory is skipped only when
another directory at or below the scan target — the target itself included —
also carries a `.git` entry. A `machine-audit` scan root is a plain directory
holding independent repositories side by side, so none of them has such an
ancestor and all of them stay discovered.

Detection does not descend derived directories (`vendor/`, `node_modules/`,
`build/`, and the rest of the skip list). A repository found there is a
source-installed **dependency** — `composer install --prefer-source`, a CMake
`build/_deps/` fetch — not a second copy of the project, and `--full` exists to
catalog installed trees, so it catalogs those as it always has.

Skipped roots are excluded from manifest and lockfile discovery, from the
staged source scan, from the `.safe-audit` config walk, and from the SBOM,
`--full` included. A scan that skipped any prints one line saying how many;
`--verbose` lists them.

### What osv-scanner is handed

osv-scanner selects an extractor from the filename, and a file it has no
extractor for is fatal for the **whole batch**: it exits nonzero, writes
nothing, and discards the lockfiles it had already extracted. So discovery's
set is translated before the scanner sees it:

- `go.sum` is replaced by its sibling `go.mod` — the Go extractor reads the
  module file, never the checksum file.
- `bun.lockb` is replaced by its sibling `bun.lock`; the binary format has no
  extractor. `bun.lock` on its own is read directly.
- A file with no readable stand-in is dropped, and the drop is reported.

Two safeguards sit behind the translation, because the failure it prevents is
silent by nature — the tier goes missing while the scan still completes:

- If the batch fails anyway, each lockfile is rescanned on its own and the
  results are merged. One unreadable file costs its own coverage, never the
  whole tier; the tool status becomes `partial` and names the file.
- Coverage that was lost is stated on the surface's closing line
  (`finished ... with degraded coverage: ...`), not only inside the result
  JSON's `tool_status`. A degraded tier also WARNs the verdict and blocks
  caching.

`safe audit lockfile-support [--json]` probes the installed scanner against
every format safe hands it and reports any it can no longer read. `safe doctor`
runs it, so a scanner upgrade that drops an extractor is visible before it
costs a scan rather than after.

### Scan cache (`--deps-only`)

A dependency-only scan reads only dependency evidence: the lockfiles and
manifests discovery finds, plus the few per-root files a scanner reads to
decide its answer (enumerated below). When that evidence hashes to a set
already scanned within 24 hours, re-running the scanners cannot produce a
different verdict, so the recorded result is replayed instead:

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
scored verdicts differently, is a miss. The key carries no version, so the
schema is what retires stale semantics: 1.58.0 moved it to 2, and every entry
written before it misses. A malformed entry never aborts the scan
it was meant to accelerate — the failure mode of a cache must be slowness, not
an error a caller reads as "the scan failed".

A result is stored only when the scanner set that produced it is fully
represented by the key. Nothing is cached when:

- **govulncheck is involved at all.** It analyses `./...` — Go source, which no
  evidence hash covers. That holds even when it was merely absent, so
  installing it later is never masked by a replay of the run that lacked it.
- **an ecosystem audit failed, was absent, or returned partial coverage**, or
  any of osv-scanner, syft and grype is in a non-ok state. Missing coverage is
  not a cacheable answer. (A deterministic `unsupported` record — npm audit
  facing a pnpm lockfile — *is* cacheable: it is decided by files that are in
  the key.)

Beyond the manifests and lockfiles discovery finds, the key also hashes the
per-root inputs that decide what a scanner *asks*: `.npmrc` (which registry
`npm audit` queries), `.safe-audit` (which ecosystems are audited at all), and
every known evidence name that exists as a **symlink** — discovery walks
regular files, but `npm audit` reads the link happily.

Composer's **installed tree** is in the key for the same reason. `composer
audit` audits what is in `vendor/`, not what is in the lock, so a checkout
whose `vendor/` was rebuilt from another branch can hold an advisory its
unchanged `composer.lock` never mentions — and without this the unchanged lock
would replay the previous tree's verdict. The file hashed per root is the one
composer will read: `$COMPOSER_VENDOR_DIR/composer/installed.json` when that
variable is exported, else the directory named by `config.vendor-dir` in
`composer.json`, else `vendor/`. A root with no installed tree — every path
package in a monorepo, every checkout audited before its build — is audited
from its lock and keyed on that lock alone, which is exactly what it read.

The **scanner set** is part of the key too: each tool's presence and, when
present, its path, size and mtime. Installing pip-audit gains a project Python
coverage it did not have; removing it loses that coverage. Neither touches an
evidence file, so without this a cache hit would replay a verdict produced by a
different set of tools.

One input remains deliberately outside the key: **advisory databases**. OSV and
the ecosystem audits consult live data that can gain an advisory while an entry
is still fresh. That window is exactly the TTL, and it is the price of the
cache: lower `SAFE_AUDIT_SCAN_CACHE_TTL_SECONDS`, or pass `--no-cache`, when a
scan must reflect advisories published in the last hours. A replay always says
so on stdout, with the entry's age.

Evidence is re-enumerated and re-hashed after the scanners finish: if a
lockfile or manifest changed while they ran — or a file that was not there
before appeared, like a `.safe-audit` that switches an ecosystem off — the
result describes a project that no longer matches the key, and is not cached. A file that is swapped out and restored inside that same
window is not detected — the residual is the same class as absolute-path
invocation, documented in [Install Wrappers](install-wrappers.md).

Evidence paths enter the key relative to the scan root rather than by absolute
path, so a target staged into a fresh temporary directory on every run derives
a stable key. Remote scans do not benefit from this yet: a staged remote scan
cannot select the core scanners through the remote machine identity, so its
core tool status is not `ok` and the result is never stored. Remote
`--deps-only` scans therefore re-scan every time; the cache is a local-target
feature today.

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
- Evidence a scanner **structurally cannot read** is its own state,
  `unsupported`, distinct from both a finding and a breakage: `npm audit` needs
  an npm lockfile, so a pnpm or Yarn project is reported as not run rather than
  as a broken scanner. It does not change the verdict — osv-scanner reads that
  lockfile, so the project IS covered, and warning there would put every pnpm
  project behind an operator prompt for a tool that was never going to answer.
  A `package.json` with **no lockfile at all** is different: nothing covers
  those dependencies, so that WARNs rather than reporting a clean project.
- Coverage that is partly missing is `partial`: when pip-audit audits two
  requirements files and one fails, the advisories the other one found are
  still counted. A failure in one target must not erase a critical found in
  another.
- A scanner reporting **nothing to audit** is a clean result, not a breakage:
  a `composer.json` with no dependencies makes `composer audit` exit 0 with an
  empty stdout and `No packages - skipping audit.` on stderr. That is a
  complete answer — zero advisories because there is nothing to look at — and
  it is recorded as `ok` with the note `composer reported no packages to
  audit`. Mirrors the osv-scanner `No package sources found` benign zero.

A scanner that is **absent** does warn (its coverage is genuinely missing), and
a scanner that **failed** warns and blocks caching. `pip-audit` audits every
declared target — `requirements.txt`, `requirements-dev.txt`, and a
`pyproject.toml` *by path* — because a bare `pip-audit` audits the active
Python environment rather than the project, and stopping at the first target
hid every dev-only advisory.

`govulncheck` is required to exit 0: in `-json` mode it reports findings in
the stream, so a nonzero exit means the run itself failed, whatever prefix it
managed to write. That stream is a sequence of **concatenated JSON documents**,
each pretty-printed across many lines — not NDJSON — and safe slurps it as
such. A stream that stops mid-document still fails to parse and is still an
`error`; a run whose findings were truncated is never reported as clean.

A scanner that exited 0 but whose output could not be validated says exactly
that (`output validation failed (scanner exit 0)`) rather than
`failed (exit 0)`: the status is still `error`, but the note names the output
as what broke instead of implying the tool did.

`composer audit` reads the **installed** tree by default, and `--locked` reads
the lock file instead — a different package set. safe audits the installed tree
first, because a deployed checkout whose lock has drifted can carry an
installed advisory the lock does not mention: against such a fixture the
default run reported six advisories including one critical while `--locked`
reported none.

The lock file is used only when there is no installed tree to read. composer
refuses that case outright (`No installed packages found ... pass --locked`) —
every path package in a monorepo, every checkout audited before its build — and
safe then reruns with `--locked` rather than reporting a broken scanner. The
record's note says `audited composer.lock (no installed packages)`, because a
lock-file audit and an installed-tree audit are not the same coverage. With no
lock either, the refusal stays an `error`: nothing was audited.

Every audit record carries the **root it ran in** (`.root`, relative to the
scan target; `.` is the target itself), on `.ecosystem_audits[]` and on
`.audit_totals.ecosystem[]` alike. A monorepo runs the same scanner once per
package, and without the root the report read as one scanner reported N times.
The scan summary follows: the `ECOSYSTEM AUDITS:` line in the CVE block names
each scanner once with its counts summed across the roots it ran in (and
`across N roots` when that is more than one), while the detail block below
prints one line per record, prefixed with its root.

`safe audit machine-audit --allow-missing-tools` turns a missing ecosystem auditor from
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

### JVM / Maven and Gradle

JVM dependencies get **coverage without command-gating**. Gradle and Maven are
declarative — dependencies resolve transitively at build time, with no discrete
install verb to wrap the way `npm install <pkg>` is wrapped — so there is no
PATH shim for `mvn` or `gradle`, and a JVM dependency add is not intercepted at
install time. Coverage comes from the audit engine instead:

- **`safe audit repo-audit`** sweeps `pom.xml` and `gradle.lockfile` through
  OSV like any other lockfile, so a project scan covers JVM dependencies and
  reports a verdict rather than silently skipping them.
- **`safe audit package-audit --ecosystem Maven <group:artifact>@<version>`** is
  the single-coordinate preflight; `Maven`, `maven`, and `gradle` all map to the
  OSV `Maven` ecosystem.

There is **no per-ecosystem JVM auditor** (no equivalent of `npm audit`), and
**Socket has no Maven tier**, so a JVM audit is OSV-only: the behavioral tier
degrades honestly to a disclosed skip (`Socket has no Maven tier`) — never a
false `GO`, and never an infrastructure-outage signal. A qualified Maven version
OSV cannot range-match (`1.0.0.RELEASE`, `2.5-RC1`) resolves to a WARN with a
pin-an-exact-version hint rather than a silent pass.

### `--result-out <file>`

Writes the result document to a caller-owned path. The published result lives
at `~/.local/share/safe/audit/results/<machine>/<date>-scan.json`, one file per
machine per day: a concurrent scan of another project replaces it. The replace
is atomic — a reader gets one complete document, never a truncated one — but
which scan's document it gets is whichever wrote last. Any caller that
*decides* something from a scan (`safe install --project` does) must read its
own copy instead. Single-target scans only.

Full filesystem scan, including installed dependency trees:

```bash
safe audit repo-audit . --full
```

Configured machine scan:

```bash
safe audit machine-audit --machine remote-a --project /path/to/project
```

All configured machines:

```bash
safe audit machine-audit --all
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
SAFE_AUDIT_GRYPE_DB_MAX_AGE_DAYS=14 safe audit machine-audit --machine remote-a --project /path/to/project
```

## Package Checks

```bash
safe audit package-audit express@4.21.0 --ecosystem npm
safe audit package-audit express --ecosystem npm            # unpinned: resolves the target first
safe audit package-audit ruff@0.11.0 --ecosystem python --json
safe audit package-audit org.apache.logging.log4j:log4j-core@2.17.1 --ecosystem Maven
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

Socket is the primary behavioral tier and is consulted on every check unless
the operator explicitly sets `install.socket.mode` to `never`. A validated
Socket result BLOCKs only for a `critical` `supplyChainRisk` alert. Critical
vulnerability alerts, high-severity alerts, and scores below 70 WARN; the
receipt retains the validated envelope for review. Missing CLI, auth,
rate-limit, timeout, and malformed-result conditions are infrastructure WARNs,
not package findings.

Successful envelopes are cached for the exact ecosystem, package name, and
resolved version under `~/.cache/safe/socket/` (default TTL: 7 days; configure
`install.socket.cache_ttl_days`). The cache root is configurable via
`install.socket.cache_dir` (env override: `SAFE_AUDIT_SOCKET_CACHE_DIR`):
point it at a synced path to share Socket's per-package scoring across trusted
machines, since entries are per-package JSON keyed by purl (no secrets),
atomically written, and TTL-bounded. Cache entries are private and atomically
written. Expired entries never decide a verdict: if the refresh fails, safe
returns the live infrastructure WARN and may disclose the last complete score
and its age as context.

Verdicts and exit codes are unchanged for consumers:

```text
GO    (exit 0)
WARN  (exit 10)
BLOCK (exit 20)
```

### Install gate mode

The shell install wrappers and `safe install` invoke the check as a gate:

```bash
safe audit package-audit <pkg> --ecosystem npm --gate install --op install|update
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

Review a whole GitHub release from a single spec — release metadata,
advisories, checksum, signature, TUF trust material and a sandboxed smoke
run, aggregated into one verdict:

```bash
safe audit binary-audit release-review --spec ./review.json
```

This is the `release-review` composite (implemented in `safe-core`, forwarded
here). It replaced the earlier six granular sub-lanes — `release github`,
`vuln github-release`, `verify release-asset`, `verify sigstore-bundle`,
`verify tuf-bootstrap` and `exec` — which no longer exist as commands. The
spec schema, the six checks it runs, the report shape, and the ledger of
places it deliberately diverges from those sub-lanes are documented in
[release-review.md](release-review.md).

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
