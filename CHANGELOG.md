# Changelog

## Unreleased

- **`verify sigstore-bundle` accepts `--identity-regexp` as an alternative to
  the exact `--identity`.** GitHub attestation-style per-asset bundles — the
  shape openai/codex publishes — are signed by a tag-bound workflow identity
  (`https://github.com/openai/codex/.github/workflows/...@refs/tags/<tag>`),
  which changes on every release and therefore cannot be pinned as an exact
  identity. The flag maps to cosign's `--certificate-identity-regexp` and is
  used for the main verification pass and the identity probe alike, so a
  regexp-mode policy failure still classifies as `identity_mismatch` rather
  than a blanket signature failure. It is mutually exclusive with `--identity`
  and one of the two is required. `verify release-asset` already exposed
  `--certificate-identity-regexp`, so this closes an inconsistency inside the
  binary-audit lane rather than adding a new capability: whichever flag was
  given is what the JSON payload reports (`expected_identity` and
  `expected_identity_regexp`, each null when unset).

- **The Socket cache location is now a first-class config knob.** The cache root
  was resolvable only via `SAFE_AUDIT_SOCKET_CACHE_DIR`, an env var the docs
  framed as test-only, even though relocating the cache to a shared/synced path
  is a legitimate recurring need (pay Socket's ~per-package scoring once
  fleet-wide instead of on every machine). `install.socket.cache_dir` now sits
  beside `install.socket.cache_ttl_days` as a supported, documented setting; a
  leading `~/` expands to `$HOME`. Precedence is env override →
  `install.socket.cache_dir` → the `~/.cache/safe/socket` default, so existing
  setups and the test suite are unchanged. No verdict behavior changes: cache
  entries are per-package JSON keyed by purl (no secrets), atomically written,
  and TTL-bounded, which is what makes a synced cache dir safe to share across
  trusted machines.

- **Socket "no record of this package" is no longer conflated with a Socket
  outage.** A package Socket has never scored (a 404/`not_found`) produced the
  `socket_error` cause — the same one a real timeout, auth failure, or 429
  outage produces — so it could not be tolerated without also tolerating genuine
  outages, and ecosystems with no host-allow lane (go, cargo) had no override at
  all. `not_found` now carries its own `socket_not_found` cause. It stays a WARN
  by default (a package Socket has never seen can be a fresh typosquat in an
  ecosystem Socket fully indexes, like npm/PyPI), but it is independently
  tolerable via `install.auto_allow_tolerate` — opt-in, per machine — which is
  the only override lane for go/cargo, where host-allow does not apply. Sibling
  versions on a ranged update are classified the same way. This is what lets a
  vetted `go install golang.org/x/vuln/cmd/govulncheck@<pinned>` (OSV and
  blocklist PASS; Socket simply has no record) be allowed on a Go box without a
  blanket bypass. Socket does index Go and Rust — this is per-package absence of
  data, not a structural ecosystem gap, so an indexed module still gets its real
  behavioral score.

- **Non-global Composer installs honor `--working-dir`/`-d` when scanning.** A
  non-global `composer install`/`update`/`require`/`reinstall` — and a
  package-less `create-project` — run with an effective working directory
  (`-d <dir>`, `-d<dir>`, `--working-dir <dir>`, `--working-dir=<dir>`, at either
  argument position) now runs its project presence check and dependency scan in
  THAT directory rather than the process cwd. Previously the scan targeted the
  caller's cwd, so `composer install -d /path/project` from an unrelated
  directory skipped the project scan (or audited the wrong tree) before
  delegating. An existing working directory that cannot be entered now refuses
  (exit 100) instead of delegating unaudited; a nonexistent one has nothing to
  scan and delegates (Composer rejects it). A repeated working-dir option
  resolves first-wins (`--working-dir=A --working-dir=B` audits A, matching
  Composer), and the directory is entered with physical path semantics so a
  symlinked `..` resolves to the same project Composer's `chdir` reaches. The
  effective directory is also threaded to safe-audit as `--project-dir`, closing
  the same gap for the glued `-d<dir>` form. The leading glued form
  (`composer -d<dir> install`) stays fail-closed as before.

- **Composer `reinstall` and `create-project` are now gated.** Both fetch remote
  artifacts but were recognized-but-passthrough. `reinstall` re-fetches the
  locked tree, so it is audited as an install-class project scan (covering both
  `reinstall` and `reinstall vendor/pkg`). `create-project` audits only its
  first positional package as the root package; Composer's explicit `[version]`
  positional overrides a version fused into the name, and the `[directory]`
  positional is never a package. Any `--require` additions are audited on top of
  the root. A `create-project` with no root but a `--require` addition, or a
  bare one, is install-class: safe scans the current project (and audits the
  additions), or fails closed when there is no project. `--stability`/`-s` (a
  candidate selector safe-audit cannot model) and ambiguous multi-character
  short-option bundles (e.g. `-nd`, which Symfony parses as `-n` plus a
  `-d<dir>` that shifts the package boundary) both refuse with a pin/unbundle
  hint rather than audit a guess. Because Composer binds command options lazily,
  a `--stability` or `--require` placed *before* the subcommand
  (`composer --require=… create-project …`) is caught too — it refuses rather
  than fetch unaudited. Value-taking flags (`--repository`,
  `--repository-url`, `--working-dir`, …) can no longer be mistaken for the
  package, and `--repository-url` reaches the audit as the custom source.
  Abbreviations of both commands (`composer creat`, `composer reins`) now refuse
  with a canonical spelling instead of passing through unaudited — closing a
  bypass where Symfony would expand the prefix and fetch before the gate saw it.

- **`safe doctor`'s mise-shim warning is now actionable.** When mise shims are
  bound to the gate wrapper, doctor printed "repoint the shims at the real mise
  binary" — whose obvious execution, a bare `mise reshim`, rebinds them to the
  wrapper again (the wrapper shadows the real mise on PATH), recreating the very
  drift it warned about. It now prints a runnable repair that strips safe's bin
  dir from `PATH` for the reshim, so mise relinks the shims to the real binary.
  The gate bin dir is exposed in `safe doctor --json` under
  `environment.install_wrappers.bin_root`.
- **`safe doctor` now reports the ecosystem auditors it was blind to.**
  `govulncheck`, `pip-audit`, `cargo-audit`, and `composer` are needed only
  when a project of that ecosystem is audited, so doctor never listed them —
  and answered "no missing prerequisites" on a box that had none of them. They
  now appear as a distinct advisory ("ecosystem auditors — present only matters
  when auditing that ecosystem") reporting each present/absent, and surface in
  `--json` under `features.ecosystem_auditors`. They are deliberately NOT
  missing prerequisites: a machine that never touches Go does not owe
  `govulncheck`, and a `repo-audit` that needs one already WARNs and names it.
- **A partly-failed ecosystem audit no longer hard-refuses the install.** The
  project gate classed a scanner as broken infrastructure by matching
  `/fail|error/` against its free-form note, so a `pip-audit` that covered
  `requirements.txt` and only broke on `requirements-dev.txt` — status
  `partial`, note `pip-audit failed for: …` — was refused with exit 100 as if
  nothing had been checked, a dead end no allow could rescue. "broken" is now
  the structural `status == "error"` alone; a `partial` run (real, if
  incomplete, coverage) is disclosed on the `not run:` line and WARNs the
  verdict like any other degraded tier. The same note-regex also misfired on
  lockfile paths containing "fail"/"error". Only a scanner that returned
  nothing usable refuses.

  As part of the same move, `syft_status` now distinguishes its own markers: a
  `syft failed` (the executable ran and exited nonzero, leaving an empty SBOM
  that grype then scans) statuses `error` and refuses, while `syft unavailable`
  (absent) stays a disclosed skip. Collapsing both to `skipped` — harmless
  while the note-regex still caught "failed" — would otherwise have let a real
  syft execution failure pass under `--yes` once the regex was gone.

- **Removed a latent typosquat vector: the sandboxed audit "preflight."**
  `safe run` built an audit command as `npx --yes safe-audit package-audit …`
  inside a Podman sandbox — an unpinned fetch of a public npm package named
  `safe-audit` that this repo has never published (the name is 404 on the
  registry). On every real machine the fetch failed, the preflight returned
  "inconclusive," and execution continued — so the check never produced a
  verdict. But had anyone registered that name, `safe` would have run their
  code (inside the confinement) *and* let it author a gate verdict. The whole
  preflight path is removed; the sandbox's own confinement is unchanged.

- **`host-allow add`/`update` and `scripts-allow add` now always require
  `--reason`.** That requirement previously lived only in the preflight's
  always-taken "inconclusive" branch, so removing the preflight would have
  silently dropped it. A trust escalation carrying an operator reason is the
  audit trail for bypassing the sandbox default; it is now unconditional,
  matching `block add`. (The audit-gated affordance where a clean verdict let
  you skip the reason only ever worked against a mocked audit; restoring it
  the honest way — auditing on the host — is tracked for a follow-up.)

- **Fixed — a Go repo lost its entire OSV tier, silently.** Discovery handed
  osv-scanner `go.sum`, which its Go extractor has never read (it reads
  `go.mod`). osv-scanner treats a file it cannot extract as fatal for the
  *whole batch*: it exits nonzero, writes nothing, and discards the lockfiles
  it had already read. So a Go repo got no OSV coverage at all, and in a mixed
  repo the Go file took the npm results down with it — 54 advisories were
  invisible in the repo that surfaced this — while the audit still printed
  `repo-audit: finished`.

  What safe hands the scanner is now translated first: `go.sum` resolves to its
  sibling `go.mod`, `bun.lockb` to its sibling `bun.lock`, and a file with no
  readable stand-in is dropped and reported rather than passed in to kill the
  batch.

- If the osv batch fails anyway, each lockfile is rescanned on its own and the
  results merged. One unreadable file now costs its own coverage instead of the
  whole tier; the tool status becomes `partial` and names the file.

- Lost coverage is stated where the operator reads it. `repo-audit` and
  `machine-audit` close with `finished ... with degraded coverage: <tiers>`
  instead of a clean `finished`, and the install gate's `not run:` line now
  includes core tiers, not just ecosystem audits. The result JSON already
  carried this in `tool_status`; nothing surfaced it.

- **`bun.lock` and `bun.lockb` are discovered.** Bun projects were invisible to
  `repo-audit`: no lockfile found, so nothing was audited. `bun.lock` is read
  by osv-scanner directly; `bun.lockb` is binary and has no extractor, so it
  counts as dependency evidence but is never handed to the scanner.

- **New: `safe audit lockfile-support [--json]`**, which probes the installed
  osv-scanner against every lockfile format safe hands it and reports any it
  can no longer read. `safe doctor` runs it and lists dropped extractors under
  missing prerequisites, so a scanner upgrade that strips a tier is visible
  before it costs a scan. This defect shipped in an osv-scanner release and was
  caught by a user, not by a check.

- **Breaking — `safe audit` subcommands renamed to four narrow surfaces.**
  `check` → `package-audit`, `scan --project <path>` → `repo-audit [<path>]`,
  `scan` → `machine-audit`, and `binary`/`verify`/`release`/`vuln` → subverbs
  of `binary-audit`. The old spellings are gone; there are no aliases. Each
  surface now has one role and one vocabulary, over the same shared internals
  (`scan_machine` is unchanged).

  The reason is a defect the shared entrypoint kept producing: `scan` served
  both a project audit and a fleet audit from one body, iterating machine
  targets unconditionally, so auditing a directory printed fleet vocabulary —
  `scan: finished rainbow project '/home/…'`. `repo-audit` has no machine
  dimension at all; it resolves the local machine only because `scan_machine`
  needs an execution context, and never names it. Auditing a project on a
  remote host stays available as
  `safe audit machine-audit --project <path> --machine <name>`.

  `repo-audit` also takes its target as a positional path defaulting to `.`
  rather than `--project`, and rejects `--all`/`--machine` with a message
  naming `machine-audit`.

- The verdict decision now lives in Go (`internal/verdict`, exposed as
  `safe-core package-verdict`). `bin/safe-audit` still gathers all evidence —
  version resolution, Socket scoring, OSV classification, release age,
  registry trust, blocklist state — and advisory classification stays in bash
  because it needs semver range matching. Only the decision moved, so there is
  one implementation of the policy rather than a bash copy that drifts. No
  verdict changes: the existing 338 golden cases pass unmodified.

- `safe audit package-audit` exits **30** when it could not produce a verdict at all —
  the verdict engine is missing, version-skewed, or failed, or the evidence
  could not be assembled. Previously this shared exit 20 with a genuine BLOCK,
  so broken tooling was indistinguishable from a real refusal about the
  package. 30 carries no evidence about the package and is repaired, not
  retried; through the gate it refuses with exit 100 and a message naming the
  breakage rather than offering an allow entry. `docs/contract/agent-contract.json`
  documents the new code.

- `safe-core` is now required for every audit, not just `npm dedupe`/`prune`.
  A missing or version-skewed `safe-core` refuses as audit-infrastructure
  breakage with a "rerun install.sh" recovery path, never as a package
  finding, and never as a verdict. `install.sh` already rebuilds and
  reinstalls `safe-core` on every run, and `safe doctor` already reports skew.

- `install.socket.mode=never` no longer produces a clean GO on its own. Since
  Socket became the only behavioral tier, a check that skips it has gathered
  no behavioral evidence, and declining to look does not make an artifact
  safer — so the skip warns and is recorded as `socket_disabled`, distinct
  from the causes that mean Socket failed. The skip stays free: no request, no
  timeout. Operators who want that posture routinely can add `socket_disabled`
  to `install.auto_allow_tolerate`, which passes the gate and records
  `WARN_TOLERATED` rather than `GO`.

- GuardDog has been removed from the install gate. Socket is now the primary
  behavioral tier for every check unless `install.socket.mode=never` is set.
  A critical `supplyChainRisk` alert BLOCKs; critical vulnerability, high
  alerts, and scores below 70 WARN. The retired behavioral-ack override lane
  and its configuration have been removed. Validated successful Socket results
  now cache for seven days by exact resolved package identity; expired entries
  are context only and never decide a verdict.
  Every resolved version is scored, not only the primary one, so a clean
  version can no longer carry a flagged sibling through a ranged update; a
  version that cannot be scored is reported unproven rather than assumed
  clean. Alert classification is exhaustive: a critical alert in a category
  safe does not recognize is treated as unresolved, never as clean. Socket
  error bodies are classified into fixed reason codes and their text is
  discarded — provider responses can carry account context and never reach a
  receipt, cache, or terminal.

- npm gate routing covers install, update, ci, exec, and lock-diff aliases and
  abbreviations before delegation. It uses a checked-in full command/alias
  snapshot with exact alias priority, so non-fetch aliases such as `c` and
  `un` stay passthrough while abbreviated fetch routes (including alias
  prefixes such as `ad` and `dd`) are audited; camel-case normalization is
  covered too.
- Composer accepts only canonical `install`, `update`, and `require`
  spellings, plus exact `global`, on its gated surface, case-insensitively to
  match Symfony. Aliases targeting those commands and gated-looking prefixes
  refuse before delegation with a canonical spelling plus `composer run-script`
  escape hatch. The Unix-only global-home resolver ignores Windows-shaped
  environment variables. An accepted Composer-global route scans the resolved
  global home plus the first absolute `--working-dir` project; relative working
  directories and package-less `require` forms refuse before an interactive
  selection can bypass audit. Require option values never become package
  operands. Original tokens remain unchanged on every delegated path.

- Fresh releases whose initial Socket score times out now receive one bounded
  patience retry (`install.socket.fresh_scan_budget_seconds`, default 90s).
  If Socket still has no score, receipts record `PENDING`; a clean OSV and
  blocklist verdict may proceed with that disclosed note, while any incomplete
  or adverse companion evidence remains WARN/BLOCK.
- Socket low-score detection now reads the current Socket CLI score envelope
  (`data.self.score.overall`), so an overall score below 70 again produces the
  existing `socket_low_score` WARN.
- Package-level OSV pagination keeps its accumulating advisory corpus in
  scratch files instead of passing it through jq arguments, preventing
  `E2BIG` from disabling the cooldown security-fix waiver for large advisory
  histories.

- `safe run <tool> [args...]` now silently delegates a bare wrapped tool name
  (for example `npm` or `go`) to its verified PATH gate wrapper, so the normal
  audited package-manager lane handles the operation instead of treating the
  tool itself as an npx-style package at `latest`. Versioned specs stay on the
  package lane. Command paths and missing, unmarked, or self-referential
  targets refuse with exit 100 rather than bypassing the gate.

## 1.12.0 - 2026-08-10

- npm gate: `npm dedupe` (including `ddp`) and `npm prune` now project their
  package-lock-only mutation into a scratch directory before delegation. An
  empty lock diff delegates directly; added and changed-to registry package
  versions receive the normal per-target install audit, while pre-existing
  findings on untouched packages do not block the operation. The projected
  dependency scan, npm projection, or lock-diff parse failure fails closed as
  audit-infrastructure breakage rather than a package finding. This first
  version covers npm only; pnpm, yarn, and bun equivalents remain outside the
  lane.
- bootstrap: added the stdlib-only Go `safe-core` binary and its initial
  `lockdiff` subcommand for npm lockfileVersion 2/3 package-map diffs.
  `install.sh` now requires Go, builds `safe-core` with the safe version, and
  installs it alongside the bash binaries; `safe doctor` reports missing or
  version-drifted safe-core as a repair warning.

## 1.11.1 - 2026-08-10

- gate/mise: a bare tool name the registry cannot resolve but the mise
  config pins under exactly one backend now refuses with the configured
  spec to rerun (`rerun with the full spec 'npm:@scope/tool'`, preserving
  the version and options the operator typed) instead of
  misframing the spelling as safe/mise infrastructure breakage. mise itself
  does not act on the bare form of a backend tool, so safe never resolves
  and proceeds — the audit would vouch for an artifact the delegate never
  touches. Ambiguous (two backends, one name) and truly unknown names keep
  the infrastructure refusal.
- gate/mise: a leading-@ npm scope in a bare spec is no longer read as a
  version separator — `mise use @scope/tool` was refused as a malformed
  tool spec; it now takes the normal resolution (and hint) path.

## 1.11.0 - 2026-08-04

- Behavioral acknowledgement (operator FP lane, ruled 2026-08-04 after
  GuardDog's popular-package behavioral false positives reached BLOCK tier:
  graphifyy, prettier, qwen-code). `safe run host-allow add <pkg>@<version>
  --acknowledge-behavioral --reason "..."` (TTY-gated) records the exact
  GuardDog rule set from a check receipt as operator-reviewed false
  positives for that exact version. `safe audit check` then downgrades a
  GuardDog high-risk BLOCK to a host-allowable WARN
  (`guarddog_high_risk_acknowledged`) only while ALL of: the live rule set
  stays a subset of the acknowledged one (new rules veto), OSV reports
  nothing affecting the version and is reachable (any affecting advisory or
  OSV outage voids the ack), and Socket — force-consulted as the second
  opinion whenever the ack is a candidate, tier-3 skip suspended — reports
  nothing high/critical. Blocklist, MAL-* records and OSV-critical stay
  unoverridable; multi-version resolutions never match; `host-allow update`
  drops the ack (it never carries to an unreviewed version). Gate BLOCK
  refusals for behavioral findings now name the lane; the agent contract
  documents it as operator-only (agents relay, never run).

## 1.10.2 - 2026-08-04

- GuardDog invocations no longer run under `ulimit -f` (RLIMIT_FSIZE):
  the limit bound every file the process tree writes — including the
  package tarball GuardDog downloads before scanning — so any npm package
  whose tarball (or any single extracted file) exceeded 16 MiB died
  mid-download as `download-package: [Errno 27] File too large`, silently
  zeroing behavioral coverage for large packages (found live on
  `@qwen-code/qwen-code@0.21.5`, 24.6 MB; GuardDog v3.1.0 itself imposes no
  file-size limit — source audit). Both output streams are now live-capped
  by `head -c` pipes on what safe keeps: runaway JSON still fails with the
  same legible per-stream-limit note, a stderr flood stops at the limit
  instead of running its wall-clock budget against the scratch filesystem,
  the scan's own exit status is carried through the pipe structure (a
  failing capture — e.g. `head` on a full filesystem — is named "check
  free space" via an in-memory note instead of masking GuardDog's status
  or being written to the very filesystem it diagnoses). GuardDog's
  internal writes are bounded by its own archive-bomb limits and the
  wall-clock budget — the same disk-exposure class its workdir always had.

## 1.10.1 - 2026-08-04

- Gate audit leash is now computed from the audit's sequential worst case
  (Socket sub-budget × 2 attempts + GuardDog budget × (version probe + up
  to 4 resolved versions) + 80s paginated OSV per version and cooldown
  re-query + 120s bounded-fetch overhead; 1150s with defaults) instead of a
  flat 30s that
  was smaller than the Socket probe's own 30s timeout — a hanging Socket
  backend consumed the entire leash and every uncached install died as an
  illegible `TIMEOUT_FAILCLOSED` that host-allow cannot rescue (live during
  the 2026-08-04 Socket scoring outage). The gate now also hands the audit
  child a 15s Socket budget (`SAFE_AUDIT_SOCKET_TIMEOUT`, caller value
  wins), so a Socket hang degrades to its legible per-component infra WARN
  inside a completed audit. `SAFE_INSTALL_TIMEOUT_SECONDS` still overrides
  the leash absolutely; timeout values are accepted only in 1..99999s —
  out-of-range or malformed values fall back to defaults rather than being
  passed to `timeout(1)`, where garbage fails every audit and an
  arithmetic-wrapped 0 disables the backstop entirely. The gate leash and
  the Socket score leash both escalate TERM to KILL (`--kill-after=2s`): a
  TERM-only timeout is no backstop against a TERM-resistant child. The
  shell's own job-death diagnostic on KILL escalation is suppressed so the
  refusal stays the single final stderr line.

## 1.10.0 - 2026-08-04

- Bun Security Scanner API integration: `safe audit scanner-batch` (stdin
  package set → Bun-shaped advisory array; local blocklist + version-scoped
  OSV querybatch with per-advisory severity classification honoring
  `install.block_severities`; MAL-* records fatal unconditionally) plus the
  `share/scanner.mjs` adapter, installed to `~/.config/safe/scanner.mjs`.
  Hosts implementing Bun's scanner contract — mise's embedded aube
  installer (`AUBE_SECURITY_SCANNER`), bun >= 1.3 — get fail-closed
  install-time scanning of the fully resolved dependency tree. The gate
  injects `AUBE_SECURITY_SCANNER` into every delegate when the adapter is
  deployed and the caller has not set its own. Infrastructure failure
  (OSV unreachable, malformed responses) exits nonzero without advisories:
  the host blocks the install and the cause reads as audit-infrastructure
  breakage, never as a package finding.

## 1.9.2 - 2026-08-03

- Gate delegate discovery accepts a mise shim that a reshim re-linked onto
  our mise wrapper (a `<tool>` file whose marker says `tool=mise`): its
  argv0 dispatch still reaches the real mise, so it is the version-manager
  shim the gate wants to delegate to. Previously it was classified as one
  of our wrappers and skipped, leaving every node-family tool with zero
  non-wrapper candidates — `safe gate pnpm` (and npm, npx, …) exited 127
  even though the audit returned GO.

## 1.9.1 - 2026-08-03

- `safe doctor` no longer execs `podman --version` from a no-new-privs
  process (Codex/bwrap sandboxes): the SELinux domain transition podman
  needs is denied there, so every probe logged an AVC (setroubleshoot storms
  during sandboxed test runs) and doctor misreported podman as broken.
  Sandboxed runs answer from PATH lookup and report
  `present, probed: false` with the reason; unsandboxed probing is
  unchanged.
- `tests/run-all.sh`: parallel suite runner — 15 hermetic suites,
  wall-clock ≈ the slowest suite (~2 min) instead of the serial sum
  (~7 min).

## 1.9.0 - 2026-08-03

- `install.cooldown_security_fix` (`exempt` default, `enforce`): a resolved
  version inside the release-age cooldown that FIXES a published advisory
  (an OSV record whose `fixed` event equals that version) is waived by
  default — a cooldown that blocks the release remediating a CVE recreates
  the catch-22 the gate exists to end. The verdict line and the receipt
  (`release.remediates`, `release.security_fix_policy`,
  `release.cooldown_waived`) name the advisory ids; `enforce` keeps the wait
  and the refusal says the fix exists and which setting held it back. The
  package-level OSV lookup runs only inside the cooldown window and never
  feeds verdict classification.
- host-allow grants now work outside npm (graphifyy regression): all three
  gate matchers were npm-only while `safe run host-allow add --ecosystem
  python` happily recorded grants — the operator pin existed but was never
  consulted, so a WARN-tier cause (cooldown, GuardDog findings) refused a
  host-allowed python package. Matchers now compare ecosystems with spelling
  normalization (`py`/`uv`/`pipx`/`pypi` ≡ `python`, `bun` ≡ `npm`; an npm
  pin can never authorize a same-named python package), and refusal hints
  offer the ecosystem-qualified `host-allow add` command for the python
  family instead of steering non-npm to operator review.

## 1.8.0 - 2026-08-03

- Socket is demoted to tier 3 (`install.socket.mode`, default `auto`): it is
  consulted only when the GuardDog behavioral tier produced no complete
  verdict (not installed, disabled, unsupported ecosystem, unresolved
  version, error/partial) or when the operator forces `always`. A clean
  GuardDog verdict skips Socket entirely — a Socket outage can no longer
  degrade those checks — and the skip is recorded honestly in receipts and
  install-known reasons (`socket_skipped_tier3`/`socket_disabled`, never
  `socket_ok`). `never` disables Socket outright.
- `install.guarddog.sandbox` (`auto` default, `required`, `off`): GuardDog
  extracts archives inside a kernel sandbox and refuses to scan when that
  sandbox is unavailable — on hosts where its sandboxed child cannot start
  that meant zero behavioral coverage, which silently kept Socket
  load-bearing. `auto` retries once with `--no-sandbox` (never over a
  shape-valid result, and within the same wall-clock budget), discloses the
  weaker isolation on every surface — human output, receipt
  `guarddog.sandbox.fell_back`, `safe report-fp`, and a distinct
  `guarddog_clean_for_versions_nosandbox` install-known reason — and binds
  the result to a separate cache profile so it can never replay as a
  sandboxed result. `required` keeps the hard failure; `off` never
  sandboxes.
- Release-age cooldown (`install.cooldown_days`, default 3): a resolved
  version published fewer than N days ago WARNs (`release_too_new`,
  overridable via exact host-allow pin or `auto_allow_tolerate`) — the
  compromised-release window. A failed publish-date lookup skips the check
  with a disclosed note, never a refusal; `0` disables.

## 1.7.0 - 2026-08-03

- `safe audit check` adds GuardDog as the npm/PyPI behavioral tier. Exact
  resolved versions are scanned with GuardDog's correlated risk model:
  formed `low`/`suspicious` risks WARN with named rules, while `high_risk`
  source behavior BLOCKs; raw capability matches that form no risk remain GO.
  Complete results are cached permanently per public-registry artifact
  integrity and GuardDog version; missing integrity scans without caching. A
  missing binary is an explicit non-adverse skip while Socket remains
  always-on, but a present scanner that fails or times out is reported as
  infrastructure breakage. Receipts, install-known reasons, configuration,
  refusal hints, and `safe doctor` expose the tier. Safe currently accepts
  GuardDog 3.1.0, scrubs its behavior-changing ambient variables into a
  cache-bound safe profile, force-terminates overrunning scans, and bounds each
  scanner output stream at 16 MiB.

## 1.6.0 - 2026-08-03

- `safe audit check`: OSV `MAL-*` records (OpenSSF malicious-packages) are
  now blocklist-class. They usually carry no CVSS, so the severity ladder
  ranked them `unknown` — an overridable WARN. A MAL record affecting the
  resolved version now BLOCKs unconditionally: `install.block_severities`
  cannot downgrade it, host-allow never overrides it, and the refusal names
  the malware record instead of suggesting an allowlist pin. On the
  degraded unresolved-version path, a MAL record anywhere in the package's
  history BLOCKs (same fail-closed rule as historical criticals). First
  slice of the tiered-scoring direction (make Socket optional, not
  load-bearing).

## 1.5.1 - 2026-08-03

- Socket scores for non-npm ecosystems reach the API again: the socket CLI
  takes a purl type, and safe passed its own ecosystem names, so `python`,
  `rust`, `go`, and `php` produced `pkg:python/...` etc. — a 400 Bad Request
  that degraded every non-npm score to an infra-WARN. They now map to
  `pypi`/`cargo`/`golang`/`composer` (npm was already correct).

## 1.5.0 - 2026-08-03

- `safe run scripts-allow`: operator-reviewed lifecycle-script grants for
  exact npm identities. `add` (TTY-only) displays the package's install
  scripts before confirmation and snapshots them with the registry
  integrity hash; on a gated `npm install -g` of a granted identity the
  gate injects npm 12's per-command policy (`ignore-scripts=false`,
  `allow-scripts=<granted identities>`, `strict-allow-scripts=true`) so
  exactly the reviewed scripts run and unreviewed script-bearing
  dependencies fail the install — the global `ignore-scripts` default
  never changes. npm < 12 gets a legible manual fallback. `safe audit
  check --gate install` now hints when a resolved version declares
  install scripts without a grant, and records `has_install_script` in
  the check receipt. Closes the manager-neutral lifecycle-scripts gap
  (originally observed via Volta).

## 1.4.0 - 2026-08-03

- `safe run host-allow review`: read-only staleness report for host-allow
  entries — age, observed usage (executions + install-gate overrides), and a
  re-audit of each pinned version (`removable` / `keep` / `review-urgent` /
  `unknown`; audit-infrastructure failure is always `unknown`, never
  staleness evidence). `--json` for machines, `--digest` writes a dated
  inbox note into the safe repo when it finds removable or review-urgent
  entries, `--no-audit` skips the probes. `install.sh --review-timer`
  installs an opt-in weekly systemd user timer running `review --digest`.
  Removal stays operator-only (TTY-gated).

## 1.3.0 - 2026-08-03

- CVSS v4.0 vectors now use a self-contained port of the pinned FIRST
  calculator, so v4-only critical advisories reach BLOCK while malformed
  vectors retain the fail-closed high floor.

## 1.2.1 - 2026-08-02

- The mise gate wrapper is argv0-aware: mise shims are symlinks to whatever
  `mise` resolves to on PATH, and a `mise reshim` run while the wrapper
  shadowed the real binary bound all 36 shims to the wrapper, which dropped
  argv[0] — every shimmed tool (node, npm, acpx, …) executed mise bare.
  A shim dispatch (argv[0] ≠ mise) now reaches the real mise with argv[0]
  intact and never enters the gate; `safe doctor` reports shims still bound
  to the wrapper (functional but one exec slower) for repair.

- npm override resolution: a single top-level exact-version `overrides` entry
  with no conflicting direct dependency now resolves (`override-pin`, no
  fetch) instead of degrading to the package-level WARN; override ranges,
  nested/qualified overrides, and requested-range-beside-override still
  degrade fail-closed.
- Sandboxed installs (`safe run install`) announce up front when the strict
  sandbox has networking disabled, and trailer a failed install with the
  DNS/network cause and the `-n/--network` recovery — a registry `EAI_AGAIN`
  no longer reads as a broken install with no hint.

## 1.2.0 - 2026-08-02

- Scanners and helper CLIs (osv-scanner, socket, jq, …) resolve through the
  machine tool cache (`audit/tools.json`) with caller PATH taking precedence,
  so a caller whose PATH lacks the mise shim directory no longer sees a
  missing-scanner WARN that reads like a supply-chain signal. `uv` joins the
  gated tools: `install.sh` displaces the real binary to `uv.original` and
  installs a gate wrapper, with rollback if any wrapper write fails, and a
  hard error naming every tool left ungated.
- The agent contract became a single machine-readable source
  (`docs/contract/agent-contract.json`): `safe explain --json` emits it
  verbatim, `safe explain` and the docs render from it, and a drift suite
  fails when they diverge. New `safe report-fp <spec>` files a suspected
  false positive as an evidence note in safe's inbox — it re-runs the check,
  records the receipt, and can never quiet the gate or touch trust state.
- The effective-source derivation behind the trust floor now models Cargo,
  Composer, and Bun selectors, keyed by the installer that actually reads
  them: cargo registry names resolve through `CARGO_REGISTRIES_<NAME>_INDEX`
  or become the trustable opaque identity `cargo-registry:<name>`; composer
  repositories in `$COMPOSER_HOME/config.json` are read directly (every
  dist/source endpoint, packagist-disable shapes included); bun installs
  judge bun's own registry chain (`BUN_CONFIG_REGISTRY`, npm env forms,
  its two npmrc files) via `--installer bun`, and resolution fetches the
  packument from bun's registry. mise-only selectors (`cargo.registry_name`,
  `pipx.registry_url`) translate into the same argv plumbing, so those
  backend installs get real verdicts instead of the not-audit-gated notice
  (only `CARGO_HOME` keeps it — an unread config.toml). Per-invocation
  config injection fails closed: `cargo install --config` and bun
  `--config=<file>` on gated subcommands are refused. Cargo argv-name
  identities changed shape (`explicit:<name>` →
  `explicit:cargo-registry:<name>`): old install-known entries for named
  cargo registries stop matching and re-audit fresh; `trusted_registries`
  entries for cargo names need the `cargo-registry:` prefix.
- The socket score call is wall-clock bounded everywhere
  (`SAFE_AUDIT_SOCKET_TIMEOUT`, default 30s), including the vault-injected
  retry; with no `timeout` binary the call is not started at all and the
  WARN names the lost coverage. A wedged socket CLI used to hang a direct
  `safe audit check` for minutes with zero output.
- The contract documents the preflight surface: exit codes 0/10/20 are
  `safe audit check` verdict codes (not refusals), a direct WARN/BLOCK
  check prints the same next-step hints the gate prints, refusals are
  defined as the final `safe: BLOCKED` stderr line, advisory+infra hints
  firing together resolve infrastructure-first, and an affecting list
  longer than three IDs says `+N more`.

- `safe install` gains a project mode: with no package named and a manifest in
  the current directory (`package.json`, `requirements.txt`, `pyproject.toml`,
  `Cargo.toml`, `composer.json`, `go.mod`), it bulk-audits what the project
  already depends on instead of printing a usage error. `--project` forces the
  mode. It runs `safe audit scan --deps-only --project .` and prints a
  one-screen summary — audited manifests, package count, findings by severity,
  verdict, and the top critical/high findings with package and advisory id.
  The mode audits only and never runs a package manager. Critical findings
  refuse with exit 104 even under `--yes` (`--yes` accepts WARNs only); a WARN
  verdict prompts interactively and refuses with 102 in a non-interactive
  shell; a clean verdict exits 0 quietly there. A scan that fails or leaves no
  readable result document fails closed with exit 100 rather than reporting a
  clean project. Decisions are recorded in the safe-run audit log as
  `install:project`.

- Lockfile-keyed scan cache for `--deps-only` scans: when the dependency
  evidence hashes to a set already scanned within 24 hours, the recorded result
  is replayed (`[safe audit] scan cache hit (<age>)`) with the same verdict and
  exit code instead of re-running osv-scanner, syft, and grype — a repeat scan
  of an unchanged tree drops from tens of seconds to well under one. Entries
  live in `~/.local/share/safe/audit/scan-cache/`, keyed on machine, target,
  mode, and each evidence file's own hash, so touching any lockfile or manifest
  forces a real scan. `safe audit scan --no-cache` bypasses the lookup and
  `SAFE_AUDIT_SCAN_CACHE_TTL_SECONDS` overrides the TTL. The cache can only
  skip work, never invent a verdict: missing, expired, corrupt, or
  unrecognizable entries fall through to a real scan, evidence-free scans are
  never cached, and source/`--full` scans are excluded entirely (they stage
  arbitrary files the evidence hash does not capture).

- The wrapper project-scan preflight now runs `safe audit scan --deps-only`, so
  a bare `npm ci` / `pnpm install` in an unchanged tree costs a cache hit
  instead of a full scanner run.

- Scan results carry `audit_totals`: the CVE-scan counts plus every ecosystem
  audit that ran (`npm audit`, `composer audit`, `cargo-audit`, `govulncheck`,
  `pip-audit`), with a per-scanner breakdown. Those advisory counts previously
  reached the result document but no verdict — a critical only `npm audit` saw
  left the scan at `GO`. The verdict and `safe install --project` both read the
  aggregate now. The counts are scanner *reports*, not deduplicated advisories
  (only osv and grype carry comparable ids), so anything shown to a human is
  broken down per source rather than summed.

- Ecosystem audits are normalized properly, which wiring them into the verdict
  made load-bearing. Previously every runner emitted `status:"ok"` regardless
  of what happened: a scanner that could not reach its advisory database was
  reported as a successful zero-finding scan — indistinguishable from a clean
  project. Now each runner keeps the exit status and validates the output
  shape, and unreadable output is `status:"error"` (which also makes the scan
  verdict `WARN` and blocks caching). Counts moved from containers to
  advisories: `pip-audit` lists one entry per *dependency* with its advisories
  under `vulns`, so a clean Python project used to score one `medium` per
  installed package; `composer audit` keys advisories by package, so its
  findings were invisible; `cargo audit` severities now come from the CVSS
  vector RustSec actually ships; `govulncheck` findings are deduplicated by
  OSV id. A severity that cannot be determined counts as `unknown` — it warns,
  it does not invent a band. An unrecognized scanner name is a configuration
  error rather than a silent skip. The remote scan helper carries the same
  normalizers, and a test compares the two copies verbatim.

- Scan cache hardening. An entry stores its schema, key, machine, target and
  mode, and every field is validated against the current request before replay,
  so an entry belonging to another project — or written by a safe that scored
  verdicts differently — misses instead of answering. Validation happens in a
  single jq predicate: a malformed timestamp used to be read into bash
  arithmetic, where `08` is a fatal error, which aborted the scan (exit 1) and
  read to a PATH wrapper as a scan failure it was willing to proceed past.
  Evidence is re-hashed after the scanners finish, so a result whose lockfiles
  changed mid-scan is not filed under the key those lockfiles produced. Results
  including a `govulncheck` run are never cached at all: it reads Go source,
  which no evidence hash covers. Nor is anything cached when an ecosystem or
  core scanner did not return `ok` (missing coverage is not a cacheable
  answer), or when a project holds known evidence that discovery did not hash
  — a symlinked lockfile, for instance, which `npm audit` reads and the file
  walk skips: those are hashed directly now, alongside the project-root
  `.npmrc` (which selects the registry `npm audit` queries) and `.safe-audit`
  (which decides what is audited at all). `npm-shrinkwrap.json` is recognized
  as evidence. Evidence paths enter the key relative to the scan root rather
  than by absolute path, so a staged target derives a stable key. A malformed
  TTL disables the cache rather than silently defaulting. Known residuals: the
  cache is a local-target feature (a staged remote scan cannot select the core
  scanners and is never stored), user-level npm/pip configuration outside the
  project root is not keyed, and the advisory-database window is bounded only
  by the TTL.

- The PATH-wrapper project preflight decides from the scan's result document
  instead of its exit code. A scan that finds a critical advisory exits 0 (the
  verdict lives in the document), so the preflight treated every finding as a
  clean scan and ran the package manager. It now refuses on a critical count
  (interactive confirm, exit 102 non-interactive) and names a scanner that ran
  and failed while still proceeding, per the documented policy that only
  critical findings stop an install.

- `safe audit scan --allow-missing-tools` turns an uninstalled ecosystem
  auditor from an abort into a reported gap, and both gating callers pass it.
  Without it a Rust or Go project on a machine without cargo-audit or
  govulncheck could not be audited from any non-interactive shell at all: the
  scan refused to run, and `safe install --project` reported it as a broken
  scan rather than the documented "not run" WARN.

- `npm audit` needs an npm lockfile, so a pnpm, Yarn or not-yet-locked project
  is reported as coverage it structurally cannot provide rather than as a
  broken scanner — and that state leaves the verdict alone, so a pnpm project
  is not pushed behind an operator prompt for an answer npm was never going to
  give. Absent tools still warn; failed ones still warn and block caching.

- `pip-audit` audits every declared target instead of the first one found: a
  vulnerable dependency present only in `requirements-dev.txt` was never
  submitted. A `pyproject.toml` project is audited by path — a bare
  `pip-audit -f json` audits the active Python environment, not the project.
  Advisories are merged across targets and deduplicated by package and id.

- `govulncheck` output is rejected whole if any non-blank line fails to parse
  or the stream is not govulncheck's: tolerating an unparsable tail turned a
  process that died halfway into a confident "zero findings".

- The scan cache keys the **scanner set** as well as the evidence: each tool's
  presence, path, size and mtime. Removing `pip-audit` (or installing it) now
  misses instead of replaying a verdict produced by a different set of tools —
  neither event touches an evidence file. Evidence is also re-enumerated after
  the scan, not just re-hashed, so a `.safe-audit` created mid-scan (switching
  an ecosystem off) cannot be stored under the key of the project that did not
  have it.

- Ecosystem coverage has explicit machine-readable states. `unsupported` is a
  scanner that structurally cannot read this evidence — `npm audit` facing a
  pnpm or Yarn lockfile — which osv-scanner covers anyway, so it neither warns
  nor defeats the cache. `partial` keeps the advisories a run did find when
  another target failed: a critical in `requirements.txt` no longer disappears
  because `requirements-dev.txt` broke. A `package.json` with **no lockfile at
  all** now WARNs instead of reporting `GO`: neither osv-scanner nor npm audit
  can read it, so a clean verdict would mean "we looked at nothing".

- `govulncheck` must exit 0. In `-json` mode findings are reported in the
  stream, so a nonzero exit means the run failed — and the complete-looking
  prefix it had already written used to be normalized to zero findings.

- The wrapper preflight never proceeds on silence. If it cannot allocate a
  private result destination it falls back to safe's own state directory, and
  if that fails too it says the project was NOT audit-gated instead of reading
  a scan's exit 0 as "clean". A failed scan is described as a failed scan:
  the old heuristic labelled any scan exiting >= 2 "critical findings", which
  is exactly the infrastructure-as-vulnerability conflation the refusal
  contract forbids.

- `--result-out` and `--allow-missing-tools` are completable, and the
  completion test now derives its expectation from `--help` instead of pinning
  a literal list that passed *because* new flags were missing.

- `safe audit scan --result-out <file>` hands the caller its own copy of the
  result document, and scans now assemble that document privately before
  publishing it. The per-machine result path is one file per day: a concurrent
  scan of another project could replace it between the scan and the read, so
  `safe install --project` grades its own copy instead of parsing a path out of
  the rendered summary.

- `safe install --project` no longer swallows an install request. Combining it
  with package arguments or with `-g`/`--host`/`--manager`/`--trust-host` is a
  usage error instead of an audit-only exit 0 that installs nothing;
  auto-detection applies only to a bare `safe install`. A scanner that ran and
  failed now refuses with exit 100 naming the scanner and a recovery path
  (`--yes` could previously accept it as an ordinary WARN), an unknown verdict
  string refuses instead of being treated as acceptable, and a missing
  `safe audit` refuses with the `BLOCKED` contract rather than a bare exit 1.
  Scanner diagnostics go to a log file named in the refusal, keeping refusals
  to the contractual single stderr line — as does the audit-log write, whose
  own failure could previously add a second line. The refusal names the actual
  failure (nonzero exit, absent result, unreadable verdict) rather than always
  claiming no result was produced, and a critical refusal attributes the
  advisories to the scanners that reported them.

- Gate `mise` backend installs: `mise install`/`up`/`use`/`exec` previously
  installed registry packages (`npm:*`, `pipx:*`, `cargo:*`, `go:*` backends,
  lifecycle scripts included) with no audit at all. A `mise` PATH wrapper now
  routes through `safe gate`: explicit backend specs are audited like any
  install; bare `mise install`/`up` preflights the configured tools (via
  `mise ls --current --json`) and audits not-yet-installed entries — plus
  floating-version entries on `up` (a pinned installed entry cannot change
  without a config edit, so a fully pinned manifest audits nothing); a gated
  command behind `mise exec --` gets the full routing/audit pass with the
  exec left to mise (which owns the tool env). Official runtime installs
  (`node@22`) pass through untouched; non-registry backends (aqua/ubi/gem)
  pass with an explicit not-audit-gated notice. Review round: bare
  shorthands (`mise install prettier`) resolve through `mise registry` to
  their effective backend before the runtime-vs-package call (registry
  shorthands were installing npm packages unaudited); the audited identity
  is canonicalized (tool `[options]` stripped; `pipx:owner/repo` GitHub
  shorthands and `git+`/URL forms take the notice path instead of a false
  registry audit); enumeration and env-derivation failures refuse as
  infrastructure breakage instead of falling open; install/up/use/exec get
  exact flag tables (a value flag's value no longer reads as a tool spec,
  `-C`/`-E` thread into the preflight, `--monorepo`-class scope flags
  refuse, unknown equals-forms fail closed, `--locked` and friends are
  legal); non-exact pins ("3", ranges) count as floating on `up` and
  `up --bump` audits everything; `mise exec` preflights configured tools
  unless `exec_auto_install` is verifiably off; audits run under mise's
  project `[env]` package-source variables; `mise exec -c` and bare
  interactive `mise use` fail closed with rewrite hints (launcher first
  words behind `exec --` stay a documented residual). Second review round:
  every helper query (`registry`/`ls`/`env`/`settings`) runs under the
  delegate's full context, including `--no-config`/`--no-env`/`--no-hooks`,
  and the audit runs from the `-C` directory so directory-scoped config
  files count as source; tool options are allowlisted rather than
  discarded (`npm_args`-class options take the notice path instead of
  vouching for a redirected install); env values travel base64-framed with
  strict typing (a newline in one value could otherwise export a second
  variable, and a non-string source value now refuses instead of auditing
  the default); `mise ls` entries require their fields (a missing
  `installed` no longer reports a package verdict for unreadable output)
  and jq diagnostics stay internal; `install --force` audits every
  configured tool, `upgrade --exclude` drops excluded targets,
  `--minimum-release-age` refuses non-exact targets; `--help`/`--version`/
  `--dry-run` pass through; counted verbosity (`-vvv`) is legal again;
  Cargo/pipx/composer registry variables joined the source allowlist.
  Third review round: `package_manager` is no longer treated as
  identity-neutral (it selects an installer with different registry
  inputs), and the bare preflight reads each configured entry's options
  via `mise tool --json` since `mise ls` hides them; a mise-selected
  Cargo/pipx/Composer/Bun registry takes the not-audit-gated notice path
  instead of a verdict computed against the default public source (safe's
  effective-source derivation covers npm/Python/Go only — extending it is
  tracked separately); env values round-trip byte-exactly (a trailing
  newline was being stripped by command substitution) and a value that
  cannot survive intact refuses; `requested_version` is required rather
  than defaulted; exclusion matching is backend-aware so an npm scope is
  not mistaken for a version; `use` honors `--minimum-release-age` like
  install/upgrade; `upgrade --interactive` declines with an
  explicit-target hint (same class as bare `mise use`); a leading global
  `--help`/`--version` passes through; and an unusable `-C` directory
  refuses with a real one-line message instead of a silent exit.

- Second review round (PR#29 delta findings): custom package sources
  (`--registry`, `--index-url`, `--find-links`, `--no-index`, composer
  `--repository`) now floor the verdict at WARN for every ecosystem — exact
  versions included — because public advisory data cannot vouch for a
  private artifact of the same name@version; the operator lifts the floor
  per source via `install.trusted_registries` (or per version via a pinned
  host-allow). `safe install` and the uv wrapper thread the same selectors.
  OSV pagination rejects non-string/repeated tokens (a malformed
  completeness token no longer reads as zero advisories). SemVer prerelease
  identifiers compare per spec (identifier-by-identifier, numeric before
  alphanumeric) instead of lexically, and version-qualified `overrides` keys
  (`"pkg@^2.0.0"`) degrade resolution like bare ones. An adverse advisory
  result revokes recorded clean install-known evidence even when a pinned
  host-allow permits the current invocation, and the stale readers use the
  canonical ecosystem key (cargo/composer entries are findable again).

- Install gating now works in **every shell**, not just interactive zsh. The
  zsh wrapper functions are retired and replaced by executable PATH wrappers
  (`~/.local/bin/{npm,pnpm,pnpx,yarn,bun,pip,pip3,uv,cargo,go,composer}`), each
  a three-line shim that execs the new `safe gate <tool> -- <args...>`
  subcommand. Previously `bash -c 'npm i evil'`, a Makefile recipe, a CI step,
  or an agent harness bypassed the gate entirely by hitting the version-manager
  shim directly. All routing lives in `lib/gate-lib.sh` (installed at
  `~/.config/safe/gate-lib.sh`), a faithful bash port of the reviewed zsh
  routing tables, so gate upgrades ship with `safe` and the wrappers are never
  rewritten. The real tool is the first non-wrapper executable of that name on
  PATH, so mise/asdf shims and per-project tool versions keep working.
  `install.sh` refuses to overwrite an unmarked file of a wrapped name (it
  reports and skips); `uninstall.sh` removes only marked wrappers.
  `safe status` and `safe doctor --json` now probe every wrapper in the set
  (`installed` / `shadowed` / `not-on-path` / `missing` / `foreign`) instead of
  shell function state, and report the set healthy only when every tool
  resolves to its own wrapper — `not-on-path` covers the cron/service shape
  where the wrapper files exist but `$SAFE_BIN_DIR` is not on PATH, so nothing
  is actually gated.
  `lib/install-wrappers.zsh` remains, as a stub that defines no wrappers and
  warns once in an interactive shell when gating is absent.
  Two consequences of the process model: the "safe audit not installed" warning
  is now once per command rather than once per shell, and the degraded-mode
  guards are gone — an executable wrapper cannot be half-loaded. The Volta
  wrapper is retired (no `volta` wrapper is installed). The version/help
  switches (`--version`, `-v`/`-V`, `--help`, `-h`) are now classified as the
  valueless switches they are, so `npm --version` and friends pass through
  instead of failing closed. Volta's dead shim-backup resolution is deleted
  from `bin/safe-run`; `safe run link` clears stale Volta runner paths and
  host-allow exec resolves the real runner through `mise which` at exec time.

- Orthogonal-review hardening of the version-aware gate (PR#29 findings):
  version-scoped OSV results are server-authoritative — the local range
  comparator annotates but can never downgrade a hit to GO; OSV pagination is
  followed (a token-only page no longer reads as zero advisories, anomalies
  fail closed); target-altering selectors are threaded into the audit
  (`--tag` → dist-tag resolution, `--registry` → packument source,
  `--prefix`/`--working-dir` → project dir; custom pip/uv/cargo/composer
  indexes degrade to the unresolved refusal instead of auditing the default
  registry); the npm resolver follows npm-pick-manifest's latest-tag
  preference, no longer globs range tokens against cwd files, and degrades
  when root `overrides` mention the package; a WARN/BLOCK check revokes any
  stale install-known entry for that version and the timeout fallback only
  accepts verdict-GO evidence; severity now normalizes from qualitative
  labels AND standard CVSS v3 vectors (computed base score, most severe
  wins; v4-only floors at high); `cargo`/`composer` ecosystem labels map to
  their resolvers and OSV names, and `cargo install --version X` audits the
  pinned crate.

- Version-aware install verdicts: `safe audit check` now resolves the version
  the package manager would actually install (exact spec as-is; npm dist-tag
  for installs; the **in-range** target from `package.json`/lockfile ranges
  for `--op update`; registry latest for pip/uv, cargo, composer, go) and
  matches OSV advisories against that exact version's affected ranges.
  Previously the query sent `version:"latest"`, OSV returned every advisory
  ever filed, and the verdict was a version-blind count — which WARN-blocked
  the very bumps that remediate a CVE (inbox 2026-07-31, third occurrence).
  Advisories are classified `affecting`/`remediated`/`unfixed`/`ambiguous`;
  only affecting ones drive the verdict, with `install.block_severities`
  (default critical) escalating to BLOCK. Resolution failure degrades to a
  package-level audit with a WARN floor (`version_unresolved`), and an OSV
  outage now fails closed (it used to count as zero CVEs). Exit codes and
  plain `check` semantics are unchanged for consumers.

- New install gate mode (`safe audit check --gate install`), used by the zsh
  wrappers and `safe install`: GO proceeds with no operator terminal and
  records the pinned resolved version in machine-written
  `~/.config/safe/run/install-known.json` (evidence pointing at the check
  receipt; consulted only as an offline fallback when the audit times out,
  within `install.auto_allow_ttl_days`). WARN proceeds only on a pinned
  host-allow entry matching the **resolved** version — fixing the dead end
  where `npm update` audited `pkg@latest` and a pinned allow could never
  match — or via the opt-in `install.auto_allow_tolerate` causes. Refusal
  hints are always pinned (`host-allow add <pkg>@<resolved>`); nothing ever
  suggests `@latest`. Socket scoring failures refuse with an explicit
  infrastructure-failure message and recovery path (`socket login`,
  `safe doctor` now reports the Socket CLI/token wiring), clearly
  distinguished from a package finding. Wrapper and `safe install` gate
  decisions now leave a persistent record in the safe-run audit log
  (`install:<ecosystem> | ... | GATE | ... | PROCEED/REFUSED_*`).

- Add `safe vendor update --preset <vendor>` for claude, gh, op, uv, and
  codex: fills `--name`, `--path` (auto-detected on PATH), and `--version-cmd`
  so a native vendor update needs only `--reason` and the command; explicit
  flags still override. New `docs/vendor.md` collects the recipes, the
  trust calculus, and per-tool auto-update disablement.

- Close a universal bypass in the zsh install wrappers: every wrapper read
  its subcommand as `$1`, so a leading global flag hid the real command
  (`npm --loglevel=error install evil`, `yarn --cwd sub add evil`,
  `pnpm --filter=x dlx cmd`) and slipped the whole gate. A shared resolver
  now finds the first non-flag token, skipping leading global flags:
  `=`-form flags are unambiguous, per-tool value/boolean tables are skipped
  correctly, and any unrecognized space-form flag fails closed with a
  legible exit-100 refusal (escapable as `--flag=value`). Tables are kept
  small and are load-bearing (a MISclassified flag bypasses; a gap only
  over-refuses); `go` accepts no pre-command flags so any leading flag fails
  closed. Degraded-mode guards are unchanged (they match `$1` only, the
  conservative broken-shell fallback).

- Wrapper parity with `safe run`: the `npm exec`/`bun x` bare-name local-bin
  passthrough now walks `node_modules/.bin` from the physical cwd upward
  (npm's own bin resolution), so hoisted monorepo tools pass through instead
  of being audited as remote fetches. Builtin-only walk, immune to shell
  function/PATH shadowing, mirroring `find_local_project_bin` in safe-run.

- Extend the `safe run` local-bin tier to walk parent directories for
  `node_modules/.bin/<name>` (nearest first), matching npm's own bin
  resolution so hoisted monorepo workspaces resolve their installed tools
  instead of falling into the sandbox pipeline (`npx envsub` from a
  workspace subdirectory previously prompted to sandbox and then failed to
  fetch under strict no-network). Guards unchanged: bare unversioned
  unscoped names only, blocklist first; the audit log records the resolved
  bin path.

- Fix a false positive that broke husky-era pre-commit hooks: `npx
  --no-install lint-staged ...` was parsed with the flag as the package name
  and refused as exit 103 "invalid package name". Runner-native flags are now
  handled explicitly: `--no-install`/`--no` run the local
  `./node_modules/.bin` binary or refuse legibly (modern npx ignores the flag
  and fetches anyway; `safe run` restores its never-fetch meaning),
  `-q`/`--quiet`/`--silent` are dropped, npm-exec selector flags
  (`--package`, `-c`, workspace flags) refuse with exit 100, and any other
  unrecognized flag before the package fails closed with a legible exit-100
  refusal instead of a bogus 103.
- Add a local-bin decision tier to `safe run` (npx/bunx): a bare, unversioned
  name backed by `./node_modules/.bin` runs the already-installed local
  binary directly with no fetch, mirroring the install-wrapper rule. The
  blocklist still wins, and versioned or scoped specs stay in the audit
  pipeline.
- Gate exec-style fetch-and-run subcommands in healthy wrappers: `npm
  exec|x`, `pnpm dlx`, `yarn dlx`, `bun x`, `uv run --with|-w`, `uv tool
  run`, and `go run <module>@<version>` now audit the named package via
  `safe audit check` before delegating (GO proceeds, WARN/BLOCK refuse with
  the BLOCKED contract).
- Identify the exec package by `--package`/`--from` value or the first
  positional (npm's greedy parser also honors `--package` after the command,
  so it is audited there too); an unrecognized space-form flag before the
  command fails closed with a legible refusal (rewrite as `--flag=value`).
  `uv --with`/`-w` extras are audited; `--with-requirements <file>` fails
  closed since its packages can't be vetted inline. Per-tool flag tables are
  validated against each tool's `--help` and are load-bearing (a
  misclassified known flag can bypass), so they must track upstream.
- Audit versioned/aliased exec specs (`tool@1.2.3`, `tool@npm:other`) even
  when a same-named `./node_modules/.bin` binary exists; only a bare command
  name backed by a local bin passes through.
- `go run` classifies build flags (value vs switch, per `go help build`) and
  fails closed on an unrecognized flag before the target, so a space-form
  value flag (`-C`, `-mod`, ...) cannot hide a later `module@version` fetch.
- Gate update families like project installs: `npm update|u|up|upgrade|udpate`,
  `npm it|install-test`, `pnpm update|up|upgrade`, `bun update`, `yarn
  up|upgrade|upgrade-interactive`, `yarn global upgrade`.
- Document passthrough-by-design commands that never fetch registry
  packages (`pnpm exec`, `composer exec`, `volta run`, `uv run` without
  `--with`, local `go run`). Degraded-mode guards are conservative but
  parity-aligned: `pnpm exec`/`composer exec`/`volta run` no longer blocked,
  `uv run` blocked only when `--with`/`-w` appears, `go run` only when an
  argument contains `@`.

- Fix silent exit-127 wrapper failures in agent shells: rename
  `_safe_install_*` helpers to `safe_install_*` so harness shell snapshots
  (Claude Code strips single-underscore functions) keep them loaded.
- Add an inlined degraded-mode guard to every public wrapper: when helpers
  are missing, install/exec-ish subcommands refuse with a legible
  `safe: BLOCKED` line (exit 100) and everything else passes through.
- Standardize wrapper refusals to one stderr line — `safe: BLOCKED <cmd> —
  <reason>; to allow: <operator command>; details: safe explain` — with
  policy exit codes 100/102/104 instead of a generic 2.
- Add `safe explain`: prints the agent contract (gates, refusal format,
  exit codes, operator-only allow flows), plus a new Agent Contract docs
  page.
- Make `safe run host-allow add/update` operator-only: non-TTY invocations
  refuse with exit 102 so agents can suggest but never execute trust
  escalations.
- Document policy exit codes in `safe run` help and the command reference.
- Apply the same refusal contract to `safe install` host installs: audit
  WARN/failure exit 100, audit BLOCK exits 104, non-TTY confirmation exits
  102, each with a `safe: BLOCKED` line (previously generic exit 1).
- Format `safe run` invalid-package-name rejections as `BLOCKED` with the
  `safe explain` pointer (still exit 103).
- Extend degraded-mode gated lists with update/exec aliases (`npm
  x|it|install-test|update|up|upgrade`, `pnpm update|up|upgrade`,
  `bun update`, `yarn up|upgrade|upgrade-interactive`).

## 1.1.3 - 2026-06-29

- Make `safe audit scan` default to `source` mode: dependency evidence plus
  first-party source while skipping installed dependency trees and generated
  output.
- Add `safe audit scan --deps-only`, `--full`, and `--verbose` scan controls.
- Make project and default machine scans discover package ecosystems, require
  the matching audit tools, and fail closed instead of reporting missing tools
  as zero CVEs.
- Preserve valid `osv-scanner` JSON results when OSV exits nonzero because it
  found vulnerabilities.
- Fix scan result assembly for non-empty OSV and Grype findings.

## 1.1.2 - 2026-06-09

- Prefer `safe run`, `safe audit`, and `safe install` across docs, help,
  status, version, and wrapper output.
- Route install wrappers through the `safe audit` dispatcher command.
- Make `safe audit help` show audit help instead of erroring.

## 1.1.1 - 2026-06-08

- Preserve symlinked `.zshrc` files when installing, migrating, or uninstalling
  safe shell integration lines.

## 1.1.0 - 2026-06-04

- Add audited `safe install -g` host installs with confirmation before
  delegating to the package manager.
- Add global install translation for npm, pnpm, yarn, bun, and Composer.
- Add exact-version `--trust-host` support and post-install trust prompts for
  npm packages while refusing to trust `latest`, omitted versions, dist-tags,
  or ranges.
- Update help, completions, and docs to prefer `safe run` and `safe audit`
  over legacy hyphenated command names.

## 1.0.1 - 2026-06-02

- Harden `safe audit setup` so it no longer downloads scanner binaries, runs
  upstream installer scripts, or runs language package installers.
- Make scanner setup fail closed unless required scanners already exist or an
  explicit local scanner bundle is provided.
- Treat Socket CLI as optional for scanner setup.

## 1.0.0 - 2026-06-02

- Initial public release baseline.
