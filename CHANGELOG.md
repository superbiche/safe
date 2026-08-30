# Changelog

## Unreleased

- **release-review `tuf`: the bootstrap mirror is served through a containment
  cage** (1.51.0). The `tuf` check serves the operator-supplied mirror to cosign
  over a loopback HTTP bridge, and that bridge used `http.Dir`, which follows
  symlinks — the same defect class 1.43.0 closed at the hash-read sink, at a
  second sink. A mirror entry symlinked out of the tree could hand cosign
  out-of-mirror bytes during `cosign initialize`, content cosign then caches as
  trusted TUF material, before any of the caged blob reads run. The bridge now
  serves through an `os.Root` rooted at the mirror, which refuses any resolution
  that leaves it — at the requested file or at any directory component of the
  request path. An escaping request fails the fetch (HTTP 500), so cosign fails
  to initialize and the check reports the existing `bootstrap_failure` BLOCK:
  fail-closed, and distinguishable from a merely absent blob (404). Semantics
  match the 1.43.0 cage: containment, not link-refusal — an in-tree symlink is
  still followed and served, and a mirror root that is itself a symlink still
  resolves, since that path is the operator's declaration rather than
  mirror-supplied content. Defense-in-depth on an operator-supplied mirror; no
  legitimate mirror changes verdict.
- **Trust stores are anchored to the canonical config root; an
  environment-redirected store can no longer grant escalation** (1.50.0).
  `SAFE_RUN_CONFIG_DIR` / `SAFE_CONFIG_DIR` relocate the config root — a
  documented convenience, but also the one lever a gated agent (allowed to
  invoke runners only *through* safe) could pull to point safe at a store it
  controls and thereby escape the sandbox. safe now honors a **trust
  escalation** (host-allow host execution, `scripts-allow` lifecycle scripts)
  and a **trust write** (`host-allow add`/`update`/`import`, `scripts-allow
  add`) only from the canonical `~/.config/safe/run` store. A redirected root
  **fails safe on reads** (the grant is declined; the package still runs
  sandboxed) and **hard-refuses writes with exit 100**. The anchor spans every
  trust-authority surface — `safe run` (`bin/safe-run`) and the whole install
  gate (`bin/safe-audit`, which every `npm`/`pnpm`/`yarn`/`bun`/`pip` lane
  calls, plus its `bin/safe` and `lib/gate-lib.sh` callers) — so a forged
  host-allow cannot authorize a host install, and the canonical blocklist is
  unioned in on the install path too, so a redirect can never *hide* a malice
  signal. Trust reads and writes go to the literal canonical path, immune to a
  symlink flip on the config root between check and use. An
  operator who genuinely relocates config sets `SAFE_RUN_TRUST_OVERRIDE=1` to
  bless the redirected store; that override is deliberately loud and logged (a
  bright tripwire on the surface operators watch). This is a bash-level
  hardening, not a hard boundary — `HOME` redirection remains a floor, and the
  non-forgeable operator check plus a root-owned store are tracked for the Go
  migration.

- **`safe run` regains a real host-side unknown-package audit preflight**
  (1.49.0). PR #82 removed a sandboxed preflight that fetched an unpinned
  `safe-audit` npm name inside Podman and never once produced a verdict on a
  real machine (404, "inconclusive", continue). This restores a *working*
  preflight that reuses the **installed** `safe-audit` on the host — no
  container, no npm fetch — the same probe shape as `host_allow_review_probe`
  (`SAFE_AUDIT_NO_INIT`, closed stdin, timeout leash via
  `SAFE_RUN_PREFLIGHT_TIMEOUT`, default 90s). Before an **unknown** package is
  sandboxed, safe re-audits it: a **BLOCK** verdict (Socket BLOCK or a critical
  advisory on the resolved version) now refuses with **exit 104** before the
  package runs — it can refuse installs that succeed today. A **WARN** with a
  real package finding warns and continues into the sandbox; audit-infrastructure
  breakage (Socket/OSV unavailable/auth/rate-limit) and any inconclusive or
  unparseable result degrade honestly (warn + continue, never a CVE signal).
  The non-TTY unknown path still refuses early with exit 102 and runs **no**
  audit — the hottest refusal lane in agent shells adds no latency or quota
  burn. A new **`--force`** flag (operator TTY, logged) overrides a preflight
  BLOCK into the **sandbox only** — never host exec — and overrides nothing
  else: the blocklist, host-allow pin mismatch, and every other refusal stay
  fail-closed. The trust-escalation grants (`host-allow add`/`update`,
  `scripts-allow add`) also regain a grant-time preflight: a WARN/BLOCK
  requires an explicit interactive confirmation, while `--reason` stays
  unconditionally required regardless of verdict (a clean GO does **not** skip
  it). The shared exec core (`_safe_audit_run_json`) backs both the run-lane
  and review probes so their incantation cannot drift. This is a genuine gate
  activation, not a cleanup: the old preflight never fired live, so the gate
  now audits uniformly on every machine (host-side needs no podman). A forced
  BLOCK runs once in the sandbox but is NEVER persisted as sandbox-known (so a
  later non-TTY run cannot silently re-run the blocked package unaudited); the
  preflight binds to the `safe-audit` installed beside `safe run` (dispatcher
  pins the same sibling), so a PATH-shadowed `safe-audit` cannot author a
  verdict; the probe passes `--installer` so a bunx preflight models bun's
  resolution, not npm's; and a grant-time rc-0 result without a corroborating
  GO warns as inconclusive rather than passing silently. Fibery #86.

- **mise `-C`/`--cd` lane enters the target with physical `cd`** (1.48.0). The
  mise routing surface entered the caller's `-C`/`--cd` directory with a bare
  `cd` at both the audit lane (`safe_gate_mise_check_with_env`) and the
  inner-exec scan lane, which processes `..` lexically: a `-C` value reaching
  through a symlinked `..` collapsed to a different directory than mise's own
  `chdir()` (Rust `set_current_dir` → `chdir(2)`, verified physical against
  real mise 2026.8.7), so safe could audit or scan a clean directory while mise
  installs into the real one. Both sites now enter with physical, CDPATH-free
  `CDPATH= cd -P --` (`2>/dev/null`, so an unenterable target keeps its single
  refusal line), matching mise's `chdir()` exactly as the composer helpers
  already do (1.25.0/1.44.0). The `CDPATH=` closes the same divergence for a
  RELATIVE `-C` value: Bash's `cd` searches an exported `CDPATH` (and echoes
  the hit to stdout) while mise's `chdir(2)` never does, so `mise -C project`
  could otherwise send safe to a same-named directory elsewhere. Same defect
  class as the #94/#95 composer fixes; this was
  the third instance — the mise routing surface — parked out of the #95 slice
  and now closed. An ordinary route (whose logical and physical resolution are
  identical) is unaffected; only a route reaching through a symlinked `..`
  changes which directory is audited — now the one mise actually enters.

- **release-review `vuln`: package/ecosystem scoping and compound-range
  parsing** (1.47.0). Two hardening fixes on the advisory check, grounded in
  openai/codex's GHSA-w5fx. (1) The check was package-blind: it matched an
  advisory's version ranges against the subject whatever package the advisory
  named, so an advisory published against a repo's npm wrapper or VS Code
  extension could match the Rust binary beside them. A vuln spec may now declare
  `checks.vuln.packages` — the advisory-package identities that describe the
  subject; an advisory whose entries all name a different package is ruled
  not-applicable and recorded in one aggregated `advisory_out_of_scope` GO note.
  Absent, the check stays package-blind exactly as before; an empty `packages`
  array is the honest "no advisory package here tracks this artifact". Two edges
  fail closed: an entry naming no package is read anyway, and an advisory with no
  entries stays ambiguous. Matching is case-insensitive (the ecosystem is free
  text, e.g. `"vs code"`). (2) `versionMatchesRange` now reads GitHub's
  space-separated two-sided bound `A <= B` as `>= A, <= B` (both inclusive) — the
  spelling of codex's npm range `0.2.0 <= 0.38.0`, previously ambiguous and
  resolved only by its `patched_versions`. Additive only: no range that already
  decided changes meaning. **The release-review `spec_version` rises 2 → 3**: both
  this `packages` field and 1.46.0's `checks.release.allow_unsigned_commit` are
  optional fields a strict-decoding older build refuses as unknown, so the
  advertised spec_version must rise for a consumer to preflight them (1.46.0
  shipped its field without the bump — 3 covers both). safe-core and the
  `safe audit capabilities` payload now advertise `spec_version: 3`; a consumer
  pinned to 2 is told to bump in lockstep rather than silently rejected mid-spec.
- **release-review `release`: read the release history in small early-stopping
  pages, and accept an unsigned commit when the spec allows it** (1.46.0). Two
  live-usage fixes surfaced reviewing openai/codex. (1) The release-history
  listing was read at `per_page=100` and walked to the page cap regardless of
  need. codex publishes over a thousand releases whose bodies run to hundreds of
  KB, so one page was ~27 MB — past the in-memory body cap — and the review
  failed to run (`metadata_unavailable`). It now reads small pages, against a
  page budget of its own (~250 releases, so a smaller page did not shrink how far
  back a review can reach) and stops once the predecessor is resolved and it has
  read past the release's publication day. A recent release resolves from the
  first page. `same_day_churn` stays a best-effort positive detector: GitHub
  orders the listing by the tagged commit's date, so a same-day release built
  from an older commit can sort deep and go unread — a known limitation, carried
  as a known risk, not a completeness proof. (2) A new
  `checks.release.allow_unsigned_commit` accepts a tagged commit GitHub reports as
  `unsigned` as a visible `commit_unsigned_allowed` GO note instead of a
  `commit_unverified` BLOCK — for a subject whose upstream never signs its tags
  and whose sigstore workflow attestation covers the same risk. It narrows to the
  plain `unsigned` reason; any other unverified state (`invalid`, a bad author
  email, an unknown key) still BLOCKs.

- **release-review `vuln`: resolve an unreadable advisory range by its
  `patched_versions`, and compare the subject tag by its version core**
  (1.45.0). An advisory whose `vulnerable_version_range` this check cannot parse
  used to BLOCK every version forever (`version_mapping_ambiguous`) — which is
  what a repository publishing an advisory for an *adjacent* package (its npm
  library, its editor extension) with a nonstandard range did to an unrelated
  binary release. Two changes: (1) the subject version, which is the GitHub tag
  the `release` check looks up, is reduced to its numeric core before advisory
  comparison (`rust-v0.149.1` → `0.149.1`; a tag with no digit stays whole and
  cannot be placed), so comparisons are numeric rather than string-collated; (2)
  when a range is unreadable, the entry's `patched_versions` is consulted as a
  second signal — a single parseable fix version decides (at or above it, not
  affected; below it, affected). Strictly a resolver, not a loosening: a
  readable range stays authoritative and is never overridden; a comma-separated
  patched list does not resolve; a digitless candidate does not resolve; and
  when neither range nor patched version can place the advisory it is still
  `version_mapping_ambiguous` and still fails closed.

- **composer global scan enters selected projects with physical `cd`**
  (1.44.0). The global composer scan lane
  (`safe_gate_composer_scan_targets`) entered each selected project with a
  bare `cd`, which processes `..` lexically: a target reaching through a
  symlinked `..` collapsed to a different directory than Composer's PHP
  `chdir()` resolves, so the audit could scan a clean directory while
  Composer installs into the real one. It now enters with physical `cd -P --`
  (`2>/dev/null`, so an unenterable target keeps its single BLOCKED stderr
  line), matching Composer's `chdir()` exactly as the non-global helpers
  already do (1.25.0). Same defect class as the #94 non-global fix; this was
  the parked global sibling. An ordinary route (whose logical and physical
  resolution are identical) is unaffected; only a route reaching through a
  symlinked `..` changes which directory is audited — now the one Composer
  actually enters.

- **release-review `tuf`: physical containment of mirror reads against
  symlinked entries** (1.43.0). The `tuf` check already refused a `..`-bearing
  or absolute TUF target name and a non-hex trusted-metadata digest, but those
  rules are lexical and `os.Stat`/`os.Open` follow symlinks — so a mirror entry
  that was itself a symlink out of the targets tree could still steer the
  hash-read at an out-of-tree file. The mirror blob and the materialized
  candidate are now read through an `os.Root` cage rooted at the targets tree,
  which refuses any resolution — at the blob, at a `targets` directory that is
  itself a symlink out of the mirror, or at any parent component of a path-like
  name — that leaves it. An escaping entry is a new BLOCK,
  `trusted_mirror_target_escapes_tree`; other resolution failures (missing blob,
  symlink loop, non-directory component) keep the existing missing-blob reason;
  an in-tree symlink (mirrors legitimately dedup content-addressed blobs) still
  resolves normally, within the platform's symlink-resolution depth limit.
  Defense-in-depth on an operator-supplied mirror; no legitimate mirror changes
  verdict.
- **Ranged install-gate: a primary-only host-allow pin no longer covers a
  warned sibling** (1.42.0). On a ranged/multi-version operation (e.g. `--op
  update` resolving two majors), the warn-cause list is a single aggregate with
  no per-version attribution. A host-allow entry pinning only the PRIMARY
  version was read as "matches every warned resolved version" and allowed the
  whole range — even when the version that actually produced the Socket WARN
  was a resolved SIBLING, not the pinned one. Socket-derived (and other
  unattributed) WARN classes now require the host-allow to cover the WHOLE
  resolved set; the single-entry schema cannot express a multi-version range,
  so a ranged op is deliberately non-host-allowable and routes to
  `install.auto_allow_tolerate` as its aggregate override. A single-version
  install is unchanged (its resolved set is just the primary). The matching
  refusal no longer dangles a `host-allow add` hint that could never match a
  ranged set — it names the tolerate lane instead. Fail-closed tightening of a
  gate override; surfaced as proposal P1 during the 2026-08-14
  socket_not_found review (pre-existing on main, not introduced there). Adds a
  ranged gate/host-allow regression to `tests/audit/socket_tier.sh`.
- **`safe audit` subprocess scratch is reclaimed, not left in `$TMPDIR`**
  (1.41.0). Several audit-path helpers created working files with a bare
  `mktemp`, which lands the file directly in `$TMPDIR` where the process-exit
  cleanup trap — which only reclaims directories registered through
  `new_scratch_dir` — never sees it, so the scratch survived every exit path
  including a clean rc 0. The grype db-health check (`raw` status capture, its
  stderr sibling, and the health JSON), the scan-result snapshot, and the three
  `safe audit ioc` helpers now route their scratch through the registry, so a
  clean run leaves nothing behind. Observed live by the setup-new-machines
  release-review verification (scratch accumulating per candidate across a
  post-update sweep). Behavior-neutral to every verdict; hygiene only.
- **`release-review` learns detached signature verification** (`spec_version`
  → 2, 1.40.0). The `signature` check now accepts a detached
  `certificate`+`signature` pair (the `<checksums>.pem` + `<checksums>.sig`
  shape a release publishes beside its checksum file) alongside the existing
  Sigstore `bundle`. The pair signs the **checksum file**, not the artifact, so
  a verified detached signature vouches for an artifact through the digest the
  `checksum` check matches against that same file: detached evidence therefore
  requires the artifact to carry `evidence.checksum_file` and the `checksum`
  check to be enabled, enforced at spec validation. This unblocks releases like
  trufflehog that ship detached sigstore material and no bundle. `spec_version`
  rose to 2, so a consumer preflighting the advertised
  `binary-audit.release-review` capability must move in lockstep — a build
  advertising `spec_version` 2 will refuse a `spec_version` 1 spec, and a
  consumer pinned to 1 must bump before installing this release. Report
  `schema_version` is unchanged (1): detached mode adds reason codes
  (`certificate_missing`, `certificate_unreadable`, `signature_missing`,
  `signature_unreadable`, `verification_infrastructure_unavailable`), not report
  shape.
- **A cosign trust-root outage no longer reads as a signature verdict**
  (`release-review` signature check, 1.40.0). Detached verification needs a live
  Sigstore-TUF and Rekor lookup that a bundle bakes in, so a review run while
  those are unreachable would fail cosign with a network error. That is
  audit-infrastructure breakage, not a signer the policy disallows: the cascade
  now classifies cosign's own trust-bootstrap failure phrasing as
  `verification_infrastructure_unavailable` (ERROR) and stops, at every probe,
  rather than emitting a `signature_failure` BLOCK. The same classifier guards
  the bundle path, where a cold trust-root cache with no network is the same
  outage — closing a latent false-malice case there too. The classifier reads
  only cosign's fatal error line and excludes its evidence-load and
  identity-mismatch lines, so neither the non-fatal trusted-root warning nor the
  caller-supplied evidence path or cert SAN that cosign echoes can steer a
  genuine signature failure into it; an unrecognized fatal line falls through to
  BLOCK (fail-closed). Detached mode uses
  cosign's deprecated `--certificate`/`--signature` flags (a known risk, parked
  with the feature; no bundle synthesis, and `--insecure-ignore-tlog` stays
  rejected).

- **Scanner discovery and OSV coverage stop misreporting two benign states as
  breakage** (1.39.0). (1) A `tools.json` scanner cache that is empty (a
  truncated write) or otherwise not a JSON object no longer poisons every audit
  into "all scanners missing": `ensure_tools_file` normalizes it to `{}` before
  any read or write, so a broken cache self-heals on the next run, and
  `tool_cache_set` now validates its jq output before replacing the file —
  previously jq read zero documents from a 0-byte cache, ran no filter, and
  wrote an empty file while exiting 0, clobbering the cache for good.
  `install.sh` guards the same clobber in its legacy-migration merge and
  normalizes an imported empty/truncated `tools.json`. The cache is
  re-derivable (detection re-probes), so overwriting a broken file loses
  nothing. (2) A project whose lockfiles hold zero packages no longer reads as
  `osv-scanner failed` (a degraded WARN indistinguishable from a finding):
  osv-scanner exits nonzero with empty stdout and `No package sources found` on
  stderr for a dependency-free scan, which safe now classifies as a clean empty
  result, in both the machine-audit and repo-audit osv paths. The signal is the
  same positive stderr phrase `osv_probe_format_support` already trusts; a real
  crash prints a different error, so a future osv reword degrades safely to the
  conservative "failed" and never suppresses a real error.
- **`release-review` hardens three input paths against traversal, mis-mounting,
  and byte-order-decided verdicts** (defense-in-depth, no change to a verdict on
  any legitimate input). (1) A TUF trust target name that is absolute or carries
  a `..` segment is refused at spec validation, and a non-hex trusted-metadata
  digest is refused at the check — both are joined into the paths the `tuf` check
  hashes, where `filepath.Join`'s `Clean` would resolve `..` out of the mirror
  tree. (2) An `exec` artifact whose directory path contains a `:` is `ERROR`
  (`artifact_path_unmappable`): podman splits a `-v` spec on `:`, so such a path
  would mis-split the bind mount and the sandbox cannot be built safely. (3)
  `safe-core package-verdict` now refuses an evidence document that names the same
  member twice: `encoding/json` keeps the last occurrence silently, so two
  conflicting values for one fact would resolve by byte order. These are
  divergences 16–17 in the release-review ledger plus a shared
  `internal/strictjson` check; the evidence document is machine-assembled, so (3)
  is belt-and-suspenders.

- **A non-interactive install gate now fails closed when the project audit
  cannot run.** The install preflight (`safe_gate_scan_project`) already refused
  critical findings in a non-TTY shell (exit 102); a scan that failed *outright*
  — most commonly required scanners missing, which returns a non-zero exit — was
  the one no-verdict path that still warned and proceeded. In a non-interactive
  shell there is no operator to weigh that warning, so it now refuses with exit
  100 ("audit-infrastructure breakage, not a package finding; fix the scanner and
  retry"), mirroring the projected-dependency scan guard. Interactive shells are
  unchanged: the operator still sees the warning and proceeds. Scope note: this
  is the missing-scanner / outright-failure path only; the sibling no-verdict
  sites (an unwritable result destination, or a scan that exits 0 with an
  unreadable document) still warn-and-proceed and are parked to the audit lane.

- **`safe run host-allow export` / `import` replicate a reviewed allow set to a
  fresh machine.** The host-allow set is per-machine by design, so bringing up a
  second machine used to mean rediscovering the first's whole WARN-verdict allow
  set one failed install at a time. `export [--json]` dumps the set as a portable
  JSON document (`schema: safe-host-allow-export/1`) — `name@version`, ecosystem,
  the public registry integrity hash, reason, and date; no secrets. `import
  <file> [--dry-run]` applies a reviewed set in one explicit operator-run action:
  it is TTY-gated exactly like `add`/`update` (a real apply refuses non-TTY with
  exit 102 and initializes no state before that gate; `--dry-run` is the
  read-only preview an agent may run). It accepts only exact version pins — never
  a range, dist-tag, or npm source spec (`file:`/`git+…`) — writes an entry only
  when that exact version verifies against the registry (re-fetching integrity
  rather than trusting the file's hash), never overwrites a divergent local pin,
  and preserves each grant's original date. The allow set is deliberately not
  auto-synced between machines — import keeps the human review in the loop.

- **JVM/Maven dependencies are now OSV-covered, without command-gating.** `safe
  audit repo-audit` sweeps `pom.xml` and `gradle.lockfile` through OSV like any
  other lockfile, and `safe audit package-audit --ecosystem Maven <group:artifact>@<version>`
  is a documented single-coordinate preflight (`Maven`, `maven` and `gradle`
  all map to the OSV `Maven` ecosystem). Gradle and Maven are declarative —
  dependencies resolve at build time with no discrete install verb to PATH-wrap
  the way `npm install <pkg>` is — so there is no `mvn`/`gradle` shim and no
  per-ecosystem JVM auditor: coverage without auto-gating is the honest end
  state, not a stepping stone. Socket has no Maven tier, so a JVM audit is
  OSV-only and its behavioral tier degrades to a disclosed `Socket has no Maven
  tier` skip — never a false GO, and never an infrastructure-outage signal. A
  qualified Maven version OSV cannot range-match (`1.0.0.RELEASE`) resolves to a
  WARN with a pin-hint rather than a silent pass.

- **The six `binary-audit` bash sub-lanes are deleted; `release-review` is the
  one binary-audit command.** `safe audit binary-audit release github`,
  `vuln github-release`, the three `verify` lanes (`release-asset`,
  `sigstore-bundle`, `tuf-bootstrap`) and `exec` no longer exist — the Go
  `release-review` composite has done their whole job since 1.32.0, and keeping
  them was dual maintenance. Their capability keys are withdrawn: `safe audit
  capabilities` now advertises only `binary-audit.release-review` under the
  `binary-audit` group (`SAFE_AUDIT_VERSION` → 0.3.0), and `safe doctor` reports
  one `release-review` feature (ready when `cosign` and `podman` are present —
  the composite's only external tools; checksum, TUF mirror, release and vuln are
  pure Go, and the sub-lanes' `timeout` and `python` dependencies are gone). The
  parity corpus that diffed the two lanes retires with them; the verdict-affecting
  divergences it checked are now in-process Go goldens
  (`internal/releasereview/ledger_test.go`), and a systematic differential golden
  froze the bash version comparator before its deletion
  (`version_test.go`). No release verdict changes.

- **`release-review` now pins `GITHUB_TOKEN` to the base URL's origin and puts a
  deadline on its `cosign` subprocesses.** The `release` and `vuln` checks make
  two of their requests to absolute URLs GitHub itself returns — a `Link`
  rel="next" target and an annotated tag object's address — and the bearer token
  is now attached only when such a URL shares the base URL's origin (scheme, host,
  and effective port), so a compromised or proxied response cannot steer the
  credential elsewhere. The pin covers redirects too: the client installs its own
  redirect policy, because Go's default forwards the header to any
  same-host-or-subdomain target by hostname alone — dropping scheme and port. The
  `signature` and `tuf` checks run their `cosign` invocations under the same
  Go-context deadline the `exec` check uses; a cosign that runs past it — or that
  exits while a descendant holds its output pipe open — is `ERROR`
  (`verification_timeout` / `bootstrap_timeout`), never the `BLOCK` a real
  verification or bootstrap failure produces: a tool that never answered is the
  review failing to run, not a finding about the release. Both are deliberate
  divergences from the bash sub-lanes (ledger entries 14 and 15) and carry Go
  regression tests. No verdict on any well-formed release changes.

- **`release-review`'s version comparison now cuts file suffixes with gnulib's
  actual forward-scan `file_prefixlen`.** The earlier port used a backward scan
  that could cut a version string's prefix to empty and cut trailing runs the
  real `filevercmp` leaves whole, so on degenerate-but-parseable shapes it
  decided a `vuln` advisory range opposite to the `sort -V` bash oracle — e.g.
  `1.2.V.` compared as `1.2`, dropping an advisory the oracle matched
  (fail-open). The comparison of every well-formed version is unchanged; the
  captured regression pairs in `version_test.go` pin the corrected edge cases to
  the bash oracle's verdicts.

- **`release-review` is now advertised as `binary-audit.release-review` in
  `safe audit capabilities`.** A capability key is a promise that the surface
  behind it is whole, and with all six checks live it is. The advertisement
  carries the contract as well as the key: a new `versions` object states the
  `spec_version` the composite accepts and the `report_schema_version` it emits,
  so a consumer preflights both instead of discovering them from a refusal.
  Those numbers are what `safe-core release-review --versions` prints, and
  `tests/audit/release_review_forward.sh` fails if the advertisement and the
  engine ever disagree — a capability promising a schema its engine does not
  accept would be worse than no capability at all. The capabilities payload
  gaining a key and an object is a change to that surface, so
  `SAFE_AUDIT_VERSION` moves to `0.2.0`; it versions the capabilities command
  and is independent of `SAFE_VERSION`. The six `binary-audit` sub-lanes stay
  advertised beside the composite: they are still callable, and a key is
  withdrawn when its command is deleted, not when a successor lands.

- **The `exec` sandbox no longer runs the release binary through a shell.** The
  bash lane wrapped it in `sh -c 'exec /artifact/<name> "$@"' sh` to forward its
  arguments, which spliced a spec-supplied file name into shell program text: an
  artifact named `x|touch PWNED` executed the second half of its own name inside
  the container. It was contained — the injected code ran under the same
  `--network=none --read-only --cap-drop=ALL` sandbox as the untrusted binary
  the check runs by design — but the name becomes attacker-chosen the day a
  consumer smokes a binary under the name an archive gave it. Go passes argv as
  argv, so the wrapper bought nothing; podman is now handed the artifact path as
  one argv entry followed by its arguments.

- **A fixture-parity corpus (`tests/corpus/`) runs the same releases through
  both the bash sub-lanes and the composite and diffs their verdicts.** The
  composite is a surface the bash suites cannot exercise through their own CLIs,
  so this is its parity belt, and it stays until those sub-lanes are deleted.
  Both lanes are driven over real HTTP from one local fixture server — bash
  through curl, the composite through `net/http` — because mocking each side
  separately would compare two different fixtures and call the result parity.
  Twelve cases assert the lanes agree; eight assert they differ in exactly the
  way the divergence ledger records, so a ledgered divergence that quietly stops
  happening fails the suite as loudly as one that appears. That covers every
  verdict-affecting ledger entry, including the ones inherited from earlier
  slices — a missing `cosign` or `podman`, and a missing `exec` artifact, were
  claims about how the composite differs from bash that nothing checked until
  now.

- **`release-review` implements `release` and `vuln`, completing all six
  checks.** Both are native Go against the GitHub REST API — no `curl`, no `jq`,
  no subprocess. `release` reads the release's channel, its age, whether it
  carries the asset the spec names, whether other releases were published the
  same day, what changed against its predecessor, and whether GitHub reports the
  tagged commit as signed; every adverse answer is `BLOCK`, because every one of
  them is a fact about the release. `vuln` matches the version against the
  repository's published advisories: high or critical is `BLOCK`, lower is
  `WARN`, and an advisory whose affected range cannot be read is `BLOCK` — a
  mapping that might cover the version fails closed. Version comparison is a
  port of GNU version sort, the semantics `sort -V` gave the bash lanes, so a
  release candidate still sorts above its release exactly as it did there; the
  port's tables were captured by running the bash functions rather than written
  from memory. `checks.release.asset` is required when the check is enabled.
  **Three deliberate divergences from the bash sub-lanes, all ledgered in
  `docs/release-review.md`:** a GitHub that cannot be read is now `ERROR` (exit
  30) rather than `BLOCK` — only a `404` is evidence about the release, and its
  message names the private-repository-without-`GITHUB_TOKEN` case, because
  GitHub answers 404 rather than 403 for a read it will not authorize; paginated
  listings follow the `Link` header instead of silently deciding on the first
  page of 100, with a 10-page bound that is always reported; and an advisory
  naming no readable version range is ambiguous rather than absent, closing a
  fail-open where the bash lane read it as "does not affect this version".
  `GITHUB_TOKEN`, when set, is sent as an `Authorization` header and reaches
  nothing else — no URL, no report, no reason, no error message.

- **`release-review` implements `signature`, `tuf` and `exec`, and can now
  return a top-level `GO`.** Four of the six checks are live; `release` and
  `vuln` remain schema-only and refused if enabled, and the composite stays
  unadvertised in `safe audit capabilities` until they land. `signature`
  verifies each artifact's Sigstore bundle with `cosign verify-blob` against the
  spec's identity policy, and re-probes a failure with wildcard identity and
  issuer so the report distinguishes a bundle that does not verify at all
  (`signature_failure`) from one signed by the wrong identity or the wrong
  issuer — both, when both are wrong. `tuf` bootstraps `cosign initialize`
  against a pinned root over the spec's local mirror and compares each named
  trust target against the trusted metadata. `exec` runs the release binary
  under the same podman sandbox the bash lane used — no network, read-only
  artifact bind, every capability dropped, tmpfs scratch — and reports how it
  behaved, capturing at most 64 KiB of each output stream so a binary that
  floods its output cannot grow the reviewer's memory until it is OOM-killed
  mid-review (the bash lane bounded the same flood on disk instead). **`checksum_only_verification` earns its retirement**: a matched
  digest no longer warns when an enabled `signature` check verified that same
  artifact (matched by position, since a spec may repeat an asset name), so a
  verified release exits 0 for the first time. Signature *metadata* alone still
  does not suppress it — presence of a bundle path is not verification.
  Three severities deliberately diverge from the bash sub-lanes: a missing
  `cosign` or `podman` is `ERROR` (exit 30, audit-infrastructure breakage with
  an install as its recovery) rather than `BLOCK`/`WARN`, and a missing `exec`
  artifact is `BLOCK` rather than `WARN`, because the same observation must not
  be classified two ways inside one composite. Three external dependencies
  disappear in the port: the python HTTP bridge (the mirror is served by a
  loopback listener from Go's own stdlib), the `sha256sum`/`shasum` preflight
  (hashing is native), and coreutils `timeout` (the deadline is a Go context
  with SIGTERM and a 5s kill delay). `docs/release-review.md` carries the new
  reason taxonomy per check and a full divergence ledger.

- **`safe audit binary-audit release-review --spec PATH` reviews a whole
  release from one spec and emits one report.** Judging a release meant running
  the six `binary-audit` sub-commands in sequence and stitching their JSON
  together caller-side, which put the aggregation logic — the part that decides
  what a release is worth — in every consumer rather than in `safe`. The
  composite takes a spec naming the subject, its artifacts, the evidence
  collected for each, and which checks to run; it returns a single report
  (`schema_version` 1) with a per-check breakdown and one top-level verdict.
  Exit codes are 0/10/20 as elsewhere, plus 30 for a review that broke
  (audit-infrastructure breakage, never a release finding) and 3 for a spec
  that cannot be read or validated, which is never a verdict. Advisory checks
  may warn but never decide the run, and their own uncapped verdict still
  appears in the report. The spec is decoded strictly: unknown fields anywhere,
  anything appended after the first JSON document, and a member repeated inside
  one object are all refused, so a stale or ambiguous spec fails immediately
  rather than halfway through a review — or, worse, silently resolving to
  whichever of two contradictory values came last. This build implements the
  `checksum` check only — `signature`, `release`, `vuln`, `tuf`, and `exec` are
  named in the schema and refused if enabled, and the composite is deliberately
  not advertised in `safe audit capabilities` until they land. One consequence
  is deliberate: since nothing here verifies a checksum file, a verified
  artifact still warns with `checksum_only_verification` and this build cannot
  return a top-level `GO`. Signature metadata in the spec does not change that
  — presence of an unverified bundle path is not verification.
  `docs/release-review.md` carries
  the spec, the report schema, the reason taxonomy, and the one deliberate
  divergence from the bash checksum lane (a single-entry checksum file answers
  for an unnamed asset; a multi-entry one reports "no entry" instead of
  mislabeling it as a mismatch).

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
