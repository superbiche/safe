---
name: safe
description: "Safe package-install gate: BLOCKED refusals and exit codes, operator handoff, exact pinned installs, worktree dependency reuse (vendor/, node_modules/), false positives and audits; npm/pnpm/yarn/bun/pip/uv/cargo/go/composer/mise and ungated Gradle/Maven."
---

# safe

`safe explain --json` is the installed contract: gated surfaces, every exit
code, consent and reusable approvals. The sections marked generated below are
rendered from that same contract and installed with this release of safe.

<!-- BEGIN GENERATED: skill-rules -->
This machine routes package execution and installation through `safe`, a supply-chain safety net. If a package-manager command fails with a message starting with `safe:` or `safe run:`, it was refused BY POLICY — the toolchain is not broken.

A refusal is policy, not breakage. Do not work around it: no direct node_modules/.bin calls of packages that failed to install, no alternate installers, no curl|sh. Relay the refusal and its `to allow:` command to the operator verbatim, wait, then retry the original command unchanged.

- Treat any BLOCKED line as policy, not breakage; do not retry blind.
- Relay the refusal line and its `to allow:` command to the operator verbatim. Trust escalations (safe run host-allow add/update/import) only work in the operator's interactive terminal — never attempt them yourself.
- After the operator allows, retry the original command unchanged.
- Exit 127 from a wrapped tool means a genuinely missing command (or a `safe` missing from PATH), never a policy block — the gate always refuses legibly with exit 100. Report a silent 127, don't bypass.
- ALWAYS install exact pinned versions. NEVER execute or hand the operator an install command containing @latest, another moving tag, a version range, or a package without an explicit version. Resolve the intended exact version first; if resolution is unavailable, report that blocker instead of offering an unpinned command. Manifest/lockfile installs must use committed exact resolved versions; this does not require listing transitive dependencies on the command line.
- If the advisories do not affect the resolved version, run `safe report-fp <spec>` instead of arguing with the gate.
- Preflight with `safe audit package-audit <pkg>@<version> --ecosystem <eco>` before proposing an install; its exit codes are verdicts (0/10/20), not refusals. Exit 30 means the audit could not run at all — repair the tooling, never read it as a verdict about the package.
- Agents may request any number of exact pinned packages in one unattended install. Each target keeps its normal audit and refusal paths. Never allocate a PTY, remove agent markers, or answer an operator prompt to obtain an override.
<!-- END GENERATED: skill-rules -->

## Gate refusals

<!-- BEGIN GENERATED: refusal-codes -->
| Code | Meaning | What to do |
| --- | --- | --- |
| 100 | Blocked by policy: an audit WARN with no matching allow entry, blocklist, fail-closed audit, unrecognized/unsupported runner-native flags, or a trust-store change requested against a non-canonical (environment-redirected) config root — the refusal line names which | Relay the refusal line verbatim to the operator. Do not retry, do not reword the command. |
| 101 | Host-allow version pin mismatch | The allowlist pins a different version than the one requested. Report both versions; re-pin is an operator decision. |
| 102 | Interactive operator confirmation required (non-TTY refusal) | Nothing an agent can do in this shell. Ask the operator to run it in their terminal. |
| 103 | Invalid package name rejected | Check the spec for a typo before escalating — this one is usually the caller's error. |
| 104 | Safe audit BLOCK verdict | The audit returned BLOCK. That can be a critical advisory affecting the resolved version, a known-malware or blocklist entry, a Socket critical supply-chain-risk alert, or a critical advisory safe could not tie to a resolved version — the reason is in the receipt. Inspect it, and use `safe report-fp <spec>` only when its resolved-version and advisory evidence are inconsistent with the refusal. The operator's override is a typed confirmation at an interactive terminal; for an advisory-only BLOCK they may record it (`safe run host-allow add <pkg>@<version> --accept-block`). |
| 127 | Genuinely missing command (never a policy refusal) | The command is not installed, or `safe` is missing from PATH. Report it; never treat it as a reason to bypass. |

Refusal shape: `safe: BLOCKED <tool> <action> — <reason>; to allow: <operator command>; details: safe explain`

The refusal is the FINAL stderr line in that shape. It may be preceded by the audit's own report and `safe audit:` hint lines — relay the BLOCKED line (plus any `safe audit:` hints) to the operator; the lines above it are supporting evidence, not the refusal.
<!-- END GENERATED: refusal-codes -->

`safe audit package-audit` has its own verdict codes (0 GO, 10 WARN, 20 BLOCK,
30 no verdict; gate-mode 11-22): `safe explain --json` lists them all.
`safe doctor` diagnoses scanner availability; an advisory hint and an
infrastructure hint together mean the audit is incomplete.

## Handing a refusal to the operator

Relay the final `BLOCKED` line verbatim. When the operator can lift the
refusal at their own terminal (exit 102, a WARN, a release cooldown, a pending
Socket score), also hand them the exact pinned command to run there, with its
working directory and the non-secret environment it needs: at a terminal safe
runs the full audit and offers the override. A printed
`safe run host-allow add` line is a durable trusted-host grant, and on a
signing origin it propagates to followed hosts: present it as that, for when
the operator wants a standing grant, never as the routine way through.

## Exact versions

<!-- BEGIN GENERATED: version-resolution -->
safe audits the version that will actually be installed, never the literal string `latest`. An unversioned spec is resolved through the registry first (dist-tag for installs, the max version satisfying the declared range for updates), and the advisory match is evaluated against that resolved version.

ALWAYS install exact pinned versions. NEVER execute or hand the operator an install command containing @latest, another moving tag, a version range, or a package without an explicit version. Resolve the intended exact version first; if resolution is unavailable, report that blocker instead of offering an unpinned command. Manifest/lockfile installs must use committed exact resolved versions; this does not require listing transitive dependencies on the command line.

When resolution fails (a private registry, a git or workspace spec, a compound range), the verdict floors at WARN with reason `version_unresolved` and is never auto-allowed. Pin an exact version and retry.
<!-- END GENERATED: version-resolution -->

## Allow flows and worktree reuse

<!-- BEGIN GENERATED: allow-flows -->
When a project install is refused in a worktree because its unchanged lockfile carries advisories, do not copy vendor/ or node_modules/ by hand: run `safe install --reuse` there (Composer and npm/Yarn/pnpm/bun projects; a project with both is reused in one run). It verifies the source is the same project in a checkout of the same repository with byte-identical lockfiles (a mismatch refuses 100), and that each installed tree is complete, matches its lockfile and is unchanged since its trust-on-first-use baseline (a gap refuses 102: the operator decides at the terminal), then copies without hardlinks. A refusal before an ecosystem is published leaves it untouched in the worktree and names any tree already reused; if only the receipt cannot be finalized afterwards, the refusal says the tree is installed and how to recover. After a Composer reuse run `composer dump-autoload` (its `next:` line): the copied autoloader still describes the source checkout's own classes. Report its status line verbatim — a reuse runs no audit and is not audit evidence. On a host without `install.reuse.enabled` it refuses 102 unattended: hand the command to the operator. Trust escalations require the operator's interactive terminal. `safe run host-allow add`, `update`, `import` (without `--dry-run`), `export --sign`, and `follow-signer add|remove` refuse in non-TTY shells with exit 102. Add and update verify the exact requested version against its public registry and obtain fresh integrity before the trust-store writer runs; unknown or unreachable versions fail closed. A subkey fingerprint given to `follow-signer add` is refused with the matching primary fingerprint to use instead. Agents may run `safe run host-allow follow [--dry-run] [--from <dir>]`: it applies statements signed by an operator whose full GPG primary fingerprint was pinned at a TTY in follow.signers, so it is not a new agent trust escalation. It verifies signatures with an isolated pinned-key keyring, rejects revoked/expired keys and signatures, re-validates exact pins and registry integrity as import does, adds missing entries and replaces different local pins only when the statement's generation is newer than the generation recorded on the entry, and never removes grants. Agents may also run `safe release follow [--dry-run]`: it installs only an annotated strict-semver descendant tag verified against those pinned primary fingerprints, from an archive of the verified commit, and only with the recorded installer component flags. It never uses the ambient keyring, working tree, or a user prompt; a refusal remains non-zero and includes the manual pull/install or signer bootstrap path. Entries without a recorded generation yield to a signed statement. The newest signed statement wins across origins; a host-set pin yields to any signed statement. Replacements are recorded in the run audit trail and the origin's follow-state.json `replaced` array. Followed entries carry followed_from and followed_generation; a local follow-state.json stores each origin as {accepted, applied:["pkg@version"], replaced:["pkg@old->new"], refused:["pkg@version"]}. Equal generations retry only unapplied identities, preserving operator removals of applied grants; a different signed statement for an already-accepted generation (same exported_at instant, different bytes) is a collision, refused without changing the ledger; a local re-pin survives an equal generation and a newer generation re-aligns it. Generation-less refusals are warned once and remembered per identity for that generation; same-generation retries are quiet INFO skips that remain non-zero and cannot replace a TTY re-pin. Generation-bearing refusals are re-derived against the incoming generation and WARNed on every run; a newer generation clears refused identities. After upgrading, the first follow derives a missing followed_generation when followed_from and the matching applied identity identify a previously followed entry. Fully applied equal generations return 0 with one quiet info line and no import hint; only older generations are replay skips (WARN, counted, non-zero). A stale cross-origin replacement is WARNed, counted, and left retryable until its origin publishes a newer generation. Registry fetches run outside the writer lock with 10-second timeouts; lock waits are bounded to 10 seconds, and ledger/local pins are rechecked during commit. Each identity is marked before its grant and rolled back on a reported write failure; interruption between ledger/store renames may conservatively require operator recovery for that identity. Registry outages do not consume unapplied identities. Dry-run changes neither trust nor ledger/lock state and previews replacements. Key-level statuses for unrelated expired/revoked subkeys do not invalidate GOODSIG; adverse signature statuses still refuse. Skipped files retain the operator's TTY import override; unsigned import conflicts still require an explicit update. --yes never grants trust, and the redirected-store write guard remains active.

```bash
safe run host-allow add <pkg>@<version>                      # trusted host exec (npm)
safe run host-allow add <pkg>@<version> --accept-block       # operator records an override of an advisory-only BLOCK on that exact version (typed name@version; accepts exactly the blocking advisories named; signed exports carry it to followed hosts)
safe run -y <pkg>@<version> -- <args>                        # one-off sandbox run
safe install [-g] <pkg>@<version>                            # audited install
safe install --reuse [--reuse-from <checkout>] [--dry-run]   # agent-permitted where the host enables it: fill a worktree's missing Composer vendor/ and Node node_modules/ (npm, Yarn, pnpm, bun) by copying the installed trees of another checkout of the same repository with identical lockfiles (no audit, no php, no node, no package manager, no network); the status is reused-existing-vendor or reused-existing-node-modules, never an audit result
safe run block list && safe run audit --blocked              # review refusals
safe run host-allow export --sign                            # operator-signed fleet export (TTY); on an origin (its own signed export exists) host-allow add/update/remove republish it automatically unless follow.auto_export is false
safe run host-allow follow-signer add <fingerprint>          # pin a full GPG primary fingerprint (operator TTY)
safe run host-allow follow [--dry-run] [--from <dir>]        # agent-permitted UNION of verified operator-signed grants; a followed exact version then installs unattended (gate exit 16)
safe release follow [--dry-run] [--checkout <dir>]           # agent-permitted install of a verified signed safe release
```
<!-- END GENERATED: allow-flows -->

After a Composer reuse run `composer dump-autoload` (its `next:` line). In a
worktree whose lockfiles are unchanged, prefer `safe install --reuse` to a
package-manager install. A project install gate weighs only the critical
findings of the ecosystem it installs; the project's other ecosystems' are
named on stderr.

## False positives

<!-- BEGIN GENERATED: report-fp -->
```bash
safe report-fp <spec> [--ecosystem <eco>] [--source <agent>]
```

Re-runs the check as JSON, saves the receipt, and writes inbox/YYYY-MM-DD-<source>-fp-<slug>.md in safe's repo with the command it ran, its exit code, the resolved version, every advisory with its fixed bound, and the receipt path. It re-runs the check rather than capturing the original refusal, so quote that refusal to the operator yourself if it matters.

**The note IS the escalation. Nothing auto-applies and no behaviour changes until the operator validates it.**
<!-- END GENERATED: report-fp -->

## JVM dependencies

Gradle and Maven have no command gate. Before adding a coordinate:

```bash
safe audit package-audit <group:artifact>@<version> --ecosystem Maven --json
```

`repo-audit` scans `pom.xml` and `gradle.lockfile`; no refusal protects a
declarative JVM dependency add.

## Remote hosts

safe gates the machine it is installed on. An install run on another host over
SSH is not audited by the local wrapper: it must go through that host's own
safe.
