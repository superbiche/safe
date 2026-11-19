# Safe Lanes — wayfinder map (belt export)

Canonical map: [Safe Lanes](https://superbiche.fibery.io/Superbiche/Tasks/1492)
(Fibery is coordination only: it holds the frontier, the blockers and the
operator's original words. This export means losing the tracker loses that
state and zero decisions. Re-export after each session that closes a ticket.)

## Destination

Every question that stands between today's install-time gate and the lane
model has an answer: which lane a command falls in, what each lane gates on,
what the operator is asked and through which channel, what an agent receives
instead of a question, how validated tooling reaches the hosts, and in which
order the slices are built. Building the slices is outside the map.

## Notes

**The problem.** safe decides everything at install time, in one synchronous
gate, with one answer: pass, or stop and ask. The operator's account of the
result: updating tools means `mise outdated --bump`, then `mise use -g` for
each, then answering safe's questions almost mechanically, which is friction
and a habit that becomes a risk. Updating a repository stops on advisories the
update does not touch, and adding a clean dependency stops on the findings the
repository already had.

**Two jobs are mixed in that gate.**

- Keeping malicious code out (malware, a compromised release, a typosquat, the
  blocklist). This is binary and fail-closed by nature, but rare, and time is
  the main defence: most malicious releases are withdrawn within days.
- Vulnerability hygiene (an advisory against legitimate code). This is a
  property of a project's state, not of one command. It should be judged as a
  difference (did this command make things worse?) and followed
  asynchronously, never as a wall in front of the command that improves it.

**The primitives stay.** What changes is when they run and whom they ask. What
exists today, and what each lane builds on:

- The package verdict (`safe audit package-audit`, `internal/verdict`): GO,
  WARN or BLOCK for one exact artifact, from OSV, Socket, the blocklist and the
  release age.
- A cooldown: `install.cooldown_days` is 3, a younger release is a WARN cause,
  and `install.cooldown_security_fix: exempt` waives it when the version is the
  fix of an advisory. Socket has its own 7-day fresh window that ends in a
  question for the operator.
- The project gate (`safe_gate_scan_project`): a scan of the whole project
  that gates on its critical findings in the tool's ecosystem, whether the
  command introduced them or not. Named packages are audited as roots; their
  dependency closure is not audited before delegation
  ([#752](https://superbiche.fibery.io/Superbiche/Tasks/752)).
- One differential lane: `npm dedupe` and `npm prune` are projected to a
  lockfile in a scratch directory, the two lockfiles are diffed by
  `safe-core lockdiff`, and only the introduced set is audited.
- Severity rules: an advisory below high informs and never gates; high is an
  adverse WARN; critical blocks.
- Consent that travels: an exact artifact accepted once is reused locally, and
  a machine that signs an export makes its successful installs installable on
  every follower, unattended, while the follower's own audit still runs.
- `safe audit tools-scan`: a daily scan of the installed mise tools for
  advisories published after the install.
- `safe run`'s Podman sandbox: an isolation primitive for running a package
  without host access.
- The operator terminal predicate: stdin is a terminal and no agent marker is
  set. It identifies the operator by the absence of a signal.

**Four lanes** (proposed 2026-11-17, settled in the tickets: see Decisions so
far).

1. Habitual tooling on workstations and agent VMs. A pull model: an isolated
   origin watches releases, waits the cooldown, runs the full battery, and
   signs what passed. Hosts update only to validated versions, with no prompt.
2. Project update. The command is projected to a lockfile first; findings are
   compared before and after; nothing new means it passes, with a report of
   what was fixed and what remains.
3. Project add. Only the closure the new dependency brings is audited. The
   project's existing findings are reported, never gating.
4. One-shot: a runner, or a package the fleet has never seen. Today's full
   gate, because a first-seen name deserves the most scrutiny.

Across the lanes: safe proposes versions instead of only refusing one; the
cooldown is a wait rather than a question; a finding is weighed against how it
can be reached; and the operator is asked as rarely as possible, in one place,
at a time they choose.

**Rulings that bound the design** (`AGENTS.md`, Operator rulings): malice
signals stay fail-closed; every terminus leaves the operator a deliberate
override; agents install exact pinned versions and never answer an
operator-only prompt; audit-infrastructure breakage never reads as a package
finding.

**Slice order** (2026-11-19, from the tickets' rulings):

1. The differential project gate: npm, then Composer, then the other
   projections in the survey's order. Refusals name their lane on the final
   line and carry the override
   ([differential gate](https://superbiche.fibery.io/Superbiche/Tasks/1500),
   [lane selection](https://superbiche.fibery.io/Superbiche/Tasks/1501)).
2. Version targeting: the candidates table, the 3-day cooldown in every lane,
   the major-version tiers delivered when they apply
   ([version targeting](https://superbiche.fibery.io/Superbiche/Tasks/1502)).
3. Socket design A in its simple form: batch scoring into a signed cache, no
   Socket state that asks or blocks, malice narrowed to Socket's Known malware
   ([Socket's place](https://superbiche.fibery.io/Superbiche/Tasks/1572)).
4. The operator's decision channel: the queue, Vigie, the FIDO2 proof
   ([operator and agent](https://superbiche.fibery.io/Superbiche/Tasks/1503)).
5. The decontamination origin and the host update path
   ([origin](https://superbiche.fibery.io/Superbiche/Tasks/1506),
   [host update path](https://superbiche.fibery.io/Superbiche/Tasks/1507)).
6. Risk context: the development-scope preset and not-affected statements
   ([risk context](https://superbiche.fibery.io/Superbiche/Tasks/1504)).
7. Custody: the proxy, npm with release binaries first, then Composer, then
   Python ([custody](https://superbiche.fibery.io/Superbiche/Tasks/1508)).

Ruled by the operator: the first slice (2026-11-17), Composer right after npm,
Socket's simple form before the proxies, the proxies' order. The rest is the
coordinator's order, from what each slice needs from the ones before it.

## Decisions so far

- Operator, 2026-11-17: safe's primitives stay; what changes is how and when
  the operator is solicited, and the operator is not the agent.
- Operator, 2026-11-17: the first slice is the differential project gate.
- [Prior art survey](https://superbiche.fibery.io/Superbiche/Tasks/1498),
  2026-11-18: release age is native in almost every manager of the fleet and
  can be passed per invocation, but a locked install skips it, so safe keeps
  its own exact-artifact check; bots let a security fix bypass the wait while
  npm and Composer do not. Diff-based gating exists (GitHub dependency review)
  but judges vulnerable added artifacts, not (package, advisory) identities.
  KEV, EPSS and the CVSS vector are context, never proof of unreachability;
  Grype consumes VEX. Real quarantine exists only in Sonatype Firewall and
  JFrog Curation; light registries can serve a validated-only namespace.
  OpenSSF Package Analysis and GuardDog run locally; Socket stays an API
  signal.
- [Lockfile projection survey](https://superbiche.fibery.io/Superbiche/Tasks/1499),
  2026-11-18: a lockfile-only projection exists for npm, pnpm, Bun, Yarn
  Berry, Composer, uv projects and Cargo; Go has a module graph; Yarn Classic
  and pip keep today's gate. No projection is network-free and several can run
  code unless guarded, so the first adapters accept declarative registry
  projects only. The npm diff document is too narrow to generalise. The
  delegate must install the projected result, not resolve again. Order: npm,
  pnpm, Bun, Yarn Berry, Composer, uv, Cargo, Go (Composer later moved up,
  below).
- Operator, 2026-11-18,
  [differential gate rule](https://superbiche.fibery.io/Superbiche/Tasks/1500):
  a project command is judged on the set it introduces, direct or transitive.
  Malice signals gate wherever they are found. An advisory gates only when
  introduced, with (package name, advisory id) as identity; one that was
  already there is accepted because it was already there, and is reported. No
  arithmetic between fixed and introduced. The whole-project scan becomes a
  report.
- [Binding prototype on npm](https://superbiche.fibery.io/Superbiche/Tasks/1509),
  2026-11-18: without binding the installed graph drifts from the audited one
  (4 of 67 packages over two months for an add, 2 for an update over three
  weeks). Bind by consuming the projected lockfile: write the projected
  manifests and lockfile, then run a locked materialisation (`npm ci`, or
  `npm ci --dry-run` then a plain `npm install`), and compare lockfile and tree
  afterwards. The user's verb is never run again: `npm update` on a seeded
  lockfile resolves again. Projection costs 0.2 to 0.6 s for one more
  dependency and 4 to 15 s for a full re-resolution of 950 entries; today's
  gate dominates the wall clock. Workspace members, `file:` directories and git
  dependencies are not bound by a lockfile. The `npm dedupe` / `npm prune` lane
  moves to the same shape with the first slice.
- [Battery dry run](https://superbiche.fibery.io/Superbiche/Tasks/1505),
  2026-11-18: one day's seven outdated npm tools cost about two minutes and
  under 1 GB of scratch, with no Socket call (an unattended session cannot
  obtain one for a fresh release). Every candidate is fresh and stops at
  today's gate on its age or on the Socket consent. A scan of what was
  installed sees advisories the root audit does not; against the installed
  versions, six of seven updates introduce no critical or high advisory. Three
  steps cannot run through `safe run`'s sandbox today: a host-allow pin refuses
  another version of the tool, install scripts do not run even when asked, and
  nothing records network destinations or file writes. Release-binary tools
  were not covered.
- Operator, 2026-11-18, addendum to the
  [differential gate rule](https://superbiche.fibery.io/Superbiche/Tasks/1500):
  a critical advisory never blocks a command that bumps the package carrying
  it, even when it remains after the bump or other critical or high advisories
  already there remain; blocking on what was already there does not help in
  most cases. Malice signals are the blocklist, malware advisories and Socket
  BLOCK (narrowed below to Socket's Known malware); a critical advisory the
  command introduces still blocks. Reporting a critical that appears on
  resident packages belongs to Vigie or to Phare (Berceuse), not to the
  install gate; which one is not settled.
- Operator, 2026-11-18, order of the projections: Composer comes right after
  npm, before pnpm, Bun and Yarn Berry, because that is where the problem
  reached the operator (a Laravel update stopped on the critical it fixed).
  Composer plugins: a closed list of plugins checked to have no effect on
  resolution; a project with any other active plugin keeps today's gate. On
  the project observed, none of the 186 lockfile entries carried an archive
  hash (a commit reference only), so binding is measured for Composer as it
  was for npm.
- Operator, 2026-11-18,
  [lane selection](https://superbiche.fibery.io/Superbiche/Tasks/1501): the
  lane follows from the command (habitual tooling, project update or add,
  one-shot). First-seen is about the name, and a name a followed signed
  statement carries is not first-seen. A cloned project's committed lockfile
  is the baseline (its first install reports advisories; malice is checked
  over the whole closure); a project with no lockfile has an empty baseline.
  Every refusal names its lane on its final line and offers an override that
  holds once and for all. A refusal must make sense: one caused by a Socket
  rate limit, or one that leaves nothing to do, is friction that pushes to
  override. A first-seen version comes with every dependency bump, so Socket's
  place is evaluated on its own
  ([Socket's place](https://superbiche.fibery.io/Superbiche/Tasks/1572)):
  score ahead of time within quota, share the results between workstations and
  cluster, or keep Socket for exceptions.
- Operator, 2026-11-18,
  [version targeting and cooldown](https://superbiche.fibery.io/Superbiche/Tasks/1502):
  the cooldown is 3 days for every lane, aligned on Dependabot. When a version
  does not pass, safe answers with a table of candidates and an agent retries
  with a passing exact version; the cooldown is a wait, not a question.
  Candidates may cross a major: safe proposes, the agent judges the breaking
  changes in four tiers (none, or trivial: moves and informs afterwards; more
  work: the operator validates in prose; a Nuxt 2 to 4 kind of migration:
  blocked). The direct tiers need the project's checks to pass; a global tool
  goes direct only when its release notes announce no breaking change.
  Instructions that apply under a condition arrive when the condition
  triggers, in safe's output, not as standing text in the contract.
- Operator, 2026-11-18,
  [Socket's place](https://superbiche.fibery.io/Superbiche/Tasks/1572): safe
  was spending Socket's quota one artifact at a time (100 units a call) where a
  batch scores up to 1 024 for the same cost; the local projects' committed
  bumps fit in one or two batches a day. Design A: one place scores ahead of
  time in batches into a signed cache replicated to workstations and cluster;
  install time reads the cache and no Socket state asks or blocks. A simple
  version first; later A feeds the package-manager proxies on the cluster, so
  most upgrades go through validated versions and the exception path is very
  rare. Only demonstrated malice blocks (Socket's Known malware, an OSV MAL-
  record, the blocklist), with the operator's override, in an output set apart
  from every other finding and carrying verifiable identifiers and links.
  False-alarm fatigue is safe's main problem: findings at the same level stop
  being read.
- Operator, 2026-11-18,
  [operator and agent](https://superbiche.fibery.io/Superbiche/Tasks/1503):
  agents never receive a question. A code decision (a major bump that needs
  work) is settled in prose with the agent; a security override needs the
  operator's proof, FIDO2 on their YubiKey (touch over USB, NFC tap on the
  phone): WebAuthn in Vigie, an `ed25519-sk` signature over the decision batch
  at a terminal, one proof per batch, bound to the exact decisions. Yubico OTP
  was set aside (a bearer token that proves a touch, not what it approves, and
  needs YubiCloud or a held AES key). safe keeps the queue of decisions; Vigie
  shows it and becomes where the operator answers (Vigie acting is a Vigie
  objective), with a skill agents cannot invoke as a convenience, not a
  boundary. One desktop notification on workstations, replaced as the queue
  grows; a click opens Vigie with the command. The only install-time prompt
  left at the terminal is a refusal's override, on its final line.
- Operator, 2026-11-18,
  [risk context](https://superbiche.fibery.io/Superbiche/Tasks/1504): the only
  automatic lowering is GitHub's Dependabot preset for development-scoped
  dependencies (npm, a curated CWE list), extended with the same list to
  Composer and Python development dependencies; KEV, EPSS and the CVSS vector
  are context and lower nothing; a KEV-listed advisory and a malice signal are
  never lowered. When an introduced advisory has no passing candidate, the
  agent analyses reachability and proposes a "not affected, because ..."
  statement (VEX justification, evidence) that the operator approves with the
  hardware key. A statement is (package, advisory id), project-scoped by
  default, fleet- or cluster-scoped when the reason does not depend on the
  project's code; it holds until the advisory changes (KEV, severity, affected
  range), is signed and followed like a grant, in OpenVEX.
- Operator, 2026-11-18,
  [decontamination origin](https://superbiche.fibery.io/Superbiche/Tasks/1506):
  one service watches, scores Socket in batches, runs the battery and signs.
  Detonation runs in a dedicated KVM VM on lugus (clean image each run, no
  secret, public internet only), separate from a signer that never runs
  package code. The origin advances the version of a package a host already
  has, globally or in a repository's lockfile, scheduled by priority,
  criticality and how often the repository updates. A version is signed after
  the 3-day cooldown, with no malice signal, no introduced critical or high
  advisory, scripts run under OpenSSF Package Analysis with no behaviour new
  against the previous version, and a passing smoke run; release binaries on
  cooldown, signer-identity continuity, binary SBOM and a recorded smoke run.
  An unsigned version blocks nothing: it goes through the normal lane. The
  introduced-advisory criterion takes an operator override per project and per
  dependency for legacy projects while they migrate. The operator's signed
  decisions always outrank the origin's, for the whole fleet.
- Operator, 2026-11-19,
  [host update path](https://superbiche.fibery.io/Superbiche/Tasks/1507):
  `safe tools update` applies validated versions with exact versions and no
  prompt, and shows the others as waiting with their reason. The follow of
  signed statements runs on a schedule on every host. Validated non-major
  versions apply by themselves on agent VMs and workstations; majors never do
  and follow the version-targeting tiers; Vigie shows what changed and the
  previous version for rollback. Global tools outside mise (registry
  `uv tool`, `cargo install`) move into mise; tools from the operator's own
  sources are out of scope. Moving a host-allow pin stays an operator decision
  through the queue.
- Operator, 2026-11-19,
  [custody](https://superbiche.fibery.io/Superbiche/Tasks/1508): one proxy for
  every ecosystem rather than one tool each; candidate
  [git-pkgs/proxy](https://github.com/git-pkgs/proxy) (npm, PyPI, Composer,
  Cargo, Go, GitHub release downloads; cooldown that hides young versions from
  metadata, exact denylist, external scanner hook), adopted after a prototype
  on npm. The origin is the proxy's block-mode scanner and answers from its
  signed verdicts; an unvalidated version is refused with its reason and
  queued at high priority. Release binaries rely on
  [packslip](https://packslip.dev/), then aqua, for the vendor's signature and
  no-downgrade rule; the proxy caches an unmodified copy. Order: npm (with
  binaries), Composer, Python. On cluster outage the host uses the normal gate
  on the public registry and says so; a network deny of public registries
  applies to agent VMs only, once the proxy has proven itself.

## Not yet specified

- Which of Vigie or Phare (Berceuse) reports a project's resident findings,
  including a critical that appears on a resident package and the re-check of
  not-affected statements, and whether that report joins the
  tool-vulnerability publication.
- Ungated ecosystems (Gradle, Maven): which lane they belong to.
- How a host moves from today's gate to the lanes, and what becomes of the
  existing consent stores.
- The standing rulings in `AGENTS.md` that the lanes supersede (the Socket
  rate-limit consent and exit codes 12 to 14, the malice line that counts
  every Socket critical alert, the negative operator predicate for
  overrides): each is rewritten with the slice that changes it.
- Whether personal and client repositories share one policy.
- How to tell that friction dropped without risk rising: what is counted, and
  from which log.
- How the lanes land in the Go migration
  ([Safe Go Migration](https://superbiche.fibery.io/Superbiche/Tasks/119)):
  new capability grows in Go.
- Each ticket's readings to confirm at spec time and its unchecked facts are
  settled when its slice is specified.

## Out of scope

- Building the slices.
- The trust tiers and sandbox policy of `safe run`.
- The Go migration itself.
- Operating the cluster services the origin or a registry would need.

## Tickets (index at export time, 2026-11-19, fourth export)

Every ticket is closed; the destination is reached.

- [Prior art survey](https://superbiche.fibery.io/Superbiche/Tasks/1498) — research, CLOSED 2026-11-18.
- [Lockfile projection per package manager](https://superbiche.fibery.io/Superbiche/Tasks/1499) — research, CLOSED 2026-11-18.
- [What gates a project update or add under the differential gate](https://superbiche.fibery.io/Superbiche/Tasks/1500) — grilling, CLOSED 2026-11-18 (operator ruling, addendum the same day). First slice.
- [Lane selection and the first-seen boundary](https://superbiche.fibery.io/Superbiche/Tasks/1501) — grilling, CLOSED 2026-11-18 (operator ruling).
- [Version targeting and cooldown](https://superbiche.fibery.io/Superbiche/Tasks/1502) — grilling, CLOSED 2026-11-18 (operator ruling).
- [Operator and agent: identification, and where decisions arrive](https://superbiche.fibery.io/Superbiche/Tasks/1503) — grilling, CLOSED 2026-11-18 (operator ruling).
- [Risk context: which findings may be set aside without the operator](https://superbiche.fibery.io/Superbiche/Tasks/1504) — grilling, CLOSED 2026-11-18 (operator ruling).
- [Decontamination battery dry run on one workstation's outdated tools](https://superbiche.fibery.io/Superbiche/Tasks/1505) — prototype, CLOSED 2026-11-18.
- [Decontamination origin: where it runs, what it holds, what validated means](https://superbiche.fibery.io/Superbiche/Tasks/1506) — grilling, CLOSED 2026-11-18 (operator ruling).
- [Host update path for habitual tooling](https://superbiche.fibery.io/Superbiche/Tasks/1507) — grilling, CLOSED 2026-11-19 (operator ruling).
- [Package registry on the cluster: custody of validated bytes](https://superbiche.fibery.io/Superbiche/Tasks/1508) — grilling, CLOSED 2026-11-19 (operator ruling).
- [Binding the audited projection to the real command](https://superbiche.fibery.io/Superbiche/Tasks/1509) — prototype, CLOSED 2026-11-18.
- [Socket's place: score ahead of time within quota, share the results, or keep Socket for exceptions](https://superbiche.fibery.io/Superbiche/Tasks/1572) — research then operator ruling, CLOSED 2026-11-18.
