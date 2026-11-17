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
exists today, and what each lane would build on:

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

**Four lanes (coordinator's proposal, each settled in its ticket).**

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

**Proposed slice order.** The differential project gate first (lanes 2 and 3):
it removes the daily friction, closes the closure gap for the lanes it
projects, and needs no new infrastructure. Then version targeting, then the
operator's decision channel, then the origin and the host update path, then
risk context, then the registry.

## Decisions so far

- Operator, 2026-11-17: safe's primitives stay; what changes is how and when
  the operator is solicited, and the operator is not the agent.
- Operator, 2026-11-17: the first slice is the differential project gate.

## Not yet specified

- Where the report of a project's resident findings is read once it stops
  being a prompt, and whether it joins the tool-vulnerability publication.
- Tools safe does not advisory-audit today (release binaries through mise
  backends) and ungated ecosystems (Gradle, Maven): which lane they belong to.
- How a host moves from today's gate to the lanes, and what becomes of the
  existing consent stores.
- Whether personal and client repositories share one policy.
- How to tell that friction dropped without risk rising: what is counted, and
  from which log.
- How the lanes land in the Go migration
  ([Safe Go Migration](https://superbiche.fibery.io/Superbiche/Tasks/119)):
  new capability grows in Go.

## Out of scope

- Building the slices.
- The trust tiers and sandbox policy of `safe run`.
- The Go migration itself.
- Operating the cluster services the origin or a registry would need.

## Tickets (index at export time, 2026-11-17)

- [Prior art survey](https://superbiche.fibery.io/Superbiche/Tasks/1498) — research, open.
- [Lockfile projection per package manager](https://superbiche.fibery.io/Superbiche/Tasks/1499) — research, open.
- [What gates a project update or add under the differential gate](https://superbiche.fibery.io/Superbiche/Tasks/1500) — grilling, open. First slice.
- [Lane selection and the first-seen boundary](https://superbiche.fibery.io/Superbiche/Tasks/1501) — grilling, open.
- [Version targeting and cooldown](https://superbiche.fibery.io/Superbiche/Tasks/1502) — grilling, open.
- [Operator and agent: identification, and where decisions arrive](https://superbiche.fibery.io/Superbiche/Tasks/1503) — grilling, open.
- [Risk context: which findings may be set aside without the operator](https://superbiche.fibery.io/Superbiche/Tasks/1504) — grilling, open, blocked by the prior art survey.
- [Decontamination battery dry run on one workstation's outdated tools](https://superbiche.fibery.io/Superbiche/Tasks/1505) — prototype, open; starts on the operator's go.
- [Decontamination origin: where it runs, what it holds, what validated means](https://superbiche.fibery.io/Superbiche/Tasks/1506) — grilling, open, blocked by the dry run and the prior art survey.
- [Host update path for habitual tooling](https://superbiche.fibery.io/Superbiche/Tasks/1507) — grilling, open, blocked by the origin ticket.
- [Package registry on the cluster: custody of validated bytes](https://superbiche.fibery.io/Superbiche/Tasks/1508) — grilling, open, blocked by the prior art survey and the origin ticket.
