# Architecture

`safe` is organized around one dispatcher and two direct component CLIs.

```text
safe
  run      -> sandboxed package runner
  audit    -> evidence and verdict engine
  install  -> audited npm host install, or safe run install with --sandbox
  vendor   -> safe vendor update
  setup    -> safe audit setup
  status   -> combined status
  doctor   -> local readiness diagnostics
```

The dispatcher forwards `safe run`, `safe audit`, `safe setup`, and unknown
runner invocations without changing their meaning. Direct binaries remain
installed for compatibility and for scripts that intentionally call `safe-run`
or `safe-audit`.

## Components

`safe run` decides how package execution is allowed:

- blocklist entries are refused;
- host allowlist entries run on the host with script execution suppressed where supported;
- unknown packages are sandboxed in Podman (after an interactive prompt);
- sandbox-known packages run in Podman without another prompt;
- unknown non-TTY execution blocks unless explicitly allowed by flags.

`safe audit` handles evidence gathering and verdicts:

- project and multi-machine scans;
- SBOM generation and vulnerability scans;
- package behavior checks;
- IOC updates and scans.

`safe install -g` runs `safe audit package-audit` for explicit package specs, prompts,
then delegates to the selected package manager. npm is the default; `--pnpm`,
`--yarn`, `--bun`, and `--composer` translate `-g` to each manager's native
global command. After successful installs of exact npm versions, interactive
runs can add that exact version to host-allow; `--trust-host` makes that step
explicit. `safe install --sandbox` keeps the isolated `safe run install` workflow.

Install wrappers are executable shims on PATH that exec `safe gate <tool>`.
The gate runs `safe audit package-audit` (install-gate mode) for package installs or
`safe audit repo-audit .` for project-local installs, then delegates to
the first non-wrapper executable of that name on PATH — so mise/asdf shims
and per-project tool versions keep working, in every shell.

`safe vendor update` wraps explicit vendor-native updater commands. It cannot
intercept in-process auto-updaters automatically, but it records a durable audit
trail for intentional updates that bypass package-manager safeguards.

## Direction: Go

`safe-core` (`cmd/safe-core`, with `internal/lockdiff`, `internal/strictjson`,
`internal/verdict`, `internal/toolscan`, `internal/nodetree` and
`internal/projectlane`, the project lane's judging core) is the start of a gradual migration of `safe`'s logic
out of bash and into Go. New capability grows in Go, not bash, wherever the
choice exists.

The first Go lane, `binary-audit` (the `release-review` composite, 1.34.0 to
1.66.1), was removed after 1.66.1 with its only consumer: release binaries are
installed through mise backends, which check checksums and, where the backend
supports them, signatures and attestations. The mise gate reports those tools
as not advisory-audited.

### Project lane: the binding transaction

Groundwork only: nothing an installed gate executes calls these commands yet.
The project lane judges an npm command on what it introduces and must then
install exactly what was judged. That last step is `safe-core project-bind`
(`internal/projectlane/transaction.go`), and the tree check it relies on is
`safe-core project-tree` (`internal/projectlane/tree.go`), usable on its own.
Linux only (it is built on descriptor-relative operations, `renameat2` and
`/proc`); elsewhere `project-bind` refuses.

**Threat model.** The content of a project (a cloned repository, its lockfile,
anything committed or left in its directory) is untrusted input: nothing the
transaction finds there may steer it. The install command is the admitted npm
with scripts off and is *trusted as today's delegate is*: it runs with the
installing user's filesystem access and its writes are not confined (no
sandbox), and a same-user process that wants to bypass the gate can call npm
directly. The document says so (`assumptions`). What the transaction guarantees
is about the project: that what lands in it is what was judged and verified,
and that it is left either as it was or as judged.

`project-bind --project <dir> (--lock-fd <n> | --take-lock) --state-dir <dir>
--publish <rel>=<file>... --copy <rel>=<file>... --live <rel>=(sha256:<hex>|absent)...
--env-file <file> --os <os> --cpu <cpu> [--libc <libc>] [--omit dev|optional|peer]...
-- <absolute command> [<arg>...]` takes the judged manifests and lockfile
(`--publish`), the judged configuration (`--copy`), the digest of every project
input as it was judged (`--live`, which must include `npm-shrinkwrap.json=absent`:
the competing lockfile name), the whole environment of the install command
(`--env-file`: NUL-separated `KEY=VALUE`, nothing is inherited), safe's own
state directory (`--state-dir`, outside the project: where the record of each
staging directory it creates is kept) and the selection the install was probed
with. It prints one versioned document (`schema_version` 1, the same members
every time) and exits with the outcome's status:

| Exit | `outcome` | Meaning |
| --- | --- | --- |
| 0 | `published` | the verified tree and the judged files are in place |
| 2 | | usage |
| 3 | | a judged input or the environment file cannot be read |
| 30 | `refused` | refused before anything ran; `reason` says why (descriptor table unreadable, lock not held or lock operation failed, tree root a symbolic link, input a symbolic link or with set-id bits, lockfile with links or paths outside the tree, competing lockfile, state directory invalid or not private, ...) |
| 31 | `install_failed` | the install command failed; its own status is in `install` (`exit_code`, or `signal`), apart from this one |
| 32 | `verification_failed` | the staged tree is not the judged one; `verification` lists the problems |
| 33 | `inputs_changed` | a live input, or the tree root, is no longer what was judged (or a lockfile, configuration or tree root appeared); `inputs_changed` lists them |
| 34 | `interrupted` | a signal ended the run before publication |
| 35 | `publication_failed` | publication failed and was undone (see `publication`) |
| 36 | `install_unsettled` | the install ran but it could not be established that its process group is gone (or that it ended): told apart from an install failure; staging is kept and marked kept |

**Identity, not pathnames.** The transaction holds directory descriptors for
the project (a duplicate of the caller's locked one), the staging directory, the
record directory, and the live and staged trees, and works relative to them:
every lookup of the transaction is one name below a held directory, opened with
`O_NOFOLLOW`, so no symbolic link is followed at any component and a replaced
ancestor redirects nothing. The tree that was verified is the tree that is
moved: its handle is kept from before verification to the end and its identity
(device and inode) is checked again immediately before the exchange; the live
tree root is held from the first look, and the displaced object is inspected
after the exchange: a replacement is exchanged back and the transaction stops.
The verifier is anchored on the held staged-tree descriptor and resolves each
name below it with an `Lstat` per component (no link followed); it is not an
`openat` chain, and the documentation claims no more. Removal of a directory
never follows a link and never crosses a device or mount boundary (a bind mount
of the same device included).

**Order of the steps and what each interruption leaves.** There is no journal and
no replay. The guarantees below concern a *process* that is interrupted or killed
(a signal, `SIGKILL`, a crash of `project-bind`) with the filesystem running on.
They are not a power-loss guarantee: the extracted tree, the state record and the
directories touched by renames carry no durability barriers.

| Step | What it does | If it stops here (failure, signal, kill) the project is |
| --- | --- | --- |
| 1 | check the request, seal every inherited descriptor (an unreadable descriptor table refuses), take or prove the lock | untouched |
| 2 | remove staging directories this command recorded for this project (and not marked kept) | untouched |
| 3 | check the tree root and every live input against the judged digests; the tree root is "absent" or "present" from the first look | untouched |
| 4 | create staging (0700, random name), record it, copy the judged inputs in, probe the atomic exchange | untouched; staging exists (removed at the end; after a kill, by the next run) |
| 5 | run the install in staging; once it has exited kill its process group and wait until the group is empty | untouched |
| 6 | verify the staged tree against the judged lockfile bytes; an install that leaves no tree for a lockfile that selects none verifies as empty | untouched |
| 7a | last digest pass, then the signal check; from here a signal is deferred to the end of publication; the record is marked **kept** | untouched; staging kept |
| 7b | for each file in order: atomic exchange of the prepared file with the destination (`renameat2(RENAME_EXCHANGE)`) recorded the moment it succeeds, the displaced object inspected (bytes and permission bits must be the ones judged and seen at preparation), anything else exchanged back and the run stops; a file that did not exist is created with `RENAME_NOREPLACE` | each file is the old bytes or the judged bytes; tree old |
| 7c | the tree: exchange with the live tree (`RENAME_EXCHANGE`; `RENAME_NOREPLACE` when there was none; nothing when there was none and none is selected), the displaced tree's identity checked | all files judged; tree old, then the verified one (never none while an old one existed) |
| 7d | final check of everything, published destinations and the tree included | published |
| 8 | mark the record not kept, remove staging (old tree and old files with it) and its record | published |

So after any interruption the tree in place is the old one, none (only when
there was none) or the verified one, and each manifest and the lockfile is
either the old bytes or the judged bytes. A kill inside 7b or 7c leaves the files
and tree in one of those combinations; nothing repairs it: the next lane command
re-judges from what it finds (its judged digests no longer match, and
`project-bind` reports `inputs_changed` rather than guess).

**Undo never deletes what it cannot identify.** A failure inside publication
(an error, a changed input found by the final check) is undone in the same
process, in reverse order, best effort. Every object the undo takes out of the
project is *inspected* (identity, bytes and permission bits) and goes to the
document: the judged object goes back to staging; anything else is somebody's
change and is put straight back where it was (a file the run created is moved,
never deleted, and moved back if it was edited). If that fails too, the object is
**retained**: staging is kept, its record says kept, and `publication.retained`
names the object, where it is and what was observed of it. A kill from step 7a on
leaves the same: the staging directory is kept and the next run names it in
`recovery.left` and does not remove it, because it may hold an object displaced
from the project (an editor's save) that nobody has inspected. `publication`
says exactly which state was left: `state` (`not_started`, `committed`,
`rolled_back`, `partial`), `tree` (`old`, `none`, `verified`, `changed`), each
file (`old`, `judged`, `changed`), `conflicts` and `retained`.

**Leftovers and the record.** safe's own state directory (`--state-dir`, outside
the project, and not inside or holding it) holds, per project, a record of each
staging directory this command created: the project's and the directory's
device and inode, and whether it is kept. The state directory, its
`project-bind` directory and the per-project directory must belong to the user,
not be writable by group or others, and not be links; they are used through held
descriptors. A later run removes a leftover `.safe-bind-*` directory only when a
valid record names it for this project, the record does not say kept, the
directory is the very object recorded, owned by the user and on the project's
mount. Any other `.safe-bind-*` directory (a name copied from a repository, one
holding a journal, a link, a kept one) is left untouched and named in
`recovery.left` with the reason. Pruning removes only records it validated
(regular file of the user, right name, strict JSON, this project's identity)
whose directory is gone. This run's own cleanup removes the directory it holds
only if the name still refers to it. Limit: the record is not defended against a
writer running as the same user, nor against an inode reused under the same
128-bit random name.

**The lock** is the caller's: the gate takes `flock(LOCK_EX)` on the project
directory before it reads anything and keeps it until it exits, so `project-bind`
is given the descriptor (`--lock-fd`, the descriptor `flock -x <fd>` took in
bash, which a child inherits) and proves it: it is the project directory, a
separate open file description cannot take even a shared lock on it, and the
descriptor can take the exclusive lock without waiting. It never releases it.
`--take-lock` takes it itself, without waiting, and releases it on exit: it
reports contention (`lock_held_by_another`) apart from an operation that is
unsupported or fails (`lock_operation_failed`), so a filesystem without
working locks is not mistaken for a busy project. Give the lock's open file
description to exactly one binder at a time: two binders inheriting the same
description both pass the proof.

**The install command** is run as a child in its own process group with exactly
the given environment, and every inherited descriptor, whatever its number, is
close-on-exec for it (checked: a table that cannot be read refuses before
anything runs). Once the child has exited its process group is killed and waited
for until it is empty; nothing else is looked for. A process that left the group
(`setsid`, a double fork) is outside the stated assumption: the install command is
trusted and runs no script. If the group cannot be shown empty, or the child does
not end after `SIGKILL`, the outcome is `install_unsettled`, not an install
failure, and staging is kept.

`project-tree [--omit ...] --os <os> --cpu <cpu> [--libc <libc>] <lockfile> <dir>`
exits 0 when the tree below `<dir>/node_modules` is the judged one and 32 when
it is not (30 for a lockfile with link entries, which this slice does not
verify). Nothing is read through a symbolic link; a package directory without a
manifest is broken, not absent. **Absence is excused on the judged lockfile's own
flags and on the platform, as npm does**: an entry may be absent when its optional,
dev, devOptional or peer flag is deselected by the selection, or when its os, cpu
or libc constraint excludes a stated platform (a constraint deselects only
against a stated os, cpu and libc: leave the libc out and an entry that carries
one must be present), or when the occurrence it is nested under is itself absent
and deselected; an entry nested under a *present* occurrence is never excused by
it. The flags are not checked against the lockfile's dependency edges (that
check refused lockfiles npm 11 writes). Limit: a lockfile whose flags lie yields
an incomplete tree, never a foreign or an extra package. Extras include hidden
entries apart from npm's `.package-lock.json` and `.bin`. Each `.bin` entry that
is present must be a symbolic link whose text is exactly the relative path npm's
linker writes for a command a package's lockfile entry declares
(`../<package>/<declared file>`, as `bin-links` computes it; a link with a
cancelling or redundant component, a file or a directory in `.bin` is refused)
and the declared file must be a regular file beneath that package directory
reached without following a link (an `Lstat` per component, then an
`O_NOFOLLOW` open). npm's hidden lockfile, when present, must be readable and
record exactly the tree (version, name, resolved location, hash and bundling of
every entry, compared as written, absent against absent included).

**An empty install.** A lockfile that selects no package (no dependency, or every
entry deselected) and an install that leaves no `node_modules` verify and
publish: with no old tree the result is **no tree** (`publication.tree` is
`none`, and a tree root that appears meanwhile refuses as changed input); with
an old tree the old tree is replaced by an **empty** `node_modules` directory,
made in staging and verified like any other.

**Limits.** The verifier attests the *set of packages and their identities*; it
does not attest the bytes of their files. Payload integrity rests on npm
checking each tarball against the integrity hash of the lockfile, and the
hidden lockfile is read as written by the install command that is trusted to
write it. Both are stated in the report (`limits`, `assumptions`). Also: the
engines of an optional package are not part of the selection, so an optional
package npm skipped for its `engines` reads as missing; publication is not
atomic as a whole, only ordered so that every interruption leaves a state the
table above names.

**Exact keys.** Lockfiles, installed manifests and npm's hidden lockfile are read
by exact, case-sensitive member names, as npm reads them: a repeated member, a
second spelling of a field that matters (`name`, `version`, `resolved`,
`integrity`, `link`, `inBundle`, the flags, the dependency maps, `packages`; any
other case or Unicode fold), a `null` where an identity field is present, or
content after the document is refused, in the judging core's loader
(`internal/lockdiff`, every entry of it, the root and the ones it skips included)
as in the verifier. Unrelated npm fields stay allowed in any spelling.
Compatibility limits: a UTF-8 byte-order mark refuses (npm strips it), and so does
a lockfile that npm would take for a merge-conflicted file (seven or more each of
`<`, `=` and `>` anywhere in its text).

## Trust Tiers

Packages move through four persistent tiers:

```text
blocked        never run
host-allow     pinned versions allowed on the host
sandbox-known  known enough for sandbox execution
unknown        prompt in TTY, block in non-TTY
```

`blocked.json` is shared by `safe run` and `safe audit package-audit`, so a package
blocked during audit is also refused by the runner.

## Data Flow

Runtime decisions and audit output are intentionally separated from config:

- config: policy and machine state under `~/.config/safe`;
- data: logs, SBOMs, scan results, package checks, and IOC output under `~/.local/share/safe`.

This keeps policy reviewable while allowing high-volume generated evidence to live in data directories.
