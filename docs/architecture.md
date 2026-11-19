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

`project-bind --project <dir> (--lock-fd <n> | --take-lock) --publish <rel>=<file>...
--copy <rel>=<file>... --live <rel>=(sha256:<hex>|absent)... --env-file <file>
--os <os> --cpu <cpu> [--libc <libc>] [--omit dev|optional|peer]... -- <absolute
command> [<arg>...]` takes the judged manifests and lockfile (`--publish`), the
judged configuration (`--copy`), the digest of every project input as it was
judged (`--live`, which must include `npm-shrinkwrap.json=absent`: the
competing lockfile name), the whole environment of the install command
(`--env-file`: NUL-separated `KEY=VALUE`, nothing is inherited) and the
selection the install was probed with. It prints one versioned document
(`schema_version` 1, the same members every time) and exits with the outcome's
status:

| Exit | `outcome` | Meaning |
| --- | --- | --- |
| 0 | `published` | the verified tree and the judged files are in place |
| 2 | | usage |
| 3 | | a judged input or the environment file cannot be read |
| 30 | `refused` | refused before anything ran; `reason` says why (lock not held, tree root a symbolic link, input a symbolic link, lockfile with links or paths outside the tree, competing lockfile, unfinished recovery, ...) |
| 31 | `install_failed` | the install command failed; its own status is in `install` (`exit_code`, or `signal`), apart from this one |
| 32 | `verification_failed` | the staged tree is not the judged one; `verification` lists the problems |
| 33 | `inputs_changed` | a live input is no longer what was judged (or a lockfile or configuration appeared); `inputs_changed` lists them |
| 34 | `interrupted` | a signal ended the run before publication |
| 35 | `publication_failed` | publication failed and was undone (see `publication.state`) |

Order of the steps and what each failure point leaves on disk:

1. Check the request, the project directory and the lock. Nothing is written.
2. Recover a staging directory an earlier killed run left (below).
3. Check the tree root (absent or a real directory on the project's
   filesystem, never a symbolic link) and every live input against its judged
   digest; an input that is a symbolic link, or sits below one, refuses. Nothing
   is written.
4. Create the staging directory (`.safe-bind-<128 random bits>`, mode 0700,
   inside the project) and copy the judged inputs in. Only staging exists.
5. Run the install command in staging, as a child in its own process group
   with exactly the given environment and none of the caller's descriptors (the
   lock included). Turning scripts off is the caller's argv and environment. The
   child dies with `project-bind` (parent-death signal), and its process group
   is swept when it exits.
6. Verify the staged tree against the judged lockfile bytes (`project-tree`'s
   check). The project is still untouched.
7. Publish. Re-check the live inputs and the tree root, write the replacement
   files (the destination's mode, by `fchmod`, so the umask never applies),
   write the journal, then: move the old tree aside into staging; move the
   staged tree in; for each judged file link the old one to a backup, check it
   is still what was judged and rename the new one over it; look once more at
   the inputs publication does not replace; remove the journal (the commit);
   remove staging.

A failure, a signal, the child's death or a failed check at any point up to the
journal leaves the project byte for byte as it was, old tree included, and the
staging directory is removed. A signal that arrives once the journal is
written is deferred until the commit (`signal` in the document). A failure
inside publication is undone in process, in reverse; a crash (SIGKILL, power)
is undone by the next `project-bind`, under the lock, before it does anything
else: a staging directory without a journal never published (or committed) and
is removed; one with a journal is rolled back from what is on disk. A file that
changed since the transaction wrote it is left as it is and reported. So the tree
in place is only ever the old one, none, or the verified one, and what an
interrupted publication leaves is read, not guessed, by the next run. An edit that
lands in a destination during publication survives: the replaced file is
compared with the one that was judged before it is replaced.

The lock is the caller's: the gate takes `flock(LOCK_EX)` on the project
directory before it reads anything and keeps it until it exits, so
`project-bind` is given the descriptor (`--lock-fd`, the descriptor `flock -x
<fd>` took in bash, which a child inherits) and proves it: it is the project
directory, a separate open file description cannot take even a shared lock on
it, and the descriptor can take the exclusive lock without waiting. It never
releases it. `--take-lock` takes it itself, without waiting, and refuses when
anyone holds it; that is for standalone use. Neither mode lets two holders
exist.

`project-tree [--omit ...] --os <os> --cpu <cpu> [--libc <libc>] <lockfile> <dir>`
exits 0 when the tree below `<dir>/node_modules` is the judged one and 32 when
it is not (30 for a lockfile with link entries, which this slice does not
verify). Nothing is read through a symbolic link; a package directory without a
manifest is broken, not absent; an entry is absent only when the selection
provably deselects it (an optional platform constraint is deselecting only
against a stated os, cpu and libc: leave the libc out and an entry that
carries one must be present); extras include hidden entries apart from npm's
`.package-lock.json` and `.bin` links that stay in the tree; npm's hidden
lockfile, when present, must be readable and record the tree.

Residuals: the engines of an optional package are not part of the selection,
so an optional package npm skipped for its `engines` reads as missing; a
`SIGKILL` of `project-bind` kills the install command but not what that
started, which can only write into the orphaned staging directory the next run
removes; publication is not atomic as a whole, only journaled.

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
