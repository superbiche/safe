# Configuration

Unified config lives under:

```text
~/.config/safe/
  run/
    host-allow.json
    private-registries.json
    private-follow-state.json
    blocked.json
    sandbox-known.json
    install-known.json
    config.json
  audit/
    machines.json
    tools.json
    host-allow-digest.json
    host-allow-digest.md
  install-wrappers.zsh
```

Generated data lives under:

```text
~/.local/share/safe/
  run/
    audit.log
  audit/
    results/
    sbom/
    checks/
    ioc/
    host-allow-log.jsonl
    tool-bundles/
```

## Root Overrides

Move all config or data:

```bash
SAFE_CONFIG_DIR=/tmp/safe-config SAFE_DATA_DIR=/tmp/safe-data safe status
```

### Trust is anchored to the canonical root

`SAFE_RUN_CONFIG_DIR` / `SAFE_CONFIG_DIR` relocate the config root, but the
**trust** decisions — host-allow host execution, `scripts-allow` lifecycle
scripts, and the trust-store writes (`host-allow add`/`update`/`import`,
`scripts-allow add`) — are honored only from the canonical
`~/.config/safe/run` store. This closes an escalation path: a process that can
run package managers only through `safe` cannot point it at a store it wrote
itself and thereby escape the sandbox. Against a redirected root safe **fails
safe** on reads (the grant is declined; the package still runs sandboxed) and
**refuses writes with exit 100**; the canonical blocklist is always consulted,
so a redirect can never hide a block.

If you genuinely relocate config and want trust to apply at the new location,
set `SAFE_RUN_TRUST_OVERRIDE=1` — it blesses the redirected store's **grants**
(host-allow host execution and `scripts-allow` lifecycle scripts) and lifts the
write refusal. It does **not** extend to the blocklist: that is a malice signal,
so the canonical blocklist is always unioned in regardless of the token — a
redirect, blessed or not, can only add blocks, never hide a canonical one. The
override is deliberately loud (it prints a warning on every honored grant) so
its use stands out. Note the bash-level limits: this guard
does not defend against a `HOME` redirection, and it is not a substitute for a
non-forgeable operator check or a root-owned store (both tracked for the Go
rewrite). It raises the bar and leaves a bright, greppable trail; it is not a
hard privilege boundary.

## Run Config

`host-allow.json` stores pinned package versions allowed to execute on the host.
Existing entries with retired metadata are ignored; newly written entries use
only the current pinned-version schema. `host-allow add` and `update` verify the
exact version against its registry and obtain fresh integrity before writing;
an unknown or unreachable version is refused.

`private-registries.json` and `private-follow-state.json` hold the
operator-managed trust for owner-controlled private registries (trusted
origins): the local registry policy and the statements followed from fleet
origins. They are trust stores (canonical root only,
operator-TTY writes through `safe run private-registry`); see
[private registries](private-registries.md).

`blocked.json` stores package names or patterns that should never run.

`sandbox-known.json` stores packages accepted for future sandbox execution.

`install-known.json` is machine-written by `safe audit package-audit --gate install`:
one entry per `ecosystem:name` recording the pinned resolved version that
passed a clean version-aware check, the reasons, and a pointer to the check
receipt. Its `approvals` map also retains exact ecosystem/name/version/source
consent from gate confirmations independently of the latest audit evidence.
Later audits still run, but reuse that consent without another terminal prompt;
revoking stale clean evidence does not erase an operator decision. Removing the
corresponding `approvals` entry withdraws that local consent. Legacy
`packages` receipts cannot prove operator presence and grant no install consent. Source identity binds the effective registry
selectors, not a content digest: replaced bytes under the same registry version
are not detected by this consent store. Package-manager integrity checks remain
responsible for artifact integrity. Clean evidence still supports the separate
offline/timeout fallback within `install.auto_allow_ttl_days`; no `safe run`
exec path consults install consent. Operator
host-execution trust stays in `host-allow.json`, which is TTY-gated and
unchanged.

`follow.signing_key` in `run/config.json` optionally selects the GPG key for
operator-only `safe run host-allow export --sign`; absent, GPG uses its default.
`follow.auto_export` (default `true`) republishes that signed export after each
`host-allow add|update|remove` on a host that already publishes one; `false`
keeps the export manual.
`follow.signers` is a list of full GPG primary-key fingerprints. Manage it at an
operator TTY using `safe run host-allow follow-signer add|remove <fingerprint>`;
add requires that public key in the local GPG keyring. `follow` verifies signed
exports in an isolated keyring containing only these authorities (including
their certified signing subkeys), honouring key revocation/expiry and signature
expiry. Update revocation information in the follower's local GPG keyring;
verification never fetches keys. Unrelated expired/revoked subkeys do not
invalidate a good signature. A subkey fingerprint passed to `follow-signer add`
is refused with the matching primary fingerprint to use instead. `follow-state.json`, beside the guard-selected
host-allow store, records per-origin `{accepted, applied:["pkg@version"],
replaced:["pkg@old->new"], refused:["pkg@version"], signer:"<fingerprint>", granted:["ecosystem:pkg@version"], installed:["ecosystem:pkg@version"], block_overrides:{"ecosystem:pkg@version":["advisory id"]}}` and must remain local. `installed` holds the origin's install allowances (exact versions safe allowed to install there), rewritten from each verified statement like `granted`; under a still-pinned signer the gate installs them unattended (exit 21; see [followed install allowances](safe-run.md#followed-install-allowances-at-the-install-gate)). `signer` is
the verified primary fingerprint of the accepted generation: while it stays in
`follow.signers`, the install gate lets an applied identity with a matching
local pin install unattended. `granted` binds that pass to the canonical
ecosystem the signed statement named; each verified run rewrites both fields
from its own statement, so a key never inherits identities another key
signed (gate exit 16; see
[followed grants at the install gate](safe-run.md#followed-grants-at-the-install-gate)),
so `follow-signer remove` also withdraws that pass. An entry may also carry
`block_override: {advisories, accepted}`, written only by
`host-allow add --accept-block` or taken from a signed export; see
[BLOCK overrides](safe-run.md#block-overrides). Followed store entries also
carry `followed_from` and `followed_generation` so the newest signed statement
wins across origins; a host-set pin yields to any signed statement. Preserve it
grants: equal generations skip
applied identities and retry pending ones; older generations are refused and
remembered per identity for that generation. After an upgrade, the first follow
derives a missing generation for a previously followed entry from its origin
ledger; a newer origin generation clears refused identities.
An equal generation with nothing pending returns 0 with one info line. Legacy
string-only records require operator review/migration, never silent reset.
Both operations retain the redirected-store guard. See [signed follower import](safe-run.md#signed-follower-import).

`release-follow.json` is a machine-local regular file written by `install.sh`.
It records the absolute source checkout and the union of normalized installer
component flags from successful `install.sh` invocations:

```json
{"schema":"safe-release-follow/1","checkout":"/absolute/path/to/safe","install_flags":["--run"]}
```

Do not synchronize this file or replace it with a symlink. `safe release follow`
refuses a missing or malformed record unless an explicit `--checkout` repair
path is supplied. The record does not pin trust; release trust remains solely
in the TTY-managed `follow.signers` list. `--no-wrappers` keeps wrappers out of
the recorded union when none were previously installed; it does not remove
wrappers already present in that union.

`release-follow-status.json` is a machine-local regular file written after
each non-dry release-follow pass. It is atomically replaced and has this
shape:

```json
{"schema":"safe-release-follow/1","time":"2026-09-18T12:00:00Z","installed_before":"1.64.1","candidate":"v1.64.2","verdict":"installed"}
```

The candidate is `null` when there was no candidate or the pass refused before
selecting one. Verdicts are `installed`, `nothing-newer`, or
`refused`. Dry runs do not write this file. `safe status` reads
it for the release-follow age line, and `safe doctor --json` exposes its last
pass and warnings under `environment.release_follow`.

`config.json` stores runtime defaults, linked runner paths, sandbox limits, warning behavior, and the install-gate policy:

```json
{
  "install": {
    "auto_allow": true,
    "auto_allow_tolerate": [],
    "trusted_registries": [],
    "auto_allow_ttl_days": 30,
    "block_severities": ["critical"],
    "cooldown_days": 3,
    "cooldown_security_fix": "exempt",
    "reuse": { "enabled": false },
    "project_lane": false,
    "socket": {
      "mode": "auto",
      "cache_ttl_days": 7,
      "cache_dir": "~/.cache/safe/socket",
      "ecosystems": ["npm", "python"],
      "fresh_window_days": 7
    }
  }
}
```

- `auto_allow`: record clean checks in `install-known.json` (GO still
  proceeds either way).
- `auto_allow_tolerate`: opt-in WARN causes (e.g. `socket_unavailable`) that
  may proceed when no advisory affects the resolved version. Default: none.
- `trusted_registries`: package sources (URL prefixes) the operator trusts
  like the default public registry. Any other custom source
  (`--registry`, `--index-url`, `--find-links`, `--no-index`,
  `--repository`, env selectors like `CARGO_REGISTRY_DEFAULT` or
  `BUN_CONFIG_REGISTRY`, and composer's global `config.json` repositories)
  floors the verdict at WARN — public advisory data cannot vouch for a
  private artifact of the same name@version. Non-URL identities are
  trusted verbatim: a cargo registry whose index URL safe cannot see is
  `cargo-registry:<name>`, and a disabled packagist is
  `local:packagist-disabled`. This list says "audit it like the public
  registry"; it is not private-registry trust. An owner-controlled private
  registry belongs in `safe run private-registry add`, whose lane decides
  its namespace whatever this list says ([private registries](private-registries.md)).
- `auto_allow_ttl_days`: freshness window for the offline/timeout fallback.
- `project_lane`: switch for the npm project lane (default `false`; on only when
  the operator's canonical run config, `~/.config/safe/run/config.json`, is
  exactly one JSON document that sets it to the boolean `true`; a redirected
  run-config directory does not turn it on unless trusted with
  `SAFE_RUN_TRUST_OVERRIDE`). With it off the gate behaves exactly as before. With it on, `npm
  install` (bare or with exact `name@version` registry specs), `npm update`, `npm ci`, `npm dedupe` and
  `npm prune` in a project are judged on what they introduce over an established baseline (see
  below) and installed exactly as judged: the
  lane takes an exclusive lock on the project directory, works on one snapshot of
  the manifest, lockfile and `.npmrc`, projects the command in a scratch copy
  with one npm (the one the gate's delegate would run, reached without passing
  through the gate again, with Node's start-up options removed), decides, and
  hands the judged files to `safe-core project-bind`, which stages the tree,
  verifies it strictly and publishes it ([architecture](architecture.md)). Until
  publication the project is untouched; the user's own verb is never run. Every
  class at stake refuses (104 malice or a blocking advisory, 100 a high-severity
  advisory, 102 missing evidence or a graph safe cannot bind), for the operator
  too: this first pass has no prompt, no install record and no scripts. Any
  command or project it does not cover goes one of three ways (**routing**).
  **Scripts.** The lane runs no lifecycle script: not a dependency's, not a bundled member's, not the project's own, and no implicit
  native build (the frozen installation carries `--ignore-scripts`; the lane starts no other npm, never `rebuild`, and never reads
  `allowScripts` or asks npm about `ignore-scripts`). A separate step that runs them afterwards was tried on npm 11.20.0 and 12.2.1: it
  runs the same set of dependency scripts as a plain install, but not the project's own, not in npm's order and not with npm's handling
  of a failure, so it cannot be shown to run exactly what today's policy runs. On a host that follows the operator's standing policy
  (`ignore-scripts=true`) today's gate runs none either. After a verified publication the lane says which scripts did not run, from
  data only (`safe-core project-scripts`: the judged lockfile and the published tree, never npm's messages, never a question to npm):
  the packages the command put into the tree (new or changed against the previous tree's own record, `node_modules/.package-lock.json`;
  every package for `ci`) that declare a `preinstall`, `install` or `postinstall` script or that npm would build natively on its own (a
  `binding.gyp`, no `install` and no `preinstall` script, `gypfile` not false: measured on both versions), a bundled member with its
  host; for a bare `install` and for `ci`, the project's own install-time scripts, and not for an install that names packages. The
  report names the command that runs them (`npm rebuild ./node_modules/<name> …`, a bundled member through its host's path; `npm run
  install`, `npm run prepare` and the others measured to fire the same events) and says that npm's own script policy applies to it; it
  prints no option that overrides that policy. **The tree decides where the two sources disagree:** npm's own install trusts the
  lockfile's `hasInstallScript` over what is on disk (measured: with the flag removed, `npm ci` skipped an install script that `npm
  rebuild` runs), so a package whose files have scripts its lockfile entry does not declare is listed and marked. `--dry-run` and
  `--package-lock-only` publish no tree: the report is then the lockfile's `hasInstallScript` alone for what the command would
  introduce, labelled as such, and the project's own scripts are not named. At most 25 packages are listed, with the count of the
  rest and `npm rebuild` alone for all; a name is cleaned like every other the lane prints. A command that introduced nothing with
  scripts says nothing about scripts. Accepted limit: the previous tree's record is the project's own file (a forged one can only make
  the report smaller, never the lane run anything).
  **How each verb yields its plan.** `install` and `update`: the original arguments resolved in the
  scratch copy, lockfile only. `dedupe` and `prune`: the same, with the verb's own arguments (npm writes
  a changed plan for `dedupe` on a project that needs it, and `prune` drops from the lockfile the entries
  nothing needs; when `prune` only has a tree to prune, the plan is the lockfile unchanged and nothing is
  introduced); the frozen installation of the judged lockfile is what yields the deduplicated or pruned
  tree. Nothing stands in for npm's own `dedupe`. npm's `dedupe` saves nothing in lockfile-only mode when no
  package name is duplicated, so: when npm's run wrote a lockfile that differs from the snapshot's, that
  lockfile is the plan; when it wrote none (or left the bytes as they were), the plan is the lockfile on disk,
  byte for byte, provided npm's own frozen check (the one `ci` runs) accepts it. A lockfile out of step with
  the manifest refuses with npm's diagnostic and status (the way out is `npm install` first). With no
  lockfile, `dedupe` and `prune` refuse 100: npm would work from the installed tree, which the lane does not
  read (a lockfile-only run in the scratch copy would resolve a newer version than the resident one).
  **Cooldown.** `install.cooldown_days` (3 by default, 0 disables, at most 36500) and `install.cooldown_security_fix`
  apply on the lane on what a command introduces. The days are read by value before any arithmetic: a JSON number is a
  whole number of days when it equals its integer part (`4e3` is 4000, `36500.0` is 36500), a digit string is read as
  decimal; a negative or fractional number, a string that is not digits and any other type read as 3 (as in today's
  gate); a value above 36500 (`4e4`, `1e50`, 19 digits) refuses 100 with a configuration error naming the key, and is
  never capped or wrapped. npm's release-age filter is set to the same window, on the command line of every npm run of
  the lane (`--min-release-age`), with the exact versions the command names excluded by name
  (`--min-release-age-exclude`; npm refuses an exact version inside the window with its own error, which would hide the
  wait): a selection aid, so that `npm update` resolves nothing younger than the window. npm's effective configuration
  is read back, positively and typed (an absent or mistyped field refuses), and must hold exactly that window and
  those exclusions and no absolute `before` date (absent or null: `false` refuses), so no configuration file or
  environment variable can widen the cooldown (a project `.npmrc` that sets any of the three is not on the
  allow-list: the command takes the one-shot route). The decision is safe's own reading: the publish time of every
  introduced registry version of a public host, read from the registry the artifact is bound to over a transport the
  caller does not steer (no proxy, no redirect, the system's TLS roots only). **There is no publish time the lane lets
  pass unread.** One complete answer is accepted: the registry's full metadata document, read to its end with
  nothing after it, whose name is the package asked and which lists the version asked; the version's time is its own
  (`time[version]`), or, when the document lists the version without one, the document's last-modified time
  (`time.modified`), which no publish time in the document can exceed (measured on the public registry for seven
  packages of different ages: left-pad, semver, express, typescript, lodash, react, ms; the abbreviated document has no
  `time` at all, only a top-level `modified`, so it is not accepted) - older than the cooldown means old enough, younger
  means the version waits until the bound is old enough. Everything else is missing evidence, 102, naming how many
  readings are missing (registry unreachable, an error status or a redirect, a time or size limit, a reading not
  attempted, an abbreviated or truncated answer, another package's answer, a version the answer does not list, no
  last-modified time), after what the evidence already establishes: a blocklist hit or a blocking advisory is decided
  first (104) and **before any publish time is read**, so no network wait is spent under the project lock on a command
  that ends there; a lockfile judged on missing evidence is refused, so nothing is recorded as a baseline. The answer is
  read as a stream and only the name, the versions' names and times and the last-modified time are kept, so an answer's
  size does not set the memory a reading takes. Measured on the public registry: the largest full documents are `next`
  (30 MiB), `npm` (25 MiB), `gatsby` (23 MiB), `react-native` (15 MiB) and `typescript` (15 MiB); 1,300 identities
  (1,188 packuments, 8 at a time) of a real 2,640-entry lockfile took 18 s cold with a peak of 143 MB (0.08 s and 14 MB
  from the cache). The limits follow: one answer at most 256 MiB (eight times the largest) and 60 s, and 5 minutes for
  all the readings of a command (sixteen times the cold run). Publish times safe read are cached per exact version and
  per source in the lane's own store (`project-lane/state/publish-times/<source>/<entry>`), under the checks the
  recorded lockfiles get (a chain of private directories held by descriptor, entries that are regular files of mode
  0600 owned by the user, opened without following a link, and read with the repository's exact-object validator:
  repeated members, a second spelling of a field or trailing data make the entry ignored); an entry that fails a check
  is ignored and read again, and a reading bounded by the last-modified time is never cached. A version the caller
  named exactly is waived under `exempt` (and waits under `enforce`, which says so) only when it REPLACES, at the same
  place in the graph, a baseline version of the same package that an advisory affects and that advisory is gone from
  the result, as the lane's own advisory evidence shows (aliases are matched by registry identity); when several
  versions of the package are involved and that relation cannot be told, it waits; so does a young version of a
  package the project does not have yet, another young version of the same name, and a young fix nobody named. This
  is narrower than today's gate on purpose. The advisory evidence comes from the auditor installed beside safe's own
  dispatcher, never from one the caller names (`SAFE_AUDIT_BIN`, `SAFE_AUDIT_PATH`, `PATH`), and an advisory whose
  record carries a withdrawal date is removed before it can count as present, introduced or fixed. A version already
  in the baseline is not judged for its age, whoever locked it (the spec's open question 1; one predicate,
  `CooldownCandidates`, holds the choice); an entry the lockfile on disk carries that the baseline does not is
  introduced, and is judged. The npm must define `min-release-age-exclude` (npm 11.17.0 or later, which the
  capability probe checks on top of the 11.12.1 floor).
  **The operator's terminal.** At the operator's terminal (stdin is a terminal and no recognized agent marker is set:
  today's predicate, never loosened; an answer is never read from stdin and `--yes` reaches no prompt), and only there, each
  class the decision leaves at stake is resolved on its own, in the decision's own order, with today's prompts (the lane calls
  the install gate's functions: it has no prompt reader of its own). **Malice:** a typed `name@version` per artifact, for this
  command, never recorded. **Blocking advisory:** a typed `name@version` per artifact (the acceptance is recorded as today's
  gate records it: a local approval of that exact artifact and source), or `record name@version`, which also records the
  advisory override on the host-allow entry (advisory-only, through `safe-run host-allow add --accept-block`, which asks
  again). **Graph not bound:** no confirmation for one command (it is decided after the evidence is read, so it ends as it does unattended, with its line); its way out is the standing decision per project (`safe run one-shot-project add`, below). **Adverse advisory:** ONE prompt
  lists every artifact and advisory; `[y]` accepts the listed exact artifacts (each recorded as an acceptance), `[a]` also
  records a host-allow grant (npm and python, as today), `[N]` declines. **Wait:** today's adverse override. **Socket on a named
  root:** the rate-limit approval (for this command; the approval of each exact artifact is recorded), the consent ask (`Y`
  reads Socket again with the consent, `n` proceeds without it and records the acceptance), the pending-score confirmation, an
  adverse finding (the adverse override), and an outage (the deliberate confirmation, for this command, recorded nowhere).
  **Missing evidence:** the deliberate confirmation of the infrastructure ruling, for this command, recording nothing, never
  `[a]`; the lockfile is then not recorded as judged, so what could not be judged is judged again the next time and is never
  read as already present. A decline ends the command with the exit of the class left (104, 102 or 100). An acceptance is
  recorded when it is given, in today's stores by today's writers (`safe audit record-installed`, `safe-run host-allow`),
  on the operator's established root (`$HOME/.config/safe/run`: never a redirect the environment names) and with the programs
  beside the dispatcher (the auditor inside `safe-run` included; a missing sibling `safe-run` refuses, it is never looked up on
  the `PATH`), so the standing acceptances clear the same command the next time without a prompt. **A read from the terminal
  that fails (end of input) authorises nothing**: it ends the command 102 before anything is written, apart from an explicit no.
  **Each class is shown within one command:** an answer clears its own class for this command and is recorded when given, so
  the next command reuses it; the other classes at stake on the same artifact (an advisory, then a wait, then a pending Socket
  score) are still asked. Each prompt lists only the unresolved items of its class (an advisory over two versions with one
  accepted lists the other); a Socket BLOCK is malice and is asked there only, once per artifact with all its signals; a block
  that is also malice is never recordable. A named root whose outcome the operator confirmed (an adverse override, a Socket
  consent declined, a pending score confirmed) is recorded after a verified publication through the same `record-installed`
  (`WARN_TTY_OVERRIDE`, `GO_SOCKET_DECLINED`, `GO_PENDING_CONFIRMED`: exportable), as the FINAL decision leaves it eligible:
  under the SAME eligibility as an ordinary record, over the root and every byte it carries: the root was introduced by the
  command, no advisory at high or above stands on its bytes (an inherited one, a bundled member's) except one the operator
  accepted in this command, it relies on no followed authority for any of them, and nothing excludes the command as a whole
  (confirmed missing evidence, a confirmed Socket outage, a malice or block override record nothing). New adverse
  evidence revokes the receipt it supersedes at once, after every reading. A routing refusal and a baseline from history that cannot be read have their one-command confirmation (see **The one-shot route, by the operator**); a graph the lane cannot bind has no confirmation for one command, and its way out is the operator's standing decision for the project (**The standing decision per project**, below). A cancellation (TERM, INT) at a prompt, or while the `[a]` grant is being reconfirmed, ends the prompt and the writer and frees the project lock; the acceptance already given stays, nothing is granted or published. A dry run, by argument or by npm's configuration, is never prompted. When
  the prompts end the evidence may not be older than 15 minutes counted from BEFORE the first evidence read
  (`install.lane_evidence_window_seconds` in the operator's configuration may shorten it), checked immediately before the
  baseline is recorded and again immediately before the binder starts: otherwise the command is refused, and what was accepted stays recorded, so the
  rerun asks nothing again. An agent session is never prompted: it ends as it does unattended.

  **The one-shot route, by the operator.** For ONE command, at the operator's terminal only. Every refusal of the lane *records*
  itself and returns; the final line is printed once, at the lane's top level, after the lane's lock and scratch are freed. A refusal
  is **confirmable** only when the site gives it an explicit kind from a closed list, and only in the routing phase (before the first
  evidence reading); there is no default. The kinds, which are what the lane loses by not judging the closure: *command form* (a spelling
  of global mode, an option before the verb, the option terminator, a workspace selection, a `--prefix`/`--cwd` selection, a combination
  the lane does not carry, a package named to `update`, `ci`, `dedupe` or `prune`, a name with a glob character, a version that is not
  exact, `mise exec`); *project shape* (an unsupported source or a legacy lockfile in uncommitted changes or outside git, a regular
  `npm-shrinkwrap.json` (the question says npm would use it), no lockfile, a plan that is not lockfile version 2 or 3, an unrecognised
  lockfile version, a private-registry name); *npm capability* (an npm that lacks what the lane needs); *baseline history* (the
  lockfile committed at the head cannot be read, when it is not the file on disk); *npm setting* (an ordinary setting the lane cannot
  carry). **Never confirmable**, whatever names it (an option, the environment, an effective configuration): an input npm or Node would
  load at start-up or a storage destination, which are the configuration keys `node-options`, `script-shell`, `onload-script`,
  `userconfig`, `globalconfig`, `cache` and `logs-dir` and the environment's `NODE_OPTIONS`, `PREFIX` and `DESTDIR` (every other key is an
  ordinary setting; a key in doubt is on the list), a project `.npmrc` setting, a launcher the lane cannot identify; a link or special
  file where the lane needs a regular one; a live lockfile that is unsafe (a key outside the tree, an unsafe link) or not completely
  decoded (an entry that does not decode never hides an unsafe key: the core's admission reports every finding by code and the shell
  branches on the code, an unsafe one first); a project inside a workspace root; the lane's own safety (its project, storage, lock and
  programs), the reused guards, npm's own errors, and everything at or after the first evidence reading, after a decision or in the bind
  phase. Their way out is to remove the cause, and their line names no confirmation. At the operator's terminal the lane asks once
  (through the same outcome handler as every prompt: a failed read is 102 and no answer, an agent session is never asked) what is not
  judged and whether to run the command on the one-shot route. The question writes nothing and hands the command to today's gate as
  written, so it is asked whether or not the command is a dry run. Yes ends the lane at once (nothing is projected, read, recorded or
  published) and today's gate runs the command exactly as with the switch off, its own receipts included, after the line `[lane:
  one-shot, …] — the closure is not judged on this route` (for `dedupe` and `prune`, the older differential path, which judges them
  where it can, refuses the rest and has no override of its own). A confirmable refusal's final line says the operator can confirm at
  their terminal. A graph the lane cannot bind has no confirmation for one command: its way out is the standing decision below.

  **The standing decision per project.** `safe run one-shot-project add [dir…] | remove [dir…|key] | list`: the lane is OFF for a
  project, so a command npm will run on it goes to today's gate before the lane looks at anything, with the one-shot line (the
  closure is not judged on that route; `dedupe` and `prune` go to the older differential path). It is for what the lane cannot drive
  (an npm older than 11.17.0, an environment it refuses, a graph it cannot bind), worked on by agents who cannot confirm anything.
  It gives no approval, no receipt and no baseline. `add` and `remove` are checked by the PROGRAM that writes the store
  (`safe-core one-shot-store`: stdin a terminal and none of the four agent markers, else 102 before anything is touched, whoever
  calls it), which resolves, shows the identity it will commit, asks on the terminal and commits under a lock in one invocation; the
  shell subcommand only delegates and writes the audit log once the core reported the commit. The store,
  `one-shot-projects.json` under the operator's established root (`$HOME/.config/safe/run`, never a redirect), is one strict,
  bounded (64 KiB) document read and written only by the core, through verified directories and one descriptor (no link, each
  directory the user's and closed to group and others, a file of mode 0600 with one link, a lock file checked the same way); the
  staged file is created with its final mode; a failure before the rename says "not recorded" and a failed directory sync after it
  says "committed and visible, durability uncertain" (exit 4). An entry is the physical path of the project directory (its bytes,
  resolved by the kernel: `link/..` is the parent of what the link leads to) with its device and inode and the time it was added; it
  carries no reason (the audit log attributes it). `list` is read-only and creates nothing; exit 3 means the store cannot be trusted
  (told apart from an empty list). **How the lane reads it:** in one place, right after it captured its project directory and BEFORE
  any lane-specific refusal (a spelled `--location=project` on a pinned project reaches today's gate; a plain `-g` command is handed
  over first and never consults a pin), with two kinds of question. First, on data alone: is the directory the command runs in, or one
  of its ancestors, a stored pin by identity? If none is, nothing more happens and no npm is run. Then npm, two read-only answers
  from the npm that will run the command (the command's own arguments, the command word replaced, everything else in place): `npm
  prefix` and `npm root`. The question never asks npm to keep no logs and never touches the caller's environment: it gives npm a cache
  and a logs directory of safe's own, in a private scratch directory made for the two questions and removed whatever ends them (a
  normal end, a failed question, the deadline), and keeps the update check off. These are the FIRST arguments npm gets, each with its
  value attached (`npm --cache=<scratch> --logs-dir=<scratch>/_logs --update-notifier=false <the command's arguments, the command word
  replaced>`): nothing precedes them, so no option of the command can take one as its value and no terminator (`--`, `---`) can
  turn them into operands, and no argument boundary is computed. An option of the command later on the line still wins, as it does for the
  command itself: when the command's own line names a cache or a logs directory, npm writes there as the command itself would (an
  environment variable naming one loses to the question's options and receives nothing). `--logs-dir` is harmless where a version does
  not define it (npm 8.1.0 keeps its logs under the cache). The question runs in the environment the delegate gets: the same scrub of
  the caller's script policy and the same preparation of the delegate's environment (one function, shared with the exec), in a
  subshell. What only becomes known after today's gate has judged the command is the accepted window: the scripts-allow injection
  (`npm_config_ignore_scripts`, `npm_config_allow_scripts`, `npm_config_strict_allow_scripts`) is not in the question's environment. The pin is honoured only when both exit 0 and print exactly one line, the root is exactly `<prefix>/node_modules`, the
  prefix names a pinned directory by identity (opened by the core, never taken as text) and that directory's `node_modules` is not a
  link. The prefix is what tells global mode from project mode: a project named `lib` under a global prefix prints the same root as
  the global tree. ONE deadline (10 s) covers the whole route: the core's version check, the delegate's resolution, both questions and the verification; when
  it expires nothing is pinned and the lane goes on. An undetermined answer is no pin. **Under
  `mise exec` the pin is not used** (the inner gate runs the ambient npm, the outer mise may run another one, so the question
  could go to the wrong npm): the command meets the lane as if nothing were pinned. The window between the question and the command
  is the ordinary one of any check made before a command (a directory replaced in it is the accepted residual below). **Accepted limits:** a command that
  selects a workspace (`-w`, `--workspaces`, or `workspace`/`workspaces` set in a file) is not served by a pin (npm gives no answer
  for it); a pin on a workspace member is not honoured where npm acts on the root above (npm 10 and later search across a git
  boundary; npm 8.1.0 does not search); the question runs npm's start-up twice for a command under a pinned directory even when the
  pin is then not honoured, and a caller who controls npm's start-up controls the answer (the same boundary as today's gate); a
  remount at the same path with the same device and inode, or a reused inode, cannot be told from the pinned directory; a process
  allowed to write files as the operator can write the store. What the real npm prints on 8.1.0, 10.9.2, 11.20.0 and 12.2.1 is held
  by `tests/live/standing_pin_npm_oracle.sh`. On a home that holds a debug log, an
  update-check stamp and a cache, the home is byte-identical and time-stamp-identical after both questions on all four, for a plain
  command, a failing question (a workspace selection), a trailing value-taking option with no value, `---` and a terminator; on a fresh
  home the question writes no file and opens no internet connection. The pin serves plain project
  commands, not workspace selections, and a command that selects a workspace is not served.

  **Standing acceptances.** The decision takes the operator's standing acceptances as a document of its own, read by safe's
  own reader (`safe audit lane-acceptances`, which calls the functions today's install gate calls and has no store, format or
  rule of its own) for exactly the artifacts a first decision leaves outstanding, from the stores where the lane reads its
  switch (`safe_gate_trust_store_file`; a store root the caller names is never read), and the decision is made again with
  them. A reader that fails gives no acceptance: nothing is cleared. What clears what: a **local exact approval** (the
  source-bound gate consent, or an exact local host-allow pin that is not a followed copy) clears a blocking advisory, an
  adverse advisory, a wait and a Socket outcome of that artifact; a **followed advisory override** (signer, generation,
  ecosystem and source checks of the follow ledger) clears a blocking advisory only when it covers every blocking advisory
  of the artifact; a **followed grant** and a **followed install allowance** clear an adverse advisory, a wait and a Socket
  outcome, never a blocking advisory; the standing **tolerance** (`install.auto_allow_tolerate`) clears a wait or a Socket
  result that is a WARN only when every cause of it is listed and the artifact has no affecting advisory at all, on the artifact or on a member its bytes carry (today's
  predicate), never an advisory, never a consent ask or a pending score. Bundled bytes are judged under their covering
  artifact: an acceptance is for the artifact whose bytes carry the advisory, and a followed override must cover every
  blocking advisory the evidence shows under those bytes, inherited or new, once one is introduced (the trigger stays
  differential). The tolerance's veto covers the artifact and every member its bytes carry.
  Nothing clears malice, a graph that cannot be bound or missing evidence. What nothing clears ends the command with its
  own exit, in the decision's order. There is no terminal prompt for these classes yet (the operator terminal is its own
  ticket).

  **Install records.** The lane writes no record itself and takes no verdict from its caller: no command turns a caller's
  statement into a receipt. After the binder reports a verified, published tree, and only then (a refusal, a failed
  materialisation, `--dry-run` and `--package-lock-only` audit and record nothing), the lane asks today's auditor to audit,
  by its ordinary path (`package-audit <name>@<version> --gate install`, stdin closed, no consent carried, under the gate's
  leash), each **named root** that the decision left eligible and that the published tree holds (a root the tree does not
  hold, deselected by `--omit` or a platform, is not audited). That audit records, or does not, by its own evidence and its
  own rules, exactly as today's gate does for a named install: `install.auto_allow=false` writes no clean receipt; a Socket
  reading that was not made is recorded as today's reasons say (`socket_out_of_scope`), and a Socket reading switched off is a
  WARN that records nothing; a tolerance applies with today's own predicate (`WARN_TOLERATED`); a root a followed authority
  clears is not audited, and a followed pass would carry a token the export never takes. The decision's eligibility
  (`records` in the report) is a filter, necessary and not sufficient: a named root, with its own complete advisory reading,
  nothing at high or above in the bytes it carries (a bundled member's included, introduced or already present) and a clear or
  tolerated Socket result. Never audited for a record: an introduced artifact nobody named (a bare install, update, ci, dedupe
  or prune names no root), a root cleared by a local approval, a followed grant or a followed install allowance, one that
  passed only because its advisories were already present, anything after missing evidence, a block override or the one-shot
  route. At most 16 roots are audited per command; the lane reads back what the store holds and says what was recorded.
  **Revocation:** when the decision establishes adverse evidence on an artifact (malice, a blocking or adverse advisory, a
  Socket finding, a young version), the receipts of the exact identity the evidence is on and of the artifact whose bytes carry it
  (a bundled member's covering artifact) are removed by `safe audit lane-revoke`, bound to the exact version and the default
  registry source. It is a local operation that only removes: it never audits, never reaches the network and cannot create,
  promote or refresh a receipt (it deletes through the function today's audit uses when its evidence supersedes one); it has no
  limit on the number of receipts, and operator approvals are not receipts and are untouched. It runs whatever the command's
  end (a refusal, a dry run). The audits that can WRITE (the ordinary audit of a named root) run only after a verified
  publication, for the named roots the binder reported present among the direct packages of the tree it published
  (`verification.present_direct`; the lane does not look at the tree again), at most 16 per command. With `install.cooldown_days`
  set, a root is submitted only on an exact reading of its publish time; with the cooldown off (0) it is as eligible as today's
  gate makes it. The lane compares the receipt before and after and says whether the audit wrote, left unchanged or removed
  it, and a block or an adverse result the audit sees on a root that was just installed is printed as a finding of its own
  (`FINDING: <package> is installed, and today's audit now reports a BLOCK`), the command's exit unchanged. The signed export
  takes the receipts as it takes today's. The signed export takes the receipts as it takes today's. A named root whose outcome the
  operator confirmed at a terminal is the third eligible kind and comes with the operator terminal.

  **Socket on a named root.** The artifacts the command names are scored by Socket as today's per-root audit scores
  them, and nothing else is: one call of the auditor beside safe's dispatcher in its evidence-only mode
  (`package-audit --evidence-only`), whatever the number of roots, and never for an artifact from a private origin.
  What is scored is the projected root: each named operand is tied to its direct occurrence in the projected lockfile
  (npm resolves `pkg@1.0.0+build.1` to `1.0.0`) and that occurrence's public identity is asked; an operand that cannot
  be tied is a coverage gap of the command (102: nothing is published, nothing is skipped; an established block still
  decides 104 first). The cooldown keeps its own exact-argument rule. The reader runs with the core
  installed beside the dispatcher (the one the lane verified, whatever `SAFE_CORE_BIN` the caller's environment names)
  and takes the Socket tool from the operator's tool configuration (`tools.json`, then the standard install
  directories), never from `PATH`; today's gate keeps its own choice until ticket 1682. Its answer is validated before
  it is used, on its original bytes: one document, no member repeated at any level (`safe-core repeated-members`), the
  complete envelope, then exactly one consistent row per identity asked; anything else is missing evidence (102) and a
  whole row or block beside it is kept. Each call gets a private temporary directory the lane made and removes whatever
  ends the call, and the rows a batch completed before a deadline survive (the rest are unavailable). Without a deadline
  utility the reader is not started (102). A failed advisory reading is missing coverage too: the cached blocks are
  still judged and decide 104 first. Each call has a deadline (the gate's own leash for one audit, plus
  the Socket part of one more audit per extra root; 120 seconds for the cache reading; `SAFE_INSTALL_TIMEOUT_SECONDS`
  overrides both): expiry is missing evidence (102), and a block already established still decides (104).
  The result is a class of the decision, after the cooldown's wait and before missing evidence, with today's exits and
  diagnoses (the recovery text is the lane's own: it names an action that works without a prompt): an adverse finding
  (low score, alerts, no record) stops 100; a rate limit, the consent ask of a fresh release, a pending score and an
  unavailable audit infrastructure stop 102; a critical supply-chain-risk alert is malice, 104. Every public
  identity of the target graph, bundled members included, is read from Socket's cache alone, with no call, each
  requested entry on its own: a blocking result already cached for any of them is malice (104) whatever else fails; an
  entry that is present and cannot be read, or is dated in the future, is a gap (102), never a clean cache. The
  reading writes nothing, from a cold start (no registry, no log, no cache entry, no audit-log event). The lane has no
  terminal prompt for these results yet and no acceptance clears them yet: the consent ask and the rate-limit approval
  are stops, and the install gate's host-allow hint does not apply on the lane; to take the terminal answer, run the
  same install with `install.project_lane` off, where today's gate asks. A named root's own advisories gate only when
  the command introduces them.
  A lockfile entry the frozen installation does not build (one nothing in the manifest needs) is caught by the
  binder's tree verification before anything is published, and the refusal says to run `npm install` first.
  npm's `prune` writes its lockfile in every case where one exists. Every npm run whose output the lane reads
  (the frozen check, the projections) carries its own heading, no colour and a log level that shows errors
  (the selected npm must define them), so the caller's presentation settings cannot hide npm's error; when no
  error line can be read the cleaned end of npm's output is shown and the final line says so. An option before
  the verb refuses before npm is asked about the token (safe's and npm's readings of which word is the command
  can differ there). The lane substitutes a canonical verb only when the selected npm itself
  resolves the caller's token to it: a token the gate's conservative classifier takes for one of the
  lane's verbs and npm does not resolve (`clean`, `install-c`, an ambiguous prefix) is left to npm
  (today's gate exactly as with the switch off, which delegates it for npm's own rejection); the lane
  does nothing with the project and refuses nothing in npm's place. That holds only for a token npm
  resolves to no command: a token npm resolves to another command than safe's table does refuses (the
  table does not match that npm, and nothing says npm would reject the command; none does on the npm
  the table was taken from). `ci`: no projection; the plan is the lockfile on disk, checked against the manifest by npm's own
  frozen check (`npm ci --dry-run` in the scratch copy: whatever npm refuses, a lockfile out of step with
  the manifest, a missing one, a platform error, is npm's own error: npm's code and message, taken from
  wherever they are in its output, are shown without its log noise or usage text, the exit status is
  npm's, and the final line says only that npm's own frozen check failed, with npm's code), judged against the baseline (a lockfile
  on disk identical to the committed or to a recorded one introduces nothing, so its advisories are
  reported and never gate; any other is judged against the committed one, else empty). Malice is read over
  the WHOLE graph every time (blocklist by name, known-malware records), entries the command would not
  materialise included, and every entry must be bound; the advisory request therefore covers every
  identity of the lockfile. The binder then runs one frozen `npm ci` in staging, verifies the tree and
  publishes it, replacing an existing tree. `ci` says how many entries of the lockfile it checked for malice
  (or only submitted for the check, when some identities could not be read completely), which baseline it
  used, and how many advisories are already present, with their severities. `ci
  --package-lock-only` refuses (npm does not define it), and so does `prune --package-lock-only` (the
  lockfile-only caller mode belongs to `install`, `update` and `dedupe`); `--dry-run` decides, reports and writes nothing.
  A clear `ci` records its lockfile as judged, like the other verbs. `dedupe` and `prune` name no
  packages (that refuses), and have no gate other than the lane: an established shape the lane cannot
  judge, which sends `install` and `ci` to today's gate, refuses for them. The older differential path
  (one audit process per introduced artifact, resolved again by npm after its checks) is reachable only
  with the switch off, until the cutover deletes it.
  **Condition for turning the lane on:** the host's npm configuration (the operator's user and global
  configuration, the environment) must be one the lane supports (the canonical public registry, no
  install strategy other than hoisted, no workspaces, no `legacy-peer-deps`, no cache or log destination
  inside a project, and so on). The lane makes **no attempt to tell the host's choice from the caller's**:
  an npm setting it cannot carry **refuses, naming the setting**, whoever set it.
  **The checks.** The caller's arguments and environment, special files, the admission of the project's
  `.npmrc`, manifest and lockfile (a lockfile with ANY unsafe finding refuses whatever else it holds,
  committed or not: a key outside the tree, a link leaving the project, an identity that cannot stand in a
  URL; every reason of every entry is reported, a link target is judged on the path it resolves to on the
  filesystem, and none of this depends on the declared lockfile version; a lockfile that declares version 2
  or 3 and has no package map cannot be decoded: 102), the
  private-name guard and, when the project's `.npmrc` was admitted, the effective npm configuration, the
  capability and parser probes and the guards of the lane's own invocation. A refusal from any of them ends
  the command. A cause that is only *unsupported* is accumulated with its own text and its own source
  files. **One decision after all of them:** the **one-shot route** is for an *established project shape*
  only: every file a cause comes from (`package.json`, `package-lock.json` or `.npmrc`) is committed at the head of the project's git work tree and byte for byte what is on
  disk (the bounded git reader). The causes: a *recognised legacy* lockfile (version 1, or no version declared
  with the legacy dependency map and no package map; any other version is refused), lockfile entries the
  lane cannot bind (a source that is not a registry package, no integrity, another host, an in-project
  link, an entry with its own shrinkwrap), committed dependencies or overrides that are not registry
  packages and a committed `.npmrc` setting outside the allow-list. With an admitted `.npmrc` the decision
  is taken after every configuration probe (effective, parity, frozen, platform selection) has refused
  nothing. **An npm without the capabilities the lane needs refuses**: what selects a tool version (a
  lockfile of the version manager, a profile, the environment) cannot be established from the project, so
  the lane reads none of it; the refusal says the operator can confirm the one-shot route for that command
  (see **The one-shot route, by the operator** below). Capability metadata that is
  malformed (a version that is not a semantic version, definitions that are not a map of options) is a
  failed probe: a refusal. When the project's `.npmrc` was not admitted no npm of the lane reads that project: the decision
  is taken at once and today's gate applies its own checks. The command then goes to today's gate exactly
  as with the switch off, after ONE stderr line `safe: project lane: npm <verb> [lane: one-shot, <reason>]
  — the closure is not judged on this route`; the lane ran in a subshell, so nothing it set, exported or
  trapped reaches the delegate (the lane's parent acts only on its exit status, one reserved value of which,
  253, means "hand this command to today's gate"). The `install-test` families (`install-test`,
  `install-ci-test`, their aliases and prefixes: `it`, `cit`, `sit`, ...) are classified apart from
  `install` and `ci` and always take the one-shot route, with the reason "its test phase runs project code".
  **Refusals** (`safe: BLOCKED npm <verb> [lane: project] — … ; details: safe explain`, one final line
  naming the cause and the way out; none suggests turning the lane off): a command-line or environment
  setting (the environment variables `PREFIX` and `DESTDIR`, which select where npm's configuration loader
  reads its files from, refuse by name before the environment is replaced); an npm configuration the lane
  cannot carry, global mode set by configuration included; a failed guard; the same shapes when one of the
  files they come from exists only in uncommitted changes (mixed causes included) or the project is not in
  a git work tree; an unsupported option; a workspace; a launcher the lane cannot follow; a failed probe;
  `npm ci --package-lock-only`; and naming packages to `ci`, `dedupe` or `prune`. **Unchanged**: a global command, which is only a command whose
  arguments say so in the plain form (`-g` or `--global`, with no value; no npm run decides the route, and
  any other spelling that selects or negates global mode, `--global=…`, a separate boolean value,
  `--no-global`, `--location…`, refuses with the plain form as the way out), `npm exec`, `npm uninstall`, every other verb and every other manager.
  **`mise exec -- npm <lane command>` refuses**, with the lane's line and the way out: mise would run the
  original command after an audit that binds nothing; run npm in the project directory instead (the mise
  shims select the same tools). A plain-form global command, an inner command that
  is not a lane command (`npm view`, `npm install-test`, `npm uninstall`) and every other tool mise wraps
  behave exactly as without the lane. Whether the lane should own `mise exec` is the operator's decision
  and its own ticket.
  `--dry-run` runs the decision
  and the report and writes nothing. `--package-lock-only` judges as usual, then
  publishes the judged `package.json` and `package-lock.json` (the binder's
  files-only mode: the same checks on the live inputs, the same atomic exchange of
  each file, no staged tree, no tree exchange, no install command) and installs
  nothing. Each decision report is kept under
  `project-lane/reports` in safe's data directory. Spec: Safe Lanes slice 1.
  **The baseline** is what the differential is taken against, and what decides which
  advisories are "already present" and never gate. It is the lockfile committed at the
  head of the project's git work tree, or one safe itself judged clear and recorded (below);
  the report says how many entries added on disk (and still in the judged target) were judged as introduced and
  `safe: project lane: baseline: …` names which baseline was used: committed, recorded or
  empty. With no lockfile on disk and nothing established the baseline is empty and the whole
  resolved graph is introduced. A *committed* lockfile that exists but cannot be read or
  decoded is missing evidence (exit 102), never an empty baseline; a recorded one that cannot
  be trusted is ignored. A project outside a git work tree has only the recorded baselines, or
  none. **The recorded baselines.** safe keeps, per canonical project path, the lockfiles it
  judged clear on complete evidence, each under its own digest:
  `project-lane/state/project-baseline/<sha256 of the project path>/<lockfile name>/<sha256
  of the bytes>` in safe's data directory, outside the project. A record is the lockfile's
  bytes. At most 16 records are kept per project and name: when one is written the older ones
  (by modification time, the entry being written counted so the bound holds) are pruned, best
  effort; a pruning that fails or goes wrong is not an error and only makes more be judged. A lockfile is recorded right
  after a decision that is clear on complete evidence and **before** the binder runs, full
  or files-only; if it cannot be recorded the command refuses (102, "cannot be recorded")
  and nothing is published. A dry run, a refusal and a command with missing evidence record
  nothing; recording a lockfile that is already recorded only refreshes its time. A record is
  trusted only when the bytes read hash to the digest it is stored under and it is a regular
  file of mode exactly `0600` owned by the user; anything else (corrupted, truncated, linked,
  another mode) is **ignored**, named once on stderr as an ignored record, and never an error:
  ignoring a record only makes more of the graph be judged. The directories of the chain
  belong to the user, are not writable by group or others and are never links, and are held by
  descriptor. Whether a publication completed does not matter to the baseline: if it did, the
  lockfile on disk is the recorded one; if it did not, the lockfile on disk is still the
  previous one, which is recorded or committed too. A recorded lockfile is a baseline whenever
  and however it comes to be on disk: restoring a judged lockfile by hand is the same as
  checking out an old commit. Two path names for one directory are two stores, and a missing
  record only makes more be judged.
  **The rule of choice.** The committed lockfile is read first, with three outcomes (below);
  a present one must decode (it does not: missing evidence, 102, whatever the lockfile on
  disk holds). The lockfile on disk is the baseline (`committed`) when it is byte-identical to
  the committed one, or (`recorded`) when its digest names a trusted record. Otherwise the
  baseline is the committed lockfile, else empty, and the entries the lockfile on disk adds are
  introduced. **A record is a baseline only when the lockfile on disk is byte-identical to it:**
  nothing falls back to "the most recent record", because that could be a plan judged clear whose
  installation failed, and an advisory disclosed in between would count as already present on a
  package the project never carried. The cost, accepted: in a project with no committed lockfile
  a lockfile edited by hand is judged whole. A record that cannot be trusted is ignored (named
  once: it is no match, and the baseline used instead is said).
  **The committed lockfile** is read with three outcomes: present, *established absent*
  (no git work tree, an unborn branch, or no `package-lock.json` in the head commit's tree)
  and unreadable (102: a git that cannot be bound to local reads, a repository that cannot be
  probed or that git does not select where the `.git` is, a `HEAD` that does not name a commit,
  a reference whose lookup fails, a missing or corrupt commit, tree or blob, a blob whose hash
  is not its name, a tree entry that is not a regular file). The lane **requires a git that can
  disable lazy fetches** (git 2.45.0 or newer; 2.44.0 lacks the option; the lane does not trust the version alone: every
  git call passes `--no-lazy-fetch`, and a probe with that very invocation, on a command that
  cannot fetch, must succeed, else the committed lockfile is unreadable). The workspace probe
  uses the same bounded invocation. git discovers the repository once, from the project
  directory, in one git process, and every later command names that git directory and work
  tree explicitly; every path handed to git is literal (`--literal-pathspecs`), the project's
  directory must come back as exactly one NUL-delimited entry of the path asked for, and the
  raw tree reader validates the mode and the framing of every entry it walks and refuses a
  tree it could not read whole (never an absence). A project path with a newline in it cannot
  be captured exactly by the shell and refuses before anything is opened. None of the
  caller's `GIT_*` variables reaches git; replacement objects are disabled. Reference absence is
  decided by git's own `show-ref --exists` (missing is distinct from a failed lookup). The raw
  tree-entry mode is read from the raw tree (git shows `100664` as `100644`): accepted are
  `100644`, `100664` and `100755`; `120000`, `160000` and anything else are unreadable. Object
  identifiers along the tree path are not re-verified (whoever can forge an object in the
  repository can also make a commit, which is a baseline by ruling). Only an established absence
  lets the empty baseline apply. Every lockfile on disk, the baseline or not,
  gets the binding and link checks and the binder's own lockfile admission (every key a chain
  of package segments inside the tree, no link entry, whether or not anything references it)
  before npm uses it. No private-registry name goes to the public advisory service: the matcher
  runs, case-folded for the purpose of refusing only (no grant is widened), over the evidence
  request itself, the baseline side included, and every identity in it must have an exact
  version (a bundled member's included).
  **The project's own `.npmrc`** is read by safe, as text, before any npm runs in
  the project's context (a special file or a link there refuses first). It is
  admitted against a short allow-list, and anything else refuses naming the
  setting (never its value): `save-exact`, `engine-strict`, `fund`, `audit`
  and `progress` (`true` or `false`), `save-prefix` (`^`, `~` or
  empty), `loglevel` (npm's levels), `registry` and `@scope:registry` (exactly
  `https://registry.npmjs.org/`). The reader takes the ini subset npm writes (one
  `key=value` per line, `;` and `#` comments, blank lines): a section,
  interpolation (`${`), a continuation, a quote or an inline comment, a repeated
  setting, a byte-order mark or a line it cannot parse refuses. Not admitted, among
  others: cache, logs, prefix, location, global, any other registry, authentication,
  proxy and certificate settings, script and git settings, release-age settings,
  workspaces, and the package-lock and dry-run switches.
  **One runtime, one environment.** The lane resolves, once and in the project's
  context, the npm the gate's delegate would run there (behind a version manager's
  shim, the real manager is asked, `mise which npm`). Two forms are supported and
  anything else refuses: (a) the launcher a version manager names, inside its own
  installation with its Node beside it, **executed as it is** in every phase (it
  picks its own Node, so the npm that runs is the one the manager chose), the
  sibling Node serving only the lane's own Node runs (probes); (b) npm's own CLI
  file, or a link to it, run by the Node beside the link. That one npm is used for
  every probe, the projection and the frozen install, from the project, a scratch
  directory and the binder's staging directory alike; nothing is resolved again.
  Every one of those runs gets exactly this environment and nothing else of the
  caller's: `PATH` (the Node's directory, then `/usr/local/bin:/usr/bin:/bin`);
  `HOME`, `USER`, `LOGNAME`, `LANG`, `LANGUAGE`, `LC_*`, `TZ`, `TMPDIR` (where npm
  finds its configuration, and the locale); `NODE_ENV` (npm's default omission of
  development dependencies follows it); `SSL_CERT_FILE`, `SSL_CERT_DIR`,
  `NODE_EXTRA_CA_CERTS`; `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, `ALL_PROXY` and
  their lower-case spellings (how npm reaches the registry); every `npm_config_*`
  setting except the script policy, `git`, `allow-git` and `node-options`, which the
  lane sets itself (so npm reads the same configuration in every phase, and the
  parity probes compare it); and `NODE_OPTIONS` only when it carries
  `--max-old-space-size`, `--max-http-header-size`, `--stack-trace-limit` or
  `--no-warnings`. A Node option that would load code (`--require`, `--import`, a
  loader, an inspector) cannot be carried, and the command refuses. `MISE_*`,
  `NODE_*`, `SAFE_*`, `BASH_ENV`, `LD_*`, `SSH_AUTH_SOCK`, `CI` and the rest are
  dropped. The lock descriptor is closed in every child.
  **Nothing is written into the project before publication.** Every npm command of
  the lane carries an explicit cache and log destination in safe's own private
  directory (`project-lane/npm-cache`, `npm-logs`, under the data directory) and
  `--replace-registry-host=never` and `--update-notifier=false` (forced, so it is not a
  project choice), so a resolved location is fetched as written. No file the
  project controls is read as configuration before the project is admitted: the
  caller's own arguments may not select a configuration file or a destination
  (`--userconfig`, `--globalconfig`, `--prefix`, `-C`, `--cache`, `--logs-dir`,
  refused at the shell before any npm runs); the route is decided from the arguments alone, with no npm probe. The operator-level destinations found
  in the environment (`npm_config_cache`, logs, prefix, user and global
  configuration, in either case) are read the way npm reads a path setting
  (trimmed, nothing else interpolated): one that is not a plain absolute path
  after that (blank, `~`, `${…}`, relative, a control character) or that lies inside
  the project refuses; the storage paths of the lane are made canonical and absolute
  once, and a link in them is judged by where it leads. A project that sits inside
  a workspace root (an ancestor up to the git top level declaring `workspaces`)
  refuses. safe's data directory
  and the temporary directory must not overlap the project in either direction, the
  lane's directories are private and not links before they are used, the committed
  lockfile comparison reads the git objects with replacement refs disabled, and
  every copy is verified. **Admission** is npm's own classification: in Go
  (`safe-core project-admit`, checked against npm's classifier by
  `tests/live/npm_spec_oracle.sh`) and then again by the selected npm's own
  `npm-package-arg` and `validate-npm-package-name`, over the same strings: command
  arguments (`name@x.y.z` exactly), manifest ranges, typed overrides (a `$name`
  reference is resolved against the root's own declared dependencies as npm
  resolves it, and refuses when the root does not declare it), and the dependency
  edges of the committed lockfile must be registry packages, or the command
  refuses. The agreement is asked again on the **final** admission (the
  projection's manifest), before a dry run returns and before binding. A committed
  lockfile that safe's core cannot decode (a wrong shape, a repeated member) is
  missing evidence (exit 102); one it reads but cannot support stays a policy
  refusal (100). A scope mapped to the canonical public registry is accepted; a
  scope (or the configured default scope) mapped elsewhere refuses when a package of
  the judged graph, one first found by the projection included, belongs to it.
  **Capability:** the npm must be at least 11.12.1, compared with npm's own semver
  (the oldest release found to define `allow-git`) and its own definitions module must define every option the
  lane passes (`allow-git`, `git`, `replace-registry-host`, `cache`, `logs-dir`,
  `logs-max`); an npm that merely echoes an option in its configuration listing
  (10.9.2 does) refuses. **Selection:** omissions, os, cpu and libc are computed
  once, by the selected Node with npm's own modules over npm's effective settings
  (libc judged against the effective os), and passed as one checked document. A
  platform value carrying a NUL refuses. The lane runs no auditor of its own for the
  private-registry store: one matcher (the store's namespace rules) is applied to
  every name the lane knows (manifest names and ranges, the paths and legacy
  identities of the committed lockfile, the names the projection adds) before any
  public evidence is requested, and a project that touches an entry of a non-empty
  store refuses (trusted private origins are not supported yet). Everything npm, the
  binder or the project prints is cleaned (control characters, bearer and basic
  authorisation, credentials in URLs, queries and fragments; headers in any case; Unicode
  format characters) at the lane's boundary,
  the last partial line included; npm's exit status is kept; a signal to the shell,
  from before the binder starts until its report is delivered, is forwarded to it,
  and a binder that dies of it before it produced a document is an interruption
  (128 plus the signal), not a refusal.
- `reuse.enabled`: per-host rule for `safe install --reuse` (default `false`).
  `true` lets the reuse of an installed `vendor/` or `node_modules/` from
  another checkout of the same repository run unattended, agents included; reuse runs no audit, and its
  receipt says so. `false` keeps each
  reuse an operator decision at an interactive terminal (exit 102 otherwise).
  Only the JSON boolean `true` enables it, and only from the canonical run
  store: a redirected config root needs `SAFE_RUN_TRUST_OVERRIDE`. See
  [reuse of installed dependencies](command-reference.md#reuse-of-installed-dependencies).
- `block_severities`: affecting-advisory severities that hard-BLOCK instead
  of WARN. Values use the severity ladder's vocabulary (`critical`, `high`,
  `moderate`, `low`); spelling is normalized (case-insensitive, `medium`
  reads as `moderate`), so write the ladder words.
- `cooldown_days`: WARN when any resolved version was published fewer than
  this many days ago (the compromised-release window; malicious versions are
  usually caught and yanked within days). Default: `3`; `0` disables. The
  WARN is overridable (exact host-allow pin, or `release_too_new` in
  `auto_allow_tolerate`); a failed publish-date lookup skips the check with
  a disclosed note, never a refusal.
- `cooldown_security_fix`: `exempt` (default) or `enforce`. A cooldown that
  blocks the release fixing a published CVE recreates the catch-22 this gate
  was built to end. When the resolved version IS the remediation — an
  advisory's `fixed` version equals it — `exempt` waives the cooldown and
  names the advisories it remediates, on the verdict line and in the
  receipt (`release.cooldown_waived`, `release.remediates`). `enforce`
  keeps the wait, on the reasoning that a compromised-maintainer release
  can carry a genuine fix as cover; the refusal then says the version does
  remediate and that this setting caused the refusal. The exemption only
  applies to advisories fixed AT a resolved version — it never waives the
  cooldown for an ordinary feature release.
- `socket.mode`: Socket is the primary behavioral tier. `auto` (default)
  scopes it per the fresh-window rule below and asks the operator before any
  live call; `always` keeps the pre-scope behavior — an unconditional call on
  every in-scope check, no consent prompt; `never` is the sole intentional
  skip. The skip is free — no request, no timeout — and is recorded as
  `socket_disabled`, distinct from the causes that mean the service failed.
  Because Socket is the only behavioral tier, a check that skipped it has no
  behavioral evidence, so `never` warns rather than passing on its own:
  advisories, blocklist, and release age still apply, and the result reflects
  what was actually gathered.
  If that posture is deliberate — an offline host, an exhausted quota, or a
  curated internal registry where advisories plus blocklist plus cooldown is
  the accepted policy — add `socket_disabled` to `auto_allow_tolerate`. The
  gate then passes and records `WARN_TOLERATED` rather than `GO`, so a
  tolerated skip is never later mistaken for a completed check.
- `socket.ecosystems`: the ecosystems Socket is consulted for. Default:
  `["npm", "python"]` — the two where Socket's behavioral scoring has real
  coverage; for go, cargo, php and others it almost always answers "no
  record" while still consuming rate limit. Audits outside the list skip
  silently (disclosed as an `out_of_scope` state, no warn) and decide on
  advisories, blocklist and release age. `java` is additionally always
  skipped by capability (Socket has no Maven tier).
- `socket.fresh_window_days`: the fresh-release window for the scope rule
  (operator ruling 2026-09-22). Under `mode: auto`, a release younger than
  this many days is NOT scored automatically: the audit stays decidable on
  advisories/blocklist/release-age, and the install gate asks the operator
  whether to spend the live Socket call (TTY, default Y; `n` proceeds
  without it). A release at or beyond the window never triggers a call or a
  prompt. An unknown release age (failed publish-date lookup) fails closed
  into the consent branch — an unknown state never widens the skip. A valid
  cached score replays without prompting: a cache hit is not a call.
  Default: `7`.
- `socket.cache_ttl_days`: cache a validated successful Socket envelope for
  the exact ecosystem, package name, and resolved version. Default: `7`; `0`
  disables caching. Entries live under the cache dir (see `socket.cache_dir`),
  are private (`0700` directory, `0600` files), and are atomically replaced. On
  expiry, safe queries Socket again; if that query fails, the WARN line may
  disclose the last complete score and its age, but stale data never supplies a
  verdict.
- `socket.cache_dir`: the Socket cache root. Default: `~/.cache/safe/socket`; a
  leading `~/` expands to `$HOME`. Point it at a shared/synced location (e.g.
  `~/Sync/config/safe/socket-cache/`) to pay Socket's per-package scoring once
  across trusted machines instead of on every host. The cache is safe to share:
  entries are per-package JSON keyed by purl (no secrets — Socket scores are
  public), atomically written, and TTL-bounded, so concurrent writers and stale
  entries are already handled. The `SAFE_AUDIT_SOCKET_CACHE_DIR` env var
  overrides this (used by the test suite) and takes precedence over the config.

Common sandbox settings include:

```json
{
  "sandbox": {
    "pids_limit": 256,
    "memory": "2g",
    "cpus": "2",
    "nofile": "1024:1024",
    "timeout": 300
  }
}
```

## Audit Machine Config

Default machine config:

```json
{
  "machines": {
    "local": { "type": "local" },
    "remote-a": { "type": "ssh", "host": "remote-a" }
  }
}
```

Unknown machine names are treated as SSH host names.

`tools.json` records scanner paths per machine. `safe audit setup` updates it after installing or detecting scanners, and every scan refreshes detection — but a refresh that finds what the cache already records does not rewrite the file. Replacements are atomic, so a concurrent reader never sees a partial cache. See [safe audit](safe-audit.md) for how the cache is read and what an unreadable one means.

## Important Environment Variables

```text
SAFE_AUDIT_GRYPE_DB_MAX_AGE_DAYS
SAFE_INSTALL_TIMEOUT_SECONDS
SAFE_AUDIT_SOCKET_TIMEOUT
SAFE_AUDIT_SOCKET_CACHE_DIR
SAFE_ZSH_COMPLETION_DIR
SAFE_ZSHRC
SAFE_BIN_DIR
```

Use environment overrides for tests, temporary runs, or host-specific policy. Keep durable policy in config files.
