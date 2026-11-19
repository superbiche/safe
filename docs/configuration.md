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
  install` (bare or with exact `name@version` registry specs) and `npm update` in
  a project are judged on what they introduce over an established baseline (see
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
  command or project it does not cover goes one of three ways (**routing**), decided in two passes.
  **Pass 1, safety, everything that needs no npm:** the caller's arguments and environment, special
  files, the private-name guard, the admission of the project's `.npmrc`, manifest and lockfile. A
  refusal from any of them ends the command; a reason that is only *unsupported* is collected. A
  lockfile the core refuses as **unsafe** refuses, committed or not: a key outside the tree
  (`lockfile_path_outside_tree`), a link that leaves the project (`link_outside_project`), an
  identity that cannot stand in a URL (`identity_invalid`), or one that cannot be decoded (102). The
  merely **unsupported** ones are collected: a lockfile that is not version 2 or 3, an in-project
  link (`links_not_supported`), a source that is not a registry package, no integrity, another host,
  an entry with its own shrinkwrap. **Pass 2, the route:** only if every applicable safety check
  passed. **(1) The one-shot route**, for a shape that is *established*: every file a collected
  reason comes from (`package.json`, `package-lock.json`, `.npmrc`) is committed at the head of the
  project's git work tree and byte for byte what is on disk (read with the bounded git reader), or the
  reason is a property of the host (an npm positively identified as lacking the capabilities, a host
  configuration the lane cannot mirror). The guards of the lane's own invocation run first and a
  failing one wins, except on a project whose `.npmrc` was not admitted: no npm of the lane reads such
  a configuration, and today's gate applies its own checks. The command then goes to today's gate
  exactly as with the switch off, after ONE stderr line `safe: project lane: npm <verb> [lane:
  one-shot, <reason>] — the closure is not judged on this route`; the lane's scratch is removed, its
  lock released and every variable the lane or its probes set is put back, so the delegate's
  environment is the one it has with the switch off. The `install-test` families (`install-test`,
  `install-ci-test`, their aliases and prefixes: `it`, `cit`, `sit`, ...) are classified apart from
  `install` and `ci` and always take it, with the reason "its test phase runs project code".
  **(2) A refusal** (`safe: BLOCKED npm <verb> [lane: project] — … ; details: safe explain`, one final
  line naming the cause and the way out; none suggests turning the lane off) for everything else: a
  command-line or environment setting; a failed guard; the same shapes when one of the files they come
  from exists only in uncommitted changes (mixed causes included) or the project is not in a git work
  tree; an unsupported option; a workspace; **a launcher the lane cannot follow** (its provenance cannot
  be established); a capability or selection probe that fails to load or answers malformed;
  `npm_config_userconfig` or `npm_config_globalconfig` in the environment (either case) when a host
  configuration reason would send the command one-shot (a configuration file chosen for this
  command), as does any environment setting that names the setting the reason is about; and `npm ci`,
  `npm dedupe` and `npm prune`, which the lane does not route yet (that refusal comes before any
  property of the host is read). **(3) Unchanged**: a command npm's own effective configuration says
  is global, `npm exec`, `npm uninstall`, every other verb and every other manager.
  **`mise exec -- npm <lane command>`** with the switch on: the lane owns the **plain form only**:
  `mise exec` or `mise x`, an optional `-C <dir>` (or `--cd`), then `--` and the command. Any tool
  selector (`node@20`) or other option before `--` refuses with the lane's line once npm has said the
  command is not global (a global install under `mise exec` behaves exactly as without the lane, an
  overlay key included). The OUTER process runs the lane itself, in the directory mise would run it in
  and with mise's `[env]` overlay applied, and does not then run the original command. The lane
  resolves npm exactly as it does anywhere, from that directory, and builds its own allow-listed
  environment: of the overlay the gate reads (npm settings and source selectors) only what the
  allow-list admits reaches the lane's npm; a key the lane fixes itself and cannot carry
  (`npm_config_git`, `npm_config_allow_git`, `npm_config_node_options`) refuses naming the key, as a
  script-policy key already did. **The result channel:** the parent creates a private result file by
  absolute path in a scratch directory of its own and keeps it; the child writes the lane's outcome
  there (`done <status>`, or `handback` when the lane hands a global command to today's gate) and
  fails if it cannot; the parent runs the original command only on an explicit hand-back, and treats a
  missing, empty or malformed result as a failure with the lane's line. The ownership state is
  initialised at both entries of the gate (the wrapper and `safe install --host`), so nothing inherited
  changes a command. An inner command that is not a lane command (`npm view`, `npm install -g`, an
  `install-test`, `npm uninstall`) keeps today's audit-only pass and the outer exec, byte for byte; the
  other tools mise wraps (pnpm, bun, yarn, pip, uv, cargo, go, composer, node and the rest) are
  untouched by the lane.
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
  refused at the shell before any npm runs), and the probe that decides whether the
  command is global or local is given only the flags that decide that, with the
  operator's own configuration sources kept. The operator-level destinations found
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
