# safe run

`safe run` is the sandboxed package runner:

```bash
safe run cowsay@1.6.0
```

Compatibility binaries and runner-shaped symlinks remain installed for scripts
and command interception:

```text
safe-run
safe-npx
safe-bunx
safe-uvx
safe-pipx-run
```

After `safe run link`, host `npx`, `bunx`, and `uvx` can be routed through
`safe run`. `pipx` is not auto-linked; use `safe-pipx-run`.

## Sandbox Defaults

Strict mode is the default:

- no package network access;
- read-only project mount;
- dropped capabilities;
- no-new-privileges;
- resource limits from config;
- secret-like project files block non-TTY execution unless allowed.

Relaxations are explicit:

```bash
safe run --write eslint@9.0.0 -- --fix .
safe run --network create-vite@latest -- my-app
safe run --allow-secrets some-tool@1.2.3
safe run --proxy --network package-that-needs-proxy@1.0.0
```

Use alternate runtime images:

```bash
safe run --node22 eslint@9.0.0 -- --version
safe run --py312 ruff@latest -- --version
```

## Decision Order

`safe run` evaluates package requests in this order:

1. `blocked`: refuse and log.
2. `local bin`: a bare, unversioned name backed by `node_modules/.bin` in
   the current **or a parent** directory (npm's own bin resolution, so
   hoisted monorepo workspaces resolve their tools) runs the
   already-installed local binary directly — nothing is fetched. Versioned
   or scoped specs never use this tier.
3. `host-allow`: execute the pinned version on the host with scripts suppressed where supported.
4. `safe audit`: check unknown packages in an isolated audit sandbox when available.
5. `sandbox-known`: run in Podman without another prompt.
6. `unknown`: prompt in a TTY; block in non-TTY.

`safe audit` `BLOCK` refuses execution. `WARN` continues to sandbox execution but is logged.

## Runner-Native Flags

When invoked as `npx`/`bunx`/`uvx`, flags that belong to the replaced runner
are handled explicitly instead of being mistaken for the package name:

- `--no-install` / `--no` — npx/bunx only, honored strictly: run the local
  `node_modules/.bin` binary (current or parent directory), or refuse with
  exit 100 if it is not installed. (Modern npx maps `--no-install` to a prompt setting and still
  resolves against the registry; `safe run` restores the flag's original
  never-fetch meaning.) This keeps husky-era `npx --no-install lint-staged`
  pre-commit hooks working. Via `uvx`/`pipx` the flag is refused through the
  unrecognized-flag path.
- `-q` / `--quiet` / `--silent` — accepted and dropped.
- `--package`, `-p`, `-c`/`--call`, `--workspace`, `--workspaces`,
  `--include-workspace-root` — refused with exit 100: they change what would
  execute, and the shim cannot honor them safely. Use the wrapped `npm exec`
  or `safe run <pkg> [-- args]` instead.
- Any other flag before the package name fails closed with a legible exit-100
  refusal — never a misleading exit-103 "invalid package name".

## Host Allowlist

Use host allow for pinned, reviewed tools that must execute outside the sandbox:

```bash
safe run host-allow add pnpm@10.11.0 --reason "daily package manager"
safe run host-allow update pnpm@10.12.0 --reason "reviewed update"
safe run host-allow list
safe run host-allow remove pnpm
```

`host-allow add` and `host-allow update` are operator-only trust escalations: they require an interactive terminal and refuse in non-TTY shells with exit 102, so a cooperative agent can suggest the command verbatim but not execute it. (The TTY check is a cooperative-agent boundary, not proof of operator presence — a process that allocates a pseudo-terminal can satisfy it; see the residual-risk note in `install-wrappers.md`.) Both run `safe audit` before mutating the allowlist. A `GO` result can proceed without a reason. `WARN`, `BLOCK`, or unavailable audit results require a reason and interactive confirmation.

### Staleness review

Entries outlive their reason: a pin added to override a WARN keeps granting host
execution long after the pinned version audits clean on its own.

```bash
safe run host-allow review            # human table
safe run host-allow review --json     # machine-readable report
safe run host-allow review --digest   # + inbox note in the safe repo when actionable
safe run host-allow review --no-audit # age/usage only, no re-audit probes
```

Per entry the review reports age, observed usage (host executions plus
install-gate overrides, joined from the audit logs), and a status from
re-auditing the pinned version:

- `removable` — audits GO on its own; the entry is dead weight.
- `keep` — still overriding a real WARN finding.
- `review-urgent` — the pinned version now audits BLOCK; standing host trust
  contradicts current knowledge.
- `unknown` — audit infrastructure failure (Socket/OSV outage, timeout). This
  is breakage to fix, never evidence of staleness; retry later.

The review is read-only — removal stays operator-only and TTY-gated. Each
re-audit probe is bounded (`SAFE_HOST_ALLOW_REVIEW_TIMEOUT`, default 90s).
`--digest` writes `inbox/<date>-safe-host-allow-digest.md` into the safe repo
(`SAFE_REPO_DIR` overrides discovery) when it finds removable or review-urgent
entries; an existing note for the day is never overwritten. `install.sh
--review-timer` installs a weekly systemd user timer
(`safe-host-allow-review.timer`) that runs `review --digest`.

## Scripts Allowlist

`~/.npmrc` keeps `ignore-scripts=true` globally, so a package whose
functioning requires its install scripts (platform-binary postinstalls)
installs "successfully" but broken. A scripts-allow entry is an
operator-reviewed grant for one exact identity:

```bash
safe run scripts-allow add opencode-ai@0.5.0 --reason "fetches platform binary"
safe run scripts-allow list
safe run scripts-allow remove opencode-ai
```

`add` is operator-only (TTY, exit 102 otherwise; the same cooperative-agent
boundary as host-allow — see the residual-risk note in
`install-wrappers.md`), requires an exact version (never names, ranges, or
tags), runs the audit preflight, then fetches and **displays the package's
install-time lifecycle scripts** for review before asking for confirmation —
the grant is a statement that these scripts were seen. A registry fetch
failure refuses the grant: sight-unseen authorization is not an option. The
reviewed scripts and the registry integrity hash are snapshotted into the
entry.

Consumption: on a gated `npm install -g <pkg>@<granted-version>` (npm ≥ 12),
the gate injects npm's per-command policy for that one invocation —
`ignore-scripts=false`, `allow-scripts=<every granted identity>`,
`strict-allow-scripts=true` — so exactly the reviewed scripts run and any
script-bearing dependency outside the grant list fails the install. The
global `ignore-scripts` default never changes. With npm < 12 (no per-command
policy) the gate states the manual fallback and installs script-less as
before. An unpinned install of a granted package gets a hint naming the
pinned grant.

`safe audit check --gate install` prints a hint when a resolved version
declares install scripts and no grant exists (`has_install_script` is also
recorded in the check receipt), so "installed but broken" has a visible
cause and the exact operator command to fix it.

## Blocklist

```bash
safe run block add bad-package --reason "known malicious package"
safe run block remove bad-package
safe run block list
safe run block import ./blocked-packages.txt
```

The blocklist supports JSON or newline-list imports and is shared with
`safe audit check`.

## Host and Sandboxed Installs

`safe install -g` audits explicit npm package specs with `safe audit check`,
asks for confirmation, then delegates to `npm install -g` with the original npm
flags preserved:

```bash
safe install -g cowsay@1.6.0
safe install --trust-host -g cowsay@1.6.0
safe install --host --yes --registry https://registry.example left-pad@1.3.0
```

After a successful install of an exact npm version, interactive runs offer to add
that exact package version to `safe run` host-allow. `--trust-host` performs that
step without a second prompt after install. `latest`, omitted versions, dist-tags,
and ranges are not trusted.

For other supported global package managers, select the manager explicitly and
`safe install` translates `-g` to the manager's native global command:

```bash
safe install --pnpm -g cowsay@1.6.0
safe install --yarn -g typescript@5.0.0
safe install --bun -g cowsay@1.6.0
safe install --composer -g vendor/pkg:^1
```

`safe install --sandbox` routes to `safe run install` for isolated install
workflows:

```bash
safe install --sandbox --allow-scripts cowsay@1.6.0
safe run install --write --network native-addon@1.0.0
```

Persistent package-manager commands typed directly in zsh are still covered by
the install wrappers.
