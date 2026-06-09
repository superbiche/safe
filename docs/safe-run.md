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
2. `host-allow`: execute the pinned version on the host with scripts suppressed where supported.
3. `safe audit`: check unknown packages in an isolated audit sandbox when available.
4. `sandbox-known`: run in Podman without another prompt.
5. `unknown`: prompt in a TTY; block in non-TTY.

`safe audit` `BLOCK` refuses execution. `WARN` continues to sandbox execution but is logged.

## Host Allowlist

Use host allow for pinned, reviewed tools that must execute outside the sandbox:

```bash
safe run host-allow add pnpm@10.11.0 --reason "daily package manager"
safe run host-allow update pnpm@10.12.0 --reason "reviewed update"
safe run host-allow list
safe run host-allow remove pnpm
```

`host-allow add` and `host-allow update` run `safe audit` before mutating the allowlist. A `GO` result can proceed without a reason. `WARN`, `BLOCK`, or unavailable audit results require a reason and interactive confirmation.

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
