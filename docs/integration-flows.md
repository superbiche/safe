# Integration Flows

This page shows how the pieces fit together in real workflows.

## New Machine Onboarding

```bash
git clone <repo-url> /path/to/safe
cd /path/to/safe
bash install.sh
safe doctor
safe audit setup
safe run link
safe status
```

`safe audit setup` only detects scanners or installs from an explicit local
bundle. Install scanners manually after verification before this step, or use
`safe audit setup --bundle <scanners.tar.gz>`.

Then review machine config:

```bash
$EDITOR ~/.config/safe/audit/machines.json
safe audit setup --all
safe audit machine-audit --all
```

Install protection is active as soon as `install.sh` has written the PATH
wrappers — no shell integration and no sourcing involved. Each wrapper in
`$SAFE_BIN_DIR` (default `~/.local/bin`) execs `safe gate <tool>`, which loads
the routing tables from `~/.config/safe/gate-lib.sh` and delegates to the real
tool. What activates it is PATH order: `$SAFE_BIN_DIR` must precede the
directory holding the real package managers (a version-manager shim dir, for
instance). Verify with:

```bash
safe status   # wrappers: ok (11/11 installed in ~/.local/bin)
```

`~/.config/safe/install-wrappers.zsh` is a compatibility stub for existing
`.zshrc` lines. It defines no wrapper functions and cannot enable protection;
it only prints a one-time warning in an interactive shell when the wrappers are
missing.

## Unknown Package Execution

```bash
safe run create-vite@latest -- my-app
```

Flow:

1. `safe run` normalizes the package and checks `blocked.json`.
2. If not host-allowed, it tries `safe audit package-audit` in an isolated audit container.
3. `BLOCK` refuses execution.
4. `WARN` logs the warning and continues only in the sandbox path.
5. Unknown TTY execution prompts; unknown non-TTY execution blocks.
6. Sandbox execution uses strict defaults unless flags relax them.

## Host-Allow Promotion

```bash
safe run host-allow add pnpm@10.11.0 --reason "daily package manager"
```

Flow:

1. `safe run` validates the exact package version.
2. It asks `safe audit` for a package verdict.
3. It records the pinned version, ecosystem, integrity where available, and reason.
4. Future executions of the exact version run on the host.
5. Host executions are appended to `~/.local/share/safe/audit/host-allow-log.jsonl`.

Use host allow sparingly. It is for tools that need real host access, not for convenience.

## Persistent Install Guard

```bash
npm install express
```

Flow:

1. The PATH wrapper execs `safe gate npm`, which detects a package install.
2. If the current directory looks like an npm project, it runs `safe audit repo-audit .`.
3. It extracts package specs and runs `safe audit package-audit <pkg> --ecosystem npm --gate install`.
4. Only a passing gate proceeds.
5. The real command runs through the first non-wrapper `npm` on PATH.

Equivalent gate routing exists for pnpm, pnpx, yarn, bun, uv, pip, pip3, cargo, go, and composer (Volta is retired).

## External Binary Review

External binary installers should treat a reviewed manifest as desired state and
call `safe audit` for review signals before install.

Representative review sequence for a GitHub-backed binary:

```bash
safe audit capabilities --json
safe audit binary-audit release github --repo go-task/task --version v3.50.0 --asset task_linux_amd64.tar.gz --json
safe audit binary-audit vuln github-release --repo go-task/task --version v3.50.0 --json
safe audit binary-audit verify release-asset --artifact ./task --checksum ./task_checksums.txt --json
safe audit binary-audit exec ./task --json -- --version
```

For Sigstore bootstrap-shaped binaries such as `cosign`, the flow can include:

```bash
safe audit binary-audit verify sigstore-bundle \
  --artifact ./cosign-linux-amd64 \
  --bundle ./cosign-linux-amd64.sigstore.json \
  --identity keyless@projectsigstore.iam.gserviceaccount.com \
  --oidc-issuer https://accounts.google.com

safe audit binary-audit verify tuf-bootstrap \
  --mirror ./mirror \
  --root ./root.json \
  --root-checksum "$(sha256sum ./root.json | awk '{print $1}')" \
  --target artifact.pub=./trust/artifact.pub
```

## CI Or Script Integration

Use `safe audit capabilities --json` before relying on advanced checks:

```bash
if safe audit capabilities --json | jq -e '.capabilities["verify.release-asset"]'; then
  safe audit binary-audit verify release-asset --artifact ./tool --checksum ./checksums.txt --json
fi
```

Use `safe doctor --json` for local readiness:

```bash
safe doctor --json | jq '.features'
```

Avoid parsing human status output in automation when JSON is available.
