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
safe audit scan --all
```

Enable persistent install protection by starting a new zsh session or sourcing:

```bash
source "$HOME/.config/safe/install-wrappers.zsh"
```

## Unknown Package Execution

```bash
safe run create-vite@latest -- my-app
```

Flow:

1. `safe run` normalizes the package and checks `blocked.json`.
2. If not host-allowed, it tries `safe audit check` in an isolated audit container.
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

1. The zsh wrapper detects a package install.
2. If the current directory looks like an npm project, it runs `safe audit scan --project .`.
3. It extracts package specs and runs `safe audit check <pkg>@<version> --ecosystem npm`.
4. Only `GO` proceeds for package checks.
5. The real command runs through `command npm install express`.

Equivalent wrapper patterns exist for pnpm, yarn, bun, uv, pip, pip3, cargo, go, composer, and volta.

## External Binary Review

External binary installers should treat a reviewed manifest as desired state and
call `safe audit` for review signals before install.

Representative review sequence for a GitHub-backed binary:

```bash
safe audit capabilities --json
safe audit release github --repo go-task/task --version v3.50.0 --asset task_linux_amd64.tar.gz --json
safe audit vuln github-release --repo go-task/task --version v3.50.0 --json
safe audit verify release-asset --artifact ./task --checksum ./task_checksums.txt --json
safe audit binary exec ./task --json -- --version
```

For Sigstore bootstrap-shaped binaries such as `cosign`, the flow can include:

```bash
safe audit verify sigstore-bundle \
  --artifact ./cosign-linux-amd64 \
  --bundle ./cosign-linux-amd64.sigstore.json \
  --identity keyless@projectsigstore.iam.gserviceaccount.com \
  --oidc-issuer https://accounts.google.com

safe audit verify tuf-bootstrap \
  --mirror ./mirror \
  --root ./root.json \
  --root-checksum "$(sha256sum ./root.json | awk '{print $1}')" \
  --target artifact.pub=./trust/artifact.pub
```

## CI Or Script Integration

Use `safe audit capabilities --json` before relying on advanced checks:

```bash
if safe audit capabilities --json | jq -e '.capabilities["verify.release-asset"]'; then
  safe audit verify release-asset --artifact ./tool --checksum ./checksums.txt --json
fi
```

Use `safe doctor --json` for local readiness:

```bash
safe doctor --json | jq '.features'
```

Avoid parsing human status output in automation when JSON is available.
