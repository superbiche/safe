# safe audit

`safe audit` is the evidence and verdict engine for the ecosystem.

Call it through the dispatcher:

```bash
safe audit scan --project .
```

The compatibility `safe-audit` binary remains installed for scripts, but
documentation and examples use the dispatcher form.

## Capabilities

Use the machine-readable capability command when integrating with other scripts:

```bash
safe audit capabilities --json
```

The current capability groups cover:

- scan, check, diff, and status;
- GitHub release review;
- GitHub repository advisory checks;
- release asset verification;
- Sigstore bundle verification;
- TUF bootstrap verification;
- binary sandbox execution;
- IOC lookup, list scanning, and updates;
- machine setup and scanner bundle creation.

## Scanner Setup

`safe audit setup` detects already-installed scanner tools and can install
scanner binaries from an explicit local bundle. It does not download upstream
release assets, run `curl | sh`, or run language package installers.

Scanner dependency policy and upstream links are documented in
[External Dependencies](dependencies.md).

Create a bundle from an audited machine:

```bash
safe audit setup --create-bundle ./scanners.tar.gz
```

Install that bundle on a target machine:

```bash
safe audit setup local --bundle ./scanners.tar.gz
```

## Project And Machine Scans

Local project scan:

```bash
safe audit scan --project .
```

Configured machine scan:

```bash
safe audit scan --machine remote-a --project /path/to/project
```

All configured machines:

```bash
safe audit scan --all
```

Results are written under:

```text
~/.local/share/safe/audit/results/<machine>/
~/.local/share/safe/audit/sbom/<machine>/
```

Remote scan strategies are selected from available tools and connectivity:

- remote direct scanner execution;
- remote SBOM generation with local vulnerability scanning;
- staged local scanning of copied manifests.

Before trusting a remote Grype scan, `safe audit` checks `grype db status -o json -q`. The stale threshold defaults to 7 days and can be changed:

```bash
SAFE_AUDIT_GRYPE_DB_MAX_AGE_DAYS=14 safe audit scan --machine remote-a --project /path/to/project
```

## Package Checks

```bash
safe audit check express@4.21.0 --ecosystem npm
safe audit check ruff@0.11.0 --ecosystem python --json
```

Checks include OSV, Socket package scoring when available, and the shared `safe run` blocklist. Verdicts are:

```text
GO
WARN
BLOCK
```

Socket is optional for command availability but improves package behavior scoring. Authenticate with:

```bash
socket login
```

For predictable repeated use, use a Socket account token. The practical token scope for `socket package score` is `packages:list`.

## Release Review

Review a GitHub release before downloading assets:

```bash
safe audit release github \
  --repo sigstore/cosign \
  --version v3.0.5 \
  --asset cosign-linux-amd64 \
  --json
```

Checks include release age, draft/prerelease status, asset presence, release churn, previous release comparison, high-risk path changes, tag-to-commit resolution, and GitHub commit verification status.

For repositories with multiple release streams:

```bash
safe audit release github \
  --repo scaleway/scaleway-cli \
  --version v2.55.0 \
  --asset scaleway-cli_2.55.0_linux_amd64 \
  --tag-regex '^v2\.'
```

## Advisory Review

```bash
safe audit vuln github-release --repo OWNER/REPO --version v1.2.3 --json
```

The command maps GitHub repository security advisory ranges to the supplied release version where possible. High or critical matches block. Ambiguous advisory mappings block instead of being ignored.

## Verification

Checksum-only release asset verification:

```bash
safe audit verify release-asset \
  --artifact ./tool-linux-amd64 \
  --checksum ./checksums.txt \
  --json
```

Checksum-only success returns `WARN` because no signature was verified. Add Sigstore certificate and signature data when available:

```bash
safe audit verify release-asset \
  --artifact ./tool-linux-amd64 \
  --checksum ./checksums.txt \
  --certificate ./checksums.txt.pem \
  --signature ./checksums.txt.sig \
  --certificate-identity-regexp '^https://github.com/OWNER/REPO/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --require-signature
```

Verify a Sigstore bundle:

```bash
safe audit verify sigstore-bundle \
  --artifact ./cosign-linux-amd64 \
  --bundle ./cosign-linux-amd64.sigstore.json \
  --identity keyless@projectsigstore.iam.gserviceaccount.com \
  --oidc-issuer https://accounts.google.com
```

Verify a local TUF bootstrap:

```bash
safe audit verify tuf-bootstrap \
  --mirror ./mirror \
  --root ./root.json \
  --root-checksum "$(sha256sum ./root.json | awk '{print $1}')" \
  --target artifact.pub=./trust/artifact.pub \
  --json
```

`verify tuf-bootstrap` requires `cosign`, a checksum tool, and `python3` or `python`. Local mirror inputs can be paths or `file://...` URLs. The verifier serves local mirror content through a temporary loopback `http://127.0.0.1:<port>` bridge before calling `cosign initialize`, because Cosign does not bootstrap correctly from `file://` mirrors.

## Binary Execution

Run an artifact in a networkless Podman sandbox:

```bash
safe audit binary exec ./tool --json -- --version
```

The sandbox uses a read-only artifact bind mount, no network, dropped capabilities, no-new-privileges, and tmpfs scratch space. Startup-shaped failures are classified with reason codes such as `missing_interpreter`, `missing_shared_library`, `sandbox_runtime_mismatch`, and `runtime_failure`.

## IOC Workflows

Lookup one advisory and scan the default machine:

```bash
safe audit ioc GHSA-example-id
```

Scan with a custom IOC JSON file:

```bash
safe audit ioc --list ./ioc.json --machine remote-a
```

Update the CISA KEV-derived IOC catalog and scan:

```bash
safe audit ioc --update --since 7d --all
```
