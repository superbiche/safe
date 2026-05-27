# Native vendor binary updates — trust gap not covered by safe-audit

**Date**: 2026-05-25
**Context**: Discovered while trying to update Claude Code 2.1.143 → 2.1.145 to unlock `/run-skill-generator`.
**Status**: gap acknowledged, no scanner integration today — policy + audit-trail approach proposed below.

## The gap

`safe-audit` is ecosystem-scoped: npm, PyPI, Composer, crates.io, Go modules. It checks Socket / OSV / blocklist against named packages in a public registry.

**Native vendor binaries don't fit**:
- Installed via vendor's own installer (e.g. `claude install`, `gh install`, `1password-cli` direct downloads)
- Update channel is vendor infrastructure, not a public registry
- No package manifest → no `safe audit check <name> --ecosystem X` analog
- No Socket / OSV record because the binary isn't in those registries

Examples on this machine:
- `~/.local/share/claude/versions/<ver>/` — Anthropic Claude Code
- `gh` (GitHub CLI native), `op` (1Password CLI), `bw` (Bitwarden), `pulumi`, `tofu`, `volta` itself, anything from a vendor's direct-download installer

## Trust calculus when no registry check applies

Three questions to answer per-update:

1. **Same publisher, same channel?** If yes, the update doesn't expand the trust surface — the running binary already has full local privileges and pulls code from the same infra on every invocation. Refusing the update would be inconsistent with continuing to run the tool.

2. **Side-by-side install possible?** If the installer keeps old versions on disk (Claude Code does: `~/.local/share/claude/versions/<ver>/`), rollback is trivial. Lower-risk than in-place replacement.

3. **Pinned to specific version vs `latest`?** Pinning to a stated minimum (e.g. `claude install 2.1.145` because that's what we need) reduces surprise vs `latest`.

If all three are yes → low marginal risk. If any is no → consider alternatives (downgrade, sandbox, skip the feature).

## Proposed policy (for safe v2 or a separate `safe-vendor` subcommand)

For native vendor binaries, ship a thin wrapper that:

1. **Logs the update intent** to `~/.local/share/safe/vendor/audit.log` with: vendor, current version, target version, channel URL (if observable), timestamp, reason.
2. **Captures pre-update binary hash** (`sha256sum`) and post-update binary hash. Difference logged.
3. **Verifies the publisher signature** if the vendor ships one (Anthropic, GitHub, 1Password all sign — check each).
4. **Records the rollback path** explicitly in the log (e.g. "rollback: `claude install 2.1.143 --force`").
5. **Does NOT block** on missing registry info — vendor binaries are out of `safe-audit`'s ecosystem scope by design. The check is an audit trail, not a gate.

Manifest of vendors / install paths to support first:
- `claude` (Anthropic) — versions in `~/.local/share/claude/versions/<ver>/`
- `gh` (GitHub) — binary at `/usr/bin/gh` or `~/.local/bin/gh`
- `op` (1Password) — `~/.local/bin/op`
- `volta` — `~/.volta/bin/volta`
- `uv` (Astral) — `~/.local/bin/uv`
- `pulumi` — `~/.pulumi/bin/pulumi`
- `tofu` (OpenTofu) — wherever
- `cargo-binstall`-managed binaries

## Concrete case that prompted this entry

- **Vendor**: Anthropic (Claude Code)
- **Current**: 2.1.143
- **Target**: 2.1.145 (minimum needed for bundled `/run` + `/verify` + `/run-skill-generator` skills)
- **Channel**: `claude install 2.1.145` — Anthropic infra, native installer
- **Trust calc**: same publisher, same channel, side-by-side install (old version preserved), version-pinned not `latest` → low marginal risk
- **Decision**: proceed, no scanner integration available
- **Rollback**: `claude install 2.1.143 --force`

## Next steps if this is worth building

1. Decide whether `safe-vendor` is a subcommand of `safe` or a separate tool.
2. Hash-log + signature-verify is the v1 scope — keep it minimal.
3. The vendor manifest needs to be opt-in per-machine (different machines have different installed vendors).
4. Audit log lives next to existing `safe-audit` data (`~/.local/share/safe/`) for unified retention.

— Claude (drafted on Michel's behalf, in his safe inbox)
