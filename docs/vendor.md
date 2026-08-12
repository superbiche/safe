# Vendor Binary Updates

`safe audit` is registry-scoped (npm, PyPI, Composer, crates.io, Go modules):
it checks named packages against Socket / OSV / the blocklist. Native vendor
binaries — installed by a vendor's own installer and updated over the vendor's
own infrastructure — have no public registry manifest, so there is no
`safe audit package-audit` analog for them.

`safe vendor update` covers that gap. It is an **audit trail, not a gate**: it
records the before/after binary hash, the observed version, the reason, and the
exit code to `~/.local/share/safe/vendor/audit.log`, then delegates to the
vendor's own update command. It never blocks — a native vendor update is
outside safe audit's scope by design.

## Trust calculus

Before running a vendor update, three questions bound the marginal risk:

1. **Same publisher, same channel?** If yes, the update does not expand the
   trust surface — the running binary already pulls code from that infra on
   every invocation.
2. **Side-by-side install / easy rollback?** Some vendors keep old versions on
   disk (e.g. Claude Code under `~/.local/share/claude/versions/<ver>/`),
   making rollback trivial.
3. **Pinned version vs `latest`?** Pinning to a stated minimum reduces
   surprise. Prefer a pinned target when the vendor supports it.

All three yes → low marginal risk. Any no → consider downgrade, sandbox, or
skipping the update.

## Recipes (presets)

`--preset <vendor>` fills `--name`, `--path` (auto-detected on `PATH`), and
`--version-cmd` for a known vendor, so you supply only `--reason` and the
command. Explicit flags still override the preset. Known presets: `claude`,
`gh`, `op`, `uv`, `codex`.

```bash
# Claude Code (Anthropic) — versions kept side-by-side, so rollback is easy
safe vendor update --preset claude --reason "unlock /run-skill-generator" \
  --rollback "claude install 2.1.204" -- claude install 2.1.205

# GitHub CLI
safe vendor update --preset gh --reason "security patch" -- gh extension upgrade --all

# 1Password CLI
safe vendor update --preset op --reason "CVE fix" -- op update

# uv (Astral)
safe vendor update --preset uv --reason "new resolver" -- uv self update

# codex CLI
safe vendor update --preset codex --reason "bugfix" -- codex update
```

If a preset cannot find the binary on `PATH`, it refuses with a legible error;
pass `--path /abs/path` explicitly.

For a vendor without a preset, spell the fields out:

```bash
safe vendor update \
  --name pulumi --path "$HOME/.pulumi/bin/pulumi" --version-cmd version \
  --reason "pin to 3.x" -- pulumi plugin install ...
```

## Disable in-app auto-update

Automatic in-process updaters bypass `safe vendor update` entirely — they fetch
and replace the binary without recording anything. Disable per-tool auto-update
where the vendor supports it, and run deliberate updates through the recipes
above. Verify each setting against the vendor's current docs; the mechanisms
drift.

| Vendor | Disable auto-update |
| --- | --- |
| Claude Code (`claude`) | Set `DISABLE_AUTOUPDATER=1` in the environment (or `autoUpdates: false` in the Claude Code settings). Versions live in `~/.local/share/claude/versions/`. |
| GitHub CLI (`gh`) | No in-app auto-updater; updates come via the OS package manager or `gh extension upgrade`. Pin the package where possible. |
| 1Password CLI (`op`) | Has an explicit `op update` self-update command (no background auto-updater observed). Run it deliberately through the `op` preset; on managed machines prefer pinning via the package manager. |
| uv (`uv`) | `uv self update` is explicit (no background updater). Distro packages may disable `self update` entirely — prefer the package manager on managed machines. |
| codex CLI (`codex`) | Update explicitly; avoid any `--auto-update`/background flag the vendor offers. |

The audit log is the record of every deliberate update. Review it with:

```bash
tail -n 20 ~/.local/share/safe/vendor/audit.log | jq .
```
