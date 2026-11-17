# Installation

Clone the repository, inspect it, scan it, then run the installer:

```bash
git clone <repo-url> safe
cd safe
safe audit repo-audit .
bash install.sh
```

If `safe` is not already available on the machine, run equivalent local scanners
before installing. Treat this repository like any other supply-chain input.

Default install mode is `--all`, which installs:

- `safe`, plus compatibility component binaries, to `~/.local/bin`;
- seed config under `~/.config/safe/run` and `~/.config/safe/audit`;
- `~/.config/safe/install-wrappers.zsh`;
- PATH gate wrappers in `~/.local/bin` for the gated tools;
- zsh completion `~/.local/share/zsh/site-functions/_safe`;
- `.zshrc` source and completion `fpath` lines when missing.

The installer is idempotent. It refreshes installed files, seeds only missing config, and preserves existing data.

After a successful install, it also writes the machine-local
`$SAFE_CONFIG_DIR/release-follow.json` record with the absolute checkout path
from which that installer ran and the union of normalized component flags. A
later component-only install extends the record instead of narrowing it. The record is
used by `safe release follow`; it is not a synced artifact and contains no
signer trust.

## Install Modes

```bash
bash install.sh --all
bash install.sh --run
bash install.sh --audit
bash install.sh --wrappers
bash install.sh --no-wrappers
bash install.sh --review-timer
bash install.sh --tools-scan-timer
bash install.sh --agent-skills
```

`--review-timer` and `--tools-scan-timer` add opt-in systemd user timers: the
weekly host-allow staleness review ([safe-run](safe-run.md)) and the daily
[tools-scan](tools-scan.md) publication.
When the user systemd manager cannot be reached (as under `safe release
follow`), the units are still installed and the installer warns with the
`systemctl --user enable --now` command instead of failing.

Every install also installs the agent skill, `~/.local/share/safe/skills/safe`
(`SKILL.md`): what an AI coding agent needs to read a refusal, hand the operator
a command and use the allow flows, rendered from the same agent contract as
`safe explain`, so it changes with the release that changes the gate.
`--agent-skills` links it into `~/.claude/skills/safe` and
`~/.codex/skills/safe` for each harness present. It never replaces an entry it
did not create (it names it and leaves it), `safe release follow` repeats the
flag, and `uninstall.sh` removes the skill and only its own links.

`--no-wrappers` installs the run and audit tools without generating the
PATH gate wrappers. On an existing installation the gate library
(`~/.config/safe/gate-lib.sh`) is still refreshed together with the `safe`
binary — the dispatcher and its routing library are one upgrade unit, so
already-installed wrappers always load the library matching the installed
`safe`.

## mise Shims

Wrapper installation also normalizes the mise shims directory
(`${MISE_DATA_DIR:-~/.local/share/mise}/shims`) when it exists. mise's shims
are symlinks to whatever `mise` resolved to at reshim time, and gate coverage
under mise depends on them resolving to safe's mise wrapper: a shims directory
still bound to the real mise lets a tool reached through it install unaudited.
The installer re-points those symlinks at the wrapper and reports the counts.

Regular files in that directory are left alone — they are not something mise
generated — and nothing is re-pointed unless `~/.local/bin/mise` is safe's own
wrapper, so a skipped or foreign `mise` never becomes the target of the whole
shim fleet.

`uninstall.sh` puts them back: shims bound to the wrapper it is removing are
re-pointed at the first non-wrapper `mise` on PATH, so removing the gate does
not uninstall the tools it was gating. If no such `mise` resolves, the symlinks
are left in place and the uninstaller says to run `mise reshim` — it never
deletes a shim.

## First Run

After installation:

```bash
safe status
safe doctor
safe audit setup
safe run link
```

`safe audit setup` detects already-installed scanners or installs scanners from
an explicit local bundle. It does not download scanners or run upstream
installer scripts.

Scanner dependency policy and upstream project links are documented in
[External Dependencies](dependencies.md).

`install.sh` owns the `npx`, `bunx` and `uvx` runner links in `~/.local/bin`
(symlinks to `safe-run`, ahead of mise shims on PATH) and lists them in
`~/.config/safe/runner-links`. A reinstall keeps a link that already points at
`safe-run` (a hand-made one is adopted), moves a uv-installed `uvx` aside to
`uvx.original` as it does for `uv`, and leaves any other existing file alone
with a warning. The mise wrapper also routes a shim named `npx`, `bunx` or
`uvx` to `safe-run`. `pnpx` and `bun x` are gate routes through the `pnpx` and
`bun` wrappers. `safe doctor` and `safe status` report which runners really
resolve to the gate on the current PATH. `uninstall.sh` removes only the links
listed in that manifest that still point at `safe-run`.

`safe run link` additionally replaces runners found elsewhere on PATH with safe shims where supported. It is transactional and backs up originals before linking.

## Uninstall

Remove binaries and completions while preserving config and data:

```bash
bash uninstall.sh
```

Remove config and data as well:

```bash
bash uninstall.sh --all
```

`--purge` also requests source-line cleanup. The uninstall path calls `safe run unlink` first when possible.
