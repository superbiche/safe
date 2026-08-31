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

## Install Modes

```bash
bash install.sh --all
bash install.sh --run
bash install.sh --audit
bash install.sh --wrappers
bash install.sh --no-wrappers
```

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

`safe run link` replaces host package-runner commands with safe shims where supported. It is transactional and backs up originals before linking.

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
