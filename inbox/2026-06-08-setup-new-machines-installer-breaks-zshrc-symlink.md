# Installer breaks symlinked ~/.zshrc

**Date:** 2026-06-08
**Source:** setup-new-machines (where this surfaced)
**Affects:** safe installer shell integration

## Observed
`~/.zshrc` was expected to be a symlink managed by `setup-new-machines` (`MichelLinux/config/zsh/.zshrc -> ~/.zshrc`), but it had become a regular file. The file birth time was `2026-06-04 16:29:24`, matching a `./install.sh` run in shell history. The resulting file also had `user_tmp_t` SELinux context, consistent with replacement by a temporary file.

The likely culprit is `safe/install.sh`: `strip_zshrc_line()` writes filtered content to `mktemp` and then runs `mv "$tmp" "$target"`. When `$target` is a symlink, that replaces the symlink itself instead of updating the symlink target.

## Why it matters
This silently breaks managed dotfile symlinks. Future setup runs see `~/.zshrc` as a normal file and would need an interactive backup/replace prompt, while edits drift between the local file and the synced source.

## Suggested action
Make the installer symlink-aware before rewriting shell startup files. Resolve the target with `readlink -f` when appropriate, or use an editing strategy that preserves symlinks instead of `mv` over `$ZSHRC`. Add a regression test with `$HOME/.zshrc` as a symlink to a separate file.
