# install.sh writes zsh rc lines on bash hosts; the "user manager unreachable" warning under release follow reads as a failure

**Date:** 2026-11-18
**Source:** machine-setup (consuming fige-fiscal's 2026-10-28 capture of the safe 1.71.1 release-follow install on rainbow)
**Affects:** `install.sh` (`ZSHRC`, the source/fpath lines appended around lines 1040–1057; `install_user_timer`)

## Observed
- The fleet login shell is bash on rainbow, tuxedo and agent-dev since 2026-10-24, but every install
  appends `source "$HOME/.config/safe/install-wrappers.zsh"` and the zsh completion `fpath` line to
  `~/.zshrc` (rainbow's `~/.zshrc` now holds only those Safe lines). They are inert on bash; the
  gate wrappers in `~/.local/bin` do the work.
- Under `safe release follow` the installer runs under `env -i`, cannot reach the user manager and
  warns "user systemd manager unreachable; … units installed … enable with: …". That is designed
  (the comment above `install_user_timer` says so) and the timers enabled by an earlier install keep
  running, but the release-follow log reads like a failure to an operator (fige's capture took it for
  one).

## Suggested action
- Write zsh rc lines only when the login shell (or `$SHELL`) is zsh, or behind an option; offer the
  bash equivalent for completions if wanted.
- In the release-follow path, say that the existing timers keep running and that this warning is
  expected there (or check `systemctl --user is-enabled` through the user bus when
  `XDG_RUNTIME_DIR` can be derived from the uid).
