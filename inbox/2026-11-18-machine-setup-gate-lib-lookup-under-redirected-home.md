# Safe shims fail closed under a redirected HOME: the "beside safe" lookup never matches an installed layout

**Date:** 2026-11-18
**Source:** machine-setup (consuming liaison captures of 2026-11-01, rtk upstream test suite on rainbow)
**Affects:** `bin/safe` `gate_lib_path` (around line 442), `install.sh` (installs `lib/gate-lib.sh` only to `~/.config/safe/gate-lib.sh`)

## Observed
Every gate wrapper (`~/.local/bin/{cargo,go,npm,pnpm,yarn,bun,pip,uv,composer,mise}`) runs
`safe gate <tool>`. `gate_lib_path` looks at `$SAFE_DIR/../lib/gate-lib.sh` (the dev-checkout layout,
i.e. `~/.local/lib/gate-lib.sh` for an installed `~/.local/bin/safe`) and at
`$SAFE_CONFIG_ROOT/gate-lib.sh` (`$HOME/.config/safe`). The installer writes only the second. With HOME
redirected (hermetic test suites, containers, units with a private HOME) every shimmed toolchain
refuses. Reproduced on rainbow 2026-11-18 (safe at 1.7x, checkout 90bf774):
`HOME=$(mktemp -d) ~/.local/bin/go version` →
`safe: BLOCKED go — safe gate library not found (looked beside safe and in /tmp/…/.config/safe)`, exit 100.
The message says "beside safe", which reads as `~/.local/bin/gate-lib.sh`; neither path exists.
machine-setup only runs `install.sh --all --review-timer --tools-scan-timer` (BOOTSTRAP-CHECKLIST);
it does not omit anything the installer would place.

## Why it matters
Upstream test suites that spawn a shimmed toolchain under a scrubbed HOME (rtk's `go --version` /
`cargo --version` fixtures) fail for this reason only; lanes currently exclude those tests locally.

## Suggested action
Have the installer place the gate library where the HOME-independent lookup finds it (for example
`~/.local/lib/safe/gate-lib.sh` with the lookup updated to match, or `$SAFE_DIR/../lib/gate-lib.sh`),
keep fail-closed semantics, and make the refusal message print the exact paths it tried. Then verify
`HOME=$(mktemp -d) go version` and check `safe doctor` for other HOME-bound state (config, grants,
trust stores must stay HOME-bound and refuse cleanly).
