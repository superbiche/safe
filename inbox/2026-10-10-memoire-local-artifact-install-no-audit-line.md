# `safe run pip` local-artifact installs leave no install:python audit line

**Date:** 2026-10-10
**Source:** memoire (Caviar redact-v6 core delivery)
**Affects:** safe — audit.log coverage of the Python local-artifact route
**Related:** companion to inbox/2026-10-10-memoire-bare-relative-local-wheel-misparsed.md (same install, same day)

## Observed
Operator-approved install (ruling a20), Safe 1.68.1, non-TTY, cwd `~/dev/personal/caviar`:
`safe run pip install --no-index --no-deps --target=tmp/delivery-work/installed/v6 ./dist/caviar_redact-0.2.0-py3-none-linux_x86_64.whl` — exit 0, wheel installed.

`~/.local/share/safe/run/audit.log` for that run carries only:
`2026-10-10T14:27:59+02:00 | npx | pip@gate | DELEGATED | non-tty | GATE_DELEGATION | target=/home/michel/.local/bin/pip`
No `install:python` line names the artifact, its sha256 or an OK/PROCEED outcome. The only `install:python` line for this wheel is the earlier refusal of the bare-relative spelling (11:49:18, REFUSED_WARN). The 0.1.0 local installs on 2026-10-09 (21:34, 21:55, 22:28) show the same shape.

## Why it matters
An auditor reading audit.log sees a refusal for the artifact and no subsequent success, so the log cannot prove what was installed, or that the local-artifact exclusion (not a bypass) was the route taken. Consumers had to keep their own install receipt (Caviar tmp/v6-core/INSTALL-A20.json) to fill the gap.

## Suggested action
When the Python extractor routes an argument as a local artifact, emit an `install:python | <path> | LOCAL_ARTIFACT | <tty> | OK` line (ideally with resolved absolute path and sha256 of the file), mirroring the npm `LOCAL_BIN` lines. No change to the gate decision itself.
