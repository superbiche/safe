# GuardDog 3.1.0 sandboxed extraction fails on this host (tier inert)

**Date:** 2026-08-03
**Source:** claude (live adoption of the GuardDog behavioral tier, PR #58/#60)
**Affects:** `install.guarddog` tier on hzws1-class Fedora hosts; the tier is
installed and resolvable but produces zero behavioral verdicts

## Symptom

GuardDog 3.1.0 (installed via `uv tool install 'guarddog==3.1.0' --python
3.12`) returns its error envelope for every scan:

```json
{"package": "left-pad", "issues": 0,
 "errors": {"download-package": "Sandboxed extraction failed: Fatal Python error: _Py_HashRandomization_Init: failed to get random numbers to initialize Python\nPython runtime state: preinitialized"}}
```

Reproduces standalone (`guarddog npm scan left-pad --version 1.3.0
--output-format=json`), so it is NOT caused by safe's `GUARDDOG_*`
environment scrubbing. `PYTHONHASHSEED=0` does not help. `/dev/urandom`
exists and is readable outside the sandbox.

## Cause (read from the pinned source)

`guarddog/sandbox.py:100-113` extracts archives through
`nono_py.sandboxed_exec` (Landlock capability set). The capability set is
built from `_get_common_read_paths()` plus the archive dir, target dir and
tempdir; the child is a fresh `python -m guarddog.sandbox`. The child cannot
reach the entropy source it needs for hash-randomization init, so it dies
before running. Upstream bug or a host/kernel-Landlock interaction — safe
must NOT work around it by weakening the sandbox (that is exactly the
coverage the cache-bound `safe-default-v1` profile promises).

## Current behavior (correct, verified live)

- Verdict line: `GuardDog: WARN (scan failed — infrastructure failure, NOT a
  package finding)`; the receipt note now names the real cause
  (`guarddog scan failed — download-package: Sandboxed extraction failed:
  …`) rather than "malformed JSON" — fixed in the PR #60 slice.
- Tier-3 fallback works as designed: a GuardDog `error` status is
  non-conclusive, so Socket is still consulted. Nothing is silently trusted.
- Net effect: on this host the behavioral tier is inert and Socket remains
  the behavioral signal — i.e. the 429 exposure persists until this is
  fixed.

## Next steps (operator ruling)

1. File upstream (DataDog/guarddog) with the reproduction above; check
   whether nono_py's capability set is missing `/dev/urandom` (or
   `/dev/random`) in `_get_common_read_paths()`.
2. Or run GuardDog under a Python built/configured without the sandbox
   path (`--no-sandbox`-equivalent does not exist in 3.1.0's CLI; the env
   var `GUARDDOG_SUBSCAN_SANDBOX` only governs the risky-new-dependency
   subscan, not extraction).
3. Or pin a different GuardDog version once one ships with a fix
   (`GUARDDOG_SUPPORTED_VERSION` in `bin/safe-audit` gates this
   deliberately; bumping it requires re-verifying the JSON contract).

Until then `install.socket.mode=auto` keeps Socket in play automatically —
no config change needed, and no false sense of coverage.

## Resolution — 2026-08-03 (operator ruling: pin GuardDog, unblock the work)

Ruled by michel: a security gate that blocks the security tooling meant to
replace the rate-limited scanner is a deal breaker. Actions taken:

- `npm@12.0.2` installed with an explicitly authorized one-time gate bypass
  (OSV + blocklist were clean; only the Socket infra-WARN stood in the way).
  This also activates the 1.5.0 scripts-allow per-command injection.
- `guarddog==3.1.0` installed (pinned; `GUARDDOG_SUPPORTED_VERSION` in
  `bin/safe-audit` already gates the accepted version, and the machine-setup
  inbox carries the pinned install line).
- Root cause addressed in-product rather than worked around by hand: GuardDog
  exposes `--no-sandbox` ("scan fails if the sandbox is unavailable unless
  --no-sandbox is passed"). New knob `install.guarddog.sandbox`:
  `auto` (default) retries once unsandboxed when the kernel sandbox is
  broken, discloses the weaker isolation on every surface (human line,
  receipt `sandbox.fell_back`, note), and binds the result to a SEPARATE
  cache profile (`safe-nosandbox-v1`) so it can never replay as a sandboxed
  result; `required` keeps the hard failure; `off` never sandboxes.

Verified live on this host: `safe audit check left-pad@1.3.0 --ecosystem npm`
→ `GuardDog: PASS`, `Socket: SKIP (tier 3 — behavioral verdict from
GuardDog; not consulted)`, VERDICT GO, with the weaker-isolation disclosure
printed. **The tiered design now delivers its purpose: a Socket 429 cannot
degrade a check whose behavioral tier concluded.**

Still worth doing (not blocking): report the Landlock/nono_py sandbox
failure upstream so `auto` can stop falling back on this host.
