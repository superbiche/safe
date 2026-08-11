# `safe run npm update` resolves the npm TOOL as a package at "latest"; absolute-path workaround blocked as path traversal

**Date:** 2026-08-06
**Source:** memoire CI-image-lane session (embed-worker tar/brace-expansion security bumps)
**Affects:** safe run tool-version resolution for `npm` (mise-shimmed machines); command-path validation

## Observed

Non-interactive `safe run npm update tar brace-expansion` (cwd
`~/dev/personal/memoire/services/embed-worker`) refused with:

```
safe run: safe audit preflight unavailable or inconclusive; continuing with sandbox policy
safe run: BLOCKED: npm@latest is unknown and invocation is non-interactive
```

Same class as the go note filed alongside this one: the mise-shimmed
`npm` TOOL is looked up as a package at "latest" instead of resolving
its version from the shim target
(`~/.local/share/mise/installs/node/24.18.1/bin/npm` at the time).

The go-style workaround does NOT port: invoking the real binary by
absolute path — `safe run /home/michel/.local/share/mise/installs/node/24.18.1/bin/npm update tar brace-expansion`
— is refused as:

```
safe run: BLOCKED: invalid package name (path traversal, encoded chars, or invalid charset)
```

so for npm there is no non-interactive path at all; the operator had to
run the update interactively. (Also observed in the first refusal: "safe
audit preflight unavailable or inconclusive" riding the osv-scanner
coverage failure — `safe doctor` reports socket wired, guarddog version
unavailable; separate wiring issue, noted here for correlation.)

## Ask

1. Resolve the npm tool version from the resolved shim target (its
   `npm --version`), never as a registry lookup at `latest` — same fix
   class as the go note.
2. Distinguish the COMMAND path from package-name arguments in argv
   validation: an absolute path in position 0 is the tool being run, not
   a package name, and should be validated as an executable path (or
   deliberately rejected with a message saying absolute tool paths are
   unsupported — not mislabeled as a malformed package name).

## Correction (operator, same day)

Plain `npm update tar brace-expansion` — WITHOUT the `safe run` prefix —
worked, with the expected audits firing: the mise shims are bound to the
gate wrapper (argv0 dispatch), so the shim itself IS the gate. The defect
is therefore narrower than first filed: `safe run <shimmed-tool>`
double-wraps and tries to resolve the tool as a package, while the
intended path (plain shim invocation) works. Re-shape the ask: either
make `safe run <shimmed-tool>` detect the shim and no-op into it, or
document loudly that shimmed package managers must be invoked PLAIN.
The agent-facing skill (my-safe-gate) has been corrected fleet-side to
say invoke-plainly; this note remains for the double-wrap ergonomics.

## Resolution (2026-08-11)

Both asks fixed by PR #72 (safe 1.13.0). (1) `safe run npm update ...`
silently delegates to the gate-bound npm wrapper (no registry lookup of the
npm tool at latest); the shim lane's per-target audits apply, non-interactive
included. (2) An absolute or relative command path in position 0 is now
classified as a command path and refused exit 100 with an honest message
("command paths are unsupported; invoke the tool plainly ... or use safe run
<name>") — deliberately NOT an execution lane, since an absolute path to a
real tool binary would dodge the shim; the "invalid package name (path
traversal)" mislabel (103) is gone for this class. Evidence: command-path +
delegation cases in `tests/install/run.sh` and
`tests/run/safe_audit_integration.sh`; 19/19 suites green.
