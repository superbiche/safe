# `safe run go get` resolves the go TOOL as a package at "latest" and refuses non-interactively

**Date:** 2026-08-06
**Source:** memoire CI-image-lane session (x/text security bump)
**Affects:** safe run tool-version resolution for `go` (mise-shimmed machines)

## Observed

Non-interactive `safe run go get golang.org/x/text@v0.39.0` (cwd
`~/dev/personal/memoire/services/api`) refused with:

```
safe run: BLOCKED: go@latest is unknown and invocation is non-interactive
safe run:   to allow: ask the operator to run interactively first, or: safe run host-allow add go@<version> --reason "..."
```

safe treated the `go` TOOL itself as a package to resolve (at "latest")
instead of auditing the requested module. The requested module spec was
exactly pinned (`@v0.39.0`), so the pinned-version happy path should have
applied. The same class hit `npm` minutes later (separate note). The
operator worked around it interactively using the local toolchain binary
`~/.local/bin/go`.

## Ask

Resolve the invoking Go toolchain's version from the LOCAL binary
(`go version` of the resolved command — the mise shim target or
`~/.local/bin/go`) instead of trying to look the tool up as an
installable package at `latest`. A tool that is already installed and
merely EXECUTING the module operation should never itself need
resolution against a registry; the audit target is the module spec in
argv. Non-interactive agent flows are the default consumer of `safe run`
on this fleet — a refusal class that only clears interactively defeats
the gate's purpose (agents must then either bother the operator or be
tempted to bypass, which the contract forbids).

## Correction (operator, same day — see the npm sibling note)

Plain invocation through the gate-bound shim (no `safe run` prefix) is
the working path — the shim carries the gate via argv0 dispatch. The
`go@latest` refusal is the `safe run <shimmed-tool>` double-wrap class,
not a missing capability. Same reshaped ask as the npm note.

## Resolution (2026-08-11)

Fixed by PR #72 (safe 1.13.0) per the reshaped ask: `safe run go get ...`
now silently delegates to the gate-bound go wrapper instead of resolving the
go TOOL as a package at latest — the non-interactive flow inherits the shim
lane's audits (the module spec in argv is the audit target). A go without a
gate-bound PATH target refuses precisely (exit 100, "not gate-bound...rerun
install.sh") rather than sandbox-prompting. Evidence: delegation cases in
`tests/install/run.sh`, live classifier assertions in
`tests/live/shim_delegation.sh`; 19/19 suites green.
