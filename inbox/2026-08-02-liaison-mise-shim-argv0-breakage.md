# safe-gate wrapper on mise breaks EVERY mise shim (argv0 dispatch destroyed)

**Date:** 2026-08-02
**Source:** liaison (D364 review slice; full-suite run caught it)
**Affects:** safe — wrapper deployment strategy; every machine where `mise` is safe-gated

## Observed

`~/.local/bin/mise` is the safe-gate-wrapper v1 stub (`exec safe gate mise --
"$@"`, deployed 2026-08-02 15:15). `~/.local/share/mise/shims/*` are symlinks
to that path (regenerated 21:42). A mise shim dispatches on **argv[0]** (shim
invoked as `node` → mise resolves tool `node`); the bash wrapper drops argv[0]
and forwards only `"$@"`, so `node script.cjs` reaches mise as `mise
script.cjs` → `mise ERROR 'script.cjs' is not executable`.

Live impact measured: every `node <script>` via shims fails machine-wide;
liaison's test suite lost `tests/test_rtk_gates.py::OpencodePluginTableTests`
(setUpClass runs `node driver.cjs`). Any harness/tool resolving node, npm,
npx, python, etc. through mise shims is equally broken. `mise exec node --
node -e ...` works (real binary fine); only the shim path is dead.

## Why it matters

The gate intended to guard *installs* is intercepting *runtime tool
dispatch*. Blast radius is the whole shim surface, silently, on every
safe-gated machine.

## Suggested action

Gate only the `mise` CLI entry point, never the shim target: shims must
resolve to the real mise binary (or the wrapper must preserve argv[0], e.g.
`exec -a "$0" <real-mise> "$@"` with safe-gating decided INSIDE by inspecting
argv[0]==mise + subcommand). Regenerate shims after the fix.

## Resolution (2026-08-10)

Fixed the same evening it was filed, along exactly this note's suggested
line: PR #46 (`bb4dcd1`, 2026-08-02 22:08, "gate: argv0-aware mise wrapper —
shim dispatch reaches real mise, never the gate") gave the wrapper an
argv0-dispatch branch (`install.sh:162-182`): invoked under any name other
than `mise`, it PATH-walks past gate wrappers to the real mise and
`exec -a "$0"` preserves argv[0], so shim dispatch never enters the gate.
PR #63 (`4a6a296`, 2026-08-03) covered the reverse direction — gate
delegate discovery accepts mise shims re-linked onto our wrapper.

Evidence: live wrapper at `~/.local/bin/mise` re-verified 2026-08-10
(argv0 branch present, shims symlinked onto it); the 2026-08-06 memoire
notes' operator correction confirms plain shim invocation is the working
audited lane; regression cases `case_mise_wrapper_dispatches_foreign_argv0`
and `case_mise_wrapper_dispatch_without_real_mise_is_legible` in
`tests/install/run.sh` (suite 143/143 green, 2026-08-10).
