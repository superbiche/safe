# Retire Volta-specific safe integration during the manager migration

**Date:** 2026-07-13
**Source:** codex-acp (Codex version-resolution investigation)
**Affects:** safe — install wrappers, safe-run runner resolution, and Volta compatibility

## Observed

Volta 2.0.2 is officially unmaintained and its maintainers recommend migrating
to mise. The Codex investigation also exposed two distinct behaviors:

- Volta's `codex` shim intentionally selected the repository-local
  `@openai/codex@0.144.1` instead of the globally installed `0.144.3`; this is
  expected project-aware package routing, not a stale shim.
- `safe` incorrectly blocks the valid informational command `volta --version`
  with exit 100 because the wrapper treats `--version` as an unrecognized
  pre-subcommand flag. `command volta --version` succeeds.

`safe` is coupled more deeply to Volta than the install wrapper alone: runtime
config stores `npx_real` paths under Volta, and `safe-run` contains
Volta-specific discovery and repair logic for per-version `npx.original`
binaries.

A separate same-day inbox item,
`2026-07-13-michel-volta-exact-postinstall-allowlist.md`, proposes more
Volta-specific lifecycle-script machinery. Reassess that proposal against the
migration direction before investing in it.

## Why it matters

An unmaintained tool should not remain a growing compatibility surface inside
`safe`. Removing Volta without first replacing these assumptions could break
audited package execution or silently bypass the intended runner. Conversely,
continuing to add Volta-only fixes increases migration cost.

## Suggested action

1. Fix the generic wrapper-parser bug so informational top-level flags such as
   `volta --version` pass through.
2. Inventory every Volta-specific path, shim backup, resolver, test fixture,
   and runtime-config key in `safe`.
3. Define the desired mise boundary: which `mise` install/use operations
   require `safe` audit receipts, and how mise npm-backend lifecycle-script
   controls interact with `safe` policy.
4. Add manager-neutral tests for selecting the real npm/npx runner across Node
   versions before replacing Volta-specific implementation.
5. Migrate one path at a time, retain explicit fail-closed behavior, and remove
   Volta branches only after the machine-setup migration verifies all
   consumers.
6. Reconcile or supersede the existing Volta postinstall-allowlist capture
   instead of implementing a soon-to-be-retired integration.

## References

- Volta retirement notice: https://github.com/volta-cli/volta/issues/2080
- mise npm backend: https://mise.jdx.dev/dev-tools/backends/npm.html
