# lockdiff gate residual: partially populated node_modules can still reify unaudited artifacts

**Date:** 2026-08-10
**Source:** PR #70 orthogonal review finding F3 (ARCHITECTURAL) — operator
ruled 2026-08-10: conservative guard now, full parity deferred; this note IS
the deferral record.
**Affects:** safe — npm dedupe/prune lock-diff gate (gate-lib), future Go
verdict-engine port

## Context

The dedupe/prune gate audits the *lockfile delta* of a scratch projection.
The delegated real command operates on the *actual tree*. The ruled guard
closes the demonstrated divergence (missing `node_modules` → empty lock diff
→ real run materializes every lockfile artifact unaudited) by refusing when
`node_modules` is absent, and copies the project `.npmrc` into the scratch so
projection and real run resolve under the same project-level config.

## Residual (accepted, deferred)

1. **Partial trees.** A `node_modules` that exists but is incomplete (deleted
   subdirs, interrupted install) can still make the real run reify lockfile
   entries the empty-diff path never audited. Detecting this honestly means
   comparing actual-tree state against the lockfile — actual/ideal tree
   modeling the current bash gate does not have.
2. **Config beyond the project `.npmrc`.** User/global npmrc via relative
   `--userconfig`, environment-sourced config, and workspace-level rc files
   are not mirrored into the scratch; a divergence there can still make the
   projection resolve differently than the delegate.

## Suggested action

Fold actual-tree parity into the Go verdict-engine port (strangler plan,
slice 5): safe-core grows the actual-vs-ideal tree model npm itself uses, at
which point the lock-diff lane's projection can vouch for materialization,
not just lockfile bytes. Until then the gate's honest claim is: lockfile
deltas audited, fully-absent trees refused, partial-tree reification out of
scope.
