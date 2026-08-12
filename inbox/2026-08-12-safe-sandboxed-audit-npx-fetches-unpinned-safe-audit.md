# The sandboxed audit fetches an unpinned npm package named `safe-audit`

**Date:** 2026-08-12
**Source:** safe (found during the Slice 6 entrypoint split)
**Affects:** `bin/safe-run` — `safe_audit_check_spec`, the podman audit path

## Observed
`safe_audit_check_spec` (`bin/safe-run:106-117`) audits an unknown package by
running an audit INSIDE a podman sandbox, and builds that command as:

```
audit_cmd=$(printf 'npx --yes --ignore-scripts %q package-audit %q --ecosystem %q --json' \
  "$audit_pkg" "$spec" "$ecosystem")
```

with `audit_pkg="$SAFE_AUDIT_BIN"`, defaulting to the bare name `safe-audit`
(`bin/safe-run:20`). Inside the container that is `npx --yes safe-audit` — an
unpinned fetch of whatever package is published under that name on the public
npm registry.

This repo publishes no npm package: there is no `package.json`, no publish
workflow, and no registry configuration anywhere in the tree. So the name is
not ours.

Not verified from here (deliberately — resolving it would mean running `npx`,
which is exactly what should not happen casually): whether a package named
`safe-audit` currently exists on npm, and if so who owns it.

## Why it matters
If a package by that name exists and is not ours, safe's sandboxed audit path
downloads and executes third-party code to decide whether third-party code is
safe. `--ignore-scripts` and the podman confinement (`--cap-drop=ALL`,
`--read-only`, `--http-proxy=false`) limit the blast radius, but the verdict
itself would come from an unknown publisher — and the verdict is what the gate
acts on. If no such package exists, the path is simply dead: every sandboxed
audit fails and the fallback is whatever `return 2` leads to.

Either way this is not the behavior the code reads as intending.

## Suggested action
1. Determine what `safe-audit` resolves to on npm today (registry metadata
   lookup, not `npx`).
2. Then pick a direction: mount the installed `safe-audit` into the container
   instead of fetching one, publish a real pinned package under an owned
   scope, or remove the path if it is dead.

Untouched by the Slice 6 split beyond the `check` -> `package-audit` rename
that the hard cut required on that line.
