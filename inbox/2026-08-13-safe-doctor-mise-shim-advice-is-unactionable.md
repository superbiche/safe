# doctor's mise-shim advice cannot be followed as written — the obvious repair recreates the drift

**Date:** 2026-08-13
**Source:** safe (fixing the drift doctor reported after the 1.19.0 install)
**Affects:** `bin/safe` doctor — `mise_shims_bound_to_wrapper`; possibly `install.sh`

## Observed
`safe doctor` reported:

> mise shims: 44 bound to the gate wrapper — dispatch still works (argv0 branch)
> but pays an extra exec per call; repoint the shims at the real mise binary

The advice is correct about the state and gives no way to reach it. The obvious repair,
`mise reshim`, does NOT work — and neither does invoking the real binary directly:

```
$ /usr/bin/mise reshim && readlink ~/.local/share/mise/shims/node
/home/michel/.local/bin/mise        # still the wrapper
```

mise picks the shim target by resolving `mise` on PATH, not from `current_exe`. Since
`install.sh` puts the gate wrapper at `~/.local/bin/mise` and that directory precedes
`/usr/bin`, every reshim binds all shims back to the wrapper. The drift is not a one-off
accident from "a reshim ran while the wrapper sat first on PATH" (the comment at
`bin/safe:791`) — it is the guaranteed outcome of any reshim on a gated machine.

What actually works is removing the wrapper directory from PATH for that one call:

```sh
env PATH="$(printf '%s' "$PATH" | tr ':' '\n' | grep -vx "$HOME/.local/bin" | paste -sd:)" \
  /usr/bin/mise reshim
```

Applied 2026-08-13: all 44 shims now resolve to `/usr/bin/mise`, doctor reports no drift,
`node` and the shimmed tools still run, and `npm` still resolves to `~/.local/bin/npm`
(the gate is unaffected either way — the wrapper's argv0 branch was a pass-through
`exec -a`, never a gate).

## Prior art — this state was previously ruled acceptable
`inbox/2026-08-02-liaison-mise-shim-argv0-breakage.md` (Resolution 2026-08-10) records
shims-symlinked-onto-the-wrapper as the WORKING post-fix state: PR #46 gave the wrapper
its argv0 branch precisely so shim dispatch reaches real mise, and the resolution's
evidence line is "argv0 branch present, shims symlinked onto it".

So doctor is warning about a configuration a previous slice deliberately made safe. That
is the sharper version of this finding: either the warning should not exist, or it should
be clearable. Today it is neither.

## Why it matters
Two separate problems:

1. **The advice is unactionable.** An operator or agent following it reaches for
   `mise reshim`, sees rc=0, and re-runs doctor to find the same 44. Nothing signals
   that the repair silently failed.
2. **It regresses on its own.** Any future `mise install`, `mise use`, or plugin update
   that triggers a reshim rebinds all shims to the wrapper. The fix applied today has a
   shelf life measured in the next tool install.

Cost is small — one extra bash exec and PATH scan per shimmed tool call — so this is
polish, not a defect. But a warning that cannot be cleared durably trains people to
ignore doctor output, which is expensive in a tool whose value is that its warnings mean
something.

## Suggested action
Pick one:

- **Make doctor's message actionable** — print the PATH-stripped reshim command instead
  of the goal state. Cheapest, still regresses.
- **Have `install.sh` run the corrected reshim** after installing the wrappers, so the
  state is repaired every install. Still regresses between installs.
- **Stop warning** and accept the extra exec, if the cost is genuinely negligible —
  defensible, and better than an uncleanable warning.

The durable variant of option 2 is a mise hook or a wrapper that makes mise resolve its
own real path, but that is a bigger change than the symptom justifies.
