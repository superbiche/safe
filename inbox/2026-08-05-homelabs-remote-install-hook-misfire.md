# safe-gate hook fires on remote-node installs, where `safe` is not the gate

**Date:** 2026-08-05
**Source:** homelabs (WanGP v11.90 → v12.41 bump on HL2)
**Affects:** safe — PreToolUse hook targeting / scope detection

## Observed
Ran `ssh cc-hl2 'cd /opt/wan2gp && sudo /opt/wan2gp/.venv/bin/pip install -r requirements.txt'`
from the workstation. The safe PreToolUse hook fired with the standard advisory
("Package installs route through 'safe' on this machine — load my-safe-gate FIRST").

Two problems:
1. **Wrong host.** The install happens on HL2, a remote lab node. `safe` is a
   workstation gate; it is not installed on the HL nodes and cannot audit a pip
   install running inside an SSH payload. The advice is unactionable as written.
2. **Fires after the fact.** The hook context arrived attached to the tool
   *result*, i.e. after the install already completed — so it cannot gate
   anything even when it is correct. It only produces post-hoc noise the session
   then has to explain away.

Operator reaction: "this is dumb af".

## Why it matters
An advisory that cannot be acted on trains sessions to ignore the safe hook
generally — including on workstation installs where it IS the correct gate.
Every misfire cheapens the signal that makes the gate work.

## Suggested action
Scope the hook's matcher so it does not fire on Bash commands whose package
manager invocation is inside an `ssh <host> '...'` payload — the install is not
happening on this machine. Options, roughly in order of effort:

- Cheap: skip when the command matches `^\s*ssh\s` (or contains `ssh <alias>` before
  the package-manager token).
- Better: detect the target host and emit a different message — either silence,
  or "remote host <h>: safe is workstation-only; verify the remote install path
  yourself" — so the distinction is taught rather than hidden.
- Separately: check whether the hook can fire *pre*-execution here at all. If it
  is structurally post-hoc for this shape, that is worth knowing, since a gate
  that reports after the write is not a gate.

Open question for triage: is there any appetite for a `safe` presence on the HL
nodes, or is remote-install auditing explicitly out of scope? That ruling
determines whether the fix is "stay silent" or "say something useful".

## Resolution (2026-08-05)

Operator direction: avoid the misleading advisory for installs not happening on
this machine — "say something useful" variant chosen (teach the distinction
rather than hide it).

**Fix (in the hook, not this repo):** `~/.claude/hooks/bash-load-gates.sh` now
detects when the first package-manager token sits inside an `ssh` payload
(`install_is_remote()`: command contains `ssh ` and no install token precedes
it) and swaps the advisory for a one-liner — "this install runs on a remote
host; safe gates only this workstation — do not load my-safe-gate for this" —
under its own once-per-session marker (`safegate_remote`), so a later LOCAL
install in the same session still gets the full my-safe-gate advisory.

**Evidence:** hook exercised directly with six command shapes — the exact
misfire command (`ssh cc-hl2 '... pip install -r requirements.txt'`) → remote
one-liner; plain `npm install` → unchanged advisory; `pip install foo && ssh
hl2 reboot` → local advisory (install precedes the ssh); `npm ci` → silent;
remote-then-local same session → both messages fire independently;
`sshpass ...` → not treated as ssh.

**Post-hoc question answered:** structural, not a bug. PreToolUse runs before
execution, but `additionalContext` is advisory — it reaches the model with the
tool result and can only shape the NEXT action; blocking would require a deny
decision from the hook. Locally that is acceptable because the real gate is
execution-level (safe's PATH wrappers refuse regardless of what the model was
told). Remotely there is no execution-level gate, which is the scope boundary,
not a hook defect.

**Scope ruling recorded:** remote-install auditing stays out of safe's scope
for now; the hook teaches that boundary instead of misadvising. A `safe`
presence on HL nodes remains an open idea for the operator to revive — nothing
here forecloses it.
