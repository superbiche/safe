# Socket `package score` hangs headless — every install stalls minutes, then fails closed

**Date:** 2026-08-02
**Source:** memoire (D183 pilot bridge session)
**Affects:** safe — install gate scoring (Socket wiring)

## What was observed

On rainbow, installing a host-allow-eligible pinned package stalled for
minutes and then failed closed — twice, plus once reproduced directly:

```
cd ~/dev/personal/memoire/tmp/d183-pilot
npm install @agentmemory/agentmemory@0.9.28
# → long stall, then:
# Terminated  "${socket_invocation[@]}" package score "$ecosystem" "$spec" --json > "$output.raw" 2> "$output.stderr" < /dev/null
# safe audit: interrupted; stopping active child processes
# safe: BLOCKED npm install of @agentmemory/agentmemory@0.9.28 — safe audit timed out (fail closed); retry or ask the operator
```

Retry: identical. Direct reproduction:

```
safe audit check @agentmemory/agentmemory@0.9.28 --ecosystem npm --json
# → same: Socket `package score` child hangs until safe's timeout kills it
```

`safe doctor` at the same moment reported everything nominal: audit
capabilities available, socket CLI at
`~/.local/share/mise/shims/socket`, token "vault mapping", missing
prerequisites: none.

The operator unblocked by host-allowing both packages manually
(`@agentmemory/agentmemory@0.9.28`, `@huggingface/transformers@4.2.0`)
and running the install in an interactive terminal.

## Evidence / hypothesis

The child is killed by safe's own leash, not by a Socket API error —
the failure is a HANG, not a fast refusal. Prime suspect: the vault
token mapping needs an interactive touch (Bitwarden/polkit) that a
non-TTY shell can never surface, so the socket CLI blocks on credential
resolution forever. Whatever the root cause, the current behavior turns
every gated install into a multi-minute stall followed by a policy
refusal with no diagnosable cause — operator verdict verbatim: "it's
even worse than before now". Sits alongside (but is distinct from) the
degraded-scanner escalation in PR #36 (osv-scanner failure + missing
govulncheck): that one degrades coverage, this one degrades EVERY
install path.

## Operator ruling to keep (encode, don't lose)

Host-allow entries are ALWAYS version-pinned — the operator deliberately
allowed `@huggingface/transformers@4.2.0`, "never without a version,
this is a behavior I want to keep." safe should refuse to record a
host-allow that carries no exact version, making the pin a hard
invariant of the allowlist, not a convention.

## Suggested action

1. Make Socket-scoring failures fail FAST and diagnosably: separate
   "token resolution hung" from "Socket API unreachable/slow" in the
   refusal line; a headless shell should get an immediate actionable
   error, not a timeout.
2. Verify the vault token mapping actually resolves in non-TTY
   contexts (or document/enforce that scoring requires a TTY and say
   so in the refusal).
3. Enforce the pinned-version invariant on `host-allow add` (reject
   version-less allows).
