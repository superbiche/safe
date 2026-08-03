# `safe doctor` podman probe triggers SELinux AVC storms under Codex sandbox — make it sandbox-aware

**Date:** 2026-08-03
**Source:** setup-new-machines (SELinux alert investigation on rainbow)
**Affects:** safe — `safe doctor` capability probing (`bin/safe`, `command_presence_json podman --version`)

## Observed
2332 SELinux AVC denials since 2026-07-04 on rainbow (`nnp_transition nosuid_transition`, `unconfined_t` → `container_runtime_t`, comm=bash/zsh). Live ancestry capture pinned the chain:

```
bwrap (codex-linux-sandbox, acpx/codex-acp)
  └─ bash tests/audit/guarddog_tier.sh
      └─ safe doctor --json
          └─ podman --version   ← denied
```

Codex sandboxes commands with bwrap (no_new_privs + nosuid remounts). `/usr/bin/podman` is `container_runtime_exec_t`; exec'ing it requires a domain transition to `container_runtime_t`, which SELinux refuses from an nnp/nosuid context. Every `safe doctor` run inside a Codex sandbox = one denial; test-suite runs produce bursts of ~59/minute. Unsandboxed `safe` on the host is unaffected (verified: podman execs fine with NoNewPrivs=0).

Side effect: inside Codex sandboxes `safe doctor` reports podman as missing — tests asserting on podman availability are silently degraded there.

## Why it matters
~78 setroubleshoot alerts/day of pure noise (plus setroubleshoot CPU per burst), and doctor's podman report is misleading under sandboxes. The audit2allow "fix" (allow nnp_transition/nosuid_transition to container_runtime_t) was rejected: it relaxes a system-wide sandbox boundary for zero benefit.

## Suggested action
Make the podman probe sandbox-aware in `safe doctor`: when `/proc/self/status` shows `NoNewPrivs: 1`, don't exec `podman --version` — use `command -v podman` and report "present but unusable in sandbox" (distinct from missing). Kills 100% of the AVC noise at the source and makes doctor output truthful under Codex/bwrap. Chosen over a local SELinux dontaudit module (option 2) by operator ruling 2026-08-03.

## Resolution — 2026-08-03 (safe 1.9.1)

Implemented as ruled (option 1, sandbox-aware probe): `safe doctor` checks
`/proc/self/status` for `NoNewPrivs: 1` before probing podman; sandboxed
runs answer from PATH lookup alone (`present, probed: false`, note naming
the no-new-privs cause) and never exec podman — zero AVCs at the source.
Unsandboxed probing is unchanged. Regression case
`case_doctor_podman_probe_skips_exec_under_no_new_privs` in
`tests/install/run.sh` runs doctor under `setpriv --no-new-privs` with a
logging podman stub and asserts no invocation. Landed via PR #62.
