# Investigate recursive project audits during pnpm install

**Date:** 2026-09-12
**Source:** oss workbench, upstream Paperclip PR12786 repair
**Affects:** safe project-audit execution / package-manager wrapper routing

## Observed

On this workstation, safe 1.61.0, running the normal gated command
`pnpm install --frozen-lockfile --ignore-scripts` from
`/home/michel/dev/personal/oss/.worktrees/paperclip-redaction-feedback`
spawned nested `bash /home/michel/.local/bin/safe-audit repo-audit . --deps-only --allow-missing-tools --result-out /tmp/safe-gate-scan.*` processes. Each level used a distinct result path. No completed audit verdict or policy refusal appeared. The process was interrupted with Ctrl-C (exit 130).

After `pnpm --version` resolved the repository-required 9.15.4, one normal retry reproduced the nested audits and was also interrupted. No matching audit processes remained after termination. No dependency installation completed.

The worktree is based on Paperclip PR head `1aae093b51c9ace27298634166edac0995e9e8a3`; local repair candidate is `0bc99434b33f150683da97583953be669d2ad1c6`. It has no installed workspace dependencies.

## Evidence and uncertainty

- `safe doctor` reported core readiness/parity OK, no missing prerequisites, Socket CLI and vault mapping present.
- It also reported 78 mise shims bound to the gate wrapper. Readlink confirmed `~/.local/share/mise/shims/pnpm` resolves to `~/.local/bin/mise`.
- Installed `~/.local/bin/pnpm` dispatches `safe gate pnpm`; installed mise wrapper also dispatches gated argv0 names to `safe gate`.
- **The shim warning is not an established cause.** Doctor explicitly says this arrangement should still dispatch successfully, with an extra exec. The exact command that re-enters the audit was not identified.
- No package advisory or Socket outage was established. This is an observed execution-loop symptom, not a supply-chain finding.
- No PATH/shim/configuration changes, host-allow grants, or enforcement bypasses were made.

## Impact

The install loop blocks repository validation: `pnpm -r typecheck` fails missing Node type definitions; `pnpm test:run` and `pnpm build` fail preflight because `cli/node_modules/tsx/dist/cli.mjs` is absent. PR12786 also has separate unresolved code-review findings; fixing safe alone will not make that candidate publishable.

## Suggested action

Michel will handle this in safe. Identify the precise audit child command that re-enters the gate, checking live installed code and argv0/tool resolution before attributing the issue to mise shims. Add a bounded regression for audit self-reentry if confirmed. Preserve normal gating; no further install retries were attempted after the second reproduction.

Source evidence: `/home/michel/dev/personal/oss/tmp/redaction-12786-repair/gates.md` and `/home/michel/dev/personal/oss/_archive/2026-09-12-redaction-12786-repair.md`. Process-tree observations were recorded during execution; a raw process-tree capture was not retained.
