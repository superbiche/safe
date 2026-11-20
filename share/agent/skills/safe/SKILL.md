---
name: safe
description: "Safe package-install gate: BLOCKED refusals and exit codes, operator handoff, exact pinned installs, worktree dependency reuse (vendor/, node_modules/), false positives and audits; npm/pnpm/yarn/bun/pip/uv/cargo/go/composer/mise and ungated Gradle/Maven."
---

# safe

`safe explain --json` is the installed contract: gated surfaces, every exit
code, consent, reusable approvals and the operator's fleet flows. The
generated sections below are rendered from it.

<!-- BEGIN GENERATED: skill-rules -->
A refusal is policy, not breakage. Do not work around it: no direct node_modules/.bin calls of packages that failed to install, no alternate installers, no curl|sh. Relay the refusal line to the operator verbatim and hand them the exact original command to run in their own terminal, where safe audits it in full and offers the override; wait, then retry the original command unchanged.

- Treat any BLOCKED line as policy, not breakage; do not retry blind.
- Relay the refusal line verbatim. To lift it, hand the operator the exact original command (pinned, with its working directory and the non-secret environment it needs) to run in their interactive terminal: safe re-runs the full audit there and offers the override. A printed `safe run host-allow add` line is a standing trusted-host grant that tolerates the finding without that audit (on a signing origin it also reaches followed hosts): present it only when the operator asks for a standing grant, and say what it grants. Trust escalations only work in the operator's terminal — never attempt them yourself. A refusal of the npm project lane that names the one-shot route is lifted the same way: the operator re-runs the exact original command in their terminal and is asked once whether to run it on the one-shot route for that command; a printed `safe run one-shot-project add` line is a standing per-project decision (the closure of that project is then never judged by the lane): present it only when the operator asks for a standing decision, and say what it does. An agent session, a project file, the environment or a command-line option cannot choose that route.
- After the operator allows, retry the original command unchanged.
- Exit 127 from a wrapped tool means a genuinely missing command (or a `safe` missing from PATH), never a policy block — the gate always refuses legibly with exit 100. Report a silent 127, don't bypass.
- ALWAYS install exact pinned versions. NEVER execute or hand the operator an install command containing @latest, another moving tag, a version range, or a package without an explicit version. Resolve the intended exact version first; if resolution is unavailable, report that blocker instead of offering an unpinned command. Manifest/lockfile installs must use committed exact resolved versions; this does not require listing transitive dependencies on the command line.
- If the advisories do not affect the resolved version, run `safe report-fp <spec>` instead of arguing with the gate.
- Preflight with `safe audit package-audit <pkg>@<version> --ecosystem <eco>` before proposing an install; its exit codes are verdicts (0/10/20), not refusals. Exit 30 means the audit could not run at all — repair the tooling, never read it as a verdict about the package.
- Agents may request any number of exact pinned packages in one unattended install. Each target keeps its normal audit and refusal paths. Never allocate a PTY, remove agent markers, or answer an operator prompt to obtain an override.
<!-- END GENERATED: skill-rules -->

## Gate refusals

<!-- BEGIN GENERATED: refusal-codes -->
| Code | Meaning | What to do |
| --- | --- | --- |
| 100 | Blocked by policy: an audit WARN with no matching allow entry, blocklist, fail-closed audit, unrecognized/unsupported runner-native flags, or a trust-store change requested against a non-canonical (environment-redirected) config root — the refusal line names which; for a refusal of the npm project lane that cannot judge the command, it also names the operator's two ways out (confirm the one-shot route for this command at their terminal, or `safe run one-shot-project add` for the project) | Relay the refusal line verbatim to the operator and hand them the original command to run in their own terminal. Do not retry, do not reword the command. |
| 101 | Host-allow version pin mismatch | The allowlist pins a different version than the one requested. Report both versions; re-pin is an operator decision. |
| 102 | Interactive operator confirmation required (non-TTY refusal); also `safe run one-shot-project add|remove` and a lane refusal's one-shot confirmation, which only the operator's terminal can give | Nothing an agent can do in this shell. Ask the operator to run it in their terminal. |
| 103 | Invalid package name rejected | Check the spec for a typo before escalating — this one is usually the caller's error. |
| 104 | Safe audit BLOCK verdict | The audit returned BLOCK. That can be a critical advisory affecting the resolved version, a known-malware or blocklist entry, a Socket critical supply-chain-risk alert, or a critical advisory safe could not tie to a resolved version — the reason is in the receipt. Inspect it, and use `safe report-fp <spec>` only when its resolved-version and advisory evidence are inconsistent with the refusal. The operator's override is a typed confirmation at an interactive terminal; for an advisory-only BLOCK they may record it (`safe run host-allow add <pkg>@<version> --accept-block`). |
| 127 | Genuinely missing command (never a policy refusal) | The command is not installed, or `safe` is missing from PATH. Report it; never treat it as a reason to bypass. |

The refusal is the final stderr line: `safe: BLOCKED <tool> <action> — <reason>; to allow: <operator command>; details: safe explain`
<!-- END GENERATED: refusal-codes -->

`safe audit package-audit` has its own verdict codes (0 GO, 10 WARN, 20 BLOCK,
30 no verdict); `safe doctor` diagnoses scanners. An advisory hint and an
infrastructure hint together mean the audit is incomplete.

## Commands an agent runs

<!-- BEGIN GENERATED: skill-allow-flows -->
```bash
safe run -y <pkg>@<version> -- <args>
  # one-off sandbox run
safe install [-g] <pkg>@<version>
  # audited install
safe install --reuse [--reuse-from <checkout>] [--dry-run]
  # agent-permitted where the host enables it: fill a worktree's missing Composer vendor/ and Node node_modules/ (npm, Yarn, pnpm, bun) by copying the installed trees of another checkout of the same repository with identical lockfiles (no audit, no php, no node, no package manager, no network); the status is reused-existing-vendor or reused-existing-node-modules, never an audit result
safe run block list && safe run audit --blocked
  # review refusals
```
<!-- END GENERATED: skill-allow-flows -->

After a Composer reuse run `composer dump-autoload` (its `next:` line). In a
worktree whose lockfiles are unchanged, prefer `safe install --reuse` to a
package-manager install. A project install gate weighs only the critical
findings of the ecosystem it installs.

## JVM dependencies and remote hosts

Gradle and Maven have no command gate: preflight a coordinate with
`safe audit package-audit <group:artifact>@<version> --ecosystem Maven --json`.
safe gates only the machine it is installed on; an install over SSH must go
through that host's own safe.
