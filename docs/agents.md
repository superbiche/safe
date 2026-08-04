# Agent Contract

Coding agents (Claude Code, Codex, local LLM harnesses) hit safe's gates
constantly. This page is the machine-facing contract: what is gated, what a
refusal looks like, and how to get unblocked without bypassing the safety
net.

The same content is available on any gated machine, in two forms:

```bash
safe explain          # human/agent-readable text
safe explain --json   # the contract as data
```

> **Single source.** Everything below marked as generated comes from
> `docs/contract/agent-contract.json`, which is also what `safe explain`
> renders at runtime. Edit the JSON, then run `scripts/render-contract.sh`.
> Do not hand-edit generated blocks — `tests/contract/drift.sh` fails on it.
>
> That suite also cross-checks the contract against the code, but only
> partially: it compares documented exit codes against the `refuse` calls in
> `bin/safe` (not `bin/safe-run` or `lib/gate-lib.sh`) and checks that every
> wrapped tool is documented (not that every documented tool is wrapped). A
> claim can still drift in the directions it does not cover.

## The one rule

A refusal is policy, not breakage. If a package-manager command fails with a
line starting with `safe: BLOCKED` or `safe run: BLOCKED`, the toolchain is
working as designed. Agents must not work around a refusal — no direct
`node_modules/.bin` calls of packages that failed to install, no alternate
installers, no `curl | sh`. Relay the refusal and its `to allow:` command to
the operator verbatim, wait, then retry the original command unchanged.

## What is gated

<!-- BEGIN GENERATED: gated-surfaces -->
| Surface | Mechanism | Refusal source |
| --- | --- | --- |
| `npx, bunx, uvx` | Binaries are symlinked to `safe run`: packages run from a project node_modules/.bin (bare unversioned names, current or parent dir), an allowlist, a Podman sandbox, or not at all. | `safe run: BLOCKED ...` + exit 100-104 |
| `npm, pnpm, pnpx, yarn, bun, pip, pip3, uv, cargo, go, composer, mise` | PATH wrappers in ~/.local/bin exec `safe gate <tool>`, which audits install, update, and exec-style subcommands with `safe audit` before delegating to the real tool. This applies in every shell, not just interactive zsh. | `safe: BLOCKED ...` + exit 100/102/104 |
| `safe install <pkg>` | Audited, confirmed install path (multi-manager). With no specs in a project directory it audits the project's dependencies instead. | `safe: BLOCKED ...` + exit 100/102/104 |

**Audited subcommands.** Installs (install/add/ci/require and global variants), updates (update/up/upgrade, npm it), and exec-style fetch-and-run (npm exec|x, pnpm dlx, pnpx, yarn dlx, bun x, uv run --with|-w, uv tool run, go run <module>@<version>). An unrecognized space-form value flag before the command fails closed (escapable with --flag=value).

**Passthrough.** No registry fetch, no gate: non-install subcommands (npm run, npm --version, ...), npm exec/npx of a bare unversioned name already in node_modules/.bin of the current or a parent directory (a versioned or aliased spec is still audited), pnpm exec and composer exec (project/vendor binaries only), uv run without --with, and go run of local paths. npx --no-install/--no is honored strictly: the local binary runs or the refusal is exit 100, never a registry fetch.
<!-- END GENERATED: gated-surfaces -->

The wrappers are executables on PATH, so gating applies in every shell —
`bash -c`, Makefiles, CI, and agent harnesses included, not just an
interactive zsh.

## Refusal format

The refusal is the FINAL stderr line, always the same shape:

```text
safe: BLOCKED <tool> <action> — <reason>; to allow: <operator command>; details: safe explain
```

It may be preceded by the audit's own report and `safe audit:` hint lines
— relay the BLOCKED line (plus the hints) to the operator; the lines above
it are supporting evidence, not the refusal. `safe run` refusals use the
same `BLOCKED:` keyword with follow-up hint lines, including `agent
contract: safe explain`.

## Preflight

<!-- BEGIN GENERATED: preflight -->
Before proposing an install, an agent can check a spec directly: `safe audit check <pkg>@<version> --ecosystem <eco>` (add `--json` for the receipt). It prints per-scanner lines, including GuardDog for exact npm/PyPI versions, `VERDICT: GO|WARN|BLOCK`, next-step hints on WARN/BLOCK, and exits 0/10/20 — those are verdict codes, not refusals. GuardDog hints name the risk-forming rules. The gate turns the same WARN into a refusal with exit 100 (unless an allow matches) and BLOCK into exit 104.
<!-- END GENERATED: preflight -->

## Exit codes

Verdict codes (0/10/20) come from `safe audit check`; policy refusals use
a dedicated 100-range so scripts and agents can distinguish a block from
a missing binary (127):

<!-- BEGIN GENERATED: exit-codes -->
| Code | Meaning | What an agent should do |
| --- | --- | --- |
| 0 | Clean verdict (GO) from `safe audit check`, or a gated command that passed and ran | Proceed. |
| 10 | `safe audit check` verdict WARN (advisory affecting the resolved version, lower-confidence GuardDog behavioral findings, custom source, unresolved version, or an audit-infrastructure failure — the per-scanner lines say which) | Read the `safe audit:` hint lines: an infrastructure cause is breakage to escalate, an advisory cause is the gate working. Via the gate this same state refuses with exit 100. |
| 20 | `safe audit check` verdict BLOCK (critical advisory affecting the resolved version, a known-malware `MAL-*` record, GuardDog `high_risk` behavior, or blocklist) | Do not install. Via the gate this refuses with exit 104; the receipt carries the evidence. |
| 100 | Blocked by policy: an audit WARN with no matching allow entry, blocklist, fail-closed audit, or unrecognized/unsupported runner-native flags — the refusal line names which | Relay the refusal line verbatim to the operator. Do not retry, do not reword the command. |
| 101 | Host-allow version pin mismatch | The allowlist pins a different version than the one requested. Report both versions; re-pin is an operator decision. |
| 102 | Interactive operator confirmation required (non-TTY refusal) | Nothing an agent can do in this shell. Ask the operator to run it in their terminal. |
| 103 | Invalid package name rejected | Check the spec for a typo before escalating — this one is usually the caller's error. |
| 104 | Safe audit BLOCK verdict | The audit returned BLOCK. That can be a critical advisory affecting the resolved version, a known-malware or blocklist entry, GuardDog high-risk behavior, or a critical advisory safe could not tie to a resolved version — the reason is in the receipt. Inspect it, and use `safe report-fp <spec>` only when its resolved-version and advisory evidence are inconsistent with the refusal. |
| 127 | Genuinely missing command (never a policy refusal) | The command is not installed, or `safe` is missing from PATH. Report it; never treat it as a reason to bypass. |
<!-- END GENERATED: exit-codes -->

## Version resolution

<!-- BEGIN GENERATED: version-resolution -->
safe audits the version that will actually be installed, never the literal string `latest`. An unversioned spec is resolved through the registry first (dist-tag for installs, the max version satisfying the declared range for updates), and the advisory match is evaluated against that resolved version.

Never suggest, request, or construct an allow entry for `<pkg>@latest`. Allow entries are pinned to resolved versions. A refusal that needs an allow will name the exact pinned version in its `to allow:` command — use that string as-is.

When resolution fails (a private registry, a git or workspace spec, a compound range), the verdict floors at WARN with reason `version_unresolved` and is never auto-allowed. Pin an exact version and retry.
<!-- END GENERATED: version-resolution -->

## When to escalate

<!-- BEGIN GENERATED: escalation -->
| Situation | Signal | Action |
| --- | --- | --- |
| Audit backend is down or unauthenticated | The refusal names a Socket auth failure, a rate limit, or a network error — not an advisory. | Escalate to the operator immediately. Do not park it, do not retry around it, do not treat it as a vulnerability finding. Recovery is usually `socket login` or a vault-injection fix; `safe doctor` checks the wiring. |
| A critical advisory affects the resolved version | Exit 104 with an advisory ID and the resolved version. | This is the gate working. Report the advisory to the operator and propose a fixed version if one exists. |
| The advisory does not affect the resolved version | In the receipt (`--json`), an advisory listed as affecting carries a fixed bound at or below the resolved version — the advisory's own range data contradicts the verdict. | Suspected false positive. Run `safe report-fp <spec>` — it re-runs the check, saves the receipt, and writes a dated note in safe's inbox listing every advisory's fixed bound so the operator can apply the disqualifying test. Nothing auto-applies. |
| A refusal carries BOTH an advisory hint and an infrastructure hint | One `safe audit:` line offers a pinned allow command while another names a Socket/OSV failure as infrastructure breakage. | Infrastructure first: get the broken check fixed (or escalate it), then re-run — the verdict may change once full evidence is available. Only pursue the allow lane on a verdict computed with all checks working. |
| A scanner is missing or broke | The output names a broken scanner and the verdict degraded to WARN. The explicit `guarddog not installed — behavioral tier skipped` note is the temporary exception in the current slice: Socket is still always-on, so that missing binary alone is not a WARN. | Coverage is missing, not a finding. Run `safe doctor` and report a present scanner that failed. For the explicit missing-GuardDog skip, relay the install note if behavioral coverage is wanted; do not read the skip as a vulnerability. |
<!-- END GENERATED: escalation -->

## Reporting a false positive

<!-- BEGIN GENERATED: report-fp -->
```bash
safe report-fp <spec> [--ecosystem <eco>] [--source <agent>]
```

Re-runs the check as JSON, saves the receipt, and writes inbox/YYYY-MM-DD-<source>-fp-<slug>.md in safe's repo with the command it ran, its exit code, the resolved version, every advisory with its fixed bound, and the receipt path. It re-runs the check rather than capturing the original refusal, so quote that refusal to the operator yourself if it matters.

**The note IS the escalation. Nothing auto-applies and no behaviour changes until the operator validates it.**
<!-- END GENERATED: report-fp -->

## No partial-load state

Gating is executable-based, so the old "degraded wrapper" mode (a shell
snapshot keeping wrapper functions while stripping their helpers, which died
with a silent 127) no longer exists: a wrapper either runs the full gate or is
not on PATH at all. If `safe gate` cannot load its routing tables it refuses
with the usual `safe: BLOCKED` line and exit 100 rather than delegating.

If an agent sees a bare, silent 127 from a wrapped tool, that means the command
genuinely is not installed — or that `safe` itself is missing from PATH, which
is worth reporting to the operator. It is never a reason to bypass.

## Allow flows (operator only)

<!-- BEGIN GENERATED: allow-flows -->
Trust escalations require the operator's interactive terminal. `safe run host-allow add` and `update` refuse in non-TTY shells with exit 102, so an agent can suggest the command but never execute it.

```bash
safe run host-allow add <pkg>@<version> --reason "..."                            # trusted host exec (npm)
safe run host-allow add <pkg>@<version> --acknowledge-behavioral --reason "..."   # operator-only behavioral-FP lane: downgrades a GuardDog high-risk BLOCK to a host-allowable WARN for one reviewed exact version; engages only while the live rule set stays within the acknowledged one, OSV shows nothing affecting, and a forced Socket second opinion is clean. Agents relay this command to the operator, never run it
safe run -y <pkg>@<version> -- <args>                                             # one-off sandbox run
safe install [-g] <pkg>@<version>                                                 # audited install
safe run block list && safe run audit --blocked                                   # review refusals
```
<!-- END GENERATED: allow-flows -->

## Snippet for harness instruction files

Paste into `AGENTS.md` / `CLAUDE.md` on gated machines:

<!-- BEGIN GENERATED: harness-snippet -->
```markdown
## Package manager gates

This machine gates package execution/installation through `safe`. If a
command fails with a `safe: BLOCKED` / `safe run: BLOCKED` line or exit code
100–104, that is policy, not breakage: run `safe explain`, relay the refusal
and its `to allow:` command to the operator verbatim, and never bypass
(no direct node_modules/.bin calls, alternate installers, or curl|sh).
Suspected false positive: `safe report-fp <spec>`.
```
<!-- END GENERATED: harness-snippet -->
