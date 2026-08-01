# Agent Contract

Coding agents (Claude Code, Codex, local LLM harnesses) hit safe's gates
constantly. This page is the machine-facing contract: what is gated, what a
refusal looks like, and how to get unblocked without bypassing the safety
net. The same content is available on any gated machine via:

```bash
safe explain
```

## The one rule

A refusal is policy, not breakage. If a package-manager command fails with a
line starting with `safe: BLOCKED` or `safe run: BLOCKED`, the toolchain is
working as designed. Agents must not work around a refusal — no direct
`node_modules/.bin` calls of packages that failed to install, no alternate
installers, no `curl | sh`. Relay the refusal and its `to allow:` command to
the operator verbatim, wait, then retry the original command unchanged.

## What is gated

| Surface | Mechanism | Refusal source |
| --- | --- | --- |
| `npx`, `bunx`, `uvx` | Binaries symlinked to `safe run` | `safe run: BLOCKED ...` + exit 100–104 |
| `npm`, `pnpm`, `pnpx`, `yarn`, `bun`, `pip`, `pip3`, `uv`, `cargo`, `go`, `composer` | PATH wrappers exec `safe gate <tool>`, which audits install, update, and exec-style subcommands via `safe audit` before delegating | `safe: BLOCKED ...` + exit 100/102/104 |
| `safe install <pkg>` | Audited, confirmed install path | `safe: BLOCKED ...` + exit 100/102/104 |

Audited subcommand families: installs (`install`/`add`/`ci`/`require` and
global variants), updates (`update`/`up`/`upgrade`, `npm it`), and
exec-style fetch-and-run (`npm exec|x`, `pnpm dlx`, `yarn dlx`, `bun x`,
`uv run --with|-w`, `uv tool run`, `go run <module>@<version>`). An
unrecognized space-form value flag before the command fails closed
(escapable with `--flag=value`).

The wrappers are executables on PATH, so gating applies in every shell —
`bash -c`, Makefiles, CI, and agent harnesses included, not just an
interactive zsh.

Passthrough by design (no registry fetch involved): non-install subcommands
(`npm run`, `npm --version`, ...), `npm exec <tool>` and
`npx <tool>` for a **bare, unversioned** name already present in
`node_modules/.bin` of the current or a parent directory (a versioned or
aliased spec is still audited),
`pnpm exec` and `composer exec` (project/vendor binaries only), `uv run`
without `--with`, and `go run` of local paths. `npx --no-install <tool>` / `--no` are honored strictly:
the local binary runs, or the refusal is exit 100 — never a registry fetch
(modern npx would fetch anyway; safe restores the flag's meaning).

## Refusal format

One stderr line, always the same shape:

```text
safe: BLOCKED <tool> <action> — <reason>; to allow: <operator command>; details: safe explain
```

`safe run` refusals use the same `BLOCKED:` keyword with follow-up hint
lines, including `agent contract: safe explain`.

## Exit codes

Policy refusals use a dedicated 100-range so scripts and agents can
distinguish a block from a missing binary (127):

| Code | Meaning |
| --- | --- |
| 100 | Blocked by policy (blocklist, fail-closed audit, unrecognized/unsupported runner-native flags) |
| 101 | host-allow version pin mismatch |
| 102 | Interactive operator confirmation required (non-TTY refusal) |
| 103 | Invalid package name rejected |
| 104 | `safe audit` BLOCK verdict |

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

Trust escalations require the operator's interactive terminal. `safe run
host-allow add` and `update` refuse in non-TTY shells with exit 102, so an
agent can suggest the command but never execute it:

```bash
safe run host-allow add <pkg>@<version> --reason "..."   # trusted host exec (npm)
safe run -y <pkg>@<version> -- <args>                    # one-off sandbox run
safe install [-g] <pkg>@<version>                        # audited install
safe run block list && safe run audit --blocked          # review refusals
```

## Snippet for harness instruction files

Paste into `AGENTS.md` / `CLAUDE.md` on gated machines:

```markdown
## Package manager gates

This machine gates package execution/installation through `safe`. If a
command fails with a `safe: BLOCKED` / `safe run: BLOCKED` line or exit code
100–104, that is policy, not breakage: run `safe explain`, relay the refusal
and its `to allow:` command to the operator verbatim, and never bypass
(no direct node_modules/.bin calls, alternate installers, or curl|sh).
```
