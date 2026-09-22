# Custom package index: BLOCK with no operator override pushes the operator to bypass

**Date:** 2026-09-20
**Source:** liaison (SemIf classifier probe, session 4385bd1a)
**Affects:** safe — pip gate, custom package sources, `install.trusted_registries`

## Observed
Agent ran, through the pip shim: `pip --python .venv/bin/python install --index-url https://download.pytorch.org/whl/rocm7.0 'torch==2.10.0+rocm7.0'` (exact pin; the ROCm build exists only on PyTorch's own index). Output:
- `safe audit: custom package source — public advisory evidence cannot vouch for a private artifact`
- `safe audit: to trust this source permanently: add it to install.trusted_registries in ~/.config/safe/run/config.json (operator)`
- `safe audit: could not resolve the target version for torch — pin an exact version and retry` (the version WAS pinned exactly; the local `+rocm7.0` segment is probably what fails resolution)
- `safe: BLOCKED … operator review required: safe audit package-audit torch@2.10.0+rocm7.0 --ecosystem python --json`
The operator then added the source to `install.trusted_registries` as instructed: it was not taken into account, still BLOCK. No operator override path existed at that point, so the operator installed by bypassing safe. Also: `safe audit check …` (named in the my-safe-gate skill) answers `unknown command: check`.

## Why it matters
Operator's words: "c'est BLOCK sans possibilité d'override opérateur, ce qui pousse à : bypasser". A gate the operator himself cannot satisfy trains the bypass reflex, which defeats the gate for the cases where it matters. The message also promises a remedy (trusted_registries) that did not work, and gives a misleading "pin an exact version" hint for a PEP 440 local version.

## Suggested action
1. Reproduce: trusted_registries entry for `download.pytorch.org` + the command above; find why it is ignored (host vs full URL match? `--index-url` vs `--extra-index-url`? config not reloaded?).
2. Handle local version segments (`+rocm7.0`, `+cu128`) in target resolution; fix the misleading hint.
3. Give the operator a one-command, single-install consent for a custom source (operator-only, like the Socket consent), so review → accept is possible without leaving the gate.
4. Align my-safe-gate's `safe audit check` with the real subcommand (`package-audit`?).
