# `safe run pip install` misparses a bare relative wheel path as a package name

**Date:** 2026-10-10
**Source:** memoire (Caviar redact-v6 core delivery, coordinated from the Memoire redact thread)
**Affects:** safe — Python install extractor / local-artifact route

## Observed
Safe 1.68.1, non-TTY, cwd `~/dev/personal/caviar`:
`safe run pip install --no-index --no-deps --target=tmp/delivery-work/installed/v6 dist/caviar_redact-0.2.0-py3-none-linux_x86_64.whl`
refused with exit 100. audit.log 2026-10-10T11:49:18: `install:python | dist/caviar_redact-0.2.0-py3-none-linux_x86_64.whl | GATE | non-tty | REFUSED_WARN`; resolution unresolved / "latest"; socket consent_required.

The argument is a local wheel file, not a package identity. Read-only inspection of the gate shows the Python extractor takes the local-artifact path route only for `./`, `../` and absolute paths. A bare relative path that names an existing `*.whl` (or sdist) file falls through to package extraction and is judged as an unresolved private package.

Earlier exact local 0.1.0 installs on 2026-10-09 went through as `npx | pip@gate | DELEGATED` (21:34, 21:55, 22:28) with no package_audit entries, consistent with the `./`/absolute route.

## Why it matters
pip itself treats `dist/x.whl` and `./dist/x.whl` identically. The refusal is a false positive on the spelling, not on the artifact, and it pushes agents to "re-spell after a refusal", which looks like evasion and is correctly escalated rather than retried. Operator ruled (a20, 2026-10-10) that the explicit `./` route is the approved one for this wheel.

## Suggested action
In the Python extractor, classify an argument as a local artifact when it ends in `.whl` / `.tar.gz` / `.zip` and resolves to an existing file (or contains a path separator), regardless of a `./` prefix. Add a regression case for `dist/<name>.whl`. Optionally make the refusal message suggest the `./` spelling for local files.
