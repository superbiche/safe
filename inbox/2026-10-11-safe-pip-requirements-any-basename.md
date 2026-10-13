# Safe: audit pip/uv requirement files regardless of basename

**Date:** 2026-10-11
**Source:** safe (feat/private-registry-trust review, round-5 P13, ruling a44)
**Affects:** safe public install gate (lib/gate-lib.sh, pip/uv lanes)

## Observed
On main (da89170), `pip install -r <file>` whose file is not named
`requirements.txt` / `requirements-*.txt` reaches pip with no package audit:
`safe_gate_python_packages` returns 1 on `-r`, `safe_gate_pip_project_install`
only matches those basenames, so `safe_gate_pip` falls through to
`safe_gate_exec_real`. This holds whatever `--index-url` / `--extra-index-url`
says. The same applies to `-c` constraint files and `${VAR}` spellings inside
requirement files.

## Why it matters
Public packages named only in an arbitrarily named requirements file install
unaudited. Pre-existing on main, outside the private-registry slice; the
private lane deliberately does not certify a complete pip requirement
inventory (docs/private-registries.md).

## Suggested action
Build candidate (theme security, near term, agent executor): route any `-r`/`-c`
file through the existing project scan, including its effective sources and
pip-supported substitutions (`${VAR}`), not only by basename. New behavior gets
a case in tests/install.
