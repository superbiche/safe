#!/usr/bin/env bash
# Hard gate: the free-prose doc<->code bindings (drift.lock, Fiberplane Drift)
# must be current. This is the enforceable twin of the fail-open
# .githooks/pre-commit hook: the hook lets a clone WITHOUT `drift` commit
# freely (fail-open by design), but the aggregate test gate must go RED when
# bound code changed and its doc was never reviewed — otherwise stale docs (the
# exact failure drift exists to stop) ship silently, which is what happened for
# dozens of versions before this gate existed.
#
# Distinct from tests/contract/drift.sh, which guards the agent-contract RENDER
# pipeline (docs/contract/agent-contract.json -> docs/agents.md generated
# blocks / `safe explain`). THIS suite guards the free-prose doc<->code
# bindings in drift.lock and the markdown links drift discovers.
#
# Under SAFE_TEST_STRICT=1 (exported by tests/run-all.sh) a missing `drift`
# binary is a FAILURE, not a skip: an unrun gate must read red, exactly as the
# Go parity belt (tests/go/run.sh) refuses to skip itself into a false green.
# Run directly (non-strict) without drift, it skips — a dev without the tool is
# not blocked from running this single suite by hand.
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT"

if ! command -v drift >/dev/null 2>&1; then
  if [[ "${SAFE_TEST_STRICT:-}" == "1" ]]; then
    printf 'FAIL: drift is unavailable and SAFE_TEST_STRICT=1; the docs-drift gate must run\n' >&2
    exit 1
  fi
  printf 'SKIP: drift is unavailable; docs-drift binding check skipped\n'
  exit 0
fi

if [[ ! -f drift.lock ]]; then
  printf 'FAIL: drift.lock is missing; the doc<->code bindings are gone\n' >&2
  exit 1
fi

# drift check exits non-zero if any bound target drifted from its doc's
# provenance snapshot, or a discovered markdown link is broken.
if ! out=$(drift check 2>&1); then
  printf '%s\n' "$out" >&2
  printf 'FAIL: docs stale or a markdown link is broken — update the doc prose, then refresh provenance with `drift link <doc> <target>` (or `drift link <doc> --doc-is-still-accurate` if the prose already covers the change). See CONTRIBUTING.md "Docs drift".\n' >&2
  exit 1
fi

printf 'docs-drift: all %s doc<->code bindings current and discovered links resolve\n' "$(grep -c '^\[\[bindings\]\]' drift.lock)"
