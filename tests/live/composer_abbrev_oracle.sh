#!/usr/bin/env bash
# LIVE suite — verifies Composer's read-only help dispatch through the same
# real-tool resolver as the gate. No package command or registry access occurs.
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
PASS=0
FAIL=0

pass() { printf 'ok - %s\n' "$1"; PASS=$((PASS + 1)); }
fail() { printf 'FAIL - %s\n' "$1"; FAIL=$((FAIL + 1)); }

# shellcheck source=/dev/null
source "$ROOT/lib/gate-lib.sh" >/dev/null 2>&1 || {
  printf 'FAIL - cannot source lib/gate-lib.sh\n'
  exit 1
}

real_composer="$(safe_gate_resolve_real composer 2>/dev/null || true)"
if [[ -z "$real_composer" ]]; then
  printf 'SKIP: no real (non-wrapper) composer available; live abbreviation oracle skipped\n'
  exit 0
fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/safe-live-composer-abbrev.XXXXXX") || exit 1
trap 'rm -rf -- "$WORK"' EXIT

for token in u up; do
  if "$real_composer" "$token" --help > "$WORK/$token" 2>&1 \
    && grep -Eq '^[[:space:]]*update[[:space:]]' "$WORK/$token"; then
    pass "composer $token --help resolves to update"
  else
    fail "composer $token --help did not resolve to update"
  fi
done

# `global` is a proxy command and Symfony accepts every unique prefix. Asking
# for its own help proves dispatch without entering the global project or
# touching a registry.
for token in g globa; do
  if "$real_composer" "$token" --help > "$WORK/global-$token" 2>&1 \
    && grep -Fq 'Allows running commands in the global composer dir' "$WORK/global-$token"; then
    pass "composer $token --help resolves to global"
  else
    fail "composer $token --help did not resolve to global"
  fi
done

printf '%s passed, %s failed\n' "$PASS" "$FAIL"
(( FAIL == 0 ))
