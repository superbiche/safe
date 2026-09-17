#!/usr/bin/env bash
# Contract guard for test HOME and safe-state isolation.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=tests/lib/test-isolation.sh
. "$ROOT/tests/lib/test-isolation.sh"
safe_test_setup_isolation || exit 1

pass() { printf 'ok - %s\n' "$*"; }
fail() { printf 'not ok - %s\n' "$*" >&2; exit 1; }

for suite in "$ROOT"/tests/*/*.sh; do
  [[ "$suite" == "$ROOT/tests/lib/"* ]] && continue
  grep -Fq 'SAFE_TEST_ISOLATION_MARKER' "$suite" || fail "missing isolation marker: ${suite#"$ROOT"/}"
  grep -Fq 'test-isolation.sh' "$suite" || fail "missing isolation helper: ${suite#"$ROOT"/}"
  grep -Fq 'safe_test_setup_isolation' "$suite" || fail "missing isolation call: ${suite#"$ROOT"/}"
done
pass 'every suite carries the isolation helper and marker'

fake_real_home="$SAFE_TEST_ROOT/fake-real-home"
mkdir -p "$fake_real_home/.config/safe/run" "$fake_real_home/.local/share/safe"
if (
  SAFE_TEST_INVOKING_HOME="$fake_real_home" \
  SAFE_CONFIG_DIR="$fake_real_home/.config/safe" \
  SAFE_DATA_DIR="$fake_real_home/.local/share/safe" \
  safe_test_assert_isolated_paths
); then
  fail 'runtime guard accepted safe paths under the invoking HOME'
else
  pass 'runtime guard rejects safe paths under the invoking HOME'
fi
