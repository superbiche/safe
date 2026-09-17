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

live_tool_suites=(
  "$ROOT/tests/live/npm_config_oracle.sh"
  "$ROOT/tests/live/npm_abbrev_oracle.sh"
  "$ROOT/tests/live/composer_abbrev_oracle.sh"
  "$ROOT/tests/live/shim_delegation.sh"
)
for suite in "${live_tool_suites[@]}"; do
  grep -Fq 'export SAFE_TEST_ISOLATION_KEEP_TOOLS=1' "$suite" || \
    fail "live tool suite does not preserve real tool discovery: ${suite#"$ROOT"/}"
done
pass 'live tool suites opt into real PATH and mise roots explicitly'

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

keep_home="$SAFE_TEST_ROOT/keep-tools-home"
keep_tool="$keep_home/tools"
mkdir -p "$keep_tool"
if (
  unset SAFE_TEST_INVOKING_HOME MISE_CONFIG_DIR MISE_DATA_DIR MISE_CACHE_DIR
  export HOME="$keep_home" PATH="$keep_tool:/usr/bin"
  export SAFE_TEST_ISOLATION_KEEP_TOOLS=1
  . "$ROOT/tests/lib/test-isolation.sh"
  safe_test_setup_isolation
  case ":$PATH:" in
    *":$keep_tool:"*) ;;
    *) exit 1 ;;
  esac
  [[ "$MISE_CONFIG_DIR" == "$keep_home/.config/mise" ]] || exit 1
  [[ "$MISE_DATA_DIR" == "$keep_home/.local/share/mise" ]] || exit 1
  [[ "$MISE_CACHE_DIR" == "$keep_home/.cache/mise" ]] || exit 1
); then
  pass 'keep-tools opt preserves real tool PATH and mise roots'
else
  fail 'keep-tools opt did not preserve real tool discovery'
fi
