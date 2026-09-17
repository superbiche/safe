#!/usr/bin/env bash
# Contract guard for test HOME and safe-state isolation.
# SAFE_TEST_ISOLATION_MARKER: the contract verifies the isolation contract.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=tests/lib/test-isolation.sh
. "$ROOT/tests/lib/test-isolation.sh"
safe_test_setup_isolation || exit 1

pass() { printf 'ok - %s\n' "$*"; }
fail() { printf 'not ok - %s\n' "$*" >&2; exit 1; }

while IFS= read -r -d '' suite; do
  [[ "$suite" == "$ROOT/tests/lib/"* ]] && continue
  grep -Eq '^[[:space:]]*#[[:space:]]*SAFE_TEST_ISOLATION_MARKER([[:space:]:]|$)' "$suite" || fail "missing isolation marker: ${suite#"$ROOT"/}"
  grep -Eq '^[[:space:]]*(source|\.)[[:space:]].*test-isolation\.sh' "$suite" || fail "missing isolation helper source: ${suite#"$ROOT"/}"
  grep -Eq '^[[:space:]]*safe_test_setup_isolation([[:space:]]|\||$)' "$suite" || fail "missing isolation call: ${suite#"$ROOT"/}"
  grep -Eq '^[[:space:]]*trap .* EXIT' "$suite" && fail "suite replaces composed EXIT trap: ${suite#"$ROOT"/}"
done < <(find "$ROOT/tests" -mindepth 2 -type f -name '*.sh' -print0)
pass 'every suite carries the isolation helper and marker'

grep -Eq '^[[:space:]]*unset SAFE_TEST_ISOLATION_KEEP_TOOLS$' "$ROOT/tests/run-all.sh" || fail 'aggregate does not clear ambient live-tool opt'
grep -Eq '^[[:space:]]*env -u SAFE_TEST_ISOLATION_KEEP_TOOLS bash ' "$ROOT/tests/run-all.sh" || fail 'aggregate does not clear live-tool opt for child suites'
pass 'aggregate keeps the live-tool opt local to live probes'

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
  SAFE_TEST_INVOKING_HOME="$fake_real_home/" \
  SAFE_CONFIG_DIR="$fake_real_home/.config/safe" \
  SAFE_DATA_DIR="$fake_real_home/.local/share/safe" \
  safe_test_assert_isolated_paths
); then
  fail 'runtime guard accepted safe paths under the invoking HOME'
else
  pass 'runtime guard rejects safe paths under the invoking HOME'
fi

if SAFE_TEST_INVOKING_HOME='' safe_test_assert_isolated_paths; then
  fail 'runtime guard accepted an empty invoking HOME'
else
  pass 'runtime guard rejects an empty invoking HOME'
fi

# shellcheck disable=SC2016 # this child shell expands its own environment.
if env SAFE_TEST_INVOKING_HOME="$fake_real_home/" \
  npm_config_userconfig="$fake_real_home/.npmrc" \
  bash -c 'source "$1"; safe_test_setup_isolation; [[ "${npm_config_userconfig:-}" != "$2/.npmrc" ]] && safe_test_assert_isolated_paths' \
  bash "$ROOT/tests/lib/test-isolation.sh" "$fake_real_home"; then
  pass 'hostile npm config paths are neutralized before suite code'
else
  fail 'hostile npm config path was not neutralized or rejected'
fi

keep_home="$SAFE_TEST_ROOT/keep-tools-home"
keep_tool="$keep_home/tools"
mkdir -p "$keep_tool"
if (
  unset SAFE_TEST_INVOKING_HOME MISE_CONFIG_DIR MISE_DATA_DIR MISE_CACHE_DIR \
    SAFE_TEST_ORIGINAL_PATH SAFE_TEST_ORIGINAL_MISE_CONFIG_DIR \
    SAFE_TEST_ORIGINAL_MISE_DATA_DIR SAFE_TEST_ORIGINAL_MISE_CACHE_DIR \
    SAFE_TEST_ORIGINAL_NPM_PREFIX SAFE_TEST_ORIGINAL_NPM_PREFIX_PRESENT
  export HOME="$keep_home" PATH="$keep_tool:/usr/bin"
  export SAFE_TEST_ISOLATION_KEEP_TOOLS=1
  . "$ROOT/tests/lib/test-isolation.sh"
  safe_test_setup_isolation
  case ":$PATH:" in
    *":$keep_tool:"*) ;;
    *) exit 1 ;;
  esac
  tool_home="$(safe_test_real_home)"
  [[ "$MISE_CONFIG_DIR" == "$tool_home/.config/mise" ]] || exit 1
  [[ "$MISE_DATA_DIR" == "$tool_home/.local/share/mise" ]] || exit 1
  [[ "$MISE_CACHE_DIR" == "$tool_home/.cache/mise" ]] || exit 1
); then
  pass 'keep-tools opt preserves real tool PATH and mise roots'
else
  fail 'keep-tools opt did not preserve real tool discovery'
fi
