#!/usr/bin/env bash
# LIVE suite — probes the checked-in safe-run classifier against the machine's
# actual gate wrappers. The hermetic install suite covers refusal and exec
# behavior; this catches an installed wrapper/marker topology that fixtures
# cannot represent.
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SAFE_RUN="$ROOT/bin/safe-run"
PASS=0
FAIL=0

pass() { printf 'ok - %s\n' "$1"; PASS=$((PASS + 1)); }
fail() { printf 'FAIL - %s\n' "$1"; FAIL=$((FAIL + 1)); }

# Source the executable under argv0=safe-run, as the existing run suites do,
# then call the classifier it ships. This deliberately does not duplicate its
# PATH walk or marker logic in the test.
classify() {
  local tool="$1"
  SAFE_RUN_NO_INIT=1 SAFE_RUN_PATH="$SAFE_RUN" bash -c '
    tool="$1"
    set -- version
    source "$SAFE_RUN_PATH" >/dev/null
    safe_run_find_gate_bound_target "$tool"
  ' safe-run "$tool"
}

classify_with_path() {
  local search_path="$1" tool="$2"
  PATH="$search_path" SAFE_RUN_NO_INIT=1 SAFE_RUN_PATH="$SAFE_RUN" bash -c '
    tool="$1"
    set -- version
    source "$SAFE_RUN_PATH" >/dev/null
    safe_run_find_gate_bound_target "$tool"
  ' safe-run "$tool"
}

declare -A targets=()
found=0
missing=()
for tool in npm go mise; do
  if target="$(classify "$tool")"; then
    targets["$tool"]="$target"
    found=$((found + 1))
    pass "shipped classifier finds a gate-bound ${tool} target (${target})"
  else
    missing+=("$tool")
  fi
done

if (( found == 0 )); then
  printf 'SKIP: no gate-bound npm/go/mise target on PATH; live shim-delegation checks skipped\n'
  exit 0
fi

if (( found != 3 )); then
  fail "partial gate surface: missing ${missing[*]}"
else
  WORK=$(mktemp -d "${TMPDIR:-/tmp}/safe-live-shim-delegation.XXXXXX") || exit 1
  trap 'rm -rf -- "$WORK"' EXIT

  # A marked wrapper remains gate-bound through a symlink at the requested
  # tool name. This models a version-manager shim without duplicating the
  # shipped marker read in this suite.
  ln -s "${targets[npm]}" "${WORK}/npm"
  if linked="$(classify_with_path "${WORK}:$PATH" npm)" && [[ "$linked" == "${WORK}/npm" ]]; then
    pass "shipped classifier accepts the exact npm marker through a symlink"
  else
    fail "classifier did not accept a symlink to the exact npm gate wrapper"
  fi

  # A mise argv0 shim may be named npm but its marker names mise; accepting it
  # would bypass `safe gate npm`. The installed classifier must fail closed.
  mkdir -p "${WORK}/wrong-marker"
  ln -s "${targets[mise]}" "${WORK}/wrong-marker/npm"
  if classify_with_path "${WORK}/wrong-marker:$PATH" npm >/dev/null; then
    fail "classifier accepted an npm path whose marker belongs to mise"
  else
    pass "classifier rejects a mise-marked npm argv0 shim"
  fi
fi

printf '%s passed, %s failed\n' "$PASS" "$FAIL"
(( FAIL == 0 ))
