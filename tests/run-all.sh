#!/usr/bin/env bash
# Parallel suite runner. Every suite is scratch-isolated (own mktemp dirs,
# mocked PATH), so they run concurrently: wall-clock is the slowest suite,
# not the sum. SAFE_TEST_JOBS caps concurrency (default: nproc).
#
# Excluded by design: audit/cvss4_exhaustive.sh and audit/fetch_cvss4_ref.sh
# — development cross-checks that need the FIRST oracle bootstrapped into
# tmp/cvss4-ref/; the committed known-answer suite covers the scorer.
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)

SUITES=(
  tests/go/run.sh
  tests/live/npm_config_oracle.sh
  tests/live/npm_abbrev_oracle.sh
  tests/live/composer_abbrev_oracle.sh
  tests/live/shim_delegation.sh
  tests/install/run.sh
  tests/audit/check_version_aware.sh
  tests/audit/socket_tier.sh
  tests/audit/smoke.sh
  tests/audit/ecosystem_audits.sh
  tests/audit/external_binary.sh
  tests/audit/scan_cache.sh
  tests/audit/tool_resolution.sh
  tests/audit/cvss4_known_answers.sh
  tests/audit/scanner_batch.sh
  tests/contract/drift.sh
  tests/contract/report_fp.sh
  tests/run/host_allow_review.sh
  tests/run/safe_audit_integration.sh
  tests/run/scripts_allow.sh
  tests/integration/dispatcher.sh
)

JOBS="${SAFE_TEST_JOBS:-$(nproc 2>/dev/null || echo 4)}"
if ! [[ "$JOBS" =~ ^[1-9][0-9]*$ ]]; then
  printf 'run-all: SAFE_TEST_JOBS must be a positive integer (got %s)\n' "$JOBS" >&2
  exit 2
fi
logdir=$(mktemp -d "${TMPDIR:-/tmp}/safe-tests.XXXXXX")

slug() { printf '%s' "$1" | tr '/' '_'; }

run_suite() {
  local suite="$1" log rc start elapsed
  log="$logdir/$(slug "$suite").log"
  start=$SECONDS
  bash "$ROOT/$suite" > "$log" 2>&1
  rc=$?
  elapsed=$(( SECONDS - start ))
  printf '%s\n%s\n' "$rc" "$elapsed" > "$logdir/$(slug "$suite").rc"
}

running=0
for suite in "${SUITES[@]}"; do
  if (( running >= JOBS )); then
    wait -n
    running=$((running - 1))
  fi
  run_suite "$suite" &
  running=$((running + 1))
done
wait

fail_count=0
for suite in "${SUITES[@]}"; do
  rcfile="$logdir/$(slug "$suite").rc"
  log="$logdir/$(slug "$suite").log"
  if [[ ! -f "$rcfile" ]]; then
    printf 'FAIL %-42s (no result recorded)\n' "$suite"
    fail_count=$((fail_count + 1))
    continue
  fi
  { read -r rc; read -r elapsed; } < "$rcfile"
  summary=$(tail -n 1 "$log" 2>/dev/null || true)
  if [[ "$rc" == "0" ]]; then
    printf 'ok   %-42s %3ss  %s\n' "$suite" "$elapsed" "$summary"
  else
    printf 'FAIL %-42s %3ss  rc=%s  log: %s\n' "$suite" "$elapsed" "$rc" "$log"
    fail_count=$((fail_count + 1))
  fi
done

if (( fail_count > 0 )); then
  printf 'run-all: %d of %d suites FAILED — logs kept in %s\n' "$fail_count" "${#SUITES[@]}" "$logdir" >&2
  exit 1
fi
rm -rf "$logdir"
printf 'run-all: all %d suites passed\n' "${#SUITES[@]}"
