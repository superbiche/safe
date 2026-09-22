#!/usr/bin/env bash
# Parallel suite runner. Every suite is scratch-isolated (own mktemp dirs);
# default suites use a clean PATH and live tool probes opt into real tools, so
# they run concurrently: wall-clock is the slowest suite, not the sum.
#
# Excluded by design: the two CVSS development cross-checks need the FIRST
# oracle bootstrapped into tmp/cvss4-ref/; the committed known-answer suite
# covers the scorer. The socket and syft probes remain excluded per their own
# headers; the four tool probes below are release-gate members.
set -u

# The live probes opt into real tool discovery themselves. Do not let an
# ambient opt leak into the aggregate's non-live children.
unset SAFE_TEST_ISOLATION_KEEP_TOOLS

ROOT=$(cd "$(dirname "$0")/.." && pwd)
# SAFE_TEST_ISOLATION_MARKER: the aggregate runner owns the outer scratch tree.
# shellcheck source=tests/lib/test-isolation.sh
. "$ROOT/tests/lib/test-isolation.sh"
safe_test_setup_isolation || exit 1

SUITES=(
  tests/go/run.sh
  tests/live/npm_config_oracle.sh
  tests/live/npm_abbrev_oracle.sh
  tests/live/composer_abbrev_oracle.sh
  tests/live/shim_delegation.sh
  tests/install/run.sh
  tests/install/socket_command_consent.sh
  tests/install/unattended_green.sh
  tests/install/gate_adverse_warn_override.sh
  tests/audit/check_version_aware.sh
  tests/audit/socket_tier.sh
  tests/audit/smoke.sh
  tests/audit/ecosystem_audits.sh
  tests/audit/scan_cache.sh
  tests/audit/scan_report.sh
  tests/audit/tool_resolution.sh
  tests/audit/lockfile_coverage.sh
  tests/audit/cvss4_known_answers.sh
  tests/audit/scanner_batch.sh
  tests/audit/release_review_forward.sh
  tests/audit/tempfile_hygiene.sh
  tests/contract/drift.sh
  tests/contract/docs_drift.sh
  tests/contract/home_isolation.sh
  tests/contract/wrapper_detect_parity.sh
  tests/contract/report_fp.sh
  tests/run/host_allow_review.sh
  tests/run/host_allow_export_import.sh
  tests/run/host_allow_follow.sh
  tests/run/release_follow.sh
  tests/run/safe_audit_integration.sh
  tests/run/scripts_allow.sh
  tests/run/trust_store_redirect.sh
  tests/integration/dispatcher.sh
)

# Parity-belt guard (AGENTS.md § Tests): every depth-2 test script must be
# registered in SUITES or excluded here — a migration slice cannot add or
# strand a belt suite silently.
EXCLUDED=(
  tests/audit/cvss4_exhaustive.sh   # dev cross-check needing a bootstrapped oracle
  tests/audit/fetch_cvss4_ref.sh    # dev bootstrap helper for that oracle
  tests/live/socket_envelope.sh     # opt-in live network probe, excluded per its own header
  tests/live/syft_exclude_oracle.sh # opt-in live probe needing an installed syft, excluded per its own header
  tests/lib/test-isolation.sh       # shared HOME/state isolation helper, not a suite
  tests/lib/safe-core.sh            # shared helper, not a suite
  tests/lib/real-tool.sh            # shared helper (real-toolchain resolver), not a suite
  tests/fixtures/release_follow_pre_fix.sh # checked-in pre-fix driver for the release-follow non-vacuity case, not a suite
)
for f in "$ROOT"/tests/*/*.sh; do
  rel=${f#"$ROOT"/}
  found=0
  for s in "${SUITES[@]}" "${EXCLUDED[@]}"; do
    [[ $rel == "$s" ]] && { found=1; break; }
  done
  if (( ! found )); then
    printf 'run-all: %s is not in SUITES or EXCLUDED — register it (parity belt, AGENTS.md § Tests)\n' "$rel" >&2
    exit 2
  fi
done

# The aggregate runner never lets the Go belt skip itself into a false green.
export SAFE_TEST_STRICT=1

JOBS="${SAFE_TEST_JOBS:-$(nproc 2>/dev/null || echo 4)}"
if ! [[ "$JOBS" =~ ^[1-9][0-9]*$ ]]; then
  printf 'run-all: SAFE_TEST_JOBS must be a positive integer (got %s)\n' "$JOBS" >&2
  exit 2
fi
logdir=$(mktemp -d "${SAFE_TEST_PARENT_TMPDIR:-/tmp}/safe-tests.XXXXXX")

slug() { printf '%s' "$1" | tr '/' '_'; }

run_suite() {
  local suite="$1" log rc start elapsed
  log="$logdir/$(slug "$suite").log"
  start=$SECONDS
  env -u SAFE_TEST_ISOLATION_KEEP_TOOLS bash "$ROOT/$suite" > "$log" 2>&1
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
