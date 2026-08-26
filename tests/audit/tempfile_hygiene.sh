#!/usr/bin/env bash
# Subprocess scratch must be reclaimed, not left in $TMPDIR after a clean run.
#
# safe-audit funnels every scratch directory through new_scratch_dir, which
# registers it in SAFE_AUDIT_SCRATCH_DIRS so the process-exit trap
# (remove_scratch_dirs) can reclaim the whole tree — the mechanism that exists
# because 1382 orphaned scratch trees once filled a workstation's /tmp. A bare
# `tmp=$(mktemp)` bypasses that registry: the file lands directly in $TMPDIR
# and no trap knows about it, so it survives every exit path including rc 0.
#
# setup-new-machines observed exactly that leak live (grype db health scratch,
# among others, left behind after `safe audit` runs exited 0). This test drives
# each formerly-leaking function under an isolated $TMPDIR and asserts that:
#   1. nothing is left directly in $TMPDIR (a bare mktemp would sit there), and
#   2. remove_scratch_dirs reclaims whatever registered scratch it did create.
#
# Hermetic: no network, no real scanners; grype is a stub, and the machine
# helpers are stubbed so the health path runs without a configured target.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SAFE_AUDIT="$ROOT/bin/safe-audit"

PASS_COUNT=0
FAIL_COUNT=0
pass() { printf 'ok - %s\n' "$*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { printf 'not ok - %s\n' "$*" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }

bash -n "$SAFE_AUDIT"

# Each case runs in its own subshell with a private $TMPDIR, sources safe-audit
# (guarded: sourcing does not run main), exercises one function, then runs the
# same cleanup the exit trap would, and finally prints how many entries remain
# directly in $TMPDIR. A leak shows up as a nonzero count.
run_case() {
  local label="$1" body="$2"
  local scratch outdir count
  scratch="$(mktemp -d)"
  outdir="$(mktemp -d)"   # caller-owned output lives here, never under $TMPDIR
  count="$(
    SAFE_AUDIT_PATH="$SAFE_AUDIT" CASE_TMP="$scratch" CASE_OUT="$outdir" CASE_BODY="$body" \
      bash -c '
        set -euo pipefail
        set -- --version
        export TMPDIR="$CASE_TMP"
        # Isolate config/data roots OUTSIDE $TMPDIR so the test never touches
        # the real audit state and any stray write cannot perturb the $TMPDIR
        # leftover count. (Sourcing is guarded and does not run main, so nothing
        # here is actually created — this is belt-and-suspenders hermeticity.)
        export HOME="$CASE_OUT/home"
        export XDG_CONFIG_HOME="$CASE_OUT/home/.config"
        export XDG_DATA_HOME="$CASE_OUT/home/.local/share"
        mkdir -p "$HOME"
        source "$SAFE_AUDIT_PATH" >/dev/null 2>&1

        # Stub the machine + scanner surface so the grype-health path runs
        # without a configured target or a real grype. grype "present" so the
        # raw-status branch (raw + captured stderr) executes.
        machine_type() { printf "local"; }
        scanner_path_for_machine() { printf "%s/grype" "$CASE_TMP"; }
        tool_cache_path() { printf "%s/grype" "$CASE_TMP"; }
        cat > "$CASE_TMP/grype" <<"STUB"
#!/usr/bin/env bash
printf "{\"valid\":true,\"built\":\"2999-01-01T00:00:00Z\",\"schemaVersion\":6}\n"
STUB
        chmod +x "$CASE_TMP/grype"

        eval "$CASE_BODY"

        # What the process-exit trap would do on a clean exit.
        remove_scratch_dirs

        # Count entries left directly in $TMPDIR (the grype stub we planted
        # lives there too, so discount it).
        left=0
        for e in "$TMPDIR"/* "$TMPDIR"/.[!.]*; do
          [ -e "$e" ] || continue
          [ "$e" = "$TMPDIR/grype" ] && continue
          left=$((left + 1))
        done
        # A `<output>.stderr` sibling beside the caller-owned output file is the
        # specific leak grype_db_health_json used to leave; it must not exist.
        for s in "$CASE_OUT"/*.stderr; do
          [ -e "$s" ] && left=$((left + 1))
        done
        printf "%s" "$left"
      '
  )"
  rm -rf "$scratch" "$outdir"
  if [[ "$count" == "0" ]]; then
    pass "$label leaves no scratch in \$TMPDIR after cleanup"
  else
    fail "$label left $count scratch ent\(ies\) in \$TMPDIR"
  fi
}

# machine_grype_db_healthy: created a bare `health` temp before delegating, and
# grype_db_health_json created a bare `raw` plus a `<output>.stderr` sibling.
run_case "machine_grype_db_healthy" 'machine_grype_db_healthy local >/dev/null 2>&1 || true'

# grype_db_health_json directly (raw + stderr), writing health JSON to a file
# inside the case scratch dir so only its own working files are under test.
run_case "grype_db_health_json" 'grype_db_health_json local "$CASE_OUT/health.out" >/dev/null 2>&1 || true'

printf '\n%d passed, %d failed\n' "$PASS_COUNT" "$FAIL_COUNT"
[[ "$FAIL_COUNT" -eq 0 ]]
