#!/usr/bin/env bash
# Unattended all-green installs (operator direction 2026-09-22): a GO with a
# final Socket answer or a ruled out-of-scope skip installs without a terminal
# in the `safe install` lane; any non-green state already refused above keeps
# its own code. The confirm helpers read /dev/tty, so the ROUTING is asserted
# with stubs (mirror of gate_adverse_warn_override.sh).

set -uo pipefail

# SAFE_TEST_ISOLATION_MARKER: every suite owns a scratch HOME and safe state.
# shellcheck disable=SC1091
# shellcheck source=tests/lib/test-isolation.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/test-isolation.sh"
safe_test_setup_isolation || exit 1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

pass() { printf 'ok - %s\n' "$*"; }
fail() { printf 'not ok - %s\n' "$*" >&2; exit 1; }

bash -n "$ROOT/bin/safe" || fail "bin/safe syntax"
pass "bash syntax"

tmp="$(mktemp -d)"
safe_test_compose_exit_trap "rm -rf \"\$tmp\""
export ROOT tmp

mkdir -p "$tmp/bin" "$tmp/run-config"
printf '{"packages":{}}\n' > "$tmp/run-config/blocked.json"
printf '#!/usr/bin/env bash\nexit 0\n' > "$tmp/bin/npm"
chmod +x "$tmp/bin/npm"
export PATH="$tmp/bin:$PATH"
: >"$tmp/gate-log"
: >"$tmp/confirm-log"
export AUDIT_RC=0

run_cmd_install() {
  bash <<'INNER'
source <(sed '/^argv0=/,$d' "$ROOT/bin/safe")
source "$ROOT/lib/gate-lib.sh"
set +e
SAFE_AUDIT_PATH="$tmp/audit"
if [[ "$AUDIT_RC" == "mixed" ]]; then
  cat > "$SAFE_AUDIT_PATH" <<'MIXED'
#!/usr/bin/env bash
n=$(cat "$MIXED_CALLS" 2>/dev/null || echo 0)
n=$((n+1))
printf '%s' "$n" > "$MIXED_CALLS"
[[ "$n" == 1 ]] && exit 10
exit 0
MIXED
else
  printf '#!/bin/sh\nexit %s\n' "$AUDIT_RC" > "$SAFE_AUDIT_PATH"
fi
chmod +x "$SAFE_AUDIT_PATH"
export SAFE_RUN_CONFIG_DIR="$tmp/run-config" SAFE_AUDIT_DATA_DIR="$tmp/audit-data"
mkdir -p "$SAFE_RUN_CONFIG_DIR" "$SAFE_AUDIT_DATA_DIR"
gate_lib_path() { printf '%s' "$tmp/empty-lib"; }
: >"$tmp/empty-lib"
manager=npm
global_mode=0
safe_install_gate_log() { printf '%s | %s\n' "$2" "$3" >>"$tmp/gate-log"; }
# Mimics the real confirm's non-TTY refusal (refuse exits the shell).
safe_install_confirm() { printf 'confirm-consulted\n' >>"$tmp/confirm-log"; exit 102; }
safe_install_trustable_package() { return 1; }
safe_gate_dispatch() { return 0; }
rc=0
( cmd_install --host --yes green@1.0.0 ) 2>"$tmp/err.txt" || rc=$?
printf '%s' "$rc" > "$tmp/rc.txt"
exit 0
INNER
  cat "$tmp/rc.txt" 2>/dev/null
}

# --yes + all-green (exit 0): proceeds, routes, never consults a confirm.
rc="$(AUDIT_RC=0 WITH_YES=1 PACKAGES='green@1.0.0' run_cmd_install)"
[[ "$rc" == "0" ]] || fail "--yes green install failed (rc=$rc)"
[[ ! -s "$tmp/confirm-log" ]] || fail "--yes still consulted the confirm"
grep -q "INSTALL_UNATTENDED_GREEN" "$tmp/gate-log" &&
  fail "--yes logs PROCEED, not the unattended token"
pass "--yes green install proceeds and logs PROCEED"

# Non-TTY + all-green (exit 0, no --yes): proceeds WITHOUT a terminal.
: >"$tmp/gate-log"
run_cmd_install() {
  bash <<'INNER'
source <(sed '/^argv0=/,$d' "$ROOT/bin/safe")
source "$ROOT/lib/gate-lib.sh"
set +e
SAFE_AUDIT_PATH="$tmp/audit"
if [[ "$AUDIT_RC" == "mixed" ]]; then
  cat > "$SAFE_AUDIT_PATH" <<'MIXED'
#!/usr/bin/env bash
n=$(cat "$MIXED_CALLS" 2>/dev/null || echo 0)
n=$((n+1))
printf '%s' "$n" > "$MIXED_CALLS"
[[ "$n" == 1 ]] && exit 10
exit 0
MIXED
else
  printf '#!/bin/sh\nexit %s\n' "$AUDIT_RC" > "$SAFE_AUDIT_PATH"
fi
chmod +x "$SAFE_AUDIT_PATH"
export SAFE_RUN_CONFIG_DIR="$tmp/run-config" SAFE_AUDIT_DATA_DIR="$tmp/audit-data"
mkdir -p "$SAFE_RUN_CONFIG_DIR" "$SAFE_AUDIT_DATA_DIR"
gate_lib_path() { printf '%s' "$tmp/empty-lib"; }
: >"$tmp/empty-lib"
manager=npm
global_mode=0
safe_install_gate_log() { printf '%s | %s\n' "$2" "$3" >>"$tmp/gate-log"; }
# Mimics the real confirm's non-TTY refusal (refuse exits the shell).
safe_install_confirm() { printf 'confirm-consulted\n' >>"$tmp/confirm-log"; exit 102; }
safe_install_host_allow_matches() { return "${HOST_ALLOW_RC:-1}"; }
safe_install_known_matches() { return "${KNOWN_RC:-1}"; }
safe_install_trustable_package() { return 1; }
safe_gate_dispatch() { return 0; }
yes_flag=""
[[ "${WITH_YES:-0}" == "1" ]] && yes_flag="--yes"
rc=0
( cmd_install --host $yes_flag ${PACKAGES:-} ) 2>"$tmp/err.txt" || rc=$?
printf '%s' "$rc" > "$tmp/rc.txt"
exit 0
INNER
  cat "$tmp/rc.txt" 2>/dev/null
}
rc="$(AUDIT_RC=0 WITH_YES=0 PACKAGES='green@1.0.0' run_cmd_install)"
[[ "$rc" == "0" ]] || fail "unattended green install failed (rc=$rc)"
[[ ! -s "$tmp/confirm-log" ]] || fail "unattended green consulted the confirm (no TTY exists)"
grep -q "INSTALL_UNATTENDED_GREEN" "$tmp/gate-log" ||
  fail "unattended green did not log the token"
pass "non-TTY all-green installs without a terminal and logs INSTALL_UNATTENDED_GREEN"

# Multi-package batch: the token names every package.
: >"$tmp/gate-log"
rc="$(AUDIT_RC=0 WITH_YES=0 PACKAGES='green@1.0.0 green2@2.0.0' run_cmd_install)"
[[ "$rc" == "0" ]] || fail "multi-package green install failed (rc=$rc)"
grep -q "INSTALL_UNATTENDED_GREEN" "$tmp/gate-log" &&
  grep -q "green@1.0.0 green2@2.0.0" "$tmp/gate-log" ||
  fail "multi-package token does not name every package"
pass "multi-package batches log every package in the unattended token"

# Non-green exit-0 lanes ride the confirm (refuse 102 non-TTY), never green:
# a host-allow WARN override and a stale-evidence timeout both return 0.
: >"$tmp/gate-log"; : >"$tmp/confirm-log"
rc="$(AUDIT_RC=10 WITH_YES=0 HOST_ALLOW_RC=0 PACKAGES='tolerated@1.0.0' run_cmd_install)"
[[ "$rc" == "102" ]] || fail "host-allow override went unattended green (rc=$rc)"
[[ -s "$tmp/confirm-log" ]] || fail "host-allow override skipped the confirm lane"
grep -q "INSTALL_UNATTENDED_GREEN" "$tmp/gate-log" &&
  fail "host-allow override logged the green token"
pass "host-allow WARN override is not treated as all-green"
: >"$tmp/gate-log"; : >"$tmp/confirm-log"
rc="$(AUDIT_RC=124 WITH_YES=0 KNOWN_RC=0 PACKAGES='stale@1.0.0' run_cmd_install)"
[[ "$rc" == "102" ]] || fail "stale-evidence timeout went unattended green (rc=$rc)"
grep -q "INSTALL_UNATTENDED_GREEN" "$tmp/gate-log" &&
  fail "stale-evidence timeout logged the green token"
pass "stale-evidence timeout is not treated as all-green"

# Non-TTY + pending Socket score (gate exit 14): refuses before any route.
: >"$tmp/gate-log"
: >"$tmp/confirm-log"
rc="$(AUDIT_RC=14 WITH_YES=0 PACKAGES='green@1.0.0' run_cmd_install)"
[[ "$rc" == "102" ]] || { printf 'nontty-pending got %s; err:\n%s\n' "$rc" "$(cat "$tmp/err.txt" 2>/dev/null)" >&2; exit 1; }
[[ ! -s "$tmp/confirm-log" ]] || fail "pending state consulted the confirm"
grep -q "INSTALL_UNATTENDED_GREEN" "$tmp/gate-log" &&
  fail "pending state logged the green token"
pass "pending Socket score refuses 102 and is never treated as all-green"

# --yes + pending Socket score: --yes cannot substitute for the terminal.
rc="$(AUDIT_RC=14 WITH_YES=1 PACKAGES='green@1.0.0' run_cmd_install)"
[[ "$rc" == "102" ]] || { printf 'yes-pending got %s; err:\n' "$rc" >&2; cat "$tmp/err.txt" >&2; exit 1; }
grep -q "INSTALL_UNATTENDED_GREEN" "$tmp/gate-log" &&
  fail "--yes pending logged the green token"
pass "--yes cannot make a pending Socket score all-green"

# Non-TTY + tolerated/host-allowed WARN pass (gate exit 15): not all-green.
: >"$tmp/gate-log"; : >"$tmp/confirm-log"
rc="$(AUDIT_RC=15 WITH_YES=0 PACKAGES='tol@1.0.0' run_cmd_install)"
[[ "$rc" == "102" ]] || fail "tolerated WARN pass did not refuse 102 (rc=$rc)"
grep -q "INSTALL_UNATTENDED_GREEN" "$tmp/gate-log" &&
  fail "tolerated WARN pass logged the green token"
pass "tolerated WARN pass refuses 102 and is never treated as all-green"

# Mixed batch: a host-allow WARN override (returns 0, the install continues)
# followed by a clean package — the batch must not go green off its FINAL
# package (delta-round BLOCKER closure: this is the only shape where the
# aggregation bug manifests, because the override lane does not fail fast).
: >"$tmp/gate-log"; : >"$tmp/confirm-log"
export MIXED_CALLS="$tmp/mixed-calls"
rc="$(AUDIT_RC=mixed HOST_ALLOW_RC=0 WITH_YES=0 PACKAGES='tol@1.0.0 clean@2.0.0' run_cmd_install)"
[[ "$rc" == "102" ]] || fail "mixed batch did not refuse 102 (rc=$rc)"
grep -q "tol@1.0.0 | HOST_ALLOW_OVERRIDE" "$tmp/gate-log" ||
  fail "mixed batch never overrode the first package"
grep -q "clean@2.0.0 | PROCEED" "$tmp/gate-log" ||
  { printf 'mixed gate-log:\n%s\nerr:\n%s\n' "$(cat "$tmp/gate-log")" "$(cat "$tmp/err.txt" 2>/dev/null)" >&2; fail "mixed batch never reached the clean package"; }
grep -q "INSTALL_UNATTENDED_GREEN" "$tmp/gate-log" &&
  fail "mixed batch logged the green token"
pass "a mixed batch never goes green off its final package"

# Non-TTY + consent ask (gate exit 13): refuses 102 (operator decision needed).
: >"$tmp/gate-log"
rc="$(AUDIT_RC=13 WITH_YES=0 PACKAGES='green@1.0.0' run_cmd_install)"
[[ "$rc" == "102" ]] || { printf 'consent got %s; err:\n%s\n' "$rc" "$(cat "$tmp/err.txt" 2>/dev/null)" >&2; exit 1; }
grep -q "INSTALL_UNATTENDED_GREEN" "$tmp/gate-log" &&
  fail "consent ask logged the green token"
pass "fresh-release consent ask refuses 102 outside a terminal"

printf 'unattended-green: all cases passed\n'
