#!/usr/bin/env bash
# Install-gate BLOCK override (operator rulings 2026-09-30).
#
# A BLOCK (gate exit 20) on one exact resolved version takes a typed override
# at an operator terminal: name@version installs once, `record name@version`
# (advisory-only BLOCK, npm/python) also records the override through
# `safe run host-allow add --accept-block`. Off a terminal, or without an
# exact version, it refuses 104 as before. Gate exit 17 (an override recorded
# on this host covers the BLOCK) confirms at the terminal and refuses 102
# without one. The typed prompt reads /dev/tty, so each case runs inside a pty
# fed with the operator's answer; the audit itself is stubbed and hands the
# gate its result document through SAFE_AUDIT_RESULT_OUT, as safe-audit does.

set -uo pipefail

# SAFE_TEST_ISOLATION_MARKER: every suite owns a scratch HOME and safe state.
# shellcheck source=tests/lib/test-isolation.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/test-isolation.sh"
safe_test_setup_isolation || exit 1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

pass() { printf 'ok - %s\n' "$*"; }
fail() { printf 'not ok - %s\n' "$*" >&2; exit 1; }

for tool in jq python3; do
  command -v "$tool" >/dev/null 2>&1 || fail "missing required command: $tool"
done
bash -n "$ROOT/lib/gate-lib.sh" || fail "gate-lib syntax"
bash -n "$ROOT/bin/safe" || fail "bin/safe syntax"
pass "bash syntax"

tmp="$(mktemp -d)"
safe_test_compose_exit_trap "rm -rf \"\$tmp\""
export ROOT tmp

# Recording stub for the safe-run grant sub-call.
cat > "$tmp/safe-run" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$tmp/safe-run.argv"
STUB
chmod +x "$tmp/safe-run"

# One scenario per process, inside a pty. LANE: wrapper | mise | bin-safe.
cat > "$tmp/scenario.sh" <<'SCENARIO'
#!/usr/bin/env bash
set -uo pipefail
export SAFE_RUN_DATA_DIR="$tmp/data" TMPDIR="$tmp/tmpdir"
mkdir -p "$SAFE_RUN_DATA_DIR" "$TMPDIR"
# shellcheck source=/dev/null
source "$ROOT/lib/gate-lib.sh"
safe_gate_audit_available() { return 0; }
safe_gate_audit_op() { printf 'install'; }
safe_gate_mise_apply_overlay() { :; }
safe_gate_operator_terminal() { [[ "$TEST_TERMINAL" == 1 ]]; }
safe_gate_run_audit() {
  [[ -z "${SAFE_AUDIT_RESULT_OUT:-}" || -z "${TEST_RESULT:-}" ]] || printf '%s\n' "$TEST_RESULT" > "$SAFE_AUDIT_RESULT_OUT"
  printf '%s\n' "${SAFE_AUDIT_RESULT_OUT:-none}" > "$tmp/result-path"
  return "$TEST_AUDIT_RC"
}
SAFE_RUN_BIN="$tmp/safe-run"
rc=0
case "$LANE" in
  wrapper) safe_gate_check "$TEST_PKG" "$TEST_ECO" || rc=$? ;;
  defer)   safe_gate_check "$TEST_PKG" "$TEST_ECO" defer-socket-consent || rc=$? ;;
  mise)    safe_gate_mise_check_with_env '' "$TEST_PKG" "$TEST_ECO" || rc=$? ;;
  bin-safe)
    source <(sed '/^argv0=/,$d' "$ROOT/bin/safe")
    source "$ROOT/lib/gate-lib.sh"
    safe_gate_operator_terminal() { [[ "$TEST_TERMINAL" == 1 ]]; }
    SAFE_RUN_BIN="$tmp/safe-run"
    SAFE_AUDIT_PATH="$tmp/audit-stub"
    cat > "$SAFE_AUDIT_PATH" <<'AUDIT'
#!/usr/bin/env bash
[[ -z "${SAFE_AUDIT_RESULT_OUT:-}" || -z "${TEST_RESULT:-}" ]] || printf '%s\n' "$TEST_RESULT" > "$SAFE_AUDIT_RESULT_OUT"
printf '%s\n' "${SAFE_AUDIT_RESULT_OUT:-none}" > "$tmp/result-path"
exit "$TEST_AUDIT_RC"
AUDIT
    chmod +x "$SAFE_AUDIT_PATH"
    ( safe_install_audit_package "$TEST_PKG" "$TEST_ECO" ) || rc=$?
    ;;
esac
printf '%s' "$rc" > "$tmp/rc"
SCENARIO
chmod +x "$tmp/scenario.sh"

# run_case <lane> <audit-rc> <terminal 0|1> <result-json|""> <typed-answer> [pkg] [eco]
run_case() {
  rm -f "$tmp/rc" "$tmp/result-path" "$tmp/safe-run.argv" "$tmp/data/audit.log"
  printf '%s\n' "$5" | LANE="$1" TEST_AUDIT_RC="$2" TEST_TERMINAL="$3" TEST_RESULT="$4" \
    TEST_PKG="${6:-blk@1.0.0}" TEST_ECO="${7:-npm}" \
    python3 -c 'import pty,sys,os; sys.exit(os.waitstatus_to_exitcode(pty.spawn(sys.argv[1:])))' \
    bash "$tmp/scenario.sh" > "$tmp/out" 2>&1
  cat "$tmp/rc" 2>/dev/null || printf 'none'
}
last_token() { awk -F' \\| ' 'NF >= 6 {t = $6} END {print t}' "$tmp/data/audit.log" 2>/dev/null; }
result_removed() { local p; p="$(cat "$tmp/result-path")"; [[ "$p" != none && ! -e "$p" ]]; }

ADVISORY='{"package":"blk","resolved_versions":["1.0.0"],"block":{"class":"advisory","advisories":["GHSA-aaaa"]},"gate_exit":20}'
MALWARE='{"package":"blk","resolved_versions":["1.0.0"],"block":{"class":"malware","advisories":[]},"gate_exit":20}'
RANGED='{"package":"blk","resolved_versions":["1.0.0","2.0.0"],"block":{"class":"advisory","advisories":["GHSA-aaaa"]},"gate_exit":20}'

# --- off a terminal nothing changes -------------------------------------------
rc="$(run_case wrapper 20 0 "$ADVISORY" '')"
[[ "$rc" == 104 && "$(last_token)" == REFUSED_BLOCK ]] || fail "non-terminal BLOCK: rc=$rc token=$(last_token)"
grep -q 'safe audit verdict BLOCK; operator review required' "$tmp/out" || fail "non-terminal BLOCK message changed: $(cat "$tmp/out")"
result_removed || fail "the wrapper left its result file behind"
pass "an agent or non-terminal shell still gets the unchanged 104 refusal"

# --- typed once ---------------------------------------------------------------
rc="$(run_case wrapper 20 1 "$ADVISORY" 'blk@1.0.0')"
[[ "$rc" == 0 && "$(last_token)" == BLOCK_TTY_OVERRIDE ]] || fail "typed once: rc=$rc token=$(last_token) out=$(cat "$tmp/out")"
grep -q 'GHSA-aaaa' "$tmp/out" || fail "the prompt does not name the blocking advisories"
[[ ! -e "$tmp/safe-run.argv" ]] || fail "a once override recorded something"
pass "typing name@version at an operator terminal installs once, nothing recorded"

rc="$(run_case wrapper 20 1 "$ADVISORY" 'y')"
[[ "$rc" == 100 && "$(last_token)" == REFUSED_BLOCK_DECLINED ]] || fail "y answer: rc=$rc token=$(last_token)"
rc="$(run_case wrapper 20 1 "$ADVISORY" 'blk@1.0.1')"
[[ "$rc" == 100 ]] || fail "wrong identity: rc=$rc"
pass "y or a mistyped identity refuses 100"

# --- record -------------------------------------------------------------------
rc="$(run_case wrapper 20 1 "$ADVISORY" 'record blk@1.0.0')"
[[ "$rc" == 0 && "$(last_token)" == BLOCK_TTY_OVERRIDE_RECORD ]] || fail "record: rc=$rc token=$(last_token)"
grep -q -- '^host-allow add blk@1.0.0 --reason .* --accept-block$' "$tmp/safe-run.argv" \
  || fail "record argv: $(cat "$tmp/safe-run.argv" 2>/dev/null)"
rc="$(run_case wrapper 20 1 '{"package":"blk","resolved_versions":["1.0.0"],"block":{"class":"advisory","advisories":["PYSEC-1"]},"gate_exit":20}' 'record blk@1.0.0' 'blk==1.0.0' python)"
[[ "$rc" == 0 ]] && grep -q -- '--accept-block --ecosystem python$' "$tmp/safe-run.argv" || fail "python record argv: $(cat "$tmp/safe-run.argv" 2>/dev/null)"
pass "record name@version installs and records through host-allow add --accept-block"

rc="$(run_case wrapper 20 1 "$MALWARE" 'record blk@1.0.0')"
[[ "$rc" == 100 && ! -e "$tmp/safe-run.argv" ]] || fail "malware record: rc=$rc"
grep -q 'never recorded' "$tmp/out" || fail "the malware prompt does not say it is never recorded"
rc="$(run_case wrapper 20 1 "$MALWARE" 'blk@1.0.0')"
[[ "$rc" == 0 && "$(last_token)" == BLOCK_TTY_OVERRIDE ]] || fail "malware once: rc=$rc"
rc="$(run_case wrapper 20 1 '{"package":"blk","resolved_versions":["1.0.0"],"block":{"class":"advisory","advisories":["RUSTSEC-1"]},"gate_exit":20}' 'record blk@1.0.0' blk@1.0.0 cargo)"
[[ "$rc" == 100 && ! -e "$tmp/safe-run.argv" ]] || fail "cargo record: rc=$rc"
pass "malware and non-grantable ecosystems take the once override only"

# --- no exact version ---------------------------------------------------------
rc="$(run_case wrapper 20 1 "$RANGED" 'blk@1.0.0')"
[[ "$rc" == 104 ]] || fail "ranged BLOCK: rc=$rc"
rc="$(run_case wrapper 20 1 '' 'blk@1.0.0')"
[[ "$rc" == 104 ]] || fail "missing result: rc=$rc"
rc="$(run_case wrapper 20 1 '{"package":"blk","resolved_versions":["1.0.0"],"block":{"class":"unresolved","advisories":[]},"gate_exit":20}' 'blk@1.0.0')"
[[ "$rc" == 104 ]] || fail "unresolved class: rc=$rc"
pass "a BLOCK without one exact version refuses 104 even at a terminal"

# --- recorded override on this host (17) ---------------------------------------
rc="$(run_case wrapper 17 0 "$ADVISORY" '')"
[[ "$rc" == 102 && "$(last_token)" == REFUSED_RECORDED_BLOCK_OVERRIDE_NONTTY ]] || fail "17 non-terminal: rc=$rc"
rc="$(run_case wrapper 17 1 "$ADVISORY" 'y')"
[[ "$rc" == 0 && "$(last_token)" == RECORDED_BLOCK_OVERRIDE_TTY ]] || fail "17 confirm: rc=$rc"
rc="$(run_case wrapper 17 1 "$ADVISORY" 'n')"
[[ "$rc" == 100 && "$(last_token)" == REFUSED_RECORDED_BLOCK_OVERRIDE_DECLINED ]] || fail "17 decline: rc=$rc"
pass "a locally recorded override confirms at the terminal and refuses 102 without one"

# --- mise: the child defers, the parent's terminal decides -----------------------
rc="$(run_case defer 20 1 "$ADVISORY" '')"
[[ "$rc" == 20 ]] || fail "deferring child: rc=$rc"
rc="$(run_case mise 20 1 "$ADVISORY" 'blk@1.0.0')"
[[ "$rc" == 0 && "$(last_token)" == BLOCK_TTY_OVERRIDE ]] || fail "mise once: rc=$rc token=$(last_token) out=$(cat "$tmp/out")"
result_removed || fail "the mise parent left its result file behind"
rc="$(run_case mise 20 0 "$ADVISORY" '')"
[[ "$rc" == 104 ]] || fail "mise non-terminal: rc=$rc"
rc="$(run_case mise 17 0 "$ADVISORY" '')"
[[ "$rc" == 102 ]] || fail "mise 17 non-terminal: rc=$rc"
pass "mise install puts the deferred BLOCK override to its own terminal"

# --- safe install lane --------------------------------------------------------
rc="$(run_case bin-safe 20 1 "$ADVISORY" 'blk@1.0.0')"
[[ "$rc" == 0 && "$(last_token)" == BLOCK_TTY_OVERRIDE ]] || fail "safe install once: rc=$rc out=$(cat "$tmp/out")"
result_removed || fail "safe install left its result file behind"
rc="$(run_case bin-safe 20 0 "$ADVISORY" '')"
[[ "$rc" == 104 ]] || fail "safe install non-terminal: rc=$rc"
rc="$(run_case bin-safe 17 0 "$ADVISORY" '')"
[[ "$rc" == 102 ]] || fail "safe install 17 non-terminal: rc=$rc"
rc="$(run_case bin-safe 0 0 '' '')"
[[ "$rc" == 0 ]] && result_removed || fail "safe install GO kept its result file (rc=$rc)"
pass "safe install shares the override lanes and cleans up its result file"

printf 'all gate BLOCK override checks passed\n'
