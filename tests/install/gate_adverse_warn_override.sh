#!/usr/bin/env bash
# gate-lib exit-10 (adverse WARN) interactive operator override routing.
#
# The confirm helpers read /dev/tty, which no non-pty test can drive, so the
# TTY gate (safe_gate_install_is_interactive) and the confirm (safe_gate_confirm_warn)
# are stubbed and the ROUTING of safe_gate_check is asserted: which log token,
# which return code, and whether the standing-grant helper fires. The non-TTY
# refusal is also exercised end-to-end by tests/install/run.sh (the `warnme`
# case), which proves the agent path is unchanged.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

pass() { printf 'ok - %s\n' "$*"; }
fail() { printf 'not ok - %s\n' "$*" >&2; exit 1; }

command -v jq >/dev/null 2>&1 || fail "missing required command: jq"

bash -n "$ROOT/lib/gate-lib.sh"
pass "bash syntax"

# shellcheck source=/dev/null
source "$ROOT/lib/gate-lib.sh" || fail "could not source gate-lib.sh"
pass "sourced gate-lib.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
LOGF="$tmp/log.txt"

# --- shared stubs: an adverse WARN (exit 10), no pre-existing host-allow -------
safe_gate_audit_available()   { return 0; }
safe_gate_run_audit()         { return 10; }
safe_gate_audit_op()          { printf 'install'; }
safe_gate_host_allow_matches(){ return 1; }
safe_gate_audit_log()         { printf '%s\n' "$3" >>"$LOGF"; }

GRANT_CALLS=0
safe_gate_warn_grant_host_allow() { GRANT_CALLS=$((GRANT_CALLS + 1)); }

last_log() { tail -n 1 "$LOGF" 2>/dev/null; }

run_gate() {  # captures rc without tripping the harness
  local rc=0
  safe_gate_check "$@" >/dev/null 2>&1 || rc=$?
  printf '%s' "$rc"
}

# --- [y] install once ---------------------------------------------------------
: >"$LOGF"; GRANT_CALLS=0
safe_gate_install_is_interactive() { return 0; }
safe_gate_confirm_warn() { printf 'once'; }
rc="$(run_gate pkg@1.0.0 npm)"
[[ "$rc" == "0" ]]                         || fail "once: expected rc 0, got $rc"
[[ "$(last_log)" == "WARN_TTY_OVERRIDE" ]] || fail "once: expected WARN_TTY_OVERRIDE, got $(last_log)"
(( GRANT_CALLS == 0 ))                     || fail "once: must not record a standing grant"
pass "[y] installs once, no standing grant"

# --- [a] install and allow future reinstalls ----------------------------------
: >"$LOGF"; GRANT_CALLS=0
safe_gate_confirm_warn() { printf 'allow'; }
rc="$(run_gate pkg@1.0.0 npm)"
# NOTE: GRANT_CALLS is bumped in the $() subshell, so re-check via a direct call.
[[ "$rc" == "0" ]]                               || fail "allow: expected rc 0, got $rc"
[[ "$(last_log)" == "WARN_TTY_OVERRIDE_ALLOW" ]] || fail "allow: expected WARN_TTY_OVERRIDE_ALLOW, got $(last_log)"
pass "[a] proceeds and logs the standing-grant intent"

# grant helper actually fires (run in THIS shell, not a subshell)
: >"$LOGF"; GRANT_CALLS=0
safe_gate_check pkg@1.0.0 npm >/dev/null 2>&1 || true
(( GRANT_CALLS == 1 )) || fail "allow: standing-grant helper must fire exactly once (got $GRANT_CALLS)"
pass "[a] fires the standing-grant helper"

# --- [N] / unreadable tty: decline -> refuse 100 ------------------------------
: >"$LOGF"; GRANT_CALLS=0
safe_gate_confirm_warn() { return 1; }
rc="$(run_gate pkg@1.0.0 npm)"
[[ "$rc" == "100" ]]                          || fail "decline: expected rc 100, got $rc"
[[ "$(last_log)" == "REFUSED_WARN_DECLINED" ]] || fail "decline: expected REFUSED_WARN_DECLINED, got $(last_log)"
(( GRANT_CALLS == 0 ))                         || fail "decline: must not record a grant"
pass "[N]/unreadable tty refuses 100, no grant"

# --- non-interactive: unchanged agent path (refuse 100 + host-allow hint) -----
: >"$LOGF"; GRANT_CALLS=0
safe_gate_install_is_interactive() { return 1; }
CONFIRM_CONSULTED=0
safe_gate_confirm_warn() { CONFIRM_CONSULTED=1; printf 'once'; }  # must be ignored
err_out="$(safe_gate_check pkg@1.0.0 npm 2>&1 >/dev/null; true)"
rc=0; safe_gate_check pkg@1.0.0 npm >/dev/null 2>&1 || rc=$?
[[ "$rc" == "100" ]]                     || fail "nontty: expected rc 100, got $rc"
[[ "$(last_log)" == "REFUSED_WARN" ]]    || fail "nontty: expected REFUSED_WARN, got $(last_log)"
(( CONFIRM_CONSULTED == 0 ))             || fail "nontty: the confirm must never run without a TTY"
grep -q "host-allow add" <<<"$err_out"   || fail "nontty: expected the host-allow hint on stderr"
pass "non-interactive refuses 100 with the host-allow hint (agent path unchanged)"

# --- a pre-existing host-allow entry is honored first, even at a TTY -----------
: >"$LOGF"; GRANT_CALLS=0
safe_gate_install_is_interactive() { return 0; }
safe_gate_host_allow_matches()     { return 0; }   # pre-existing grant
CONFIRM_CONSULTED=0
safe_gate_confirm_warn() { CONFIRM_CONSULTED=1; printf 'once'; }
rc=0; safe_gate_check pkg@1.0.0 npm >/dev/null 2>&1 || rc=$?
[[ "$rc" == "0" ]]                       || fail "preexisting: expected rc 0, got $rc"
[[ "$(last_log)" == "HOST_ALLOW_OVERRIDE" ]] || fail "preexisting: expected HOST_ALLOW_OVERRIDE, got $(last_log)"
(( CONFIRM_CONSULTED == 0 ))             || fail "preexisting: a standing grant must not re-prompt"
pass "a pre-existing host-allow entry is honored without prompting"
safe_gate_host_allow_matches() { return 1; }   # restore

# --- the [a] grant helper builds the right safe-run command -------------------
# Use the REAL safe_gate_warn_grant_host_allow with a fake safe-run that records argv.
unset -f safe_gate_warn_grant_host_allow
source "$ROOT/lib/gate-lib.sh"   # restore the real grant helper (+ everything)
# re-install the routing stubs the sourced file overwrote
safe_gate_audit_available()   { return 0; }
safe_gate_run_audit()         { return 10; }
safe_gate_audit_op()          { printf 'install'; }
safe_gate_host_allow_matches(){ return 1; }
safe_gate_audit_log()         { printf '%s\n' "$3" >>"$LOGF"; }

ARGV_LOG="$tmp/argv.txt"
fake_run="$tmp/fake-safe-run"
cat >"$fake_run" <<FAKE
#!/usr/bin/env bash
printf '%s\n' "\$*" >>"$ARGV_LOG"
exit 0
FAKE
chmod +x "$fake_run"
safe_gate_resolve_run_bin() { printf '%s\n' "$fake_run"; }

: >"$ARGV_LOG"
safe_gate_warn_grant_host_allow "left-pad@1.3.0" npm >/dev/null 2>&1
grep -q "host-allow add left-pad@1.3.0 --reason " "$ARGV_LOG" || fail "grant(npm): wrong argv: $(cat "$ARGV_LOG")"
grep -q -- "--ecosystem" "$ARGV_LOG" && fail "grant(npm): must not pass --ecosystem for npm"
pass "grant helper builds: host-allow add <pkg> --reason <canned> (npm)"

: >"$ARGV_LOG"
safe_gate_warn_grant_host_allow "cowsay==6.1" python >/dev/null 2>&1
grep -q "host-allow add cowsay==6.1 --reason .*--ecosystem python" "$ARGV_LOG" \
  || fail "grant(python): expected --ecosystem python: $(cat "$ARGV_LOG")"
pass "grant helper appends --ecosystem python for the python family"

# --- grant failure is surfaced, never fatal (install already proceeded) --------
fail_run="$tmp/fail-safe-run"
cat >"$fail_run" <<'FAKE'
#!/usr/bin/env bash
exit 3
FAKE
chmod +x "$fail_run"
safe_gate_resolve_run_bin() { printf '%s\n' "$fail_run"; }
grant_err="$(safe_gate_warn_grant_host_allow "left-pad@1.3.0" npm 2>&1 >/dev/null; true)"
grep -q "not recorded" <<<"$grant_err" || fail "grant failure must be surfaced: $grant_err"
pass "a failed grant is surfaced, not fatal"

printf 'all gate adverse-warn override checks passed\n'
