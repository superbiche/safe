#!/usr/bin/env bash
# #87 — trust-store redirection guard. A constrained agent (gated: may only
# invoke runners THROUGH safe) must not escape the sandbox by pointing safe at a
# store it controls via SAFE_RUN_CONFIG_DIR / SAFE_CONFIG_DIR — either writing a
# forged trust entry through safe's own commands (write side) or pre-seeding a
# store and running `safe run <pkg>` so a host-allow / scripts-allow grant is
# honored from the redirected root (read side twin, incl. lib/gate-lib.sh).
#
# The guard anchors trust to the canonical $HOME-derived store; a redirected
# root carries trust only under the explicit, logged SAFE_RUN_TRUST_OVERRIDE
# token (env-forgeable by construction — the accepted bash floor; its value is a
# loud, greppable transcript tripwire, not a hard wall). Reads fail-safe to the
# sandbox; writes hard-refuse (exit 100). The canonical blocklist is unioned in
# so a redirect cannot HIDE a malice signal (fail-closed doctrine).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SAFE_RUN="$ROOT/bin/safe-run"
SAFE_AUDIT="$ROOT/bin/safe-audit"
SAFE="$ROOT/bin/safe"
GATE_LIB="$ROOT/lib/gate-lib.sh"

pass() { printf 'ok - %s\n' "$*"; }
fail() { printf 'not ok - %s\n' "$*" >&2; exit 1; }
require() { command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"; }

require bash
require jq

bash -n "$SAFE_RUN"
bash -n "$GATE_LIB"
pass "bash syntax"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Canonical store lives under a fake HOME so the suite never touches the real
# ~/.config/safe. REDIR is a non-canonical root an "attacker" would supply.
H="$tmp/home"
CANON="$H/.config/safe/run"
REDIR="$tmp/redir/config"
mkdir -p "$CANON" "$REDIR" "$tmp/data"
printf '{"packages":{}}\n' > "$CANON/host-allow.json"
printf '{"packages":{}}\n' > "$CANON/blocked.json"
printf '{"packages":{}}\n' > "$REDIR/host-allow.json"
printf '{"packages":{}}\n' > "$REDIR/scripts-allow.json"
printf '{"packages":{}}\n' > "$REDIR/blocked.json"

# --- Part 1: write refusals (exit 100, store untouched) -------------------
# Falsifier: without the guard, add/update/import land the entry, and
# scripts-allow add reaches the TTY gate (exit 102) instead of 100.
redir_run() {
  HOME="$H" SAFE_RUN_CONFIG_DIR="$REDIR" SAFE_RUN_DATA_DIR="$tmp/data" \
  SAFE_RUN_NO_INIT=1 "$SAFE_RUN" "$@"
}

for verb in add update; do
  set +e
  out=$(redir_run host-allow "$verb" evil-pkg@1.0.0 --reason x </dev/null 2>&1); rc=$?
  set -e
  [[ "$rc" -eq 100 ]] || fail "host-allow $verb on redirected store must exit 100 (got $rc)"
  grep -q "trust store redirected" <<<"$out" || fail "host-allow $verb refusal not legible"
  jq -e '.packages | length == 0' "$REDIR/host-allow.json" >/dev/null \
    || fail "host-allow $verb must not write to the redirected store"
done
pass "host-allow add/update on a redirected store refuse (exit 100), nothing written"

printf '{"schema":"safe-host-allow-export/1","packages":{"evil-pkg":{"version":"1.0.0","ecosystem":"npm","added":"2026-08-27","reason":"x"}}}\n' > "$tmp/export.json"
set +e
out=$(redir_run host-allow import "$tmp/export.json" </dev/null 2>&1); rc=$?
set -e
[[ "$rc" -eq 100 ]] || fail "host-allow import on redirected store must exit 100 (got $rc)"
jq -e '.packages | length == 0' "$REDIR/host-allow.json" >/dev/null \
  || fail "host-allow import must not write to the redirected store"
pass "host-allow import on a redirected store refuses (exit 100), nothing written"

set +e
out=$(redir_run scripts-allow add evil-pkg@1.0.0 --reason x </dev/null 2>&1); rc=$?
set -e
[[ "$rc" -eq 100 ]] || fail "scripts-allow add on redirected store must exit 100, not the TTY 102 (got $rc)"
grep -q "trust store redirected" <<<"$out" || fail "scripts-allow add refusal not legible"
pass "scripts-allow add on a redirected store refuses (exit 100) before the TTY gate"

# --- Part 2: the token lifts the guard (reaches the TTY gate: 102) --------
set +e
out=$(HOME="$H" SAFE_RUN_CONFIG_DIR="$REDIR" SAFE_RUN_DATA_DIR="$tmp/data" \
  SAFE_RUN_NO_INIT=1 SAFE_RUN_TRUST_OVERRIDE=1 \
  "$SAFE_RUN" host-allow add evil-pkg@1.0.0 --reason x </dev/null 2>&1); rc=$?
set -e
[[ "$rc" -eq 102 ]] || fail "token must lift the write guard to the TTY gate exit 102 (got $rc)"
pass "SAFE_RUN_TRUST_OVERRIDE lifts the write guard (falls through to the TTY gate)"

# --- Part 3: read-side host-allow grant guard (unit) ----------------------
# Seed a host-allow entry in BOTH stores so only the guard, not a missing
# entry, decides the outcome.
printf '{"packages":{"trust-pkg":{"version":"1.0.0","sha":"a","ecosystem":"npm","added":"2026-08-27","reason":"x"}}}\n' > "$REDIR/host-allow.json"
printf '{"packages":{"trust-pkg":{"version":"1.0.0","sha":"a","ecosystem":"npm","added":"2026-08-27","reason":"x"}}}\n' > "$CANON/host-allow.json"

read_fixture='
  set -- version
  source "$SAFE_RUN_PATH" >/dev/null
  PKG_VERSION_USER_SPECIFIED=1
  if in_host_allow trust-pkg 1.0.0; then echo GRANTED; else echo DECLINED; fi
'
read_probe() {
  HOME="$H" SAFE_RUN_DATA_DIR="$tmp/data" SAFE_RUN_NO_INIT=1 SAFE_RUN_PATH="$SAFE_RUN" \
  "$@" bash -c "$read_fixture" safe-run 2>"$tmp/read.err"
}

out=$(SAFE_RUN_CONFIG_DIR="$REDIR" read_probe env)
[[ "$out" == "DECLINED" ]] || fail "redirected host-allow read must be declined (got $out)"
grep -q "ignored for host-allow grant" "$tmp/read.err" || fail "read decline must warn on stderr"
pass "redirected host-allow read is declined (fail-safe to sandbox) with a stderr tripwire"

out=$(SAFE_RUN_CONFIG_DIR="$REDIR" read_probe env SAFE_RUN_TRUST_OVERRIDE=1)
[[ "$out" == "GRANTED" ]] || fail "redirected host-allow read with token must be granted (got $out)"
pass "redirected host-allow read is honored under the token"

# Falsifier: the canonical store (no override) grants normally — proves the
# guard fires ONLY on redirection.
out=$(SAFE_RUN_CONFIG_DIR="$CANON" read_probe env)
[[ "$out" == "GRANTED" ]] || fail "canonical host-allow read must be granted (got $out)"
pass "canonical host-allow read is unaffected by the guard"

# --- Part 4: blocklist union (a redirect cannot HIDE a malice signal) -----
printf '{"packages":{"malice-pkg":{"reason":"known-bad","added":"2026-08-27"}}}\n' > "$CANON/blocked.json"
printf '{"packages":{}}\n' > "$REDIR/blocked.json"

blocked_fixture='
  set -- version
  source "$SAFE_RUN_PATH" >/dev/null
  if in_blocked malice-pkg; then echo BLOCKED; else echo CLEAR; fi
'
blocked_probe() {
  HOME="$H" SAFE_RUN_DATA_DIR="$tmp/data" SAFE_RUN_NO_INIT=1 SAFE_RUN_PATH="$SAFE_RUN" \
  "$@" bash -c "$blocked_fixture" safe-run 2>/dev/null
}

out=$(SAFE_RUN_CONFIG_DIR="$REDIR" blocked_probe env)
[[ "$out" == "BLOCKED" ]] || fail "redirected empty blocklist must still union-in the canonical malice signal (got $out)"
pass "a redirected (empty) blocklist cannot hide the canonical malice signal"

# The blocklist is a malice signal: the token blesses GRANTS, never the
# suppression of a block. Even a BLESSED redirect must still union the canonical
# blocklist in, so a forgeable token cannot empty it (fail-closed doctrine, F2).
out=$(SAFE_RUN_CONFIG_DIR="$REDIR" blocked_probe env SAFE_RUN_TRUST_OVERRIDE=1)
[[ "$out" == "BLOCKED" ]] || fail "even a blessed token must not hide the canonical malice signal (got $out)"
pass "a blessed token cannot hide a canonical block (blocklist always unions canonical)"

# --- Part 5: gate-lib read-side twin (npm install wrapper) ----------------
printf '{"packages":{"gpkg":{"version":"1.0.0","ecosystem":"npm","added":"2026-08-27","reason":"x"}}}\n' > "$REDIR/host-allow.json"
printf '{"packages":{"gpkg":{"version":"1.0.0","ecosystem":"npm","added":"2026-08-27","reason":"x"}}}\n' > "$REDIR/scripts-allow.json"

gate_probe() {  # $1 = extra env assignment or "env"
  HOME="$H" SAFE_RUN_CONFIG_DIR="$REDIR" "$@" \
    bash -c "source '$GATE_LIB'
      if safe_gate_host_allow_matches 'gpkg@1.0.0' npm; then echo HA_MATCH; else echo HA_NOMATCH; fi
      safe_gate_npm_scripts_env 'gpkg@1.0.0' >/dev/null
      printf 'scripts=%s\n' \"\${npm_config_allow_scripts:-unset}\"" 2>"$tmp/gate.err"
}

out=$(gate_probe env)
grep -q "HA_NOMATCH" <<<"$out" || fail "gate-lib host-allow on a redirected store must not match (got: $out)"
grep -q "scripts=unset" <<<"$out" || fail "gate-lib must not inject allow-scripts from a redirected store"
grep -q "ignored for host-allow grant" "$tmp/gate.err" || fail "gate-lib host-allow decline must warn"
grep -q "ignored for scripts-allow grant" "$tmp/gate.err" || fail "gate-lib scripts decline must warn"
pass "gate-lib host-allow + scripts-allow grants are declined on a redirected store (fail-safe)"

# Falsifier: the token lets the gate-lib host-allow grant match again.
out=$(gate_probe env SAFE_RUN_TRUST_OVERRIDE=1)
grep -q "HA_MATCH" <<<"$out" || fail "gate-lib host-allow under the token must match (got: $out)"
pass "gate-lib host-allow grant is honored under the token"

# --- Part 6: safe-audit install-gate host-allow decline (F1) --------------
# The install gate calls `safe-audit … --gate install` FIRST; a redirected
# host-allow must not let safe-audit turn a WARN into GO. Unit-drive the
# authority function (sourcing safe-audit is guarded; main is a no-op here).
printf '{"packages":{"gpkg":{"version":"1.0.0","ecosystem":"npm"}}}\n' > "$CANON/host-allow.json"
audit_ha_probe() {  # $@ = extra env
  HOME="$H" SAFE_RUN_CONFIG_DIR="$REDIR" SAFE_AUDIT_NO_INIT=1 "$@" \
    bash -c "source '$SAFE_AUDIT' >/dev/null 2>&1
      host_allow_matches_resolved npm gpkg 1.0.0 && echo HA_MATCH || echo HA_NOMATCH" 2>"$tmp/audit.err"
}
[[ "$(audit_ha_probe env)" == "HA_NOMATCH" ]] \
  || fail "safe-audit host-allow on a redirected store must not match (install-gate F1)"
grep -q "ignored for host-allow grant" "$tmp/audit.err" || fail "safe-audit host-allow decline must warn"
[[ "$(audit_ha_probe env SAFE_RUN_TRUST_OVERRIDE=1)" == "HA_MATCH" ]] \
  || fail "safe-audit host-allow under the token must match"
pass "safe-audit install-gate host-allow grant is declined on a redirected store (F1)"

# --- Part 7: safe-audit blocklist union / authority (F2) ------------------
printf '{"packages":{"malice-pkg":{"reason":"known-bad"}}}\n' > "$CANON/blocked.json"
printf '{"packages":{}}\n' > "$REDIR/blocked.json"
audit_block_probe() {  # $@ = extra env; stderr captured to $tmp/audit_block.err
  HOME="$H" SAFE_RUN_CONFIG_DIR="$REDIR" SAFE_AUDIT_NO_INIT=1 "$@" \
    bash -c "source '$SAFE_AUDIT' >/dev/null 2>&1
      blocked_entry_reason malice-pkg >/dev/null && echo BLOCKED || echo CLEAR" 2>"$tmp/audit_block.err"
}
[[ "$(audit_block_probe env)" == "BLOCKED" ]] \
  || fail "safe-audit must union the canonical blocklist (redirect cannot hide a block, F2)"
# The blocklist is a malice signal, so the token cannot empty it on the install
# gate either: a BLESSED redirect must still union the canonical blocklist (F2).
[[ "$(audit_block_probe env SAFE_RUN_TRUST_OVERRIDE=1)" == "BLOCKED" ]] \
  || fail "even a blessed token must not hide a canonical block on the install gate (F2)"
# The install gate stays quiet on the blocklist path — the token's presence is
# surfaced by the host-allow grant warning, not by per-package blocklist spam
# (no stderr leak: token-blessed suites assert an empty stderr).
[[ ! -s "$tmp/audit_block.err" ]] \
  || fail "blocklist lookups must not leak to stderr (got: $(cat "$tmp/audit_block.err"))"
pass "safe-audit always unions the canonical blocklist; a blessed token cannot hide a block (F2)"

# (bin/safe's `safe install --trust-host` write refusal (F4) is exercised
# end-to-end in tests/integration/dispatcher.sh, which has the mock npm +
# verdict-engine harness the writer path requires. That suite also covers the
# SAFE_RUN_CONFIG_DIR alias, twin to SAFE_CONFIG_DIR, for the F1 precedence fix.)

# --- Part 8: F5 — the refusal stays stderr-final even if the data root is
# unwritable. audit_log runs an unredirected mkdir/append; a permission
# diagnostic must not trail the single BLOCKED line the contract promises.
if [[ "$EUID" -ne 0 ]]; then
  baddata="$tmp/baddata"
  mkdir -p "$baddata"
  chmod 000 "$baddata"
  set +e
  errout=$(HOME="$H" SAFE_RUN_CONFIG_DIR="$REDIR" SAFE_RUN_DATA_DIR="$baddata" \
    SAFE_RUN_NO_INIT=1 "$SAFE_RUN" host-allow add evil-pkg@1.0.0 --reason x \
    </dev/null 2>&1 >/dev/null); rc=$?
  set -e
  chmod 755 "$baddata"
  [[ "$rc" -eq 100 ]] || fail "unwritable data root must not change the exit-100 refusal (got $rc)"
  last=$(printf '%s\n' "$errout" | grep -v '^[[:space:]]*$' | tail -n1)
  grep -q "trust store redirected" <<<"$last" \
    || fail "BLOCKED line must be the FINAL stderr line under an unwritable data root (got: $last)"
  pass "trust write refusal stays stderr-final under an unwritable data root (F5)"
else
  pass "F5 unwritable-data-root case skipped (running as root; perms are advisory)"
fi

# --- Part 9: N1 — a fresh unblessed redirect must not abort non-npm runners.
# F4 seeds no host-allow.json under an unblessed redirect; the non-npm dispatch
# diagnostic (and cmd_status) must tolerate its absence rather than jq-abort
# under set -e. Exercised through REAL production init (no NO_INIT) + no token,
# the exact conditions the F4 fix created — a fresh redirect with no trust file.
n1home="$tmp/n1home"; n1redir="$tmp/n1redir/config"; n1data="$tmp/n1data"
mkdir -p "$n1home" "$n1redir" "$n1data"
shimdir="$tmp/n1shim"; mkdir -p "$shimdir"
for r in uvx bunx pipx; do
  ln -sf "$SAFE_RUN" "$shimdir/$r"
  set +e
  out=$(HOME="$n1home" SAFE_RUN_CONFIG_DIR="$n1redir" SAFE_RUN_DATA_DIR="$n1data" \
    "$shimdir/$r" n1-unknown-pkg </dev/null 2>&1); rc=$?
  set -e
  [[ ! -f "$n1redir/host-allow.json" ]] \
    || fail "$r: an unblessed redirect must not seed host-allow.json (F4)"
  [[ "$rc" -eq 102 ]] \
    || fail "$r: fresh unblessed redirect must reach the non-interactive policy exit 102, not a jq abort (got $rc): $out"
done
pass "non-npm runners tolerate an absent host-allow file under a fresh unblessed redirect (N1)"

# --- Part 10: N1 sibling class — the F4 no-seed change also left the non-guarded
# management readers (host-allow/scripts-allow list + remove) reading a raw,
# now-absent store. They must treat "absent" as "empty", not abort under
# set -e/pipefail. Fresh unblessed redirect, real production init, no token.
mgmt_home="$tmp/mgmt-home"; mgmt_redir="$tmp/mgmt-redir/config"; mgmt_data="$tmp/mgmt-data"
mkdir -p "$mgmt_home" "$mgmt_redir" "$mgmt_data"
mgmt_run() {
  HOME="$mgmt_home" SAFE_RUN_CONFIG_DIR="$mgmt_redir" SAFE_RUN_DATA_DIR="$mgmt_data" \
    "$SAFE_RUN" "$@" </dev/null
}
for cmd in "host-allow list" "scripts-allow list" \
           "host-allow remove somepkg" "scripts-allow remove somepkg"; do
  set +e
  # shellcheck disable=SC2086
  mgmt_out=$(mgmt_run $cmd 2>&1); mgmt_rc=$?
  set -e
  [[ "$mgmt_rc" -eq 0 ]] \
    || fail "safe run $cmd on a fresh unblessed redirect must tolerate the absent store (got rc=$mgmt_rc): $mgmt_out"
done
# The absent store must NOT be created as a side effect of a read/remove.
[[ ! -f "$mgmt_redir/host-allow.json" && ! -f "$mgmt_redir/scripts-allow.json" ]] \
  || fail "management readers must not seed a trust file under an unblessed redirect"
pass "host-allow/scripts-allow list + remove tolerate an absent store (N1 sibling sweep)"

# --- Part 11: N2 — a present-but-malformed/unreadable authority member is
# BREAKAGE, not "not blocked". The always-union reader and the fail-closed
# validity gate must consume the SAME member list, so a blessed redirect cannot
# let a malformed CANONICAL blocklist pass as readable and hide a canonical
# block. Run lane (in_blocked) refuses; audit lane's validity gate flags it.
printf 'this is not valid json\n' > "$CANON/blocked.json"
printf '{"packages":{}}\n' > "$REDIR/blocked.json"
n2_run_fixture='
  set -- version
  source "$SAFE_RUN_PATH" >/dev/null
  in_blocked anything-pkg; echo "RET=$?"
'
set +e
n2_out=$(HOME="$H" SAFE_RUN_CONFIG_DIR="$REDIR" SAFE_RUN_DATA_DIR="$tmp/data" SAFE_RUN_NO_INIT=1 \
  SAFE_RUN_PATH="$SAFE_RUN" SAFE_RUN_TRUST_OVERRIDE=1 \
  bash -c "$n2_run_fixture" safe-run 2>"$tmp/n2.err"); n2_rc=$?
set -e
[[ "$n2_rc" -eq 100 ]] \
  || fail "malformed canonical blocklist under a blessed redirect must refuse (exit 100), not pass as readable (rc=$n2_rc)"
grep -q "cannot read the blocklist" "$tmp/n2.err" || fail "blocklist breakage must be legible (got: $(cat "$tmp/n2.err"))"
grep -q "not a package verdict" "$tmp/n2.err" || fail "blocklist breakage must be framed as breakage-to-fix, not a malice verdict"
pass "run lane refuses a malformed canonical blocklist under a blessed redirect (N2, breakage-framed)"

# safe-audit validity gate: unreadable when the canonical member is malformed,
# even under a blessed token (the gate validates every member searched, not just
# trust_store_file's single selection).
audit_n2_probe() {  # $@ = extra env
  HOME="$H" SAFE_RUN_CONFIG_DIR="$REDIR" SAFE_AUDIT_NO_INIT=1 "$@" \
    bash -c "source '$SAFE_AUDIT' >/dev/null 2>&1
      blocklist_authority_readable && echo READABLE || echo UNREADABLE" 2>/dev/null
}
[[ "$(audit_n2_probe env SAFE_RUN_TRUST_OVERRIDE=1)" == "UNREADABLE" ]] \
  || fail "safe-audit must flag a malformed CANONICAL blocklist member even under a blessed redirect (N2)"
printf '{"packages":{}}\n' > "$CANON/blocked.json"   # canonical now valid
[[ "$(audit_n2_probe env SAFE_RUN_TRUST_OVERRIDE=1)" == "READABLE" ]] \
  || fail "safe-audit must read a valid canonical+redirected union as readable"
pass "safe-audit validity gate covers every authority member searched (N2)"

# A present-but-NON-REGULAR member (e.g. a directory at the canonical
# blocked.json path) must fail closed too, not be treated as absent — audit-lane
# parity with the run lane (round-4 N2 residual: -f vs -e).
rm -f "$CANON/blocked.json"; mkdir -p "$CANON/blocked.json"
[[ "$(audit_n2_probe env SAFE_RUN_TRUST_OVERRIDE=1)" == "UNREADABLE" ]] \
  || fail "safe-audit must fail closed on a non-regular canonical blocklist member (N2 lane parity)"
rmdir "$CANON/blocked.json"; printf '{"packages":{}}\n' > "$CANON/blocked.json"
pass "safe-audit fails closed on a non-regular canonical blocklist member (N2 lane parity)"

# Unreadable (not malformed) canonical member — same breakage class. chmod 000
# is advisory for root, so skip there.
if [[ "$EUID" -ne 0 ]]; then
  printf '{"packages":{}}\n' > "$CANON/blocked.json"; chmod 000 "$CANON/blocked.json"
  set +e
  n2u_out=$(HOME="$H" SAFE_RUN_CONFIG_DIR="$REDIR" SAFE_RUN_DATA_DIR="$tmp/data" SAFE_RUN_NO_INIT=1 \
    SAFE_RUN_PATH="$SAFE_RUN" SAFE_RUN_TRUST_OVERRIDE=1 \
    bash -c "$n2_run_fixture" safe-run 2>"$tmp/n2u.err"); n2u_rc=$?
  set -e
  chmod 644 "$CANON/blocked.json"
  [[ "$n2u_rc" -eq 100 ]] \
    || fail "an unreadable canonical blocklist member must refuse, not be silently skipped (rc=$n2u_rc)"
  grep -q "cannot read the blocklist" "$tmp/n2u.err" || fail "unreadable-blocklist breakage must be legible"
  pass "run lane refuses an unreadable canonical blocklist member (N2)"
else
  pass "N2 unreadable-member case skipped (running as root; perms are advisory)"
fi

# --- Part 12: N3 — status shows a malformed store as a visible marker, never a
# silent 0 that reads as "empty" when the file is actually corrupt.
# Canonical root + real init (no NO_INIT) so the operational files (config, etc.)
# are seeded normally; the pre-written malformed host-allow.json survives (init
# only seeds absent files). This is the production shape for a corrupt store.
n3home="$tmp/n3home"; n3run="$n3home/.config/safe/run"; mkdir -p "$n3run" "$tmp/n3data"
printf 'garbage, not json\n' > "$n3run/host-allow.json"
set +e
n3_out=$(HOME="$n3home" SAFE_RUN_CONFIG_DIR="$n3run" SAFE_RUN_DATA_DIR="$tmp/n3data" \
  "$SAFE_RUN" status </dev/null 2>&1); n3_rc=$?
set -e
[[ "$n3_rc" -eq 0 ]] || fail "status must not abort on a malformed store (rc=$n3_rc): $n3_out"
grep -Eq 'host-allow: +\?\(unreadable/malformed\)' <<<"$n3_out" \
  || fail "status must show a malformed host-allow as a visible marker, not a silent 0 (got: $(grep -i host-allow <<<"$n3_out"))"
pass "status reports a malformed store as a visible marker, not a silent 0 (N3)"

# A parseable but schema-wrong store ({"packages":[]}) is malformed, not empty:
# the readers index .packages by name, so an array is corrupt (round-4 N3
# residual — length alone cannot tell 0-entries from wrong-shape).
printf '{"packages":[]}\n' > "$n3run/host-allow.json"
set +e
n3b_out=$(HOME="$n3home" SAFE_RUN_CONFIG_DIR="$n3run" SAFE_RUN_DATA_DIR="$tmp/n3data" \
  "$SAFE_RUN" status </dev/null 2>&1); n3b_rc=$?
set -e
[[ "$n3b_rc" -eq 0 ]] || fail "status must not abort on a schema-malformed store (rc=$n3b_rc)"
grep -Eq 'host-allow: +\?\(unreadable/malformed\)' <<<"$n3b_out" \
  || fail 'status must mark a schema-wrong {"packages":[]} store, not print 0 (got: '"$(grep -i host-allow <<<"$n3b_out")"')'
pass "status marks a parseable-but-schema-wrong store as malformed (N3 residual)"

# --- Part 13: @scope/* wildcard blocks union too (round-3 flagged this path as
# correct-by-inspection but unpinned).
printf '{"packages":{"@evil/*":{"reason":"scope-bad","added":"2026-08-27"}}}\n' > "$CANON/blocked.json"
printf '{"packages":{}}\n' > "$REDIR/blocked.json"
scope_fixture='
  set -- version
  source "$SAFE_RUN_PATH" >/dev/null
  if in_blocked @evil/somepkg; then echo BLOCKED; else echo CLEAR; fi
'
scope_out=$(HOME="$H" SAFE_RUN_CONFIG_DIR="$REDIR" SAFE_RUN_DATA_DIR="$tmp/data" \
  SAFE_RUN_NO_INIT=1 SAFE_RUN_PATH="$SAFE_RUN" \
  bash -c "$scope_fixture" safe-run 2>/dev/null)
[[ "$scope_out" == "BLOCKED" ]] \
  || fail "a canonical @scope/* wildcard block must union into a redirected root (got $scope_out)"
pass "canonical @scope/* wildcard block is honored through the union (N2 scope pin)"

printf '\nall trust-store redirection guard tests passed\n'
