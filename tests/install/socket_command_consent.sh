#!/usr/bin/env bash
# Command-local rate-limit consent, without weakening other verdicts.
set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail() { printf 'not ok - %s\n' "$*" >&2; exit 1; }
pass() { printf 'ok - %s\n' "$*"; }
source "$ROOT/lib/gate-lib.sh"
safe_gate_audit_available() { return 0; }
safe_gate_audit_op() { printf install; }
safe_gate_host_allow_matches() { return 1; }
safe_gate_audit_log() { :; }
safe_gate_run_audit() { calls=$((calls+1)); return "$audit_rc"; }
safe_gate_operator_terminal() { return "$terminal_rc"; }
safe_gate_confirm_socket_command() { prompts=$((prompts+1)); return "$confirm_rc"; }
run_check() { actual=0; safe_gate_check "$1" npm >"$tmp/out" 2>"$tmp/err" || actual=$?; }
calls=0; prompts=0; audit_rc=12; terminal_rc=0; confirm_rc=0
SAFE_GATE_SOCKET_COMMAND_CONSENT=0
run_check a@1.0.0; [[ $actual == 0 ]] || fail 'initial acceptance'
run_check b@1.0.0; [[ $actual == 0 && $calls == 2 && $prompts == 1 ]] || fail 'one prompt, both audits run'
pass 'one consent covers subsequent pure rate limits while all audits run'
audit_rc=20; run_check bad@1.0.0
[[ $actual == 104 ]] || fail 'BLOCK survives consent'
audit_rc=10; safe_gate_install_is_interactive() { return 1; }; run_check warn@1.0.0
[[ $actual == 100 ]] || fail 'adverse WARN survives consent'
audit_rc=11; run_check outage@1.0.0
[[ $actual == 102 ]] || fail 'other infrastructure still needs independent consent'
pass 'consent does not cover BLOCK, adverse WARN or another outage'
audit_rc=12; terminal_rc=1; run_check a@1.0.0
[[ $actual == 102 && $prompts == 1 ]] || fail 'nonterminal cannot reuse consent'
terminal_rc=0; confirm_rc=1; SAFE_GATE_SOCKET_COMMAND_CONSENT=0; run_check a@1.0.0
[[ $actual == 100 && $SAFE_GATE_SOCKET_COMMAND_CONSENT == 0 ]] || fail 'decline preserves refusal'
pass 'nonterminal and declined consent refuse'
terminal_rc=1; confirm_rc=0; audit_rc=12
safe_gate_host_allow_matches() { return 0; }
run_check allowed@1.0.0
[[ $actual == 0 ]] || fail 'existing grant must remain effective on rate-only WARN'
safe_gate_host_allow_matches() { return 1; }
pass 'pre-existing exact grant remains effective without new consent'

# Exercise the real entrypoint reset, including forged inherited consent.
safe_gate_npm_like() { [[ $SAFE_GATE_SOCKET_COMMAND_CONSENT == 0 ]] || return 99; }
export SAFE_GATE_SOCKET_COMMAND_CONSENT=1
safe_gate_main npm install a@1.0.0 || fail 'entrypoint reset'
pass 'new wrapper command resets inherited consent'
terminal_rc=1; calls=0; actual=0
safe_gate_check_many npm a@1 b@1 c@1 d@1 >"$tmp/out" 2>"$tmp/err" || actual=$?
[[ $actual == 102 && $calls == 0 ]] || fail 'batch refusal must precede audits'
audit_rc=0
safe_gate_check_many npm a@1 b@1 c@1 || fail 'three should fit'
[[ $calls == 3 ]] || fail 'three audits required'
pass 'four refuses before audit, three audits normally'
# bin/safe sibling path: function definitions only, with isolated shell options.
export ROOT tmp
bash <<'INNER' || exit 1
source <(sed '/^argv0=/,$d' "$ROOT/bin/safe")
source "$ROOT/lib/gate-lib.sh"
set +e
SAFE_AUDIT_PATH="$tmp/audit"
printf '#!/bin/sh\nexit 12\n' >"$SAFE_AUDIT_PATH"; chmod +x "$SAFE_AUDIT_PATH"
safe_gate_operator_terminal() { return 0; }
safe_gate_confirm_socket_command() { printf 'prompt\n' >>"$tmp/prompts"; }
safe_install_gate_log() { :; }
SAFE_GATE_SOCKET_COMMAND_CONSENT=0
safe_install_audit_package a@1 npm || exit 1
safe_install_audit_package b@1 npm || exit 1
[[ $(wc -l <"$tmp/prompts") == 1 ]] || exit 1
safe_gate_operator_terminal() { return 1; }
safe_install_host_allow_matches() { return 0; }
safe_install_audit_package allowed@1 npm || exit 1
safe_install_host_allow_matches() { return 1; }
# cmd_install owns reset; stub only downstream boundaries, no network/delegate.
gate_lib_path() { printf '%s' "$tmp/empty-lib"; }
: >"$tmp/empty-lib"
safe_install_audit_specs() { printf 'a@1\n'; }
safe_install_audit_package() { [[ $SAFE_GATE_SOCKET_COMMAND_CONSENT == 0 ]]; }
safe_install_build_command() { install_cmd=(npm install a@1); }
safe_gate_dispatch() { [[ $SAFE_GATE_SOCKET_COMMAND_CONSENT == 0 ]]; }
cmd_install --host --yes a@1 || exit 1
INNER
pass 'safe install sibling prompts once and resets each invocation'
# Real terminal eligibility must reject explicit agent markers even in a PTY.
# This is a fixture shell with no installs or prompts, not a live override.
export ROOT
python3 <<'PY' || exit 1
import os, pty, subprocess
root=os.environ['ROOT']
for marker in ('CODEX_THREAD_ID','CODEX_CI','CLAUDECODE','OPENCODE'):
 m,s=pty.openpty()
 env=os.environ.copy(); env[marker]='fixture-agent'
 p=subprocess.run(['bash','-c','source "$ROOT/lib/gate-lib.sh"; safe_gate_operator_terminal'],stdin=s,stdout=s,stderr=s,env=env)
 os.close(s); os.close(m)
 assert p.returncode != 0, marker
PY
pass 'real terminal predicate rejects recognized agent sessions with PTYs'
# Real /dev/tty prompt in an isolated fixture, with synthetic environment.
cat >"$tmp/terminal-fixture" <<'FIXTURE'
source "$ROOT/lib/gate-lib.sh"
safe_gate_audit_available() { return 0; }
safe_gate_audit_op() { printf install; }
safe_gate_run_audit() { return 12; }
safe_gate_audit_log() { :; }
safe_gate_npm_like() { safe_gate_check_many npm a@1.0.0 b@1.0.0 c@1.0.0; }
safe_gate_main npm install || exit $?
safe_gate_main npm install || exit $?
FIXTURE
export fixture_path="$tmp/terminal-fixture"
python3 <<'PY' || exit 1
import os, pty, select, time, signal
pid,fd=pty.fork()
if pid==0:
 os.execve('/bin/bash',['bash',os.environ['fixture_path']],{'PATH':'/usr/bin:/bin','ROOT':os.environ['ROOT']})
buf=b''; count=0; deadline=time.monotonic()+10
try:
 while time.monotonic()<deadline:
  if not select.select([fd],[],[],0.1)[0]: continue
  try: chunk=os.read(fd,65536)
  except OSError: break
  if not chunk: break
  buf+=chunk
  prompts=buf.count(b'continue this install without Socket scores? [y/N]')
  if prompts>count:
   os.write(fd,b'y\n'); count=prompts
 else:
  os.kill(pid,signal.SIGKILL); raise AssertionError('fixture timed out: '+repr(buf))
 _,rc=os.waitpid(pid,0)
 assert os.waitstatus_to_exitcode(rc)==0,repr(buf)
 assert count==2,repr(buf)
 assert buf.count(b'missing Socket score accepted for this command')==6,repr(buf)
finally: os.close(fd)
PY
pass 'real terminal prompts once per command and asks again for the next command'
# Mise retains isolated env/cwd audits but consent belongs to the command parent.
source "$ROOT/lib/gate-lib.sh"
safe_gate_audit_available() { return 0; }
safe_gate_run_audit() { return 12; }
safe_gate_audit_op() { printf install; }
safe_gate_operator_terminal() { return 0; }
safe_gate_audit_log() { :; }
safe_gate_mise_apply_overlay() { :; }
safe_gate_confirm_socket_command() { printf 'prompt\n' >>"$tmp/mise-prompts"; }
SAFE_GATE_SOCKET_COMMAND_CONSENT=0
safe_gate_mise_check_with_env '' a@1.0.0 npm || fail 'mise first package'
safe_gate_mise_check_with_env '' b@1.0.0 npm || fail 'mise second package'
[[ $(wc -l <"$tmp/mise-prompts") == 1 ]] || fail 'mise consent lost between isolated audits'
pass 'mise asks once across isolated package audits'
# Explicit targets count; configuration expansion is not an argv batch.
safe_gate_operator_terminal() { return 1; }
safe_gate_mise_parse_sub() { SAFE_GATE_MISE_SPECS=(); SAFE_GATE_MISE_MODE=0; }
safe_gate_mise_collect_entries() { local -n dest="$3"; dest=(a@1 b@1 c@1 d@1); }
safe_gate_mise_filter_excluded() { :; }
safe_gate_mise_min_age_guard() { :; }
safe_gate_mise_overlay_or_refuse() { SAFE_GATE_MISE_OVERLAY=''; }
safe_gate_mise_check_spec() { checks=$((checks+1)); }
checks=0
safe_gate_mise_gate_install install || fail 'configuration set must not count as explicit batch'
[[ $checks == 4 ]] || fail 'configuration audits must remain complete'
safe_gate_mise_parse_sub() { SAFE_GATE_MISE_SPECS=(a@1 b@1 c@1 d@1); SAFE_GATE_MISE_MODE=0; }
for sub in install exec; do
 checks=0; actual=0
 "safe_gate_mise_gate_$sub" "$sub" >"$tmp/out" 2>"$tmp/err" || actual=$?
 [[ $actual == 102 && $checks == 0 ]] || fail "mise $sub explicit batch must refuse before audits"
done
pass 'mise explicit install/exec batch refuses before audits, configured set stays audited'
# Inner preflight cannot import consent from mise's arbitrary environment overlay.
safe_gate_mise_parse_sub() { SAFE_GATE_MISE_SPECS=(); SAFE_GATE_MISE_CMD=(npm install a@1.0.0); SAFE_GATE_MISE_CTX=(); }
safe_gate_mise_exec_auto_install_enabled() { return 1; }
safe_gate_mise_unmodeled_source() { return 1; }
safe_gate_mise_overlay_scripts_policy() { return 1; }
safe_gate_mise_apply_overlay() { SAFE_GATE_SOCKET_COMMAND_CONSENT="$injected"; export SAFE_GATE_SOCKET_COMMAND_CONSENT; }
safe_gate_dispatch() { [[ "$SAFE_GATE_SOCKET_COMMAND_CONSENT" == "$expected" ]] && ! export -p | grep -q 'declare -x SAFE_GATE_SOCKET_COMMAND_CONSENT='; }
for expected in 0 1; do
 SAFE_GATE_SOCKET_COMMAND_CONSENT="$expected"; injected=$((1-expected))
 safe_gate_mise_gate_exec exec || fail 'inner preflight must preserve original, nonexported consent'
done
pass 'mise inner preflight preserves consent without trusting overlay variables'

# A parent-context grant must never be applied to a different mise audit source.
source "$ROOT/lib/gate-lib.sh"
safe_gate_audit_available() { return 0; }
safe_gate_run_audit() { return 12; }
safe_gate_audit_op() { printf install; }
safe_gate_audit_log() { :; }
safe_gate_mise_apply_overlay() { source_context=overlay; }
safe_gate_host_allow_matches() { [[ "${source_context:-parent}" == parent ]]; }
safe_gate_operator_terminal() { return 1; }
SAFE_GATE_SOCKET_COMMAND_CONSENT=0; actual=0
safe_gate_mise_check_with_env '' a@1.0.0 npm >"$tmp/out" 2>"$tmp/err" || actual=$?
[[ $actual == 102 ]] || fail 'parent grant must not clear different audit source'
pass 'mise grant matching stays in audit source context before consent deferral'
