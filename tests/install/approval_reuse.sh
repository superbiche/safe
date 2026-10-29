#!/usr/bin/env bash
set -euo pipefail
# SAFE_TEST_ISOLATION_MARKER: every suite owns a scratch HOME and safe state.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/test-isolation.sh"
safe_test_setup_isolation
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp=$(mktemp -d)
safe_test_compose_exit_trap 'rm -rf "$tmp"'
source "$ROOT/lib/gate-lib.sh"
safe_gate_audit_available() { return 0; }
safe_gate_audit_op() { printf install; }
safe_gate_run_audit() { return 22; }
safe_gate_audit_log() { :; }
safe_gate_operator_terminal() { return 1; }
safe_gate_mise_apply_overlay() { :; }
for eco in npm python cargo go composer; do
  safe_gate_check accepted@1.2.3 "$eco" || exit 1
  safe_gate_mise_check_with_env '' accepted@1.2.3 "$eco" || exit 1
done
printf 'ok - wrappers and isolated mise audits consume local approval without a terminal\n'
export ROOT tmp
bash <<'INNER'
source <(sed '/^argv0=/,$d' "$ROOT/bin/safe")
source "$ROOT/lib/gate-lib.sh"
SAFE_AUDIT_PATH="$tmp/audit"
printf '#!/bin/sh\nexit 22\n' > "$SAFE_AUDIT_PATH"
chmod +x "$SAFE_AUDIT_PATH"
safe_install_gate_log() { :; }
safe_gate_operator_terminal() { return 1; }
for eco in npm python cargo go composer; do
  SAFE_INSTALL_LOCAL_APPROVAL=0
  safe_install_audit_package accepted@1.2.3 "$eco" || exit 1
  [[ "$SAFE_INSTALL_LOCAL_APPROVAL" == 1 ]]
done
INNER
printf 'ok - CLI consumes local approval as authorized non-green evidence\n'
# Exercise durable receipt plumbing with the actual auditor (no network).
mkdir -p "$tmp/run"
for decision in '11 INFRA_TTY_OVERRIDE' '12 SOCKET_RATE_LIMIT_COMMAND_OVERRIDE' '13 GO_SOCKET_CONFIRMED' '14 GO_PENDING_CONFIRMED' '15 TOLERATED_WARN_TTY_OVERRIDE' '17 RECORDED_BLOCK_OVERRIDE_TTY'; do
  read -r code token <<<"$decision"
  printf '{"gate_exit":%s,"ecosystem":"python","package":"accepted","resolved_versions":["1.2.3"],"warn_causes":[]}\n' "$code" > "$tmp/result.json"
  SAFE_RUN_TRUST_OVERRIDE=1 SAFE_RUN_CONFIG_DIR="$tmp/run" safe_test_operator_receipt_fixture "$ROOT/bin/safe-audit" record-installed \
    --result "$tmp/result.json" --verdict "$token" --source-id explicit:https://fixture.example >/dev/null
  jq -e '.approvals["python:accepted"] | length == 1 and .[0].source == "explicit:https://fixture.example"' "$tmp/run/install-known.json" >/dev/null
done
printf 'ok - confirmed infrastructure and pending decisions retain only exact source-bound consent\n'
rm "$tmp/run/install-known.json"
rc=0
SAFE_RUN_TRUST_OVERRIDE=1 SAFE_RUN_CONFIG_DIR="$tmp/run" "$ROOT/bin/safe-audit" record-installed \
  --result "$tmp/result.json" --verdict RECORDED_BLOCK_OVERRIDE_TTY --source-id implicit-default >/dev/null 2>&1 || rc=$?
[[ "$rc" == 102 && ! -e "$tmp/run/install-known.json" ]]
rc=0
SAFE_TEST_OPERATOR_AGENT_MARKER=1 SAFE_RUN_TRUST_OVERRIDE=1 SAFE_RUN_CONFIG_DIR="$tmp/run" \
  safe_test_operator_receipt_fixture "$ROOT/bin/safe-audit" record-installed \
  --result "$tmp/result.json" --verdict RECORDED_BLOCK_OVERRIDE_TTY --source-id implicit-default >/dev/null || rc=$?
[[ "$rc" == 102 && ! -e "$tmp/run/install-known.json" ]]
printf 'ok - headless and agent-marked terminal callers cannot mint approval from forged documents\n'
# A successful Y recheck must preserve consent even after its cache expires;
# a failed recheck must never turn acceptance of a scan into install authority.
printf '{"gate_exit":13,"ecosystem":"python","package":"accepted","source_identity":"explicit:https://fixture.example","resolved_versions":["1.2.3"]}\n' > "$tmp/recheck.json"
safe_gate_mark_installed() {
  [[ "$4" == GO_SOCKET_CONFIRMED ]]
  jq -e '.gate_exit == 13 and .source_identity == "explicit:https://fixture.example"' "$3" >/dev/null
  printf 'marked\n' >> "$tmp/recheck-mark"
}
recheck() { rm -f "$tmp/recheck.json"; return "${recheck_status:-0}"; }
safe_gate_socket_recheck accepted@1.2.3 python "$tmp/recheck.json" recheck
[[ $(wc -l < "$tmp/recheck-mark") == 1 ]]
printf '{"gate_exit":13}\n' > "$tmp/recheck.json"
recheck_status=104
rc=0
safe_gate_socket_recheck accepted@1.2.3 python "$tmp/recheck.json" recheck || rc=$?
[[ "$rc" == 104 && $(wc -l < "$tmp/recheck-mark") == 1 ]]
printf 'ok - successful Socket Y recheck retains consent; failed recheck cannot mint it\n'
