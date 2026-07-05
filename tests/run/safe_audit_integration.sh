#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SAFE_RUN="$ROOT/bin/safe-run"

pass() { printf 'ok - %s\n' "$*"; }
fail() { printf 'not ok - %s\n' "$*" >&2; exit 1; }

require() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

require bash
require jq

bash -n "$SAFE_RUN"
pass "bash syntax"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

mockbin="$tmp/mockbin"
mkdir -p "$mockbin"

cat > "$mockbin/podman" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$SAFE_AUDIT_CALL_LOG"
case "$1" in
  image) exit 0 ;;
  run) jq -cn --arg verdict "${SAFE_AUDIT_VERDICT:-GO}" '{verdict:$verdict}' ;;
  *) exit 1 ;;
esac
SH
chmod +x "$mockbin/podman"

cat > "$mockbin/npx-real" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$HOST_RUNNER_CALL_LOG"
SH
chmod +x "$mockbin/npx-real"

run_fixture() {
  local verdict="$1" script="$2"
  SAFE_RUN_CONFIG_DIR="$tmp/config-$verdict" \
  SAFE_RUN_DATA_DIR="$tmp/data-$verdict" \
  SAFE_AUDIT_DATA_DIR="$tmp/audit-data-$verdict" \
  SAFE_AUDIT_BIN="safe-audit" \
  SAFE_AUDIT_VERDICT="$verdict" \
  SAFE_AUDIT_CALL_LOG="$tmp/audit-calls-$verdict.log" \
  HOST_RUNNER_CALL_LOG="$tmp/host-runner-$verdict.log" \
  SAFE_RUN_PATH="$SAFE_RUN" \
  PATH="$mockbin:$PATH" \
    bash -c "$script" safe-run
}

run_fixture WARN '
  set -- version
  source "$SAFE_RUN_PATH" >/dev/null
  ensure_dirs
  RUNNER_KIND=npm
  PKG_NAME=warnpkg
  PKG_VERSION=1.0.0
  PKG_VERSION_USER_SPECIFIED=1
  mark_sandbox_known warnpkg 1.0.0
  run_sandbox() { SANDBOX_AUDIT_EXTRA="sbom_vulns=0"; return 0; }
  dispatch_run
'
grep -q 'check warnpkg@1.0.0 --ecosystem npm --json' "$tmp/audit-calls-WARN.log" || fail "safe audit check did not run before sandbox"
grep -q 'SANDBOX.*OK.*sbom_vulns=0' "$tmp/data-WARN/audit.log" || fail "sandbox audit omitted sbom_vulns"
pass "WARN continues to sandbox with sbom audit"

set +e
run_fixture BLOCK '
  set -- version
  source "$SAFE_RUN_PATH" >/dev/null
  ensure_dirs
  RUNNER_KIND=npm
  PKG_NAME=blockpkg
  PKG_VERSION=1.0.0
  PKG_VERSION_USER_SPECIFIED=1
  mark_sandbox_known blockpkg 1.0.0
  run_sandbox() { printf called > "$SAFE_RUN_DATA_DIR/sandbox-called"; return 0; }
  dispatch_run
'
rc=$?
set -e
[[ "$rc" -eq 104 ]] || fail "BLOCK did not exit 104"
[[ ! -e "$tmp/data-BLOCK/sandbox-called" ]] || fail "BLOCK executed sandbox"
grep -q 'SAFE_AUDIT_BLOCK' "$tmp/data-BLOCK/audit.log" || fail "BLOCK audit entry missing"
pass "BLOCK exits before sandbox"

run_fixture GO '
  set -- version
  source "$SAFE_RUN_PATH" >/dev/null
  ensure_dirs
  RUNNER_KIND=npm
  PKG_NAME=hostpkg
  PKG_VERSION=2.0.0
  PKG_VERSION_USER_SPECIFIED=1
  tmpfile=$(mktemp)
  jq --arg p hostpkg --arg v 2.0.0 ".packages[\$p] = {version:\$v, reason:\"fixture\"}" "$HOST_ALLOW_FILE" > "$tmpfile"
  mv "$tmpfile" "$HOST_ALLOW_FILE"
  tmpfile=$(mktemp)
  jq --arg p "'"$mockbin"'/npx-real" ".runners.npx_real = \$p" "$CONFIG_FILE" > "$tmpfile"
  mv "$tmpfile" "$CONFIG_FILE"
  dispatch_run --flag
'
[[ ! -s "$tmp/audit-calls-GO.log" ]] || fail "safe audit ran before host-allow"
jq -e 'select(.package == "hostpkg" and .version == "2.0.0" and .runner == "npx")' "$tmp/audit-data-GO/host-allow-log.jsonl" >/dev/null || fail "host-allow JSONL log missing"
[[ "$(wc -l < "$tmp/audit-data-GO/host-allow-log.jsonl")" -eq 1 ]] || fail "host-allow JSONL contains blank lines"
pass "host-allow JSONL logging"

SAFE_RUN_CONFIG_DIR="$tmp/config-update-latest" \
SAFE_RUN_DATA_DIR="$tmp/data-update-latest" \
SAFE_RUN_PATH="$SAFE_RUN" \
  bash -c '
    set -- version
    source "$SAFE_RUN_PATH" >/dev/null
    ensure_dirs
    tmpfile=$(mktemp)
    jq --arg p hostpkg --arg v 2.0.0 ".packages[\$p] = {version:\$v, reason:\"fixture\", ecosystem:\"npm\"}" "$HOST_ALLOW_FILE" > "$tmpfile"
    mv "$tmpfile" "$HOST_ALLOW_FILE"
    set +e
    require_operator_tty() { :; }
    ( cmd_host_allow_update hostpkg@latest ) >/dev/null 2>&1
    rc=$?
    set -e
    [[ "$rc" -ne 0 ]]
    [[ "$(jq -r ".packages.hostpkg.version" "$HOST_ALLOW_FILE")" == "2.0.0" ]]
  ' safe-run || fail "host-allow update @latest mutated allowlist"
pass "host-allow update rejects latest before mutation"

SAFE_RUN_CONFIG_DIR="$tmp/config-add-go-no-reason" \
SAFE_RUN_DATA_DIR="$tmp/data-add-go-no-reason" \
SAFE_AUDIT_VERDICT=GO \
SAFE_AUDIT_CALL_LOG="$tmp/audit-calls-add-go-no-reason.log" \
SAFE_RUN_PATH="$SAFE_RUN" \
PATH="$mockbin:$PATH" \
  bash -c '
    set -- version
    source "$SAFE_RUN_PATH" >/dev/null
    ensure_dirs
    registry_integrity_npm() { printf "sha512-fixture"; }
    require_operator_tty() { :; }
    cmd_host_allow_add hostpkg@2.0.0 >/dev/null 2>&1
    [[ "$(jq -r ".packages.hostpkg.version" "$HOST_ALLOW_FILE")" == "2.0.0" ]]
    [[ "$(jq -r ".packages.hostpkg.reason" "$HOST_ALLOW_FILE")" == "" ]]
  ' safe-run || fail "host-allow add GO required a reason"
pass "host-allow add accepts safe audit GO without reason"

SAFE_RUN_CONFIG_DIR="$tmp/config-add-reason-equals" \
SAFE_RUN_DATA_DIR="$tmp/data-add-reason-equals" \
SAFE_AUDIT_VERDICT=GO \
SAFE_AUDIT_CALL_LOG="$tmp/audit-calls-add-reason-equals.log" \
SAFE_RUN_PATH="$SAFE_RUN" \
PATH="$mockbin:$PATH" \
  bash -c '
    set -- version
    source "$SAFE_RUN_PATH" >/dev/null
    ensure_dirs
    registry_integrity_npm() { printf "sha512-fixture"; }
    require_operator_tty() { :; }
    cmd_host_allow_add @qwen-code/qwen-code@0.16.2 --reason="misses only Socket that fails" >/dev/null 2>&1
    [[ "$(jq -r ".packages[\"@qwen-code/qwen-code\"].version" "$HOST_ALLOW_FILE")" == "0.16.2" ]]
    [[ "$(jq -r ".packages[\"@qwen-code/qwen-code\"].reason" "$HOST_ALLOW_FILE")" == "misses only Socket that fails" ]]
  ' safe-run || fail "host-allow add rejected --reason=value"
pass "host-allow add accepts --reason=value"

SAFE_RUN_CONFIG_DIR="$tmp/config-add-non-tty" \
SAFE_RUN_DATA_DIR="$tmp/data-add-non-tty" \
SAFE_AUDIT_VERDICT=GO \
SAFE_AUDIT_CALL_LOG="$tmp/audit-calls-add-non-tty.log" \
SAFE_RUN_PATH="$SAFE_RUN" \
ERR_FILE="$tmp/add-non-tty.err" \
PATH="$mockbin:$PATH" \
  bash -c '
    set -- version
    source "$SAFE_RUN_PATH" >/dev/null
    ensure_dirs
    set +e
    ( cmd_host_allow_add hostpkg@2.0.0 ) >/dev/null 2>"$ERR_FILE"
    rc=$?
    set -e
    [[ "$rc" -eq 102 ]]
    grep -q "interactive operator terminal" "$ERR_FILE"
    [[ "$(jq -r ".packages | length" "$HOST_ALLOW_FILE")" == "0" ]]
  ' safe-run || fail "host-allow add non-TTY was not refused with exit 102"
pass "host-allow add refuses non-TTY with legible exit 102"

invalid_name_err="$tmp/invalid-name.err"
set +e
SAFE_RUN_CONFIG_DIR="$tmp/config-invalid-name" SAFE_RUN_DATA_DIR="$tmp/data-invalid-name" \
  "$SAFE_RUN" "../bad" >/dev/null 2>"$invalid_name_err" </dev/null
invalid_name_rc=$?
set -e
[[ "$invalid_name_rc" -eq 103 ]] || fail "invalid package name expected rc=103, got $invalid_name_rc"
grep -q "BLOCKED: invalid package name" "$invalid_name_err" || fail "invalid package name refusal not BLOCKED-formatted"
grep -q "safe explain" "$invalid_name_err" || fail "invalid package name refusal missing safe explain pointer"
pass "invalid package name refuses with BLOCKED contract and exit 103"

SAFE_RUN_CONFIG_DIR="$tmp/config-update-go-no-reason" \
SAFE_RUN_DATA_DIR="$tmp/data-update-go-no-reason" \
SAFE_AUDIT_VERDICT=GO \
SAFE_AUDIT_CALL_LOG="$tmp/audit-calls-update-go-no-reason.log" \
SAFE_RUN_PATH="$SAFE_RUN" \
PATH="$mockbin:$PATH" \
  bash -c '
    set -- version
    source "$SAFE_RUN_PATH" >/dev/null
    ensure_dirs
    registry_integrity_npm() { printf "sha512-fixture"; }
    tmpfile=$(mktemp)
    jq --arg p hostpkg --arg v 2.0.0 ".packages[\$p] = {version:\$v, reason:\"old exception\", ecosystem:\"npm\"}" "$HOST_ALLOW_FILE" > "$tmpfile"
    mv "$tmpfile" "$HOST_ALLOW_FILE"
    require_operator_tty() { :; }
    cmd_host_allow_update hostpkg@2.1.0 >/dev/null 2>&1
    [[ "$(jq -r ".packages.hostpkg.version" "$HOST_ALLOW_FILE")" == "2.1.0" ]]
    [[ "$(jq -r ".packages.hostpkg.reason" "$HOST_ALLOW_FILE")" == "" ]]
  ' safe-run || fail "host-allow update GO required or preserved a reason"
pass "host-allow update accepts safe audit GO without reason"

SAFE_RUN_CONFIG_DIR="$tmp/config-update-block" \
SAFE_RUN_DATA_DIR="$tmp/data-update-block" \
SAFE_AUDIT_VERDICT=BLOCK \
SAFE_AUDIT_CALL_LOG="$tmp/audit-calls-update-block.log" \
SAFE_RUN_PATH="$SAFE_RUN" \
PATH="$mockbin:$PATH" \
  bash -c '
    set -- version
    source "$SAFE_RUN_PATH" >/dev/null
    ensure_dirs
    tmpfile=$(mktemp)
    jq --arg p hostpkg --arg v 2.0.0 ".packages[\$p] = {version:\$v, reason:\"fixture\", ecosystem:\"npm\"}" "$HOST_ALLOW_FILE" > "$tmpfile"
    mv "$tmpfile" "$HOST_ALLOW_FILE"
    set +e
    require_operator_tty() { :; }
    ( cmd_host_allow_update hostpkg@2.1.0 ) >/dev/null 2>&1
    rc=$?
    set -e
    [[ "$rc" -ne 0 ]]
    [[ "$(jq -r ".packages.hostpkg.version" "$HOST_ALLOW_FILE")" == "2.0.0" ]]
  ' safe-run || fail "host-allow update safe audit BLOCK mutated allowlist"
pass "host-allow update audits before mutation"

podman_log="$tmp/podman.log"
cat > "$mockbin/podman" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$PODMAN_CALL_LOG"
case "$1" in
  image) exit 0 ;;
  create) printf 'container1234567890\n' ;;
  start) exit 0 ;;
  rm) exit 0 ;;
esac
SH
chmod +x "$mockbin/podman"

PATH="$mockbin:$PATH" \
SAFE_RUN_CONFIG_DIR="$tmp/config-podman-nontty" \
SAFE_RUN_DATA_DIR="$tmp/data-podman-nontty" \
PODMAN_CALL_LOG="$podman_log" \
SAFE_RUN_PATH="$SAFE_RUN" \
  bash -c '
    set -- version
    source "$SAFE_RUN_PATH" >/dev/null
    ensure_dirs
    RUNNER_KIND=npm
    PKG_NAME=podpkg
    PKG_VERSION=1.0.0
    run_sandbox podpkg 1.0.0
  ' safe-run
grep -q '^start -a container1234567890$' "$podman_log" || fail "non-tty podman start flags changed"
grep -q -- '--network=none' "$podman_log" || fail "default sandbox did not disable network"
grep -q -- '/work:Z,ro' "$podman_log" || fail "default sandbox did not mount project read-only"

rm -f "$podman_log"
PATH="$mockbin:$PATH" \
SAFE_RUN_CONFIG_DIR="$tmp/config-podman-relaxed" \
SAFE_RUN_DATA_DIR="$tmp/data-podman-relaxed" \
PODMAN_CALL_LOG="$podman_log" \
SAFE_RUN_PATH="$SAFE_RUN" \
  bash -c '
    set -- version
    source "$SAFE_RUN_PATH" >/dev/null
    ensure_dirs
    RUNNER_KIND=npm
    ALLOW_WRITE=1
    ALLOW_NETWORK=1
    run_sandbox podpkg 1.0.0
  ' safe-run
! grep -q -- '--network=none' "$podman_log" || fail "network opt-in still disabled network"
grep -q -- '/work:Z,rw' "$podman_log" || fail "write opt-in did not mount project read-write"
pass "write and network opt-ins relax package sandbox"

rm -f "$podman_log"
PATH="$mockbin:$PATH" \
SAFE_RUN_CONFIG_DIR="$tmp/config-podman-tty" \
SAFE_RUN_DATA_DIR="$tmp/data-podman-tty" \
PODMAN_CALL_LOG="$podman_log" \
SAFE_RUN_PATH="$SAFE_RUN" \
  bash -c '
    set -- version
    source "$SAFE_RUN_PATH" >/dev/null
    is_tty() { return 0; }
    ensure_dirs
    RUNNER_KIND=npm
    PKG_NAME=podpkg
    PKG_VERSION=1.0.0
    run_sandbox podpkg 1.0.0
  ' safe-run
grep -q '^start -ai container1234567890$' "$podman_log" || fail "tty podman start did not attach stdin"
pass "podman start preserves interactive stdin"

rm -f "$podman_log"
secret_dir="$tmp/secret-project"
mkdir -p "$secret_dir"
: > "$secret_dir/.env"
set +e
PATH="$mockbin:$PATH" \
SAFE_RUN_CONFIG_DIR="$tmp/config-secret-nontty" \
SAFE_RUN_DATA_DIR="$tmp/data-secret-nontty" \
PODMAN_CALL_LOG="$podman_log" \
SAFE_RUN_PATH="$SAFE_RUN" \
  bash -c '
    cd "'"$secret_dir"'"
    set -- version
    source "$SAFE_RUN_PATH" >/dev/null
    ensure_dirs
    RUNNER_KIND=npm
    run_sandbox secretpkg 1.0.0
  ' safe-run
rc=$?
set -e
[[ "$rc" -ne 0 ]] || fail "secret-like files did not block non-tty sandbox"
[[ ! -s "$podman_log" ]] || fail "secret-like files blocked after podman execution started"
pass "secret-like files block non-tty sandbox unless allowed"

help_output="$("$SAFE_RUN" --help)"
grep -q 'safe audit' <<<"$help_output" || fail "help omits safe audit integration"
pass "help documents safe audit integration"
