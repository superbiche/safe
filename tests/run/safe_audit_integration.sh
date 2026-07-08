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

# ---------------------------------------------------------------------------
# npx-native flag handling and local-bin passthrough (hermes false positive)
# ---------------------------------------------------------------------------

localbin_proj="$tmp/proj-local-bin"
mkdir -p "$localbin_proj/node_modules/.bin"
cat > "$localbin_proj/node_modules/.bin/lint-staged" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" > "$LOCAL_BIN_CALL_LOG"
exit 0
SH
chmod +x "$localbin_proj/node_modules/.bin/lint-staged"

# Verbatim hermes/api husky invocation: local bin runs, args forwarded, exit 0.
set +e
(
  cd "$localbin_proj"
  SAFE_RUN_CONFIG_DIR="$tmp/config-localbin" \
  SAFE_RUN_DATA_DIR="$tmp/data-localbin" \
  LOCAL_BIN_CALL_LOG="$tmp/local-bin-call.log" \
    "$SAFE_RUN" --no-install lint-staged --config .tooling/lint-staged.config.cjs
) </dev/null >/dev/null 2>"$tmp/localbin.err"
rc=$?
set -e
[[ "$rc" -eq 0 ]] || fail "hermes husky invocation failed rc=$rc: $(cat "$tmp/localbin.err")"
grep -q -- '--config .tooling/lint-staged.config.cjs' "$tmp/local-bin-call.log" || fail "local bin did not receive its args"
grep -q 'LOCAL_BIN' "$tmp/data-localbin/audit.log" || fail "local-bin audit entry missing"
pass "npx --no-install <local pkg> runs local bin (hermes regression)"

# Cosmetic flags are dropped; local bin still runs.
set +e
(
  cd "$localbin_proj"
  SAFE_RUN_CONFIG_DIR="$tmp/config-localbin-quiet" \
  SAFE_RUN_DATA_DIR="$tmp/data-localbin-quiet" \
  LOCAL_BIN_CALL_LOG="$tmp/local-bin-quiet-call.log" \
    "$SAFE_RUN" -q --silent lint-staged
) </dev/null >/dev/null 2>&1
rc=$?
set -e
[[ "$rc" -eq 0 ]] || fail "-q/--silent were not dropped (rc=$rc)"
[[ -s "$tmp/local-bin-quiet-call.log" ]] || fail "local bin not called after cosmetic flags"
pass "cosmetic npx flags (-q/--silent) are dropped"

# --no-install without a local bin refuses legibly with exit 100 (never fetches).
set +e
SAFE_RUN_CONFIG_DIR="$tmp/config-noinstall-miss" \
SAFE_RUN_DATA_DIR="$tmp/data-noinstall-miss" \
  "$SAFE_RUN" --no-install definitely-not-installed-xyz </dev/null >/dev/null 2>"$tmp/noinstall-miss.err"
rc=$?
set -e
[[ "$rc" -eq 100 ]] || fail "--no-install without local bin expected rc=100, got $rc"
grep -q 'BLOCKED' "$tmp/noinstall-miss.err" || fail "--no-install refusal not BLOCKED-formatted"
grep -q 'node_modules/.bin' "$tmp/noinstall-miss.err" || fail "--no-install refusal not actionable"
pass "--no-install without local bin refuses with exit 100"

# Unknown runner-native flag fails closed with exit 100, not bogus 103.
set +e
SAFE_RUN_CONFIG_DIR="$tmp/config-unknown-flag" \
SAFE_RUN_DATA_DIR="$tmp/data-unknown-flag" \
  "$SAFE_RUN" --loglevel=error lint-staged </dev/null >/dev/null 2>"$tmp/unknown-flag.err"
rc=$?
set -e
[[ "$rc" -eq 100 ]] || fail "unknown flag expected rc=100, got $rc"
grep -q "unrecognized flag '--loglevel=error'" "$tmp/unknown-flag.err" || fail "unknown-flag refusal not legible"
grep -q 'safe explain' "$tmp/unknown-flag.err" || fail "unknown-flag refusal missing safe explain pointer"
pass "unknown runner flag fails closed with exit 100 (not 103)"

# npm-exec selector/context flags are refused explicitly.
set +e
SAFE_RUN_CONFIG_DIR="$tmp/config-package-flag" \
SAFE_RUN_DATA_DIR="$tmp/data-package-flag" \
  "$SAFE_RUN" --package=cowsay moo </dev/null >/dev/null 2>"$tmp/package-flag.err"
rc=$?
set -e
[[ "$rc" -eq 100 ]] || fail "--package= expected rc=100, got $rc"
grep -q 'not supported through safe run' "$tmp/package-flag.err" || fail "--package refusal not legible"
pass "npm exec selector flags (--package) refuse with exit 100"

# A versioned spec never uses the local bin: it stays in the audit pipeline
# (here: unknown + non-TTY => exit 102) and the local stub must not run.
set +e
(
  cd "$localbin_proj"
  SAFE_RUN_CONFIG_DIR="$tmp/config-versioned" \
  SAFE_RUN_DATA_DIR="$tmp/data-versioned" \
  LOCAL_BIN_CALL_LOG="$tmp/local-bin-versioned-call.log" \
    "$SAFE_RUN" lint-staged@1.0.0
) </dev/null >/dev/null 2>&1
rc=$?
set -e
[[ "$rc" -eq 102 ]] || fail "versioned spec with local bin expected rc=102, got $rc"
[[ ! -e "$tmp/local-bin-versioned-call.log" ]] || fail "versioned spec executed the local bin"
pass "versioned spec bypasses local bin and stays in the audit pipeline"

# Blocklist beats the local bin.
mkdir -p "$tmp/config-blocked-local"
printf '{"packages":{"lint-staged":{"reason":"fixture block"}}}' > "$tmp/config-blocked-local/blocked.json"
set +e
(
  cd "$localbin_proj"
  SAFE_RUN_CONFIG_DIR="$tmp/config-blocked-local" \
  SAFE_RUN_DATA_DIR="$tmp/data-blocked-local" \
  LOCAL_BIN_CALL_LOG="$tmp/local-bin-blocked-call.log" \
    "$SAFE_RUN" lint-staged
) </dev/null >/dev/null 2>"$tmp/blocked-local.err"
rc=$?
set -e
[[ "$rc" -eq 100 ]] || fail "blocked package with local bin expected rc=100, got $rc"
[[ ! -e "$tmp/local-bin-blocked-call.log" ]] || fail "blocked package executed the local bin"
grep -q 'fixture block' "$tmp/blocked-local.err" || fail "blocklist reason missing from refusal"
pass "blocklist wins over local-bin passthrough"

# --no-install is npm/bun-only: via a uvx-shaped invocation it is refused as
# an unrecognized flag (generic message), not the npm-specific refusal.
ln -sf "$SAFE_RUN" "$tmp/uvx"
set +e
SAFE_RUN_CONFIG_DIR="$tmp/config-uvx-noinstall" \
SAFE_RUN_DATA_DIR="$tmp/data-uvx-noinstall" \
  "$tmp/uvx" --no-install ruff </dev/null >/dev/null 2>"$tmp/uvx-noinstall.err"
rc=$?
set -e
[[ "$rc" -eq 100 ]] || fail "uvx --no-install expected rc=100, got $rc"
grep -q "unrecognized flag '--no-install'" "$tmp/uvx-noinstall.err" || fail "uvx --no-install not refused as unrecognized"
grep -q 'node_modules' "$tmp/uvx-noinstall.err" && fail "uvx --no-install took the npm-specific refusal path"
pass "uvx --no-install refuses as unrecognized flag (npm-specific path not taken)"
