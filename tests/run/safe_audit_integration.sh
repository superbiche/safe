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

# Regression: the sandboxed audit preflight fetched an unpinned npm package
# named `safe-audit` (npx --yes) that this repo never published — a latent
# typosquat vector. It was removed; guard against its return.
! grep -qE 'npx .*package-audit' "$SAFE_RUN" || fail "container npx safe-audit fetch reintroduced"
! grep -q 'safe_audit_check_spec\|safe_audit_check_unknown' "$SAFE_RUN" || fail "container audit preflight function reintroduced"
pass "no unpinned npx safe-audit preflight in bin/safe-run"

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

# Stub safe-audit for the host-side preflight (Fibery #86). Logs each
# package-audit invocation (so a case can assert zero invocations) and emits a
# verdict JSON + exit code from env; defaults to a clean GO so the
# host-allow/scripts-allow success-path cases proceed unchanged. Exported onto
# PATH below so it shadows any real safe-audit and the suite stays hermetic.
cat > "$mockbin/safe-audit" <<'SH'
#!/usr/bin/env bash
if [[ "${1:-}" == "package-audit" ]]; then
  printf 'package-audit %s\n' "$*" >> "${SAFE_AUDIT_PROBE_LOG:-/dev/null}"
  json="${SAFE_AUDIT_PROBE_JSON:-}"
  [[ -n "$json" ]] || json='{"verdict":"GO","warn_causes":[]}'
  printf '%s' "$json"
  exit "${SAFE_AUDIT_PROBE_RC:-0}"
fi
exit 0
SH
chmod +x "$mockbin/safe-audit"
# Shadow any real safe-audit on PATH for every fixture in this file, including
# the bare `bash -c` cases that do not set PATH themselves.
export PATH="$mockbin:$PATH"

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

# A sandbox-known package runs straight in the sandbox. The host-side unknown
# preflight (Fibery #86) fires ONLY on the unknown path, after the
# sandbox-known early-return, so a sandbox-known package is never re-audited.
# The sandbox's own sbom audit still lands.
SAFE_AUDIT_PROBE_LOG="$tmp/probe-SANDBOXKNOWN.log" \
run_fixture SANDBOXKNOWN '
  set -- version
  source "$SAFE_RUN_PATH" >/dev/null
  ensure_dirs
  RUNNER_KIND=npm
  PKG_NAME=knownpkg
  PKG_VERSION=1.0.0
  PKG_VERSION_USER_SPECIFIED=1
  mark_sandbox_known knownpkg 1.0.0
  run_sandbox() { SANDBOX_AUDIT_EXTRA="sbom_vulns=0"; return 0; }
  dispatch_run
'
[[ ! -s "$tmp/audit-calls-SANDBOXKNOWN.log" ]] || fail "a preflight invoked podman before the sandbox"
[[ ! -s "$tmp/probe-SANDBOXKNOWN.log" ]] || fail "sandbox-known package was re-audited by the host-side preflight"
grep -q 'SANDBOX.*OK.*sbom_vulns=0' "$tmp/data-SANDBOXKNOWN/audit.log" || fail "sandbox audit omitted sbom_vulns"
pass "sandbox-known package runs in sandbox with sbom audit, no preflight"

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

SAFE_RUN_CONFIG_DIR="$tmp/config-add-no-reason" \
SAFE_RUN_DATA_DIR="$tmp/data-add-no-reason" \
SAFE_RUN_PATH="$SAFE_RUN" \
ERR_FILE="$tmp/add-no-reason.err" \
  bash -c '
    set -- version
    source "$SAFE_RUN_PATH" >/dev/null
    ensure_dirs
    registry_integrity_npm() { printf "sha512-fixture"; }
    require_operator_tty() { :; }
    set +e
    ( cmd_host_allow_add hostpkg@2.0.0 ) >/dev/null 2>"$ERR_FILE"
    rc=$?
    set -e
    [[ "$rc" -ne 0 ]]
    grep -q "reason is required" "$ERR_FILE"
    [[ "$(jq -r ".packages | length" "$HOST_ALLOW_FILE")" == "0" ]]
  ' safe-run || fail "host-allow add without --reason was not refused"
pass "host-allow add requires --reason (audit-gated skip removed)"

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

command_path_err="$tmp/command-path.err"
set +e
SAFE_RUN_CONFIG_DIR="$tmp/config-command-path" SAFE_RUN_DATA_DIR="$tmp/data-command-path" \
  "$SAFE_RUN" "../bad" >/dev/null 2>"$command_path_err" </dev/null
command_path_rc=$?
set -e
[[ "$command_path_rc" -eq 100 ]] || fail "command path expected rc=100, got $command_path_rc"
grep -q "BLOCKED: command paths are unsupported" "$command_path_err" || fail "command path refusal not the command-path contract"
pass "leading command path refuses as command path with exit 100 (not invalid-package 103)"

invalid_name_err="$tmp/invalid-name.err"
set +e
SAFE_RUN_CONFIG_DIR="$tmp/config-invalid-name" SAFE_RUN_DATA_DIR="$tmp/data-invalid-name" \
  "$SAFE_RUN" "bad%name" >/dev/null 2>"$invalid_name_err" </dev/null
invalid_name_rc=$?
set -e
[[ "$invalid_name_rc" -eq 103 ]] || fail "invalid package name expected rc=103, got $invalid_name_rc"
grep -q "BLOCKED: invalid package name" "$invalid_name_err" || fail "invalid package name refusal not BLOCKED-formatted"
grep -q "safe explain" "$invalid_name_err" || fail "invalid package name refusal missing safe explain pointer"
pass "invalid package name refuses with BLOCKED contract and exit 103"

SAFE_RUN_CONFIG_DIR="$tmp/config-update-no-reason" \
SAFE_RUN_DATA_DIR="$tmp/data-update-no-reason" \
SAFE_RUN_PATH="$SAFE_RUN" \
  bash -c '
    set -- version
    source "$SAFE_RUN_PATH" >/dev/null
    ensure_dirs
    registry_integrity_npm() { printf "sha512-fixture"; }
    tmpfile=$(mktemp)
    jq --arg p hostpkg --arg v 2.0.0 ".packages[\$p] = {version:\$v, reason:\"old exception\", ecosystem:\"npm\"}" "$HOST_ALLOW_FILE" > "$tmpfile"
    mv "$tmpfile" "$HOST_ALLOW_FILE"
    require_operator_tty() { :; }
    set +e
    ( cmd_host_allow_update hostpkg@2.1.0 ) >/dev/null 2>&1
    rc=$?
    set -e
    [[ "$rc" -ne 0 ]]
    [[ "$(jq -r ".packages.hostpkg.version" "$HOST_ALLOW_FILE")" == "2.0.0" ]]
  ' safe-run || fail "host-allow update without --reason was not refused"
pass "host-allow update requires --reason (audit-gated skip removed)"

SAFE_RUN_CONFIG_DIR="$tmp/config-update-reason" \
SAFE_RUN_DATA_DIR="$tmp/data-update-reason" \
SAFE_RUN_PATH="$SAFE_RUN" \
  bash -c '
    set -- version
    source "$SAFE_RUN_PATH" >/dev/null
    ensure_dirs
    registry_integrity_npm() { printf "sha512-fixture"; }
    tmpfile=$(mktemp)
    jq --arg p hostpkg --arg v 2.0.0 ".packages[\$p] = {version:\$v, reason:\"old\", ecosystem:\"npm\"}" "$HOST_ALLOW_FILE" > "$tmpfile"
    mv "$tmpfile" "$HOST_ALLOW_FILE"
    require_operator_tty() { :; }
    cmd_host_allow_update hostpkg@2.1.0 --reason "bump for fix" >/dev/null 2>&1
    [[ "$(jq -r ".packages.hostpkg.version" "$HOST_ALLOW_FILE")" == "2.1.0" ]]
    [[ "$(jq -r ".packages.hostpkg.reason" "$HOST_ALLOW_FILE")" == "bump for fix" ]]
  ' safe-run || fail "host-allow update with --reason failed"
pass "host-allow update with --reason bumps version"

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
grep -q 'sandbox-known' <<<"$help_output" || fail "help omits the sandbox decision tiers"
pass "help documents the decision tiers"

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

# A versioned spec never uses the local bin: it takes the package-policy path
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
pass "versioned spec bypasses local bin and takes the package-policy path"

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

# Hoisted monorepo: the bin lives in a parent directory's node_modules/.bin
# (npm's own upward resolution). Regression for the agentrh envsub case.
mono="$tmp/mono"
mkdir -p "$mono/node_modules/.bin" "$mono/apps/web"
cat > "$mono/node_modules/.bin/envsub" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" > "$LOCAL_BIN_CALL_LOG"
exit 0
SH
chmod +x "$mono/node_modules/.bin/envsub"
set +e
(
  cd "$mono/apps/web"
  SAFE_RUN_CONFIG_DIR="$tmp/config-mono" \
  SAFE_RUN_DATA_DIR="$tmp/data-mono" \
  LOCAL_BIN_CALL_LOG="$tmp/mono-call.log" \
    "$SAFE_RUN" envsub in.json out.json
) </dev/null >/dev/null 2>"$tmp/mono.err"
rc=$?
set -e
[[ "$rc" -eq 0 ]] || fail "hoisted monorepo bin failed rc=$rc: $(cat "$tmp/mono.err")"
grep -q 'in.json out.json' "$tmp/mono-call.log" || fail "hoisted bin did not receive args"
grep -q "bin=$mono/node_modules/.bin/envsub" "$tmp/data-mono/audit.log" || fail "audit log missing resolved bin path"
pass "hoisted monorepo bin resolves via parent walk (envsub regression)"

# Nearest node_modules/.bin wins over an ancestor's.
mkdir -p "$mono/apps/web/node_modules/.bin"
cat > "$mono/apps/web/node_modules/.bin/envsub" <<'SH'
#!/usr/bin/env bash
printf 'NEAREST %s\n' "$*" > "$LOCAL_BIN_CALL_LOG"
exit 0
SH
chmod +x "$mono/apps/web/node_modules/.bin/envsub"
set +e
(
  cd "$mono/apps/web"
  SAFE_RUN_CONFIG_DIR="$tmp/config-mono-nearest" \
  SAFE_RUN_DATA_DIR="$tmp/data-mono-nearest" \
  LOCAL_BIN_CALL_LOG="$tmp/mono-nearest-call.log" \
    "$SAFE_RUN" envsub x
) </dev/null >/dev/null 2>&1
rc=$?
set -e
[[ "$rc" -eq 0 ]] || fail "nearest-bin case failed rc=$rc"
grep -q '^NEAREST x' "$tmp/mono-nearest-call.log" || fail "nearest bin did not win over ancestor"
pass "nearest node_modules/.bin wins over ancestor"

# Symlinked cwd: the walk must follow the PHYSICAL path (npm's process.cwd()),
# never logical $PWD parents — a planted node_modules in the symlink's parent
# tree must not execute, while a physical ancestor bin must still resolve.
sym_physical="$tmp/sym-physical"
sym_logical_root="$tmp/sym-logical-root"
mkdir -p "$sym_physical/project/apps/web" "$sym_physical/project/node_modules/.bin" "$sym_logical_root"
ln -s "$sym_physical/project" "$sym_logical_root/project-link"
mkdir -p "$sym_logical_root/node_modules/.bin"
cat > "$sym_logical_root/node_modules/.bin/probe" <<'SH'
#!/usr/bin/env bash
printf 'LOGICAL %s\n' "$*" > "$LOCAL_BIN_CALL_LOG"
SH
chmod +x "$sym_logical_root/node_modules/.bin/probe"
cat > "$sym_physical/project/node_modules/.bin/probe" <<'SH'
#!/usr/bin/env bash
printf 'PHYSICAL %s\n' "$*" > "$LOCAL_BIN_CALL_LOG"
SH
chmod +x "$sym_physical/project/node_modules/.bin/probe"
set +e
(
  cd "$sym_logical_root/project-link/apps/web"
  SAFE_RUN_CONFIG_DIR="$tmp/config-symcwd" \
  SAFE_RUN_DATA_DIR="$tmp/data-symcwd" \
  LOCAL_BIN_CALL_LOG="$tmp/symcwd-call.log" \
    "$SAFE_RUN" probe hello
) </dev/null >/dev/null 2>&1
rc=$?
set -e
[[ "$rc" -eq 0 ]] || fail "symlinked-cwd physical resolution failed rc=$rc"
grep -q '^PHYSICAL hello' "$tmp/symcwd-call.log" || fail "walk did not resolve the physical ancestor bin"
grep -q "bin=$sym_physical/project/node_modules/.bin/probe" "$tmp/data-symcwd/audit.log" || fail "audit log did not record the physical bin path"
pass "symlinked cwd resolves physical ancestors, never logical parents"

# Same layout with NO physical bin: the planted logical-parent bin must not
# run; the request stays in the pipeline (non-TTY unknown => 102).
rm "$sym_physical/project/node_modules/.bin/probe"
set +e
(
  cd "$sym_logical_root/project-link/apps/web"
  SAFE_RUN_CONFIG_DIR="$tmp/config-symcwd-miss" \
  SAFE_RUN_DATA_DIR="$tmp/data-symcwd-miss" \
  LOCAL_BIN_CALL_LOG="$tmp/symcwd-miss-call.log" \
    "$SAFE_RUN" probe
) </dev/null >/dev/null 2>&1
rc=$?
set -e
[[ "$rc" -eq 102 ]] || fail "planted logical-parent bin case expected rc=102, got $rc"
[[ ! -e "$tmp/symcwd-miss-call.log" ]] || fail "planted logical-parent bin was executed"
pass "planted bin in a logical parent never executes"

# Blocklist beats a PARENT-resolved bin too (not just a cwd-local one).
mkdir -p "$tmp/config-blocked-parent"
printf '{"packages":{"envsub":{"reason":"parent fixture block"}}}' > "$tmp/config-blocked-parent/blocked.json"
set +e
(
  cd "$mono/apps/web"
  SAFE_RUN_CONFIG_DIR="$tmp/config-blocked-parent" \
  SAFE_RUN_DATA_DIR="$tmp/data-blocked-parent" \
  LOCAL_BIN_CALL_LOG="$tmp/blocked-parent-call.log" \
    "$SAFE_RUN" envsub
) </dev/null >/dev/null 2>"$tmp/blocked-parent.err"
rc=$?
set -e
[[ "$rc" -eq 100 ]] || fail "blocked parent-resolved bin expected rc=100, got $rc"
[[ ! -e "$tmp/blocked-parent-call.log" ]] || fail "blocked package executed a parent-resolved bin"
grep -q 'parent fixture block' "$tmp/blocked-parent.err" || fail "parent blocklist reason missing"
pass "blocklist wins over a parent-resolved bin"

# Audit log stays one-physical-line per decision even for hostile paths.
nl_dir="$tmp/nl-$(printf 'a\nb')"
mkdir -p "$nl_dir/node_modules/.bin"
cat > "$nl_dir/node_modules/.bin/nltool" <<'SH'
#!/usr/bin/env bash
exit 0
SH
chmod +x "$nl_dir/node_modules/.bin/nltool"
set +e
(
  cd "$nl_dir"
  SAFE_RUN_CONFIG_DIR="$tmp/config-nl" \
  SAFE_RUN_DATA_DIR="$tmp/data-nl" \
    "$SAFE_RUN" nltool
) </dev/null >/dev/null 2>&1
rc=$?
set -e
[[ "$rc" -eq 0 ]] || fail "newline-path local bin failed rc=$rc"
[[ "$(grep -c 'LOCAL_BIN' "$tmp/data-nl/audit.log")" -eq 1 ]] || fail "LOCAL_BIN entry count wrong"
[[ "$(wc -l < "$tmp/data-nl/audit.log")" -eq "$(grep -c ' | ' "$tmp/data-nl/audit.log")" ]] || fail "audit log contains split records"
pass "audit log records stay single-line for hostile bin paths"

# Shell/PATH shadowing must not steer the walk: exported pwd/dirname
# functions and a PATH-shadowed dirname point at an attacker tree, but the
# builtin-only walk must still resolve from the real physical cwd.
attacker="$tmp/steer-attacker"
victim="$tmp/steer-victim/apps/web"
mkdir -p "$attacker/node_modules/.bin" "$victim"
cat > "$attacker/node_modules/.bin/probe" <<'SH'
#!/usr/bin/env bash
printf 'STEERED %s\n' "$*" > "$LOCAL_BIN_CALL_LOG"
SH
chmod +x "$attacker/node_modules/.bin/probe"
shadowbin="$tmp/steer-shadowbin"
mkdir -p "$shadowbin"
printf '#!/usr/bin/env bash\necho %s\n' "$attacker" > "$shadowbin/dirname"
chmod +x "$shadowbin/dirname"
set +e
(
  cd "$victim"
  pwd() { echo "$attacker"; }
  dirname() { echo "$attacker"; }
  export -f pwd dirname
  SAFE_RUN_CONFIG_DIR="$tmp/config-steer" \
  SAFE_RUN_DATA_DIR="$tmp/data-steer" \
  LOCAL_BIN_CALL_LOG="$tmp/steer-call.log" \
  PATH="$shadowbin:$PATH" \
    "$SAFE_RUN" probe
) </dev/null >/dev/null 2>&1
rc=$?
set -e
[[ "$rc" -eq 102 ]] || fail "steered walk expected rc=102, got $rc"
[[ ! -e "$tmp/steer-call.log" ]] || fail "shell/PATH shadowing steered the local-bin walk"
pass "exported pwd/dirname and PATH shadowing cannot steer the walk"

# Same steering against the strict --no-install path.
set +e
(
  cd "$victim"
  pwd() { echo "$attacker"; }
  export -f pwd
  SAFE_RUN_CONFIG_DIR="$tmp/config-steer-ni" \
  SAFE_RUN_DATA_DIR="$tmp/data-steer-ni" \
  LOCAL_BIN_CALL_LOG="$tmp/steer-ni-call.log" \
  PATH="$shadowbin:$PATH" \
    "$SAFE_RUN" --no-install probe
) </dev/null >/dev/null 2>&1
rc=$?
set -e
[[ "$rc" -eq 100 ]] || fail "steered --no-install expected rc=100, got $rc"
[[ ! -e "$tmp/steer-ni-call.log" ]] || fail "shadowing steered the --no-install local-bin path"
pass "steering cannot reach the strict --no-install path either"

# ---------------------------------------------------------------------------
# Host-side unknown-package audit preflight (Fibery #86)
#
# The preflight re-audits an unknown package host-side (installed safe-audit,
# no container) on the proceed path, before it is sandboxed. safe-audit is
# mocked (see $mockbin/safe-audit) so the suite stays hermetic. The BLOCK->104
# case is the falsifier: without the preflight an unknown package sandboxes
# (rc 0), never 104.
# ---------------------------------------------------------------------------

# Fresh (unknown) npm package on the interactive proceed path; run_sandbox is
# stubbed to record that execution was reached. FORCE=1 sets --force.
preflight_fixture='
  set -- version
  source "$SAFE_RUN_PATH" >/dev/null
  ensure_dirs
  is_tty() { return 0; }
  RUNNER_KIND=npm
  PKG_NAME=freshpkg
  PKG_VERSION=9.9.9
  PKG_VERSION_USER_SPECIFIED=1
  SKIP_PROMPT=1
  [[ "${FORCE:-0}" == "1" ]] && FORCE_AUDIT_OVERRIDE=1
  mark_sandbox_known() { :; }
  run_sandbox_with_audit_log() { printf ran >> "$PREFLIGHT_RAN_LOG"; return 0; }
  dispatch_run
'

# A: BLOCK verdict refuses with exit 104 before the sandbox (the falsifier).
set +e
SAFE_RUN_CONFIG_DIR="$tmp/config-pf-block" SAFE_RUN_DATA_DIR="$tmp/data-pf-block" \
SAFE_RUN_PATH="$SAFE_RUN" \
SAFE_AUDIT_PROBE_RC=20 SAFE_AUDIT_PROBE_JSON='{"verdict":"BLOCK","warn_causes":[]}' \
SAFE_AUDIT_PROBE_LOG="$tmp/pf-block-probe.log" \
PREFLIGHT_RAN_LOG="$tmp/pf-block-ran.log" \
  bash -c "$preflight_fixture" safe-run >"$tmp/pf-block.err" 2>&1
rc=$?
set -e
[[ "$rc" -eq 104 ]] || fail "unknown BLOCK preflight expected exit 104, got $rc"
[[ ! -e "$tmp/pf-block-ran.log" ]] || fail "BLOCK preflight reached the sandbox"
[[ -s "$tmp/pf-block-probe.log" ]] || fail "BLOCK preflight did not invoke safe-audit"
grep -q 'to override' "$tmp/pf-block.err" || fail "BLOCK refusal omits the --force override hint"
pass "unknown-package BLOCK verdict refuses with exit 104 before sandboxing"

# B: --force (operator TTY) overrides the BLOCK into the sandbox, logged.
set +e
SAFE_RUN_CONFIG_DIR="$tmp/config-pf-force" SAFE_RUN_DATA_DIR="$tmp/data-pf-force" \
SAFE_RUN_PATH="$SAFE_RUN" FORCE=1 \
SAFE_AUDIT_PROBE_RC=20 SAFE_AUDIT_PROBE_JSON='{"verdict":"BLOCK","warn_causes":[]}' \
SAFE_AUDIT_PROBE_LOG="$tmp/pf-force-probe.log" \
PREFLIGHT_RAN_LOG="$tmp/pf-force-ran.log" \
  bash -c "$preflight_fixture" safe-run >/dev/null 2>&1
rc=$?
set -e
[[ "$rc" -eq 0 ]] || fail "--force override expected exit 0, got $rc"
[[ -s "$tmp/pf-force-ran.log" ]] || fail "--force did not reach the sandbox"
grep -q 'PREFLIGHT | interactive | BLOCK_FORCED' "$tmp/data-pf-force/audit.log" || fail "--force override not logged as BLOCK_FORCED"
pass "--force overrides a BLOCK verdict into the sandbox (TTY, logged)"

# C: WARN with a real package finding warns and continues into the sandbox.
set +e
SAFE_RUN_CONFIG_DIR="$tmp/config-pf-warn" SAFE_RUN_DATA_DIR="$tmp/data-pf-warn" \
SAFE_RUN_PATH="$SAFE_RUN" \
SAFE_AUDIT_PROBE_RC=10 SAFE_AUDIT_PROBE_JSON='{"verdict":"WARN","warn_causes":["malware"]}' \
PREFLIGHT_RAN_LOG="$tmp/pf-warn-ran.log" \
  bash -c "$preflight_fixture" safe-run >/dev/null 2>&1
rc=$?
set -e
[[ "$rc" -eq 0 ]] || fail "WARN preflight expected exit 0, got $rc"
[[ -s "$tmp/pf-warn-ran.log" ]] || fail "WARN preflight did not continue into the sandbox"
grep -q 'PREFLIGHT | interactive | WARN' "$tmp/data-pf-warn/audit.log" || fail "WARN preflight not logged"
pass "unknown-package WARN warns and continues into the sandbox"

# D: infra-only WARN is audit breakage, not a package finding -> inconclusive.
set +e
SAFE_RUN_CONFIG_DIR="$tmp/config-pf-infra" SAFE_RUN_DATA_DIR="$tmp/data-pf-infra" \
SAFE_RUN_PATH="$SAFE_RUN" \
SAFE_AUDIT_PROBE_RC=10 SAFE_AUDIT_PROBE_JSON='{"verdict":"WARN","warn_causes":["socket_unavailable"]}' \
PREFLIGHT_RAN_LOG="$tmp/pf-infra-ran.log" \
  bash -c "$preflight_fixture" safe-run >/dev/null 2>&1
rc=$?
set -e
[[ "$rc" -eq 0 ]] || fail "infra-only WARN expected exit 0, got $rc"
[[ -s "$tmp/pf-infra-ran.log" ]] || fail "infra-only WARN did not continue into the sandbox"
grep -q 'PREFLIGHT | interactive | INCONCLUSIVE' "$tmp/data-pf-infra/audit.log" || fail "infra-only WARN not logged as INCONCLUSIVE"
pass "unknown-package infra-only WARN degrades to inconclusive, never blocks"

# E: clean GO continues and is logged as GO.
set +e
SAFE_RUN_CONFIG_DIR="$tmp/config-pf-go" SAFE_RUN_DATA_DIR="$tmp/data-pf-go" \
SAFE_RUN_PATH="$SAFE_RUN" \
PREFLIGHT_RAN_LOG="$tmp/pf-go-ran.log" \
  bash -c "$preflight_fixture" safe-run >/dev/null 2>&1
rc=$?
set -e
[[ "$rc" -eq 0 ]] || fail "GO preflight expected exit 0, got $rc"
[[ -s "$tmp/pf-go-ran.log" ]] || fail "GO preflight did not continue into the sandbox"
grep -q 'PREFLIGHT | interactive | GO' "$tmp/data-pf-go/audit.log" || fail "GO preflight not logged"
pass "unknown-package clean GO continues into the sandbox"

# F: no installed safe-audit -> degrade honestly (warn + continue), no verdict.
set +e
SAFE_RUN_CONFIG_DIR="$tmp/config-pf-missing" SAFE_RUN_DATA_DIR="$tmp/data-pf-missing" \
SAFE_RUN_PATH="$SAFE_RUN" \
SAFE_AUDIT_BIN="/nonexistent/safe-audit-absent" \
SAFE_AUDIT_PROBE_LOG="$tmp/pf-missing-probe.log" \
PREFLIGHT_RAN_LOG="$tmp/pf-missing-ran.log" \
  bash -c "$preflight_fixture" safe-run >/dev/null 2>&1
rc=$?
set -e
[[ "$rc" -eq 0 ]] || fail "missing safe-audit expected exit 0, got $rc"
[[ -s "$tmp/pf-missing-ran.log" ]] || fail "missing safe-audit did not continue into the sandbox"
[[ ! -e "$tmp/pf-missing-probe.log" ]] || fail "missing safe-audit somehow probed"
grep -q 'PREFLIGHT | interactive | UNAVAILABLE' "$tmp/data-pf-missing/audit.log" || fail "missing safe-audit not logged as UNAVAILABLE"
pass "no installed safe-audit degrades honestly (no verdict, continue)"

# G (placement discriminator): a NON-TTY unknown still refuses early with exit
# 102 and runs NO audit — the hottest refusal lane pays no preflight cost.
set +e
SAFE_RUN_CONFIG_DIR="$tmp/config-pf-nontty" SAFE_RUN_DATA_DIR="$tmp/data-pf-nontty" \
SAFE_RUN_PATH="$SAFE_RUN" \
SAFE_AUDIT_PROBE_LOG="$tmp/pf-nontty-probe.log" \
PREFLIGHT_RAN_LOG="$tmp/pf-nontty-ran.log" \
  bash -c '
    set -- version
    source "$SAFE_RUN_PATH" >/dev/null
    ensure_dirs
    RUNNER_KIND=npm
    PKG_NAME=freshpkg
    PKG_VERSION=9.9.9
    PKG_VERSION_USER_SPECIFIED=1
    run_sandbox_with_audit_log() { printf ran >> "$PREFLIGHT_RAN_LOG"; return 0; }
    dispatch_run
  ' safe-run >/dev/null 2>&1
rc=$?
set -e
[[ "$rc" -eq 102 ]] || fail "non-TTY unknown expected exit 102, got $rc"
[[ ! -e "$tmp/pf-nontty-probe.log" ]] || fail "non-TTY unknown invoked the preflight (should not)"
[[ ! -e "$tmp/pf-nontty-ran.log" ]] || fail "non-TTY unknown reached the sandbox"
pass "non-TTY unknown refuses with exit 102 and runs no audit preflight"

# --- Grant-lane preflight (host-allow add): re-audit before trust escalation ---

# I: BLOCK verdict aborts the grant on a non-TTY confirmation; nothing written.
set +e
SAFE_RUN_CONFIG_DIR="$tmp/config-grant-block" SAFE_RUN_DATA_DIR="$tmp/data-grant-block" \
SAFE_RUN_PATH="$SAFE_RUN" \
SAFE_AUDIT_PROBE_RC=20 SAFE_AUDIT_PROBE_JSON='{"verdict":"BLOCK","warn_causes":[]}' \
SAFE_AUDIT_PROBE_LOG="$tmp/grant-block-probe.log" \
ERR_FILE="$tmp/grant-block.err" \
  bash -c '
    set -- version
    source "$SAFE_RUN_PATH" >/dev/null
    ensure_dirs
    registry_integrity_npm() { printf "sha512-fixture"; }
    require_operator_tty() { :; }
    set +e
    ( cmd_host_allow_add newpkg@1.0.0 --reason "wants it" ) >/dev/null 2>"$ERR_FILE"
    grc=$?
    set -e
    [[ "$grc" -ne 0 ]] || exit 1
    [[ "$(jq -r ".packages | length" "$HOST_ALLOW_FILE")" == "0" ]] || exit 1
    grep -q "interactive operator terminal" "$ERR_FILE" || exit 1
  ' safe-run
rc=$?
set -e
[[ "$rc" -eq 0 ]] || fail "host-allow add did not abort on a non-TTY BLOCK confirmation"
[[ -s "$tmp/grant-block-probe.log" ]] || fail "grant preflight did not audit before host-allow add"
pass "host-allow add re-audits; a BLOCK verdict aborts the grant (non-TTY)"

# J: a clean GO proceeds and the grant lane did audit (probe invoked).
SAFE_RUN_CONFIG_DIR="$tmp/config-grant-go" SAFE_RUN_DATA_DIR="$tmp/data-grant-go" \
SAFE_RUN_PATH="$SAFE_RUN" \
SAFE_AUDIT_PROBE_LOG="$tmp/grant-go-probe.log" \
  bash -c '
    set -- version
    source "$SAFE_RUN_PATH" >/dev/null
    ensure_dirs
    registry_integrity_npm() { printf "sha512-fixture"; }
    require_operator_tty() { :; }
    cmd_host_allow_add okpkg@1.2.3 --reason "clean" >/dev/null 2>&1
    [[ "$(jq -r ".packages.okpkg.version" "$HOST_ALLOW_FILE")" == "1.2.3" ]]
  ' safe-run || fail "host-allow add with a clean GO preflight failed"
[[ -s "$tmp/grant-go-probe.log" ]] || fail "grant preflight did not audit on a clean add"
pass "host-allow add audits host-side and a clean GO proceeds"

# L: infra-only WARN never blocks a grant (audit breakage != package finding).
SAFE_RUN_CONFIG_DIR="$tmp/config-grant-infra" SAFE_RUN_DATA_DIR="$tmp/data-grant-infra" \
SAFE_RUN_PATH="$SAFE_RUN" \
SAFE_AUDIT_PROBE_RC=10 SAFE_AUDIT_PROBE_JSON='{"verdict":"WARN","warn_causes":["osv_unavailable"]}' \
  bash -c '
    set -- version
    source "$SAFE_RUN_PATH" >/dev/null
    ensure_dirs
    registry_integrity_npm() { printf "sha512-fixture"; }
    require_operator_tty() { :; }
    cmd_host_allow_add infrapkg@2.0.0 --reason "infra" >/dev/null 2>&1
    [[ "$(jq -r ".packages.infrapkg.version" "$HOST_ALLOW_FILE")" == "2.0.0" ]]
  ' safe-run || fail "host-allow add blocked on an infra-only WARN (should degrade)"
pass "host-allow add: infra-only WARN degrades, grant proceeds"

# --- Round-1 fix regressions (F1–F4) ---

# F1: a forced BLOCK runs ONCE in the sandbox but is NEVER persisted as
# sandbox-known — else a later non-TTY/no-force run would sandbox the blocked
# package with no fresh audit. Uses the REAL mark_sandbox_known (the no-op stub
# is exactly what masked this).
CFG_FP="$tmp/config-force-persist"; DATA_FP="$tmp/data-force-persist"
set +e
SAFE_RUN_CONFIG_DIR="$CFG_FP" SAFE_RUN_DATA_DIR="$DATA_FP" SAFE_RUN_PATH="$SAFE_RUN" \
SAFE_AUDIT_BIN=safe-audit FORCE=1 \
SAFE_AUDIT_PROBE_RC=20 SAFE_AUDIT_PROBE_JSON='{"verdict":"BLOCK","warn_causes":[]}' \
PREFLIGHT_RAN_LOG="$tmp/fp1-ran.log" \
  bash -c '
    set -- version
    source "$SAFE_RUN_PATH" >/dev/null
    ensure_dirs
    is_tty() { return 0; }
    RUNNER_KIND=npm; PKG_NAME=freshpkg; PKG_VERSION=9.9.9; PKG_VERSION_USER_SPECIFIED=1
    SKIP_PROMPT=1; FORCE_AUDIT_OVERRIDE=1
    run_sandbox_with_audit_log() { printf ran >> "$PREFLIGHT_RAN_LOG"; return 0; }
    dispatch_run
  ' safe-run >/dev/null 2>&1
rc1=$?
set -e
[[ "$rc1" -eq 0 ]] || fail "forced-BLOCK run expected exit 0, got $rc1"
[[ -s "$tmp/fp1-ran.log" ]] || fail "forced-BLOCK did not run once in the sandbox"
[[ "$(jq -r '.packages.freshpkg // "absent"' "$CFG_FP/sandbox-known.json")" == "absent" ]] \
  || fail "forced BLOCK persisted the blocked package as sandbox-known (F1)"
# Second dispatch: non-TTY, no force -> the package is still unknown -> refuse 102.
set +e
SAFE_RUN_CONFIG_DIR="$CFG_FP" SAFE_RUN_DATA_DIR="$DATA_FP" SAFE_RUN_PATH="$SAFE_RUN" \
SAFE_AUDIT_BIN=safe-audit \
PREFLIGHT_RAN_LOG="$tmp/fp2-ran.log" \
  bash -c '
    set -- version
    source "$SAFE_RUN_PATH" >/dev/null
    ensure_dirs
    RUNNER_KIND=npm; PKG_NAME=freshpkg; PKG_VERSION=9.9.9; PKG_VERSION_USER_SPECIFIED=1
    run_sandbox_with_audit_log() { printf ran >> "$PREFLIGHT_RAN_LOG"; return 0; }
    dispatch_run
  ' safe-run >/dev/null 2>&1
rc2=$?
set -e
[[ "$rc2" -eq 102 ]] || fail "post-force non-TTY dispatch expected 102, got $rc2 (blocked pkg was persisted?)"
[[ ! -e "$tmp/fp2-ran.log" ]] || fail "post-force run reached the sandbox — the blocked pkg persisted (F1)"
pass "forced BLOCK runs once but is never persisted as sandbox-known (F1)"

# F2: an EXECUTED safe-run binds its preflight to the safe-audit installed
# beside it, never a PATH-shadowed decoy. Driven via `host-allow review` (a
# read-only, non-TTY-OK path that runs the same host-side probe), so no pty is
# needed. safe-run is copied next to a recording sibling; a decoy is first on
# PATH; SAFE_AUDIT_BIN is left unset so the executed-mode resolution runs.
fake="$tmp/fake-install"; decoy="$tmp/decoy-bin"
mkdir -p "$fake" "$decoy"
command cp "$SAFE_RUN" "$fake/safe-run"
cat > "$fake/safe-audit" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$SIBLING_LOG"
printf '{"verdict":"GO","warn_causes":[]}'
exit 0
SH
cat > "$decoy/safe-audit" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$DECOY_LOG"
printf '{"verdict":"GO","warn_causes":[]}'
exit 0
SH
chmod +x "$fake/safe-audit" "$decoy/safe-audit"
CFG_F2="$tmp/config-f2"; mkdir -p "$CFG_F2"
cat > "$CFG_F2/host-allow.json" <<'JSON'
{"packages":{"probepkg":{"version":"1.0.0","ecosystem":"npm","added":"2026-01-01","reason":"x","sha":"sha512-x"}}}
JSON
set +e
env -u SAFE_AUDIT_BIN \
SAFE_RUN_CONFIG_DIR="$CFG_F2" SAFE_RUN_DATA_DIR="$tmp/data-f2" SAFE_AUDIT_DATA_DIR="$tmp/adata-f2" \
SIBLING_LOG="$tmp/f2-sibling.log" DECOY_LOG="$tmp/f2-decoy.log" \
PATH="$decoy:/usr/bin:/bin" \
  "$fake/safe-run" host-allow review >/dev/null 2>&1
set -e
[[ -s "$tmp/f2-sibling.log" ]] || fail "executed safe-run did not bind to its sibling safe-audit (F2)"
[[ ! -s "$tmp/f2-decoy.log" ]] || fail "executed safe-run used a PATH-shadowed decoy safe-audit (F2)"
pass "executed safe-run binds its preflight probe to the sibling safe-audit, not a PATH decoy (F2)"

# F3: grant-time rc 0 without a corroborating GO (e.g. empty {} output) must
# degrade honestly — proceed, but WARN so the operator knows the grant-time
# audit did not actually clear the package.
CFG_F3="$tmp/config-f3"
set +e
SAFE_RUN_CONFIG_DIR="$CFG_F3" SAFE_RUN_DATA_DIR="$tmp/data-f3" SAFE_RUN_PATH="$SAFE_RUN" \
SAFE_AUDIT_BIN=safe-audit \
SAFE_AUDIT_PROBE_RC=0 SAFE_AUDIT_PROBE_JSON='{}' \
ERR_FILE="$tmp/f3.err" \
  bash -c '
    set -- version
    source "$SAFE_RUN_PATH" >/dev/null
    ensure_dirs
    registry_integrity_npm() { printf "sha512-fixture"; }
    require_operator_tty() { :; }
    cmd_host_allow_add incpkg@3.0.0 --reason "x" 2>"$ERR_FILE"
    [[ "$(jq -r ".packages.incpkg.version" "$HOST_ALLOW_FILE")" == "3.0.0" ]]
  ' safe-run
rc=$?
set -e
[[ "$rc" -eq 0 ]] || fail "grant on rc-0 empty output did not proceed (should degrade, not block)"
grep -q "inconclusive" "$tmp/f3.err" || fail "grant on rc-0 empty output did not warn inconclusive (F3)"
pass "grant-time rc-0 without a corroborating GO degrades honestly (warns, proceeds) (F3)"

# F4: a bun (bunx) preflight passes --installer bun so safe-audit models bun's
# resolution, not npm's. Bun still maps to the npm ECOSYSTEM.
set +e
SAFE_RUN_CONFIG_DIR="$tmp/config-f4" SAFE_RUN_DATA_DIR="$tmp/data-f4" SAFE_RUN_PATH="$SAFE_RUN" \
SAFE_AUDIT_BIN=safe-audit \
SAFE_AUDIT_PROBE_LOG="$tmp/f4-probe.log" \
  bash -c '
    set -- version
    source "$SAFE_RUN_PATH" >/dev/null
    ensure_dirs
    is_tty() { return 0; }
    RUNNER_KIND=bun; PKG_NAME=bunpkg; PKG_VERSION=1.0.0; PKG_VERSION_USER_SPECIFIED=1
    SKIP_PROMPT=1
    mark_sandbox_known() { :; }
    run_sandbox_with_audit_log() { return 0; }
    dispatch_run
  ' safe-run >/dev/null 2>&1
set -e
grep -q -- '--installer bun' "$tmp/f4-probe.log" || fail "bun preflight did not pass --installer bun (F4)"
grep -q -- '--ecosystem npm' "$tmp/f4-probe.log" || fail "bun preflight did not use the npm ecosystem (F4)"
pass "bunx preflight passes --installer bun on the npm ecosystem (F4)"
