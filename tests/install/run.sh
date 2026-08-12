#!/usr/bin/env bash
set -u

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
# The repo VERSION, read once. Fixtures that need the CURRENT version must
# derive it here: hard-coding it makes every release bump a false failure.
SAFE_REPO_VERSION="$(tr -d '[:space:]' < "${ROOT_DIR}/VERSION")"
ZSH_BIN="$(command -v zsh)"
TEST_ROOT="$(mktemp -d)"
PASS_COUNT=0
FAIL_COUNT=0
SAFE_CORE_TEST_BIN="${TEST_ROOT}/safe-core"
SAFE_CORE_TEST_AVAILABLE=0

if command -v go >/dev/null 2>&1; then
  if ( cd "${ROOT_DIR}" && go build -trimpath -ldflags "-X main.version=$(tr -d '[:space:]' < VERSION)" -o "${SAFE_CORE_TEST_BIN}" ./cmd/safe-core ); then
    SAFE_CORE_TEST_AVAILABLE=1
  else
    printf 'not ok - safe-core test binary build failed\n' >&2
    exit 1
  fi
else
  printf 'SKIP: Go is unavailable; safe-core lockdiff install cases are skipped\n' >&2
fi

cleanup() {
  rm -rf "${TEST_ROOT}"
}
trap cleanup EXIT

fail() {
  printf 'not ok - %s\n' "$1" >&2
  FAIL_COUNT=$((FAIL_COUNT + 1))
}

pass() {
  printf 'ok - %s\n' "$1"
  PASS_COUNT=$((PASS_COUNT + 1))
}

write_tool_stub() {
  local bin_dir="$1"
  local tool="$2"

  cat > "${bin_dir}/${tool}" <<'STUB'
#!/usr/bin/env bash
tool="$(basename -- "$0")"
{
  if [[ "${SAFE_GATE_LOCKDIFF_PROJECTION:-0}" == "1" ]]; then
    printf 'PROJECTION\t%s' "${tool}"
    # The projection must see the project's npm config (F3 ruling): surface
    # whether the scratch cwd carries the copied .npmrc.
    [[ -f .npmrc ]] && printf '\tPROJNPMRC'
  else
    printf 'REAL\t%s' "${tool}"
  fi
  for arg in "$@"; do
    printf '\t%s' "${arg}"
  done
  printf '\n'
  # Any source-set variable reaching the delegated tool's environment is a
  # credential leak: the gate accumulates them, the real tool must never see
  # them. Logged only when non-empty so existing assertions are unaffected.
  for leak in SAFE_GATE_REGISTRY SAFE_GATE_DIST_TAG SAFE_GATE_PROJECT_DIR \
    SAFE_GATE_NPM_USERCONFIG SAFE_GATE_NPM_GLOBALCONFIG SAFE_INSTALL_REGISTRY; do
    if [[ -n "${!leak:-}" ]]; then
      printf 'ENVLEAK\t%s=%s\n' "${leak}" "${!leak}"
    fi
  done
} >> "${SAFE_INSTALL_COMMAND_LOG}"

# Emulate npm 12's REAL config output shapes, not a convenient fiction: only
# `config list --json` emits JSON; `config get` always emits key=value text
# (bare value for a single key). The previous stub answered `config get
# --json` with a JSON object, which is a format npm never produces — the
# suite stayed green while the live gate refused every command (PR#70
# delta-3 F2/F4). A regression back to `config get` now fails the caller's
# jq parse here too, exactly as it would live.
if [[ "${tool}" == "npm" && "${1:-}" == "config" && "${2:-}" == "list" ]]; then
  wants_json=0
  for arg in "$@"; do
    [[ "${arg}" == "--json" ]] && wants_json=1
  done
  if (( wants_json )); then
    # One effective-config object, as npm returns: both probes read it.
    effective_json="${NPM_LOCKDIFF_EFFECTIVE_CONFIG_JSON:-}"
    [[ -n "${effective_json}" ]] || effective_json='{"package-lock":true,"ignore-scripts":true}'
    registry_json="${NPM_LOCKDIFF_REGISTRY_CONFIG_JSON:-}"
    [[ -n "${registry_json}" ]] || registry_json='{"registry":"https://registry.npmjs.org/"}'
    jq -cn --argjson a "${effective_json}" --argjson b "${registry_json}" '$b * $a' 2>/dev/null \
      || printf '%s\n' "${effective_json}"
  else
    printf 'package-lock=true\nignore-scripts=true\n'
  fi
  exit "${NPM_LOCKDIFF_CONFIG_STATUS:-0}"
fi

if [[ "${tool}" == "npm" && "${1:-}" == "config" && "${2:-}" == "get" ]]; then
  # npm's real `config get` format: key=value lines, never JSON.
  printf 'package-lock=true\nignore-scripts=true\n'
  exit "${NPM_LOCKDIFF_CONFIG_STATUS:-0}"
fi

if [[ "${tool}" == "npm" && -n "${NPM_LOCK_MUTATION_JSON:-}" ]]; then
  package_lock_only=0
  package_lock=1
  end_options=0
  args=("$@")
  for (( i=0; i<${#args[@]}; i++ )); do
    arg="${args[$i]}"
    (( end_options )) && continue
    [[ "${arg}" == "--" ]] && { end_options=1; continue; }
    case "${arg,,}" in
      --package-lock-only|--package-lock-only=true) package_lock_only=1 ;;
      --package-lock-only=false|--no-package-lock-only) package_lock_only=0 ;;
      --package-lock)
        [[ "${args[$((i+1))]:-}" == "false" ]] && package_lock=0
        ;;
      --package-lock=false|--no-package-lock|--no-package-lock=true) package_lock=0 ;;
      --no-package-lock=false|--package-lock=true) package_lock=1 ;;
    esac
  done
  if [[ "${npm_config_package_lock_only:-}" == "true" ]]; then package_lock_only=1; fi
  if [[ "${npm_config_package_lock:-}" == "false" ]]; then package_lock=0; fi
  if (( package_lock_only && package_lock )); then
    lockfile="package-lock.json"
    [[ -f "npm-shrinkwrap.json" ]] && lockfile="npm-shrinkwrap.json"
    printf '%s\n' "${NPM_LOCK_MUTATION_JSON}" > "${lockfile}"
    printf 'NPM_LOCK_MUTATION\t%s\n' "${lockfile}" >> "${SAFE_INSTALL_COMMAND_LOG}"
  fi
fi
exit "${SAFE_INSTALL_REAL_STATUS:-0}"
STUB
  chmod +x "${bin_dir}/${tool}"
}

write_safe_audit_stub() {
  local bin_dir="$1"

  cat > "${bin_dir}/safe-audit" <<'STUB'
#!/usr/bin/env bash
# effective-sources is local-only plumbing the stale readers depend on:
# forward it to the REAL implementation so the tests exercise the real
# source-identity derivation (delta-4 findings 3.2/N1).
if [[ "${1:-}" == "effective-sources" ]]; then
  exec "${ROOT_DIR}/bin/safe-audit" "$@"
fi
{
  printf 'AUDIT'
  for arg in "$@"; do
    printf '\t%s' "${arg}"
  done
  printf '\n'
  # The mise routes overlay project [env] sources onto the audit process:
  # surface what this invocation actually saw so tests can assert it.
  for env_name in NPM_CONFIG_REGISTRY PIP_INDEX_URL PIP_CONFIG_FILE GOPROXY \
                  CARGO_REGISTRY_DEFAULT CARGO_REGISTRIES_PRIVATE_INDEX \
                  BUN_CONFIG_REGISTRY COMPOSER_HOME SAFE_AUDIT_SOCKET_TIMEOUT \
                  SAFE_AUDIT_SOCKET_FRESH_SCAN_TIMEOUT; do
    if [[ -n "${!env_name:-}" ]]; then
      printf 'AUDITENV\t%s=%s\n' "${env_name}" "${!env_name}"
      # Byte-exact form: the plain line cannot show a trailing newline or
      # distinguish empty from unset.
      printf 'AUDITENV_B64\t%s=%s\n' "${env_name}" "$(printf '%s' "${!env_name}" | base64 -w0)"
    fi
  done
  # Global-Composer routing must scan the global project rather than the
  # caller's cwd. Only the focused regression sets this fixture assertion.
  if [[ -n "${SAFE_AUDIT_EXPECT_PROJECT:-}" || -n "${SAFE_AUDIT_EXPECT_PROJECTS:-}" ]]; then
    printf 'AUDITPROJECT\t%s\n' "$PWD"
  fi
} >> "${SAFE_INSTALL_COMMAND_LOG}"

if [[ "${1:-}" == "scan" ]]; then
  [[ -n "${SAFE_AUDIT_SCAN_OUTPUT:-}" ]] && printf '%s\n' "${SAFE_AUDIT_SCAN_OUTPUT}"
  # The gate decides from the result document, not from this exit code: a scan
  # that finds a critical advisory still exits 0.
  result_out=""
  prev=""
  for arg in "$@"; do
    [[ "${prev}" == "--result-out" ]] && result_out="${arg}"
    prev="${arg}"
  done
  if [[ -n "${result_out}" && "${SAFE_AUDIT_SCAN_MALFORMED_RESULT:-0}" == "1" ]]; then
    # A truncated write: non-empty, so the "is there a file" test passes, but
    # every jq expression against it falls back to its default.
    printf '{"verdict": "GO", "audit_totals": {"critic' > "${result_out}"
    exit "${SAFE_AUDIT_SCAN_STATUS:-0}"
  fi
  if [[ -n "${result_out}" && "${SAFE_AUDIT_SCAN_NO_RESULT:-0}" != "1" ]]; then
    # Defaults are assigned first: inside a heredoc, ${var:-'{"a":1}'} keeps
    # the quotes literally and the document stops being JSON.
    stub_tool_status="${SAFE_AUDIT_SCAN_TOOL_STATUS:-}"
    [[ -n "${stub_tool_status}" ]] || stub_tool_status='{"osv-scanner":{"status":"ok","note":null}}'
    stub_eco_audits="${SAFE_AUDIT_SCAN_ECOSYSTEM_AUDITS:-}"
    [[ -n "${stub_eco_audits}" ]] || stub_eco_audits='[]'
    scan_critical="${SAFE_AUDIT_SCAN_CRITICAL:-0}"
    if [[ -n "${SAFE_AUDIT_SCAN_CRITICAL_PROJECT:-}" ]]; then
      if [[ "$PWD" == "${SAFE_AUDIT_SCAN_CRITICAL_PROJECT}" ]]; then
        scan_critical=1
      else
        scan_critical=0
      fi
    fi
    cat > "${result_out}" <<JSON
{
  "verdict": "${SAFE_AUDIT_SCAN_VERDICT:-GO}",
  "summary": {"packages_total": 3},
  "cve_scan": {"critical": ${scan_critical}, "high": 0, "medium": 0, "low": 0, "findings": []},
  "audit_totals": {
    "critical": ${scan_critical}, "high": 0, "medium": 0, "low": 0, "unknown": 0,
    "cve_scan": {"critical": ${scan_critical}, "high": 0, "medium": 0, "low": 0},
    "ecosystem": [], "deduplicated": false
  },
  "tool_status": ${stub_tool_status},
  "ecosystem_audits": ${stub_eco_audits}
}
JSON
  fi
  exit "${SAFE_AUDIT_SCAN_STATUS:-0}"
fi

for arg in "$@"; do
  case "${arg}" in
    *blockme*) exit 20 ;;
    *warnme*) exit 10 ;;
  esac
done

# Bounded sleeper for leash-liveness cases: proves the gate's timeout(1)
# actually wraps this child (PR#65 review F3). The TERM-resistant variant
# ignores TERM and keeps re-spawning short sleeps (timeout signals the whole
# process group, so a single long sleep would die cooperatively) — only the
# --kill-after KILL escalation can end it (delta N2).
if [[ -n "${SAFE_AUDIT_CHECK_SLEEP:-}" ]]; then
  if [[ "${SAFE_AUDIT_CHECK_TRAP_TERM:-0}" == "1" ]]; then
    trap '' TERM
    deadline=$(( SECONDS + SAFE_AUDIT_CHECK_SLEEP ))
    while (( SECONDS < deadline )); do sleep 0.2 || true; done
  else
    sleep "${SAFE_AUDIT_CHECK_SLEEP}"
  fi
fi

exit "${SAFE_AUDIT_CHECK_STATUS:-0}"
STUB
  chmod +x "${bin_dir}/safe-audit"
}

# mise needs a smarter stub: the gate queries the REAL mise for config
# enumeration (ls), env derivation (env --json), bare-name backend
# resolution (registry) and the exec auto-install setting before
# delegating. Helper queries answer from MISE_* vars and log MISEQ lines
# (so tests can assert the exact query argv, context flags included);
# anything else is a delegated command and logs REAL.
write_mise_stub() {
  local bin_dir="$1"

  cat > "${bin_dir}/mise" <<'STUB'
#!/usr/bin/env bash
log_line() {
  {
    printf '%s' "$1"
    shift
    for arg in "$@"; do
      printf '\t%s' "${arg}"
    done
    printf '\n'
  } >> "${SAFE_INSTALL_COMMAND_LOG}"
}
args=("$@")
sub=""
i=0
while (( i < ${#args[@]} )); do
  case "${args[$i]}" in
    -C|--cd|-E|--env|-j|--jobs|--output|--log-level) i=$((i + 2)) ;;
    -*) i=$((i + 1)) ;;
    *) sub="${args[$i]}"; break ;;
  esac
done
case "$sub" in
  ls)
    log_line MISEQ "$@"
    [[ "${MISE_LS_STATUS:-0}" != 0 ]] && exit "${MISE_LS_STATUS}"
    # A second answer proves whether callers re-query: if the snapshot is
    # shared, MISE_LS_JSON_2 is never observed.
    if [[ -n "${MISE_LS_JSON_2:-}" && -f "${SAFE_INSTALL_COMMAND_LOG}.lsonce" ]]; then
      printf '%s\n' "${MISE_LS_JSON_2}"
      exit 0
    fi
    : > "${SAFE_INSTALL_COMMAND_LOG}.lsonce"
    printf '%s\n' "${MISE_LS_JSON:-{\}}"
    exit 0
    ;;
  env)
    log_line MISEQ "$@"
    [[ "${MISE_ENV_STATUS:-0}" != 0 ]] && exit "${MISE_ENV_STATUS}"
    printf '%s\n' "${MISE_ENV_JSON:-{\}}"
    exit 0
    ;;
  registry)
    log_line MISEQ "$@"
    if [[ -n "${MISE_REGISTRY_OUT:-}" ]]; then
      printf '%s\n' "${MISE_REGISTRY_OUT}"
      exit "${MISE_REGISTRY_STATUS:-0}"
    fi
    name=""
    seen=0
    for arg in "$@"; do
      if (( seen )) && [[ "$arg" != "--" ]]; then
        name="$arg"
        break
      fi
      [[ "$arg" == "registry" ]] && seen=1
    done
    case "$name" in
      node|python|ruby|go|rust|java|bun|deno|erlang|elixir|zig|swift)
        printf 'core:%s\n' "$name"
        exit 0
        ;;
      prettier) printf 'npm:prettier\n'; exit 0 ;;
      cowsay) printf 'npm:cowsay\n'; exit 0 ;;
      blockme) printf 'npm:blockme\n'; exit 0 ;;
      ripgrep) printf 'aqua:BurntSushi/ripgrep cargo:ripgrep\n'; exit 0 ;;
      *) exit 1 ;;
    esac
    ;;
  settings)
    log_line MISEQ "$@"
    setting=""
    for arg in "$@"; do
      case "$arg" in
        exec_auto_install|npm.package_manager) setting="$arg" ;;
      esac
    done
    case "$setting" in
      npm.package_manager)
        [[ "${MISE_NPM_PM_STATUS:-0}" != 0 ]] && exit "${MISE_NPM_PM_STATUS}"
        printf '%s\n' "${MISE_NPM_PM:-auto}"
        ;;
      *) printf '%s\n' "${MISE_EXEC_AUTO_INSTALL:-false}" ;;
    esac
    exit 0
    ;;
  tool)
    log_line MISEQ "$@"
    [[ "${MISE_TOOL_STATUS:-0}" != 0 ]] && exit "${MISE_TOOL_STATUS}"
    printf '%s\n' "${MISE_TOOL_JSON:-{\"tool_options\": {\}\}}"
    exit 0
    ;;
esac
log_line REAL mise "$@"
exit "${SAFE_INSTALL_REAL_STATUS:-0}"
STUB
  chmod +x "${bin_dir}/mise"
}

# The wrappers install.sh generates. Shape must stay in sync with
# install_gate_wrappers() in install.sh — that is what the suite exercises.
write_gate_wrappers() {
  local wrapper_dir="$1"
  local tool

  for tool in npm pnpm pnpx yarn bun pip pip3 uv cargo go composer; do
    cat > "${wrapper_dir}/${tool}" <<EOF
#!/usr/bin/env bash
# safe-gate-wrapper v1 tool=${tool}
exec safe gate ${tool} -- "\$@"
EOF
    chmod +x "${wrapper_dir}/${tool}"
  done
  # The mise wrapper carries the argv0-dispatch branch: mise shims are
  # symlinks to whatever `mise` resolves to, and a shim dispatch must reach
  # the real binary with argv[0] intact, never the gate.
  cat > "${wrapper_dir}/mise" <<'EOF'
#!/usr/bin/env bash
# safe-gate-wrapper v1 tool=mise
if [[ "${0##*/}" != "mise" ]]; then
  IFS=: read -ra __dirs <<< "$PATH"
  for __d in "${__dirs[@]}"; do
    [[ -n "$__d" ]] || continue
    __c="${__d%/}/mise"
    [[ -f "$__c" && -x "$__c" ]] || continue
    [[ "$__c" -ef "${BASH_SOURCE[0]}" ]] && continue
    LC_ALL=C head -n 2 -- "$__c" 2>/dev/null | grep -q '^# safe-gate-wrapper' && continue
    exec -a "$0" "$__c" "$@"
  done
  printf 'safe gate: real mise not found on PATH (argv0 dispatch for %s)\n' "${0##*/}" >&2
  exit 127
fi
exec safe gate mise -- "$@"
EOF
  chmod +x "${wrapper_dir}/mise"
}

# PATH-injected timeout recorder: logs the exact argv the gate hands
# timeout(1), so the leash value is pinned at the real call site instead of
# self-reported by the code under test (PR#65 delta N2), then delegates to
# the real binary.
write_timeout_recorder() {
  local bin_dir="$1"
  cat > "${bin_dir}/timeout" <<'STUB'
#!/usr/bin/env bash
{
  printf 'TIMEOUTARGV'
  for arg in "$@"; do
    printf '\t%s' "${arg}"
  done
  printf '\n'
} >> "${SAFE_INSTALL_COMMAND_LOG}"
exec /usr/bin/timeout "$@"
STUB
  chmod +x "${bin_dir}/timeout"
}

prepare_case() {
  local name="$1"
  local with_safe_audit="${2:-yes}"
  CASE_DIR="${TEST_ROOT}/${name}"
  BIN_DIR="${CASE_DIR}/bin"
  WRAPPER_DIR="${CASE_DIR}/wrappers"
  WORK_DIR="${CASE_DIR}/work"
  HOME_DIR="${CASE_DIR}/home"
  LOG_FILE="${CASE_DIR}/commands.log"
  OUT_FILE="${CASE_DIR}/stdout.log"
  ERR_FILE="${CASE_DIR}/stderr.log"

  mkdir -p "${BIN_DIR}" "${WRAPPER_DIR}" "${WORK_DIR}" "${HOME_DIR}"
  : > "${LOG_FILE}"
  : > "${OUT_FILE}"
  : > "${ERR_FILE}"

  local tool
  for tool in npm pnpm pnpx yarn bun uv pip pip3 cargo go composer volta; do
    write_tool_stub "${BIN_DIR}" "${tool}"
  done
  write_mise_stub "${BIN_DIR}"

  # The real dispatcher: `safe gate` is under test, so nothing about it is
  # stubbed. Only safe-audit is (via SAFE_AUDIT_PATH, see run_zsh).
  ln -sf "${ROOT_DIR}/bin/safe" "${BIN_DIR}/safe"

  write_gate_wrappers "${WRAPPER_DIR}"

  if [[ "${with_safe_audit}" == "yes" ]]; then
    write_safe_audit_stub "${BIN_DIR}"
  fi
  if [[ "${SAFE_CORE_TEST_AVAILABLE}" == "1" ]]; then
    ln -s "${SAFE_CORE_TEST_BIN}" "${BIN_DIR}/safe-core"
  fi
}

# lockdiff trusts the helper installed beside the real dispatcher. Most gate
# cases intentionally symlink `safe` to the checkout so they exercise its
# development lib path; these cases instead model the installed layout with a
# copied dispatcher, a sibling core, and the copied gate library's parent.
prepare_lockdiff_case() {
  prepare_case "$1"
  rm -f "${BIN_DIR}/safe"
  cp "${ROOT_DIR}/bin/safe" "${BIN_DIR}/safe"
  chmod +x "${BIN_DIR}/safe"
  ln -s "${ROOT_DIR}/lib" "${CASE_DIR}/lib"
  ln -s "${ROOT_DIR}/bin/safe-run" "${BIN_DIR}/safe-run"
  # The F3 guard refuses when node_modules is absent (the real command would
  # materialize every lockfile artifact unaudited); lockdiff cases model a
  # populated project unless they test the guard itself.
  mkdir -p "${WORK_DIR}/node_modules"
}

# Gate mode: the wrappers sit ahead of the tool stubs on PATH, so a command
# resolves to the wrapper executable, which execs `safe gate <tool>`. Nothing
# is sourced into the shell — that is the point of the port, and running the
# script under `zsh -fc` proves the gate no longer depends on shell state.
run_zsh() {
  (
    cd "${WORK_DIR}" || exit 99
    ROOT_DIR="${ROOT_DIR}" \
    HOME="${SAFE_INSTALL_HOME:-${HOME_DIR}}" \
    PATH="${WRAPPER_DIR}:${BIN_DIR}:/usr/bin:/bin" \
    SAFE_AUDIT_PATH="${BIN_DIR}/safe-audit" \
    SAFE_INSTALL_COMMAND_LOG="${LOG_FILE}" \
    SAFE_INSTALL_TEST_SCRIPT="${SAFE_INSTALL_TEST_SCRIPT:-}" \
    SAFE_AUDIT_SCAN_OUTPUT="${SAFE_AUDIT_SCAN_OUTPUT:-}" \
    SAFE_AUDIT_SCAN_STATUS="${SAFE_AUDIT_SCAN_STATUS:-}" \
    SAFE_AUDIT_SCAN_CRITICAL="${SAFE_AUDIT_SCAN_CRITICAL:-}" \
    SAFE_AUDIT_SCAN_VERDICT="${SAFE_AUDIT_SCAN_VERDICT:-}" \
    SAFE_AUDIT_SCAN_TOOL_STATUS="${SAFE_AUDIT_SCAN_TOOL_STATUS:-}" \
    SAFE_AUDIT_SCAN_ECOSYSTEM_AUDITS="${SAFE_AUDIT_SCAN_ECOSYSTEM_AUDITS:-}" \
    SAFE_AUDIT_SCAN_NO_RESULT="${SAFE_AUDIT_SCAN_NO_RESULT:-}" \
    SAFE_AUDIT_CHECK_STATUS="${SAFE_AUDIT_CHECK_STATUS:-}" \
    SAFE_AUDIT_CHECK_SLEEP="${SAFE_AUDIT_CHECK_SLEEP:-}" \
    SAFE_AUDIT_CHECK_TRAP_TERM="${SAFE_AUDIT_CHECK_TRAP_TERM:-}" \
    SAFE_AUDIT_SOCKET_TIMEOUT="${SAFE_AUDIT_SOCKET_TIMEOUT:-}" \
    SAFE_AUDIT_SOCKET_FRESH_SCAN_TIMEOUT="${SAFE_AUDIT_SOCKET_FRESH_SCAN_TIMEOUT:-}" \
    SAFE_INSTALL_TIMEOUT_SECONDS="${SAFE_INSTALL_TIMEOUT_SECONDS:-}" \
    SAFE_INSTALL_REAL_STATUS="${SAFE_INSTALL_REAL_STATUS:-}" \
    COMPOSER_HOME="${COMPOSER_HOME:-}" \
    APPDATA="${APPDATA:-}" \
    OS="${OS:-}" \
    SAFE_INSTALL_COMPOSER_HOME_UNSET="${SAFE_INSTALL_COMPOSER_HOME_UNSET:-}" \
    SAFE_AUDIT_EXPECT_PROJECT="${SAFE_AUDIT_EXPECT_PROJECT:-}" \
    SAFE_AUDIT_EXPECT_PROJECTS="${SAFE_AUDIT_EXPECT_PROJECTS:-}" \
    SAFE_AUDIT_SCAN_CRITICAL_PROJECT="${SAFE_AUDIT_SCAN_CRITICAL_PROJECT:-}" \
    NPM_LOCK_MUTATION_JSON="${NPM_LOCK_MUTATION_JSON:-}" \
    NPM_CONFIG_PACKAGE_LOCK="${NPM_CONFIG_PACKAGE_LOCK:-}" \
    npm_config_package_lock="${npm_config_package_lock:-}" \
    NPM_CONFIG_IGNORE_SCRIPTS="${NPM_CONFIG_IGNORE_SCRIPTS:-}" \
    npm_config_ignore_scripts="${npm_config_ignore_scripts:-}" \
    NPM_LOCKDIFF_EFFECTIVE_CONFIG_JSON="${NPM_LOCKDIFF_EFFECTIVE_CONFIG_JSON:-}" \
    NPM_LOCKDIFF_REGISTRY_CONFIG_JSON="${NPM_LOCKDIFF_REGISTRY_CONFIG_JSON:-}" \
    NPM_LOCKDIFF_CONFIG_STATUS="${NPM_LOCKDIFF_CONFIG_STATUS:-}" \
    MISE_LS_JSON="${MISE_LS_JSON:-}" \
    "${ZSH_BIN}" -fc '[[ "${SAFE_INSTALL_COMPOSER_HOME_UNSET:-0}" == 1 ]] && unset COMPOSER_HOME; eval "${SAFE_INSTALL_TEST_SCRIPT}"'
  ) >"${OUT_FILE}" 2>"${ERR_FILE}"
  STATUS=$?
}

assert_status() {
  local expected="$1"
  local label="$2"
  if [[ "${STATUS}" -ne "${expected}" ]]; then
    printf 'expected status %s, got %s\n' "${expected}" "${STATUS}" >&2
    printf 'stdout:\n%s\n' "$(cat "${OUT_FILE}")" >&2
    printf 'stderr:\n%s\n' "$(cat "${ERR_FILE}")" >&2
    fail "${label}"
    return 1
  fi
  return 0
}

assert_log_contains() {
  local needle="$1"
  local label="$2"
  if ! grep -Fqx "${needle}" "${LOG_FILE}"; then
    printf 'missing log line: %s\n' "${needle}" >&2
    printf 'log:\n%s\n' "$(cat "${LOG_FILE}")" >&2
    fail "${label}"
    return 1
  fi
  return 0
}

# The preflight scan carries a private --result-out path, so its argv cannot
# be matched whole; the parts that are contractual are the mode flags and the
# project target.
assert_project_scan_logged() {
  local label="$1"
  local line
  line="$(grep -F $'AUDIT\tscan\t' "${LOG_FILE}" | tail -n 1)"
  if [[ "${line}" != *$'--deps-only'* || "${line}" != *$'--allow-missing-tools'* || "${line}" != *$'--project\t.'* ]]; then
    printf 'project scan not logged with the expected flags; got: %s\n' "${line:-<none>}" >&2
    printf 'log:\n%s\n' "$(cat "${LOG_FILE}")" >&2
    fail "${label}"
    return 1
  fi
  return 0
}

assert_scan_targets_logged() {
  local label="$1" target
  shift
  for target in "$@"; do
    assert_log_contains $'AUDITPROJECT\t'"${target}" "${label}" || return
  done
}

assert_log_not_contains_fragment() {
  local fragment="$1"
  local label="$2"
  if grep -Fq "${fragment}" "${LOG_FILE}"; then
    printf 'unexpected log fragment: %s\n' "${fragment}" >&2
    printf 'log:\n%s\n' "$(cat "${LOG_FILE}")" >&2
    fail "${label}"
    return 1
  fi
  return 0
}

assert_count() {
  local expected="$1"
  local pattern="$2"
  local file="$3"
  local label="$4"
  local count
  count="$(grep -Fxc "${pattern}" "${file}" || true)"
  if [[ "${count}" != "${expected}" ]]; then
    printf 'expected %s occurrences of %s in %s, got %s\n' "${expected}" "${pattern}" "${file}" "${count}" >&2
    fail "${label}"
    return 1
  fi
  return 0
}

assert_err_contains_fragment() {
  local fragment="$1"
  local label="$2"
  if ! grep -Fq "${fragment}" "${ERR_FILE}"; then
    printf 'missing stderr fragment: %s\n' "${fragment}" >&2
    printf 'stderr:\n%s\n' "$(cat "${ERR_FILE}")" >&2
    fail "${label}"
    return 1
  fi
  return 0
}

assert_err_not_contains_fragment() {
  local fragment="$1"
  local label="$2"
  if grep -Fq "${fragment}" "${ERR_FILE}"; then
    printf 'unexpected stderr fragment: %s\n' "${fragment}" >&2
    printf 'stderr:\n%s\n' "$(cat "${ERR_FILE}")" >&2
    fail "${label}"
    return 1
  fi
  return 0
}

skip_lockdiff_case() {
  local label="$1"
  if [[ "${SAFE_CORE_TEST_AVAILABLE}" == "1" ]]; then
    return 0
  fi
  printf 'ok - %s # SKIP: Go is unavailable; safe-core lockdiff is not built\n' "${label}"
  PASS_COUNT=$((PASS_COUNT + 1))
  return 1
}

# The degraded-mode cases that used to live here (STRIP_HELPERS: a shell
# snapshot keeping the public wrapper functions while stripping the
# safe_install_* helpers) are gone with the zsh functions themselves. An
# executable wrapper cannot be half-loaded: it either exists on PATH and execs
# `safe gate`, or it does not exist and the tool is simply ungated. The
# remaining failure mode with the same shape — the gate routing tables being
# unavailable — is covered by case_gate_lib_missing_fails_closed below.

case_gate_lib_missing_fails_closed() {
  prepare_case "gate-lib-missing-fails-closed"
  # `safe` resolving to a copy outside the repo (no ../lib/gate-lib.sh, no
  # ~/.config/safe/gate-lib.sh) must refuse legibly, never delegate unaudited.
  rm -f "${BIN_DIR}/safe"
  cp "${ROOT_DIR}/bin/safe" "${BIN_DIR}/safe"
  chmod +x "${BIN_DIR}/safe"
  SAFE_INSTALL_TEST_SCRIPT='npm install -g left-pad' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_err_contains_fragment 'safe: BLOCKED npm' "$FUNCNAME" || return
  assert_err_contains_fragment 'safe explain' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm' "$FUNCNAME" || return
  assert_err_not_contains_fragment 'command not found' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_wrapper_passthrough_is_cheap() {
  prepare_case "wrapper-passthrough-is-cheap"
  # Perf guard: a non-gated command must reach the real tool with zero audit
  # invocations. Timed without the zsh layer, so it measures the wrapper path
  # itself (wrapper -> bin/safe -> gate-lib -> exec).
  local start end elapsed
  start="$(date +%s%N)"
  (
    cd "${WORK_DIR}" || exit 99
    HOME="${HOME_DIR}" \
    PATH="${WRAPPER_DIR}:${BIN_DIR}:/usr/bin:/bin" \
    SAFE_AUDIT_PATH="${BIN_DIR}/safe-audit" \
    SAFE_INSTALL_COMMAND_LOG="${LOG_FILE}" \
    "${WRAPPER_DIR}/npm" --version
  ) >"${OUT_FILE}" 2>"${ERR_FILE}"
  STATUS=$?
  end="$(date +%s%N)"
  elapsed=$(( (end - start) / 1000000 ))
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\t--version' "$FUNCNAME" || return
  printf '# passthrough wall time: %s ms\n' "${elapsed}"
  pass "$FUNCNAME"
}

case_refusal_message_contract() {
  prepare_case "refusal-message-contract"
  SAFE_INSTALL_TEST_SCRIPT='npm install -g warnme@1.0.0' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_err_contains_fragment 'safe: BLOCKED npm install of warnme@1.0.0' "$FUNCNAME" || return
  assert_err_contains_fragment 'safe run host-allow add warnme@1.0.0 --reason' "$FUNCNAME" || return
  assert_err_contains_fragment 'safe explain' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_exec_fetch_audits() {
  prepare_case "npm-exec-fetch-audits"
  SAFE_INSTALL_TEST_SCRIPT='npm exec create-foo' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tcreate-foo\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\texec\tcreate-foo' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_exec_local_bin_passthrough() {
  prepare_case "npm-exec-local-bin-passthrough"
  mkdir -p "${WORK_DIR}/node_modules/.bin"
  printf '#!/bin/sh\n' > "${WORK_DIR}/node_modules/.bin/eslint"
  chmod +x "${WORK_DIR}/node_modules/.bin/eslint"
  # Bare name with a matching local bin: no fetch, passthrough.
  SAFE_INSTALL_TEST_SCRIPT='npm exec eslint' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\texec\teslint' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_exec_versioned_spec_audits_despite_local_bin() {
  prepare_case "npm-exec-versioned-spec-audits-despite-local-bin"
  mkdir -p "${WORK_DIR}/node_modules/.bin"
  printf '#!/bin/sh\n' > "${WORK_DIR}/node_modules/.bin/blockme"
  chmod +x "${WORK_DIR}/node_modules/.bin/blockme"
  # A versioned/aliased spec can still fetch remotely even with a same-named
  # local bin, so it must be audited (review High 1).
  SAFE_INSTALL_TEST_SCRIPT='npm exec blockme@latest' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm' "$FUNCNAME" || return
  SAFE_INSTALL_TEST_SCRIPT='bun x blockme@1.2.3' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme@1.2.3\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall\t--installer\tbun' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_exec_hoisted_parent_bin_passthrough() {
  prepare_case "npm-exec-hoisted-parent-bin-passthrough"
  # Hoisted monorepo: the bin lives at the workspace root, the command runs
  # from a workspace subdirectory (agentrh envsub shape, PR #19 parity).
  mkdir -p "${WORK_DIR}/node_modules/.bin" "${WORK_DIR}/apps/web"
  printf '#!/bin/sh\n' > "${WORK_DIR}/node_modules/.bin/envsub"
  chmod +x "${WORK_DIR}/node_modules/.bin/envsub"
  SAFE_INSTALL_TEST_SCRIPT='cd apps/web && npm exec envsub' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\texec\tenvsub' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_exec_parent_walk_resists_shadowing() {
  prepare_case "npm-exec-parent-walk-resists-shadowing"
  # Shadowed pwd/dirname must not steer the walk into an attacker tree: with
  # no real local bin anywhere in the physical ancestry, the bare name is
  # still audited (and blocked here) despite the attacker-planted bin.
  # Two shadowing vectors now: shell functions in the calling shell (which the
  # gate process no longer inherits at all), and a bash exported-function env
  # var, which the gate process DOES import — `builtin pwd -P` defeats both.
  mkdir -p "${WORK_DIR}/attacker/node_modules/.bin" "${WORK_DIR}/victim"
  printf '#!/bin/sh\n' > "${WORK_DIR}/attacker/node_modules/.bin/blockme"
  chmod +x "${WORK_DIR}/attacker/node_modules/.bin/blockme"
  SAFE_INSTALL_TEST_SCRIPT='
    cd victim
    pwd() { print -r -- "'"${WORK_DIR}"'/attacker"; }
    dirname() { print -r -- "'"${WORK_DIR}"'/attacker"; }
    npm exec blockme
  ' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm' "$FUNCNAME" || return
  SAFE_INSTALL_TEST_SCRIPT='
    cd victim
    env "BASH_FUNC_pwd%%=() { echo '"${WORK_DIR}"'/attacker; }" npm exec blockme
  ' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_pnpx_audits_like_dlx() {
  prepare_case "pnpx-audits-like-dlx"
  # pnpx is pnpm dlx with the subcommand implied: same exec gate, same tables.
  SAFE_INSTALL_TEST_SCRIPT='pnpx cowsay@1.6.0' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tcowsay@1.6.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_contains $'REAL\tpnpx\tcowsay@1.6.0' "$FUNCNAME" || return
  SAFE_INSTALL_TEST_SCRIPT='pnpx blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tpnpx\tblockme' "$FUNCNAME" || return
  SAFE_INSTALL_TEST_SCRIPT='pnpx --package blockme benign' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_leading_global_flag_gates_npm_install() {
  prepare_case "leading-global-flag-gates-npm-install"
  # The inbox bypass: a leading global flag made the subcommand read as the
  # flag, so `install` slipped the gate. =form and space-form both gate now.
  SAFE_INSTALL_TEST_SCRIPT='npm --loglevel=error install -g blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm' "$FUNCNAME" || return
  SAFE_INSTALL_TEST_SCRIPT='npm --loglevel error install -g blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_leading_global_flag_gates_pnpm_dlx() {
  prepare_case "leading-global-flag-gates-pnpm-dlx"
  SAFE_INSTALL_TEST_SCRIPT='pnpm --filter=web dlx blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tpnpm' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_leading_global_flag_gates_yarn_add() {
  prepare_case "leading-global-flag-gates-yarn-add"
  # The verbatim inbox shape: yarn --cwd <dir> add <pkg>. The --cwd value is
  # the effective project dir and must reach resolution (review finding 3).
  SAFE_INSTALL_TEST_SCRIPT='yarn --cwd sub add blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall\t--project-dir\tsub' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tyarn' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_leading_global_flag_gates_uv_tool_run() {
  prepare_case "leading-global-flag-gates-uv-tool-run"
  SAFE_INSTALL_TEST_SCRIPT='uv --offline tool run blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tpython\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tuv' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_value_flag_consumes_its_value() {
  prepare_case "value-flag-consumes-its-value"
  # A known value-taking leading flag must skip its value so the real
  # subcommand is still found. `install` here happens to also be a plausible
  # value; the resolver must not stop on it.
  SAFE_INSTALL_TEST_SCRIPT='npm --registry https://r.example install -g blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall\t--registry\thttps://r.example' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_doctor_podman_probe_skips_exec_under_no_new_privs() {
  prepare_case "doctor-podman-nnp"
  if ! command -v setpriv >/dev/null 2>&1; then
    pass "$FUNCNAME (setpriv unavailable — sandbox probe not exercised)"
    return
  fi
  # Exec'ing podman from a no-new-privs process draws one SELinux AVC per
  # attempt on enforcing hosts and reads as broken; the sandboxed probe must
  # answer from PATH lookup alone. The stub logs any invocation.
  local bindir="${HOME_DIR}/stub-bin"
  mkdir -p "${bindir}"
  printf '#!/usr/bin/env bash\nprintf "%%s\\n" "$*" >> "%s/podman-invocations.log"\nprintf "podman version 5.0.0\\n"\n' \
    "${HOME_DIR}" > "${bindir}/podman"
  chmod +x "${bindir}/podman"
  local doctor_out
  doctor_out="$(setpriv --no-new-privs env HOME="${HOME_DIR}" PATH="${bindir}:/usr/bin:/bin" \
    bash "${ROOT_DIR}/bin/safe" doctor --json 2>/dev/null)"
  jq -e '.dependencies.sandbox.podman.present == true
    and .dependencies.sandbox.podman.probed == false
    and (.dependencies.sandbox.podman.note | test("no-new-privs"))' \
    <<<"${doctor_out}" >/dev/null || { printf '%s\n' "${doctor_out}" >&2; fail "$FUNCNAME"; return; }
  if [[ -f "${HOME_DIR}/podman-invocations.log" ]]; then
    cat "${HOME_DIR}/podman-invocations.log" >&2
    fail "$FUNCNAME"
    return
  fi
  # The default human output must carry the same disclosure — a bare
  # "sandbox: ready" from a process that cannot exec podman misleads
  # (review PR#62 F1) — and must not list podman as missing.
  local doctor_human
  doctor_human="$(setpriv --no-new-privs env HOME="${HOME_DIR}" PATH="${bindir}:/usr/bin:/bin" \
    bash "${ROOT_DIR}/bin/safe" doctor 2>/dev/null)"
  grep -Fq 'podman present but unprobed' <<<"${doctor_human}" \
    || { printf '%s\n' "${doctor_human}" >&2; fail "$FUNCNAME"; return; }
  grep -A2 'missing prerequisites:' <<<"${doctor_human}" | grep -Fq 'podman' \
    && { printf '%s\n' "${doctor_human}" >&2; fail "$FUNCNAME"; return; }
  # Outside a sandbox the version probe still runs and no caveat renders.
  doctor_out="$(env HOME="${HOME_DIR}" PATH="${bindir}:/usr/bin:/bin" \
    bash "${ROOT_DIR}/bin/safe" doctor --json 2>/dev/null)"
  jq -e '.dependencies.sandbox.podman.version == "podman version 5.0.0"' \
    <<<"${doctor_out}" >/dev/null || { printf '%s\n' "${doctor_out}" >&2; fail "$FUNCNAME"; return; }
  doctor_human="$(env HOME="${HOME_DIR}" PATH="${bindir}:/usr/bin:/bin" \
    bash "${ROOT_DIR}/bin/safe" doctor 2>/dev/null)"
  grep -Fq 'podman present but unprobed' <<<"${doctor_human}" \
    && { printf '%s\n' "${doctor_human}" >&2; fail "$FUNCNAME"; return; }
  pass "$FUNCNAME"
}

case_uv_python_selector_not_a_package() {
  prepare_case "uv-python-selector-not-a-package"
  # --python/-p selects an interpreter; its value ("3.12") must never be
  # collected as a package spec — that produced a false unresolvable-package
  # refusal on `uv tool install exampletool==3.1.0 --python 3.12` (live
  # 2026-08-03). The real package must still be audited.
  SAFE_INSTALL_TEST_SCRIPT='uv tool install --python 3.12 okpkg==1.0.0' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tokpkg@1.0.0\t--ecosystem\tpython\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'AUDIT\tcheck\t3.12' "$FUNCNAME" || return
  SAFE_INSTALL_TEST_SCRIPT='uv tool install okpkg==1.0.0 --python 3.12' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment $'AUDIT\tcheck\t3.12' "$FUNCNAME" || return
  SAFE_INSTALL_TEST_SCRIPT='uv tool install --python=3.12 -p 3.12 okpkg==1.0.0' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment $'AUDIT\tcheck\t3.12' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_unknown_leading_flag_fails_closed() {
  prepare_case "unknown-leading-flag-fails-closed"
  # An unrecognized space-form leading flag is ambiguous → refuse (exit 100),
  # never silently pass the command through unaudited.
  SAFE_INSTALL_TEST_SCRIPT='npm --totally-unknown-flag value install -g blockme' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_err_contains_fragment 'cannot find the subcommand' "$FUNCNAME" || return
  assert_err_contains_fragment 'safe explain' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_unknown_leading_flag_eqform_escapes() {
  prepare_case "unknown-leading-flag-eqform-escapes"
  # The =form of an unknown flag is unambiguous → the gate proceeds and the
  # real install is still audited.
  SAFE_INSTALL_TEST_SCRIPT='npm --totally-unknown-flag=value install -g blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_leading_flag_benign_command_passes() {
  prepare_case "leading-flag-benign-command-passes"
  # A non-gated subcommand behind a known leading flag still passes through.
  SAFE_INSTALL_TEST_SCRIPT='npm --loglevel=error run build' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\t--loglevel=error\trun\tbuild' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_optional_boolean_explicit_value_gates() {
  prepare_case "optional-boolean-explicit-value-gates"
  # npm/pnpm config booleans accept an explicit space-form true/false
  # (npm --global false install ...). The value must be consumed so the real
  # subcommand is still found and gated (review round 1 High 1/High 3).
  SAFE_INSTALL_TEST_SCRIPT='npm --global false install blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm' "$FUNCNAME" || return
  SAFE_INSTALL_TEST_SCRIPT='npm --workspaces false install blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  SAFE_INSTALL_TEST_SCRIPT='pnpm --recursive false add blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_optional_boolean_without_value_still_gates() {
  prepare_case "optional-boolean-without-value-still-gates"
  # The common form (no explicit value): the subcommand directly follows the
  # boolean flag and must not be consumed as a value.
  SAFE_INSTALL_TEST_SCRIPT='npm --global install blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_pnpm_config_switch_not_value() {
  prepare_case "pnpm-config-switch-not-value"
  # --config is a no-value switch on `pnpm add`; misclassifying it as a value
  # flag ate the `add` subcommand and bypassed the gate (review round 1 High 2).
  SAFE_INSTALL_TEST_SCRIPT='pnpm --config add blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tpnpm' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_pip_use_feature_takes_value() {
  prepare_case "pip-use-feature-takes-value"
  # --use-feature takes a value; misclassifying it as boolean exposed the
  # value as the subcommand and bypassed the gate (review round 1 High 4).
  SAFE_INSTALL_TEST_SCRIPT='pip --use-feature fast-deps install blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tpython\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tpip' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_bun_equals_only_flag_not_space_value() {
  prepare_case "bun-equals-only-flag-not-space-value"
  # bun --config/--cwd/-c are equals-only; the space form must not be treated
  # as a value flag (it would eat the subcommand). =form still works; bare
  # space form fails closed (review round 2 High).
  SAFE_INSTALL_TEST_SCRIPT='bun --config add blockme' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_err_contains_fragment 'cannot find the subcommand' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tbun' "$FUNCNAME" || return
  # The =form parses cleanly but swaps in a bunfig.toml whose
  # install.registry can redirect the source — per-invocation config
  # injection fails closed rather than earning a default-source verdict
  # (same class as cargo --config).
  SAFE_INSTALL_TEST_SCRIPT='bun --config=bunfig.toml add blockme' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tbun' "$FUNCNAME" || return
  assert_err_contains_fragment 'bunfig.toml' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_exec_package_flag_blocks() {
  prepare_case "npm-exec-package-flag-blocks"
  SAFE_INSTALL_TEST_SCRIPT='npm exec --package=blockme -- create' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_exec_value_flag_does_not_hide_package() {
  prepare_case "exec-value-flag-does-not-hide-package"
  # A known value-taking flag before the command must not be mistaken for the
  # package; the real fetched package is audited (review High 2).
  SAFE_INSTALL_TEST_SCRIPT='npm exec --cache /tmp/cache-ok blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm' "$FUNCNAME" || return
  SAFE_INSTALL_TEST_SCRIPT='pnpm dlx --allow-build ok-builder blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tpnpm' "$FUNCNAME" || return
  # =form is unambiguous and must not over-refuse.
  SAFE_INSTALL_TEST_SCRIPT='npm exec --cache=/tmp/cache-ok cowsay' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tcowsay\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_exec_unknown_flag_fails_closed() {
  prepare_case "exec-unknown-flag-fails-closed"
  # An unrecognized space-form flag before the command is ambiguous → refuse,
  # never guess and let the real package fetch unaudited.
  SAFE_INSTALL_TEST_SCRIPT='npm exec --frobnicate val blockme' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_err_contains_fragment 'unrecognized option' "$FUNCNAME" || return
  assert_err_contains_fragment 'safe explain' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_exec_package_selector_flags() {
  prepare_case "exec-package-selector-flags"
  # --package selects the fetched package; the positional is the command it
  # provides and must not shadow it (re-review High 1/2).
  SAFE_INSTALL_TEST_SCRIPT='pnpm dlx --package blockme benign' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tpnpm' "$FUNCNAME" || return
  SAFE_INSTALL_TEST_SCRIPT='bun x --package=blockme benign' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tbun' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_exec_boolean_flags_do_not_eat_package() {
  prepare_case "exec-boolean-flags-do-not-eat-package"
  # A boolean flag must not consume the following package as its value
  # (re-review High 1/3): the package still audits.
  SAFE_INSTALL_TEST_SCRIPT='pnpm dlx -c blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tpnpm' "$FUNCNAME" || return
  SAFE_INSTALL_TEST_SCRIPT='yarn dlx -q blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tyarn' "$FUNCNAME" || return
  # Documented booleans pass through without over-refusing (re-review Med 1).
  SAFE_INSTALL_TEST_SCRIPT='npm exec --workspaces cowsay' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tcowsay\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  SAFE_INSTALL_TEST_SCRIPT='bun x --verbose cowsay' run_zsh
  assert_status 0 "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_exec_post_positional_package() {
  prepare_case "npm-exec-post-positional-package"
  # npm's config parser is greedy: --package after the command still selects
  # the fetched package (round-3 High 1).
  SAFE_INSTALL_TEST_SCRIPT='npm exec benign --package blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm' "$FUNCNAME" || return
  SAFE_INSTALL_TEST_SCRIPT='npm exec benign --package=blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  # Even with a local bin as the command, a later --package is still audited.
  mkdir -p "${WORK_DIR}/node_modules/.bin"
  printf '#!/bin/sh\n' > "${WORK_DIR}/node_modules/.bin/eslint"
  chmod +x "${WORK_DIR}/node_modules/.bin/eslint"
  SAFE_INSTALL_TEST_SCRIPT='npm exec eslint --package blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  # The command's own flags after the command are ignored, not failed closed.
  SAFE_INSTALL_TEST_SCRIPT='npm exec eslint --fix src' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\texec\teslint\t--fix\tsrc' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_exec_short_p_not_greedy_post_command() {
  prepare_case "npm-exec-short-p-not-greedy-post-command"
  # Short -p is NOT greedy post-command in real npm, so a trailing -p value
  # must not shadow the actual fetched positional package (round-4 High 1).
  SAFE_INSTALL_TEST_SCRIPT='npm exec blockme -p okpkg' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm' "$FUNCNAME" || return
  # -p before the command IS a selector (audited); okpkg is the command.
  SAFE_INSTALL_TEST_SCRIPT='npm exec -p blockme okpkg' run_zsh
  assert_status 104 "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_uv_with_requirements_refused() {
  prepare_case "uv-with-requirements-refused"
  # A requirements file names packages we can't vet inline → fail closed
  # (round-3 High 2), healthy and degraded.
  SAFE_INSTALL_TEST_SCRIPT='uv run --with-requirements req.txt python' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_err_contains_fragment 'with-requirements' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tuv' "$FUNCNAME" || return
  SAFE_INSTALL_TEST_SCRIPT='uv tool run --with-requirements=req.txt ruff' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tuv' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_dlx_and_x_audit() {
  prepare_case "dlx-and-x-audit"
  SAFE_INSTALL_TEST_SCRIPT='pnpm dlx cowsay@1.6.0' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tcowsay@1.6.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_contains $'REAL\tpnpm\tdlx\tcowsay@1.6.0' "$FUNCNAME" || return
  SAFE_INSTALL_TEST_SCRIPT='bun x cowsay' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tcowsay\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall\t--installer\tbun' "$FUNCNAME" || return
  assert_log_contains $'REAL\tbun\tx\tcowsay' "$FUNCNAME" || return
  SAFE_INSTALL_TEST_SCRIPT='yarn dlx blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tyarn' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_uv_run_and_tool_run_gate() {
  prepare_case "uv-run-and-tool-run-gate"
  SAFE_INSTALL_TEST_SCRIPT='uv run --with warnme script.py' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\twarnme\t--ecosystem\tpython\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tuv' "$FUNCNAME" || return
  SAFE_INSTALL_TEST_SCRIPT='uv run script.py' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'REAL\tuv\trun\tscript.py' "$FUNCNAME" || return
  SAFE_INSTALL_TEST_SCRIPT='uv tool run ruff' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\truff\t--ecosystem\tpython\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  SAFE_INSTALL_TEST_SCRIPT='uv tool run --from blockme r' run_zsh
  assert_status 104 "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_uv_short_with_and_boundary() {
  prepare_case "uv-short-with-and-boundary"
  # -w is the short --with and must be audited (review High 3).
  SAFE_INSTALL_TEST_SCRIPT='uv run -w blockme script.py' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tpython\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tuv' "$FUNCNAME" || return
  # A value flag before --with must not shift the boundary; --with rich audits.
  SAFE_INSTALL_TEST_SCRIPT='uv run --python 3.12 --with rich pytest' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\trich\t--ecosystem\tpython\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_contains $'REAL\tuv\trun\t--python\t3.12\t--with\trich\tpytest' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_uv_run_program_arg_not_audited() {
  prepare_case "uv-run-program-arg-not-audited"
  # --with appearing in the program's own args (after the command) is not a
  # uv fetch and must not be audited (review Medium 2).
  SAFE_INSTALL_TEST_SCRIPT='uv run python -c print --with blockme' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_log_contains $'REAL\tuv\trun\tpython\t-c\tprint\t--with\tblockme' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_uv_tool_run_short_with_keeps_tool() {
  prepare_case "uv-tool-run-short-with-keeps-tool"
  # -w extra must not become the audited package; the tool (blockme) is
  # (review High 4).
  SAFE_INSTALL_TEST_SCRIPT='uv tool run -w ok-extra blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tpython\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tuv' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_uv_tool_run_with_extra_is_audited() {
  prepare_case "uv-tool-run-with-extra-is-audited"
  # --with/-w extras are themselves fetched and must be audited alongside the
  # tool (re-review High 4).
  SAFE_INSTALL_TEST_SCRIPT='uv tool run -w blockme ruff' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tpython\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tuv' "$FUNCNAME" || return
  # Both clean → audited and delegated.
  SAFE_INSTALL_TEST_SCRIPT='uv tool run --with ok ruff' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tok\t--ecosystem\tpython\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\truff\t--ecosystem\tpython\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_uv_run_value_flag_before_with() {
  prepare_case "uv-run-value-flag-before-with"
  # --no-extra takes a value; misclassifying it as boolean would stop the
  # scan early and miss the later --with fetch (re-review High 5).
  SAFE_INSTALL_TEST_SCRIPT='uv run --no-extra dev --with blockme python' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tpython\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tuv' "$FUNCNAME" || return
  # -m is a switch; it must not fail closed (re-review Med 1).
  SAFE_INSTALL_TEST_SCRIPT='uv run -m pytest' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'REAL\tuv\trun\t-m\tpytest' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_go_run_module_gates() {
  prepare_case "go-run-module-gates"
  write_tool_stub "${BIN_DIR}" go
  SAFE_INSTALL_TEST_SCRIPT='go run example.com/blockme@v1.0.0' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\texample.com/blockme@v1.0.0\t--ecosystem\tgo\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tgo' "$FUNCNAME" || return
  SAFE_INSTALL_TEST_SCRIPT='go run ./cmd' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'REAL\tgo\trun\t./cmd' "$FUNCNAME" || return
  assert_count 0 $'AUDIT\tcheck\t./cmd@latest\t--ecosystem\tgo' "${LOG_FILE}" "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_go_run_value_flag_does_not_hide_module() {
  prepare_case "go-run-value-flag-does-not-hide-module"
  write_tool_stub "${BIN_DIR}" go
  # A space-form value build flag must not swallow the remote module target
  # (round-5 High): -C/-mod take values, then the module@version still audits.
  SAFE_INSTALL_TEST_SCRIPT='go run -C /tmp example.com/blockme@v1.0.0' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\texample.com/blockme@v1.0.0\t--ecosystem\tgo\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tgo' "$FUNCNAME" || return
  SAFE_INSTALL_TEST_SCRIPT='go run -mod mod example.com/blockme@v1.0.0' run_zsh
  assert_status 104 "$FUNCNAME" || return
  # Boolean build flags still pass a local run through.
  SAFE_INSTALL_TEST_SCRIPT='go run -race ./cmd' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'REAL\tgo\trun\t-race\t./cmd' "$FUNCNAME" || return
  # An unrecognized dash flag before the target fails closed, not passthrough
  # (status 100 = refused before delegating to the real tool).
  SAFE_INSTALL_TEST_SCRIPT='go run -bogusflag val example.com/x@v1' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_err_contains_fragment 'unrecognized flag' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_update_family_gates() {
  prepare_case "update-family-gates"
  touch "${WORK_DIR}/package.json"
  SAFE_INSTALL_TEST_SCRIPT='npm update lodash' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_project_scan_logged "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tlodash\t--ecosystem\tnpm\t--gate\tinstall\t--op\tupdate' "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tupdate\tlodash' "$FUNCNAME" || return
  SAFE_INSTALL_TEST_SCRIPT='yarn upgrade left-pad' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tleft-pad\t--ecosystem\tnpm\t--gate\tinstall\t--op\tupdate' "$FUNCNAME" || return
  SAFE_INSTALL_TEST_SCRIPT='npm u blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  # npm ships `udpate` as a real alias of update (review Medium 1).
  SAFE_INSTALL_TEST_SCRIPT='npm udpate blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tupdate' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_abbreviation_classifier_gates_and_preserves_argv() {
  prepare_case "npm-abbreviation-classifier"

  # `inst` is a hardcoded npm alias. The check and the real delegate must both
  # see the operation, while the delegate retains the operator's spelling.
  SAFE_INSTALL_TEST_SCRIPT='npm inst okpkg' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tokpkg\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tinst\tokpkg' "$FUNCNAME" || return

  # The block canary proves an abbreviated install cannot delegate unaudited.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='npm inst blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm\tinst\tblockme' "$FUNCNAME" || return

  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='npm updat okpkg' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tokpkg\t--ecosystem\tnpm\t--gate\tinstall\t--op\tupdate' "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tupdat\tokpkg' "$FUNCNAME" || return

  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='npm exe blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm\texe\tblockme' "$FUNCNAME" || return

  # `in` is a short explicit install alias, while `d` is not a length-one
  # match and stays a passthrough for npm to reject or handle itself.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='npm in okpkg' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tokpkg\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tin\tokpkg' "$FUNCNAME" || return
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='npm d blockme' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\td\tblockme' "$FUNCNAME" || return

  pass "$FUNCNAME"
}

case_npm_alias_prefixes_and_priority() {
  prepare_case "npm-alias-prefixes-and-priority"
  touch "${WORK_DIR}/package.json"

  # Generic npm prefixes include alias keys: `ad` -> add -> install.
  SAFE_INSTALL_TEST_SCRIPT='npm ad okpkg' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tokpkg\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tad\tokpkg' "$FUNCNAME" || return

  # install-clean is itself an alias. Its prefix must take the no-package ci
  # lane, scan the project, and preserve the original token for npm.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='npm install-cl' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_project_scan_logged "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tinstall-cl' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'AUDIT\tcheck' "$FUNCNAME" || return

  for token in cit clean-install isntall; do
    : > "${LOG_FILE}"
    SAFE_INSTALL_TEST_SCRIPT="npm ${token}" run_zsh
    assert_status 0 "$FUNCNAME" || return
    assert_project_scan_logged "$FUNCNAME" || return
    assert_log_contains $'REAL\tnpm\t'"${token}" "$FUNCNAME" || return
    assert_log_not_contains_fragment $'AUDIT\tcheck' "$FUNCNAME" || return
  done

  # Exact aliases outrank a gated prefix: c -> config and un -> uninstall.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='npm c get registry' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tc\tget\tregistry' "$FUNCNAME" || return
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='npm un blockme' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tun\tblockme' "$FUNCNAME" || return

  # Ambiguous npm spellings may be conservatively routed. A clean path keeps
  # original argv for the real command; a gated-looking ambiguity may instead
  # be refused before delegation.
  for token in is ex cl; do
    : > "${LOG_FILE}"
    SAFE_INSTALL_REAL_STATUS=1 SAFE_INSTALL_TEST_SCRIPT="npm ${token}" run_zsh
    assert_status 1 "$FUNCNAME" || return
    assert_log_contains $'REAL\tnpm\t'"${token}" "$FUNCNAME" || return
  done
  unset SAFE_INSTALL_REAL_STATUS

  pass "$FUNCNAME"
}

case_npm_camelcase_dispatch_and_conservative_ambiguity() {
  prepare_case "npm-camelcase-dispatch"
  touch "${WORK_DIR}/package.json"

  # npm normalizes installTest to install-test before dispatch. The canary
  # proves the gate does the same before the real command can fetch it.
  SAFE_INSTALL_TEST_SCRIPT='npm installTest blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm\tinstallTest\tblockme' "$FUNCNAME" || return

  # Hyphenated ci commands also normalize before npm resolves aliases/prefixes;
  # their no-package lane scans and still delegates the original spelling.
  for token in cleanInstall installCiTest; do
    : > "${LOG_FILE}"
    SAFE_INSTALL_TEST_SCRIPT="npm ${token}" run_zsh
    assert_status 0 "$FUNCNAME" || return
    assert_project_scan_logged "$FUNCNAME" || return
    assert_log_contains $'REAL\tnpm\t'"${token}" "$FUNCNAME" || return
    assert_log_not_contains_fragment $'AUDIT\tcheck' "$FUNCNAME" || return
  done

  # distTag normalizes to npm's non-gated dist-tag command and stays a
  # passthrough despite sharing the same camel-case normalization.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='npm distTag latest' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tdistTag\tlatest' "$FUNCNAME" || return

  # `ex` can look like npm exec but npm itself considers it ambiguous. Policy
  # deliberately permits this fail-closed pre-delegation refusal.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='npm ex --bogus' run_zsh
  assert_status 100 "$FUNCNAME" || return
  [[ "$(wc -l < "${ERR_FILE}")" -eq 1 ]] || { cat "${ERR_FILE}" >&2; fail "$FUNCNAME"; return 1; }
  assert_log_not_contains_fragment $'REAL\tnpm\tex' "$FUNCNAME" || return

  pass "$FUNCNAME"
}

case_non_npm_abbreviations_stay_passthrough() {
  prepare_case "non-npm-abbreviations-passthrough"
  SAFE_INSTALL_TEST_SCRIPT='pnpm inst blockme' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_log_contains $'REAL\tpnpm\tinst\tblockme' "$FUNCNAME" || return
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='yarn ad blockme' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_log_contains $'REAL\tyarn\tad\tblockme' "$FUNCNAME" || return
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='bun inst blockme' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_log_contains $'REAL\tbun\tinst\tblockme' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_composer_canonical_or_refuse() {
  prepare_case "composer-canonical-or-refuse"
  touch "${WORK_DIR}/composer.json"
  local token command args

  # Only the three canonical top-level gated spellings audit and delegate.
  for token in install update Update; do
    : > "${LOG_FILE}"
    SAFE_INSTALL_TEST_SCRIPT="composer ${token}" run_zsh
    assert_status 0 "$FUNCNAME" || return
    assert_project_scan_logged "$FUNCNAME" || return
    assert_log_contains $'REAL\tcomposer\t'"${token}" "$FUNCNAME" || return
  done
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='composer require vendor/okpkg:^1' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tvendor/okpkg@^1\t--ecosystem\tcomposer\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_contains $'REAL\tcomposer\trequire\tvendor/okpkg:^1' "$FUNCNAME" || return

  # Symfony retries command matches case-insensitively. Exact built-ins keep
  # their priority, while canonical mixed-case gated names enter the same lane.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='composer Init' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_log_contains $'REAL\tcomposer\tInit' "$FUNCNAME" || return

  # Exact command names always remain dispatchable. `require` gets an
  # explicit package because its intentional interactive zero-package refusal
  # is covered below.
  for command in "${SAFE_GATE_COMPOSER_COMMANDS[@]}"; do
    : > "${LOG_FILE}"
    args="${command}"
    [[ "${command}" == require ]] && args+=' vendor/okpkg:^1'
    SAFE_INSTALL_TEST_SCRIPT="composer ${args}" run_zsh
    assert_status 0 "$FUNCNAME" || return
    assert_log_contains $'REAL\tcomposer\t'"${command}" "$FUNCNAME" || return
  done

  # Composer accepts these aliases and abbreviations itself. Safe refuses
  # every gated-looking one before any scan, package audit, or delegation.
  for token in i u upgrade r in ins up upg upgr upgra upgrad re req requ g gl glo glob globa; do
    : > "${LOG_FILE}"
    SAFE_INSTALL_TEST_SCRIPT="composer ${token} vendor/okpkg:^1" run_zsh
    assert_status 100 "$FUNCNAME" || return
    [[ "$(wc -l < "${ERR_FILE}")" -eq 1 ]] || { cat "${ERR_FILE}" >&2; fail "$FUNCNAME"; return 1; }
    assert_err_contains_fragment 'spell it canonically (composer' "$FUNCNAME" || return
    assert_err_contains_fragment "or, if '${token}' is a project script, run it via composer run-script ${token}" "$FUNCNAME" || return
    assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
    assert_log_not_contains_fragment $'REAL\tcomposer' "$FUNCNAME" || return
  done

  # The same policy applies to the nested command after the exact global
  # proxy. This is still a refusal before global-home resolution or scanning.
  for token in i u upgrade r ins up req requ g globa; do
    : > "${LOG_FILE}"
    SAFE_INSTALL_TEST_SCRIPT="composer global ${token} vendor/okpkg:^1" run_zsh
    assert_status 100 "$FUNCNAME" || return
    [[ "$(wc -l < "${ERR_FILE}")" -eq 1 ]] || { cat "${ERR_FILE}" >&2; fail "$FUNCNAME"; return 1; }
    assert_err_contains_fragment 'spell it canonically (composer global' "$FUNCNAME" || return
    assert_err_contains_fragment "composer global run-script ${token}" "$FUNCNAME" || return
    assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
    assert_log_not_contains_fragment $'REAL\tcomposer' "$FUNCNAME" || return
  done

  # A mixed-case alias and prefix resolve in Symfony but must still fail closed
  # before any gate side effect. The original spelling stays in the script
  # escape hatch so a deliberate project command remains reachable.
  for token in U ReQu gLoBa; do
    : > "${LOG_FILE}"
    SAFE_INSTALL_TEST_SCRIPT="composer ${token} vendor/okpkg:^1" run_zsh
    assert_status 100 "$FUNCNAME" || return
    [[ "$(wc -l < "${ERR_FILE}")" -eq 1 ]] || { cat "${ERR_FILE}" >&2; fail "$FUNCNAME"; return 1; }
    assert_err_contains_fragment "or, if '${token}' is a project script, run it via composer run-script ${token}" "$FUNCNAME" || return
    assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
    assert_log_not_contains_fragment $'REAL\tcomposer' "$FUNCNAME" || return
  done

  # Non-gated command prefixes keep their pre-existing passthrough behavior.
  for token in rei rem; do
    : > "${LOG_FILE}"
    SAFE_INSTALL_TEST_SCRIPT="composer ${token} vendor/blockme" run_zsh
    assert_status 0 "$FUNCNAME" || return
    assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
    assert_log_contains $'REAL\tcomposer\t'"${token}"$'\tvendor/blockme' "$FUNCNAME" || return
  done

  # Interactive package discovery starts after safe's package-audit boundary,
  # so every zero-package require form refuses before project scans/delegation.
  for args in require 'require --no-interaction' 'require --' \
    'global require' 'global require --no-interaction' 'global require --'; do
    : > "${LOG_FILE}"
    SAFE_INSTALL_TEST_SCRIPT="composer ${args}" run_zsh
    assert_status 100 "$FUNCNAME" || return
    [[ "$(wc -l < "${ERR_FILE}")" -eq 1 ]] || { cat "${ERR_FILE}" >&2; fail "$FUNCNAME"; return 1; }
    assert_err_contains_fragment 'specify at least one package explicitly' "$FUNCNAME" || return
    assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
    assert_log_not_contains_fragment $'REAL\tcomposer' "$FUNCNAME" || return
  done

  # RequireCommand's value-taking options are not package operands. They must
  # reach the same zero-package refusal in both top-level and global lanes.
  for command in require 'global require'; do
    for option in --prefer-install --audit-format --ignore-platform-req --apcu-autoloader-prefix; do
      : > "${LOG_FILE}"
      SAFE_INSTALL_TEST_SCRIPT="composer ${command} ${option} vendor/okpkg:^1" run_zsh
      assert_status 100 "$FUNCNAME" || return
      [[ "$(wc -l < "${ERR_FILE}")" -eq 1 ]] || { cat "${ERR_FILE}" >&2; fail "$FUNCNAME"; return 1; }
      assert_err_contains_fragment 'specify at least one package explicitly' "$FUNCNAME" || return
      assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
      assert_log_not_contains_fragment $'REAL\tcomposer' "$FUNCNAME" || return
    done
  done

  for command in require 'global require'; do
    : > "${LOG_FILE}"
    SAFE_INSTALL_TEST_SCRIPT="composer ${command} --audit-format=vendor/okpkg:^1" run_zsh
    assert_status 100 "$FUNCNAME" || return
    assert_err_contains_fragment 'specify at least one package explicitly' "$FUNCNAME" || return
    assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
    assert_log_not_contains_fragment $'REAL\tcomposer' "$FUNCNAME" || return
  done

  # The option terminator changes the boundary: a following token is a real
  # explicit package.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='composer require -- vendor/okpkg:^1' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tvendor/okpkg@^1\t--ecosystem\tcomposer\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_contains $'REAL\tcomposer\trequire\t--\tvendor/okpkg:^1' "$FUNCNAME" || return

  pass "$FUNCNAME"
}

case_composer_global_canonical_routing() {
  prepare_case "composer-global-canonical-routing"
  local global_home="${HOME_DIR}/global-home"
  local default_home="${HOME_DIR}/.composer"
  local ordinary_home="${HOME_DIR}/ordinary-home"
  local before_project="${CASE_DIR}/before-project"
  local between_project="${CASE_DIR}/between-project"
  local after_project="${CASE_DIR}/after-project"
  local first_project="${CASE_DIR}/first-project"
  local second_project="${CASE_DIR}/second-project"
  local equals_project="${CASE_DIR}/equals-project"
  local ignored_project="${CASE_DIR}/ignored-project"
  local unix_home="${CASE_DIR}/unix-home"
  local backslash_home="${unix_home//\//\\}"
  local target args
  for target in "${global_home}" "${default_home}" "${ordinary_home}" \
    "${before_project}" "${between_project}" "${after_project}" \
    "${first_project}" "${second_project}" "${equals_project}" "${ignored_project}" \
    "${unix_home}/.composer"; do
    mkdir -p "${target}"
    touch "${target}/composer.json"
  done

  # Exact global plus canonical nested commands retain the unified preflight,
  # package boundary, and original argv delegation.
  COMPOSER_HOME="${global_home}" SAFE_AUDIT_EXPECT_PROJECTS=1 \
    SAFE_AUDIT_SCAN_CRITICAL_PROJECT="${global_home}" \
    SAFE_INSTALL_TEST_SCRIPT='composer global update' run_zsh
  assert_status 102 "$FUNCNAME" || return
  assert_scan_targets_logged "$FUNCNAME" "${global_home}" || return
  assert_log_not_contains_fragment $'REAL\tcomposer\tglobal\tupdate' "$FUNCNAME" || return

  : > "${LOG_FILE}"
  COMPOSER_HOME="${global_home}" SAFE_AUDIT_EXPECT_PROJECTS=1 \
    SAFE_INSTALL_TEST_SCRIPT='composer global install' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_scan_targets_logged "$FUNCNAME" "${global_home}" || return
  assert_log_contains $'REAL\tcomposer\tglobal\tinstall' "$FUNCNAME" || return

  : > "${LOG_FILE}"
  COMPOSER_HOME="${global_home}" SAFE_AUDIT_EXPECT_PROJECTS=1 \
    SAFE_INSTALL_TEST_SCRIPT='composer global require vendor/okpkg:^1' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_scan_targets_logged "$FUNCNAME" "${global_home}" || return
  assert_log_contains $'AUDIT\tcheck\tvendor/okpkg@^1\t--ecosystem\tcomposer\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_contains $'REAL\tcomposer\tglobal\trequire\tvendor/okpkg:^1' "$FUNCNAME" || return

  : > "${LOG_FILE}"
  COMPOSER_HOME="${global_home}" SAFE_AUDIT_EXPECT_PROJECTS=1 \
    SAFE_INSTALL_TEST_SCRIPT='composer global Require vendor/okpkg:^1' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_scan_targets_logged "$FUNCNAME" "${global_home}" || return
  assert_log_contains $'AUDIT\tcheck\tvendor/okpkg@^1\t--ecosystem\tcomposer\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_contains $'REAL\tcomposer\tglobal\tRequire\tvendor/okpkg:^1' "$FUNCNAME" || return

  # Factory uses PHP truthiness: unset, empty, and literal "0" select the
  # platform home, while an ordinary COMPOSER_HOME selects itself.
  : > "${LOG_FILE}"
  COMPOSER_HOME='0' SAFE_AUDIT_EXPECT_PROJECTS=1 \
    SAFE_AUDIT_SCAN_CRITICAL_PROJECT="${default_home}" \
    SAFE_INSTALL_TEST_SCRIPT='composer global update' run_zsh
  assert_status 102 "$FUNCNAME" || return
  assert_scan_targets_logged "$FUNCNAME" "${default_home}" || return

  : > "${LOG_FILE}"
  COMPOSER_HOME='' SAFE_INSTALL_COMPOSER_HOME_UNSET=1 SAFE_AUDIT_EXPECT_PROJECTS=1 \
    SAFE_INSTALL_TEST_SCRIPT='composer global update' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_scan_targets_logged "$FUNCNAME" "${default_home}" || return

  : > "${LOG_FILE}"
  COMPOSER_HOME='' SAFE_AUDIT_EXPECT_PROJECTS=1 \
    SAFE_INSTALL_TEST_SCRIPT='composer global update' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_scan_targets_logged "$FUNCNAME" "${default_home}" || return

  : > "${LOG_FILE}"
  COMPOSER_HOME="${ordinary_home}" SAFE_AUDIT_EXPECT_PROJECTS=1 \
    SAFE_INSTALL_TEST_SCRIPT='composer global update' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_scan_targets_logged "$FUNCNAME" "${ordinary_home}" || return

  # This Unix-only resolver ignores all Windows-shaped environment variables.
  : > "${LOG_FILE}"
  COMPOSER_HOME='' SAFE_AUDIT_EXPECT_PROJECTS=1 \
    SAFE_AUDIT_SCAN_CRITICAL_PROJECT="${default_home}" \
    SAFE_INSTALL_TEST_SCRIPT="env OS=Windows_NT OSTYPE=msys APPDATA=${CASE_DIR}/absent-appdata composer global update" run_zsh
  assert_status 102 "$FUNCNAME" || return
  assert_scan_targets_logged "$FUNCNAME" "${default_home}" || return
  assert_log_not_contains_fragment 'absent-appdata' "$FUNCNAME" || return

  # Factory normalizes Unix HOME before appending .composer.
  : > "${LOG_FILE}"
  SAFE_INSTALL_HOME="${backslash_home}" COMPOSER_HOME='' SAFE_AUDIT_EXPECT_PROJECTS=1 \
    SAFE_AUDIT_SCAN_CRITICAL_PROJECT="${unix_home}/.composer" \
    SAFE_INSTALL_TEST_SCRIPT='composer global update' run_zsh
  assert_status 102 "$FUNCNAME" || return
  assert_scan_targets_logged "$FUNCNAME" "${unix_home}/.composer" || return

  : > "${LOG_FILE}"
  SAFE_INSTALL_HOME="${unix_home}///" COMPOSER_HOME='' SAFE_AUDIT_EXPECT_PROJECTS=1 \
    SAFE_AUDIT_SCAN_CRITICAL_PROJECT="${unix_home}/.composer" \
    SAFE_INSTALL_TEST_SCRIPT='composer global update' run_zsh
  assert_status 102 "$FUNCNAME" || return
  assert_scan_targets_logged "$FUNCNAME" "${unix_home}/.composer" || return

  # Absolute first working-dir values are retained at every position and add
  # both selected projects to the scan set. Delegation still receives argv.
  : > "${LOG_FILE}"
  COMPOSER_HOME="${global_home}" SAFE_AUDIT_EXPECT_PROJECTS=1 \
    SAFE_INSTALL_TEST_SCRIPT="composer --working-dir ${before_project} global update" run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_scan_targets_logged "$FUNCNAME" "${global_home}" "${before_project}" || return
  assert_log_contains $'REAL\tcomposer\t--working-dir\t'"${before_project}"$'\tglobal\tupdate' "$FUNCNAME" || return

  : > "${LOG_FILE}"
  COMPOSER_HOME="${global_home}" SAFE_AUDIT_EXPECT_PROJECTS=1 \
    SAFE_AUDIT_SCAN_CRITICAL_PROJECT="${between_project}" \
    SAFE_INSTALL_TEST_SCRIPT="composer global --working-dir ${between_project} update" run_zsh
  assert_status 102 "$FUNCNAME" || return
  assert_scan_targets_logged "$FUNCNAME" "${global_home}" "${between_project}" || return

  : > "${LOG_FILE}"
  COMPOSER_HOME="${global_home}" SAFE_AUDIT_EXPECT_PROJECTS=1 \
    SAFE_INSTALL_TEST_SCRIPT="composer global update --working-dir ${after_project}" run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_scan_targets_logged "$FUNCNAME" "${global_home}" "${after_project}" || return
  assert_log_contains $'REAL\tcomposer\tglobal\tupdate\t--working-dir\t'"${after_project}" "$FUNCNAME" || return

  : > "${LOG_FILE}"
  COMPOSER_HOME="${global_home}" SAFE_AUDIT_EXPECT_PROJECTS=1 \
    SAFE_INSTALL_TEST_SCRIPT="composer --working-dir ${first_project} global update --working-dir ${second_project}" run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_scan_targets_logged "$FUNCNAME" "${global_home}" "${first_project}" || return
  assert_log_not_contains_fragment $'AUDITPROJECT\t'"${second_project}" "$FUNCNAME" || return

  : > "${LOG_FILE}"
  COMPOSER_HOME="${global_home}" SAFE_AUDIT_EXPECT_PROJECTS=1 \
    SAFE_INSTALL_TEST_SCRIPT="composer global --working-dir=${equals_project} update" run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_scan_targets_logged "$FUNCNAME" "${global_home}" "${equals_project}" || return

  : > "${LOG_FILE}"
  COMPOSER_HOME="${global_home}" SAFE_AUDIT_EXPECT_PROJECTS=1 \
    SAFE_INSTALL_TEST_SCRIPT="composer global update -- --working-dir ${ignored_project}" run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_scan_targets_logged "$FUNCNAME" "${global_home}" || return
  assert_log_not_contains_fragment $'AUDITPROJECT\t'"${ignored_project}" "$FUNCNAME" || return

  # Relative values undergo Composer's proxy cwd stages; refusing them is
  # safer than selecting a different project from the nested application.
  for args in \
    ' --working-dir relative global update' \
    ' global --working-dir relative update' \
    ' global update --working-dir relative' \
    ' global --working-dir=relative update' \
    ' global -d relative update' \
    ' global -drelative update' \
    ' global -d C:/relative update'; do
    : > "${LOG_FILE}"
    COMPOSER_HOME="${global_home}" SAFE_INSTALL_TEST_SCRIPT="composer${args}" run_zsh
    assert_status 100 "$FUNCNAME" || return
    [[ "$(wc -l < "${ERR_FILE}")" -eq 1 ]] || { cat "${ERR_FILE}" >&2; fail "$FUNCNAME"; return 1; }
    assert_err_contains_fragment 'must be an absolute path' "$FUNCNAME" || return
    assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
    assert_log_not_contains_fragment $'REAL\tcomposer' "$FUNCNAME" || return
  done

  # An unknown bare option in the accepted global lane can hide its nested
  # command, so it remains a one-line conservative refusal.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='composer global --not-a-real-global-option update' run_zsh
  assert_status 100 "$FUNCNAME" || return
  [[ "$(wc -l < "${ERR_FILE}")" -eq 1 ]] || { cat "${ERR_FILE}" >&2; fail "$FUNCNAME"; return 1; }
  assert_log_not_contains_fragment $'REAL\tcomposer\tglobal\t--not-a-real-global-option' "$FUNCNAME" || return

  pass "$FUNCNAME"
}

case_npm_dedupe_lockdiff_empty_delegates_without_scan() {
  skip_lockdiff_case "$FUNCNAME" || return
  prepare_lockdiff_case "npm-dedupe-lockdiff-empty"
  printf '{"name":"lockdiff-test","version":"1.0.0"}\n' > "${WORK_DIR}/package.json"
  printf '{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"},"node_modules/kept":{"version":"1.0.0"}}}\n' > "${WORK_DIR}/package-lock.json"
  NPM_LOCK_MUTATION_JSON='{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"},"node_modules/kept":{"version":"1.0.0"}}}' \
    SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'PROJECTION\tnpm\t--package-lock-only\t--ignore-scripts\t--no-audit\t--no-fund\tdedupe' "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tdedupe' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'AUDIT\tscan' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'AUDIT\tcheck' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_lockdiff_absent_node_modules_refuses() {
  skip_lockdiff_case "$FUNCNAME" || return
  prepare_lockdiff_case "npm-lockdiff-no-node-modules"
  rmdir "${WORK_DIR}/node_modules"
  # Empty lock diff + absent tree = the real command materializes every
  # lockfile artifact unaudited (review F3; operator-ruled guard).
  printf '{"name":"lockdiff-test","version":"1.0.0"}\n' > "${WORK_DIR}/package.json"
  printf '{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"},"node_modules/kept":{"version":"1.0.0"}}}\n' > "${WORK_DIR}/package-lock.json"
  SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_err_contains_fragment 'node_modules is absent' "$FUNCNAME" || return
  assert_log_not_contains_fragment 'PROJECTION' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_lockdiff_projection_sees_project_npmrc() {
  skip_lockdiff_case "$FUNCNAME" || return
  prepare_lockdiff_case "npm-lockdiff-npmrc-copied"
  # A project-level registry must govern the projection too, or the audit
  # vouches for a different artifact than the delegate fetches (review F3).
  printf 'registry=https://npm.example.test/\n' > "${WORK_DIR}/.npmrc"
  printf '{"name":"lockdiff-test","version":"1.0.0"}\n' > "${WORK_DIR}/package.json"
  printf '{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"},"node_modules/kept":{"version":"1.0.0"}}}\n' > "${WORK_DIR}/package-lock.json"
  NPM_LOCK_MUTATION_JSON='{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"},"node_modules/kept":{"version":"1.0.0"}}}' \
    SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'PROJECTION\tnpm\tPROJNPMRC\t--package-lock-only\t--ignore-scripts\t--no-audit\t--no-fund\tdedupe' "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tdedupe' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_dedupe_lockdiff_introduced_block_refuses_without_delegation() {
  skip_lockdiff_case "$FUNCNAME" || return
  prepare_lockdiff_case "npm-dedupe-lockdiff-block"
  printf '{"name":"lockdiff-test","version":"1.0.0"}\n' > "${WORK_DIR}/package.json"
  printf '{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"}}}\n' > "${WORK_DIR}/package-lock.json"
  NPM_LOCK_MUTATION_JSON='{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"},"node_modules/blockme":{"version":"2.0.0","resolved":"https://registry.npmjs.org/blockme/-/blockme-2.0.0.tgz","integrity":"sha512-blockme"}}}' \
    SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_project_scan_logged "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme@2.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_count 0 $'REAL\tnpm\tdedupe' "${LOG_FILE}" "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_dedupe_lockdiff_parse_failure_fails_closed() {
  skip_lockdiff_case "$FUNCNAME" || return
  prepare_lockdiff_case "npm-dedupe-lockdiff-parse-failure"
  printf '{"name":"lockdiff-test","version":"1.0.0"}\n' > "${WORK_DIR}/package.json"
  printf '{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"}}}\n' > "${WORK_DIR}/package-lock.json"
  NPM_LOCK_MUTATION_JSON='{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"},"node_modules/broken":{}}}' \
    SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_err_contains_fragment 'lock-diff analysis failed' "$FUNCNAME" || return
  assert_err_contains_fragment 'exit 3' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'AUDIT\tscan' "$FUNCNAME" || return
  assert_count 0 $'REAL\tnpm\tdedupe' "${LOG_FILE}" "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_prune_lockdiff_introduced_block_refuses_without_delegation() {
  skip_lockdiff_case "$FUNCNAME" || return
  prepare_lockdiff_case "npm-prune-lockdiff-block"
  printf '{"name":"lockdiff-test","version":"1.0.0"}\n' > "${WORK_DIR}/package.json"
  printf '{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"}}}\n' > "${WORK_DIR}/package-lock.json"
  NPM_LOCK_MUTATION_JSON='{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"},"node_modules/blockme":{"version":"2.0.0","resolved":"https://registry.npmjs.org/blockme/-/blockme-2.0.0.tgz","integrity":"sha512-blockme"}}}' \
    SAFE_INSTALL_TEST_SCRIPT='npm prune' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_project_scan_logged "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme@2.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_count 0 $'REAL\tnpm\tprune' "${LOG_FILE}" "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_lockdiff_prefixes_route_to_projection() {
  skip_lockdiff_case "$FUNCNAME" || return
  prepare_lockdiff_case "npm-lockdiff-prefixes"
  printf '{"name":"lockdiff-test","version":"1.0.0"}\n' > "${WORK_DIR}/package.json"
  printf '{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"}}}\n' > "${WORK_DIR}/package-lock.json"
  local token
  for token in dd ded dedu dedup pru prun ddp; do
    : > "${LOG_FILE}"
    NPM_LOCK_MUTATION_JSON='{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"},"node_modules/blockme":{"version":"2.0.0","resolved":"https://registry.npmjs.org/blockme/-/blockme-2.0.0.tgz","integrity":"sha512-blockme"}}}' \
      SAFE_INSTALL_TEST_SCRIPT="npm ${token}" run_zsh
    assert_status 104 "$FUNCNAME" || return
    assert_log_contains $'PROJECTION\tnpm\t--package-lock-only\t--ignore-scripts\t--no-audit\t--no-fund\t'"${token}" "$FUNCNAME" || return
    assert_count 0 $'REAL\tnpm\t'"${token}" "${LOG_FILE}" "$FUNCNAME" || return
  done
  pass "$FUNCNAME"
}

case_npm_lockdiff_refuses_bare_option_terminator() {
  skip_lockdiff_case "$FUNCNAME" || return
  prepare_lockdiff_case "npm-lockdiff-option-terminator"
  printf '{"name":"lockdiff-test","version":"1.0.0"}\n' > "${WORK_DIR}/package.json"
  printf '{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"}}}\n' > "${WORK_DIR}/package-lock.json"
  SAFE_INSTALL_TEST_SCRIPT='npm dedupe --' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_err_contains_fragment 'disables the lock-diff projection invariant' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'PROJECTION\tnpm' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm\tconfig' "$FUNCNAME" || return
  assert_count 0 $'REAL\tnpm\tdedupe' "${LOG_FILE}" "$FUNCNAME" || return
  [[ "$(wc -l < "${ERR_FILE}")" -eq 1 ]] || { cat "${ERR_FILE}" >&2; fail "$FUNCNAME"; return; }
  pass "$FUNCNAME"
}

case_npm_lockdiff_effective_config_oracle() {
  skip_lockdiff_case "$FUNCNAME" || return
  prepare_lockdiff_case "npm-lockdiff-effective-config"
  printf '{"name":"lockdiff-test","version":"1.0.0"}\n' > "${WORK_DIR}/package.json"
  printf '{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"}}}\n' > "${WORK_DIR}/package-lock.json"

  # npm 12 trims this inherited value before applying it. The oracle result
  # comes from the real npm command; the stub supplies that result exactly.
  NPM_CONFIG_PACKAGE_LOCK=' false ' \
    NPM_LOCKDIFF_EFFECTIVE_CONFIG_JSON='{"package-lock":false,"ignore-scripts":true}' \
    SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_err_contains_fragment 'effective npm config disables the lock-diff projection: package-lock is off' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'PROJECTION\tnpm' "$FUNCNAME" || return

  : > "${LOG_FILE}"
  # Quoted .npmrc values are npm syntax, not a shell parser's concern.
  printf 'package-lock = "false"\n' > "${WORK_DIR}/.npmrc"
  NPM_LOCKDIFF_EFFECTIVE_CONFIG_JSON='{"package-lock":false,"ignore-scripts":true}' \
    SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_err_contains_fragment 'effective npm config disables the lock-diff projection: package-lock is off' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'PROJECTION\tnpm' "$FUNCNAME" || return

  : > "${LOG_FILE}"
  # npm's boolean spelling below disabled lockfile writes in the round-two
  # reproduction. The oracle, rather than argv pattern matching, decides it.
  rm -f "${WORK_DIR}/.npmrc"
  NPM_LOCKDIFF_EFFECTIVE_CONFIG_JSON='{"package-lock":false,"ignore-scripts":true}' \
    SAFE_INSTALL_TEST_SCRIPT='npm dedupe --no-package-lock=0' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_err_contains_fragment 'effective npm config disables the lock-diff projection: package-lock is off' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'PROJECTION\tnpm' "$FUNCNAME" || return

  : > "${LOG_FILE}"
  # npm is last-key-wins: this project is effectively enabled and delegates.
  printf 'package-lock=false\npackage-lock=true\n' > "${WORK_DIR}/.npmrc"
  NPM_LOCKDIFF_EFFECTIVE_CONFIG_JSON='{"package-lock":true,"ignore-scripts":true}' \
    NPM_LOCK_MUTATION_JSON='{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"}}}' \
    SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tdedupe' "$FUNCNAME" || return

  : > "${LOG_FILE}"
  NPM_LOCKDIFF_CONFIG_STATUS=17 SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_err_contains_fragment 'effective npm config probe failed' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'PROJECTION\tnpm' "$FUNCNAME" || return

  : > "${LOG_FILE}"
  rm -f "${WORK_DIR}/.npmrc"
  # The probe must MIRROR the projection argv — safe's invariant flags first,
  # user argv last — not read the ambient config. Probing the ambient value
  # refused every dedupe/prune on a stock machine, where npm's own default is
  # ignore-scripts=false. Asserting the argv (the stub answers from env, so
  # only this pins the form the real npm would resolve).
  NPM_LOCK_MUTATION_JSON='{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"}}}' \
    SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 0 "$FUNCNAME" || return
  # Invariant flags first (user argv may override them — that is the point of
  # the mirror), but `--json` LAST so an ordinary user `--json=false` cannot
  # disable the probe's own transport (delta-4 F2).
  assert_log_contains $'REAL\tnpm\tconfig\tlist\t--package-lock-only\t--ignore-scripts\t--no-audit\t--no-fund\tdedupe\t--json' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_lockdiff_refuses_nonregistry_sources() {
  skip_lockdiff_case "$FUNCNAME" || return
  prepare_lockdiff_case "npm-lockdiff-nonregistry-source"
  printf '{"name":"lockdiff-test","version":"1.0.0"}\n' > "${WORK_DIR}/package.json"
  printf '{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"}}}\n' > "${WORK_DIR}/package-lock.json"
  NPM_LOCK_MUTATION_JSON='{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"},"node_modules/alias":{"name":"left-pad","version":"1.3.0","resolved":"git+https://example.invalid/left-pad.git#deadbeef","integrity":"sha512-git"}}}' \
    SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_err_contains_fragment 'alias@1.3.0 is a git artifact, not a registry artifact; not audit-gated' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'AUDIT\tscan' "$FUNCNAME" || return
  assert_count 0 $'REAL\tnpm\tdedupe' "${LOG_FILE}" "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_lockdiff_registry_host_provenance() {
  skip_lockdiff_case "$FUNCNAME" || return
  prepare_lockdiff_case "npm-lockdiff-registry-host-provenance"
  printf '{"name":"lockdiff-test","version":"1.0.0"}\n' > "${WORK_DIR}/package.json"
  printf '{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"}}}\n' > "${WORK_DIR}/package-lock.json"

  # A HTTP tarball from an unconfigured host must not be vouched for as its
  # self-declared registry package name.
  NPM_LOCK_MUTATION_JSON='{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"},"node_modules/alias":{"name":"left-pad","version":"1.3.0","resolved":"https://example.invalid/evil.tgz","integrity":"sha512-evil"}}}' \
    SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_err_contains_fragment 'alias@1.3.0 is a remote artifact, not a registry artifact; not audit-gated' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'AUDIT\tscan' "$FUNCNAME" || return

  # A project-private registry host is authoritative and retains the .name
  # identity for the normal audit lane.
  prepare_lockdiff_case "npm-lockdiff-private-registry-host"
  printf '{"name":"lockdiff-test","version":"1.0.0"}\n' > "${WORK_DIR}/package.json"
  printf '{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"}}}\n' > "${WORK_DIR}/package-lock.json"
  NPM_LOCKDIFF_REGISTRY_CONFIG_JSON='{"registry":"https://registry.example.test/","@scope:registry":null}' \
    NPM_LOCK_MUTATION_JSON='{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"},"node_modules/alias":{"name":"private-pkg","version":"1.0.0","resolved":"https://registry.example.test/private-pkg/-/private-pkg-1.0.0.tgz","integrity":"sha512-private"}}}' \
    SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tprivate-pkg@1.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tdedupe' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_lockdiff_safe_core_is_pinned_and_strict() {
  skip_lockdiff_case "$FUNCNAME" || return
  prepare_lockdiff_case "npm-lockdiff-safe-core-pinned"
  printf '{"name":"lockdiff-test","version":"1.0.0"}\n' > "${WORK_DIR}/package.json"
  printf '{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"}}}\n' > "${WORK_DIR}/package-lock.json"

  # A PATH shadow must not be consulted: the sibling core stays authoritative.
  cat > "${WRAPPER_DIR}/safe-core" <<'STUB'
#!/usr/bin/env bash
exit 77
STUB
  chmod +x "${WRAPPER_DIR}/safe-core"
  NPM_LOCK_MUTATION_JSON='{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"}}}' \
    SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tdedupe' "$FUNCNAME" || return

  rm -f "${BIN_DIR}/safe-core"
  cat > "${BIN_DIR}/safe-core" <<STUB
#!/usr/bin/env bash
case "\${1:-}" in
  --version) printf '${SAFE_REPO_VERSION}\n' ;;
  lockdiff) printf '{"schema":1}\n' ;;
esac
STUB
  chmod +x "${BIN_DIR}/safe-core"
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_err_contains_fragment 'lock-diff analysis returned an unreadable result' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'AUDIT\tscan' "$FUNCNAME" || return

  cat > "${BIN_DIR}/safe-core" <<'STUB'
#!/usr/bin/env bash
if [[ "${1:-}" == "--version" ]]; then printf '0.0.0\n'; fi
STUB
  chmod +x "${BIN_DIR}/safe-core"
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_err_contains_fragment "safe-core version 0.0.0 does not match safe ${SAFE_REPO_VERSION}" "$FUNCNAME" || return
  assert_log_not_contains_fragment $'PROJECTION\tnpm' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_lockdiff_refuses_missing_scan_coverage() {
  skip_lockdiff_case "$FUNCNAME" || return
  prepare_lockdiff_case "npm-lockdiff-scan-coverage"
  printf '{"name":"lockdiff-test","version":"1.0.0"}\n' > "${WORK_DIR}/package.json"
  printf '{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"}}}\n' > "${WORK_DIR}/package-lock.json"
  local mutation='{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"},"node_modules/okpkg":{"version":"1.0.0","resolved":"https://registry.npmjs.org/okpkg/-/okpkg-1.0.0.tgz","integrity":"sha512-okpkg"}}}'

  SAFE_AUDIT_SCAN_TOOL_STATUS='{"npm":1}' NPM_LOCK_MUTATION_JSON="${mutation}" SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_err_contains_fragment 'projected dependency scan produced no readable verdict' "$FUNCNAME" || return
  assert_count 0 $'REAL\tnpm\tdedupe' "${LOG_FILE}" "$FUNCNAME" || return

  : > "${LOG_FILE}"
  SAFE_AUDIT_SCAN_ECOSYSTEM_AUDITS='[{"scanner":"npm-audit","status":"skipped","note":"npm unavailable"}]' NPM_LOCK_MUTATION_JSON="${mutation}" SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_err_contains_fragment 'projected dependency scanner failure (npm-audit' "$FUNCNAME" || return
  assert_count 0 $'REAL\tnpm\tdedupe' "${LOG_FILE}" "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_lockdiff_warn_matches_install_lane() {
  skip_lockdiff_case "$FUNCNAME" || return
  prepare_lockdiff_case "npm-lockdiff-warn-parity-install"
  SAFE_INSTALL_TEST_SCRIPT='npm install -g warnme@2.0.0' run_zsh
  assert_status 100 "$FUNCNAME" || return
  local install_refusal
  install_refusal="$(<"${ERR_FILE}")"

  prepare_lockdiff_case "npm-lockdiff-warn-parity-dedupe"
  printf '{"name":"lockdiff-test","version":"1.0.0"}\n' > "${WORK_DIR}/package.json"
  printf '{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"}}}\n' > "${WORK_DIR}/package-lock.json"
  NPM_LOCK_MUTATION_JSON='{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"},"node_modules/warnme":{"version":"2.0.0","resolved":"https://registry.npmjs.org/warnme/-/warnme-2.0.0.tgz","integrity":"sha512-warnme"}}}' \
    SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 100 "$FUNCNAME" || return
  [[ "$(<"${ERR_FILE}")" == "${install_refusal}" ]] || { printf 'dedupe refusal diverged from install:\n%s\n' "$(<"${ERR_FILE}")" >&2; fail "$FUNCNAME"; return; }
  [[ "$(wc -l < "${ERR_FILE}")" -eq 1 ]] || { cat "${ERR_FILE}" >&2; fail "$FUNCNAME"; return; }
  assert_count 0 $'REAL\tnpm\tdedupe' "${LOG_FILE}" "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_exec_passthrough_by_design() {
  prepare_case "exec-passthrough-by-design"
  SAFE_INSTALL_TEST_SCRIPT='pnpm exec eslint && composer exec tool && volta run node -v' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_log_contains $'REAL\tpnpm\texec\teslint' "$FUNCNAME" || return
  assert_log_contains $'REAL\tcomposer\texec\ttool' "$FUNCNAME" || return
  assert_log_contains $'REAL\tvolta\trun\tnode\t-v' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_global_package_check() {
  prepare_case "global-package-check"
  SAFE_INSTALL_TEST_SCRIPT='npm install -g left-pad@1.3.0' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tleft-pad@1.3.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tinstall\t-g\tleft-pad@1.3.0' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_local_project_scan() {
  prepare_case "local-project-scan"
  touch "${WORK_DIR}/package.json"
  SAFE_INSTALL_TEST_SCRIPT='npm ci' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_project_scan_logged "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tci' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_add_scans_and_checks() {
  prepare_case "add-scans-and-checks"
  touch "${WORK_DIR}/package.json"
  SAFE_INSTALL_TEST_SCRIPT='pnpm add --filter web --workspace-root lodash' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_project_scan_logged "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tlodash\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'\tweb\t--ecosystem' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_blocked_install() {
  prepare_case "blocked-install"
  SAFE_INSTALL_TEST_SCRIPT='npm install -g blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_block_refusal_never_hints_allow() {
  prepare_case "block-refusal-never-hints-allow"
  # BLOCK is not host-allow's business: host-allow only clears WARN, and for
  # a known-malware record an allowlist hint would contradict the audit's
  # "do not pin around it" (review PR#55 F2). The final refusal routes to
  # operator review only.
  SAFE_INSTALL_TEST_SCRIPT='npm install -g blockme@1.2.3' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_err_contains_fragment 'operator review required' "$FUNCNAME" || return
  assert_err_not_contains_fragment 'host-allow add' "$FUNCNAME" || return
  assert_err_not_contains_fragment 'to allow' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_warning_install_blocks() {
  prepare_case "warning-install-blocks"
  SAFE_INSTALL_TEST_SCRIPT='npm install -g warnme' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\twarnme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_host_allow_warn_allows_exact_global_install() {
  prepare_case "host-allow-warn-allows-exact-global-install"
  mkdir -p "${HOME_DIR}/.config/safe/run"
  cat > "${HOME_DIR}/.config/safe/run/host-allow.json" <<'JSON'
{"packages":{"warnme":{"version":"1.0.0","ecosystem":"npm","reason":"fixture"}}}
JSON
  SAFE_INSTALL_TEST_SCRIPT='npm install -g warnme@1.0.0' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\twarnme@1.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tinstall\t-g\twarnme@1.0.0' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_host_allow_warn_requires_exact_version() {
  prepare_case "host-allow-warn-requires-exact-version"
  mkdir -p "${HOME_DIR}/.config/safe/run"
  cat > "${HOME_DIR}/.config/safe/run/host-allow.json" <<'JSON'
{"packages":{"warnme":{"version":"1.0.0","ecosystem":"npm","reason":"fixture"}}}
JSON
  SAFE_INSTALL_TEST_SCRIPT='npm install -g warnme@1.0.1' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\twarnme@1.0.1\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_colon_version_global_install() {
  prepare_case "npm-colon-version-global-install"
  SAFE_INSTALL_TEST_SCRIPT='npm install -g @qwen-code/qwen-code:0.16.2' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\t@qwen-code/qwen-code@0.16.2\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tinstall\t-g\t@qwen-code/qwen-code:0.16.2' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_alias_audits_target_package() {
  prepare_case "npm-alias-audits-target-package"
  SAFE_INSTALL_TEST_SCRIPT='npm install -g qwen@npm:@qwen-code/qwen-code@0.16.2' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\t@qwen-code/qwen-code@0.16.2\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tinstall\t-g\tqwen@npm:@qwen-code/qwen-code@0.16.2' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_audit_failure_blocks() {
  prepare_case "audit-failure-blocks"
  SAFE_AUDIT_CHECK_STATUS=42 SAFE_INSTALL_TEST_SCRIPT='uv tool install repomix' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\trepomix\t--ecosystem\tpython\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tuv' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_critical_scan_non_tty_aborts() {
  prepare_case "critical-scan-non-tty-aborts"
  touch "${WORK_DIR}/package.json"
  SAFE_AUDIT_SCAN_OUTPUT='critical vulnerability' SAFE_AUDIT_SCAN_STATUS=1 SAFE_INSTALL_TEST_SCRIPT='npm ci' run_zsh
  assert_status 102 "$FUNCNAME" || return
  assert_project_scan_logged "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm' "$FUNCNAME" || return
  assert_err_contains_fragment 'safe: BLOCKED install — safe audit scan found critical findings' "$FUNCNAME" || return
  # Non-TTY refusals are exactly one line: the interactive preamble (which
  # says the scan FAILED, never that it "found" something) stays out.
  assert_err_not_contains_fragment 'after reporting critical findings' "$FUNCNAME" || return
  [[ "$(wc -l < "${ERR_FILE}")" -eq 1 ]] || { cat "${ERR_FILE}" >&2; fail "$FUNCNAME"; return 1; }
  pass "$FUNCNAME"
}

# The scan EXITS 0 when it finds a critical advisory — the verdict lives in
# the result document. Gating on the exit code let every finding through.
case_critical_in_result_blocks_despite_exit_zero() {
  prepare_case "critical-result-blocks"
  touch "${WORK_DIR}/package.json"
  SAFE_AUDIT_SCAN_STATUS=0 SAFE_AUDIT_SCAN_VERDICT=WARN SAFE_AUDIT_SCAN_CRITICAL=2 \
    SAFE_INSTALL_TEST_SCRIPT='npm ci' run_zsh
  assert_status 102 "$FUNCNAME" || return
  assert_project_scan_logged "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm' "$FUNCNAME" || return
  assert_err_contains_fragment 'safe: BLOCKED install — safe audit scan found critical findings' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# A result document that is present but not readable is NOT a clean verdict.
# Every jq read against a truncated document falls back to its default, and
# defaulted zeros are indistinguishable from "scanned it, found nothing" — so
# the gate used to announce a clean project it had never actually read.
case_malformed_result_document_is_not_read_as_clean() {
  prepare_case "malformed-result-not-clean"
  touch "${WORK_DIR}/package.json"
  SAFE_AUDIT_SCAN_STATUS=0 SAFE_AUDIT_SCAN_MALFORMED_RESULT=1 \
    SAFE_INSTALL_TEST_SCRIPT='npm ci' run_zsh
  # Policy is unchanged: a scan that produced no verdict warns and proceeds.
  # What must never happen is proceeding SILENTLY.
  assert_status 0 "$FUNCNAME" || return
  assert_project_scan_logged "$FUNCNAME" || return
  assert_err_contains_fragment 'produced no readable result' "$FUNCNAME" || return
  assert_err_contains_fragment 'NOT audit-gated' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# A scanner that broke does not stop the install (documented policy: only
# critical findings do), but what was not checked is said out loud.
case_broken_scanner_warns_and_proceeds() {
  prepare_case "broken-scanner-warns"
  touch "${WORK_DIR}/package.json"
  SAFE_AUDIT_SCAN_STATUS=0 SAFE_AUDIT_SCAN_VERDICT=WARN \
    SAFE_AUDIT_SCAN_ECOSYSTEM_AUDITS='[{"scanner":"npm-audit","status":"error","total":0,"critical":0,"high":0,"medium":0,"low":0,"unknown":0,"note":"npm-audit failed (exit 1)"}]' \
    SAFE_INSTALL_TEST_SCRIPT='npm ci' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_err_contains_fragment 'scanner failure (npm-audit)' "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tci' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# A clean result still proceeds silently: no new noise on the common path.
case_clean_result_proceeds_quietly() {
  prepare_case "clean-result-proceeds"
  touch "${WORK_DIR}/package.json"
  SAFE_AUDIT_SCAN_STATUS=0 SAFE_INSTALL_TEST_SCRIPT='npm ci' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_err_not_contains_fragment 'scanner failure' "$FUNCNAME" || return
  assert_err_not_contains_fragment 'BLOCKED' "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tci' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_missing_safe_audit_warns_per_command() {
  prepare_case "missing-safe-audit-warns-per-command" no
  SAFE_INSTALL_TEST_SCRIPT='npm install -g one; npm install -g two' run_zsh
  assert_status 0 "$FUNCNAME" || return
  # SEMANTIC DIFFERENCE vs the zsh wrappers: the "warn once" flag was a
  # variable in one long-lived interactive shell. Each gated command is now its
  # own process, so the warning is once per command (2 here, was 1). The
  # behaviour that matters — no audit available means warn, then proceed — is
  # unchanged.
  assert_count 2 'safe audit not installed, skipping pre-install check' "${ERR_FILE}" "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tinstall\t-g\tone' "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tinstall\t-g\ttwo' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_non_install_passthrough() {
  prepare_case "non-install-passthrough"
  SAFE_INSTALL_TEST_SCRIPT='npm view left-pad' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tview\tleft-pad' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_complex_flags() {
  prepare_case "npm-complex-flags"
  SAFE_INSTALL_TEST_SCRIPT='npm install --registry https://registry.example --tag beta --omit dev left-pad' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tleft-pad\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall\t--dist-tag\tbeta\t--registry\thttps://registry.example' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'\thttps://registry.example@latest' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'\tbeta@latest' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'\tdev@latest' "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tinstall\t--registry\thttps://registry.example\t--tag\tbeta\t--omit\tdev\tleft-pad' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_pip_complex_flags() {
  prepare_case "pip-complex-flags"
  SAFE_INSTALL_TEST_SCRIPT='pip install --index-url https://pypi.example --constraint constraints.txt requests==2.32.0' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\trequests@2.32.0\t--ecosystem\tpython\t--gate\tinstall\t--op\tinstall\t--registry\thttps://pypi.example' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'\thttps://pypi.example@latest' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'\tconstraints.txt@latest' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_requirement_install_scans() {
  prepare_case "requirement-install-scans"
  SAFE_INSTALL_TEST_SCRIPT='pip install -r requirements.txt' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_project_scan_logged "$FUNCNAME" || return
  assert_log_not_contains_fragment $'AUDIT\tcheck' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_cargo_parser() {
  prepare_case "cargo-parser"
  SAFE_INSTALL_TEST_SCRIPT='cargo install ripgrep --version 14.1.1' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tripgrep@14.1.1\t--ecosystem\tcargo\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'\t14.1.1@latest' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_go_parser() {
  prepare_case "go-parser"
  SAFE_INSTALL_TEST_SCRIPT='go install -tags netgo example.com/tool@v1.2.3' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\texample.com/tool@v1.2.3\t--ecosystem\tgo\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'\tnetgo@latest' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_composer_parser() {
  prepare_case "composer-parser"
  SAFE_INSTALL_TEST_SCRIPT='composer global require --working-dir /tmp vendor/pkg:^1' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tvendor/pkg@^1\t--ecosystem\tcomposer\t--gate\tinstall\t--op\tinstall\t--project-dir\t/tmp' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'\t/tmp@latest' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_install_idempotent_no_wrappers() {
  prepare_case "install-idempotent-no-wrappers"
  HOME="${HOME_DIR}" bash "${ROOT_DIR}/install.sh" --no-wrappers >"${OUT_FILE}" 2>"${ERR_FILE}"
  STATUS=$?
  HOME="${HOME_DIR}" bash "${ROOT_DIR}/install.sh" --no-wrappers >>"${OUT_FILE}" 2>>"${ERR_FILE}" || STATUS=$?
  assert_status 0 "$FUNCNAME" || return
  assert_count 0 'source "$HOME/.config/safe/install-wrappers.zsh"' "${HOME_DIR}/.zshrc" "$FUNCNAME" || return
  assert_count 1 'fpath=("$HOME/.local/share/zsh/site-functions" $fpath)' "${HOME_DIR}/.zshrc" "$FUNCNAME" || return
  [[ -f "${HOME_DIR}/.local/share/zsh/site-functions/_safe" ]] || { fail "$FUNCNAME"; return; }
  [[ -x "${HOME_DIR}/.local/bin/safe-core" ]] || { fail "$FUNCNAME"; return; }
  [[ "$("${HOME_DIR}/.local/bin/safe-core" --version)" == "${SAFE_REPO_VERSION}" ]] || { fail "$FUNCNAME"; return; }
  local doctor_json
  doctor_json="$(HOME="${HOME_DIR}" PATH="${HOME_DIR}/.local/bin:/usr/bin:/bin" \
    "${HOME_DIR}/.local/bin/safe" doctor --json)" || { fail "$FUNCNAME"; return; }
  jq -e --arg ver "${SAFE_REPO_VERSION}" '.dependencies.core.safe_core.present == true
    and .dependencies.core.safe_core.version == $ver
    and .environment.safe_core.version_matches == true
    and .environment.safe_core.warning == null' <<<"${doctor_json}" >/dev/null || { fail "$FUNCNAME"; return; }
  # The suite core is release-versioned for gate-time parity. Replace the
  # PATH shadow explicitly so doctor continues to exercise its drift branch.
  rm -f "${BIN_DIR}/safe-core"
  printf '#!/usr/bin/env bash\nprintf "dev\\n"\n' > "${BIN_DIR}/safe-core"
  chmod +x "${BIN_DIR}/safe-core"
  doctor_json="$(HOME="${HOME_DIR}" PATH="${BIN_DIR}:${HOME_DIR}/.local/bin:/usr/bin:/bin" \
    "${HOME_DIR}/.local/bin/safe" doctor --json)" || { fail "$FUNCNAME"; return; }
  jq -e '.environment.safe_core.version_matches == false
    and (.environment.safe_core.warning | contains("rerun install.sh"))' <<<"${doctor_json}" >/dev/null || { fail "$FUNCNAME"; return; }
  pass "$FUNCNAME"
}

case_install_idempotent_with_completions() {
  prepare_case "install-idempotent-with-completions"
  HOME="${HOME_DIR}" bash "${ROOT_DIR}/install.sh" >"${OUT_FILE}" 2>"${ERR_FILE}"
  STATUS=$?
  HOME="${HOME_DIR}" bash "${ROOT_DIR}/install.sh" >>"${OUT_FILE}" 2>>"${ERR_FILE}" || STATUS=$?
  assert_status 0 "$FUNCNAME" || return
  assert_count 1 'source "$HOME/.config/safe/install-wrappers.zsh"' "${HOME_DIR}/.zshrc" "$FUNCNAME" || return
  assert_count 1 'fpath=("$HOME/.local/share/zsh/site-functions" $fpath)' "${HOME_DIR}/.zshrc" "$FUNCNAME" || return
  [[ -f "${HOME_DIR}/.local/share/zsh/site-functions/_safe" ]] || { fail "$FUNCNAME"; return; }
  pass "$FUNCNAME"
}

case_install_writes_gate_wrappers() {
  prepare_case "install-writes-gate-wrappers"
  mkdir -p "${HOME_DIR}/.local/bin"
  # A pre-existing foreign binary of a wrapped name must survive untouched:
  # overwriting somebody else's npm would be destructive, so we report instead.
  printf '#!/usr/bin/env bash\n# not ours\n' > "${HOME_DIR}/.local/bin/pnpm"
  chmod +x "${HOME_DIR}/.local/bin/pnpm"

  HOME="${HOME_DIR}" bash "${ROOT_DIR}/install.sh" >"${OUT_FILE}" 2>"${ERR_FILE}"
  STATUS=$?
  assert_status 0 "$FUNCNAME" || return

  local tool
  for tool in npm pnpx yarn bun pip pip3 uv cargo go composer mise; do
    head -n 2 "${HOME_DIR}/.local/bin/${tool}" | grep -Fq '# safe-gate-wrapper' || { fail "$FUNCNAME"; return; }
    [[ -x "${HOME_DIR}/.local/bin/${tool}" ]] || { fail "$FUNCNAME"; return; }
    grep -Fq "exec safe gate ${tool} -- \"\$@\"" "${HOME_DIR}/.local/bin/${tool}" || { fail "$FUNCNAME"; return; }
  done
  grep -Fqx '# not ours' "${HOME_DIR}/.local/bin/pnpm" || { fail "$FUNCNAME"; return; }
  assert_err_contains_fragment 'gating NOT active for: pnpm' "$FUNCNAME" || return
  [[ -f "${HOME_DIR}/.config/safe/gate-lib.sh" ]] || { fail "$FUNCNAME"; return; }
  # No volta wrapper: the volta integration is retired.
  [[ ! -e "${HOME_DIR}/.local/bin/volta" ]] || { fail "$FUNCNAME"; return; }
  pass "$FUNCNAME"
}

# uv installs itself to exactly the path its wrapper needs, so the ordinary
# rule — an unmarked file belongs to somebody else, leave it and report — meant
# uv could never be gated at all: `uv add` and `uv sync` bypassed safe on every
# machine. Those tools are moved aside instead, the convention already used for
# uvx, and the resolver falls back to <tool>.original.
case_uv_binary_is_displaced_and_gated() {
  prepare_case "uv-binary-displaced"
  mkdir -p "${HOME_DIR}/.local/bin"
  printf '#!/usr/bin/env bash\n# the real uv\necho uv-real\n' > "${HOME_DIR}/.local/bin/uv"
  chmod +x "${HOME_DIR}/.local/bin/uv"

  HOME="${HOME_DIR}" bash "${ROOT_DIR}/install.sh" >"${OUT_FILE}" 2>"${ERR_FILE}"
  STATUS=$?
  assert_status 0 "$FUNCNAME" || return

  head -n 2 "${HOME_DIR}/.local/bin/uv" | grep -Fq '# safe-gate-wrapper v1 tool=uv' || { fail "$FUNCNAME"; return; }
  # The displaced copy must be the original binary, byte for byte, and still
  # executable: this is the user's uv, not a backup we may mangle.
  grep -Fqx '# the real uv' "${HOME_DIR}/.local/bin/uv.original" || { fail "$FUNCNAME"; return; }
  [[ -x "${HOME_DIR}/.local/bin/uv.original" ]] || { fail "$FUNCNAME"; return; }
  assert_err_contains_fragment 'moved real binaries aside to <tool>.original and gated them: uv' "$FUNCNAME" || return
  # And it must NOT be reported as ungated, which is what the old path said.
  assert_err_not_contains_fragment 'gating NOT active for: uv' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_uv_displacement_refuses_to_clobber_an_existing_original() {
  prepare_case "uv-displacement-no-clobber"
  mkdir -p "${HOME_DIR}/.local/bin"
  printf '#!/usr/bin/env bash\n# a newer uv\n' > "${HOME_DIR}/.local/bin/uv"
  chmod +x "${HOME_DIR}/.local/bin/uv"
  printf '#!/usr/bin/env bash\n# an older displaced uv\n' > "${HOME_DIR}/.local/bin/uv.original"
  chmod +x "${HOME_DIR}/.local/bin/uv.original"

  HOME="${HOME_DIR}" bash "${ROOT_DIR}/install.sh" >"${OUT_FILE}" 2>"${ERR_FILE}"
  STATUS=$?
  assert_status 0 "$FUNCNAME" || return

  # Both files survive untouched and the tool is honestly reported ungated:
  # overwriting either one would destroy a binary safe does not own.
  grep -Fqx '# a newer uv' "${HOME_DIR}/.local/bin/uv" || { fail "$FUNCNAME"; return; }
  grep -Fqx '# an older displaced uv' "${HOME_DIR}/.local/bin/uv.original" || { fail "$FUNCNAME"; return; }
  assert_err_contains_fragment 'found an existing <tool>.original for: uv' "$FUNCNAME" || return
  assert_err_contains_fragment 'gating NOT active for: uv' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# Displacing a binary and then failing to write its wrapper would leave the
# user with a truncated uv and their real one stranded at uv.original — every
# later `uv` call broken until they went looking for it. The two halves are one
# operation or neither.
case_failed_wrapper_write_restores_the_displaced_binary() {
  prepare_case "failed-wrapper-write-restores"
  mkdir -p "${HOME_DIR}/.local/bin"
  printf '#!/usr/bin/env bash\n# the real uv\necho uv-real\n' > "${HOME_DIR}/.local/bin/uv"
  chmod +x "${HOME_DIR}/.local/bin/uv"

  # Fail the chmod for the uv wrapper only, delegating everything else to the
  # real one: this exercises install.sh's own failure path, not a stub of it.
  local stubdir="${WORK_DIR}/failing-chmod"
  mkdir -p "${stubdir}"
  cat > "${stubdir}/chmod" <<'STUB'
#!/usr/bin/env bash
for arg in "$@"; do
  case "${arg}" in
    */uv) exit 1 ;;
  esac
done
exec /usr/bin/chmod "$@"
STUB
  chmod +x "${stubdir}/chmod"

  PATH="${stubdir}:${PATH}" HOME="${HOME_DIR}" bash "${ROOT_DIR}/install.sh" >"${OUT_FILE}" 2>"${ERR_FILE}"
  STATUS=$?
  # An install that could not gate what it was asked to gate exits non-zero.
  # Before the rollback existed, `set -e` did this; swallowing it would tell
  # automation and an operator reading $? that gating is active when it is not.
  assert_status 1 "$FUNCNAME" || return
  assert_err_contains_fragment 'these tools are NOT gated' "$FUNCNAME" || return

  # uv is back where its owner put it, executable, with no wrapper and no
  # leftover .original — and the installer said so instead of claiming success.
  grep -Fqx '# the real uv' "${HOME_DIR}/.local/bin/uv" || { fail "$FUNCNAME"; return; }
  [[ -x "${HOME_DIR}/.local/bin/uv" ]] || { fail "$FUNCNAME"; return; }
  [[ ! -e "${HOME_DIR}/.local/bin/uv.original" ]] || { fail "$FUNCNAME"; return; }
  assert_err_contains_fragment 'could not write gate wrappers for: uv' "$FUNCNAME" || return
  assert_err_not_contains_fragment 'gated them: uv' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_uninstall_restores_the_displaced_binary() {
  prepare_case "uninstall-restores-displaced"
  mkdir -p "${HOME_DIR}/.local/bin"
  printf '#!/usr/bin/env bash\n# the real uv\necho uv-real\n' > "${HOME_DIR}/.local/bin/uv"
  chmod +x "${HOME_DIR}/.local/bin/uv"
  HOME="${HOME_DIR}" bash "${ROOT_DIR}/install.sh" >"${OUT_FILE}" 2>"${ERR_FILE}"
  STATUS=$?
  assert_status 0 "$FUNCNAME" || return

  HOME="${HOME_DIR}" bash "${ROOT_DIR}/uninstall.sh" >>"${OUT_FILE}" 2>>"${ERR_FILE}"
  STATUS=$?
  assert_status 0 "$FUNCNAME" || return

  # Removing the gate must not uninstall the tool: uv goes back where its owner
  # put it, and the .original scaffolding disappears with the wrapper.
  grep -Fqx '# the real uv' "${HOME_DIR}/.local/bin/uv" || { fail "$FUNCNAME"; return; }
  [[ -x "${HOME_DIR}/.local/bin/uv" ]] || { fail "$FUNCNAME"; return; }
  [[ ! -e "${HOME_DIR}/.local/bin/uv.original" ]] || { fail "$FUNCNAME"; return; }
  # Managed scanner adapter follows the managed-file lifecycle: deployed by
  # install, removed by uninstall — a leftover with safe-audit gone makes
  # every scanner-configured host fail closed (PR#64 review F8).
  [[ ! -e "${HOME_DIR}/.config/safe/scanner.mjs" ]] || { fail "$FUNCNAME"; return; }
  [[ ! -e "${HOME_DIR}/.local/bin/safe-core" ]] || { fail "$FUNCNAME"; return; }
  pass "$FUNCNAME"
}

case_gate_resolves_a_displaced_original() {
  prepare_case "gate-resolves-displaced-original"
  local dir="${WORK_DIR}/displaced"
  mkdir -p "${dir}"
  printf '#!/usr/bin/env bash\n# safe-gate-wrapper v1 tool=uv\nexec safe gate uv -- "$@"\n' > "${dir}/uv"
  chmod +x "${dir}/uv"
  printf '#!/usr/bin/env bash\necho real\n' > "${dir}/uv.original"
  chmod +x "${dir}/uv.original"

  local got
  got="$(PATH="${dir}:/usr/bin:/bin" GATE_LIB="${ROOT_DIR}/lib/gate-lib.sh" \
    bash -c 'source "${GATE_LIB}"; safe_gate_resolve_real uv')"
  [[ "${got}" == "${dir}/uv.original" ]] || {
    printf 'resolved to %s, expected %s\n' "${got:-<empty>}" "${dir}/uv.original" >&2
    fail "$FUNCNAME"; return
  }

  # A real tool further along PATH still wins: the displaced copy is a last
  # resort, never an override of a version manager's shim.
  local shim="${WORK_DIR}/shimdir"
  mkdir -p "${shim}"
  printf '#!/usr/bin/env bash\necho shim\n' > "${shim}/uv"
  chmod +x "${shim}/uv"
  got="$(PATH="${dir}:${shim}:/usr/bin:/bin" GATE_LIB="${ROOT_DIR}/lib/gate-lib.sh" \
    bash -c 'source "${GATE_LIB}"; safe_gate_resolve_real uv')"
  [[ "${got}" == "${shim}/uv" ]] || {
    printf 'resolved to %s, expected %s\n' "${got:-<empty>}" "${shim}/uv" >&2
    fail "$FUNCNAME"; return
  }
  pass "$FUNCNAME"
}

case_gate_resolves_a_wrapped_mise_shim() {
  prepare_case "gate-resolves-wrapped-mise-shim"
  local bindir="${WORK_DIR}/gatebin" shimdir="${WORK_DIR}/miseshims"
  mkdir -p "${bindir}" "${shimdir}"
  # Our pnpm gate wrapper occupies the tool name in BIN_DIR.
  printf '#!/usr/bin/env bash\n# safe-gate-wrapper v1 tool=pnpm\nexec safe gate pnpm -- "$@"\n' > "${bindir}/pnpm"
  chmod +x "${bindir}/pnpm"
  # Our mise wrapper, with a mise shim symlinked onto it — the layout a mise
  # reshim produces while the wrapper shadows the real binary (2026-08-03:
  # discovery classified the shim as ours and every node tool exited 127).
  printf '#!/usr/bin/env bash\n# safe-gate-wrapper v1 tool=mise\nexec safe gate mise -- "$@"\n' > "${bindir}/mise"
  chmod +x "${bindir}/mise"
  ln -s "${bindir}/mise" "${shimdir}/pnpm"

  local got
  got="$(PATH="${bindir}:${shimdir}:/usr/bin:/bin" GATE_LIB="${ROOT_DIR}/lib/gate-lib.sh" \
    bash -c 'source "${GATE_LIB}"; safe_gate_resolve_real pnpm')"
  [[ "${got}" == "${shimdir}/pnpm" ]] || {
    printf 'resolved to %s, expected %s\n' "${got:-<empty>}" "${shimdir}/pnpm" >&2
    fail "$FUNCNAME"; return
  }

  # Resolving mise itself must still skip every wrapper: the real binary
  # further along PATH wins, never the wrapper occupying the name.
  local realbin="${WORK_DIR}/realbin"
  mkdir -p "${realbin}"
  printf '#!/usr/bin/env bash\necho real-mise\n' > "${realbin}/mise"
  chmod +x "${realbin}/mise"
  got="$(PATH="${bindir}:${shimdir}:${realbin}:/usr/bin:/bin" GATE_LIB="${ROOT_DIR}/lib/gate-lib.sh" \
    bash -c 'source "${GATE_LIB}"; safe_gate_resolve_real mise')"
  [[ "${got}" == "${realbin}/mise" ]] || {
    printf 'resolved to %s, expected %s\n' "${got:-<empty>}" "${realbin}/mise" >&2
    fail "$FUNCNAME"; return
  }
  pass "$FUNCNAME"
}

case_gate_exec_delegates_through_a_wrapped_mise_shim() {
  # End-to-end over the previous case (PR#63 review F1): discovery acceptance
  # and the argv0-dispatch contract are separate mechanisms — this drives
  # safe_gate_exec_real through the PRODUCTION-shaped mise wrapper and proves
  # the accepted shim delegate actually reaches the real mise with the tool's
  # args intact, never the gate.
  prepare_case "gate-exec-through-wrapped-mise-shim"
  local wrap="${WORK_DIR}/wrap" shimdir="${WORK_DIR}/miseshims" realbin="${WORK_DIR}/realbin"
  mkdir -p "${wrap}" "${shimdir}" "${realbin}"
  write_gate_wrappers "${wrap}"
  ln -s "${wrap}/mise" "${shimdir}/pnpm"
  cat > "${realbin}/mise" <<'STUB'
#!/usr/bin/env bash
printf 'REALMISE args=%s\n' "$*"
STUB
  chmod +x "${realbin}/mise"

  local out
  out="$(PATH="${wrap}:${shimdir}:${realbin}:/usr/bin:/bin" GATE_LIB="${ROOT_DIR}/lib/gate-lib.sh" \
    bash -c 'source "${GATE_LIB}"; safe_gate_exec_real pnpm --version' 2>&1)"
  # The shim dispatches argv0=pnpm through the wrapper's preamble to the real
  # mise, which receives the delegate's args. Any gate re-entry or dispatch
  # failure surfaces as different output (or the preamble's 127 message).
  if [[ "$out" != "REALMISE args=--version" ]]; then
    printf 'got: %s\n' "$out" >&2
    fail "$FUNCNAME"
    return
  fi
  pass "$FUNCNAME"
}

case_gate_audit_leash_fits_component_budgets() {
  # The leash must exceed the sum of the audit's internal budgets (Socket +
  # bounded-curl overhead), or a single hanging component turns a
  # legible infra WARN into TIMEOUT_FAILCLOSED (Socket outage 2026-08-04:
  # socket 30s hang vs 30s leash killed every uncached install).
  prepare_case "gate-audit-leash-arithmetic"
  local cfg="${WORK_DIR}/runcfg"
  mkdir -p "${cfg}"

  leash() {
    SAFE_RUN_CONFIG_DIR="${cfg}" GATE_LIB="${ROOT_DIR}/lib/gate-lib.sh" \
      "$@" bash -c 'source "${GATE_LIB}"; safe_gate_audit_leash_seconds'
  }

  leash_with_budgets() {
    SAFE_RUN_CONFIG_DIR="${cfg}" GATE_LIB="${ROOT_DIR}/lib/gate-lib.sh" \
      bash -c 'source "${GATE_LIB}"; safe_gate_audit_leash_seconds "$1" "$2"' -- "$1" "$2"
  }

  local got
  # No config: socket 15 x 2 attempts (auth-failure vault retry), then the
  # one 90s fresh-score call, each with the same two-attempt budget, plus
  # OSV 80*(4 versions + 1 cooldown re-query) and overhead 120.
  got="$(leash env)"
  [[ "${got}" == "730" ]] || { printf 'default leash %s, expected 730\n' "${got}" >&2; fail "$FUNCNAME"; return; }

  # The explicit operator override wins absolutely.
  got="$(leash env SAFE_INSTALL_TIMEOUT_SECONDS=42)"
  [[ "${got}" == "42" ]] || { printf 'override leash %s, expected 42\n' "${got}" >&2; fail "$FUNCNAME"; return; }

  # An invalid override is ignored, never handed to timeout(1) where it
  # would fail every audit as exit 125.
  got="$(leash env SAFE_INSTALL_TIMEOUT_SECONDS=soon)"
  [[ "${got}" == "730" ]] || { printf 'invalid-override leash %s, expected 730\n' "${got}" >&2; fail "$FUNCNAME"; return; }

  # An oversized override (>5 digits) is rejected the same way: unbounded
  # integers can wrap the arithmetic, and timeout(1) treats 0 as DISABLED.
  got="$(leash env SAFE_INSTALL_TIMEOUT_SECONDS=999999)"
  [[ "${got}" == "730" ]] || { printf 'oversized-override leash %s, expected 730\n' "${got}" >&2; fail "$FUNCNAME"; return; }

  # A caller-set socket budget participates in the arithmetic — counted
  # twice per socket_score_json call.
  got="$(leash env SAFE_AUDIT_SOCKET_TIMEOUT=9)"
  [[ "${got}" == "718" ]] || { printf 'socket-9 leash %s, expected 718\n' "${got}" >&2; fail "$FUNCNAME"; return; }

  # An overflow-sized socket budget falls back to 15, keeping the leash sane
  # (a raw 20-digit value wrapped the computed leash to exactly 0).
  got="$(leash env SAFE_AUDIT_SOCKET_TIMEOUT=18446744073709551436)"
  [[ "${got}" == "730" ]] || { printf 'overflow-socket leash %s, expected 730\n' "${got}" >&2; fail "$FUNCNAME"; return; }

  # The fresh-release score budget comes from the same config source and has
  # two-attempt term in the leash.
  printf '{"install":{"socket":{"fresh_scan_budget_seconds":45}}}\n' > "${cfg}/config.json"
  got="$(leash env)"
  [[ "${got}" == "640" ]] || { printf 'fresh-45 leash %s, expected 640\n' "${got}" >&2; fail "$FUNCNAME"; return; }
  got="$(leash env SAFE_AUDIT_SOCKET_FRESH_SCAN_TIMEOUT=9)"
  [[ "${got}" == "568" ]] || { printf 'fresh-env-9 leash %s, expected 568\n' "${got}" >&2; fail "$FUNCNAME"; return; }
  got="$(leash env SAFE_AUDIT_SOCKET_FRESH_SCAN_TIMEOUT=999999)"
  [[ "${got}" == "730" ]] || { printf 'fresh-overflow leash %s, expected 730\n' "${got}" >&2; fail "$FUNCNAME"; return; }
  got="$(leash_with_budgets 25 31)"
  [[ "${got}" == "632" ]] || { printf 'overridden-budgets leash %s, expected 632\n' "${got}" >&2; fail "$FUNCNAME"; return; }
  pass "$FUNCNAME"
}

case_gate_audit_receives_socket_budget() {
  # The gate hands the audit child its Socket sub-budget so the component
  # bound the leash arithmetic assumed is the one that actually applies —
  # and the PATH-injected timeout recorder pins the exact leash argv at the
  # REAL call site (a self-reported mirror could lie if the call site
  # regressed to a constant — delta N2).
  prepare_case "gate-audit-socket-budget"
  write_timeout_recorder "${BIN_DIR}"
  SAFE_INSTALL_TEST_SCRIPT='npm install left-pad@1.2.3' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDITENV\tSAFE_AUDIT_SOCKET_TIMEOUT=15' "$FUNCNAME" || return
  assert_log_contains $'AUDITENV\tSAFE_AUDIT_SOCKET_FRESH_SCAN_TIMEOUT=90' "$FUNCNAME" || return
  if ! grep -Fq $'TIMEOUTARGV\t--kill-after=2s\t730\t' "${LOG_FILE}"; then
    printf 'no timeout argv with the computed default leash\nlog:\n%s\n' "$(cat "${LOG_FILE}")" >&2
    fail "$FUNCNAME"
    return
  fi

  # A caller-set budget survives — the gate default never clobbers it — and
  # flows into the leash the call site actually applied (25*2 + 90*2 + 520).
  prepare_case "gate-audit-socket-budget-caller"
  write_timeout_recorder "${BIN_DIR}"
  SAFE_AUDIT_SOCKET_TIMEOUT=25 SAFE_INSTALL_TEST_SCRIPT='npm install left-pad@1.2.3' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDITENV\tSAFE_AUDIT_SOCKET_TIMEOUT=25' "$FUNCNAME" || return
  if ! grep -Fq $'TIMEOUTARGV\t--kill-after=2s\t750\t' "${LOG_FILE}"; then
    printf 'no timeout argv with the caller-budget leash\nlog:\n%s\n' "$(cat "${LOG_FILE}")" >&2
    fail "$FUNCNAME"
    return
  fi

  # A malformed caller value degrades to the gate default, not to garbage
  # reaching the audit's arithmetic.
  prepare_case "gate-audit-socket-budget-invalid"
  SAFE_AUDIT_SOCKET_TIMEOUT=soon SAFE_INSTALL_TEST_SCRIPT='npm install left-pad@1.2.3' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDITENV\tSAFE_AUDIT_SOCKET_TIMEOUT=15' "$FUNCNAME" || return

  # The fresh budget is propagated as its own bounded component and changes
  # the real timeout argv, not merely a mirror calculation.
  prepare_case "gate-audit-fresh-socket-budget-caller"
  write_timeout_recorder "${BIN_DIR}"
  SAFE_AUDIT_SOCKET_FRESH_SCAN_TIMEOUT=31 SAFE_INSTALL_TEST_SCRIPT='npm install left-pad@1.2.3' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDITENV\tSAFE_AUDIT_SOCKET_FRESH_SCAN_TIMEOUT=31' "$FUNCNAME" || return
  if ! grep -Fq $'TIMEOUTARGV\t--kill-after=2s\t612\t' "${LOG_FILE}"; then
    printf 'no timeout argv with the caller fresh-score budget\nlog:\n%s\n' "$(cat "${LOG_FILE}")" >&2
    fail "$FUNCNAME"
    return
  fi

  # The child env and timeout argv must derive from the exact captured reads.
  # This helper emits 31 once then 7: a leash that re-reads the fresh budget
  # would pass 31 to safe-audit but incorrectly calculate from 7.
  prepare_case "gate-audit-captured-socket-budgets"
  write_timeout_recorder "${BIN_DIR}"
  local fresh_budget_state="${CASE_DIR}/fresh-budget-state"
  printf '31\n' > "${fresh_budget_state}"
  if ! (
    PATH="${BIN_DIR}:/usr/bin:/bin"
    SAFE_GATE_AUDIT_BIN="${BIN_DIR}/safe-audit"
    SAFE_INSTALL_COMMAND_LOG="${LOG_FILE}"
    SAFE_RUN_CONFIG_DIR="${CASE_DIR}/runcfg"
    export PATH SAFE_GATE_AUDIT_BIN SAFE_INSTALL_COMMAND_LOG SAFE_RUN_CONFIG_DIR
    source "${ROOT_DIR}/lib/gate-lib.sh"
    safe_gate_socket_fresh_scan_budget() {
      local budget
      budget=$(<"${fresh_budget_state}")
      printf '7\n' > "${fresh_budget_state}"
      printf '%s\n' "${budget}"
    }
    safe_gate_run_audit left-pad@1.2.3 --ecosystem npm --gate install
  ) > "${OUT_FILE}" 2> "${ERR_FILE}"; then
    fail "$FUNCNAME"
    return
  fi
  assert_log_contains $'AUDITENV\tSAFE_AUDIT_SOCKET_FRESH_SCAN_TIMEOUT=31' "$FUNCNAME" || return
  if ! grep -Fq $'TIMEOUTARGV\t--kill-after=2s\t612\t' "${LOG_FILE}"; then
    printf 'captured fresh budget did not reach matching timeout argv\nlog:\n%s\n' "$(cat "${LOG_FILE}")" >&2
    fail "$FUNCNAME"
    return
  fi
  pass "$FUNCNAME"
}

case_run_all_excludes_live_socket_envelope() {
  if grep -Fqx '  tests/live/socket_envelope.sh' "${ROOT_DIR}/tests/run-all.sh"; then
    fail "$FUNCNAME"
    return
  fi
  if ! grep -Fq 'Run `bash tests/live/socket_envelope.sh` manually' \
    "${ROOT_DIR}/tests/live/socket_envelope.sh"; then
    fail "$FUNCNAME"
    return
  fi
  pass "$FUNCNAME"
}

case_gate_audit_fd_exhaustion_fails_closed() {
  # The audit status is assigned INSIDE the fd-shuffle group; if the group's
  # own redirection setup fails (fd exhaustion), the body never runs — a
  # zero-initialized status returned as a false audit GO (delta-3 N4,
  # fail-open reproduced at ulimit -n 4..5 on the pre-fix commit). The rc
  # must be nonzero whenever the audit did not complete.
  prepare_case "gate-audit-fd-exhaustion"
  printf '#!/usr/bin/env bash\nexit 10\n' > "${WORK_DIR}/safe-audit"
  chmod +x "${WORK_DIR}/safe-audit"

  run_audit_rc() {
    bash -c 'exec 2>/dev/null; ulimit -n "$1" || exit 97
      source "$2"
      SAFE_GATE_AUDIT_BIN="$3"
      safe_gate_run_audit pkg --ecosystem npm >/dev/null
      printf "%s\n" "$?"' fd-case "$1" "${ROOT_DIR}/lib/gate-lib.sh" "${WORK_DIR}/safe-audit" 2>/dev/null | tail -n 1
  }

  local lim got
  for lim in 4 5 6; do
    got="$(run_audit_rc "${lim}")"
    if [[ -z "${got}" || "${got}" == "0" ]]; then
      printf 'ulimit -n %s: audit rc %s — fd-setup failure returned as GO\n' "${lim}" "${got:-<none>}" >&2
      fail "$FUNCNAME"
      return
    fi
  done

  # Sanity: with enough descriptors the same harness reports the stub's
  # real WARN status, proving the assertion above exercised the gate and
  # not a broken fixture.
  got="$(run_audit_rc 64)"
  if [[ "${got}" != "10" ]]; then
    printf 'ulimit -n 64: audit rc %s, expected the stub 10\n' "${got:-<none>}" >&2
    fail "$FUNCNAME"
    return
  fi
  pass "$FUNCNAME"
}

case_gate_leash_kills_a_wedged_audit() {
  # Hard liveness of the backstop: the operator override reaches timeout(1)
  # at the call site (recorder argv), and a TERM-RESISTANT child dies to the
  # --kill-after escalation into the legible fail-closed refusal within
  # leash + kill-after + slack — never the child's own 15s, never a hang.
  prepare_case "gate-leash-kills-wedged-audit"
  write_timeout_recorder "${BIN_DIR}"
  local start_ts elapsed
  start_ts=${SECONDS}
  SAFE_INSTALL_TIMEOUT_SECONDS=1 SAFE_AUDIT_CHECK_SLEEP=15 SAFE_AUDIT_CHECK_TRAP_TERM=1 \
    SAFE_INSTALL_TEST_SCRIPT='npm install left-pad@1.2.3' run_zsh
  elapsed=$(( SECONDS - start_ts ))
  assert_status 100 "$FUNCNAME" || return
  if ! grep -Fq 'safe audit timed out (fail closed)' "${ERR_FILE}"; then
    printf 'stderr:\n%s\n' "$(cat "${ERR_FILE}")" >&2
    fail "$FUNCNAME"
    return
  fi
  # Single final stderr line (operator contract): the KILL escalation must
  # not leak the shell's own "Killed ..." job diagnostic ahead of the
  # refusal (delta-2 N3 — GNU timeout signals its own group and dies of the
  # KILL it sends).
  if [[ "$(wc -l < "${ERR_FILE}")" != "1" ]] || grep -q 'Killed' "${ERR_FILE}"; then
    printf 'refusal is not the single stderr line:\n%s\n' "$(cat "${ERR_FILE}")" >&2
    fail "$FUNCNAME"
    return
  fi
  if ! grep -Fq $'TIMEOUTARGV\t--kill-after=2s\t1\t' "${LOG_FILE}"; then
    printf 'override leash never reached the call site\nlog:\n%s\n' "$(cat "${LOG_FILE}")" >&2
    fail "$FUNCNAME"
    return
  fi
  if (( elapsed > 10 )); then
    printf 'refusal took %ss — the KILL escalation did not bound the TERM-resistant child\n' "${elapsed}" >&2
    fail "$FUNCNAME"
    return
  fi
  if grep -F $'REAL\tnpm' "${LOG_FILE}" | grep -q install; then
    printf 'delegate ran despite the timeout refusal\n' >&2
    fail "$FUNCNAME"
    return
  fi
  pass "$FUNCNAME"
}

case_selective_install_refreshes_gate_lib() {
  prepare_case "selective-install-refreshes-gate-lib"
  # Release A: full install, then simulate a stale installed gate library.
  HOME="${HOME_DIR}" bash "${ROOT_DIR}/install.sh" >"${OUT_FILE}" 2>"${ERR_FILE}"
  STATUS=$?
  assert_status 0 "$FUNCNAME" || return
  printf '# STALE SENTINEL — release A library\n' > "${HOME_DIR}/.config/safe/gate-lib.sh"

  # Release B run in a selective mode that skips wrapper generation: the
  # dispatcher and its active library are one upgrade unit, so the library
  # must be refreshed anyway (review finding: wrappers kept loading an old
  # vulnerable library after `install.sh --run`).
  HOME="${HOME_DIR}" bash "${ROOT_DIR}/install.sh" --run >>"${OUT_FILE}" 2>>"${ERR_FILE}"
  STATUS=$?
  assert_status 0 "$FUNCNAME" || return
  if grep -Fq 'STALE SENTINEL' "${HOME_DIR}/.config/safe/gate-lib.sh"; then
    fail "$FUNCNAME"
    return
  fi
  cmp -s "${ROOT_DIR}/lib/gate-lib.sh" "${HOME_DIR}/.config/safe/gate-lib.sh" || { fail "$FUNCNAME"; return; }

  # Damaged installation: NO installed library and NO npm wrapper, but one
  # owned non-npm wrapper still gating. The npm-only probe missed this and
  # left the library unrestored, so pnpm refused for want of a library
  # (delta finding 2). Any owned wrapper must trigger the refresh, in every
  # selective mode.
  local mode
  for mode in --run --audit --no-wrappers; do
    rm -f "${HOME_DIR}/.config/safe/gate-lib.sh" "${HOME_DIR}/.local/bin/npm"
    printf '#!/usr/bin/env bash\n# safe-gate-wrapper v1 tool=pnpm\nexec safe gate pnpm -- "$@"\n' > "${HOME_DIR}/.local/bin/pnpm"
    chmod +x "${HOME_DIR}/.local/bin/pnpm"
    HOME="${HOME_DIR}" bash "${ROOT_DIR}/install.sh" "${mode}" >>"${OUT_FILE}" 2>>"${ERR_FILE}"
    STATUS=$?
    assert_status 0 "$FUNCNAME" || return
    [[ -f "${HOME_DIR}/.config/safe/gate-lib.sh" ]] || {
      printf 'mode %s did not restore the gate library for a non-npm wrapper\n' "${mode}" >&2
      fail "$FUNCNAME"
      return
    }
    cmp -s "${ROOT_DIR}/lib/gate-lib.sh" "${HOME_DIR}/.config/safe/gate-lib.sh" || {
      printf 'mode %s restored a library that is not the shipped one\n' "${mode}" >&2
      fail "$FUNCNAME"
      return
    }
  done
  pass "$FUNCNAME"
}

case_loose_marker_is_not_ownership() {
  prepare_case "loose-marker-not-ownership"
  mkdir -p "${HOME_DIR}/.local/bin"
  # A foreign file merely MENTIONING the marker phrase is not ours: neither
  # install (overwrite) nor uninstall (delete) may touch it. Exact per-tool
  # second-line markers only (review finding 5).
  printf '#!/usr/bin/env bash\n# vendored helper based on safe-gate-wrapper ideas\necho real-yarn "$@"\n' > "${HOME_DIR}/.local/bin/yarn"
  chmod +x "${HOME_DIR}/.local/bin/yarn"
  # A wrapper-marked file for the WRONG tool is foreign too.
  printf '#!/usr/bin/env bash\n# safe-gate-wrapper v1 tool=npm\nexec safe gate npm -- "$@"\n' > "${HOME_DIR}/.local/bin/cargo"
  chmod +x "${HOME_DIR}/.local/bin/cargo"
  # A symlink to a marked file must never be followed and truncated.
  printf '#!/usr/bin/env bash\n# safe-gate-wrapper v1 tool=go\nexec safe gate go -- "$@"\n' > "${HOME_DIR}/marked-target"
  ln -s "${HOME_DIR}/marked-target" "${HOME_DIR}/.local/bin/go"
  # A foreign BINARY whose second line carries NUL bytes: reading it into a
  # shell variable made bash warn "ignored null byte in input" from every
  # ownership probe (round regression R1). It is foreign, it survives, and the
  # probe must stay quiet about it.
  printf '#!/usr/bin/env bash\n\0\0binary\0payload\n' > "${HOME_DIR}/.local/bin/bun"
  chmod +x "${HOME_DIR}/.local/bin/bun"

  HOME="${HOME_DIR}" bash "${ROOT_DIR}/install.sh" >"${OUT_FILE}" 2>"${ERR_FILE}"
  STATUS=$?
  assert_status 0 "$FUNCNAME" || return
  grep -Fq 'echo real-yarn' "${HOME_DIR}/.local/bin/yarn" || { fail "$FUNCNAME"; return; }
  grep -Fq 'tool=npm' "${HOME_DIR}/.local/bin/cargo" || { fail "$FUNCNAME"; return; }
  [[ -L "${HOME_DIR}/.local/bin/go" ]] || { fail "$FUNCNAME"; return; }
  grep -Fq 'tool=go' "${HOME_DIR}/marked-target" || { fail "$FUNCNAME"; return; }
  grep -Fq 'binary' "${HOME_DIR}/.local/bin/bun" || { fail "$FUNCNAME"; return; }
  assert_err_contains_fragment 'gating NOT active for:' "$FUNCNAME" || return
  # R1: the ownership probe must not narrate about binary neighbours.
  assert_err_not_contains_fragment 'null byte' "$FUNCNAME" || return
  assert_err_not_contains_fragment 'warning:' "$FUNCNAME" || return

  HOME="${HOME_DIR}" bash "${ROOT_DIR}/uninstall.sh" >>"${OUT_FILE}" 2>>"${ERR_FILE}"
  STATUS=$?
  assert_status 0 "$FUNCNAME" || return
  [[ -f "${HOME_DIR}/.local/bin/yarn" ]] || { fail "$FUNCNAME"; return; }
  [[ -f "${HOME_DIR}/.local/bin/cargo" ]] || { fail "$FUNCNAME"; return; }
  [[ -L "${HOME_DIR}/.local/bin/go" && -f "${HOME_DIR}/marked-target" ]] || { fail "$FUNCNAME"; return; }
  [[ -f "${HOME_DIR}/.local/bin/bun" ]] || { fail "$FUNCNAME"; return; }
  assert_err_not_contains_fragment 'null byte' "$FUNCNAME" || return

  # The binary occupant must READ as foreign — an ownership probe that cannot
  # parse it must not fall back to owning it — and status/doctor must stay
  # quiet while saying so.
  local probe_err="${CASE_DIR}/probe.err" probe_out="${CASE_DIR}/probe.out"
  (cd "${WORK_DIR}" && HOME="${HOME_DIR}" PATH="${HOME_DIR}/.local/bin:/usr/bin:/bin" \
    "${ROOT_DIR}/bin/safe" status >"${probe_out}") 2>"${probe_err}" || true
  grep -Fq 'bun:foreign' "${probe_out}" || {
    printf 'binary occupant did not read as foreign:\n%s\n' "$(cat "${probe_out}")" >&2
    fail "$FUNCNAME"
    return
  }
  if grep -Fq 'null byte' "${probe_err}"; then
    printf 'status narrated about a binary neighbour:\n%s\n' "$(cat "${probe_err}")" >&2
    fail "$FUNCNAME"
    return
  fi
  (cd "${WORK_DIR}" && HOME="${HOME_DIR}" PATH="${HOME_DIR}/.local/bin:/usr/bin:/bin" \
    "${ROOT_DIR}/bin/safe" doctor --json >"${probe_out}") 2>"${probe_err}" || true
  jq -e '.environment.install_wrappers.gate_wrappers.bun == "foreign"
     and .environment.install_wrappers.gate_wrappers_healthy == false' "${probe_out}" >/dev/null || {
    printf 'doctor did not report the binary occupant as foreign:\n%s\n' "$(cat "${probe_out}")" >&2
    fail "$FUNCNAME"
    return
  }
  if grep -Fq 'null byte' "${probe_err}"; then
    printf 'doctor narrated about a binary neighbour:\n%s\n' "$(cat "${probe_err}")" >&2
    fail "$FUNCNAME"
    return
  fi
  pass "$FUNCNAME"
}

case_status_probes_every_wrapper() {
  prepare_case "status-probes-every-wrapper"
  HOME="${HOME_DIR}" bash "${ROOT_DIR}/install.sh" >"${OUT_FILE}" 2>"${ERR_FILE}"
  STATUS=$?
  assert_status 0 "$FUNCNAME" || return

  # Healthy: every wrapper resolves to its owned file.
  local status_out
  status_out="$(cd "${WORK_DIR}" && HOME="${HOME_DIR}" PATH="${HOME_DIR}/.local/bin:/usr/bin:/bin" "${HOME_DIR}/.local/bin/safe" status 2>/dev/null)"
  grep -Fq 'wrappers:       ok (12/12' <<<"${status_out}" || { printf '%s\n' "${status_out}" >&2; fail "$FUNCNAME"; return; }

  # A missing non-npm wrapper must flip the aggregate (review finding: an
  # npm-only probe concealed ungated siblings).
  rm -f "${HOME_DIR}/.local/bin/pnpm"
  status_out="$(cd "${WORK_DIR}" && HOME="${HOME_DIR}" PATH="${HOME_DIR}/.local/bin:/usr/bin:/bin" "${HOME_DIR}/.local/bin/safe" status 2>/dev/null)"
  grep -Fq 'DEGRADED' <<<"${status_out}" || { printf '%s\n' "${status_out}" >&2; fail "$FUNCNAME"; return; }
  grep -Fq 'pnpm:missing' <<<"${status_out}" || { printf '%s\n' "${status_out}" >&2; fail "$FUNCNAME"; return; }

  # doctor --json reports the same per-tool map.
  local doctor_out
  doctor_out="$(cd "${WORK_DIR}" && HOME="${HOME_DIR}" PATH="${HOME_DIR}/.local/bin:/usr/bin:/bin" "${HOME_DIR}/.local/bin/safe" doctor --json 2>/dev/null)"
  jq -e '.environment.install_wrappers.gate_wrappers.pnpm == "missing" and .environment.install_wrappers.gate_wrappers_healthy == false' <<<"${doctor_out}" >/dev/null || { printf '%s\n' "${doctor_out}" >&2; fail "$FUNCNAME"; return; }
  pass "$FUNCNAME"
}

case_dash_bin_root_never_reports_healthy() {
  prepare_case "dash-bin-root-state"
  HOME="${HOME_DIR}" bash "${ROOT_DIR}/install.sh" >"${OUT_FILE}" 2>"${ERR_FILE}"
  STATUS=$?
  assert_status 0 "$FUNCNAME" || return

  # A relative dash-leading SAFE_BIN_DIR made both readlink calls parse the
  # path as options: empty == empty reported `installed` while spraying
  # readlink diagnostics (delta-2 finding N2). With anchored operands the
  # state must be COMPUTED, not defaulted: from a cwd where the relative
  # path resolves, `installed` is truthful and stderr stays clean; from a
  # cwd where it does not, the wrapper canonicalization fails and the state
  # must be the unhealthy `not-on-path`, never a false `installed`.
  mkdir -p "${WORK_DIR}/-gate"
  cp "${HOME_DIR}/.local/bin/npm" "${WORK_DIR}/-gate/npm"
  local status_out status_err
  status_out="$(cd "${WORK_DIR}" && HOME="${HOME_DIR}" SAFE_BIN_DIR='-gate' PATH="-gate:/usr/bin:/bin" "${HOME_DIR}/.local/bin/safe" status 2>"${CASE_DIR}/status-err.log")"
  status_err="$(cat "${CASE_DIR}/status-err.log")"
  if grep -Eq '(^|[[:space:]])npm:(foreign|missing|not-on-path|shadowed)' <<<"${status_out}"; then
    printf 'resolvable relative bin root misreported npm:\n%s\n' "${status_out}" >&2
    fail "$FUNCNAME"
    return
  fi
  if grep -q 'readlink' <<<"${status_err}"; then
    printf 'readlink diagnostics leaked:\n%s\n' "${status_err}" >&2
    fail "$FUNCNAME"
    return
  fi
  status_out="$(cd "${HOME_DIR}" && HOME="${HOME_DIR}" SAFE_BIN_DIR='-gate' PATH="/usr/bin:/bin" "${HOME_DIR}/.local/bin/safe" status 2>"${CASE_DIR}/status-err2.log")"
  if grep -Fq 'npm:installed' <<<"${status_out}"; then
    printf 'unresolvable relative bin root reported healthy:\n%s\n' "${status_out}" >&2
    fail "$FUNCNAME"
    return
  fi
  if grep -q 'readlink' "${CASE_DIR}/status-err2.log"; then
    printf 'readlink diagnostics leaked (second probe)\n' >&2
    fail "$FUNCNAME"
    return
  fi
  pass "$FUNCNAME"
}

case_wrappers_not_on_path_are_unhealthy() {
  prepare_case "wrappers-not-on-path"
  HOME="${HOME_DIR}" bash "${ROOT_DIR}/install.sh" >"${OUT_FILE}" 2>"${ERR_FILE}"
  STATUS=$?
  assert_status 0 "$FUNCNAME" || return

  # The cron/service shape: installed `safe` invoked by ABSOLUTE path from a
  # PATH that omits ~/.local/bin. The owned wrapper files exist but do not
  # resolve, so they gate nothing — reporting "installed" claimed health for an
  # ungated machine (delta finding 3).
  #
  # PATH must keep /usr/bin:/bin (safe's own `#!/usr/bin/env bash` and its jq /
  # sed / date calls live there), so which managers still resolve depends on
  # the host: those found under /usr/bin are `shadowed`, the rest are
  # `not-on-path`. The expectation is therefore computed from the same PATH
  # rather than hardcoded — and the case fails loudly if the host cannot
  # exercise the not-on-path branch at all.
  local probe_path="/usr/bin:/bin"
  local -a expect_unresolved=() expect_shadowed=()
  local tool
  for tool in npm pnpm pnpx yarn bun pip pip3 uv cargo go composer mise; do
    if [[ -n "$(PATH="${probe_path}" command -v "${tool}" 2>/dev/null || true)" ]]; then
      expect_shadowed+=("${tool}")
    else
      expect_unresolved+=("${tool}")
    fi
  done
  if [[ "${#expect_unresolved[@]}" -eq 0 ]]; then
    printf 'host resolves all 11 managers under %s; cannot exercise not-on-path\n' "${probe_path}" >&2
    fail "$FUNCNAME"
    return
  fi

  local status_out doctor_out
  status_out="$(cd "${WORK_DIR}" && HOME="${HOME_DIR}" PATH="${probe_path}" "${HOME_DIR}/.local/bin/safe" status 2>/dev/null)"
  grep -Fq 'DEGRADED' <<<"${status_out}" || { printf '%s\n' "${status_out}" >&2; fail "$FUNCNAME"; return; }
  for tool in "${expect_unresolved[@]}"; do
    grep -Fq "${tool}:not-on-path" <<<"${status_out}" || {
      printf 'expected %s:not-on-path in status:\n%s\n' "${tool}" "${status_out}" >&2
      fail "$FUNCNAME"
      return
    }
  done
  for tool in "${expect_shadowed[@]}"; do
    grep -Fq "${tool}:shadowed" <<<"${status_out}" || {
      printf 'expected %s:shadowed in status:\n%s\n' "${tool}" "${status_out}" >&2
      fail "$FUNCNAME"
      return
    }
  done

  # No tool may report installed here, and the aggregate must be unhealthy.
  doctor_out="$(cd "${WORK_DIR}" && HOME="${HOME_DIR}" PATH="${probe_path}" "${HOME_DIR}/.local/bin/safe" doctor --json 2>/dev/null)"
  jq -e --arg t "${expect_unresolved[0]}" '
    .environment.install_wrappers.gate_wrappers_healthy == false
    and .environment.install_wrappers.gate_wrappers[$t] == "not-on-path"
    and ([.environment.install_wrappers.gate_wrappers[] | select(. == "installed")] | length == 0)
  ' <<<"${doctor_out}" >/dev/null || { printf '%s\n' "${doctor_out}" >&2; fail "$FUNCNAME"; return; }

  # A non-npm tool shadowed by an EARLIER PATH entry is unhealthy too, and is
  # reported as shadowed rather than not-on-path.
  local shadow_bin="${CASE_DIR}/shadow"
  mkdir -p "${shadow_bin}"
  printf '#!/usr/bin/env bash\necho foreign-cargo\n' > "${shadow_bin}/cargo"
  chmod +x "${shadow_bin}/cargo"
  status_out="$(cd "${WORK_DIR}" && HOME="${HOME_DIR}" PATH="${shadow_bin}:${HOME_DIR}/.local/bin:/usr/bin:/bin" "${HOME_DIR}/.local/bin/safe" status 2>/dev/null)"
  grep -Fq 'cargo:shadowed' <<<"${status_out}" || { printf '%s\n' "${status_out}" >&2; fail "$FUNCNAME"; return; }
  grep -Fq 'DEGRADED' <<<"${status_out}" || { fail "$FUNCNAME"; return; }
  pass "$FUNCNAME"
}

case_uv_index_selectors_reach_audit() {
  prepare_case "uv-index-selectors-reach-audit"
  # Every uv fetch path accepts index selectors; dropping them audited PyPI
  # while uv installed from the custom index (review finding 1).
  SAFE_INSTALL_TEST_SCRIPT='uv tool install --default-index https://packages.example blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tpython\t--gate\tinstall\t--op\tinstall\t--registry\thttps://packages.example' "$FUNCNAME" || return

  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='uv pip install --index-url=https://pypi.example blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tpython\t--gate\tinstall\t--op\tinstall\t--registry\thttps://pypi.example' "$FUNCNAME" || return

  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='uv run --index https://idx.example --with blockme script.py' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tpython\t--gate\tinstall\t--op\tinstall\t--registry\thttps://idx.example' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_uninstall_removes_gate_wrappers() {
  prepare_case "uninstall-removes-gate-wrappers"
  HOME="${HOME_DIR}" bash "${ROOT_DIR}/install.sh" >"${OUT_FILE}" 2>"${ERR_FILE}"
  STATUS=$?
  assert_status 0 "$FUNCNAME" || return
  printf '#!/usr/bin/env bash\n# not ours\n' > "${HOME_DIR}/.local/bin/composer"

  HOME="${HOME_DIR}" bash "${ROOT_DIR}/uninstall.sh" >>"${OUT_FILE}" 2>>"${ERR_FILE}"
  STATUS=$?
  assert_status 0 "$FUNCNAME" || return

  local tool
  for tool in npm pnpm pnpx yarn bun pip pip3 uv cargo go mise; do
    [[ ! -e "${HOME_DIR}/.local/bin/${tool}" ]] || { fail "$FUNCNAME"; return; }
  done
  # Unmarked file of a wrapped name: not ours, not removed.
  grep -Fqx '# not ours' "${HOME_DIR}/.local/bin/composer" || { fail "$FUNCNAME"; return; }
  [[ ! -e "${HOME_DIR}/.config/safe/gate-lib.sh" ]] || { fail "$FUNCNAME"; return; }
  pass "$FUNCNAME"
}

case_install_cleans_legacy_safe_install_artifacts() {
  prepare_case "install-cleans-legacy-safe-install-artifacts"
  mkdir -p "${HOME_DIR}/.config/safe-run/completions" "${HOME_DIR}/.local/bin"
  cat > "${HOME_DIR}/.zshrc" <<'EOF'
# safe-install persistent install wrappers
source "$HOME/.config/safe-run/install-wrappers.zsh"
# safe-install zsh completions
fpath=("$HOME/.config/safe-run/completions" $fpath)
EOF
  printf 'legacy wrapper\n' > "${HOME_DIR}/.config/safe-run/install-wrappers.zsh"
  printf 'legacy completion\n' > "${HOME_DIR}/.config/safe-run/completions/_safe-install"
  printf '#!/usr/bin/env bash\n' > "${HOME_DIR}/.local/bin/safe-install"
  chmod +x "${HOME_DIR}/.local/bin/safe-install"

  HOME="${HOME_DIR}" bash "${ROOT_DIR}/install.sh" >"${OUT_FILE}" 2>"${ERR_FILE}"
  STATUS=$?
  assert_status 0 "$FUNCNAME" || return
  [[ ! -e "${HOME_DIR}/.local/bin/safe-install" ]] || { fail "$FUNCNAME"; return; }
  [[ ! -e "${HOME_DIR}/.config/safe-run/install-wrappers.zsh" ]] || { fail "$FUNCNAME"; return; }
  [[ ! -e "${HOME_DIR}/.config/safe-run/completions/_safe-install" ]] || { fail "$FUNCNAME"; return; }
  assert_count 0 'source "$HOME/.config/safe-run/install-wrappers.zsh"' "${HOME_DIR}/.zshrc" "$FUNCNAME" || return
  assert_count 0 'fpath=("$HOME/.config/safe-run/completions" $fpath)' "${HOME_DIR}/.zshrc" "$FUNCNAME" || return
  assert_count 1 'source "$HOME/.config/safe/install-wrappers.zsh"' "${HOME_DIR}/.zshrc" "$FUNCNAME" || return
  assert_count 1 'fpath=("$HOME/.local/share/zsh/site-functions" $fpath)' "${HOME_DIR}/.zshrc" "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_install_preserves_symlinked_zshrc() {
  prepare_case "install-preserves-symlinked-zshrc"
  local zshrc_target="${HOME_DIR}/MichelLinux/config/zsh/.zshrc"
  mkdir -p "$(dirname "${zshrc_target}")" "${HOME_DIR}/.config/safe-run/completions" "${HOME_DIR}/.local/bin"
  cat > "${zshrc_target}" <<'EOF'
export SAFE_TEST_ZSHRC=1
source "$HOME/.config/safe-run/install-wrappers.zsh"
fpath=("$HOME/.config/safe-run/completions" $fpath)
EOF
  ln -s "${zshrc_target}" "${HOME_DIR}/.zshrc"
  printf 'legacy wrapper\n' > "${HOME_DIR}/.config/safe-run/install-wrappers.zsh"
  printf 'legacy completion\n' > "${HOME_DIR}/.config/safe-run/completions/_safe-install"
  printf '#!/usr/bin/env bash\n' > "${HOME_DIR}/.local/bin/safe-install"
  chmod +x "${HOME_DIR}/.local/bin/safe-install"

  HOME="${HOME_DIR}" bash "${ROOT_DIR}/install.sh" >"${OUT_FILE}" 2>"${ERR_FILE}"
  STATUS=$?
  assert_status 0 "$FUNCNAME" || return
  [[ -L "${HOME_DIR}/.zshrc" ]] || { fail "$FUNCNAME"; return; }
  [[ "$(readlink "${HOME_DIR}/.zshrc")" == "${zshrc_target}" ]] || { fail "$FUNCNAME"; return; }
  grep -Fqx 'export SAFE_TEST_ZSHRC=1' "${zshrc_target}" || { fail "$FUNCNAME"; return; }
  assert_count 0 'source "$HOME/.config/safe-run/install-wrappers.zsh"' "${zshrc_target}" "$FUNCNAME" || return
  assert_count 0 'fpath=("$HOME/.config/safe-run/completions" $fpath)' "${zshrc_target}" "$FUNCNAME" || return
  assert_count 1 'source "$HOME/.config/safe/install-wrappers.zsh"' "${zshrc_target}" "$FUNCNAME" || return
  assert_count 1 'fpath=("$HOME/.local/share/zsh/site-functions" $fpath)' "${zshrc_target}" "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_install_merges_legacy_state_into_new_schema() {
  prepare_case "install-merges-legacy-state-into-new-schema"
  mkdir -p \
    "${HOME_DIR}/.config/safe-run" \
    "${HOME_DIR}/.config/safe-audit" \
    "${HOME_DIR}/.config/safe/run" \
    "${HOME_DIR}/.config/safe/audit" \
    "${HOME_DIR}/.local/share/safe-run" \
    "${HOME_DIR}/.local/share/safe-audit/checks" \
    "${HOME_DIR}/.local/share/safe-audit/results/remote-a.local" \
    "${HOME_DIR}/.local/share/safe-audit/sbom/remote-a.local" \
    "${HOME_DIR}/.local/share/safe/run" \
    "${HOME_DIR}/.local/share/safe/audit/results"

  cat > "${HOME_DIR}/.config/safe-run/blocked.json" <<'EOF'
{"packages":{"legacy-blocked":{"reason":"legacy reason"}}}
EOF
  cat > "${HOME_DIR}/.config/safe-run/host-allow.json" <<'EOF'
{"packages":{"legacy-allow":{"version":"1.2.3","reason":"legacy allow"}}}
EOF
  cat > "${HOME_DIR}/.config/safe-run/sandbox-known.json" <<'EOF'
{"packages":{"legacy-known":{"last_version":"2.0.0"}}}
EOF
  cat > "${HOME_DIR}/.config/safe-run/config.json" <<'EOF'
{"defaults":{"node_version":"24","python_version":"3.14"},"runners":{"npx_real":null,"bunx_real":null,"uvx_real":null,"pipx_real":null},"sandbox":{"pids_limit":256,"memory":"2g","cpus":"2","ulimit_nofile":"1024:1024","timeout_seconds":300},"warn_env_files":false,"linked_targets":["legacy-target"]}
EOF

  cat > "${HOME_DIR}/.config/safe/run/blocked.json" <<'EOF'
{"packages":{"new-blocked":{"reason":"new reason"}}}
EOF
  cat > "${HOME_DIR}/.config/safe/run/host-allow.json" <<'EOF'
{"packages":{"new-allow":{"version":"9.9.9","reason":"new allow"}}}
EOF
  cat > "${HOME_DIR}/.config/safe/run/sandbox-known.json" <<'EOF'
{"packages":{"new-known":{"last_version":"8.0.0"}}}
EOF
  cat > "${HOME_DIR}/.config/safe/run/config.json" <<'EOF'
{"defaults":{"node_version":"22","python_version":"3.12"},"runners":{"npx_real":null,"bunx_real":null,"uvx_real":null,"pipx_real":null},"sandbox":{"pids_limit":128,"memory":"1g","cpus":"1","ulimit_nofile":"512:512","timeout_seconds":120},"warn_env_files":true,"linked_targets":["new-target"]}
EOF

  cat > "${HOME_DIR}/.config/safe-audit/machines.json" <<'EOF'
{"machines":{"local":{"type":"local","scan_root":"/legacy/dev"},"remote-a":{"type":"ssh","host":"remote-a.local"}}}
EOF
  cat > "${HOME_DIR}/.config/safe-audit/tools.json" <<'EOF'
{"local":{"socket":"/legacy/socket"},"remote-a.local":{"syft":"/legacy/syft"}}
EOF
  cat > "${HOME_DIR}/.config/safe/audit/machines.json" <<'EOF'
{"machines":{"local":{"type":"local"},"remote-a":{"type":"ssh","host":"remote-a"}}}
EOF
  cat > "${HOME_DIR}/.config/safe/audit/tools.json" <<'EOF'
{"local":{"socket":"/new/socket"}}
EOF

  printf 'legacy-run-log\n' > "${HOME_DIR}/.local/share/safe-run/audit.log"
  printf 'new-run-log\n' > "${HOME_DIR}/.local/share/safe/run/audit.log"
  printf '{"legacy":true}\n' > "${HOME_DIR}/.local/share/safe-audit/checks/legacy-check.json"
  printf 'legacy-host-allow\n' > "${HOME_DIR}/.local/share/safe-audit/host-allow-log.jsonl"
  printf '{"scan":"legacy"}\n' > "${HOME_DIR}/.local/share/safe-audit/results/remote-a.local/2026-01-01-scan.json"
  printf '{"sbom":"legacy"}\n' > "${HOME_DIR}/.local/share/safe-audit/sbom/remote-a.local/2026-01-01-sbom.cdx.json"

  HOME="${HOME_DIR}" bash "${ROOT_DIR}/install.sh" --no-wrappers >"${OUT_FILE}" 2>"${ERR_FILE}"
  STATUS=$?
  assert_status 0 "$FUNCNAME" || return

  jq -e '.packages["legacy-blocked"] and .packages["new-blocked"]' "${HOME_DIR}/.config/safe/run/blocked.json" >/dev/null || { fail "$FUNCNAME"; return; }
  jq -e '.packages["legacy-allow"] and .packages["new-allow"]' "${HOME_DIR}/.config/safe/run/host-allow.json" >/dev/null || { fail "$FUNCNAME"; return; }
  jq -e '.packages["legacy-known"] and .packages["new-known"]' "${HOME_DIR}/.config/safe/run/sandbox-known.json" >/dev/null || { fail "$FUNCNAME"; return; }
  jq -e '.warn_env_files == false and (.linked_targets | index("legacy-target")) and (.linked_targets | index("new-target"))' "${HOME_DIR}/.config/safe/run/config.json" >/dev/null || { fail "$FUNCNAME"; return; }

  jq -e '.machines.local.scan_root == "/legacy/dev" and .machines["remote-a"].host == "remote-a.local"' "${HOME_DIR}/.config/safe/audit/machines.json" >/dev/null || { fail "$FUNCNAME"; return; }
  jq -e '.local.socket == "/legacy/socket" and .["remote-a"].syft == "/legacy/syft"' "${HOME_DIR}/.config/safe/audit/tools.json" >/dev/null || { fail "$FUNCNAME"; return; }

  grep -Fqx 'new-run-log' "${HOME_DIR}/.local/share/safe/run/audit.log" || { fail "$FUNCNAME"; return; }
  grep -Fqx 'legacy-run-log' "${HOME_DIR}/.local/share/safe/run/audit.log" || { fail "$FUNCNAME"; return; }
  [[ -f "${HOME_DIR}/.local/share/safe/audit/checks/legacy-check.json" ]] || { fail "$FUNCNAME"; return; }
  grep -Fqx 'legacy-host-allow' "${HOME_DIR}/.local/share/safe/audit/host-allow-log.jsonl" || { fail "$FUNCNAME"; return; }
  [[ -f "${HOME_DIR}/.local/share/safe/audit/results/remote-a/2026-01-01-scan.json" ]] || { fail "$FUNCNAME"; return; }
  [[ -f "${HOME_DIR}/.local/share/safe/audit/sbom/remote-a/2026-01-01-sbom.cdx.json" ]] || { fail "$FUNCNAME"; return; }
  pass "$FUNCNAME"
}

case_uninstall_preserves_symlinked_zshrc() {
  prepare_case "uninstall-preserves-symlinked-zshrc"
  local zshrc_target="${HOME_DIR}/MichelLinux/config/zsh/.zshrc"
  mkdir -p "$(dirname "${zshrc_target}")" "${HOME_DIR}/.local/share/zsh/site-functions" "${HOME_DIR}/.config/safe-run/completions"
  cat > "${zshrc_target}" <<'EOF'
export SAFE_TEST_ZSHRC=1
source "$HOME/.config/safe/install-wrappers.zsh"
fpath=("$HOME/.local/share/zsh/site-functions" $fpath)
source "$HOME/.config/safe-run/install-wrappers.zsh"
fpath=("$HOME/.config/safe-run/completions" $fpath)
EOF
  ln -s "${zshrc_target}" "${HOME_DIR}/.zshrc"
  printf 'current completion\n' > "${HOME_DIR}/.local/share/zsh/site-functions/_safe"
  printf 'legacy completion\n' > "${HOME_DIR}/.config/safe-run/completions/_safe-install"

  HOME="${HOME_DIR}" bash "${ROOT_DIR}/uninstall.sh" >"${OUT_FILE}" 2>"${ERR_FILE}"
  STATUS=$?
  assert_status 0 "$FUNCNAME" || return
  [[ -L "${HOME_DIR}/.zshrc" ]] || { fail "$FUNCNAME"; return; }
  [[ "$(readlink "${HOME_DIR}/.zshrc")" == "${zshrc_target}" ]] || { fail "$FUNCNAME"; return; }
  grep -Fqx 'export SAFE_TEST_ZSHRC=1' "${zshrc_target}" || { fail "$FUNCNAME"; return; }
  assert_count 0 'source "$HOME/.config/safe/install-wrappers.zsh"' "${zshrc_target}" "$FUNCNAME" || return
  assert_count 0 'fpath=("$HOME/.local/share/zsh/site-functions" $fpath)' "${zshrc_target}" "$FUNCNAME" || return
  assert_count 0 'source "$HOME/.config/safe-run/install-wrappers.zsh"' "${zshrc_target}" "$FUNCNAME" || return
  assert_count 0 'fpath=("$HOME/.config/safe-run/completions" $fpath)' "${zshrc_target}" "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_pip_cumulative_sources_all_reach_audit() {
  prepare_case "pip-cumulative-sources"
  # pip considers BOTH --find-links and the index; a later trusted selector
  # must not erase the earlier untrusted one (delta-2 finding 3).
  # find-links records its actual endpoint (not a blanket sentinel) so an
  # operator can trust the specific location (delta-5 finding 3.2).
  SAFE_INSTALL_TEST_SCRIPT='pip install --find-links https://evil.example/wheels --index-url https://pypi.org/simple blockme==1.0.0' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme@1.0.0\t--ecosystem\tpython\t--gate\tinstall\t--op\tinstall\t--registry\thttps://evil.example/wheels https://pypi.org/simple' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_scoped_and_userconfig_sources_reach_audit() {
  prepare_case "npm-scoped-userconfig-sources"
  # Raw scoped registry flags are source selectors npm honors on the
  # command line; --userconfig swaps in a whole config file whose registry
  # keys become effective (delta-5 finding 3.2).
  # The scoped selector keeps its KEY: flattening the bare URL let the
  # resolver pick a different scope's registry (delta-6 finding 3.2b).
  SAFE_INSTALL_TEST_SCRIPT='npm install --@demo:registry=https://scoped.example @demo/pkg@1.2.3' run_zsh
  assert_log_contains $'AUDIT\tcheck\t@demo/pkg@1.2.3\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall\t--registry\t@demo:registry=https://scoped.example' "$FUNCNAME" || return

  # The prev-form scoped flag consumes its value: without that, the URL is
  # parsed as an extra PACKAGE and audited (delta-7 finding 3.2b).
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='npm install --@foo:registry https://foo.example @foo/pkg@1.2.3' run_zsh
  assert_log_contains $'AUDIT\tcheck\t@foo/pkg@1.2.3\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall\t--registry\t@foo:registry=https://foo.example' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'check\thttps://foo.example' "$FUNCNAME" || return

  # Alternate config files thread as PATHS — value extraction lost key and
  # precedence semantics and copied credentials into argv (delta-7 findings
  # 3.2b/N2).
  : > "${LOG_FILE}"
  printf 'registry=https://userconf.example/\n@demo:registry=https://scopedconf.example\n' > "${WORK_DIR}/alt-npmrc"
  SAFE_INSTALL_TEST_SCRIPT='npm install --userconfig alt-npmrc okpkg@1.0.0' run_zsh
  assert_log_contains $'AUDIT\tcheck\tokpkg@1.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall\t--npm-userconfig\talt-npmrc' "$FUNCNAME" || return
  assert_log_not_contains_fragment 'userconf.example' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_gate_never_leaks_sources_to_the_real_tool() {
  prepare_case "gate-no-source-leak"
  # The zsh suite asserts the wrapper CLEARS SAFE_INSTALL_REGISTRY after the
  # gate, because a long-lived interactive shell would otherwise retain a
  # credential-bearing set (delta-7 N2 / delta-8 N2). Gate mode has no such
  # state to clear — the scan happens inside the `safe gate` process, which
  # exits — so that assertion is structurally unfalsifiable here and was
  # passing vacuously after the merge. The equivalent live risk on this
  # branch is the set reaching the DELEGATED tool's environment, which the
  # stub reports as ENVLEAK.
  SAFE_INSTALL_TEST_SCRIPT='npm install --registry https://alice:sekret@mirror.example okpkg@1.0.0' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tinstall\t--registry\thttps://alice:sekret@mirror.example\tokpkg@1.0.0' "$FUNCNAME" || return
  assert_log_not_contains_fragment 'ENVLEAK' "$FUNCNAME" || return

  # The project-install route (no positional package) scans too.
  SAFE_INSTALL_TEST_SCRIPT='npm install --registry https://alice:sekret@mirror.example' run_zsh
  assert_log_not_contains_fragment 'ENVLEAK' "$FUNCNAME" || return

  # And the credential must not reach the calling shell either.
  SAFE_INSTALL_TEST_SCRIPT='npm install --registry https://alice:sekret@mirror.example okpkg@1.0.0; print -r -u2 -- "POST=[${SAFE_GATE_REGISTRY:-}][${SAFE_INSTALL_REGISTRY:-}]"' run_zsh
  assert_err_contains_fragment 'POST=[][]' "$FUNCNAME" || return

  # Bash assignment preserves a pre-existing EXPORT attribute: a caller that
  # exported a scanner name must not turn the gate's overwrite into an
  # inherited credential in the delegate (delta-2 finding P2). Both routes;
  # the calling shell keeps only its original sentinel.
  SAFE_INSTALL_TEST_SCRIPT='export SAFE_GATE_REGISTRY=sentinel SAFE_GATE_DIST_TAG=sentinel SAFE_GATE_PROJECT_DIR=sentinel SAFE_GATE_NPM_USERCONFIG=sentinel SAFE_GATE_NPM_GLOBALCONFIG=sentinel; npm install --registry https://alice:sekret@mirror.example okpkg@1.0.0; print -r -u2 -- "POSTX=[${SAFE_GATE_REGISTRY:-}]"' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tokpkg@1.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall\t--registry\thttps://alice:sekret@mirror.example' "$FUNCNAME" || return
  assert_log_not_contains_fragment 'ENVLEAK' "$FUNCNAME" || return
  assert_err_contains_fragment 'POSTX=[sentinel]' "$FUNCNAME" || return

  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='export SAFE_GATE_REGISTRY=sentinel; npm install --registry https://alice:sekret@mirror.example' run_zsh
  assert_log_not_contains_fragment 'ENVLEAK' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_source_credentials_preserved_for_audit() {
  prepare_case "source-credentials-operational"
  # The accumulated set is OPERATIONAL: safe-audit needs the credentials to
  # fetch packuments from authenticated registries — pre-redacting here
  # broke those installs (delta-6 finding N2). Redaction happens centrally
  # in safe-audit at every identity/receipt/display sink (covered in the
  # audit suite).
  SAFE_INSTALL_TEST_SCRIPT='npm install --registry https://alice:sekret@mirror.example/ okpkg@1.0.0' run_zsh
  assert_log_contains $'AUDIT\tcheck\tokpkg@1.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall\t--registry\thttps://alice:sekret@mirror.example' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_repeated_registry_keeps_true_last() {
  prepare_case "npm-repeated-registry-last"
  # npm is last-wins: A B A means npm installs from A. Deduplication must
  # move the repeat to the END so the resolver's last-word read matches
  # npm's choice (delta-4 finding 3.1).
  SAFE_INSTALL_TEST_SCRIPT='npm install -g --registry https://a.example --registry https://b.example --registry https://a.example okpkg@1.0.0' run_zsh
  assert_log_contains $'AUDIT\tcheck\tokpkg@1.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall\t--registry\thttps://b.example https://a.example' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_stale_evidence_is_source_scoped() {
  prepare_case "stale-evidence-source-scoped"
  mkdir -p "${HOME_DIR}/.config/safe/run"
  printf '{"packages": {"npm:okpkg": {"version": "1.0.0", "verdict": "GO", "reasons": [], "evidence": "x", "source": "implicit-default", "first_allowed": "%s", "last_used": "2026-07-31", "times_used": 1}}}\n' \
    "$(date -Iseconds)" > "${HOME_DIR}/.config/safe/run/install-known.json"

  # Same source (implicit default): the fresh GO receipt may carry an audit
  # timeout.
  SAFE_AUDIT_CHECK_STATUS=124 SAFE_INSTALL_TEST_SCRIPT='npm install -g okpkg@1.0.0' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tinstall\t-g\tokpkg@1.0.0' "$FUNCNAME" || return
  assert_err_contains_fragment 'stale evidence' "$FUNCNAME" || return

  # Different source: default-registry evidence must NOT vouch for a custom
  # index (delta-2 finding 5) — fail closed.
  : > "${LOG_FILE}"
  SAFE_AUDIT_CHECK_STATUS=124 SAFE_INSTALL_TEST_SCRIPT='npm install -g --registry https://evil.example okpkg@1.0.0' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm' "$FUNCNAME" || return

  # A literal selector spelled "default" is an EXPLICIT source: it must not
  # collide with the implicit-default sentinel (delta-3 finding 5).
  : > "${LOG_FILE}"
  SAFE_AUDIT_CHECK_STATUS=124 SAFE_INSTALL_TEST_SCRIPT='npm install -g --registry default okpkg@1.0.0' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm' "$FUNCNAME" || return

  # An env-configured registry is part of the effective source even with no
  # argv selector: implicit-default evidence must not vouch for it (delta-3
  # finding 3.2).
  : > "${LOG_FILE}"
  SAFE_AUDIT_CHECK_STATUS=124 SAFE_INSTALL_TEST_SCRIPT='NPM_CONFIG_REGISTRY=https://evil.example npm install -g okpkg@1.0.0' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm' "$FUNCNAME" || return

  # Legacy source-less receipts map to implicit default only.
  printf '{"packages": {"npm:okpkg": {"version": "1.0.0", "verdict": "GO", "reasons": [], "evidence": "x", "first_allowed": "%s", "last_used": "2026-07-31", "times_used": 1}}}\n' \
    "$(date -Iseconds)" > "${HOME_DIR}/.config/safe/run/install-known.json"
  : > "${LOG_FILE}"
  SAFE_AUDIT_CHECK_STATUS=124 SAFE_INSTALL_TEST_SCRIPT='npm install -g okpkg@1.0.0' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tinstall\t-g\tokpkg@1.0.0' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_mise_use_backend_audits() {
  prepare_case "mise-use-backend-audits"
  SAFE_INSTALL_TEST_SCRIPT='mise use npm:blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tmise' "$FUNCNAME" || return

  SAFE_INSTALL_TEST_SCRIPT='mise use npm:okpkg@1.2.3' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tokpkg@1.2.3\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_contains $'REAL\tmise\tuse\tnpm:okpkg@1.2.3' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_mise_runtime_and_other_backends_pass() {
  prepare_case "mise-runtime-passes"
  # Official runtimes are not registry packages; no audit.
  SAFE_INSTALL_TEST_SCRIPT='mise install node@22' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_log_contains $'REAL\tmise\tinstall\tnode@22' "$FUNCNAME" || return

  # Non-registry backends pass with a notice (no advisory source).
  SAFE_INSTALL_TEST_SCRIPT='mise install ubi:owner/tool' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_err_contains_fragment 'no registry advisory source' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_mise_bare_install_preflights_config() {
  prepare_case "mise-bare-install-preflight"
  # One backend tool not installed yet -> audited; blockme blocks the run.
  MISE_LS_JSON='{"node": [{"version": "22.0.0", "requested_version": "22.0.0", "installed": true}], "npm:blockme": [{"version": "1.0.0", "requested_version": "1.0.0", "installed": false}]}' \
    SAFE_INSTALL_TEST_SCRIPT='mise install' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme@1.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tmise' "$FUNCNAME" || return

  # Everything installed and pinned -> nothing audited, delegate runs.
  : > "${LOG_FILE}"
  MISE_LS_JSON='{"npm:okpkg": [{"version": "1.0.0", "requested_version": "1.0.0", "installed": true}]}' \
    SAFE_INSTALL_TEST_SCRIPT='mise install' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_log_contains $'REAL\tmise\tinstall' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_mise_bare_upgrade_audits_floating() {
  prepare_case "mise-bare-upgrade-floating"
  # Installed but floating (requested "latest") can change on `mise up`.
  MISE_LS_JSON='{"npm:blockme": [{"version": "1.0.0", "requested_version": "latest", "installed": true}]}' \
    SAFE_INSTALL_TEST_SCRIPT='mise up' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return

  # Pinned + installed cannot change without a config edit -> no audit.
  : > "${LOG_FILE}"
  MISE_LS_JSON='{"npm:blockme": [{"version": "1.0.0", "requested_version": "1.0.0", "installed": true}]}' \
    SAFE_INSTALL_TEST_SCRIPT='mise up' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_mise_exec_gates_inner_command() {
  prepare_case "mise-exec-gates-inner"
  SAFE_INSTALL_TEST_SCRIPT='mise exec -- npm install blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tmise' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm' "$FUNCNAME" || return

  # Tool specs before -- install on demand: audited too.
  SAFE_INSTALL_TEST_SCRIPT='mise exec npm:blockme -- blockme --help' run_zsh
  assert_status 104 "$FUNCNAME" || return

  # Non-gated inner command passes through to the real mise (which owns env).
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='mise exec -- node script.js' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_log_contains $'REAL\tmise\texec\t--\tnode\tscript.js' "$FUNCNAME" || return

  # Gated-but-clean inner command: audited once, then the ORIGINAL mise
  # command runs (the gate must not exec the inner npm itself).
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='mise exec -- npm install okpkg' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tokpkg\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_contains $'REAL\tmise\texec\t--\tnpm\tinstall\tokpkg' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_mise_leading_flag_fails_closed() {
  prepare_case "mise-leading-flag"
  SAFE_INSTALL_TEST_SCRIPT='mise --frobnicate value install npm:blockme' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'REAL' "$FUNCNAME" || return
  # -C consumes its value; the subcommand is still found and gated. The
  # audit runs FROM that directory (delta-1 finding 8), so it must exist —
  # a -C into a nonexistent directory is a broken command either way.
  SAFE_INSTALL_TEST_SCRIPT='mkdir -p sub; mise -C sub install npm:blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return

  # A -C target that does not exist refuses as infrastructure rather than
  # auditing from the wrong directory.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='mise -C no-such-dir install npm:blockme' run_zsh
  assert_status 100 "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_mise_bare_shorthand_resolves_backend() {
  prepare_case "mise-bare-shorthand"
  # Bare shorthands resolve to their effective backend via `mise registry`
  # (which reflects MISE_BACKENDS_* overrides itself): a registry shorthand
  # is a registry install and must be audited (review finding 1).
  SAFE_INSTALL_TEST_SCRIPT='mise install prettier@3' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tprettier@3\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_contains $'REAL\tmise\tinstall\tprettier@3' "$FUNCNAME" || return

  # A blocked package blocks through the shorthand too.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='mise install blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tmise' "$FUNCNAME" || return

  # Backend override visible through registry resolution: what mise would
  # actually install is what gets audited, not the runtime the name suggests.
  : > "${LOG_FILE}"
  MISE_REGISTRY_OUT='npm:cowsay' SAFE_INSTALL_TEST_SCRIPT='mise install node@22' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tcowsay@22\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return

  # A true runtime still passes without an audit.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='mise install node@22' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_log_contains $'REAL\tmise\tinstall\tnode@22' "$FUNCNAME" || return

  # Unresolvable name: refuse with infrastructure wording, never guess.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='mise install no-such-tool-xyz' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'REAL' "$FUNCNAME" || return
  assert_err_contains_fragment 'not a package verdict' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_mise_bare_config_pinned_names_the_spec() {
  prepare_case "mise-bare-config-pinned-hint"
  # A bare name the registry cannot resolve but the config pins under one
  # backend is a spelling problem with one exact fix: the refusal names the
  # configured spec. mise itself will not act on the bare form (it reads it
  # as a registry/plugin shorthand), so resolving-and-proceeding would audit
  # an artifact the delegate never touches — the hint is the only sound fix
  # (inbox 2026-08-06 mise notes; live: @agentclientprotocol/…).
  MISE_LS_JSON='{"npm:@scope/agent-tool": [{"version": "0.59.0", "requested_version": "0.59.0", "installed": true}]}' \
    SAFE_INSTALL_TEST_SCRIPT='mise upgrade @scope/agent-tool' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tmise' "$FUNCNAME" || return
  assert_err_contains_fragment "rerun with the full spec 'npm:@scope/agent-tool'" "$FUNCNAME" || return
  assert_err_not_contains_fragment 'not a package verdict' "$FUNCNAME" || return

  # Same hint on the install/use path — and the leading-@ scope must not be
  # read as a version separator (splitting on the first @ emptied the name
  # and misread the spec as malformed).
  : > "${LOG_FILE}"
  MISE_LS_JSON='{"npm:@scope/agent-tool": [{"version": "0.59.0", "requested_version": "0.59.0", "installed": true}]}' \
    SAFE_INSTALL_TEST_SCRIPT='mise use @scope/agent-tool' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tmise' "$FUNCNAME" || return
  assert_err_contains_fragment "rerun with the full spec 'npm:@scope/agent-tool'" "$FUNCNAME" || return

  # Two backends pinning the same tool name: ambiguous — never guess a
  # hint; the infrastructure framing stays.
  : > "${LOG_FILE}"
  MISE_LS_JSON='{"npm:sametool": [{"version": "1.0.0", "requested_version": "1.0.0", "installed": true}], "cargo:sametool": [{"version": "1.0.0", "requested_version": "1.0.0", "installed": true}]}' \
    SAFE_INSTALL_TEST_SCRIPT='mise use sametool' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tmise' "$FUNCNAME" || return
  assert_err_contains_fragment 'not a package verdict' "$FUNCNAME" || return

  # The rerun hint is behavior-preserving: the version and neutral options
  # the operator typed survive the name replacement — a hint that drops
  # '@1.2' or a platform selector points at a different artifact (PR#69
  # review F1). Exactly one refusal line either way.
  : > "${LOG_FILE}"; : > "${ERR_FILE}"
  MISE_LS_JSON='{"npm:@scope/agent-tool": [{"version": "0.59.0", "requested_version": "0.59.0", "installed": true}]}' \
    SAFE_INSTALL_TEST_SCRIPT='mise use @scope/agent-tool@1.2' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_err_contains_fragment "rerun with the full spec 'npm:@scope/agent-tool@1.2'" "$FUNCNAME" || return
  local hint_lines
  hint_lines="$(grep -c 'safe:' "${ERR_FILE}" 2>/dev/null || printf '0')"
  if [[ "${hint_lines}" != "1" ]]; then
    printf 'expected exactly one safe: line, got %s:\n' "${hint_lines}" >&2
    cat "${ERR_FILE}" >&2
    fail "$FUNCNAME"
    return
  fi
  : > "${LOG_FILE}"
  MISE_LS_JSON='{"npm:@scope/agent-tool": [{"version": "0.59.0", "requested_version": "0.59.0", "installed": true}]}' \
    SAFE_INSTALL_TEST_SCRIPT='mise use "@scope/agent-tool[platform=linux]@1.2"' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_err_contains_fragment "rerun with the full spec 'npm:@scope/agent-tool[platform=linux]@1.2'" "$FUNCNAME" || return

  # Duplicate rows of the SAME key (several configured requests) are one
  # logical match, not an ambiguity.
  : > "${LOG_FILE}"
  MISE_LS_JSON='{"npm:@scope/agent-tool": [{"version": "0.59.0", "requested_version": "0.59.0", "installed": true}, {"version": "0.60.0", "requested_version": "0.60.0", "installed": false}]}' \
    SAFE_INSTALL_TEST_SCRIPT='mise use @scope/agent-tool' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_err_contains_fragment "rerun with the full spec 'npm:@scope/agent-tool'" "$FUNCNAME" || return

  # A colonless (core-style) row never becomes hint material and does not
  # spoil the unique backend match beside it.
  : > "${LOG_FILE}"
  MISE_LS_JSON='{"sametool": [{"version": "1.0.0", "requested_version": "1.0.0", "installed": true}], "npm:sametool": [{"version": "1.0.0", "requested_version": "1.0.0", "installed": true}]}' \
    SAFE_INSTALL_TEST_SCRIPT='mise use sametool' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_err_contains_fragment "rerun with the full spec 'npm:sametool'" "$FUNCNAME" || return

  # Config enumeration failure: no hint, infrastructure framing, refusal.
  : > "${LOG_FILE}"
  MISE_LS_STATUS=1 MISE_LS_JSON='{"npm:@scope/agent-tool": [{"version": "0.59.0", "requested_version": "0.59.0", "installed": true}]}' \
    SAFE_INSTALL_TEST_SCRIPT='mise use @scope/agent-tool' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tmise' "$FUNCNAME" || return
  assert_err_contains_fragment 'not a package verdict' "$FUNCNAME" || return

  # Degenerate leading-@ shapes that now reach resolution instead of the
  # malformed refusal: still refused, never delegated.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='mise use @' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tmise' "$FUNCNAME" || return
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='mise use @scope/' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tmise' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_mise_spec_canonicalization() {
  prepare_case "mise-spec-canonicalization"
  # Tool options are mise syntax, not package identity (review finding 2):
  # the audit must see the canonical name.
  SAFE_INSTALL_TEST_SCRIPT='mise use "npm:okpkg[platform=linux]@1.2.3"' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tokpkg@1.2.3\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return

  # Unbalanced bracket syntax fails closed.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='mise use "npm:okpkg[package_manager=npm@1.2.3"' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'REAL' "$FUNCNAME" || return

  # pipx owner/repo is a GitHub shorthand, not a PyPI identity: a clean
  # PyPI audit of the unrelated name must never vouch for it; same for
  # git+/URL forms in any backend (review finding 2). Notice path instead.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='mise use pipx:psf/blockme@24.3.0' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_err_contains_fragment 'not audit-gated' "$FUNCNAME" || return
  assert_log_contains $'REAL\tmise\tuse\tpipx:psf/blockme@24.3.0' "$FUNCNAME" || return

  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='mise install cargo:https://github.com/x/blockme' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_err_contains_fragment 'not audit-gated' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_mise_preflight_fails_closed() {
  prepare_case "mise-preflight-fails-closed"
  # Enumeration failure must refuse, not fall open as "nothing configured"
  # (review finding 3); the refusal reads as infrastructure, never a CVE.
  MISE_LS_STATUS=1 SAFE_INSTALL_TEST_SCRIPT='mise install' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tmise' "$FUNCNAME" || return
  assert_err_contains_fragment 'not a package verdict' "$FUNCNAME" || return

  : > "${LOG_FILE}"
  MISE_LS_JSON='this is not json' SAFE_INSTALL_TEST_SCRIPT='mise install' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tmise' "$FUNCNAME" || return

  : > "${LOG_FILE}"
  MISE_LS_JSON='[]' SAFE_INSTALL_TEST_SCRIPT='mise up' run_zsh
  assert_status 100 "$FUNCNAME" || return

  # A validated empty enumeration is a real empty set: delegate.
  : > "${LOG_FILE}"
  MISE_LS_JSON='{}' SAFE_INSTALL_TEST_SCRIPT='mise install' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'REAL\tmise\tinstall' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_mise_install_flags_are_modeled() {
  prepare_case "mise-install-flags"
  # A value flag's value must not read as a tool spec — that skipped the
  # bare-install preflight entirely (review finding 4).
  MISE_LS_JSON='{"npm:blockme": [{"version": "1.0.0", "requested_version": "1.0.0", "installed": false}]}' \
    SAFE_INSTALL_TEST_SCRIPT='mise install --jobs 1' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tmise' "$FUNCNAME" || return

  # Scope-changing flags the preflight cannot model refuse.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='mise install --monorepo' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'REAL' "$FUNCNAME" || return

  # -C threads into the enumeration query: the preflight sees the same
  # config scope the delegated command will install from.
  : > "${LOG_FILE}"
  MISE_LS_JSON='{}' SAFE_INSTALL_TEST_SCRIPT='mise install -C sub' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'MISEQ\t-C\tsub\tls\t--current\t--json' "$FUNCNAME" || return

  # Unknown equals-forms fail closed (review finding 10)...
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='mise --frobnicate=value install npm:blockme' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'REAL' "$FUNCNAME" || return

  # ...while current global switches stay legal (refusing --locked would
  # regress a security-conscious invocation).
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='mise --locked install npm:blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_mise_up_numeric_floating_and_bump() {
  prepare_case "mise-up-numeric-floating"
  # "3" is a floating selector under mise semantics — a first-character
  # digit heuristic called it a pin and skipped the audit (review finding 5).
  MISE_LS_JSON='{"npm:blockme": [{"version": "3.0.0", "requested_version": "3", "installed": true}]}' \
    SAFE_INSTALL_TEST_SCRIPT='mise up' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme@3\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return

  # An exact pin cannot move on plain `up`...
  : > "${LOG_FILE}"
  MISE_LS_JSON='{"npm:blockme": [{"version": "1.0.0", "requested_version": "1.0.0", "installed": true}]}' \
    SAFE_INSTALL_TEST_SCRIPT='mise up' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return

  # ...but `up --bump` can move even exact pins: everything is audited.
  : > "${LOG_FILE}"
  MISE_LS_JSON='{"npm:blockme": [{"version": "1.0.0", "requested_version": "1.0.0", "installed": true}]}' \
    SAFE_INSTALL_TEST_SCRIPT='mise up --bump' run_zsh
  assert_status 104 "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_mise_exec_auto_install_preflight() {
  prepare_case "mise-exec-auto-install"
  # exec auto-installs missing configured tools before running the command
  # (review finding 6): with the setting on, the missing entry is audited.
  MISE_EXEC_AUTO_INSTALL=true \
    MISE_LS_JSON='{"npm:blockme": [{"version": "1.0.0", "requested_version": "1.0.0", "installed": false}]}' \
    SAFE_INSTALL_TEST_SCRIPT='mise exec -- node script.js' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tmise' "$FUNCNAME" || return

  # Setting validated off: no preflight, straight delegate.
  : > "${LOG_FILE}"
  MISE_EXEC_AUTO_INSTALL=false SAFE_INSTALL_TEST_SCRIPT='mise exec -- node script.js' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_log_contains $'REAL\tmise\texec\t--\tnode\tscript.js' "$FUNCNAME" || return

  # -c hides the command in a shell string safe cannot parse: fail closed
  # with the argv rewrite hint (operator-ratified; review finding 7).
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='mise exec -c "npm install blockme"' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'REAL' "$FUNCNAME" || return
  assert_err_contains_fragment 'mise exec -- <command>' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_mise_env_overlay_reaches_audit() {
  prepare_case "mise-env-overlay"
  # Project [env] selects the sources mise installs under: the audit runs
  # with the same vars exported, or a default-registry GO vouches for a
  # different artifact (review finding 8).
  MISE_ENV_JSON='{"NPM_CONFIG_REGISTRY": "https://mirror.example", "PATH": "/x"}' \
    SAFE_INSTALL_TEST_SCRIPT='mise install npm:okpkg@1.0.0' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDITENV\tNPM_CONFIG_REGISTRY=https://mirror.example' "$FUNCNAME" || return

  # The inner exec gate scans under the same overlay.
  : > "${LOG_FILE}"
  MISE_ENV_JSON='{"NPM_CONFIG_REGISTRY": "https://mirror.example"}' \
    SAFE_INSTALL_TEST_SCRIPT='mise exec -- npm install okpkg@1.0.0' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDITENV\tNPM_CONFIG_REGISTRY=https://mirror.example' "$FUNCNAME" || return

  # Deriving the env is load-bearing: failure refuses with infrastructure
  # wording, never audits against the wrong default source.
  : > "${LOG_FILE}"
  MISE_ENV_STATUS=1 SAFE_INSTALL_TEST_SCRIPT='mise install npm:okpkg@1.0.0' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_err_contains_fragment 'not a package verdict' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_mise_bare_use_refused() {
  prepare_case "mise-bare-use"
  # Bare `mise use` opens the interactive registry selector and installs
  # the choice after safe already returned: unauditable, refuse with the
  # explicit-spec hint (operator-ratified; review finding 9).
  SAFE_INSTALL_TEST_SCRIPT='mise use' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'REAL' "$FUNCNAME" || return
  assert_err_contains_fragment 'mise use <tool>@<version>' "$FUNCNAME" || return

  # Removal installs nothing: still delegates.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='mise use --remove node' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'REAL\tmise\tuse\t--remove\tnode' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_mise_flag_semantics_match_delegate() {
  prepare_case "mise-flag-semantics"
  # --force reinstalls entries mise reports as INSTALLED: a
  # not-installed-only enumeration audited nothing while everything was
  # refetched (delta-1 finding N1).
  MISE_LS_JSON='{"npm:blockme": [{"version": "1.0.0", "requested_version": "1.0.0", "installed": true}]}' \
    SAFE_INSTALL_TEST_SCRIPT='mise install --force' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tmise' "$FUNCNAME" || return

  # --exclude names what mise will NOT touch: auditing it blocked an
  # install that is not happening (delta-1 finding 4).
  : > "${LOG_FILE}"
  MISE_LS_JSON='{"npm:blockme": [{"version": "1.0.0", "requested_version": "latest", "installed": true}]}' \
    SAFE_INSTALL_TEST_SCRIPT='mise upgrade --exclude npm:blockme' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_log_contains $'REAL\tmise\tupgrade\t--exclude\tnpm:blockme' "$FUNCNAME" || return

  # --minimum-release-age makes mise pick an older release than safe would
  # check: refuse for anything but an exact pin.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='mise install --minimum-release-age 7d npm:okpkg' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'REAL' "$FUNCNAME" || return

  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='mise install --minimum-release-age 7d npm:okpkg@1.0.0' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tokpkg@1.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return

  # Counted verbosity is legal mise; refusing -vvv was a usability
  # regression (delta-1 finding 10).
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='mise -vvv install npm:blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_mise_display_only_invocations_pass() {
  prepare_case "mise-display-only"
  # help/version/dry-run install nothing: gating them blocked read-only
  # commands and hid the rewrite hints the refusals point at (delta-1
  # finding N3).
  MISE_LS_JSON='{"npm:blockme": [{"version": "1.0.0", "requested_version": "1.0.0", "installed": false}]}' \
    SAFE_INSTALL_TEST_SCRIPT='mise install --help' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_log_contains $'REAL\tmise\tinstall\t--help' "$FUNCNAME" || return

  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='mise use --help' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'REAL\tmise\tuse\t--help' "$FUNCNAME" || return

  : > "${LOG_FILE}"
  MISE_LS_JSON='{"npm:blockme": [{"version": "1.0.0", "requested_version": "1.0.0", "installed": false}]}' \
    SAFE_INSTALL_TEST_SCRIPT='mise install --dry-run' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return

  # A --help AFTER -- belongs to the inner command and must not disarm the
  # gate.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='mise exec -- npm install blockme --help' run_zsh
  assert_status 104 "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_mise_helper_queries_use_delegate_context() {
  prepare_case "mise-helper-context"
  # Every helper query must run under the SAME context as the delegate: a
  # project's disable_backends changes which backend mise picks, so a
  # context-free registry query can classify a package as a runtime
  # (delta-1 finding 1).
  SAFE_INSTALL_TEST_SCRIPT='mkdir -p sub; mise -C sub install prettier' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'MISEQ\t-C\tsub\tregistry\t--\tprettier' "$FUNCNAME" || return

  # Config/env-disabling switches travel too, or safe enumerates a config
  # the delegate never loads (delta-1 findings 6/8).
  : > "${LOG_FILE}"
  MISE_LS_JSON='{}' SAFE_INSTALL_TEST_SCRIPT='mise --no-env install' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'MISEQ\t--no-env\tls\t--current\t--json' "$FUNCNAME" || return

  : > "${LOG_FILE}"
  MISE_LS_JSON='{}' SAFE_INSTALL_TEST_SCRIPT='mise --no-config install' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'MISEQ\t--no-config\tls\t--current\t--json' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_mise_env_transport_is_lossless() {
  prepare_case "mise-env-transport"
  # A value containing a newline must not split into two exported
  # variables — that injected a source mise's single value never named
  # (delta-1 finding N2). Base64 framing keeps it one value.
  MISE_ENV_JSON='{"PIP_CONFIG_FILE": "/tmp/intended\nPIP_INDEX_URL=https://injected.example"}' \
    SAFE_INSTALL_TEST_SCRIPT='pip install okpkg==1.0.0' run_zsh >/dev/null 2>&1
  : > "${LOG_FILE}"
  MISE_ENV_JSON='{"PIP_CONFIG_FILE": "/tmp/intended\nPIP_INDEX_URL=https://injected.example"}' \
    SAFE_INSTALL_TEST_SCRIPT='mise install pipx:okpkg@1.0.0' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDITENV\tPIP_INDEX_URL=https://injected.example' "$FUNCNAME" || return

  # A relevant key whose value is not a string is malformed helper output,
  # not "absent": refuse instead of auditing the default source.
  : > "${LOG_FILE}"
  MISE_ENV_JSON='{"NPM_CONFIG_REGISTRY": 42}' \
    SAFE_INSTALL_TEST_SCRIPT='mise install npm:okpkg@1.0.0' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_err_contains_fragment 'not a package verdict' "$FUNCNAME" || return

  # A DEFINED cargo registry index is inert until something selects it —
  # defining is not selecting — but it must still ride the overlay so the
  # audit's own derivation sees it if registry.default names it (PR6).
  : > "${LOG_FILE}"
  MISE_ENV_JSON='{"CARGO_REGISTRIES_PRIVATE_INDEX": "sparse+https://private.example/"}' \
    SAFE_INSTALL_TEST_SCRIPT='mise install cargo:okpkg@1.0.0' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tokpkg@1.0.0\t--ecosystem\trust\t--gate\tinstall\t--op\tinstall\t--installer\tcargo' "$FUNCNAME" || return
  assert_log_contains $'AUDITENV\tCARGO_REGISTRIES_PRIVATE_INDEX=sparse+https://private.example/' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_mise_tool_options_are_not_discarded() {
  prepare_case "mise-tool-options"
  # Options like npm_args reach the installer and can redirect the source:
  # auditing the plain name would vouch for a different artifact (delta-1
  # finding 2). Only identity-neutral keys keep the audit.
  SAFE_INSTALL_TEST_SCRIPT='mise use "npm:okpkg[npm_args=--registry=https://evil.example]@1.0.0"' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_err_contains_fragment 'not audit-gated' "$FUNCNAME" || return

  # An identity-neutral option still gets a real audit.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='mise use "npm:blockme[bin_path=bin]@1.0.0"' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme@1.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return

  # package_manager selects npm/pnpm/bun, whose native source inputs differ
  # (bun reads BUN_CONFIG_REGISTRY, which safe-audit does not model): it is
  # NOT identity-neutral (delta-2 finding F1).
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='mise use "npm:okpkg[package_manager=bun]@1.0.0"' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_err_contains_fragment 'not audit-gated' "$FUNCNAME" || return

  # Options on a CONFIGURED tool are invisible in `mise ls`: the bare
  # preflight must ask `mise tool --json` before trusting key@version.
  : > "${LOG_FILE}"
  MISE_LS_JSON='{"npm:blockme": [{"version": "1.0.0", "requested_version": "1.0.0", "installed": false}]}' \
    MISE_TOOL_JSON='{"tool_options": {"npm_args": "--registry=https://evil.example"}}' \
    SAFE_INSTALL_TEST_SCRIPT='mise install' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_err_contains_fragment 'not audit-gated' "$FUNCNAME" || return
  assert_log_contains $'REAL\tmise\tinstall' "$FUNCNAME" || return

  # A failed option query fails closed.
  : > "${LOG_FILE}"
  MISE_LS_JSON='{"npm:blockme": [{"version": "1.0.0", "requested_version": "1.0.0", "installed": false}]}' \
    MISE_TOOL_STATUS=1 SAFE_INSTALL_TEST_SCRIPT='mise install' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tmise' "$FUNCNAME" || return
  assert_err_contains_fragment 'not a package verdict' "$FUNCNAME" || return

  # Neutral configured options keep the audit.
  : > "${LOG_FILE}"
  MISE_LS_JSON='{"npm:blockme": [{"version": "1.0.0", "requested_version": "1.0.0", "installed": false}]}' \
    MISE_TOOL_JSON='{"tool_options": {"os": null, "install_env": {}, "platform": "linux"}}' \
    SAFE_INSTALL_TEST_SCRIPT='mise install' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme@1.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_mise_unmodeled_sources_are_not_vouched() {
  prepare_case "mise-unmodeled-sources"
  # The derivation models cargo/composer/bun sources now (PR6): mise-only
  # selectors are translated into the audit's own --registry argv, and the
  # only surviving notice is CARGO_HOME (an unread config.toml, [source]
  # replacement included).
  MISE_ENV_JSON='{"MISE_PIPX_REGISTRY_URL": "https://private.example/pypi/{}/json"}' \
    SAFE_INSTALL_TEST_SCRIPT='mise install pipx:okpkg@1.0.0' run_zsh
  assert_status 0 "$FUNCNAME" || return
  # The raw setting is a {}-templated LISTING url; the installer receives
  # the normalized PEP-503 /simple endpoint (mise get_index_url — the
  # double slash is mise's own artifact and byte-faithful here), so that is
  # the identity the audit judges.
  assert_log_contains $'AUDIT\tcheck\tokpkg@1.0.0\t--ecosystem\tpython\t--gate\tinstall\t--op\tinstall\t--registry\thttps://private.example/pypi//simple\t--installer\tpipx' "$FUNCNAME" || return

  # A mise cargo registry NAME rides the same argv selector; the audit maps
  # it to its env-defined index or an opaque cargo-registry:<name> identity.
  : > "${LOG_FILE}"
  MISE_ENV_JSON='{"MISE_CARGO_REGISTRY_NAME": "private"}' \
    SAFE_INSTALL_TEST_SCRIPT='mise install cargo:okpkg@1.0.0' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tokpkg@1.0.0\t--ecosystem\trust\t--gate\tinstall\t--op\tinstall\t--registry\tprivate\t--installer\tcargo' "$FUNCNAME" || return

  # CARGO_HOME keeps the honest notice: it points cargo at a config.toml
  # the derivation does not read.
  : > "${LOG_FILE}"
  MISE_ENV_JSON='{"CARGO_HOME": "/tmp/cargo-home"}' \
    SAFE_INSTALL_TEST_SCRIPT='mise install cargo:okpkg@1.0.0' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_err_contains_fragment 'not audit-gated' "$FUNCNAME" || return

  # Without such a source, the same install audits normally.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='mise install cargo:blockme@1.0.0' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme@1.0.0\t--ecosystem\trust\t--gate\tinstall\t--op\tinstall\t--installer\tcargo' "$FUNCNAME" || return

  # npm sources safe-audit DOES model still reach the audit.
  : > "${LOG_FILE}"
  MISE_ENV_JSON='{"NPM_CONFIG_REGISTRY": "https://mirror.example"}' \
    SAFE_INSTALL_TEST_SCRIPT='mise install npm:okpkg@1.0.0' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDITENV\tNPM_CONFIG_REGISTRY=https://mirror.example' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_mise_scoped_exclusion_and_interactive() {
  prepare_case "mise-scoped-exclusion"
  # An npm scope starts with '@': a blind version split reduced every
  # unversioned scoped name to "npm:" and made unrelated tools compare
  # equal, so an unrelated --exclude silenced the audit (delta-2 F3).
  # A floating request can move on a plain upgrade; an exact one cannot
  # (delta-4 finding F3), so the movable case is what proves the audit.
  local scoped_ls='{"npm:@scope/blockme": [{"version": "1.0.0", "requested_version": "1", "installed": true}]}'
  MISE_LS_JSON="${scoped_ls}" \
    SAFE_INSTALL_TEST_SCRIPT='mise upgrade npm:@scope/blockme --exclude npm:@other/safe' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\t@scope/blockme@1\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return

  # The matching exclusion still drops its own target.
  : > "${LOG_FILE}"
  MISE_LS_JSON="${scoped_ls}" \
    SAFE_INSTALL_TEST_SCRIPT='mise upgrade npm:@scope/blockme --exclude npm:@scope/blockme' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return

  # An unversioned explicit upgrade target keeps its CONFIGURED request in
  # mise, so auditing a bare name would check the latest instead (delta-3
  # finding F3): the configured version is what gets checked, and a target
  # with no configured request refuses rather than guessing.
  : > "${LOG_FILE}"
  MISE_LS_JSON='{"npm:blockme": [{"version": "2.0.0", "requested_version": "2", "installed": true}]}' \
    SAFE_INSTALL_TEST_SCRIPT='mise upgrade npm:blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme@2\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return

  # An EXACT configured request cannot move on a plain upgrade: auditing it
  # reported a verdict for a no-op (delta-4 finding F3).
  : > "${LOG_FILE}"
  MISE_LS_JSON='{"npm:blockme": [{"version": "2.0.0", "requested_version": "2.0.0", "installed": true}]}' \
    SAFE_INSTALL_TEST_SCRIPT='mise upgrade npm:blockme' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return

  : > "${LOG_FILE}"
  MISE_LS_JSON='{}' SAFE_INSTALL_TEST_SCRIPT='mise upgrade npm:blockme' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'REAL' "$FUNCNAME" || return

  # `use` honors --minimum-release-age too.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='mise use --minimum-release-age 7d npm:blockme' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return

  # An interactive upgrade selects targets safe never sees; auditing every
  # candidate would block the picker over a tool the user may not choose.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='mise upgrade --interactive' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'REAL' "$FUNCNAME" || return
  # The rewrite hint must name an EXACT version: an optional-version hint
  # steers the user into the unversioned-target problem above (delta-3 F3).
  assert_err_contains_fragment 'rerun naming each tool with an exact version' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_mise_infra_refusals_are_one_line() {
  prepare_case "mise-infra-one-line"
  # A -C directory that cannot be entered must produce exactly one refusal
  # line, not a silent exit 100 (delta-2 finding F6).
  SAFE_INSTALL_TEST_SCRIPT='mise -C no-such-dir install npm:okpkg@1.0.0' run_zsh
  assert_status 100 "$FUNCNAME" || return
  local lines
  lines="$(grep -c 'safe:' "${ERR_FILE}" 2>/dev/null || printf '0')"
  if [[ "${lines}" != "1" ]]; then
    printf 'expected exactly one safe: line, got %s:\n' "${lines}" >&2
    cat "${ERR_FILE}" >&2
    fail "$FUNCNAME"
    return
  fi
  assert_err_contains_fragment 'not a package verdict' "$FUNCNAME" || return

  # The inner-exec route refuses the same way.
  : > "${ERR_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='mise -C no-such-dir exec -- npm install okpkg' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_err_contains_fragment 'not a package verdict' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_mise_leading_global_help_passes() {
  prepare_case "mise-leading-help"
  # `mise --help install npm:x` prints global help and installs nothing:
  # the subcommand scan never saw the flag, so the install gate ran
  # (delta-2 finding F5).
  SAFE_INSTALL_TEST_SCRIPT='mise --help install npm:blockme' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_log_contains $'REAL\tmise\t--help\tinstall\tnpm:blockme' "$FUNCNAME" || return

  # --version is NOT display-only with a subcommand: verified against mise
  # 2026.7.16, `mise --version install <pkg>` still installs, so
  # early-delegating it was an unaudited bypass (delta-3 finding F5).
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='mise --version install npm:blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tmise' "$FUNCNAME" || return

  # With no subcommand it is a plain version print: delegated.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='mise --version' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'REAL\tmise\t--version' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_mise_env_values_round_trip_exactly() {
  prepare_case "mise-env-round-trip"
  # Command substitution strips trailing newlines: a value ending in LF
  # reached the audit truncated and could name a different config file
  # than mise loads (delta-2 finding F2).
  MISE_ENV_JSON='{"NPM_CONFIG_REGISTRY": "https://mirror.example/trail\n"}' \
    SAFE_INSTALL_TEST_SCRIPT='mise install npm:okpkg@1.0.0' run_zsh
  assert_status 0 "$FUNCNAME" || return
  grep -Fq 'AUDITENV_B64	NPM_CONFIG_REGISTRY=aHR0cHM6Ly9taXJyb3IuZXhhbXBsZS90cmFpbAo=' "${LOG_FILE}" || {
    printf 'trailing newline lost in transport:\n%s\n' "$(cat "${LOG_FILE}")" >&2
    fail "$FUNCNAME"
    return
  }

  # An empty value survives as empty rather than becoming unset.
  : > "${LOG_FILE}"
  MISE_ENV_JSON='{"NPM_CONFIG_REGISTRY": ""}' \
    SAFE_INSTALL_TEST_SCRIPT='mise install npm:okpkg@1.0.0' run_zsh
  assert_status 0 "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_mise_option_checks_cover_every_preflight() {
  prepare_case "mise-option-preflight-siblings"
  # exec auto-install reconstructed entries straight from `mise ls` and
  # never asked about options — one shared enumerator now covers both
  # routes (delta-3 finding F1).
  MISE_EXEC_AUTO_INSTALL=true \
    MISE_LS_JSON='{"npm:blockme": [{"version": "1.0.0", "requested_version": "1.0.0", "installed": false}]}' \
    MISE_TOOL_JSON='{"tool_options": {"npm_args": "--registry=https://evil.example"}}' \
    SAFE_INSTALL_TEST_SCRIPT='mise exec -- node script.js' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_err_contains_fragment 'not audit-gated' "$FUNCNAME" || return

  # `mise tool --json` reports ONE option set per key, so a key with
  # several configured versions cannot be attributed: notice, never vouch.
  : > "${LOG_FILE}"
  MISE_LS_JSON='{"npm:cowsay": [{"version": "1.5.0", "requested_version": "1.5.0", "installed": false}, {"version": "1.6.0", "requested_version": "1.6.0", "installed": false}]}' \
    SAFE_INSTALL_TEST_SCRIPT='mise install' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_err_contains_fragment 'several configured versions' "$FUNCNAME" || return

  # Missing tool_options is malformed helper output, not "no options".
  : > "${LOG_FILE}"
  MISE_LS_JSON='{"npm:blockme": [{"version": "1.0.0", "requested_version": "1.0.0", "installed": false}]}' \
    MISE_TOOL_JSON='{}' SAFE_INSTALL_TEST_SCRIPT='mise install' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_err_contains_fragment 'not a package verdict' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_mise_unmodeled_sources_cover_ambient_and_inner() {
  prepare_case "mise-unmodeled-siblings"
  # mise env --json omits INHERITED variables, but the delegate still gets
  # them: the audit runs under the effective union, so an ambient
  # registry.default reaches its derivation (delta-3 finding F4 / PR6).
  SAFE_INSTALL_TEST_SCRIPT='export CARGO_REGISTRY_DEFAULT=private; mise install cargo:okpkg@1.0.0' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tokpkg@1.0.0\t--ecosystem\trust\t--gate\tinstall\t--op\tinstall\t--installer\tcargo' "$FUNCNAME" || return
  assert_log_contains $'AUDITENV\tCARGO_REGISTRY_DEFAULT=private' "$FUNCNAME" || return

  # The inner exec route audits Composer and bun-backed npm now: their
  # sources are modeled (COMPOSER_HOME/config.json is read by the
  # derivation; bun via --installer bun).
  : > "${LOG_FILE}"
  MISE_ENV_JSON='{"COMPOSER_HOME": "/tmp/composer-home"}' \
    SAFE_INSTALL_TEST_SCRIPT='mise exec -- composer require vendor/blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tvendor/blockme\t--ecosystem\tcomposer\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_contains $'AUDITENV\tCOMPOSER_HOME=/tmp/composer-home' "$FUNCNAME" || return

  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='export BUN_CONFIG_REGISTRY=https://private.example; mise exec -- bun add blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall\t--installer\tbun' "$FUNCNAME" || return
  assert_log_contains $'AUDITENV\tBUN_CONFIG_REGISTRY=https://private.example' "$FUNCNAME" || return

  # ...and npm does not read bun's variable: same audit, no bun installer —
  # applying selectors by ecosystem removed the gate from artifacts safe
  # can model (delta-4 finding F4).
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='export BUN_CONFIG_REGISTRY=https://private.example; mise exec -- npm install blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return

  # An exported but EMPTY selector chooses nothing: it must not suppress
  # the audit either.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='export BUN_CONFIG_REGISTRY=; mise exec -- bun add blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return

  # Without any selector the inner route audits normally.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='mise exec -- npm install blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_mise_env_transport_handles_unicode_and_nul() {
  prepare_case "mise-env-unicode-nul"
  # Byte-vs-character length comparison rejected a valid UTF-8 path
  # (delta-3 finding F2): non-ASCII values must survive intact.
  MISE_ENV_JSON='{"PIP_CONFIG_FILE": "/tmp/café.conf"}' \
    SAFE_INSTALL_TEST_SCRIPT='mise install pipx:okpkg@1.0.0' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDITENV\tPIP_CONFIG_FILE=/tmp/café.conf' "$FUNCNAME" || return

  # A NUL cannot exist in an environment value: rejected in the producer,
  # so exactly one refusal line appears (no bash null-byte warning).
  : > "${ERR_FILE}"
  MISE_ENV_JSON='{"PIP_CONFIG_FILE": "a\u0000b"}' \
    SAFE_INSTALL_TEST_SCRIPT='mise install pipx:okpkg@1.0.0' run_zsh
  assert_status 100 "$FUNCNAME" || return
  if grep -qi 'null byte' "${ERR_FILE}"; then
    printf 'bash null-byte warning leaked next to the refusal:\n' >&2
    cat "${ERR_FILE}" >&2
    fail "$FUNCNAME"
    return
  fi
  assert_err_contains_fragment 'not a package verdict' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_mise_option_attribution_covers_cli_and_hidden_rows() {
  prepare_case "mise-option-attribution"
  # An explicit CLI target INHERITS the configured options for its key, so
  # the attribution check must run there too (delta-4 finding F1).
  MISE_TOOL_JSON='{"tool_options": {"npm_args": "--registry=https://evil.example"}}' \
    SAFE_INSTALL_TEST_SCRIPT='mise install npm:blockme@1.0.0' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_err_contains_fragment 'not audit-gated' "$FUNCNAME" || return

  # Multiplicity must be counted BEFORE the operation mode hides sibling
  # rows: one installed + one missing row share a single reported option
  # set, so the key is still unattributable (delta-4 finding F1).
  : > "${LOG_FILE}"
  MISE_LS_JSON='{"npm:blockme": [{"version": "1.0.0", "requested_version": "1.0.0", "installed": true}, {"version": "2.0.0", "requested_version": "2.0.0", "installed": false}]}' \
    SAFE_INSTALL_TEST_SCRIPT='mise install' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_err_contains_fragment 'several configured versions' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_mise_bump_audits_the_moved_target() {
  prepare_case "mise-bump-target"
  # --bump moves to the LATEST release, outside the configured request:
  # auditing the old pin checked a version that will not be installed
  # (delta-4 finding F3). A bare name lets safe-audit resolve the same
  # target mise will pick.
  MISE_LS_JSON='{"npm:blockme": [{"version": "1.0.0", "requested_version": "1.0.0", "installed": true}]}' \
    SAFE_INSTALL_TEST_SCRIPT='mise upgrade --bump' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return

  : > "${LOG_FILE}"
  MISE_LS_JSON='{"npm:blockme": [{"version": "1.0.0", "requested_version": "1.0.0", "installed": true}]}' \
    SAFE_INSTALL_TEST_SCRIPT='mise upgrade --bump npm:blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return

  # A VERSIONED argv target under --bump is a backend filter, not the
  # audited target: mise still moves it to the latest release (delta-5 F3).
  : > "${LOG_FILE}"
  MISE_LS_JSON='{"npm:blockme": [{"version": "1.0.0", "requested_version": "1.0.0", "installed": true}]}' \
    SAFE_INSTALL_TEST_SCRIPT='mise upgrade --bump npm:blockme@0.5.0' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment 'blockme@0.5.0' "$FUNCNAME" || return

  # install --force reinstalls the CONFIGURED version, so it keeps its
  # request rather than resolving latest.
  : > "${LOG_FILE}"
  MISE_LS_JSON='{"npm:blockme": [{"version": "1.0.0", "requested_version": "1.0.0", "installed": true}]}' \
    SAFE_INSTALL_TEST_SCRIPT='mise install --force' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme@1.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_mise_upgrade_lookup_is_canonical_and_ordered() {
  prepare_case "mise-upgrade-lookup"
  # A supported bare shorthand names the same tool as its configured
  # backend key: comparing the raw spec refused it as unconfigured
  # (delta-4 finding F3).
  MISE_LS_JSON='{"npm:prettier": [{"version": "3.0.0", "requested_version": "3", "installed": true}]}' \
    SAFE_INSTALL_TEST_SCRIPT='mise upgrade prettier' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tprettier@3\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return

  # A key with SEVERAL configured requests shares one reported option set,
  # so it cannot be attributed to the target being upgraded: the
  # multiplicity rule (delta-5 finding F1) takes precedence over expanding
  # the movable requests, and the invocation is flagged rather than
  # audited against a source safe cannot confirm.
  : > "${LOG_FILE}"
  MISE_LS_JSON='{"npm:blockme": [{"version": "1.0.0", "requested_version": "1.0.0", "installed": true}, {"version": "2.0.0", "requested_version": "2", "installed": true}]}' \
    SAFE_INSTALL_TEST_SCRIPT='mise upgrade npm:blockme' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_err_contains_fragment 'several configured versions' "$FUNCNAME" || return

  # A bracket option must not end up inside the key compared against the
  # configured rows: that refused a supported invocation (delta-5 F3).
  : > "${LOG_FILE}"
  MISE_LS_JSON='{"npm:blockme": [{"version": "1.0.0", "requested_version": "1", "installed": true}]}' \
    SAFE_INSTALL_TEST_SCRIPT='mise upgrade "npm:blockme[bin_path=bin]"' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme@1\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return

  # Exclusions are canonical too: one tool, two spellings.
  : > "${LOG_FILE}"
  MISE_LS_JSON='{"npm:blockme": [{"version": "1.0.0", "requested_version": "1", "installed": true}]}' \
    SAFE_INSTALL_TEST_SCRIPT='mise upgrade blockme --exclude npm:blockme' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return

  # Exclusions apply BEFORE the configured-request lookup: a target mise
  # will not touch must not be refused for being unconfigured.
  : > "${LOG_FILE}"
  MISE_LS_JSON='{}' \
    SAFE_INSTALL_TEST_SCRIPT='mise upgrade npm:unconfigured --exclude npm:unconfigured' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'REAL\tmise\tupgrade\tnpm:unconfigured\t--exclude\tnpm:unconfigured' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_mise_npm_installer_reads_mise_settings() {
  prepare_case "mise-npm-installer-setting"
  # `mise env --json` does not export npm.package_manager, so a configured
  # bun installer was invisible and safe audited npm's source for a bun
  # install (delta-5 finding F4). The bun surface is modeled now: the
  # install audits with --installer bun and the audit judges bun's
  # registry, not npm's.
  MISE_NPM_PM=bun \
    SAFE_INSTALL_TEST_SCRIPT='export BUN_CONFIG_REGISTRY=https://private.example; mise install npm:okpkg@1.0.0' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tokpkg@1.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall\t--installer\tbun' "$FUNCNAME" || return
  assert_log_contains $'AUDITENV\tBUN_CONFIG_REGISTRY=https://private.example' "$FUNCNAME" || return

  # The default installer reads no bun variable, so the audit proceeds.
  : > "${LOG_FILE}"
  MISE_NPM_PM=auto \
    SAFE_INSTALL_TEST_SCRIPT='export BUN_CONFIG_REGISTRY=https://private.example; mise install npm:blockme@1.0.0' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme@1.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return

  # The environment still wins over the setting.
  : > "${LOG_FILE}"
  MISE_NPM_PM=bun MISE_ENV_JSON='{"MISE_NPM_PACKAGE_MANAGER": "npm"}' \
    SAFE_INSTALL_TEST_SCRIPT='export BUN_CONFIG_REGISTRY=https://private.example; mise install npm:blockme@1.0.0' run_zsh
  assert_status 104 "$FUNCNAME" || return

  # An unreadable or unrecognized setting fails closed.
  : > "${LOG_FILE}"
  MISE_NPM_PM='not-a-manager' \
    SAFE_INSTALL_TEST_SCRIPT='mise install npm:okpkg@1.0.0' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tmise' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_mise_rows_snapshot_is_shared() {
  prepare_case "mise-rows-snapshot"
  # Selection and attribution must read ONE snapshot: capturing the loader
  # with $(...) ran its assignments in a subshell, so the cache never
  # survived and each reader re-queried mise, which could disagree with
  # the first answer (delta-6 finding F1).
  MISE_LS_JSON='{"npm:blockme": [{"version": "1.0.0", "requested_version": "1", "installed": true}]}' \
    SAFE_INSTALL_TEST_SCRIPT='mise upgrade npm:blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  local ls_queries
  ls_queries="$(grep -c $'MISEQ\tls\t--current\t--json' "${LOG_FILE}" 2>/dev/null || printf '0')"
  if [[ "${ls_queries}" != "1" ]]; then
    printf 'expected exactly one mise ls query, got %s:\n' "${ls_queries}" >&2
    cat "${LOG_FILE}" >&2
    fail "$FUNCNAME"
    return
  fi
  pass "$FUNCNAME"
}

case_mise_exclusion_canonicalization_fails_closed() {
  prepare_case "mise-exclusion-fail-closed"
  # An exclusion that cannot be canonicalized must not silently match: the
  # old fallback rewrote it as the current target (bash expands every RHS
  # of one `local` before the new locals exist), dropping a real target
  # from the audit set entirely (delta-6 finding F3).
  MISE_LS_JSON='{"npm:blockme": [{"version": "1.0.0", "requested_version": "1", "installed": true}]}' \
    SAFE_INSTALL_TEST_SCRIPT='mise upgrade npm:blockme --exclude nonsense' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tmise' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_mise_bump_requires_a_configured_target() {
  prepare_case "mise-bump-configured"
  # --bump moves a CONFIGURED request; with none, mise installs nothing,
  # so auditing the latest release reported a verdict for a no-op
  # (delta-6 finding F3).
  MISE_LS_JSON='{}' SAFE_INSTALL_TEST_SCRIPT='mise upgrade --bump npm:blockme' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return

  : > "${LOG_FILE}"
  MISE_LS_JSON='{}' SAFE_INSTALL_TEST_SCRIPT='mise upgrade --bump npm:blockme@0.5.0' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_mise_installer_values_are_validated() {
  prepare_case "mise-installer-values"
  # An environment value was passed through unvalidated, so an invalid
  # selector became a package verdict instead of an infrastructure
  # refusal (delta-6 finding F4).
  MISE_ENV_JSON='{"MISE_NPM_PACKAGE_MANAGER": "not-a-manager"}' \
    SAFE_INSTALL_TEST_SCRIPT='mise install npm:blockme@1.0.0' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_err_contains_fragment 'not a package verdict' "$FUNCNAME" || return

  # Aube is a valid mise installer reading npm-compatible sources: it
  # audits normally rather than being refused as unrecognized.
  : > "${LOG_FILE}"
  MISE_NPM_PM=aube SAFE_INSTALL_TEST_SCRIPT='mise install npm:blockme@1.0.0' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme@1.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return

  : > "${LOG_FILE}"
  MISE_NPM_PM=aube_cli SAFE_INSTALL_TEST_SCRIPT='mise install npm:blockme@1.0.0' run_zsh
  assert_status 104 "$FUNCNAME" || return

  # A nonzero settings command fails closed.
  : > "${LOG_FILE}"
  MISE_NPM_PM_STATUS=1 SAFE_INSTALL_TEST_SCRIPT='mise install npm:okpkg@1.0.0' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tmise' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_mise_multi_target_shares_one_snapshot() {
  prepare_case "mise-multi-target-snapshot"
  # Every explicit target of a multi-target command must attribute options
  # against the SAME configuration: the multiplicity capture reloaded rows
  # in a subshell, so each target re-queried mise (delta-7 finding F1).
  # The stub's second answer would make the second target look ambiguous;
  # with one snapshot it is never read.
  MISE_LS_JSON='{}' \
    MISE_LS_JSON_2='{"npm:oktwo": [{"version": "1.0.0", "requested_version": "1.0.0", "installed": true}, {"version": "2.0.0", "requested_version": "2", "installed": true}]}' \
    SAFE_INSTALL_TEST_SCRIPT='mise install npm:okone@1.0.0 npm:oktwo@2.0.0' run_zsh
  assert_status 0 "$FUNCNAME" || return
  local ls_queries
  ls_queries="$(grep -c $'MISEQ\tls\t--current\t--json' "${LOG_FILE}" 2>/dev/null || printf '0')"
  if [[ "${ls_queries}" != "1" ]]; then
    printf 'expected exactly one mise ls query, got %s:\n' "${ls_queries}" >&2
    cat "${LOG_FILE}" >&2
    fail "$FUNCNAME"
    return
  fi
  assert_log_contains $'AUDIT\tcheck\toktwo@2.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return

  # Same for `use`.
  : > "${LOG_FILE}"
  rm -f "${LOG_FILE}.lsonce"
  MISE_LS_JSON='{}' MISE_LS_JSON_2='{"npm:oktwo": [{"version": "1.0.0", "requested_version": "1.0.0", "installed": true}, {"version": "2.0.0", "requested_version": "2", "installed": true}]}' \
    SAFE_INSTALL_TEST_SCRIPT='mise use npm:okone@1.0.0 npm:oktwo@2.0.0' run_zsh
  assert_status 0 "$FUNCNAME" || return
  ls_queries="$(grep -c $'MISEQ\tls\t--current\t--json' "${LOG_FILE}" 2>/dev/null || printf '0')"
  if [[ "${ls_queries}" != "1" ]]; then
    printf 'use: expected exactly one mise ls query, got %s:\n' "${ls_queries}" >&2
    cat "${LOG_FILE}" >&2
    fail "$FUNCNAME"
    return
  fi

  # ...and for exec tool specs, which install on demand.
  : > "${LOG_FILE}"
  rm -f "${LOG_FILE}.lsonce"
  MISE_EXEC_AUTO_INSTALL=false MISE_LS_JSON='{}' \
    MISE_LS_JSON_2='{"npm:oktwo": [{"version": "1.0.0", "requested_version": "1.0.0", "installed": true}, {"version": "2.0.0", "requested_version": "2", "installed": true}]}' \
    SAFE_INSTALL_TEST_SCRIPT='mise exec npm:okone@1.0.0 npm:oktwo@2.0.0 -- node script.js' run_zsh
  assert_status 0 "$FUNCNAME" || return
  ls_queries="$(grep -c $'MISEQ\tls\t--current\t--json' "${LOG_FILE}" 2>/dev/null || printf '0')"
  if [[ "${ls_queries}" != "1" ]]; then
    printf 'exec: expected exactly one mise ls query, got %s:\n' "${ls_queries}" >&2
    cat "${LOG_FILE}" >&2
    fail "$FUNCNAME"
    return
  fi
  assert_log_contains $'AUDIT\tcheck\toktwo@2.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_mise_setting_output_is_strict() {
  prepare_case "mise-setting-strict"
  # Truncating the setting to its first line turned malformed multi-line
  # helper output into an apparently valid installer identity (delta-7
  # finding F4): it must refuse as infrastructure breakage instead.
  MISE_NPM_PM=$'npm\nbun' SAFE_INSTALL_TEST_SCRIPT='mise install npm:blockme@1.0.0' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tmise' "$FUNCNAME" || return
  assert_err_contains_fragment 'not a package verdict' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_mise_entry_requires_requested_version() {
  prepare_case "mise-entry-requires-version"
  # A missing requested_version was defaulted to "": safe audited a bare
  # name and reported a package VERDICT for unreadable helper output
  # (delta-2 finding F2).
  MISE_LS_JSON='{"npm:blockme": [{"installed": false}]}' \
    SAFE_INSTALL_TEST_SCRIPT='mise install' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_err_contains_fragment 'not a package verdict' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_mise_entry_schema_is_strict() {
  prepare_case "mise-entry-schema"
  # A missing required field is malformed helper output: defaulting it
  # reported a package VERDICT for an entry safe could not read (delta-1
  # finding 3).
  MISE_LS_JSON='{"npm:blockme": [{}]}' SAFE_INSTALL_TEST_SCRIPT='mise install' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_err_contains_fragment 'not a package verdict' "$FUNCNAME" || return

  # jq's own diagnostics must not leak: the refusal contract is one line.
  : > "${ERR_FILE}"
  MISE_LS_JSON='{"npm:blockme": "not-an-array"}' SAFE_INSTALL_TEST_SCRIPT='mise install' run_zsh
  assert_status 100 "$FUNCNAME" || return
  if grep -qiE 'jq: error|parse error' "${ERR_FILE}"; then
    printf 'jq diagnostics leaked into the refusal:\n' >&2
    cat "${ERR_FILE}" >&2
    fail "$FUNCNAME"
    return
  fi
  pass "$FUNCNAME"
}

case_zsh_stub_warns_on_missing_mise_wrapper() {
  prepare_case "zsh-stub-warns-mise"
  # The zsh stub's full-set probe includes mise: an interactive shell with
  # every wrapper present EXCEPT mise must warn for mise by name.
  local stub_home="${WORK_DIR}/stub-home"
  mkdir -p "${stub_home}/.local/bin"
  local tool
  for tool in npm pnpm pnpx yarn bun pip pip3 uv cargo go composer; do
    printf '#!/usr/bin/env bash\n# safe-gate-wrapper v1 tool=%s\nexec safe gate %s -- "$@"\n' "$tool" "$tool" > "${stub_home}/.local/bin/${tool}"
    chmod +x "${stub_home}/.local/bin/${tool}"
  done
  printf '#!/usr/bin/env bash\nexit 0\n' > "${stub_home}/.local/bin/safe"
  chmod +x "${stub_home}/.local/bin/safe"
  local err_out
  err_out="$(HOME="${stub_home}" ZDOTDIR="${stub_home}" SAFE_BIN_DIR="${stub_home}/.local/bin" \
    PATH="${stub_home}/.local/bin:${PATH}" \
    zsh -i -c "source '${ROOT_DIR}/lib/install-wrappers.zsh'" 2>&1 >/dev/null)" || true
  [[ "$err_out" == *"NOT active for: mise"* ]] || { printf '%s\n' "$err_out" >&2; fail "$FUNCNAME"; return; }
  pass "$FUNCNAME"
}

case_mise_wrapper_dispatches_foreign_argv0() {
  # A mise shim (symlink named after a tool) bound to the gate wrapper must
  # reach the real mise with argv[0] intact and never enter the gate — the
  # 2026-08-02 reshim breakage where every shimmed tool executed mise bare.
  local dir="${TEST_ROOT}/${FUNCNAME}"
  mkdir -p "${dir}/wrap" "${dir}/real"
  write_gate_wrappers "${dir}/wrap"
  cat > "${dir}/real/mise" <<'STUB'
#!/usr/bin/env bash
printf 'REALMISE args=%s\n' "$*"
STUB
  chmod +x "${dir}/real/mise"
  ln -s "${dir}/wrap/mise" "${dir}/wrap/node"
  local out
  out=$(PATH="${dir}/wrap:${dir}/real:/usr/bin:/bin" "${dir}/wrap/node" --version 2>&1)
  # A shebang-script stub cannot OBSERVE the preserved argv[0] — the kernel
  # rebuilds argv for the interpreter of a script, so only a native binary
  # (like the real mise) receives it. The functional half proves the shim
  # dispatch reaches the real binary with args intact and never enters the
  # gate; the textual half pins the argv0-preserving exec form itself.
  if [[ "$out" != "REALMISE args=--version" ]]; then
    printf 'got: %s\n' "$out" >&2
    fail "$FUNCNAME"
    return
  fi
  if ! grep -Fq 'exec -a "$0" "$__c" "$@"' "${dir}/wrap/mise"; then
    fail "$FUNCNAME"
    return
  fi
  pass "$FUNCNAME"
}

case_mise_wrapper_dispatch_without_real_mise_is_legible() {
  # No real mise anywhere on PATH: the dispatch must refuse legibly with
  # 127, not loop back into itself or fall through to the gate.
  local dir="${TEST_ROOT}/${FUNCNAME}"
  mkdir -p "${dir}/wrap"
  write_gate_wrappers "${dir}/wrap"
  ln -s "${dir}/wrap/mise" "${dir}/wrap/npmshim"
  # PATH must resolve bash for the wrapper's shebang but carry no real mise.
  mkdir -p "${dir}/sysbin"
  ln -s "$(command -v bash)" "${dir}/sysbin/bash"
  local out shim_status=0
  out=$(PATH="${dir}/wrap:${dir}/sysbin" "${dir}/wrap/npmshim" --version 2>&1) || shim_status=$?
  if [[ $shim_status -ne 127 ]] || ! grep -q 'real mise not found' <<<"$out"; then
    printf 'status=%s out=%s\n' "$shim_status" "$out" >&2
    fail "$FUNCNAME"
    return
  fi
  pass "$FUNCNAME"
}

case_mise_wrapper_helper_matches_installer_output() {
  # The suite helper duplicates install.sh's mise wrapper body; the two new
  # behavioral cases exercise the helper's copy, so byte-identity with the
  # installer's output is what makes them evidence about production
  # (review PR#46 F2).
  local dir="${TEST_ROOT}/${FUNCNAME}"
  mkdir -p "${dir}/home" "${dir}/helper"
  HOME="${dir}/home" SAFE_ZSHRC="${dir}/zshrc" bash "${ROOT_DIR}/install.sh" --wrappers >/dev/null 2>&1
  write_gate_wrappers "${dir}/helper"
  if ! diff -u "${dir}/helper/mise" "${dir}/home/.local/bin/mise" >&2; then
    fail "$FUNCNAME"
    return
  fi
  pass "$FUNCNAME"
}

case_uninstall_cleans_shell_and_legacy_binaries() {
  prepare_case "uninstall-cleans-shell-and-legacy-binaries"
  mkdir -p "${HOME_DIR}/.local/bin" "${HOME_DIR}/.local/share/zsh/site-functions" "${HOME_DIR}/.config/safe-run/completions" "${HOME_DIR}/.config/safe" "${HOME_DIR}/.local/share/safe"
  cat > "${HOME_DIR}/.zshrc" <<'EOF'
source "$HOME/.config/safe/install-wrappers.zsh"
fpath=("$HOME/.local/share/zsh/site-functions" $fpath)
source "$HOME/.config/safe-run/install-wrappers.zsh"
fpath=("$HOME/.config/safe-run/completions" $fpath)
EOF
  printf 'legacy completion\n' > "${HOME_DIR}/.config/safe-run/completions/_safe-install"
  printf 'current completion\n' > "${HOME_DIR}/.local/share/zsh/site-functions/_safe"
  for bin in safe safe-audit safe-install safe-npx safe-bunx safe-uvx safe-pipx-run; do
    printf '#!/usr/bin/env bash\n' > "${HOME_DIR}/.local/bin/${bin}"
    chmod +x "${HOME_DIR}/.local/bin/${bin}"
  done
  cat > "${HOME_DIR}/.local/bin/safe-run" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "unlink" ]]; then
  printf 'unlink\n' >> "${SAFE_TEST_UNINSTALL_LOG}"
  exit 0
fi
exit 0
EOF
  chmod +x "${HOME_DIR}/.local/bin/safe-run"

  SAFE_TEST_UNINSTALL_LOG="${LOG_FILE}" HOME="${HOME_DIR}" bash "${ROOT_DIR}/uninstall.sh" >"${OUT_FILE}" 2>"${ERR_FILE}"
  STATUS=$?
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains 'unlink' "$FUNCNAME" || return
  for bin in safe safe-run safe-audit safe-install safe-npx safe-bunx safe-uvx safe-pipx-run; do
    [[ ! -e "${HOME_DIR}/.local/bin/${bin}" ]] || { fail "$FUNCNAME"; return; }
  done
  [[ ! -e "${HOME_DIR}/.local/share/zsh/site-functions/_safe" ]] || { fail "$FUNCNAME"; return; }
  [[ ! -e "${HOME_DIR}/.config/safe-run/completions/_safe-install" ]] || { fail "$FUNCNAME"; return; }
  assert_count 0 'source "$HOME/.config/safe/install-wrappers.zsh"' "${HOME_DIR}/.zshrc" "$FUNCNAME" || return
  assert_count 0 'fpath=("$HOME/.local/share/zsh/site-functions" $fpath)' "${HOME_DIR}/.zshrc" "$FUNCNAME" || return
  assert_count 0 'source "$HOME/.config/safe-run/install-wrappers.zsh"' "${HOME_DIR}/.zshrc" "$FUNCNAME" || return
  assert_count 0 'fpath=("$HOME/.config/safe-run/completions" $fpath)' "${HOME_DIR}/.zshrc" "$FUNCNAME" || return
  [[ -d "${HOME_DIR}/.config/safe" ]] || { fail "$FUNCNAME"; return; }
  [[ -d "${HOME_DIR}/.local/share/safe" ]] || { fail "$FUNCNAME"; return; }
  pass "$FUNCNAME"
}

case_safe_run_gated_tool_delegation() {
  prepare_case "safe-run-gated-tool-delegation" no
  local gate_bin="${CASE_DIR}/gate-bin"
  local delegate_target="${CASE_DIR}/npm-gate-wrapper"
  local runner
  mkdir -p "${gate_bin}"

  # Keep the marker target separate from its PATH name: the runtime classifier
  # must follow a symlink, then exec it with the npm argv0 intact.
  cat > "${delegate_target}" <<'EOF'
#!/usr/bin/env bash
# safe-gate-wrapper v1 tool=npm
printf 'WRAPPER_ARGV0=%s\n' "${0##*/}" >> "${SAFE_RUN_DELEGATE_LOG}"
exec safe gate npm -- "$@"
EOF
  chmod +x "${delegate_target}"
  ln -s "${delegate_target}" "${gate_bin}/npm"

  rm -f "${BIN_DIR}/safe"
  cat > "${BIN_DIR}/safe" <<'EOF'
#!/usr/bin/env bash
{
  printf 'SAFE'
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >> "${SAFE_RUN_DELEGATE_LOG}"
exit "${SAFE_RUN_DELEGATE_RC:-0}"
EOF
  chmod +x "${BIN_DIR}/safe"
  printf '#!/usr/bin/env bash\nexit 1\n' > "${BIN_DIR}/podman"
  chmod +x "${BIN_DIR}/podman"

  run_safe_runner() {
    local executable="$1"
    shift
    SAFE_RUN_CONFIG_DIR="${CASE_DIR}/run-config" \
      SAFE_RUN_DATA_DIR="${CASE_DIR}/run-data" \
      SAFE_RUN_DELEGATE_LOG="${CASE_DIR}/delegate.log" \
      SAFE_RUN_DELEGATE_RC="${SAFE_RUN_DELEGATE_RC:-0}" \
      PATH="${gate_bin}:${BIN_DIR}:/usr/bin:/bin" \
      "${executable}" "$@" >"${OUT_FILE}" 2>"${ERR_FILE}"
    STATUS=$?
  }

  SAFE_RUN_DELEGATE_RC=37 run_safe_runner "${ROOT_DIR}/bin/safe-run" npm update tar
  assert_status 37 "$FUNCNAME" || return
  grep -Fxq 'WRAPPER_ARGV0=npm' "${CASE_DIR}/delegate.log" || { fail "$FUNCNAME"; return; }
  grep -Fxq $'SAFE\tgate\tnpm\t--\tupdate\ttar' "${CASE_DIR}/delegate.log" || { fail "$FUNCNAME"; return; }
  [[ ! -s "${ERR_FILE}" ]] || { fail "$FUNCNAME"; return; }
  grep -Fq 'GATE_DELEGATION' "${CASE_DIR}/run-data/audit.log" || { fail "$FUNCNAME"; return; }

  # An executable without an exact marker must not run.
  rm -f "${gate_bin}/npm" "${CASE_DIR}/delegate.log"
  cat > "${gate_bin}/npm" <<'EOF'
#!/usr/bin/env bash
touch "${SAFE_RUN_DELEGATE_LOG}.canary"
EOF
  chmod +x "${gate_bin}/npm"
  SAFE_RUN_DELEGATE_RC=0 run_safe_runner "${ROOT_DIR}/bin/safe-run" npm update tar
  assert_status 100 "$FUNCNAME" || return
  grep -Fq 'npm is not gate-bound on PATH' "${ERR_FILE}" || { fail "$FUNCNAME"; return; }
  [[ ! -e "${CASE_DIR}/delegate.log.canary" ]] || { fail "$FUNCNAME"; return; }
  grep -Fq 'GATE_TARGET_NOT_BOUND' "${CASE_DIR}/run-data/audit.log" || { fail "$FUNCNAME"; return; }

  # A versioned package spec remains on the package lane, not the PATH wrapper.
  rm -f "${gate_bin}/npm" "${CASE_DIR}/delegate.log"
  ln -s "${delegate_target}" "${gate_bin}/npm"
  SAFE_RUN_DELEGATE_RC=0 run_safe_runner "${ROOT_DIR}/bin/safe-run" npm@1.2.3 update tar
  assert_status 102 "$FUNCNAME" || return
  [[ ! -e "${CASE_DIR}/delegate.log" ]] || { fail "$FUNCNAME"; return; }

  # F1 (PR#72 review): plain relative paths, trailing slashes, and the bare
  # path operands are command paths too — never the invalid-package 103 lane.
  for runner in /tmp/safe-run-absolute ./safe-run-relative ../safe-run-parent tools/npm npm/ . ..; do
    SAFE_RUN_DELEGATE_RC=0 run_safe_runner "${ROOT_DIR}/bin/safe-run" "${runner}" update tar
    assert_status 100 "$FUNCNAME" || return
    grep -Fq 'command paths are unsupported' "${ERR_FILE}" || { fail "$FUNCNAME"; return; }
    [[ "$(grep -c . "${ERR_FILE}")" == "1" ]] || { fail "$FUNCNAME"; return; }
  done
  grep -Fq 'UNSUPPORTED_COMMAND_PATH' "${CASE_DIR}/run-data/audit.log" || { fail "$FUNCNAME"; return; }

  # ...while a scoped npm spec's slash keeps the package lane (non-TTY
  # unknown → 102, and never the command-path refusal).
  SAFE_RUN_DELEGATE_RC=0 run_safe_runner "${ROOT_DIR}/bin/safe-run" @scope/pkg --help
  assert_status 102 "$FUNCNAME" || return
  grep -Fq 'command paths are unsupported' "${ERR_FILE}" && { fail "$FUNCNAME"; return; }

  # F2 (PR#72 review): --no-install is a strict local-only contract; a
  # gate-listed bare tool must NOT silently delegate past it. With no local
  # node_modules/.bin/npm the package lane refuses (100) and nothing execs.
  rm -f "${CASE_DIR}/delegate.log"
  SAFE_RUN_DELEGATE_RC=0 run_safe_runner "${ROOT_DIR}/bin/safe-run" --no-install npm exec cowsay
  assert_status 100 "$FUNCNAME" || return
  grep -Fq -- '--no-install requested' "${ERR_FILE}" || { fail "$FUNCNAME"; return; }
  [[ ! -e "${CASE_DIR}/delegate.log" ]] || { fail "$FUNCNAME"; return; }

  # F3 (PR#72 review): a trailing empty PATH component means the current
  # directory in shell lookup. Probe the SHIPPED walker under a fully
  # synthetic PATH (set inside the child, after sourcing, so the fixture
  # never depends on host /usr/bin contents).
  local cwd_gate="${CASE_DIR}/cwd-gate" cwd_candidate
  mkdir -p "${cwd_gate}"
  cp "${delegate_target}" "${cwd_gate}/npm"
  chmod +x "${cwd_gate}/npm"
  cwd_candidate=$(SAFE_RUN_NO_INIT=1 SAFE_RUN_PATH="${ROOT_DIR}/bin/safe-run" CWD_GATE="${cwd_gate}" bash -c '
    set -- version
    source "$SAFE_RUN_PATH" >/dev/null
    cd "$CWD_GATE" || exit 1
    PATH="/nonexistent-first:"
    safe_run_first_path_candidate npm
  ' safe-run)
  [[ "$cwd_candidate" == "./npm" ]] || { fail "$FUNCNAME"; return; }

  # A linked npx/bunx/uvx target must fail before it can recurse into safe-run.
  rm -f "${gate_bin}/npm"
  ln -s "${ROOT_DIR}/bin/safe-run" "${gate_bin}/npm"
  SAFE_RUN_DELEGATE_RC=0 run_safe_runner "${ROOT_DIR}/bin/safe-run" npm update tar
  assert_status 100 "$FUNCNAME" || return
  grep -Fq 'resolves to safe run itself' "${ERR_FILE}" || { fail "$FUNCNAME"; return; }
  grep -Fq 'GATE_TARGET_SELF' "${CASE_DIR}/run-data/audit.log" || { fail "$FUNCNAME"; return; }

  # Delegation intercepts --proxy before its normal ignored-proxy warning, so
  # an explicit sandbox flag produces only the prescribed advisory line.
  rm -f "${gate_bin}/npm" "${CASE_DIR}/delegate.log"
  ln -s "${delegate_target}" "${gate_bin}/npm"
  SAFE_RUN_DELEGATE_RC=0 run_safe_runner "${ROOT_DIR}/bin/safe-run" --proxy npm update tar
  assert_status 0 "$FUNCNAME" || return
  grep -Fq 'sandbox flags do not apply when delegating to the gate' "${ERR_FILE}" || { fail "$FUNCNAME"; return; }
  [[ "$(grep -c . "${ERR_FILE}")" == "1" ]] || { fail "$FUNCNAME"; return; }
  grep -Fq 'WARNING: --proxy ignored' "${ERR_FILE}" && { fail "$FUNCNAME"; return; }

  # argv0-linked runner entry points share the same classifier.
  for runner in npx bunx uvx; do
    ln -sf "${ROOT_DIR}/bin/safe-run" "${gate_bin}/${runner}"
    rm -f "${CASE_DIR}/delegate.log"
    SAFE_RUN_DELEGATE_RC=0 run_safe_runner "${gate_bin}/${runner}" npm update tar
    assert_status 0 "$FUNCNAME" || return
    grep -Fxq 'WRAPPER_ARGV0=npm' "${CASE_DIR}/delegate.log" || { fail "$FUNCNAME"; return; }
  done

  pass "$FUNCNAME"
}

main() {
  local case
  for case in \
    case_gate_lib_missing_fails_closed \
    case_wrapper_passthrough_is_cheap \
    case_refusal_message_contract \
    case_npm_exec_fetch_audits \
    case_npm_exec_local_bin_passthrough \
    case_npm_exec_versioned_spec_audits_despite_local_bin \
    case_leading_global_flag_gates_npm_install \
    case_leading_global_flag_gates_pnpm_dlx \
    case_leading_global_flag_gates_yarn_add \
    case_leading_global_flag_gates_uv_tool_run \
    case_value_flag_consumes_its_value \
    case_uv_python_selector_not_a_package \
    case_unknown_leading_flag_fails_closed \
    case_unknown_leading_flag_eqform_escapes \
    case_leading_flag_benign_command_passes \
    case_optional_boolean_explicit_value_gates \
    case_optional_boolean_without_value_still_gates \
    case_pnpm_config_switch_not_value \
    case_pip_use_feature_takes_value \
    case_bun_equals_only_flag_not_space_value \
    case_npm_exec_hoisted_parent_bin_passthrough \
    case_npm_exec_parent_walk_resists_shadowing \
    case_npm_exec_package_flag_blocks \
    case_exec_value_flag_does_not_hide_package \
    case_exec_unknown_flag_fails_closed \
    case_exec_package_selector_flags \
    case_exec_boolean_flags_do_not_eat_package \
    case_npm_exec_post_positional_package \
    case_npm_exec_short_p_not_greedy_post_command \
    case_uv_with_requirements_refused \
    case_pnpx_audits_like_dlx \
    case_dlx_and_x_audit \
    case_uv_run_and_tool_run_gate \
    case_uv_short_with_and_boundary \
    case_uv_run_program_arg_not_audited \
    case_uv_tool_run_short_with_keeps_tool \
    case_uv_tool_run_with_extra_is_audited \
    case_uv_run_value_flag_before_with \
    case_go_run_module_gates \
    case_go_run_value_flag_does_not_hide_module \
    case_update_family_gates \
    case_npm_abbreviation_classifier_gates_and_preserves_argv \
    case_npm_alias_prefixes_and_priority \
    case_npm_camelcase_dispatch_and_conservative_ambiguity \
    case_non_npm_abbreviations_stay_passthrough \
    case_composer_canonical_or_refuse \
    case_composer_global_canonical_routing \
    case_npm_dedupe_lockdiff_empty_delegates_without_scan \
    case_npm_lockdiff_absent_node_modules_refuses \
    case_npm_lockdiff_projection_sees_project_npmrc \
    case_npm_dedupe_lockdiff_introduced_block_refuses_without_delegation \
    case_npm_dedupe_lockdiff_parse_failure_fails_closed \
    case_npm_prune_lockdiff_introduced_block_refuses_without_delegation \
    case_npm_lockdiff_prefixes_route_to_projection \
    case_npm_lockdiff_refuses_bare_option_terminator \
    case_npm_lockdiff_effective_config_oracle \
    case_npm_lockdiff_refuses_nonregistry_sources \
    case_npm_lockdiff_registry_host_provenance \
    case_npm_lockdiff_safe_core_is_pinned_and_strict \
    case_npm_lockdiff_refuses_missing_scan_coverage \
    case_npm_lockdiff_warn_matches_install_lane \
    case_exec_passthrough_by_design \
    case_global_package_check \
    case_local_project_scan \
    case_add_scans_and_checks \
    case_blocked_install \
    case_block_refusal_never_hints_allow \
    case_warning_install_blocks \
    case_host_allow_warn_allows_exact_global_install \
    case_host_allow_warn_requires_exact_version \
    case_npm_colon_version_global_install \
    case_npm_alias_audits_target_package \
    case_audit_failure_blocks \
    case_critical_scan_non_tty_aborts \
    case_critical_in_result_blocks_despite_exit_zero \
    case_broken_scanner_warns_and_proceeds \
    case_malformed_result_document_is_not_read_as_clean \
    case_clean_result_proceeds_quietly \
    case_missing_safe_audit_warns_per_command \
    case_non_install_passthrough \
    case_npm_complex_flags \
    case_pip_complex_flags \
    case_requirement_install_scans \
    case_cargo_parser \
    case_go_parser \
    case_composer_parser \
    case_pip_cumulative_sources_all_reach_audit \
    case_npm_scoped_and_userconfig_sources_reach_audit \
    case_source_credentials_preserved_for_audit \
    case_gate_never_leaks_sources_to_the_real_tool \
    case_npm_repeated_registry_keeps_true_last \
    case_stale_evidence_is_source_scoped \
    case_install_idempotent_no_wrappers \
    case_install_idempotent_with_completions \
    case_install_writes_gate_wrappers \
    case_uv_binary_is_displaced_and_gated \
    case_uv_displacement_refuses_to_clobber_an_existing_original \
    case_failed_wrapper_write_restores_the_displaced_binary \
    case_uninstall_restores_the_displaced_binary \
    case_gate_resolves_a_displaced_original \
    case_gate_resolves_a_wrapped_mise_shim \
    case_gate_exec_delegates_through_a_wrapped_mise_shim \
    case_gate_audit_leash_fits_component_budgets \
    case_gate_audit_receives_socket_budget \
    case_run_all_excludes_live_socket_envelope \
    case_gate_audit_fd_exhaustion_fails_closed \
    case_gate_leash_kills_a_wedged_audit \
    case_selective_install_refreshes_gate_lib \
    case_loose_marker_is_not_ownership \
    case_status_probes_every_wrapper \
    case_wrappers_not_on_path_are_unhealthy \
    case_dash_bin_root_never_reports_healthy \
    case_doctor_podman_probe_skips_exec_under_no_new_privs \
    case_uv_index_selectors_reach_audit \
    case_uninstall_removes_gate_wrappers \
    case_install_cleans_legacy_safe_install_artifacts \
    case_install_preserves_symlinked_zshrc \
    case_install_merges_legacy_state_into_new_schema \
    case_uninstall_preserves_symlinked_zshrc \
    case_mise_use_backend_audits \
    case_mise_runtime_and_other_backends_pass \
    case_mise_bare_install_preflights_config \
    case_mise_bare_upgrade_audits_floating \
    case_mise_exec_gates_inner_command \
    case_mise_leading_flag_fails_closed \
    case_mise_bare_shorthand_resolves_backend \
    case_mise_bare_config_pinned_names_the_spec \
    case_mise_spec_canonicalization \
    case_mise_preflight_fails_closed \
    case_mise_install_flags_are_modeled \
    case_mise_up_numeric_floating_and_bump \
    case_mise_exec_auto_install_preflight \
    case_mise_env_overlay_reaches_audit \
    case_mise_bare_use_refused \
    case_mise_flag_semantics_match_delegate \
    case_mise_display_only_invocations_pass \
    case_mise_helper_queries_use_delegate_context \
    case_mise_env_transport_is_lossless \
    case_mise_tool_options_are_not_discarded \
    case_mise_entry_schema_is_strict \
    case_mise_unmodeled_sources_are_not_vouched \
    case_mise_scoped_exclusion_and_interactive \
    case_mise_infra_refusals_are_one_line \
    case_mise_leading_global_help_passes \
    case_mise_env_values_round_trip_exactly \
    case_mise_entry_requires_requested_version \
    case_mise_option_checks_cover_every_preflight \
    case_mise_unmodeled_sources_cover_ambient_and_inner \
    case_mise_env_transport_handles_unicode_and_nul \
    case_mise_option_attribution_covers_cli_and_hidden_rows \
    case_mise_bump_audits_the_moved_target \
    case_mise_upgrade_lookup_is_canonical_and_ordered \
    case_mise_npm_installer_reads_mise_settings \
    case_mise_rows_snapshot_is_shared \
    case_mise_exclusion_canonicalization_fails_closed \
    case_mise_bump_requires_a_configured_target \
    case_mise_installer_values_are_validated \
    case_mise_multi_target_shares_one_snapshot \
    case_mise_setting_output_is_strict \
    case_zsh_stub_warns_on_missing_mise_wrapper \
    case_mise_wrapper_dispatches_foreign_argv0 \
    case_mise_wrapper_dispatch_without_real_mise_is_legible \
    case_mise_wrapper_helper_matches_installer_output \
    case_uninstall_cleans_shell_and_legacy_binaries \
    case_safe_run_gated_tool_delegation
  do
    "$case"
  done

  printf '%s passed, %s failed\n' "${PASS_COUNT}" "${FAIL_COUNT}"
  [[ "${FAIL_COUNT}" -eq 0 ]]
}

main "$@"
