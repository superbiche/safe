#!/usr/bin/env bash
set -u

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
ZSH_BIN="$(command -v zsh)"
TEST_ROOT="$(mktemp -d)"
PASS_COUNT=0
FAIL_COUNT=0

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
  printf 'REAL\t%s' "${tool}"
  for arg in "$@"; do
    printf '\t%s' "${arg}"
  done
  printf '\n'
} >> "${SAFE_INSTALL_COMMAND_LOG}"
exit "${SAFE_INSTALL_REAL_STATUS:-0}"
STUB
  chmod +x "${bin_dir}/${tool}"
}

write_safe_audit_stub() {
  local bin_dir="$1"

  cat > "${bin_dir}/safe-audit" <<'STUB'
#!/usr/bin/env bash
{
  printf 'AUDIT'
  for arg in "$@"; do
    printf '\t%s' "${arg}"
  done
  printf '\n'
} >> "${SAFE_INSTALL_COMMAND_LOG}"

if [[ "${1:-}" == "scan" ]]; then
  [[ -n "${SAFE_AUDIT_SCAN_OUTPUT:-}" ]] && printf '%s\n' "${SAFE_AUDIT_SCAN_OUTPUT}"
  exit "${SAFE_AUDIT_SCAN_STATUS:-0}"
fi

for arg in "$@"; do
  case "${arg}" in
    *blockme*) exit 20 ;;
    *warnme*) exit 10 ;;
  esac
done

exit "${SAFE_AUDIT_CHECK_STATUS:-0}"
STUB
  chmod +x "${bin_dir}/safe-audit"

  cat > "${bin_dir}/safe" <<'STUB'
#!/usr/bin/env bash
if [[ "${1:-}" == "audit" ]]; then
  shift
  exec safe-audit "$@"
fi

printf 'unexpected safe command: %s\n' "$*" >&2
exit 99
STUB
  chmod +x "${bin_dir}/safe"
}

prepare_case() {
  local name="$1"
  local with_safe_audit="${2:-yes}"
  CASE_DIR="${TEST_ROOT}/${name}"
  BIN_DIR="${CASE_DIR}/bin"
  WORK_DIR="${CASE_DIR}/work"
  HOME_DIR="${CASE_DIR}/home"
  LOG_FILE="${CASE_DIR}/commands.log"
  OUT_FILE="${CASE_DIR}/stdout.log"
  ERR_FILE="${CASE_DIR}/stderr.log"

  mkdir -p "${BIN_DIR}" "${WORK_DIR}" "${HOME_DIR}"
  : > "${LOG_FILE}"
  : > "${OUT_FILE}"
  : > "${ERR_FILE}"

  local tool
  for tool in npm pnpm yarn bun uv pip pip3 cargo go composer volta; do
    write_tool_stub "${BIN_DIR}" "${tool}"
  done

  if [[ "${with_safe_audit}" == "yes" ]]; then
    write_safe_audit_stub "${BIN_DIR}"
  fi
}

run_zsh() {
  (
    cd "${WORK_DIR}" || exit 99
    ROOT_DIR="${ROOT_DIR}" \
    HOME="${HOME_DIR}" \
    PATH="${BIN_DIR}:/usr/bin:/bin" \
    SAFE_INSTALL_COMMAND_LOG="${LOG_FILE}" \
    SAFE_INSTALL_TEST_SCRIPT="${SAFE_INSTALL_TEST_SCRIPT:-}" \
    SAFE_AUDIT_SCAN_OUTPUT="${SAFE_AUDIT_SCAN_OUTPUT:-}" \
    SAFE_AUDIT_SCAN_STATUS="${SAFE_AUDIT_SCAN_STATUS:-}" \
    SAFE_AUDIT_CHECK_STATUS="${SAFE_AUDIT_CHECK_STATUS:-}" \
    SAFE_INSTALL_REAL_STATUS="${SAFE_INSTALL_REAL_STATUS:-}" \
    "${ZSH_BIN}" -fc 'source "${ROOT_DIR}/lib/install-wrappers.zsh"; eval "${SAFE_INSTALL_TEST_SCRIPT}"'
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

# Simulates a harness shell snapshot that keeps the public wrapper functions
# but strips all safe_install_* helpers (the Claude Code silent-127 regression).
STRIP_HELPERS='for f in ${(k)functions}; do [[ "$f" == safe_install_* ]] && unfunction "$f"; done; '

case_degraded_install_blocks_legibly() {
  prepare_case "degraded-install-blocks-legibly"
  SAFE_INSTALL_TEST_SCRIPT="${STRIP_HELPERS}npm install left-pad" run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_err_contains_fragment 'safe: BLOCKED npm install' "$FUNCNAME" || return
  assert_err_contains_fragment 'safe explain' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_degraded_exec_blocks_legibly() {
  prepare_case "degraded-exec-blocks-legibly"
  SAFE_INSTALL_TEST_SCRIPT="${STRIP_HELPERS}pnpm dlx cowsay" run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_err_contains_fragment 'safe: BLOCKED pnpm dlx' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tpnpm' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_degraded_non_install_passes_through() {
  prepare_case "degraded-non-install-passes-through"
  SAFE_INSTALL_TEST_SCRIPT="${STRIP_HELPERS}npm --version && volta list node && composer validate" run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\t--version' "$FUNCNAME" || return
  assert_log_contains $'REAL\tvolta\tlist\tnode' "$FUNCNAME" || return
  assert_log_contains $'REAL\tcomposer\tvalidate' "$FUNCNAME" || return
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

case_global_package_check() {
  prepare_case "global-package-check"
  SAFE_INSTALL_TEST_SCRIPT='npm install -g left-pad@1.3.0' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tleft-pad@1.3.0\t--ecosystem\tnpm' "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tinstall\t-g\tleft-pad@1.3.0' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_local_project_scan() {
  prepare_case "local-project-scan"
  touch "${WORK_DIR}/package.json"
  SAFE_INSTALL_TEST_SCRIPT='npm ci' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tscan\t--project\t.' "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tci' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_add_scans_and_checks() {
  prepare_case "add-scans-and-checks"
  touch "${WORK_DIR}/package.json"
  SAFE_INSTALL_TEST_SCRIPT='pnpm add --filter web --workspace-root lodash' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tscan\t--project\t.' "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tlodash@latest\t--ecosystem\tnpm' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'\tweb\t--ecosystem' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_blocked_install() {
  prepare_case "blocked-install"
  SAFE_INSTALL_TEST_SCRIPT='npm install -g blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme@latest\t--ecosystem\tnpm' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_warning_install_blocks() {
  prepare_case "warning-install-blocks"
  SAFE_INSTALL_TEST_SCRIPT='npm install -g warnme' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\twarnme@latest\t--ecosystem\tnpm' "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tcheck\twarnme@1.0.0\t--ecosystem\tnpm' "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tcheck\twarnme@1.0.1\t--ecosystem\tnpm' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_colon_version_global_install() {
  prepare_case "npm-colon-version-global-install"
  SAFE_INSTALL_TEST_SCRIPT='npm install -g @qwen-code/qwen-code:0.16.2' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\t@qwen-code/qwen-code@0.16.2\t--ecosystem\tnpm' "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tinstall\t-g\t@qwen-code/qwen-code:0.16.2' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_alias_audits_target_package() {
  prepare_case "npm-alias-audits-target-package"
  SAFE_INSTALL_TEST_SCRIPT='npm install -g qwen@npm:@qwen-code/qwen-code@0.16.2' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\t@qwen-code/qwen-code@0.16.2\t--ecosystem\tnpm' "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tinstall\t-g\tqwen@npm:@qwen-code/qwen-code@0.16.2' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_audit_failure_blocks() {
  prepare_case "audit-failure-blocks"
  SAFE_AUDIT_CHECK_STATUS=42 SAFE_INSTALL_TEST_SCRIPT='uv tool install repomix' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\trepomix@latest\t--ecosystem\tpython' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tuv' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_critical_scan_non_tty_aborts() {
  prepare_case "critical-scan-non-tty-aborts"
  touch "${WORK_DIR}/package.json"
  SAFE_AUDIT_SCAN_OUTPUT='critical vulnerability' SAFE_AUDIT_SCAN_STATUS=1 SAFE_INSTALL_TEST_SCRIPT='npm ci' run_zsh
  assert_status 102 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tscan\t--project\t.' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_missing_safe_audit_warns_once() {
  prepare_case "missing-safe-audit-warns-once" no
  SAFE_INSTALL_TEST_SCRIPT='npm install -g one; npm install -g two' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_count 1 'safe audit not installed, skipping pre-install check' "${ERR_FILE}" "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tcheck\tleft-pad@latest\t--ecosystem\tnpm' "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tcheck\trequests@2.32.0\t--ecosystem\tpython' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'\thttps://pypi.example@latest' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'\tconstraints.txt@latest' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_requirement_install_scans() {
  prepare_case "requirement-install-scans"
  SAFE_INSTALL_TEST_SCRIPT='pip install -r requirements.txt' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tscan\t--project\t.' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'AUDIT\tcheck' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_cargo_parser() {
  prepare_case "cargo-parser"
  SAFE_INSTALL_TEST_SCRIPT='cargo install ripgrep --version 14.1.1' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tripgrep@latest\t--ecosystem\tcargo' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'\t14.1.1@latest' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_go_parser() {
  prepare_case "go-parser"
  SAFE_INSTALL_TEST_SCRIPT='go install -tags netgo example.com/tool@v1.2.3' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\texample.com/tool@v1.2.3\t--ecosystem\tgo' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'\tnetgo@latest' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_composer_parser() {
  prepare_case "composer-parser"
  SAFE_INSTALL_TEST_SCRIPT='composer global require --working-dir /tmp vendor/pkg:^1' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tvendor/pkg@^1\t--ecosystem\tcomposer' "$FUNCNAME" || return
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

main() {
  local case
  for case in \
    case_degraded_install_blocks_legibly \
    case_degraded_exec_blocks_legibly \
    case_degraded_non_install_passes_through \
    case_refusal_message_contract \
    case_global_package_check \
    case_local_project_scan \
    case_add_scans_and_checks \
    case_blocked_install \
    case_warning_install_blocks \
    case_host_allow_warn_allows_exact_global_install \
    case_host_allow_warn_requires_exact_version \
    case_npm_colon_version_global_install \
    case_npm_alias_audits_target_package \
    case_audit_failure_blocks \
    case_critical_scan_non_tty_aborts \
    case_missing_safe_audit_warns_once \
    case_non_install_passthrough \
    case_npm_complex_flags \
    case_pip_complex_flags \
    case_requirement_install_scans \
    case_cargo_parser \
    case_go_parser \
    case_composer_parser \
    case_install_idempotent_no_wrappers \
    case_install_idempotent_with_completions \
    case_install_cleans_legacy_safe_install_artifacts \
    case_install_preserves_symlinked_zshrc \
    case_install_merges_legacy_state_into_new_schema \
    case_uninstall_preserves_symlinked_zshrc \
    case_uninstall_cleans_shell_and_legacy_binaries
  do
    "$case"
  done

  printf '%s passed, %s failed\n' "${PASS_COUNT}" "${FAIL_COUNT}"
  [[ "${FAIL_COUNT}" -eq 0 ]]
}

main "$@"
