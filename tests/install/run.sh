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

  # The real dispatcher: `safe gate` is under test, so nothing about it is
  # stubbed. Only safe-audit is (via SAFE_AUDIT_PATH, see run_zsh).
  ln -sf "${ROOT_DIR}/bin/safe" "${BIN_DIR}/safe"

  write_gate_wrappers "${WRAPPER_DIR}"

  if [[ "${with_safe_audit}" == "yes" ]]; then
    write_safe_audit_stub "${BIN_DIR}"
  fi
}

# Gate mode: the wrappers sit ahead of the tool stubs on PATH, so a command
# resolves to the wrapper executable, which execs `safe gate <tool>`. Nothing
# is sourced into the shell — that is the point of the port, and running the
# script under `zsh -fc` proves the gate no longer depends on shell state.
run_zsh() {
  (
    cd "${WORK_DIR}" || exit 99
    ROOT_DIR="${ROOT_DIR}" \
    HOME="${HOME_DIR}" \
    PATH="${WRAPPER_DIR}:${BIN_DIR}:/usr/bin:/bin" \
    SAFE_AUDIT_PATH="${BIN_DIR}/safe-audit" \
    SAFE_INSTALL_COMMAND_LOG="${LOG_FILE}" \
    SAFE_INSTALL_TEST_SCRIPT="${SAFE_INSTALL_TEST_SCRIPT:-}" \
    SAFE_AUDIT_SCAN_OUTPUT="${SAFE_AUDIT_SCAN_OUTPUT:-}" \
    SAFE_AUDIT_SCAN_STATUS="${SAFE_AUDIT_SCAN_STATUS:-}" \
    SAFE_AUDIT_CHECK_STATUS="${SAFE_AUDIT_CHECK_STATUS:-}" \
    SAFE_INSTALL_REAL_STATUS="${SAFE_INSTALL_REAL_STATUS:-}" \
    "${ZSH_BIN}" -fc 'eval "${SAFE_INSTALL_TEST_SCRIPT}"'
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
  assert_log_contains $'AUDIT\tcheck\tblockme@1.2.3\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
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
  SAFE_INSTALL_TEST_SCRIPT='bun --config=bunfig.toml add blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tcheck\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tcheck\tcowsay\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tscan\t--project\t.' "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tscan\t--project\t.' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm' "$FUNCNAME" || return
  assert_err_contains_fragment 'safe: BLOCKED install — safe audit scan found critical findings' "$FUNCNAME" || return
  assert_err_not_contains_fragment 'safe install: safe audit scan reported critical findings' "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tscan\t--project\t.' "$FUNCNAME" || return
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
  for tool in npm pnpx yarn bun pip pip3 uv cargo go composer; do
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
  grep -Fq 'wrappers:       ok (11/11' <<<"${status_out}" || { printf '%s\n' "${status_out}" >&2; fail "$FUNCNAME"; return; }

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
  for tool in npm pnpm pnpx yarn bun pip pip3 uv cargo go composer; do
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
  for tool in npm pnpm pnpx yarn bun pip pip3 uv cargo go; do
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

case_wrapper_state_cleared_after_gate() {
  prepare_case "wrapper-state-cleared"
  # A long-lived interactive shell must not retain the scanned source set
  # (possibly credential-bearing) after the gate decision (delta-7 N2).
  SAFE_INSTALL_TEST_SCRIPT='npm install --registry https://alice:sekret@mirror.example okpkg@1.0.0; print -r -u2 -- "POST_REG=[${SAFE_INSTALL_REGISTRY:-}][${SAFE_INSTALL_NPM_USERCONFIG:-}]"' run_zsh
  assert_err_contains_fragment 'POST_REG=[][]' "$FUNCNAME" || return

  # The PROJECT-install route (no positional packages) scans too and must
  # clear equally — cleanup tied to check_many missed it (delta-8 N2).
  SAFE_INSTALL_TEST_SCRIPT='npm install --registry https://alice:sekret@mirror.example; print -r -u2 -- "POST_PROJ=[${SAFE_INSTALL_REGISTRY:-}]"' run_zsh
  assert_err_contains_fragment 'POST_PROJ=[]' "$FUNCNAME" || return
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
    case_exec_passthrough_by_design \
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
    case_wrapper_state_cleared_after_gate \
    case_npm_repeated_registry_keeps_true_last \
    case_stale_evidence_is_source_scoped \
    case_install_idempotent_no_wrappers \
    case_install_idempotent_with_completions \
    case_install_writes_gate_wrappers \
    case_selective_install_refreshes_gate_lib \
    case_loose_marker_is_not_ownership \
    case_status_probes_every_wrapper \
    case_wrappers_not_on_path_are_unhealthy \
    case_uv_index_selectors_reach_audit \
    case_uninstall_removes_gate_wrappers \
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
