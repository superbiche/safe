#!/usr/bin/env bash
set -u

# A real node binary (not a shim), found BEFORE the harness isolates HOME and PATH: for the probe script, which runs on a real node.
REAL_NODE_BIN="$(node -p process.execPath 2>/dev/null || true)"
[[ -x "${REAL_NODE_BIN}" ]] || REAL_NODE_BIN=""
# SAFE_TEST_ISOLATION_MARKER: every suite owns a scratch HOME and safe state.
# shellcheck source=tests/lib/test-isolation.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/test-isolation.sh"
safe_test_setup_isolation || exit 1
# These cases assert install defaults relative to each case's HOME and set
# explicit SAFE_* paths only where a case is testing an override.
unset SAFE_CONFIG_DIR SAFE_DATA_DIR SAFE_RUN_CONFIG_DIR SAFE_RUN_DATA_DIR \
  SAFE_AUDIT_CONFIG_DIR SAFE_AUDIT_DATA_DIR SAFE_AUDIT_BIN_DIR \
  SAFE_AUDIT_SCANNER_DIR SAFE_AUDIT_SOCKET_CACHE_DIR SAFE_BIN_DIR \
  SAFE_ZSH_COMPLETION_DIR SAFE_RUN_SEED_DIR
unset MISE_CONFIG_DIR MISE_DATA_DIR MISE_CACHE_DIR

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

# Build safe-core with the real go toolchain, never safe's own gate wrapper
# (real-tool.sh): the belt is harness, not a package install to audit.
# shellcheck source=tests/lib/real-tool.sh
source "${ROOT_DIR}/tests/lib/real-tool.sh"
if GO_BIN="$(real_tool go)"; then
  if ( cd "${ROOT_DIR}" && "${GO_BIN}" build -trimpath -ldflags "-X main.version=$(tr -d '[:space:]' < VERSION)" -o "${SAFE_CORE_TEST_BIN}" ./cmd/safe-core ); then
    SAFE_CORE_TEST_AVAILABLE=1
  else
    printf 'not ok - safe-core test binary build failed\n' >&2
    exit 1
  fi
elif command -v go >/dev/null 2>&1; then
  printf "SKIP: go on PATH is only safe's gate wrapper, no real toolchain behind it; safe-core lockdiff install cases are skipped\n" >&2
else
  printf 'SKIP: Go is unavailable; safe-core lockdiff install cases are skipped\n' >&2
fi

cleanup() {
  rm -rf "${TEST_ROOT}"
}
safe_test_compose_exit_trap cleanup

fail() {
  printf 'not ok - %s\n' "$1" >&2
  FAIL_COUNT=$((FAIL_COUNT + 1))
}

pass() {
  printf 'ok - %s\n' "$1"
  PASS_COUNT=$((PASS_COUNT + 1))
}

# The node the lane runs next to npm: it answers the platform query of the
# selection (NODE_SELECTION_JSON, from the case's knobs) and logs which node ran.
write_node_stub() {
  cat > "$1/node" <<'NODE'
#!/usr/bin/env bash
# The "npm-cli.js" of the hermetic layout is a shell script of the npm stub; the
# node that starts it is logged, and nothing else of the case's knobs is read here.
case "${1:-}" in
  *npm-cli.js)
    if [[ -n "${HOME:-}" && -r "${HOME}/.stub-env0" ]]; then
      node_log="$(tr '\0' '\n' < "${HOME}/.stub-env0" | sed -n 's/^SAFE_INSTALL_COMMAND_LOG=//p' | head -n1)"
      [[ -z "${node_log}" ]] || printf 'NODEBIN\t%s\n' "$0" >> "${node_log}"
    fi
    exec bash "$@"
    ;;
esac
if [[ -n "${HOME:-}" && -r "${HOME}/.stub-env0" ]]; then
  while IFS= read -r -d '' kv; do
    name="${kv%%=*}"
    case "${name}" in PATH|HOME|PWD|OLDPWD|SHLVL|_|IFS) continue ;; esac
    [[ "${name}" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
    [[ -v "${name}" ]] || export "${name}=${kv#*=}"
  done < "${HOME}/.stub-env0"
fi
[[ -z "${SAFE_INSTALL_COMMAND_LOG:-}" ]] || printf 'NODEBIN\t%s\n' "$0" >> "${SAFE_INSTALL_COMMAND_LOG}"
case "${1:-}" in
  --version) echo v99.0.0; exit 0 ;;
  *lane-probe.cjs)
    mode="${3:-}"
    input="$(cat)"
    case "${mode}" in
      capability)
        out="${NODE_CAPABILITY_JSON:-}"
        [[ -n "${out}" ]] || out='{"version":"11.20.0","atFloor":true,"missing":[]}'
        printf '%s' "${out}"
        ;;
      agreement)
        count="$(( $(cat "${HOME}/.agreement-count" 2>/dev/null || echo 0) + 1 ))"
        printf '%s' "${count}" > "${HOME}/.agreement-count"
        out="${NODE_AGREEMENT_JSON:-}"
        [[ "${count}" -lt 2 || -z "${NODE_AGREEMENT_SECOND_JSON:-}" ]] || out="${NODE_AGREEMENT_SECOND_JSON}"
        [[ -n "${out}" ]] || out='{"disagreements":[]}'
        printf '%s' "${out}"
        ;;
      selection)
        [[ "${NODE_PROBE_STATUS:-0}" == "0" ]] || exit "${NODE_PROBE_STATUS}"
        if [[ -n "${NODE_SELECTION_RAW:-}" ]]; then
          printf '%s' "${NODE_SELECTION_RAW}"
        else
          runtime="${NODE_SELECTION_JSON:-}"
          [[ -n "${runtime}" ]] || runtime='{"os":"linux","cpu":"x64","libc":"glibc"}'
          jq -c --argjson rt "${runtime}" '.config as $c
            | def given($k): if ($c[$k] | type) == "string" and $c[$k] != "" then $c[$k] else null end;
              {os: (given("os") // $rt.os), cpu: (given("cpu") // $rt.cpu), libc: (given("libc") // $rt.libc),
               omit: (($c.omit // []) - ($c.include // []))}' <<<"${input}"
        fi
        ;;
    esac
    exit 0
    ;;
esac
exit 0
NODE
  chmod +x "$1/node"
}

write_tool_stub() {
  local bin_dir="$1"
  local tool="$2"

  cat > "${bin_dir}/${tool}" <<'STUB'
#!/usr/bin/env bash
tool="$(basename -- "$0")"
[[ "${tool}" != "npm-cli.js" ]] || tool=npm
# What the process was handed, before anything is re-read (the lane's npm gets an
# allow-listed environment, so the case's knobs travel in a file under HOME).
stub_env_names_before="$(env | cut -d= -f1 | LC_ALL=C sort | tr '\n' ' ')"
if [[ -n "${HOME:-}" && -r "${HOME}/.stub-env0" ]]; then
  while IFS= read -r -d '' kv; do
    name="${kv%%=*}"
    case "${name}" in PATH|HOME|PWD|OLDPWD|SHLVL|_|IFS) continue ;; esac
    [[ "${name}" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
    [[ -v "${name}" ]] || export "${name}=${kv#*=}"
  done < "${HOME}/.stub-env0"
fi
if [[ -n "${HOME:-}" && -e "${HOME}/.stub-log-env" && -n "${SAFE_INSTALL_COMMAND_LOG:-}" ]]; then
  printf 'ENVNAMES\t%s\n' "${stub_env_names_before}" >> "${SAFE_INSTALL_COMMAND_LOG}"
fi
is_projection=0
[[ "${SAFE_GATE_LOCKDIFF_PROJECTION:-0}" == "1" || "${1:-}" == "--package-lock-only" ]] && is_projection=1
{
  if (( is_projection )); then
    printf 'PROJECTION\t%s' "${tool}"
    # The projection must see the project's npm config (F3 ruling): surface
    # whether the scratch cwd carries the copied .npmrc.
    [[ -f .npmrc ]] && printf '\tPROJNPMRC'
    # #244: without the project's other package.json manifests the scratch is
    # a different workspace/file:-dep project than the delegate's, and npm
    # drops those entries from the projected lockfile silently. Surface every
    # non-root manifest the scratch received, root-relative and sorted.
    while IFS= read -r mirrored_manifest; do
      [[ -n "${mirrored_manifest}" ]] && printf '\tPROJMANIFEST:%s' "${mirrored_manifest}"
    done < <(find . -name node_modules -prune -o -mindepth 2 -name package.json -print 2>/dev/null \
      | sed 's|^\./||' | LC_ALL=C sort)
  else
    printf 'REAL\t%s' "${tool}"
  fi
  for arg in "$@"; do
    printf '\t%s' "${arg}"
  done
  printf '\n'
  printf 'NPMBIN\t%s\n' "$(realpath -- "$0")"
  if [[ -n "${LANE_TEST_PROJECT:-}" ]]; then
    for fd_link in /proc/$$/fd/*; do
      [[ "$(readlink "${fd_link}" 2>/dev/null)" == "${LANE_TEST_PROJECT}" ]] && printf 'LOCKFD_INHERITED\t%s\n' "$*"
    done
  fi
  # pnpm's dependency check before a script run: the value the delegate
  # would see (logged only when set, so other assertions are unaffected).
  if [[ -n "${pnpm_config_verify_deps_before_run:-}" ]]; then
    printf 'VERIFYDEPS\t%s\n' "${pnpm_config_verify_deps_before_run}"
  fi
  [[ -z "${NODE_OPTIONS:-}" ]] || printf 'NODEOPT\t%s\n' "${NODE_OPTIONS}"
  [[ -z "${SAFE_GATE_LANE_SCRATCH:-}" ]] || printf 'LANEVAR\t%s\n' "${SAFE_GATE_LANE_SCRATCH}"
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
# npm reports the EFFECTIVE os/cpu here — resolved from every config source,
# as a string, or null when nothing sets it. The gate reads that key instead
# of scanning the argv it was handed (#244), so this stub has to resolve it
# the way npm does: project .npmrc, then the environment (any case), then
# argv, last occurrence winning. An empty value is unset, matching npm's own
# reading of an empty environment variable; the `--os=` argv spelling, which
# npm reports as "", is not modeled.
stub_effective_platform() {
  local key="$1"
  shift
  local found="" token previous="" env_key rc_line
  if [[ -f .npmrc ]]; then
    while IFS= read -r rc_line || [[ -n "${rc_line}" ]]; do
      [[ "${rc_line}" == "${key}="* ]] && found="${rc_line#${key}=}"
    done < .npmrc
  fi
  for env_key in $(compgen -e); do
    [[ "${env_key,,}" == "npm_config_${key}" && -n "${!env_key}" ]] && found="${!env_key}"
  done
  for token in "$@"; do
    [[ "${previous}" == "--${key}" ]] && found="${token}"
    [[ "${token}" == "--${key}="* ]] && found="${token#--${key}=}"
    previous="${token}"
  done
  [[ -n "${found}" ]] && printf '%s' "${found}"
  return 0
}

# Two npm behaviors make one rc file report different settings from the
# project and from the scratch, which is the divergence the parity check
# exists to catch (r1 review F3): ${PWD} is expanded against the CWD of the
# process reading it, and a relative path value is resolved against that same
# CWD. Only those two shapes are modeled — they are precisely the ones whose
# reported value depends on where npm ran, so nothing else in the suite moves.
stub_cwd_dependent_rc_json() {
  local line key value out='{}'
  if [[ -f .npmrc ]]; then
    while IFS= read -r line || [[ -n "${line}" ]]; do
      # ini comments are not settings; npm reports nothing for them.
      [[ "${line}" =~ ^[[:space:]]*[\;\#] ]] && continue
      [[ "${line}" == *=* ]] || continue
      key="${line%%=*}"
      value="${line#*=}"
      key="${key// /}"
      value="${value#"${value%%[![:space:]]*}"}"
      # A backslash escapes the reference: npm reports the literal text, so
      # both lanes receive the same value and nothing diverges.
      if [[ "${value}" == *'\${'* ]]; then
        continue
      elif [[ "${value}" == *'${PWD}'* ]]; then
        value="${value//'${PWD}'/$PWD}"
      elif [[ "${value}" == ./* ]]; then
        value="${PWD}/${value#./}"
      else
        continue
      fi
      out="$(jq -cn --argjson base "${out}" --arg k "${key}" --arg v "${value}" '$base + {($k): $v}')"
    done < .npmrc
  fi
  printf '%s' "${out}"
}

# npm always reports the config FILE paths it resolved, and the hidden-config
# guard reads those keys both to know which files to scan and to know that
# userconfig/globalconfig are settings npm does report.
stub_config_file_json() {
  local token previous="" userconfig="${HOME}/.npmrc"
  for token in "$@"; do
    [[ "${previous}" == "--userconfig" ]] && userconfig="${token}"
    [[ "${token}" == --userconfig=* ]] && userconfig="${token#--userconfig=}"
    previous="${token}"
  done
  jq -cn --arg u "${userconfig}" --arg g "${HOME}/etc/npmrc" \
    '{userconfig: $u, globalconfig: $g}'
}

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
    platform_json="$(jq -cn \
      --arg os "$(stub_effective_platform os "$@")" \
      --arg cpu "$(stub_effective_platform cpu "$@")" \
      '{os: (if $os == "" then null else $os end), cpu: (if $cpu == "" then null else $cpu end)}')"
    global_json='{}'
    # the operator's own global configuration file selects the global location, unless
    # a prefix override moves npm away from it (as npm derives that file from the prefix)
    prefix_override=0
    for arg in "$@"; do [[ "${arg}" == --prefix=* || "${arg}" == "--prefix" ]] && prefix_override=1; done
    if (( ! prefix_override )) && [[ -f "${HOME}/etc/npmrc" ]] && grep -q '^location=global$' "${HOME}/etc/npmrc"; then
      global_json='{"global":true,"location":"global"}'
    fi
    for arg in "$@"; do
      [[ "${arg}" == "--" ]] && break
      [[ "${arg}" == "-g" || "${arg}" == "--global" ]] && global_json='{"global":true,"location":"global"}'
    done
    git_json='{}'
    for arg in "$@"; do
      [[ "${arg}" == --git=* ]] && git_json="$(jq -cn --argjson b "${git_json}" --arg v "${arg#--git=}" '$b + {git: $v}')"
      [[ "${arg}" == --allow-git=* ]] && git_json="$(jq -cn --argjson b "${git_json}" --arg v "${arg#--allow-git=}" '$b + {"allow-git": $v}')"
    done
    [[ "${NPM_STUB_NO_GIT_OPTIONS:-0}" != "1" ]] || git_json='{}'
    # npm reads its project configuration file: a FIFO there blocks it, as it would the real one.
    [[ ! -p .npmrc ]] || cat .npmrc >/dev/null
    # npm creates a relative cache directory in its working directory.
    if [[ -f .npmrc ]] && grep -q '^cache=\./' .npmrc; then
      mkdir -p "$(sed -n 's#^cache=\./\(.*\)$#\1#p' .npmrc | head -n1)"
    fi
    if [[ -n "${NPM_CONFIG_LIST_RAW:-}" ]]; then printf '%s' "${NPM_CONFIG_LIST_RAW}"; exit 0; fi
    cwd_json="$(stub_cwd_dependent_rc_json)"
    files_json="$(stub_config_file_json "$@")"
    # Order is npm's resolution order, not convenience: a value npm expands or
    # resolves against the cwd is what it REPORTS, so it wins over the raw
    # platform reading of the same key, and an explicit fixture override wins
    # over everything.
    jq -cn --argjson a "${effective_json}" --argjson b "${registry_json}" --argjson c "${platform_json}" \
      --argjson d "${cwd_json}" --argjson e "${files_json}" --argjson g "${global_json}" --argjson h "${git_json}" '$b * $e * $c * $d * $a * $g * $h' 2>/dev/null \
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

# Project lane: a frozen materialisation. `npm ci` builds node_modules from the
# lockfile it finds in its working directory (the binder's staging directory),
# the way npm does: it clears the tree first and, with package-lock-only set by
# any source, extracts nothing. The NPM_CI_* knobs make it misbehave the ways
# the lane must catch.
if [[ "${tool}" == "npm" && "${1:-}" == "ci" && ${is_projection} -eq 0 && "${NPM_CI_MATERIALISE:-0}" == "1" ]]; then
  printf 'CILOCK\t%s\n' "$(sha256sum package-lock.json | cut -d' ' -f1)" >> "${SAFE_INSTALL_COMMAND_LOG}"
  printf 'CICWD\t%s\n' "$(basename "${PWD}")" >> "${SAFE_INSTALL_COMMAND_LOG}"
  omit_dev=0
  lock_only=0
  [[ "${npm_config_package_lock_only:-}" == "true" ]] && lock_only=1
  for arg in "$@"; do
    [[ "${arg}" == "--omit=dev" ]] && omit_dev=1
    [[ "${arg}" == "--package-lock-only" ]] && lock_only=1
  done
  rm -rf node_modules
  mkdir -p node_modules
  if (( ! lock_only )); then
    while IFS=$'\t' read -r key version name dev; do
      [[ " ${NPM_CI_SKIP:-} " == *" ${key} "* ]] && continue
      (( omit_dev )) && [[ "${dev}" == "true" ]] && continue
      [[ "${name}" != "-" ]] || name="${key##*node_modules/}"
      shown_version="${version}"
      [[ -n "${NPM_CI_WRONG_VERSION:-}" && "${NPM_CI_WRONG_VERSION%%=*}" == "${key}" ]] && shown_version="${NPM_CI_WRONG_VERSION#*=}"
      [[ -n "${NPM_CI_WRONG_NAME:-}" && "${NPM_CI_WRONG_NAME%%=*}" == "${key}" ]] && name="${NPM_CI_WRONG_NAME#*=}"
      mkdir -p "${key}"
      printf '{"name":"%s","version":"%s"}\n' "${name}" "${shown_version}" > "${key}/package.json"
    done < <(jq -r '.packages | to_entries[] | select(.key | test("node_modules/")) | select(.value.link != true) | [.key, .value.version, (.value.name // "-"), ((.value.dev // false) | tostring)] | @tsv' package-lock.json)
  fi
  rmdir node_modules 2>/dev/null
  if [[ -n "${NPM_CI_EXTRA:-}" ]]; then
    mkdir -p "node_modules/${NPM_CI_EXTRA%@*}"
    printf '{"name":"%s","version":"%s"}\n' "${NPM_CI_EXTRA%@*}" "${NPM_CI_EXTRA##*@}" > "node_modules/${NPM_CI_EXTRA%@*}/package.json"
  fi
  [[ -n "${NPM_CI_MUTATE_PROJECT:-}" ]] && printf '\n' >> "${NPM_CI_MUTATE_PROJECT}"
  [[ "${NPM_CI_INTERRUPT:-0}" == "1" ]] && { kill -TERM "${PPID}"; sleep 1; }
  # A signal to the SHELL that waits for the binder (the binder's parent).
  [[ "${NPM_CI_SIGNAL_GATE:-0}" == "1" ]] && { kill -TERM "$(ps -o ppid= -p "${PPID}" | tr -d ' ')"; sleep 1; }
  if [[ "${NPM_CI_DIAGNOSTIC:-}" == "2" ]]; then
    printf 'npm error Authorization: Bearer abc.def.ghi123456\nnpm error fetch https://h.example/x#frag-secret\nnpm error c1 \xc2\x9b31mred\nnpm error code E500\nnpm error last-line no-newline-token=abc999' >&2
  elif [[ "${NPM_CI_DIAGNOSTIC:-}" == "3" ]]; then
    printf 'npm error AUTHORIZATION: BEARER UPPERTOKEN12345\nnpm error PROXY-AUTHORIZATION: BASIC dXNlcjpwYXNzd29yZA\nnpm error mark \xe2\x80\x8fRTL\xe2\x80\xaeX\nnpm error code E500\n' >&2
  elif [[ -n "${NPM_CI_DIAGNOSTIC:-}" ]]; then
    printf 'npm error fetch https://user:hunter2@registry.example/x?token=abc123 \033[31mred\033[0m\nnpm error code E500\n' >&2
  fi
  exit "${NPM_CI_STATUS:-0}"
fi

# Project lane projection knobs: a manifest the projection writes, a file of
# the project that changes while the command is being judged, a failure.
if [[ "${tool}" == "npm" && ${is_projection} -eq 1 && "${1:-}" == "--package-lock-only" ]]; then
  [[ -n "${NPM_PROJECTION_MANIFEST_JSON:-}" ]] && printf '%s\n' "${NPM_PROJECTION_MANIFEST_JSON}" > package.json
  [[ -n "${NPM_LANE_MUTATE_FILE:-}" ]] && printf '\n' >> "${NPM_LANE_MUTATE_FILE}"
  if [[ -n "${NPM_PROJECTION_FAIL:-}" ]]; then
    printf 'npm error code E404\nnpm error 404 Not Found - GET https://user:hunter2@registry.example/x\n' >&2
    exit "${NPM_PROJECTION_FAIL}"
  fi
fi

[[ -z "${NPM_LOCK_MUTATION_FILE:-}" ]] || NPM_LOCK_MUTATION_JSON="$(cat "${NPM_LOCK_MUTATION_FILE}")"
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
# A scripted private-registry check: a status and a result document.
if [[ "${1:-}" == "private-npm-project" && -n "${SAFE_AUDIT_PRIVATE_MOCK_STATUS:-}" ]]; then
  printf 'AUDIT\tprivate-npm-project\n' >> "${SAFE_INSTALL_COMMAND_LOG}"
  [[ -z "${SAFE_AUDIT_RESULT_OUT:-}" ]] || printf '%s' "${SAFE_AUDIT_PRIVATE_MOCK_RESULT:-}" > "${SAFE_AUDIT_RESULT_OUT}"
  exit "${SAFE_AUDIT_PRIVATE_MOCK_STATUS}"
fi
# The private-registry project check is the real one when a case asks for it.
if [[ "${1:-}" == "private-npm-project" && "${SAFE_AUDIT_REAL_PRIVATE:-0}" == "1" ]]; then
  printf 'AUDIT\tprivate-npm-project\n' >> "${SAFE_INSTALL_COMMAND_LOG}"
  printf 'PRIVATE_PATH\t%s\n' "${PATH}" >> "${SAFE_INSTALL_COMMAND_LOG}"
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

if [[ "${1:-}" == "repo-audit" ]]; then
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
    stub_by_ecosystem=""
    [[ -z "${SAFE_AUDIT_SCAN_BY_ECOSYSTEM:-}" ]] || stub_by_ecosystem=", \"by_ecosystem\": ${SAFE_AUDIT_SCAN_BY_ECOSYSTEM}"
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
    "ecosystem": [], "deduplicated": false${stub_by_ecosystem}
  },
  "tool_status": ${stub_tool_status},
  "ecosystem_audits": ${stub_eco_audits}
}
JSON
  fi
  exit "${SAFE_AUDIT_SCAN_STATUS:-0}"
fi

# Project lane advisory evidence (scanner-batch --evidence): the document the
# real reader writes, from fixture hits keyed "name@version"; the names asked
# for the blocklist alone are logged.
if [[ "${1:-}" == "scanner-batch" ]]; then
  evidence_input="$(cat)"
  printf 'EVIDENCE_INPUT\t%s\n' "$(jq -c '[.packages[] | "\(.name)@\(.version)"] | sort' <<<"${evidence_input}")" >> "${SAFE_INSTALL_COMMAND_LOG}"
  printf 'EVIDENCE_NAMES\t%s\n' "$(jq -c '(.blocklist_names // []) | sort' <<<"${evidence_input}")" >> "${SAFE_INSTALL_COMMAND_LOG}"
  [[ -z "${SAFE_AUDIT_EVIDENCE_STATUS:-}" ]] || exit "${SAFE_AUDIT_EVIDENCE_STATUS}"
  [[ -z "${SAFE_AUDIT_EVIDENCE_RAW:-}" ]] || { printf '%s' "${SAFE_AUDIT_EVIDENCE_RAW}"; exit 0; }
  ev_hits="${SAFE_AUDIT_EVIDENCE_HITS:-}"; [[ -n "${ev_hits}" ]] || ev_hits='{}'
  ev_missing="${SAFE_AUDIT_EVIDENCE_MISSING:-}"; [[ -n "${ev_missing}" ]] || ev_missing='[]'
  ev_blocklist="${SAFE_AUDIT_EVIDENCE_BLOCKLIST:-}"; [[ -n "${ev_blocklist}" ]] || ev_blocklist='[]'
  jq -n --argjson in "${evidence_input}" --argjson hits "${ev_hits}" --argjson miss "${ev_missing}" --argjson bl "${ev_blocklist}" '
    {schema_version: 1, policy: {block_severities: ["critical"]},
     identities: [ $in.packages[] | . as $p | "\($p.name)@\($p.version)" as $k
       | {name: $p.name, version: $p.version,
          coverage: (if ($miss | index($k)) then "missing" else "complete" end),
          gap: (if ($miss | index($k)) then "OSV batch failed" else "" end),
          advisories: ($hits[$k] // [])} ],
     blocklist: $bl}'
  exit 0
fi

for arg in "$@"; do
  case "${arg}" in
    *blockme*) exit 20 ;;
    *warnme*) exit 10 ;;
    *ratelimit*) exit 12 ;;
    *infrafail*) exit 11 ;;
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
[[ -z "${pnpm_config_verify_deps_before_run:-}" ]] || log_line VERIFYDEPS "${pnpm_config_verify_deps_before_run}"
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
  # symlinks to whatever `mise` resolves to, so a shim named after a gated
  # tool enters the gate under that name, and every other shim reaches the
  # real binary with argv[0] intact, never the gate.
  cat > "${wrapper_dir}/mise" <<'EOF'
#!/usr/bin/env bash
# safe-gate-wrapper v1 tool=mise
__safe_gated_argv0s=(npm pnpm pnpx yarn bun pip pip3 uv cargo go composer)
__safe_runner_argv0s=(npx bunx uvx)
__safe_argv0="${0##*/}"
if [[ "$__safe_argv0" != "mise" ]]; then
  for __t in "${__safe_runner_argv0s[@]}"; do
    [[ "$__safe_argv0" == "$__t" ]] || continue
    __r="$(readlink -f -- "${BASH_SOURCE[0]}" 2>/dev/null)"
    __r="${__r%/*}/safe-run"
    if [[ ! -x "$__r" ]]; then
      __r="$(command -v safe-run 2>/dev/null)" || __r=""
    fi
    if [[ -z "$__r" ]]; then
      printf 'safe gate: BLOCKED %s — safe-run not found beside the mise wrapper; rerun install.sh\n' "$__safe_argv0" >&2
      exit 100
    fi
    SAFE_RUN_RUNNER_ARGV0="$__safe_argv0" exec "$__r" "$@"
  done
  for __t in "${__safe_gated_argv0s[@]}"; do
    [[ "$__safe_argv0" == "$__t" ]] || continue
    exec safe gate "$__safe_argv0" -- "$@"
  done
  IFS=: read -ra __dirs <<< "$PATH"
  for __d in "${__dirs[@]}"; do
    [[ -n "$__d" ]] || continue
    __c="${__d%/}/mise"
    [[ -f "$__c" && -x "$__c" ]] || continue
    [[ "$__c" -ef "${BASH_SOURCE[0]}" ]] && continue
    LC_ALL=C head -n 2 -- "$__c" 2>/dev/null | grep -q '^# safe-gate-wrapper' && continue
    exec -a "$0" "$__c" "$@"
  done
  printf 'safe gate: real mise not found on PATH (argv0 dispatch for %s)\n' "$__safe_argv0" >&2
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

  # run_zsh forwards these npm config keys into the gated shell, so a value
  # inherited from the environment the suite was launched in would reach the
  # npm stub and move a hermetic case's effective config.
  unset npm_config_os NPM_CONFIG_OS npm_config_userconfig npm_config_globalconfig \
    pnpm_config_verify_deps_before_run PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN

  mkdir -p "${BIN_DIR}" "${WRAPPER_DIR}" "${WORK_DIR}" "${HOME_DIR}"
  : > "${LOG_FILE}"
  : > "${OUT_FILE}"
  : > "${ERR_FILE}"

  local tool
  for tool in npm pnpm pnpx yarn bun uv pip pip3 cargo go composer volta; do
    write_tool_stub "${BIN_DIR}" "${tool}"
  done
  write_mise_stub "${BIN_DIR}"
  # An installed Node the way the lane follows one: the launcher beside its Node,
  # and the npm-cli.js of the same installation (here a shell script of the stub).
  NODE_DIR="${CASE_DIR}/node"
  NODE_BIN="${NODE_DIR}/bin"
  mkdir -p "${NODE_BIN}" "${NODE_DIR}/lib/node_modules/npm/bin"
  write_node_stub "${NODE_BIN}"
  cp "${BIN_DIR}/npm" "${NODE_DIR}/lib/node_modules/npm/bin/npm-cli.js"
  ln -s ../lib/node_modules/npm/bin/npm-cli.js "${NODE_BIN}/npm"

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

# One materialized tree entry. The reify-candidate set reads
# node_modules/<name>/package.json to tell an artifact the delegated command
# would still fetch from one already on disk, so a case that wants an empty
# candidate set has to carry the entries its lockfile names.
install_lockdiff_package() {
  local name="$1" version="$2"
  mkdir -p "${WORK_DIR}/node_modules/${name}"
  printf '{"name":"%s","version":"%s"}\n' "${name}" "${version}" \
    > "${WORK_DIR}/node_modules/${name}/package.json"
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
    PATH="${WRAPPER_DIR}:${SAFE_TEST_PATH_MID:+${SAFE_TEST_PATH_MID}:}${NODE_BIN:+${NODE_BIN}:}${BIN_DIR}:/usr/bin:/bin" \
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
    NPM_CI_MATERIALISE="${NPM_CI_MATERIALISE:-}" \
    NPM_CI_SKIP="${NPM_CI_SKIP:-}" \
    NPM_CI_WRONG_VERSION="${NPM_CI_WRONG_VERSION:-}" \
    NPM_CI_WRONG_NAME="${NPM_CI_WRONG_NAME:-}" \
    NPM_CI_EXTRA="${NPM_CI_EXTRA:-}" \
    NPM_CI_MUTATE_PROJECT="${NPM_CI_MUTATE_PROJECT:-}" \
    NPM_CI_INTERRUPT="${NPM_CI_INTERRUPT:-}" \
    NPM_CI_STATUS="${NPM_CI_STATUS:-}" \
    NPM_PROJECTION_MANIFEST_JSON="${NPM_PROJECTION_MANIFEST_JSON:-}" \
    NPM_PROJECTION_FAIL="${NPM_PROJECTION_FAIL:-}" \
    NPM_LANE_MUTATE_FILE="${NPM_LANE_MUTATE_FILE:-}" \
    SAFE_AUDIT_EVIDENCE_HITS="${SAFE_AUDIT_EVIDENCE_HITS:-}" \
    SAFE_AUDIT_EVIDENCE_MISSING="${SAFE_AUDIT_EVIDENCE_MISSING:-}" \
    SAFE_AUDIT_EVIDENCE_BLOCKLIST="${SAFE_AUDIT_EVIDENCE_BLOCKLIST:-}" \
    SAFE_AUDIT_EVIDENCE_STATUS="${SAFE_AUDIT_EVIDENCE_STATUS:-}" \
    SAFE_AUDIT_EVIDENCE_RAW="${SAFE_AUDIT_EVIDENCE_RAW:-}" \
    SAFE_GATE_NO_EXEC="${SAFE_GATE_NO_EXEC:-}" \
    NODE_OPTIONS="${NODE_OPTIONS:-}" \
    NODE_SELECTION_JSON="${NODE_SELECTION_JSON:-}" \
    NODE_SELECTION_RAW="${NODE_SELECTION_RAW:-}" \
    NODE_CAPABILITY_JSON="${NODE_CAPABILITY_JSON:-}" \
    NODE_AGREEMENT_JSON="${NODE_AGREEMENT_JSON:-}" \
    NODE_AGREEMENT_SECOND_JSON="${NODE_AGREEMENT_SECOND_JSON:-}" \
    NODE_PROBE_STATUS="${NODE_PROBE_STATUS:-}" \
    NPM_CONFIG_LIST_RAW="${NPM_CONFIG_LIST_RAW:-}" \
    NPM_STUB_NO_GIT_OPTIONS="${NPM_STUB_NO_GIT_OPTIONS:-}" \
    LANE_TEST_PROJECT="${LANE_TEST_PROJECT:-}" \
    NPM_LOCK_MUTATION_FILE="${NPM_LOCK_MUTATION_FILE:-}" \
    SAFE_AUDIT_REAL_PRIVATE="${SAFE_AUDIT_REAL_PRIVATE:-}" \
    SAFE_AUDIT_PRIVATE_MOCK_STATUS="${SAFE_AUDIT_PRIVATE_MOCK_STATUS:-}" \
    SAFE_AUDIT_PRIVATE_MOCK_RESULT="${SAFE_AUDIT_PRIVATE_MOCK_RESULT:-}" \
    SAFE_CORE_BIN="${SAFE_CORE_BIN_FOR_AUDIT:-${SAFE_CORE_BIN:-}}" \
    SAFE_DATA_DIR="${SAFE_DATA_DIR_FOR_CASE:-${SAFE_DATA_DIR:-}}" \
    NPM_CI_DIAGNOSTIC="${NPM_CI_DIAGNOSTIC:-}" \
    NPM_CI_SIGNAL_GATE="${NPM_CI_SIGNAL_GATE:-}" \
    SAFE_CORE_TAMPER="${SAFE_CORE_TAMPER:-}" \
    SAFE_CORE_SIGNAL_EARLY="${SAFE_CORE_SIGNAL_EARLY:-}" \
    SAFE_CORE_REAL="${SAFE_CORE_TEST_BIN}" \
    SAFE_RUN_CONFIG_DIR="${SAFE_RUN_CONFIG_DIR_FOR_CASE:-${SAFE_RUN_CONFIG_DIR:-}}" \
    SAFE_GATE_LANE_NPM="${SAFE_GATE_LANE_NPM:-}" \
    SAFE_GATE_LANE_EXTRA_ENV="${SAFE_GATE_LANE_EXTRA_ENV:-}" \
    SAFE_GATE_LANE_SCRATCH="${SAFE_GATE_LANE_SCRATCH:-}" \
    SAFE_GATE_LANE_LOCKFD="${SAFE_GATE_LANE_LOCKFD:-}" \
    npm_config_package_lock_only="${npm_config_package_lock_only:-}" \
    NPM_CONFIG_PACKAGE_LOCK="${NPM_CONFIG_PACKAGE_LOCK:-}" \
    npm_config_package_lock="${npm_config_package_lock:-}" \
    NPM_CONFIG_IGNORE_SCRIPTS="${NPM_CONFIG_IGNORE_SCRIPTS:-}" \
    npm_config_ignore_scripts="${npm_config_ignore_scripts:-}" \
    NPM_LOCKDIFF_EFFECTIVE_CONFIG_JSON="${NPM_LOCKDIFF_EFFECTIVE_CONFIG_JSON:-}" \
    npm_config_os="${npm_config_os:-}" \
    NPM_CONFIG_OS="${NPM_CONFIG_OS:-}" \
    npm_config_userconfig="${npm_config_userconfig:-}" \
    npm_config_globalconfig="${npm_config_globalconfig:-}" \
    NPM_LOCKDIFF_REGISTRY_CONFIG_JSON="${NPM_LOCKDIFF_REGISTRY_CONFIG_JSON:-}" \
    NPM_LOCKDIFF_CONFIG_STATUS="${NPM_LOCKDIFF_CONFIG_STATUS:-}" \
    MISE_LS_JSON="${MISE_LS_JSON:-}" \
    "${ZSH_BIN}" -fc 'rm -f "${HOME}/.agreement-count"; printenv -0 > "${HOME}/.stub-env0" 2>/dev/null; [[ "${SAFE_INSTALL_COMPOSER_HOME_UNSET:-0}" == 1 ]] && unset COMPOSER_HOME; eval "${SAFE_INSTALL_TEST_SCRIPT}"'
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
  line="$(grep -F $'AUDIT\trepo-audit\t' "${LOG_FILE}" | tail -n 1)"
  if [[ "${line}" != *$'--deps-only'* || "${line}" != *$'--allow-missing-tools'* || "${line}" != *$'repo-audit\t.'* ]]; then
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
  assert_err_contains_fragment 'safe run host-allow add warnme@1.0.0' "$FUNCNAME" || return
  assert_err_contains_fragment 'safe explain' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_large_pinned_install_and_socket_rate_nontty() {
  local command tool spec
  for command in 'pnpm add' 'yarn add' 'bun add' 'pip install' 'uv pip install --python fixture-python'; do
    tool="${command%% *}"
    prepare_case "large-pinned-${tool}"
    local -a specs=(a@1.0.0 b@1.0.0 c@1.0.0 d@1.0.0)
    [[ "$tool" == pip || "$tool" == uv ]] && specs=(a==1.0.0 b==1.0.0 c==1.0.0 d==1.0.0)
    SAFE_INSTALL_TEST_SCRIPT="${command} ${specs[*]}" run_zsh
    assert_status 0 "$FUNCNAME ($tool)" || return
    for spec in "${specs[@]}"; do
      grep -Fq $'AUDIT\tpackage-audit\t'"${spec/==/@}"$'\t' "$LOG_FILE" || { fail "$FUNCNAME ($tool): missing audit for $spec"; return; }
    done
    local targets="${specs[*]}"
    grep -Fq $'REAL\t'"${command// /$'\t'}"$'\t'"${targets// /$'\t'}" "$LOG_FILE" || { fail "$FUNCNAME ($tool): missing installer targets"; return; }
  done
  prepare_case "socket-rate-nontty"
  SAFE_INSTALL_TEST_SCRIPT='npm install -g ratelimit@1.0.0' run_zsh
  assert_status 102 "$FUNCNAME" || return
  assert_err_contains_fragment 'Socket is rate-limited' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_infra_only_warn_no_host_allow_and_needs_a_tty() {
  # An infra-only WARN (audit tier unreachable, gate exit 11) is a missing
  # signal, NOT a package finding: the wrapper must not dangle a host-allow
  # package-vouch, and non-interactively it refuses with exit 102 (operator TTY
  # needed) rather than 100 with a host-allow hint. safe/AGENTS.md "Operator
  # override is mandatory at every terminus" (2026-09-07).
  prepare_case "infra-only-warn-no-host-allow"
  SAFE_INSTALL_TEST_SCRIPT='npm install -g infrafail@1.0.0' run_zsh
  assert_status 102 "$FUNCNAME" || return
  assert_err_contains_fragment 'audit infrastructure is unavailable' "$FUNCNAME" || return
  assert_err_not_contains_fragment 'host-allow add' "$FUNCNAME" || return
  assert_err_contains_fragment 'safe explain' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_exec_fetch_audits() {
  prepare_case "npm-exec-fetch-audits"
  SAFE_INSTALL_TEST_SCRIPT='npm exec create-foo' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tcreate-foo\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm' "$FUNCNAME" || return
  SAFE_INSTALL_TEST_SCRIPT='bun x blockme@1.2.3' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tblockme@1.2.3\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall\t--installer\tbun' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_exec_hoisted_parent_bin_passthrough() {
  prepare_case "npm-exec-hoisted-parent-bin-passthrough"
  # Hoisted monorepo: the bin lives at the workspace root, the command runs
  # from a workspace subdirectory (a monorepo whose workspace subdirectory resolves dependencies upward, PR #19 parity).
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
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tpackage-audit\tcowsay@1.6.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_contains $'REAL\tpnpx\tcowsay@1.6.0' "$FUNCNAME" || return
  SAFE_INSTALL_TEST_SCRIPT='pnpx blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tpnpx\tblockme' "$FUNCNAME" || return
  SAFE_INSTALL_TEST_SCRIPT='pnpx --package blockme benign' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_leading_global_flag_gates_npm_install() {
  prepare_case "leading-global-flag-gates-npm-install"
  # The inbox bypass: a leading global flag made the subcommand read as the
  # flag, so `install` slipped the gate. =form and space-form both gate now.
  SAFE_INSTALL_TEST_SCRIPT='npm --loglevel=error install -g blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm' "$FUNCNAME" || return
  SAFE_INSTALL_TEST_SCRIPT='npm --loglevel error install -g blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_leading_global_flag_gates_pnpm_dlx() {
  prepare_case "leading-global-flag-gates-pnpm-dlx"
  SAFE_INSTALL_TEST_SCRIPT='pnpm --filter=web dlx blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tpnpm' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_leading_global_flag_gates_yarn_add() {
  prepare_case "leading-global-flag-gates-yarn-add"
  # The verbatim inbox shape: yarn --cwd <dir> add <pkg>. The --cwd value is
  # the effective project dir and must reach resolution (review finding 3).
  SAFE_INSTALL_TEST_SCRIPT='yarn --cwd sub add blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall\t--project-dir\tsub' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tyarn' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_leading_global_flag_gates_uv_tool_run() {
  prepare_case "leading-global-flag-gates-uv-tool-run"
  SAFE_INSTALL_TEST_SCRIPT='uv --offline tool run blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tpython\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall\t--registry\thttps://r.example' "$FUNCNAME" || return
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
  [[ ! -e "${HOME_DIR}/podman-invocations.log" ]] || { printf '%s\n' "$doctor_out" "$doctor_human" >&2; fail "$FUNCNAME"; return; }
  # NoNewPrivs is inherited and cannot be cleared by omitting setpriv.
  # Check the real caller state; both decisions also have fixture coverage below.
  doctor_out="$(env HOME="${HOME_DIR}" PATH="${bindir}:/usr/bin:/bin" \
    bash "${ROOT_DIR}/bin/safe" doctor --json 2>/dev/null)"
  if grep -q '^NoNewPrivs:[[:space:]]*1' /proc/self/status 2>/dev/null; then
    jq -e '.dependencies.sandbox.podman.probed == false' <<<"${doctor_out}" >/dev/null \
      || { printf '%s\n' "$doctor_out" "$doctor_human" >&2; fail "$FUNCNAME"; return; }
    [[ ! -e "${HOME_DIR}/podman-invocations.log" ]] || { printf '%s\n' "$doctor_out" "$doctor_human" >&2; fail "$FUNCNAME"; return; }
  else
    jq -e '.dependencies.sandbox.podman.version == "podman version 5.0.0"' \
      <<<"${doctor_out}" >/dev/null || { printf '%s\n' "$doctor_out" "$doctor_human" >&2; fail "$FUNCNAME"; return; }
    [[ "$(cat "${HOME_DIR}/podman-invocations.log")" == '--version' ]] \
      || { printf '%s\n' "$doctor_out" "$doctor_human" >&2; fail "$FUNCNAME"; return; }
  fi
  pass "$FUNCNAME"
}

case_doctor_podman_probe_states() {
  prepare_case "doctor-podman-states"
  local bindir="${HOME_DIR}/stub-bin" real_grep nnp doctor_out doctor_human
  real_grep="$(command -v grep)"
  mkdir -p "${bindir}"
  # Only substitute the kernel-status query. All other grep calls stay real,
  # and podman is ALWAYS a stub, including the simulated unrestricted branch.
  cat > "${bindir}/grep" <<'STUB'
#!/usr/bin/env bash
if [[ "$#" == 3 && "$1" == '-q' && "$2" == '^NoNewPrivs:[[:space:]]*1' && "$3" == '/proc/self/status' ]]; then
  printf 'query\n' >> "$HOME/nnp-queries.log"
  exec "$SAFE_TEST_REAL_GREP" "$1" "$2" "$HOME/status-fixture"
fi
exec "$SAFE_TEST_REAL_GREP" "$@"
STUB
  cat > "${bindir}/podman" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$HOME/podman-invocations.log"
printf 'podman version 5.0.0\n'
STUB
  chmod +x "${bindir}/grep" "${bindir}/podman"
  for nnp in 0 1; do
    printf 'NoNewPrivs:\t%s\n' "$nnp" > "${HOME_DIR}/status-fixture"
    rm -f "${HOME_DIR}/nnp-queries.log" "${HOME_DIR}/podman-invocations.log"
    doctor_out="$(env HOME="${HOME_DIR}" PATH="${bindir}:/usr/bin:/bin" SAFE_TEST_REAL_GREP="$real_grep" \
      bash "${ROOT_DIR}/bin/safe" doctor --json 2>/dev/null)"
    doctor_human="$(env HOME="${HOME_DIR}" PATH="${bindir}:/usr/bin:/bin" SAFE_TEST_REAL_GREP="$real_grep" \
      bash "${ROOT_DIR}/bin/safe" doctor 2>/dev/null)"
    [[ "$(cat "${HOME_DIR}/nnp-queries.log")" == $'query\nquery' ]] \
      || { printf '%s\n' "$doctor_out" "$doctor_human" >&2; fail "$FUNCNAME (fixture $nnp not consumed)"; return; }
    jq -e '.dependencies.sandbox.podman.present == true' <<<"$doctor_out" >/dev/null \
      || { printf '%s\n' "$doctor_out" "$doctor_human" >&2; fail "$FUNCNAME ($nnp presence)"; return; }
    if [[ "$nnp" == 1 ]]; then
      jq -e '.dependencies.sandbox.podman.probed == false
        and (.dependencies.sandbox.podman.note | test("no-new-privs"))' <<<"$doctor_out" >/dev/null \
        || { printf '%s\n' "$doctor_out" "$doctor_human" >&2; fail "$FUNCNAME ($nnp JSON)"; return; }
      grep -Fq 'podman present but unprobed' <<<"$doctor_human" \
        || { printf '%s\n' "$doctor_out" "$doctor_human" >&2; fail "$FUNCNAME ($nnp human)"; return; }
      [[ ! -e "${HOME_DIR}/podman-invocations.log" ]] || { printf '%s\n' "$doctor_out" "$doctor_human" >&2; fail "$FUNCNAME ($nnp exec)"; return; }
    else
      jq -e '.dependencies.sandbox.podman.version == "podman version 5.0.0"' <<<"$doctor_out" >/dev/null \
        || { printf '%s\n' "$doctor_out" "$doctor_human" >&2; fail "$FUNCNAME ($nnp JSON)"; return; }
      if grep -Fq 'podman present but unprobed' <<<"$doctor_human"; then
        printf '%s\n' "$doctor_human" >&2
        fail "$FUNCNAME ($nnp human)"; return
      fi
      [[ "$(cat "${HOME_DIR}/podman-invocations.log")" == $'--version\n--version' ]] \
        || { printf '%s\n' "$doctor_out" "$doctor_human" >&2; fail "$FUNCNAME ($nnp exec)"; return; }
    fi
  done
  pass "$FUNCNAME"
}

case_doctor_mise_shim_repair_is_actionable() {
  prepare_case "doctor-mise-shim"
  # When mise shims are bound to the gate wrapper, doctor must print a runnable
  # repair — not the old "repoint the shims at the real mise binary" prose, whose
  # only obvious execution (`mise reshim` with the wrapper still on PATH) just
  # recreates the drift. The repair strips the gate bin dir from PATH so mise
  # relinks the shims to the real binary.
  local bindir="${HOME_DIR}/mise-wrap-bin"
  local misedir="${HOME_DIR}/mise-data"
  mkdir -p "${bindir}" "${misedir}/shims"
  # A marked mise gate wrapper, first on PATH -> gate_wrapper_state == installed.
  {
    printf '#!/usr/bin/env bash\n'
    printf '# safe-gate-wrapper v1 tool=mise\n'
    printf 'exit 0\n'
  } > "${bindir}/mise"
  chmod +x "${bindir}/mise"
  # A shim symlinked to the wrapper is the bound-drift state doctor reports.
  ln -sf "${bindir}/mise" "${misedir}/shims/node"
  local out
  out="$(env HOME="${HOME_DIR}" SAFE_BIN_DIR="${bindir}" MISE_DATA_DIR="${misedir}" \
    PATH="${bindir}:/usr/bin:/bin" bash "${ROOT_DIR}/bin/safe" doctor 2>/dev/null)"
  grep -Fq 'bound to the gate wrapper' <<<"${out}" \
    || { printf '%s\n' "${out}" >&2; fail "$FUNCNAME (bound shims not detected)"; return; }
  grep -Fq 'repair: PATH=' <<<"${out}" \
    || { printf '%s\n' "${out}" >&2; fail "$FUNCNAME (no repair command)"; return; }
  grep -Fq 'mise reshim' <<<"${out}" \
    || { printf '%s\n' "${out}" >&2; fail "$FUNCNAME (repair does not run reshim)"; return; }
  grep -Fq "${bindir}" <<<"${out}" \
    || { printf '%s\n' "${out}" >&2; fail "$FUNCNAME (repair does not name the bin dir to strip)"; return; }
  if grep -Fq 'repoint the shims at the real mise binary' <<<"${out}"; then
    printf '%s\n' "${out}" >&2
    fail "$FUNCNAME (still emits the old unactionable advice)"
    return
  fi
  # Shell-safety: SAFE_BIN_DIR is operator-settable, so the interpolated bin root
  # must be shell-escaped (jq @sh). A hostile path must not inject into the
  # operator-pasted repair command (review F1, MAJOR).
  local evil="${HOME_DIR}/x\"; touch ${HOME_DIR}/PWNED; echo x"
  local evilmise="${HOME_DIR}/evil-mise"
  mkdir -p "${evil}" "${evilmise}/shims"
  {
    printf '#!/usr/bin/env bash\n'
    printf '# safe-gate-wrapper v1 tool=mise\n'
    printf 'exit 0\n'
  } > "${evil}/mise"
  chmod +x "${evil}/mise"
  ln -sf "${evil}/mise" "${evilmise}/shims/node"
  local evil_repair
  evil_repair="$(env HOME="${HOME_DIR}" SAFE_BIN_DIR="${evil}" MISE_DATA_DIR="${evilmise}" \
    PATH="${evil}:/usr/bin:/bin" bash "${ROOT_DIR}/bin/safe" doctor 2>/dev/null \
    | sed -n 's/^  repair: //p')"
  [[ -n "${evil_repair}" ]] || { fail "$FUNCNAME (no repair line for hostile bin root)"; return; }
  rm -f "${HOME_DIR}/PWNED"
  ( eval "${evil_repair}" ) >/dev/null 2>&1 || true
  if [[ -e "${HOME_DIR}/PWNED" ]]; then
    printf 'injectable repair: %s\n' "${evil_repair}" >&2
    fail "$FUNCNAME (repair command is shell-injectable for a hostile bin root)"
    return
  fi
  pass "$FUNCNAME"
}

case_doctor_ecosystem_auditors_are_advisory_not_prereq() {
  prepare_case "doctor-ecosystem-auditors"
  # Ecosystem auditors (govulncheck/pip-audit/cargo-audit/composer) are needed
  # only when auditing that ecosystem, so doctor reports their presence as an
  # advisory and NEVER as a missing prerequisite — otherwise a box that never
  # touches Go fails its health check for lacking govulncheck. A stubbed
  # govulncheck is "present"; whatever is absent must not reach the prereq list.
  local bindir="${HOME_DIR}/eco-stub-bin"
  mkdir -p "${bindir}"
  printf '#!/usr/bin/env bash\nprintf "govulncheck v1.0.0\\n"\n' > "${bindir}/govulncheck"
  chmod +x "${bindir}/govulncheck"
  local doctor_out
  doctor_out="$(env HOME="${HOME_DIR}" PATH="${bindir}:/usr/bin:/bin" \
    bash "${ROOT_DIR}/bin/safe" doctor --json 2>/dev/null)"
  jq -e '.features.ecosystem_auditors.govulncheck.present == true
    and (.features.ecosystem_auditors | has("pip_audit"))
    and (.features.ecosystem_auditors | has("cargo_audit"))
    and (.features.ecosystem_auditors | has("composer"))' \
    <<<"${doctor_out}" >/dev/null || { printf '%s\n' "${doctor_out}" >&2; fail "$FUNCNAME"; return; }
  local doctor_human
  doctor_human="$(env HOME="${HOME_DIR}" PATH="${bindir}:/usr/bin:/bin" \
    bash "${ROOT_DIR}/bin/safe" doctor 2>/dev/null)"
  grep -Fq 'ecosystem auditors' <<<"${doctor_human}" \
    || { printf '%s\n' "${doctor_human}" >&2; fail "$FUNCNAME"; return; }
  grep -Eq 'govulncheck \(Go\): +present' <<<"${doctor_human}" \
    || { printf '%s\n' "${doctor_human}" >&2; fail "$FUNCNAME"; return; }
  # The core invariant: no ecosystem auditor is ever a missing prerequisite.
  if sed -n '/missing prerequisites:/,$p' <<<"${doctor_human}" \
      | grep -Eq 'govulncheck|pip-audit|cargo-audit|composer'; then
    printf '%s\n' "${doctor_human}" >&2
    fail "$FUNCNAME (ecosystem auditor leaked into missing prerequisites)"
    return
  fi
  # Absent state — govulncheck is a Go tool, never a system package, so with no
  # stub it reads absent deterministically: it must report present==false, render
  # an "absent" line, and STILL never reach the prereq list.
  local emptybin="${HOME_DIR}/eco-empty-bin"
  mkdir -p "${emptybin}"
  local doctor_absent_json doctor_absent_human
  doctor_absent_json="$(env HOME="${HOME_DIR}" PATH="${emptybin}:/usr/bin:/bin" \
    bash "${ROOT_DIR}/bin/safe" doctor --json 2>/dev/null)"
  jq -e '.features.ecosystem_auditors.govulncheck.present == false' \
    <<<"${doctor_absent_json}" >/dev/null \
    || { printf '%s\n' "${doctor_absent_json}" >&2; fail "$FUNCNAME (govulncheck should read absent)"; return; }
  doctor_absent_human="$(env HOME="${HOME_DIR}" PATH="${emptybin}:/usr/bin:/bin" \
    bash "${ROOT_DIR}/bin/safe" doctor 2>/dev/null)"
  grep -Eq 'govulncheck \(Go\): +absent' <<<"${doctor_absent_human}" \
    || { printf '%s\n' "${doctor_absent_human}" >&2; fail "$FUNCNAME (absent auditor not rendered as absent)"; return; }
  if sed -n '/missing prerequisites:/,$p' <<<"${doctor_absent_human}" \
      | grep -Eq 'govulncheck|pip-audit|cargo-audit|composer'; then
    printf '%s\n' "${doctor_absent_human}" >&2
    fail "$FUNCNAME (absent auditor leaked into missing prerequisites)"
    return
  fi
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
  assert_log_contains $'AUDIT\tpackage-audit\tokpkg@1.0.0\t--ecosystem\tpython\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'AUDIT\tpackage-audit\t3.12' "$FUNCNAME" || return
  SAFE_INSTALL_TEST_SCRIPT='uv tool install okpkg==1.0.0 --python 3.12' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment $'AUDIT\tpackage-audit\t3.12' "$FUNCNAME" || return
  SAFE_INSTALL_TEST_SCRIPT='uv tool install --python=3.12 -p 3.12 okpkg==1.0.0' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment $'AUDIT\tpackage-audit\t3.12' "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm' "$FUNCNAME" || return
  SAFE_INSTALL_TEST_SCRIPT='npm --workspaces false install blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  SAFE_INSTALL_TEST_SCRIPT='pnpm --recursive false add blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_optional_boolean_without_value_still_gates() {
  prepare_case "optional-boolean-without-value-still-gates"
  # The common form (no explicit value): the subcommand directly follows the
  # boolean flag and must not be consumed as a value.
  SAFE_INSTALL_TEST_SCRIPT='npm --global install blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_pnpm_config_switch_not_value() {
  prepare_case "pnpm-config-switch-not-value"
  # --config is a no-value switch on `pnpm add`; misclassifying it as a value
  # flag ate the `add` subcommand and bypassed the gate (review round 1 High 2).
  SAFE_INSTALL_TEST_SCRIPT='pnpm --config add blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tpnpm' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_pip_use_feature_takes_value() {
  prepare_case "pip-use-feature-takes-value"
  # --use-feature takes a value; misclassifying it as boolean exposed the
  # value as the subcommand and bypassed the gate (review round 1 High 4).
  SAFE_INSTALL_TEST_SCRIPT='pip --use-feature fast-deps install blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tpython\t--gate\tinstall\t--op\tinstall\t--python-isolated' "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_exec_value_flag_does_not_hide_package() {
  prepare_case "exec-value-flag-does-not-hide-package"
  # A known value-taking flag before the command must not be mistaken for the
  # package; the real fetched package is audited (review High 2).
  SAFE_INSTALL_TEST_SCRIPT='npm exec --cache /tmp/cache-ok blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm' "$FUNCNAME" || return
  SAFE_INSTALL_TEST_SCRIPT='pnpm dlx --allow-build ok-builder blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tpnpm' "$FUNCNAME" || return
  # =form is unambiguous and must not over-refuse.
  SAFE_INSTALL_TEST_SCRIPT='npm exec --cache=/tmp/cache-ok cowsay' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tcowsay\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tpnpm' "$FUNCNAME" || return
  SAFE_INSTALL_TEST_SCRIPT='bun x --package=blockme benign' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tbun' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_exec_boolean_flags_do_not_eat_package() {
  prepare_case "exec-boolean-flags-do-not-eat-package"
  # A boolean flag must not consume the following package as its value
  # (re-review High 1/3): the package still audits.
  SAFE_INSTALL_TEST_SCRIPT='pnpm dlx -c blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tpnpm' "$FUNCNAME" || return
  SAFE_INSTALL_TEST_SCRIPT='yarn dlx -q blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tyarn' "$FUNCNAME" || return
  # Documented booleans pass through without over-refusing (re-review Med 1).
  SAFE_INSTALL_TEST_SCRIPT='npm exec --workspaces cowsay' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tcowsay\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tpackage-audit\tcowsay@1.6.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_contains $'REAL\tpnpm\tdlx\tcowsay@1.6.0' "$FUNCNAME" || return
  SAFE_INSTALL_TEST_SCRIPT='bun x cowsay' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tcowsay\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall\t--installer\tbun' "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tpackage-audit\twarnme\t--ecosystem\tpython\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tuv' "$FUNCNAME" || return
  SAFE_INSTALL_TEST_SCRIPT='uv run script.py' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'REAL\tuv\trun\tscript.py' "$FUNCNAME" || return
  SAFE_INSTALL_TEST_SCRIPT='uv tool run ruff' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\truff\t--ecosystem\tpython\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  SAFE_INSTALL_TEST_SCRIPT='uv tool run --from blockme r' run_zsh
  assert_status 104 "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_uv_short_with_and_boundary() {
  prepare_case "uv-short-with-and-boundary"
  # -w is the short --with and must be audited (review High 3).
  SAFE_INSTALL_TEST_SCRIPT='uv run -w blockme script.py' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tpython\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tuv' "$FUNCNAME" || return
  # A value flag before --with must not shift the boundary; --with rich audits.
  SAFE_INSTALL_TEST_SCRIPT='uv run --python 3.12 --with rich pytest' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\trich\t--ecosystem\tpython\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tpython\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tuv' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_uv_tool_run_with_extra_is_audited() {
  prepare_case "uv-tool-run-with-extra-is-audited"
  # --with/-w extras are themselves fetched and must be audited alongside the
  # tool (re-review High 4).
  SAFE_INSTALL_TEST_SCRIPT='uv tool run -w blockme ruff' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tpython\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tuv' "$FUNCNAME" || return
  # Both clean → audited and delegated.
  SAFE_INSTALL_TEST_SCRIPT='uv tool run --with ok ruff' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tok\t--ecosystem\tpython\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\truff\t--ecosystem\tpython\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_uv_run_value_flag_before_with() {
  prepare_case "uv-run-value-flag-before-with"
  # --no-extra takes a value; misclassifying it as boolean would stop the
  # scan early and miss the later --with fetch (re-review High 5).
  SAFE_INSTALL_TEST_SCRIPT='uv run --no-extra dev --with blockme python' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tpython\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tpackage-audit\texample.com/blockme@v1.0.0\t--ecosystem\tgo\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tgo' "$FUNCNAME" || return
  SAFE_INSTALL_TEST_SCRIPT='go run ./cmd' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'REAL\tgo\trun\t./cmd' "$FUNCNAME" || return
  assert_count 0 $'AUDIT\tpackage-audit\t./cmd@latest\t--ecosystem\tgo' "${LOG_FILE}" "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_go_run_value_flag_does_not_hide_module() {
  prepare_case "go-run-value-flag-does-not-hide-module"
  write_tool_stub "${BIN_DIR}" go
  # A space-form value build flag must not swallow the remote module target
  # (round-5 High): -C/-mod take values, then the module@version still audits.
  SAFE_INSTALL_TEST_SCRIPT='go run -C /tmp example.com/blockme@v1.0.0' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\texample.com/blockme@v1.0.0\t--ecosystem\tgo\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tpackage-audit\tlodash\t--ecosystem\tnpm\t--gate\tinstall\t--op\tupdate' "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tupdate\tlodash' "$FUNCNAME" || return
  SAFE_INSTALL_TEST_SCRIPT='yarn upgrade left-pad' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tleft-pad\t--ecosystem\tnpm\t--gate\tinstall\t--op\tupdate' "$FUNCNAME" || return
  SAFE_INSTALL_TEST_SCRIPT='npm u blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  # npm ships `udpate` as a real alias of update (review Medium 1).
  SAFE_INSTALL_TEST_SCRIPT='npm udpate blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tupdate' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_abbreviation_classifier_gates_and_preserves_argv() {
  prepare_case "npm-abbreviation-classifier"

  # `inst` is a hardcoded npm alias. The check and the real delegate must both
  # see the operation, while the delegate retains the operator's spelling.
  SAFE_INSTALL_TEST_SCRIPT='npm inst okpkg' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tokpkg\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tinst\tokpkg' "$FUNCNAME" || return

  # The block canary proves an abbreviated install cannot delegate unaudited.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='npm inst blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm\tinst\tblockme' "$FUNCNAME" || return

  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='npm updat okpkg' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tokpkg\t--ecosystem\tnpm\t--gate\tinstall\t--op\tupdate' "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tupdat\tokpkg' "$FUNCNAME" || return

  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='npm exe blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm\texe\tblockme' "$FUNCNAME" || return

  # `in` is a short explicit install alias, while `d` is not a length-one
  # match and stays a passthrough for npm to reject or handle itself.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='npm in okpkg' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tokpkg\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tpackage-audit\tokpkg\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tad\tokpkg' "$FUNCNAME" || return

  # install-clean is itself an alias. Its prefix must take the no-package ci
  # lane, scan the project, and preserve the original token for npm.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='npm install-cl' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_project_scan_logged "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tinstall-cl' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'AUDIT\tpackage-audit' "$FUNCNAME" || return

  for token in cit clean-install isntall; do
    : > "${LOG_FILE}"
    SAFE_INSTALL_TEST_SCRIPT="npm ${token}" run_zsh
    assert_status 0 "$FUNCNAME" || return
    assert_project_scan_logged "$FUNCNAME" || return
    assert_log_contains $'REAL\tnpm\t'"${token}" "$FUNCNAME" || return
    assert_log_not_contains_fragment $'AUDIT\tpackage-audit' "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm\tinstallTest\tblockme' "$FUNCNAME" || return

  # Hyphenated ci commands also normalize before npm resolves aliases/prefixes;
  # their no-package lane scans and still delegates the original spelling.
  for token in cleanInstall installCiTest; do
    : > "${LOG_FILE}"
    SAFE_INSTALL_TEST_SCRIPT="npm ${token}" run_zsh
    assert_status 0 "$FUNCNAME" || return
    assert_project_scan_logged "$FUNCNAME" || return
    assert_log_contains $'REAL\tnpm\t'"${token}" "$FUNCNAME" || return
    assert_log_not_contains_fragment $'AUDIT\tpackage-audit' "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tpackage-audit\tvendor/okpkg@^1\t--ecosystem\tcomposer\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
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
  for token in i u upgrade r in ins up upg upgr upgra upgrad re req requ g gl glo glob globa \
    rei rein reins reinst reinsta reinstal creat crea create create-p create-projec; do
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
  # `rem` (remove) fetches nothing; only prefixes that resolve to a gated
  # command refuse.
  for token in rem; do
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
  assert_log_contains $'AUDIT\tpackage-audit\tvendor/okpkg@^1\t--ecosystem\tcomposer\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_contains $'REAL\tcomposer\trequire\t--\tvendor/okpkg:^1' "$FUNCNAME" || return

  pass "$FUNCNAME"
}

case_composer_reinstall_create_project() {
  prepare_case "composer-reinstall-create-project"

  # reinstall re-fetches the locked tree, so it audits as an install-class
  # project scan and never treats a targeted package as a new install.
  touch "${WORK_DIR}/composer.json"
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='composer reinstall' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_project_scan_logged "$FUNCNAME" || return
  assert_log_not_contains_fragment 'package-audit' "$FUNCNAME" || return
  assert_log_contains $'REAL\tcomposer\treinstall' "$FUNCNAME" || return

  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='composer reinstall vendor/blockme' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_project_scan_logged "$FUNCNAME" || return
  assert_log_not_contains_fragment 'package-audit' "$FUNCNAME" || return
  assert_log_contains $'REAL\tcomposer\treinstall\tvendor/blockme' "$FUNCNAME" || return

  # create-project audits ONLY the first positional as a package, and Composer's
  # explicit [version] positional OVERRIDES a version fused into the name
  # (Composer gives the positional precedence). The directory positional is
  # never audited.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='composer create-project vendor/okpkg:^1 targetdir 1.2.3' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tvendor/okpkg@1.2.3\t--ecosystem\tcomposer\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'\tvendor/okpkg@^1\t' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'\ttargetdir@' "$FUNCNAME" || return
  assert_log_contains $'REAL\tcomposer\tcreate-project\tvendor/okpkg:^1\ttargetdir\t1.2.3' "$FUNCNAME" || return

  # Composer keeps the fused selector when the [version] positional is PHP-falsy
  # ("" or "0"), so a literal 0 must NOT override the fused constraint — safe
  # audits what Composer actually resolves.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='composer create-project vendor/okpkg:^1 dir 0' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tvendor/okpkg@^1\t--ecosystem\tcomposer\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'\tvendor/okpkg@0\t' "$FUNCNAME" || return

  # --stability/-s selects a candidate safe-audit cannot model (no stability
  # input; a range resolves silently), so create-project fails closed with a
  # pin hint rather than auditing a default-stability guess. Space and =forms,
  # and the LEADING form (Composer binds --stability before the subcommand too:
  # `composer --stability=dev create-project …`), which the subcommand locator
  # would otherwise strip before the extractor.
  for args in 'create-project -s dev vendor/okpkg:^1 dir' \
    'create-project --stability=dev vendor/okpkg' \
    'create-project vendor/okpkg:1.2.3 -s stable' \
    '--stability=dev create-project vendor/okpkg'; do
    : > "${LOG_FILE}"
    SAFE_INSTALL_TEST_SCRIPT="composer ${args}" run_zsh
    assert_status 100 "$FUNCNAME" || return
    [[ "$(wc -l < "${ERR_FILE}")" -eq 1 ]] || { cat "${ERR_FILE}" >&2; fail "$FUNCNAME"; return 1; }
    assert_err_contains_fragment 'stability/-s makes Composer' "$FUNCNAME" || return
    assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
    assert_log_not_contains_fragment $'REAL\tcomposer' "$FUNCNAME" || return
  done

  # The space-form leading --stability is an unrecognized application option, so
  # the subcommand locator fails closed before routing — still no fetch.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='composer --stability dev create-project vendor/okpkg' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tcomposer' "$FUNCNAME" || return

  # An ambiguous multi-character short bundle (Symfony parses -nd as -n plus
  # -d<dir>, shifting the package boundary) fails closed rather than audit the
  # wrong token as the package.
  for args in 'create-project -nd vendor/allowed vendor/blockme' \
    'create-project -ns dev vendor/blockme'; do
    : > "${LOG_FILE}"
    SAFE_INSTALL_TEST_SCRIPT="composer ${args}" run_zsh
    assert_status 100 "$FUNCNAME" || return
    [[ "$(wc -l < "${ERR_FILE}")" -eq 1 ]] || { cat "${ERR_FILE}" >&2; fail "$FUNCNAME"; return 1; }
    assert_err_contains_fragment 'bundled short option' "$FUNCNAME" || return
    assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
    assert_log_not_contains_fragment $'REAL\tcomposer' "$FUNCNAME" || return
  done

  # A value flag in a form safe DOES model must not be mistaken for the package.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='composer create-project --prefer-install dist vendor/okpkg:^1 dir' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tvendor/okpkg@^1\t--ecosystem\tcomposer\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'\tdist@' "$FUNCNAME" || return

  # --require names additional fetched packages, so they are audited on top of
  # the root package. The equals and space forms both count. A named root
  # creates a NEW project, so the cwd is not scanned.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='composer create-project vendor/okpkg:^1 --require extra/one:^2 --require=extra/two:^3' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tvendor/okpkg@^1\t--ecosystem\tcomposer\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\textra/one@^2\t--ecosystem\tcomposer\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\textra/two@^3\t--ecosystem\tcomposer\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return

  # A --require BEFORE the subcommand (Composer's lazy binding accepts the
  # leading equals form and fetches it) would slip past the extractor, so it
  # fails closed; the canonical trailing form above still audits.
  for args in '--require=evil/pkg:^2 create-project vendor/okpkg:^1' \
    '--require=evil/pkg:^2 create-project'; do
    : > "${LOG_FILE}"
    SAFE_INSTALL_TEST_SCRIPT="composer ${args}" run_zsh
    assert_status 100 "$FUNCNAME" || return
    [[ "$(wc -l < "${ERR_FILE}")" -eq 1 ]] || { cat "${ERR_FILE}" >&2; fail "$FUNCNAME"; return 1; }
    assert_err_contains_fragment 'require before the subcommand' "$FUNCNAME" || return
    assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
    assert_log_not_contains_fragment $'REAL\tcomposer' "$FUNCNAME" || return
  done

  # create-project with NO root but a --require addition is install-class:
  # Composer installs the current project and adds the requirement, so safe
  # scans the project AND audits the added package (both).
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='composer create-project --require vendor/okpkg:^2' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_project_scan_logged "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tvendor/okpkg@^2\t--ecosystem\tcomposer\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return

  # --repository-url is a live (deprecated) source selector Composer uses for
  # root-package selection, so it must reach the audit as the custom source.
  for form in '--repository-url https://alt.example' '--repository-url=https://alt.example'; do
    : > "${LOG_FILE}"
    SAFE_INSTALL_TEST_SCRIPT="composer create-project ${form} vendor/okpkg:^1 dir" run_zsh
    assert_status 0 "$FUNCNAME" || return
    assert_log_contains $'AUDIT\tpackage-audit\tvendor/okpkg@^1\t--ecosystem\tcomposer\t--gate\tinstall\t--op\tinstall\t--registry\thttps://alt.example' "$FUNCNAME" || return
  done

  # A create-project package resolving to a blocked advisory refuses before any
  # delegation — the audit boundary really gates the fetch. A package-audit
  # BLOCK verdict exits 104 (distinct from the 100 policy refusals above).
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='composer create-project vendor/blockme dir' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tcomposer' "$FUNCNAME" || return

  # A bare create-project inside a project directory installs the current
  # project (install-class): it scans and delegates without auditing a package.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='composer create-project' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_project_scan_logged "$FUNCNAME" || return
  assert_log_not_contains_fragment 'package-audit' "$FUNCNAME" || return
  assert_log_contains $'REAL\tcomposer\tcreate-project' "$FUNCNAME" || return

  # With no package AND no project there is nothing to audit before the
  # interactive fetch — fail closed with a single stderr line.
  rm -f "${WORK_DIR}/composer.json" "${WORK_DIR}/composer.lock"
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='composer create-project' run_zsh
  assert_status 100 "$FUNCNAME" || return
  [[ "$(wc -l < "${ERR_FILE}")" -eq 1 ]] || { cat "${ERR_FILE}" >&2; fail "$FUNCNAME"; return 1; }
  assert_err_contains_fragment 'name the <vendor/package> to create from' "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tcomposer' "$FUNCNAME" || return

  pass "$FUNCNAME"
}

case_composer_nonglobal_working_dir() {
  prepare_case "composer-nonglobal-working-dir"
  local wd="${CASE_DIR}/wd-project"
  mkdir -p "${wd}"
  touch "${wd}/composer.json"

  # A non-global install-class composer run with an effective --working-dir/-d
  # scans THAT project, not the process cwd (which here holds no composer
  # project at all — before this fix the scan was skipped or aimed at cwd).
  # Every surface form Composer accepts is covered, at both argument positions.
  local form
  for form in "install -d ${wd}" \
    "install -d${wd}" \
    "install --working-dir ${wd}" \
    "install --working-dir=${wd}" \
    "-d ${wd} install" \
    "update -d ${wd}" \
    "reinstall -d ${wd}"; do
    : > "${LOG_FILE}"
    SAFE_AUDIT_EXPECT_PROJECT=1 \
      SAFE_INSTALL_TEST_SCRIPT="composer ${form}" run_zsh
    assert_status 0 "$FUNCNAME (${form})" || return
    assert_scan_targets_logged "$FUNCNAME (${form})" "${wd}" || return
    assert_log_not_contains_fragment 'package-audit' "$FUNCNAME (${form})" || return
  done

  # Rootless create-project is install-class and scans the effective working-dir
  # project the same way.
  : > "${LOG_FILE}"
  SAFE_AUDIT_EXPECT_PROJECT=1 \
    SAFE_INSTALL_TEST_SCRIPT="composer create-project -d ${wd}" run_zsh
  assert_status 0 "$FUNCNAME (create-project)" || return
  assert_scan_targets_logged "$FUNCNAME (create-project)" "${wd}" || return

  # The verdict is driven by the working-dir scan: a critical finding there
  # refuses (non-interactive -> 102) before any delegation.
  : > "${LOG_FILE}"
  SAFE_AUDIT_EXPECT_PROJECT=1 SAFE_AUDIT_SCAN_CRITICAL_PROJECT="${wd}" \
    SAFE_INSTALL_TEST_SCRIPT="composer install -d ${wd}" run_zsh
  assert_status 102 "$FUNCNAME (critical wd)" || return
  assert_log_not_contains_fragment $'REAL\tcomposer' "$FUNCNAME (critical wd)" || return

  # Conversely the cwd is NOT scanned: a project in cwd flagged critical does
  # not block a run whose --working-dir points at a clean project elsewhere.
  # Proves the scan moved off cwd rather than covering both.
  touch "${WORK_DIR}/composer.json"
  : > "${LOG_FILE}"
  SAFE_AUDIT_EXPECT_PROJECT=1 SAFE_AUDIT_SCAN_CRITICAL_PROJECT="${WORK_DIR}" \
    SAFE_INSTALL_TEST_SCRIPT="composer install -d ${wd}" run_zsh
  assert_status 0 "$FUNCNAME (cwd not scanned)" || return
  assert_scan_targets_logged "$FUNCNAME (cwd not scanned)" "${wd}" || return
  assert_log_contains $'REAL\tcomposer\tinstall\t-d\t'"${wd}" "$FUNCNAME (cwd not scanned)" || return
  rm -f "${WORK_DIR}/composer.json"

  # An existing working-dir that cannot be entered is audit-infrastructure
  # breakage, not a clean tree: refuse (exit 100, single stderr line), never
  # delegate unaudited.
  local unreadable="${CASE_DIR}/unreadable"
  mkdir -p "${unreadable}"
  touch "${unreadable}/composer.json"
  chmod 000 "${unreadable}"
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT="composer install -d ${unreadable}" run_zsh
  chmod 755 "${unreadable}"
  assert_status 100 "$FUNCNAME (unreadable)" || return
  [[ "$(wc -l < "${ERR_FILE}")" -eq 1 ]] || { cat "${ERR_FILE}" >&2; fail "$FUNCNAME (unreadable)"; return 1; }
  assert_err_contains_fragment 'cannot enter the --working-dir project' "$FUNCNAME (unreadable)" || return
  assert_log_not_contains_fragment $'REAL\tcomposer' "$FUNCNAME (unreadable)" || return

  # A nonexistent working-dir has no project to scan: nothing is audited and the
  # run delegates (Composer itself rejects the missing directory).
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT="composer install -d ${CASE_DIR}/absent" run_zsh
  assert_status 0 "$FUNCNAME (absent)" || return
  assert_log_not_contains_fragment $'AUDIT\trepo-audit\t' "$FUNCNAME (absent)" || return
  assert_log_contains $'REAL\tcomposer\tinstall\t-d\t'"${CASE_DIR}/absent" "$FUNCNAME (absent)" || return

  # A REPEATED working-dir option resolves first-wins, matching Composer
  # (Symfony ArgvInput.getParameterOption first-match). The scan must target the
  # FIRST directory; the second is flagged critical to prove it is NOT scanned
  # (a last-wins bug would scan it and either block or log its AUDITPROJECT).
  local wd2="${CASE_DIR}/wd-project-2"
  mkdir -p "${wd2}"
  touch "${wd2}/composer.json"
  : > "${LOG_FILE}"
  SAFE_AUDIT_EXPECT_PROJECT=1 SAFE_AUDIT_SCAN_CRITICAL_PROJECT="${wd2}" \
    SAFE_INSTALL_TEST_SCRIPT="composer install --working-dir=${wd} --working-dir=${wd2}" run_zsh
  assert_status 0 "$FUNCNAME (repeated first-wins)" || return
  assert_scan_targets_logged "$FUNCNAME (repeated first-wins)" "${wd}" || return
  assert_log_not_contains_fragment $'AUDITPROJECT\t'"${wd2}" "$FUNCNAME (repeated first-wins)" || return

  # The working-dir is entered with physical path semantics, matching Composer's
  # chdir(): a symlinked `..` resolves to the real project, where a lexical `cd`
  # would collapse symlink/.. and scan the wrong (clean) directory. Expected is
  # computed with the same physical resolution so a symlinked temp prefix cannot
  # skew the assertion.
  local realproj="${CASE_DIR}/realproj"
  mkdir -p "${realproj}/sub"
  touch "${realproj}/composer.json"
  ln -s "${realproj}/sub" "${CASE_DIR}/lnk"
  local realproj_phys
  realproj_phys="$(cd -P -- "${realproj}" && pwd)"
  : > "${LOG_FILE}"
  SAFE_AUDIT_EXPECT_PROJECT=1 \
    SAFE_INSTALL_TEST_SCRIPT="composer install -d ${CASE_DIR}/lnk/.." run_zsh
  assert_status 0 "$FUNCNAME (physical cd)" || return
  assert_scan_targets_logged "$FUNCNAME (physical cd)" "${realproj_phys}" || return

  # The leading glued -dvalue form is (pre-existing) fail-closed: safe_gate_route
  # does not model it as a value flag, so it refuses before routing rather than
  # fetch unaudited. Guard that it stays closed.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT="composer -d${wd} install" run_zsh
  assert_status 100 "$FUNCNAME (leading glued)" || return
  assert_log_not_contains_fragment $'REAL\tcomposer' "$FUNCNAME (leading glued)" || return

  pass "$FUNCNAME"
}

case_composer_working_dir_missing_audit_warns_once() {
  prepare_case "composer-missing-audit-warns-once" no
  touch "${WORK_DIR}/composer.json"
  # With no scanner available, an install-class composer run warns exactly once
  # per process. `require` runs both the project scan and a package audit; the
  # scan runs in place (not a subshell) precisely so the once-per-process
  # warning flag survives into the package-audit step.
  SAFE_INSTALL_TEST_SCRIPT='composer require vendor/okpkg:^1' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_count 1 'safe audit not installed, skipping pre-install check' "${ERR_FILE}" "$FUNCNAME" || return
  assert_log_contains $'REAL\tcomposer\trequire\tvendor/okpkg:^1' "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tpackage-audit\tvendor/okpkg@^1\t--ecosystem\tcomposer\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_contains $'REAL\tcomposer\tglobal\trequire\tvendor/okpkg:^1' "$FUNCNAME" || return

  : > "${LOG_FILE}"
  COMPOSER_HOME="${global_home}" SAFE_AUDIT_EXPECT_PROJECTS=1 \
    SAFE_INSTALL_TEST_SCRIPT='composer global Require vendor/okpkg:^1' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_scan_targets_logged "$FUNCNAME" "${global_home}" || return
  assert_log_contains $'AUDIT\tpackage-audit\tvendor/okpkg@^1\t--ecosystem\tcomposer\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
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

  # A global scan target is entered with physical path semantics, matching
  # Composer's chdir(): when COMPOSER_HOME reaches through a symlinked `..`, the
  # scan must land on the real physical directory, not the lexically-collapsed
  # one. The wrong (lexical) directory is flagged critical, so under a bare `cd`
  # the run would BLOCK; under `cd -P` it is never a scan target and the run
  # passes. Expected is computed with the same physical resolution so a
  # symlinked temp prefix cannot skew the assertion.
  local phys_real="${CASE_DIR}/phys-realproj"
  local phys_wrong="${CASE_DIR}/phys-wrongdir"
  mkdir -p "${phys_real}/sub" "${phys_wrong}"
  touch "${phys_real}/composer.json" "${phys_wrong}/composer.json"
  ln -s "${phys_real}/sub" "${phys_wrong}/lnk"
  local phys_real_canon
  phys_real_canon="$(cd -P -- "${phys_real}" && pwd)"
  : > "${LOG_FILE}"
  COMPOSER_HOME="${phys_wrong}/lnk/.." SAFE_AUDIT_EXPECT_PROJECTS=1 \
    SAFE_AUDIT_SCAN_CRITICAL_PROJECT="${phys_wrong}" \
    SAFE_INSTALL_TEST_SCRIPT='composer global install' run_zsh
  assert_status 0 "$FUNCNAME (global physical cd)" || return
  assert_scan_targets_logged "$FUNCNAME (global physical cd)" "${phys_real_canon}" || return
  assert_log_not_contains_fragment $'AUDITPROJECT\t'"${phys_wrong}" "$FUNCNAME (global physical cd)" || return

  # A selected global target that exists but cannot be entered is audit
  # infrastructure breakage, not a clean tree: refuse (exit 100, single stderr
  # line), never delegate unaudited. This locks the `cd -P -- ... 2>/dev/null`
  # + 125->100 mapping so a regression that drops the suppression (two stderr
  # lines) or the exit mapping cannot pass green.
  local global_unreadable="${CASE_DIR}/global-unreadable"
  mkdir -p "${global_unreadable}"
  touch "${global_unreadable}/composer.json"
  chmod 000 "${global_unreadable}"
  : > "${LOG_FILE}"
  COMPOSER_HOME="${global_unreadable}" SAFE_AUDIT_EXPECT_PROJECTS=1 \
    SAFE_INSTALL_TEST_SCRIPT='composer global install' run_zsh
  chmod 755 "${global_unreadable}"
  assert_status 100 "$FUNCNAME (global unreadable)" || return
  [[ "$(wc -l < "${ERR_FILE}")" -eq 1 ]] || { cat "${ERR_FILE}" >&2; fail "$FUNCNAME (global unreadable)"; return 1; }
  assert_err_contains_fragment 'cannot enter the selected project' "$FUNCNAME (global unreadable)" || return
  assert_log_not_contains_fragment $'AUDITPROJECT\t' "$FUNCNAME (global unreadable)" || return
  assert_log_not_contains_fragment $'REAL\tcomposer' "$FUNCNAME (global unreadable)" || return

  pass "$FUNCNAME"
}

case_npm_dedupe_lockdiff_empty_delegates_without_scan() {
  skip_lockdiff_case "$FUNCNAME" || return
  prepare_lockdiff_case "npm-dedupe-lockdiff-empty"
  # Empty delta AND a complete tree: nothing is fetched, so nothing is audited.
  install_lockdiff_package kept 1.0.0
  printf '{"name":"lockdiff-test","version":"1.0.0"}\n' > "${WORK_DIR}/package.json"
  printf '{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"},"node_modules/kept":{"version":"1.0.0"}}}\n' > "${WORK_DIR}/package-lock.json"
  NPM_LOCK_MUTATION_JSON='{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"},"node_modules/kept":{"version":"1.0.0"}}}' \
    SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'PROJECTION\tnpm\t--package-lock-only\t--ignore-scripts\t--no-audit\t--no-fund\tdedupe' "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tdedupe' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'AUDIT\trepo-audit' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'AUDIT\tpackage-audit' "$FUNCNAME" || return
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

# The lockfile both sides of the projection agree on, so the delta is empty and
# only the tree decides whether anything is still fetched.
LOCKDIFF_PARTIAL_TREE_LOCK='{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"},"node_modules/blockme":{"version":"2.0.0","resolved":"https://registry.npmjs.org/blockme/-/blockme-2.0.0.tgz","integrity":"sha512-blockme"}}}'

case_npm_lockdiff_partial_tree_audits_reify_candidates() {
  skip_lockdiff_case "$FUNCNAME" || return
  prepare_lockdiff_case "npm-lockdiff-partial-tree-missing"
  # A node_modules that lost a subdirectory: the delta is empty, yet the real
  # dedupe still fetches the entry both lockfiles name. The reify-candidate set
  # is what puts it through the audit (PR#70 review F3 residual).
  printf '{"name":"lockdiff-test","version":"1.0.0"}\n' > "${WORK_DIR}/package.json"
  printf '%s\n' "${LOCKDIFF_PARTIAL_TREE_LOCK}" > "${WORK_DIR}/package-lock.json"
  NPM_LOCK_MUTATION_JSON="${LOCKDIFF_PARTIAL_TREE_LOCK}" \
    SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_project_scan_logged "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tblockme@2.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_count 0 $'REAL\tnpm\tdedupe' "${LOG_FILE}" "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_lockdiff_version_mismatched_tree_is_a_reify_candidate() {
  skip_lockdiff_case "$FUNCNAME" || return
  prepare_lockdiff_case "npm-lockdiff-partial-tree-version-mismatch"
  # Present on disk is not the same as present at the locked version: the real
  # command replaces this one, which is a fetch like any other.
  install_lockdiff_package blockme 1.0.0
  printf '{"name":"lockdiff-test","version":"1.0.0"}\n' > "${WORK_DIR}/package.json"
  printf '%s\n' "${LOCKDIFF_PARTIAL_TREE_LOCK}" > "${WORK_DIR}/package-lock.json"
  NPM_LOCK_MUTATION_JSON="${LOCKDIFF_PARTIAL_TREE_LOCK}" \
    SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tblockme@2.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_count 0 $'REAL\tnpm\tdedupe' "${LOG_FILE}" "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_lockdiff_exempts_never_installed_optional_entries() {
  skip_lockdiff_case "$FUNCNAME" || return
  prepare_lockdiff_case "npm-lockdiff-optional-platform-exempt"
  # An optional entry npm skips on this platform is never fetched, so auditing
  # it would refuse the command over a package that was never going to arrive
  # (fsevents on Linux). `aix` mismatches every machine this suite runs on; the
  # entry would BLOCK if it reached the audit, so delegation proves the
  # exemption.
  printf '{"name":"lockdiff-test","version":"1.0.0"}\n' > "${WORK_DIR}/package.json"
  local lock='{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"},"node_modules/blockme":{"version":"2.0.0","optional":true,"os":["aix"],"resolved":"https://registry.npmjs.org/blockme/-/blockme-2.0.0.tgz","integrity":"sha512-blockme"}}}'
  printf '%s\n' "${lock}" > "${WORK_DIR}/package-lock.json"
  NPM_LOCK_MUTATION_JSON="${lock}" SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tdedupe' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'AUDIT\tpackage-audit' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'AUDIT\trepo-audit' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_lockdiff_symlinked_entry_is_audited() {
  skip_lockdiff_case "$FUNCNAME" || return
  prepare_lockdiff_case "npm-lockdiff-symlinked-entry"
  # npm replaces a symlinked actual node with the projected ordinary package
  # during reify, so a link carrying the locked version is a materialization,
  # not evidence of presence (r1 review F1: npm prune turned the symlink into
  # a directory). Reading the manifest through the link read the tree as
  # complete and delegated unaudited.
  mkdir -p "${WORK_DIR}/linked-source"
  printf '{"name":"blockme","version":"2.0.0"}\n' > "${WORK_DIR}/linked-source/package.json"
  ln -s "${WORK_DIR}/linked-source" "${WORK_DIR}/node_modules/blockme"
  printf '{"name":"lockdiff-test","version":"1.0.0"}\n' > "${WORK_DIR}/package.json"
  printf '%s\n' "${LOCKDIFF_PARTIAL_TREE_LOCK}" > "${WORK_DIR}/package-lock.json"
  NPM_LOCK_MUTATION_JSON="${LOCKDIFF_PARTIAL_TREE_LOCK}" \
    SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tblockme@2.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_count 0 $'REAL\tnpm\tdedupe' "${LOG_FILE}" "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_lockdiff_target_platform_follows_npm_argv() {
  skip_lockdiff_case "$FUNCNAME" || return
  prepare_lockdiff_case "npm-lockdiff-target-platform-argv"
  # --os moves the platform npm resolves optional os/cpu against, so the
  # exemption has to move with it: with --os=aix npm installs the aix-only
  # optional that case_npm_lockdiff_exempts_never_installed_optional_entries
  # proves it skips without the flag (r1 review F2).
  printf '{"name":"lockdiff-test","version":"1.0.0"}\n' > "${WORK_DIR}/package.json"
  local lock='{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"},"node_modules/blockme":{"version":"2.0.0","optional":true,"os":["aix"],"resolved":"https://registry.npmjs.org/blockme/-/blockme-2.0.0.tgz","integrity":"sha512-blockme"}}}'
  printf '%s\n' "${lock}" > "${WORK_DIR}/package-lock.json"

  local invocation
  for invocation in 'npm dedupe --os=aix' 'npm prune --os aix'; do
    : > "${LOG_FILE}"
    NPM_LOCK_MUTATION_JSON="${lock}" SAFE_INSTALL_TEST_SCRIPT="${invocation}" run_zsh
    assert_status 104 "$FUNCNAME (${invocation})" || return
    assert_log_contains $'AUDIT\tpackage-audit\tblockme@2.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME (${invocation})" || return
    assert_log_not_contains_fragment $'REAL\tnpm\tdedupe' "$FUNCNAME (${invocation})" || return
    assert_log_not_contains_fragment $'REAL\tnpm\tprune' "$FUNCNAME (${invocation})" || return
  done
  pass "$FUNCNAME"
}

case_npm_lockdiff_dash_led_target_platform_travels_verbatim() {
  skip_lockdiff_case "$FUNCNAME" || return
  prepare_lockdiff_case "npm-lockdiff-dash-led-target-platform"
  # npm treats a target platform as an opaque string, dash-led spellings
  # included — an optional entry constrained to the same string installs. The
  # gate must forward the value verbatim rather than discard it, or the
  # exemption silently re-aims at the host (r2 review, F2 residual).
  printf '{"name":"lockdiff-test","version":"1.0.0"}\n' > "${WORK_DIR}/package.json"
  local lock='{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"},"node_modules/blockme":{"version":"2.0.0","optional":true,"os":["-weird"],"resolved":"https://registry.npmjs.org/blockme/-/blockme-2.0.0.tgz","integrity":"sha512-blockme"}}}'
  printf '%s\n' "${lock}" > "${WORK_DIR}/package-lock.json"
  NPM_LOCK_MUTATION_JSON="${lock}" SAFE_INSTALL_TEST_SCRIPT='npm dedupe --os=-weird' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tblockme@2.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm\tdedupe' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# One aix-only optional entry: exempt on this machine, installed — and so
# audited — as soon as the effective target platform is aix, whichever config
# source says so.
LOCKDIFF_AIX_OPTIONAL_LOCK='{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"},"node_modules/blockme":{"version":"2.0.0","optional":true,"os":["aix"],"resolved":"https://registry.npmjs.org/blockme/-/blockme-2.0.0.tgz","integrity":"sha512-blockme"}}}'

case_npm_lockdiff_target_platform_follows_npm_environment() {
  skip_lockdiff_case "$FUNCNAME" || return
  prepare_lockdiff_case "npm-lockdiff-target-platform-env"
  # npm resolves os/cpu from its environment as well as its argv, and reads
  # those keys case-insensitively. The argv scanner this replaced saw neither
  # spelling, so an npm_config_os=aix run audited against the host platform
  # and exempted the very optional it was about to install (#244).
  printf '{"name":"lockdiff-test","version":"1.0.0"}\n' > "${WORK_DIR}/package.json"
  printf '%s\n' "${LOCKDIFF_AIX_OPTIONAL_LOCK}" > "${WORK_DIR}/package-lock.json"

  : > "${LOG_FILE}"
  npm_config_os=aix NPM_LOCK_MUTATION_JSON="${LOCKDIFF_AIX_OPTIONAL_LOCK}" \
    SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 104 "$FUNCNAME (npm_config_os)" || return
  assert_log_contains $'AUDIT\tpackage-audit\tblockme@2.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME (npm_config_os)" || return
  assert_log_not_contains_fragment $'REAL\tnpm\tdedupe' "$FUNCNAME (npm_config_os)" || return

  : > "${LOG_FILE}"
  NPM_CONFIG_OS=aix NPM_LOCK_MUTATION_JSON="${LOCKDIFF_AIX_OPTIONAL_LOCK}" \
    SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 104 "$FUNCNAME (NPM_CONFIG_OS)" || return
  assert_log_contains $'AUDIT\tpackage-audit\tblockme@2.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME (NPM_CONFIG_OS)" || return
  assert_log_not_contains_fragment $'REAL\tnpm\tdedupe' "$FUNCNAME (NPM_CONFIG_OS)" || return
  pass "$FUNCNAME"
}

case_npm_lockdiff_target_platform_follows_project_npmrc() {
  skip_lockdiff_case "$FUNCNAME" || return
  prepare_lockdiff_case "npm-lockdiff-target-platform-npmrc"
  # A project .npmrc sets the target as legitimately as the command line, and
  # this is the source no argv scan could ever have reached (#244).
  printf 'os=aix\n' > "${WORK_DIR}/.npmrc"
  printf '{"name":"lockdiff-test","version":"1.0.0"}\n' > "${WORK_DIR}/package.json"
  printf '%s\n' "${LOCKDIFF_AIX_OPTIONAL_LOCK}" > "${WORK_DIR}/package-lock.json"
  NPM_LOCK_MUTATION_JSON="${LOCKDIFF_AIX_OPTIONAL_LOCK}" \
    SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tblockme@2.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm\tdedupe' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_lockdiff_refuses_relative_config_paths() {
  skip_lockdiff_case "$FUNCNAME" || return
  prepare_lockdiff_case "npm-lockdiff-relative-config-path"
  # npm resolves a relative userconfig/globalconfig against the cwd, which is
  # the scratch for the projection and the project for the delegate: the same
  # spelling names two different config files, so the projection would vouch
  # for an artifact fetched under settings it never read.
  install_lockdiff_package kept 1.0.0
  printf '{"name":"lockdiff-test","version":"1.0.0"}\n' > "${WORK_DIR}/package.json"
  local lock='{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"},"node_modules/kept":{"version":"1.0.0"}}}'
  printf '%s\n' "${lock}" > "${WORK_DIR}/package-lock.json"

  local invocation
  # The empty spelling refuses with the relative ones: nothing pins what npm
  # resolves it to, and the projection cannot mirror what it cannot predict.
  # A literal ~user path refuses too — npm expands ONLY the ~/ prefix, so
  # ~root/.npmrc is an ordinary cwd-relative name to it (r1 review F2); it is
  # quoted here so the test shell does not expand it before the gate sees it.
  for invocation in \
    'npm dedupe --userconfig ./x' \
    'npm dedupe --userconfig=./x' \
    'npm dedupe --userconfig=' \
    'npm dedupe --userconfig='"'"'~root/.npmrc'"'" \
    'npm dedupe --userconfig='"'"'~'"'" \
    'npm dedupe --globalconfig relative/npmrc'; do
    : > "${LOG_FILE}"
    NPM_LOCK_MUTATION_JSON="${lock}" SAFE_INSTALL_TEST_SCRIPT="${invocation}" run_zsh
    assert_status 100 "$FUNCNAME (${invocation})" || return
    assert_err_contains_fragment 'names a path npm resolves against the current directory' "$FUNCNAME (${invocation})" || return
    [[ "$(wc -l < "${ERR_FILE}")" -eq 1 ]] || { cat "${ERR_FILE}" >&2; fail "$FUNCNAME (${invocation})"; return 1; }
    assert_log_not_contains_fragment $'PROJECTION\tnpm' "$FUNCNAME (${invocation})" || return
    assert_count 0 $'REAL\tnpm\tdedupe' "${LOG_FILE}" "$FUNCNAME (${invocation})" || return
  done

  : > "${LOG_FILE}"
  npm_config_userconfig='./x' NPM_LOCK_MUTATION_JSON="${lock}" \
    SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 100 "$FUNCNAME (env)" || return
  assert_err_contains_fragment 'npm_config_userconfig names a path npm resolves against the current directory' "$FUNCNAME (env)" || return
  assert_count 0 $'REAL\tnpm\tdedupe' "${LOG_FILE}" "$FUNCNAME (env)" || return

  : > "${LOG_FILE}"
  npm_config_userconfig='~root/.npmrc' NPM_LOCK_MUTATION_JSON="${lock}" \
    SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 100 "$FUNCNAME (env ~user)" || return
  assert_err_contains_fragment 'npm_config_userconfig names a path npm resolves against the current directory' "$FUNCNAME (env ~user)" || return
  assert_count 0 $'REAL\tnpm\tdedupe' "${LOG_FILE}" "$FUNCNAME (env ~user)" || return

  # An absolute value resolves to the same file from either cwd, so it is not
  # this guard's business and the command runs its ordinary course.
  : > "${LOG_FILE}"
  printf 'registry=https://registry.npmjs.org/\n' > "${CASE_DIR}/absolute.npmrc"
  NPM_LOCK_MUTATION_JSON="${lock}" \
    SAFE_INSTALL_TEST_SCRIPT="npm dedupe --userconfig ${CASE_DIR}/absolute.npmrc" run_zsh
  assert_status 0 "$FUNCNAME (absolute)" || return
  assert_err_not_contains_fragment 'names a path npm resolves' "$FUNCNAME (absolute)" || return
  assert_log_contains $'REAL\tnpm\tdedupe\t--userconfig\t'"${CASE_DIR}/absolute.npmrc" "$FUNCNAME (absolute)" || return

  # ~/ is the one prefix npm expands against $HOME, in argv and environment
  # alike, so it names the same file from either cwd and passes untouched.
  : > "${LOG_FILE}"
  NPM_LOCK_MUTATION_JSON="${lock}" \
    SAFE_INSTALL_TEST_SCRIPT='npm dedupe --userconfig='"'"'~/home.npmrc'"'" run_zsh
  assert_status 0 "$FUNCNAME (~/)" || return
  assert_err_not_contains_fragment 'names a path npm resolves' "$FUNCNAME (~/)" || return
  assert_log_contains $'REAL\tnpm\tdedupe\t--userconfig=~/home.npmrc' "$FUNCNAME (~/)" || return
  pass "$FUNCNAME"
}

# A workspace root: the member manifest lives outside the root package.json,
# and the lockfile names both the member itself and the registry dependency it
# hoists to the root tree.
LOCKDIFF_WORKSPACE_LOCK='{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0","workspaces":["packages/*"]},"packages/a":{"name":"a","version":"1.0.0","dependencies":{"blockme":"^2.0.0"}},"node_modules/a":{"resolved":"packages/a","link":true},"node_modules/blockme":{"version":"2.0.0","resolved":"https://registry.npmjs.org/blockme/-/blockme-2.0.0.tgz","integrity":"sha512-blockme"}}}'

prepare_lockdiff_workspace_fixture() {
  printf '{"name":"lockdiff-test","version":"1.0.0","workspaces":["packages/*"]}\n' > "${WORK_DIR}/package.json"
  mkdir -p "${WORK_DIR}/packages/a"
  printf '{"name":"a","version":"1.0.0","dependencies":{"blockme":"^2.0.0"}}\n' > "${WORK_DIR}/packages/a/package.json"
  printf '%s\n' "${LOCKDIFF_WORKSPACE_LOCK}" > "${WORK_DIR}/package-lock.json"
  ln -s "${WORK_DIR}/packages/a" "${WORK_DIR}/node_modules/a"
}

case_npm_lockdiff_mirrors_workspace_member_manifests() {
  skip_lockdiff_case "$FUNCNAME" || return
  prepare_lockdiff_case "npm-lockdiff-workspace-member-manifests"
  # Without the member manifests the scratch is a different project: npm
  # silently drops every workspace entry from the projected lockfile, the diff
  # reports removals only — which are never audited — and the member's own
  # dependency is materialized unaudited (#244 silent under-audit).
  prepare_lockdiff_workspace_fixture
  NPM_LOCK_MUTATION_JSON="${LOCKDIFF_WORKSPACE_LOCK}" \
    SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'PROJECTION\tnpm\tPROJMANIFEST:packages/a/package.json\t--package-lock-only\t--ignore-scripts\t--no-audit\t--no-fund\tdedupe' "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tblockme@2.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_count 0 $'REAL\tnpm\tdedupe' "${LOG_FILE}" "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_lockdiff_refuses_escaping_workspace_pattern() {
  skip_lockdiff_case "$FUNCNAME" || return
  prepare_lockdiff_case "npm-lockdiff-workspace-escape"
  # npm accepts a pattern that reaches outside the project root — it produces
  # a ../outside lockfile key — but nothing outside the root is mirrored into
  # the projection, so the two lanes would resolve different member sets.
  #
  # The escape has to be judged on the pattern npm READS, not the raw text:
  # npm 12 converts backslashes to /, so ..\outside walked past a raw-text
  # guard while npm resolved the member outside the root, and a stale lockfile
  # with no such member left the member-set belt nothing to require (r1 review
  # F1). Leading negations are equally irrelevant to where the residue points.
  printf '{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"}}}\n' > "${WORK_DIR}/package-lock.json"
  local pattern
  for pattern in '../outside' '..\\outside' '!!../outside' 'packages/../../outside'; do
    : > "${LOG_FILE}"
    printf '{"name":"lockdiff-test","version":"1.0.0","workspaces":["%s"]}\n' "${pattern}" > "${WORK_DIR}/package.json"
    SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
    assert_status 100 "$FUNCNAME (${pattern})" || return
    assert_err_contains_fragment 'reaches outside the project root' "$FUNCNAME (${pattern})" || return
    [[ "$(wc -l < "${ERR_FILE}")" -eq 1 ]] || { cat "${ERR_FILE}" >&2; fail "$FUNCNAME (${pattern})"; return 1; }
    assert_log_not_contains_fragment $'PROJECTION\tnpm\t--package-lock-only' "$FUNCNAME (${pattern})" || return
    assert_count 0 $'REAL\tnpm\tdedupe' "${LOG_FILE}" "$FUNCNAME (${pattern})" || return
  done
  # The backslash spelling is named verbatim in its refusal, as the user wrote
  # it rather than as the guard normalized it.
  assert_err_contains_fragment 'workspace pattern packages/../../outside reaches outside' "$FUNCNAME" || return

  # A leading slash is root-relative to npm, not an escape: refusing it was a
  # false refusal, and the member behind it mirrors like any other.
  : > "${LOG_FILE}"
  prepare_lockdiff_workspace_fixture
  printf '{"name":"lockdiff-test","version":"1.0.0","workspaces":["/packages/*"]}\n' > "${WORK_DIR}/package.json"
  NPM_LOCK_MUTATION_JSON="${LOCKDIFF_WORKSPACE_LOCK}" \
    SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 104 "$FUNCNAME (root-relative)" || return
  assert_err_not_contains_fragment 'reaches outside the project root' "$FUNCNAME (root-relative)" || return
  assert_log_contains $'PROJECTION\tnpm\tPROJMANIFEST:packages/a/package.json\t--package-lock-only\t--ignore-scripts\t--no-audit\t--no-fund\tdedupe' "$FUNCNAME (root-relative)" || return
  assert_log_contains $'AUDIT\tpackage-audit\tblockme@2.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME (root-relative)" || return
  pass "$FUNCNAME"
}

case_npm_lockdiff_member_set_belt_refuses_dropped_member() {
  skip_lockdiff_case "$FUNCNAME" || return
  prepare_lockdiff_case "npm-lockdiff-member-set-belt"
  # The member the project's lockfile names is gone from the projected one, so
  # npm resolved a different member set in the scratch than it will in the
  # project and the member's subtree would leave the diff as removals nothing
  # audits. A member deliberately deleted refuses here too: the two are
  # indistinguishable without reimplementing npm's member discovery.
  prepare_lockdiff_workspace_fixture
  rm -rf "${WORK_DIR}/packages/a"
  local projected='{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0","workspaces":["packages/*"]}}}'
  NPM_LOCK_MUTATION_JSON="${projected}" SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_err_contains_fragment 'resolved a different workspace member set than the project (packages/a absent from the projection)' "$FUNCNAME" || return
  [[ "$(wc -l < "${ERR_FILE}")" -eq 1 ]] || { cat "${ERR_FILE}" >&2; fail "$FUNCNAME"; return 1; }
  assert_log_not_contains_fragment $'AUDIT\trepo-audit' "$FUNCNAME" || return
  assert_count 0 $'REAL\tnpm\tdedupe' "${LOG_FILE}" "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_lockdiff_mirrors_file_dependency_manifest() {
  skip_lockdiff_case "$FUNCNAME" || return
  prepare_lockdiff_case "npm-lockdiff-file-dependency-manifest"
  # An in-project file: dependency needs its manifest in the scratch for the
  # same reason a workspace member does. Live, the missing manifest failed the
  # projection outright and the command was refused as broken infrastructure;
  # here the sweep evidence and a clean delegation are what the stub can show.
  mkdir -p "${WORK_DIR}/local-pkg"
  printf '{"name":"local-pkg","version":"1.0.0"}\n' > "${WORK_DIR}/local-pkg/package.json"
  printf '{"name":"lockdiff-test","version":"1.0.0","dependencies":{"local-pkg":"file:./local-pkg"}}\n' > "${WORK_DIR}/package.json"
  ln -s "${WORK_DIR}/local-pkg" "${WORK_DIR}/node_modules/local-pkg"
  local lock='{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0","dependencies":{"local-pkg":"file:./local-pkg"}},"local-pkg":{"name":"local-pkg","version":"1.0.0"},"node_modules/local-pkg":{"resolved":"local-pkg","link":true}}}'
  printf '%s\n' "${lock}" > "${WORK_DIR}/package-lock.json"
  NPM_LOCK_MUTATION_JSON="${lock}" SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'PROJECTION\tnpm\tPROJMANIFEST:local-pkg/package.json\t--package-lock-only\t--ignore-scripts\t--no-audit\t--no-fund\tdedupe' "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tdedupe' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'AUDIT\tpackage-audit' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_lockdiff_refuses_cwd_dependent_config() {
  skip_lockdiff_case "$FUNCNAME" || return
  prepare_lockdiff_case "npm-lockdiff-cwd-dependent-config"
  # Copying the config files does not copy what they RESOLVE to: npm resolves
  # a relative path value against the cwd of the process reading it, so the
  # same .npmrc gives the projection a different setting than the delegate
  # gets and the audit would vouch for an artifact resolved elsewhere (r1
  # review F3). The two probes are compared whole, so this is caught
  # generically. The divergence here carries no ${} reference on purpose —
  # that class refuses earlier, at the expansion guard, and this case has to
  # keep exercising the comparison itself.
  install_lockdiff_package kept 1.0.0
  printf 'cache=./cache\n' > "${WORK_DIR}/.npmrc"
  printf '{"name":"lockdiff-test","version":"1.0.0"}\n' > "${WORK_DIR}/package.json"
  local lock='{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"},"node_modules/kept":{"version":"1.0.0"}}}'
  printf '%s\n' "${lock}" > "${WORK_DIR}/package-lock.json"
  NPM_LOCK_MUTATION_JSON="${lock}" SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_err_contains_fragment 'effective npm config resolves differently inside the lock-diff projection (cache)' "$FUNCNAME" || return
  assert_err_contains_fragment 'cannot be mirrored; make those values absolute and retry' "$FUNCNAME" || return
  [[ "$(wc -l < "${ERR_FILE}")" -eq 1 ]] || { cat "${ERR_FILE}" >&2; fail "$FUNCNAME"; return 1; }
  # The projection must not run on a config the audit cannot vouch for.
  assert_log_not_contains_fragment $'PROJECTION\tnpm\t' "$FUNCNAME" || return
  assert_count 0 $'REAL\tnpm\tdedupe' "${LOG_FILE}" "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_lockdiff_refuses_hidden_config_expansion() {
  skip_lockdiff_case "$FUNCNAME" || return
  prepare_lockdiff_case "npm-lockdiff-hidden-config-expansion"
  # npm substitutes ${...} references into every config value, including the
  # secret-bearing keys it omits from its own report — where the parity check
  # cannot see them (r2 F3, r3 N2/N3). Secrecy is decided by observation: a
  # setting whose key npm does not report cannot be verified, so any ${ in it
  # refuses, with no expansion spelling modeled anywhere.
  install_lockdiff_package kept 1.0.0
  printf '{"name":"lockdiff-test","version":"1.0.0"}\n' > "${WORK_DIR}/package.json"
  local lock='{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"},"node_modules/kept":{"version":"1.0.0"}}}'
  printf '%s\n' "${lock}" > "${WORK_DIR}/package-lock.json"

  # r3 N3: npm's ${VAR?} form. The guard needs no knowledge of it.
  printf '//registry.example/:_authToken=${PWD?}\n' > "${WORK_DIR}/.npmrc"
  NPM_LOCK_MUTATION_JSON="${lock}" SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 100 "$FUNCNAME (project rc)" || return
  assert_err_contains_fragment 'sets //registry.example/:_authToken, a setting npm hides from its own config report' "$FUNCNAME (project rc)" || return
  [[ "$(wc -l < "${ERR_FILE}")" -eq 1 ]] || { cat "${ERR_FILE}" >&2; fail "$FUNCNAME (project rc)"; return 1; }
  assert_log_not_contains_fragment $'PROJECTION\tnpm\t' "$FUNCNAME (project rc)" || return
  assert_count 0 $'REAL\tnpm\tdedupe' "${LOG_FILE}" "$FUNCNAME (project rc)" || return

  # The boundary change, operator-ruled: a reference the old design classified
  # as lane-shared refuses too. Classifying references is the mechanism three
  # review rounds broke.
  : > "${LOG_FILE}"
  printf '//registry.example/:_authToken=${NPM_TOKEN}\n' > "${WORK_DIR}/.npmrc"
  NPM_LOCK_MUTATION_JSON="${lock}" SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 100 "$FUNCNAME (shared-env reference)" || return
  assert_err_contains_fragment 'a setting npm hides from its own config report' "$FUNCNAME (shared-env reference)" || return
  assert_count 0 $'REAL\tnpm\tdedupe' "${LOG_FILE}" "$FUNCNAME (shared-env reference)" || return

  # An escaped reference in a HIDDEN key refuses as well: the accepted
  # over-refusal direction, since verifying it would mean modeling the escape.
  : > "${LOG_FILE}"
  printf '//registry.example/:_authToken=\\${PWD}\n' > "${WORK_DIR}/.npmrc"
  NPM_LOCK_MUTATION_JSON="${lock}" SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 100 "$FUNCNAME (escaped in hidden key)" || return
  assert_err_contains_fragment 'a setting npm hides from its own config report' "$FUNCNAME (escaped in hidden key)" || return

  # r3 N2: the same secret carried on the command line.
  : > "${LOG_FILE}"
  rm -f "${WORK_DIR}/.npmrc"
  NPM_LOCK_MUTATION_JSON="${lock}" \
    SAFE_INSTALL_TEST_SCRIPT='npm dedupe '"'"'--//registry.example/:_authToken=${PWD}'"'" run_zsh
  assert_status 100 "$FUNCNAME (argv)" || return
  assert_err_contains_fragment 'the command line sets //registry.example/:_authToken, which npm does not report as a setting' "$FUNCNAME (argv)" || return
  assert_count 0 $'REAL\tnpm\tdedupe' "${LOG_FILE}" "$FUNCNAME (argv)" || return

  # An environment-carried VISIBLE setting is parity's jurisdiction like any
  # other: npm reports globalconfig, so the reference is verified by comparing
  # resolved values rather than refused here.
  : > "${LOG_FILE}"
  npm_config_globalconfig='/abs/${PWD}/npmrc' NPM_LOCK_MUTATION_JSON="${lock}" \
    SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 0 "$FUNCNAME (visible env key delegates)" || return
  assert_err_not_contains_fragment 'hides from its own config report' "$FUNCNAME (visible env key delegates)" || return

  # An environment-carried HIDDEN credential is the env surface's real case:
  # npm reports no such key, so nothing can verify it resolves identically.
  : > "${LOG_FILE}"
  npm_config__authToken='${PWD}' NPM_LOCK_MUTATION_JSON="${lock}" \
    SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 100 "$FUNCNAME (hidden env credential)" || return
  assert_err_contains_fragment 'npm_config__authToken sets' "$FUNCNAME (hidden env credential)" || return
  assert_err_contains_fragment 'a setting npm hides from its own config report' "$FUNCNAME (hidden env credential)" || return
  [[ "$(wc -l < "${ERR_FILE}")" -eq 1 ]] || { cat "${ERR_FILE}" >&2; fail "$FUNCNAME (hidden env credential)"; return 1; }
  assert_log_not_contains_fragment $'PROJECTION\tnpm\t' "$FUNCNAME (hidden env credential)" || return
  assert_count 0 $'REAL\tnpm\tdedupe' "${LOG_FILE}" "$FUNCNAME (hidden env credential)" || return

  # A VISIBLE key is parity's jurisdiction, not this guard's: it passes here
  # and the comparison of npm-resolved values is what refuses it.
  : > "${LOG_FILE}"
  printf 'os=${PWD}\n' > "${WORK_DIR}/.npmrc"
  NPM_LOCK_MUTATION_JSON="${lock}" SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 100 "$FUNCNAME (visible key reaches parity)" || return
  assert_err_contains_fragment 'effective npm config resolves differently inside the lock-diff projection (os)' "$FUNCNAME (visible key reaches parity)" || return
  assert_count 0 $'REAL\tnpm\tdedupe' "${LOG_FILE}" "$FUNCNAME (visible key reaches parity)" || return

  # r3 N4: an escaped reference in a VISIBLE key is a literal to npm, so both
  # lanes receive the same value, parity agrees, and the command delegates.
  # The old token guard refused this outright.
  : > "${LOG_FILE}"
  printf 'os=\\${PWD}\n' > "${WORK_DIR}/.npmrc"
  NPM_LOCK_MUTATION_JSON="${lock}" SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 0 "$FUNCNAME (escaped in visible key)" || return
  assert_err_not_contains_fragment 'hides from its own config report' "$FUNCNAME (escaped in visible key)" || return
  assert_err_not_contains_fragment 'resolves differently inside' "$FUNCNAME (escaped in visible key)" || return
  assert_log_contains $'REAL\tnpm\tdedupe' "$FUNCNAME (escaped in visible key)" || return
  pass "$FUNCNAME"
}
case_npm_lockdiff_manifest_copy_failure_is_one_line() {
  skip_lockdiff_case "$FUNCNAME" || return
  prepare_lockdiff_case "npm-lockdiff-manifest-copy-failure"
  # A manifest the sweep cannot read is audit-infrastructure breakage, and the
  # refusal contract is one final stderr line: cp's own diagnostic ahead of it
  # made two (r1 review F4).
  printf '{"name":"lockdiff-test","version":"1.0.0"}\n' > "${WORK_DIR}/package.json"
  printf '{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"}}}\n' > "${WORK_DIR}/package-lock.json"
  mkdir -p "${WORK_DIR}/nested"
  printf '{"name":"nested","version":"1.0.0"}\n' > "${WORK_DIR}/nested/package.json"
  chmod 000 "${WORK_DIR}/nested/package.json"
  SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  chmod 644 "${WORK_DIR}/nested/package.json"
  assert_status 100 "$FUNCNAME" || return
  assert_err_contains_fragment 'cannot mirror in-project package.json manifests' "$FUNCNAME" || return
  [[ "$(wc -l < "${ERR_FILE}")" -eq 1 ]] || { cat "${ERR_FILE}" >&2; fail "$FUNCNAME"; return 1; }
  assert_count 0 $'REAL\tnpm\tdedupe' "${LOG_FILE}" "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_lockdiff_refuses_nonregistry_reify_candidate() {
  skip_lockdiff_case "$FUNCNAME" || return
  prepare_lockdiff_case "npm-lockdiff-nonregistry-reify-candidate"
  # Same rule as a non-registry delta target, reached without a delta: nothing
  # audit-gates a git artifact, so materializing one refuses.
  printf '{"name":"lockdiff-test","version":"1.0.0"}\n' > "${WORK_DIR}/package.json"
  local lock='{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"},"node_modules/gitpkg":{"version":"1.0.0","resolved":"git+https://example.invalid/gitpkg.git#deadbeef","integrity":"sha512-git"}}}'
  printf '%s\n' "${lock}" > "${WORK_DIR}/package-lock.json"
  NPM_LOCK_MUTATION_JSON="${lock}" SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_err_contains_fragment 'this command would materialize gitpkg@1.0.0, a git artifact, not a registry artifact; not audit-gated' "$FUNCNAME" || return
  [[ "$(wc -l < "${ERR_FILE}")" -eq 1 ]] || { cat "${ERR_FILE}" >&2; fail "$FUNCNAME"; return 1; }
  assert_log_not_contains_fragment $'AUDIT\trepo-audit' "$FUNCNAME" || return
  assert_count 0 $'REAL\tnpm\tdedupe' "${LOG_FILE}" "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_lockdiff_projection_sees_project_npmrc() {
  skip_lockdiff_case "$FUNCNAME" || return
  prepare_lockdiff_case "npm-lockdiff-npmrc-copied"
  # A project-level registry must govern the projection too, or the audit
  # vouches for a different artifact than the delegate fetches (review F3).
  install_lockdiff_package kept 1.0.0
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
  assert_log_contains $'AUDIT\tpackage-audit\tblockme@2.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
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
  assert_log_not_contains_fragment $'AUDIT\trepo-audit' "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tpackage-audit\tblockme@2.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
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
  assert_log_not_contains_fragment $'AUDIT\trepo-audit' "$FUNCNAME" || return
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
  assert_log_not_contains_fragment $'AUDIT\trepo-audit' "$FUNCNAME" || return

  # A project-private registry host is authoritative and retains the .name
  # identity for the normal audit lane.
  prepare_lockdiff_case "npm-lockdiff-private-registry-host"
  printf '{"name":"lockdiff-test","version":"1.0.0"}\n' > "${WORK_DIR}/package.json"
  printf '{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"}}}\n' > "${WORK_DIR}/package-lock.json"
  NPM_LOCKDIFF_REGISTRY_CONFIG_JSON='{"registry":"https://registry.example.test/","@scope:registry":null}' \
    NPM_LOCK_MUTATION_JSON='{"lockfileVersion":3,"packages":{"":{"name":"lockdiff-test","version":"1.0.0"},"node_modules/alias":{"name":"private-pkg","version":"1.0.0","resolved":"https://registry.example.test/private-pkg/-/private-pkg-1.0.0.tgz","integrity":"sha512-private"}}}' \
    SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tprivate-pkg@1.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
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
  assert_log_not_contains_fragment $'AUDIT\trepo-audit' "$FUNCNAME" || return

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
  assert_log_contains $'AUDIT\tpackage-audit\tleft-pad@1.3.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tpackage-audit\tlodash\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'\tweb\t--ecosystem' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_blocked_install() {
  prepare_case "blocked-install"
  SAFE_INSTALL_TEST_SCRIPT='npm install -g blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tpackage-audit\twarnme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tpackage-audit\twarnme@1.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tpackage-audit\twarnme@1.0.1\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_colon_version_global_install() {
  prepare_case "npm-colon-version-global-install"
  SAFE_INSTALL_TEST_SCRIPT='npm install -g @qwen-code/qwen-code:0.16.2' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\t@qwen-code/qwen-code@0.16.2\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tinstall\t-g\t@qwen-code/qwen-code:0.16.2' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_alias_audits_target_package() {
  prepare_case "npm-alias-audits-target-package"
  SAFE_INSTALL_TEST_SCRIPT='npm install -g qwen@npm:@qwen-code/qwen-code@0.16.2' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\t@qwen-code/qwen-code@0.16.2\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tinstall\t-g\tqwen@npm:@qwen-code/qwen-code@0.16.2' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_audit_failure_blocks() {
  prepare_case "audit-failure-blocks"
  SAFE_AUDIT_CHECK_STATUS=42 SAFE_INSTALL_TEST_SCRIPT='uv tool install repomix' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\trepomix\t--ecosystem\tpython\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
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
  assert_err_contains_fragment 'safe: BLOCKED install — safe audit repo-audit found critical findings' "$FUNCNAME" || return
  # Non-TTY refusals are exactly one line: the interactive preamble (which
  # says the scan FAILED, never that it "found" something) stays out.
  assert_err_not_contains_fragment 'after reporting critical findings' "$FUNCNAME" || return
  [[ "$(wc -l < "${ERR_FILE}")" -eq 1 ]] || { cat "${ERR_FILE}" >&2; fail "$FUNCNAME"; return 1; }
  pass "$FUNCNAME"
}

# #147: a scan that FAILS OUTRIGHT (a non-zero exit — required scanners missing
# in non-TTY is the common case, safe-audit exit 2) yields no verdict and never
# says "critical". An interactive shell warns and lets the operator proceed; a
# non-interactive shell has no one to weigh that warning, so it fails closed
# with exit 100 rather than delegating an unaudited install — mirroring the
# projected-dependency scan guard and the critical-findings non-TTY refusal
# above. The sibling no-verdict sites (unwritable destination; exit-0 unreadable
# document) share this terminus since 2026-11-17 — see the malformed-result case.
case_scan_failed_outright_non_tty_blocks() {
  prepare_case "scan-failed-outright-non-tty-blocks"
  touch "${WORK_DIR}/package.json"
  SAFE_AUDIT_SCAN_OUTPUT='local: skipping scan because required scanners are missing in non-TTY mode' \
    SAFE_AUDIT_SCAN_STATUS=2 SAFE_AUDIT_SCAN_NO_RESULT=1 \
    SAFE_INSTALL_TEST_SCRIPT='npm ci' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_project_scan_logged "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm' "$FUNCNAME" || return
  assert_err_contains_fragment 'safe: BLOCKED install — safe audit repo-audit failed with exit 2' "$FUNCNAME" || return
  assert_err_contains_fragment 'audit-infrastructure breakage, not a package finding' "$FUNCNAME" || return
  # Non-TTY refusals are exactly one line: no interactive "proceeding" tail.
  assert_err_not_contains_fragment 'proceeding' "$FUNCNAME" || return
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
  assert_err_contains_fragment 'safe: BLOCKED install — safe audit repo-audit found critical findings' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# A package manager's install gates on its own ecosystem's criticals (and on
# findings no ecosystem claims); other ecosystems' are reported, never gating.
case_scan_scope_other_ecosystem_reported_not_gating() {
  prepare_case "scan-scope-other-ecosystem"
  touch "${WORK_DIR}/package.json"
  SAFE_AUDIT_SCAN_STATUS=0 SAFE_AUDIT_SCAN_VERDICT=WARN SAFE_AUDIT_SCAN_CRITICAL=2 \
    SAFE_AUDIT_SCAN_BY_ECOSYSTEM='{"composer":{"critical":2,"high":0,"medium":0,"low":0,"unknown":0},"npm":{"critical":0,"high":3,"medium":0,"low":0,"unknown":0}}' \
    SAFE_INSTALL_TEST_SCRIPT='npm ci' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tci' "$FUNCNAME" || return
  assert_err_contains_fragment "2 critical finding(s) in this project's composer dependencies do not gate this npm install" "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_scan_scope_own_ecosystem_still_gates() {
  prepare_case "scan-scope-own-ecosystem"
  touch "${WORK_DIR}/package.json"
  SAFE_AUDIT_SCAN_STATUS=0 SAFE_AUDIT_SCAN_VERDICT=WARN SAFE_AUDIT_SCAN_CRITICAL=2 \
    SAFE_AUDIT_SCAN_BY_ECOSYSTEM='{"composer":{"critical":1},"npm":{"critical":1}}' \
    SAFE_INSTALL_TEST_SCRIPT='yarn install' run_zsh
  assert_status 102 "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tyarn' "$FUNCNAME" || return
  # The other-ecosystem note comes first; the refusal stays the final line.
  assert_err_contains_fragment "1 critical finding(s) in this project's composer dependencies do not gate this yarn install" "$FUNCNAME" || return
  [[ "$(tail -n 1 "${ERR_FILE}")" == "safe: BLOCKED install"* ]] || { printf 'last stderr line: %s\n' "$(tail -n 1 "${ERR_FILE}")" >&2; fail "$FUNCNAME final line"; return; }
  pass "$FUNCNAME"
}

case_scan_scope_unattributed_or_inconsistent_gates() {
  prepare_case "scan-scope-unattributed"
  touch "${WORK_DIR}/package.json"
  SAFE_AUDIT_SCAN_STATUS=0 SAFE_AUDIT_SCAN_VERDICT=WARN SAFE_AUDIT_SCAN_CRITICAL=1 \
    SAFE_AUDIT_SCAN_BY_ECOSYSTEM='{"other":{"critical":1}}' \
    SAFE_INSTALL_TEST_SCRIPT='npm ci' run_zsh
  assert_status 102 "$FUNCNAME" || return
  # A breakdown that does not add up to the total gates on the total.
  prepare_case "scan-scope-inconsistent"
  touch "${WORK_DIR}/package.json"
  SAFE_AUDIT_SCAN_STATUS=0 SAFE_AUDIT_SCAN_VERDICT=WARN SAFE_AUDIT_SCAN_CRITICAL=3 \
    SAFE_AUDIT_SCAN_BY_ECOSYSTEM='{"composer":{"critical":1}}' \
    SAFE_INSTALL_TEST_SCRIPT='npm ci' run_zsh
  assert_status 102 "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# `yarn --version` and `yarn --help` print; only a bare `yarn` installs.
case_yarn_version_or_help_is_not_an_install() {
  local script
  for script in 'yarn --version' 'yarn -v' 'yarn --help' 'yarn --cwd sub -h'; do
    prepare_case "yarn-flag-only"
    touch "${WORK_DIR}/package.json"
    mkdir -p "${WORK_DIR}/sub"
    SAFE_AUDIT_SCAN_CRITICAL=1 SAFE_INSTALL_TEST_SCRIPT="${script}" run_zsh
    assert_status 0 "$FUNCNAME ${script}" || return
    assert_log_contains "REAL"$'\t'"$(tr ' ' '\t' <<<"${script}")" "$FUNCNAME ${script}" || return
    assert_log_not_contains_fragment 'repo-audit' "$FUNCNAME ${script}" || return
  done
  # A value-taking flag's value is not a version or help flag: these install.
  for script in 'yarn --cwd -v' 'yarn --modules-folder --help'; do
    prepare_case "yarn-flag-value"
    touch "${WORK_DIR}/package.json"
    mkdir -p -- "${WORK_DIR}/-v"
    touch "${WORK_DIR}/-v/package.json"
    SAFE_AUDIT_SCAN_STATUS=0 SAFE_AUDIT_SCAN_VERDICT=WARN SAFE_AUDIT_SCAN_CRITICAL=1 \
      SAFE_INSTALL_TEST_SCRIPT="${script}" run_zsh
    assert_status 102 "$FUNCNAME ${script}" || return
    assert_log_not_contains_fragment $'REAL\tyarn' "$FUNCNAME ${script}" || return
  done
  prepare_case "yarn-bare-installs"
  touch "${WORK_DIR}/package.json"
  SAFE_AUDIT_SCAN_STATUS=0 SAFE_AUDIT_SCAN_VERDICT=WARN SAFE_AUDIT_SCAN_CRITICAL=1 \
    SAFE_INSTALL_TEST_SCRIPT='yarn --frozen-lockfile' run_zsh
  assert_status 102 "$FUNCNAME bare" || return
  pass "$FUNCNAME"
}

# A result document that is present but not readable is NOT a clean verdict.
# Every jq read against a truncated document falls back to its default, and
# defaulted zeros are indistinguishable from "scanned it, found nothing" — so
# the gate used to announce a clean project it had never actually read.
# Ruled 2026-11-17: a scan with no verdict is one terminus whatever the cause.
# With no operator present it refuses (100, audit-infrastructure breakage),
# exactly like a scan that failed outright.
case_malformed_result_document_is_not_read_as_clean() {
  prepare_case "malformed-result-not-clean"
  touch "${WORK_DIR}/package.json"
  SAFE_AUDIT_SCAN_STATUS=0 SAFE_AUDIT_SCAN_MALFORMED_RESULT=1 \
    SAFE_INSTALL_TEST_SCRIPT='npm ci' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_project_scan_logged "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm' "$FUNCNAME" || return
  assert_err_contains_fragment 'safe: BLOCKED install — safe audit repo-audit produced no readable result' "$FUNCNAME" || return
  assert_err_contains_fragment 'audit-infrastructure breakage, not a package finding' "$FUNCNAME" || return
  assert_err_contains_fragment 'NOT audit-gated' "$FUNCNAME" || return
  assert_err_not_contains_fragment 'proceeding' "$FUNCNAME" || return
  [[ "$(wc -l < "${ERR_FILE}")" -eq 1 ]] || { cat "${ERR_FILE}" >&2; fail "$FUNCNAME"; return 1; }

  # A successful scan's summary prints the word "critical" with a count. With
  # no readable document that word is not evidence of a finding: the refusal
  # stays an infrastructure one and never asks for a critical confirmation.
  prepare_case "malformed-result-summary-mentions-critical"
  touch "${WORK_DIR}/package.json"
  SAFE_AUDIT_SCAN_OUTPUT='  CRITICAL: 0' SAFE_AUDIT_SCAN_STATUS=0 SAFE_AUDIT_SCAN_MALFORMED_RESULT=1 \
    SAFE_INSTALL_TEST_SCRIPT='npm ci' run_zsh
  assert_status 100 "$FUNCNAME summary" || return
  assert_err_contains_fragment 'produced no readable result' "$FUNCNAME summary" || return
  assert_err_not_contains_fragment 'critical finding' "$FUNCNAME summary" || return
  pass "$FUNCNAME"
}

# The third no-verdict cause: nowhere to write the result document. Same
# terminus, and with no operator the scan is not even run — there would be
# nothing to decide from.
case_unwritable_result_destination_blocks_without_operator() {
  prepare_case "unwritable-result-destination"
  touch "${WORK_DIR}/package.json"
  : > "${WORK_DIR}/not-a-dir"
  TMPDIR="${WORK_DIR}/not-a-dir/tmp" SAFE_DATA_DIR="${WORK_DIR}/not-a-dir/data" \
    SAFE_INSTALL_TEST_SCRIPT='npm ci' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm' "$FUNCNAME" || return
  assert_err_contains_fragment 'safe: BLOCKED install — cannot allocate a scan result file' "$FUNCNAME" || return
  assert_err_contains_fragment 'audit-infrastructure breakage, not a package finding' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# The operator's side of that terminus: at their terminal every no-verdict
# cause warns, says the project was not audit-gated, and proceeds — the
# override lane the refusal points to. The predicate and the terminal writer
# are stubbed; no PTY is manufactured.
case_no_verdict_scan_warns_and_proceeds_at_operator_terminal() {
  prepare_case "no-verdict-operator-terminal"
  local out status=0
  out="$(GATE_LIB="${ROOT_DIR}/lib/gate-lib.sh" bash -c '
    source "${GATE_LIB}"
    safe_gate_operator_terminal() { return 0; }
    safe_gate_tty_printf() { local fmt="$1"; shift; printf "${fmt}" "$@" >&2; }
    safe_gate_scan_no_verdict "safe audit repo-audit produced no readable result"
  ' 2>&1)" || status=$?
  [[ "${status}" -eq 0 ]] || { printf '%s\n' "${out}" >&2; fail "$FUNCNAME status ${status}"; return 1; }
  [[ "${out}" == 'safe install: safe audit repo-audit produced no readable result; the project was NOT audit-gated — safe doctor; proceeding' ]] ||
    { printf '%s\n' "${out}" >&2; fail "$FUNCNAME message"; return 1; }
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
  assert_log_contains $'AUDIT\tpackage-audit\tleft-pad\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall\t--dist-tag\tbeta\t--registry\thttps://registry.example' "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tpackage-audit\trequests@2.32.0\t--ecosystem\tpython\t--gate\tinstall\t--op\tinstall\t--registry\thttps://pypi.example\t--python-isolated' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'\thttps://pypi.example@latest' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'\tconstraints.txt@latest' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_requirement_install_scans() {
  prepare_case "requirement-install-scans"
  SAFE_INSTALL_TEST_SCRIPT='pip install -r requirements.txt' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_project_scan_logged "$FUNCNAME" || return
  assert_log_not_contains_fragment $'AUDIT\tpackage-audit' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# A requirement file with any basename routes through the project scan and
# its packages reach the scan's pip-audit lane (inbox 2026-10-11); a remote
# requirement file cannot be inventoried and refuses before delegating.
case_pip_requirement_any_basename() {
  prepare_case "pip-requirement-any-basename"
  mkdir -p "${WORK_DIR}/deps"
  printf 'okpkg==1.0.0\n' > "${WORK_DIR}/deps/prod.txt"
  SAFE_INSTALL_TEST_SCRIPT='pip install -r deps/prod.txt' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_project_scan_logged "$FUNCNAME" || return
  grep -Fq $'AUDIT\trepo-audit\t.\t--deps-only\t--allow-missing-tools\t--pip-requirement\tdeps/prod.txt\t' "${LOG_FILE}" || { fail "$FUNCNAME"; return; }
  assert_log_contains $'REAL\tpip\tinstall\t-r\tdeps/prod.txt' "$FUNCNAME" || return

  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='pip install --requirement=deps/prod.txt' run_zsh
  assert_status 0 "$FUNCNAME" || return
  grep -Fq -- $'--pip-requirement\tdeps/prod.txt' "${LOG_FILE}" || { fail "$FUNCNAME"; return; }

  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='uv pip install -r deps/prod.txt' run_zsh
  assert_status 0 "$FUNCNAME" || return
  grep -Fq -- $'--pip-requirement\tdeps/prod.txt' "${LOG_FILE}" || { fail "$FUNCNAME"; return; }

  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='pip install -r https://example.invalid/req.txt' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tpip' "$FUNCNAME" || return
  grep -Fq "is remote and cannot be audited" "${ERR_FILE}" || { fail "$FUNCNAME"; return; }

  # A missing local file installs nothing (pip errors itself): delegated,
  # and not threaded into the scan.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='pip install -r deps/missing.txt' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'REAL\tpip\tinstall\t-r\tdeps/missing.txt' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'--pip-requirement' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# A bare-relative wheel path is a local artifact, not a package identity
# (inbox 2026-10-10): pip runs unaudited like the ./ spelling, and the gate
# audit log names the artifact with its sha256 (inbox 2026-10-10, audit
# line). Both spellings behave identically.
case_pip_local_wheel() {
  prepare_case "pip-local-wheel"
  mkdir -p "${WORK_DIR}/dist"
  printf 'wheel-bytes' > "${WORK_DIR}/dist/caviar_redact-0.2.0-py3-none-any.whl"
  local want_sha
  want_sha="$(sha256sum "${WORK_DIR}/dist/caviar_redact-0.2.0-py3-none-any.whl" | cut -d' ' -f1)"
  local audit_log="${HOME_DIR}/.local/share/safe/run/audit.log"
  local spelling
  for spelling in 'dist/caviar_redact-0.2.0-py3-none-any.whl' './dist/caviar_redact-0.2.0-py3-none-any.whl'; do
    SAFE_INSTALL_TEST_SCRIPT="pip install --no-index --no-deps ${spelling}" run_zsh
    assert_status 0 "$FUNCNAME" || return
    assert_log_contains $'REAL\tpip\tinstall\t--no-index\t--no-deps\t'"${spelling}" "$FUNCNAME" || return
    assert_log_not_contains_fragment $'AUDIT\tpackage-audit' "$FUNCNAME" || return
    grep -Fq "| install:python | ${spelling} | GATE |" "${audit_log}" || { fail "$FUNCNAME"; return; }
    grep -Fq "| LOCAL_ARTIFACT | path=${WORK_DIR}/dist/caviar_redact-0.2.0-py3-none-any.whl sha256=${want_sha}" "${audit_log}" || { fail "$FUNCNAME"; return; }
    : > "${LOG_FILE}"
  done
  pass "$FUNCNAME"
}

case_cargo_parser() {
  prepare_case "cargo-parser"
  SAFE_INSTALL_TEST_SCRIPT='cargo install ripgrep --version 14.1.1' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tripgrep@14.1.1\t--ecosystem\tcargo\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'\t14.1.1@latest' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_go_parser() {
  prepare_case "go-parser"
  SAFE_INSTALL_TEST_SCRIPT='go install -tags netgo example.com/tool@v1.2.3' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\texample.com/tool@v1.2.3\t--ecosystem\tgo\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'\tnetgo@latest' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_composer_parser() {
  prepare_case "composer-parser"
  SAFE_INSTALL_TEST_SCRIPT='composer global require --working-dir /tmp vendor/pkg:^1' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tvendor/pkg@^1\t--ecosystem\tcomposer\t--gate\tinstall\t--op\tinstall\t--project-dir\t/tmp' "$FUNCNAME" || return
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

# The agent skill ships with the release: installed on every run, linked
# into present harnesses only with --agent-skills, never over an entry safe
# did not create, recorded for release follow, removed by uninstall.
case_install_agent_skills() {
  prepare_case "install-agent-skills"
  local data="${HOME_DIR}/.local/share/safe" installed
  installed="${data}/skills/safe"
  mkdir -p "${HOME_DIR}/.claude" "${HOME_DIR}/.codex/skills/safe"
  printf 'their own skill\n' > "${HOME_DIR}/.codex/skills/safe/SKILL.md"
  HOME="${HOME_DIR}" SAFE_DATA_DIR="${data}" SAFE_CONFIG_DIR="${HOME_DIR}/.config/safe" \
    bash "${ROOT_DIR}/install.sh" >"${OUT_FILE}" 2>"${ERR_FILE}"
  STATUS=$?
  assert_status 0 "$FUNCNAME default" || return
  cmp -s "${ROOT_DIR}/share/agent/skills/safe/SKILL.md" "${installed}/SKILL.md" || { fail "$FUNCNAME: skill not installed"; return; }
  [[ ! -e "${HOME_DIR}/.claude/skills/safe" ]] || { fail "$FUNCNAME: linked without --agent-skills"; return; }

  printf 'dropped by a newer release\n' > "${installed}/stale.md"
  HOME="${HOME_DIR}" SAFE_DATA_DIR="${data}" SAFE_CONFIG_DIR="${HOME_DIR}/.config/safe" \
    bash "${ROOT_DIR}/install.sh" --all --agent-skills >>"${OUT_FILE}" 2>>"${ERR_FILE}" || STATUS=$?
  assert_status 0 "$FUNCNAME --agent-skills" || return
  [[ ! -e "${installed}/stale.md" ]] || { fail "$FUNCNAME: a stale skill file survived the reinstall"; return; }
  [[ -L "${HOME_DIR}/.claude/skills/safe" && "$(readlink "${HOME_DIR}/.claude/skills/safe")" == "${installed}" ]] ||
    { fail "$FUNCNAME: the skill was not linked into .claude/skills"; return; }
  [[ -d "${HOME_DIR}/.codex/skills/safe" && ! -L "${HOME_DIR}/.codex/skills/safe" ]] &&
    grep -q 'their own skill' "${HOME_DIR}/.codex/skills/safe/SKILL.md" ||
    { fail "$FUNCNAME: an existing skill directory was replaced"; return; }
  assert_err_contains_fragment "${HOME_DIR}/.codex/skills/safe already exists; left as is" "$FUNCNAME" || return
  jq -e '.install_flags == ["--all", "--agent-skills"]' "${HOME_DIR}/.config/safe/release-follow.json" >/dev/null ||
    { fail "$FUNCNAME: release follow does not record --agent-skills"; return; }

  HOME="${HOME_DIR}" SAFE_DATA_DIR="${data}" SAFE_CONFIG_DIR="${HOME_DIR}/.config/safe" \
    bash "${ROOT_DIR}/uninstall.sh" >>"${OUT_FILE}" 2>>"${ERR_FILE}" || STATUS=$?
  assert_status 0 "$FUNCNAME uninstall" || return
  [[ ! -e "${HOME_DIR}/.claude/skills/safe" && ! -L "${HOME_DIR}/.claude/skills/safe" && ! -e "${installed}" ]] ||
    { fail "$FUNCNAME: uninstall left the skill or its link"; return; }
  [[ -f "${HOME_DIR}/.codex/skills/safe/SKILL.md" ]] || { fail "$FUNCNAME: uninstall removed a skill safe did not create"; return; }
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

case_gate_marker_probe_is_nul_safe() {
  # Every gated go/cargo/bun invocation ran the marker probe over an ELF
  # binary, and bash printed `warning: command substitution: ignored null byte
  # in input` to stderr each time (regression 1.56.0, #134). The probe must
  # report "not a wrapper" for a binary AND say nothing at all while doing it.
  prepare_case "gate-marker-probe-nul-safe"
  local dir="${WORK_DIR}/nulbin"
  mkdir -p "${dir}"
  printf '#!/x\n\0\0ELF\0\n' > "${dir}/go"
  chmod +x "${dir}/go"

  local out="${WORK_DIR}/marker.out" err="${WORK_DIR}/marker.err"
  PATH="${dir}:/usr/bin:/bin" GATE_LIB="${ROOT_DIR}/lib/gate-lib.sh" TOOLPATH="${dir}/go" \
    bash -c 'set -euo pipefail; source "${GATE_LIB}"; safe_gate_wrapper_marker_tool "${TOOLPATH}"' \
    > "${out}" 2> "${err}"
  [[ ! -s "${out}" ]] || {
    printf 'marker probe printed %s for a binary\n' "$(cat "${out}")" >&2
    fail "$FUNCNAME"; return
  }
  [[ ! -s "${err}" ]] || {
    printf 'marker probe wrote to stderr: %s\n' "$(cat "${err}")" >&2
    fail "$FUNCNAME"; return
  }

  # The binary is still a resolvable delegate: the probe must not disqualify it.
  local got
  got="$(PATH="${dir}:/usr/bin:/bin" GATE_LIB="${ROOT_DIR}/lib/gate-lib.sh" \
    bash -c 'source "${GATE_LIB}"; safe_gate_resolve_real go' 2>"${err}")"
  [[ "${got}" == "${dir}/go" ]] || {
    printf 'resolved to %s, expected %s\n' "${got:-<empty>}" "${dir}/go" >&2
    fail "$FUNCNAME"; return
  }
  [[ ! -s "${err}" ]] || {
    printf 'resolve_real wrote to stderr: %s\n' "$(cat "${err}")" >&2
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
  # Loop-freedom evidence (1.56.0): pnpm is a GATED argv[0], so a delegate exec
  # of the shim itself would bounce straight back into `safe gate pnpm` —
  # wrapper -> gate -> shim -> wrapper, forever. exec_real must reach the real
  # mise directly instead, so this recorder must stay empty.
  local gatelog="${WORK_DIR}/reentry.log"
  : > "${gatelog}"
  cat > "${wrap}/safe" <<STUB
#!/usr/bin/env bash
printf 'REENTRY\t%s\n' "\$*" >> "${gatelog}"
STUB
  chmod +x "${wrap}/safe"

  local out
  out="$(PATH="${wrap}:${shimdir}:${realbin}:/usr/bin:/bin" GATE_LIB="${ROOT_DIR}/lib/gate-lib.sh" \
    bash -c 'source "${GATE_LIB}"; safe_gate_exec_real pnpm --version' 2>&1)"
  # The delegate is the real mise, which receives the tool's args. Any gate
  # re-entry or dispatch failure surfaces as different output (or the
  # preamble's 127 message).
  if [[ "$out" != "REALMISE args=--version" ]]; then
    printf 'got: %s\n' "$out" >&2
    fail "$FUNCNAME"
    return
  fi
  if [[ -s "${gatelog}" ]]; then
    printf 're-entered the gate: %s\n' "$(cat "${gatelog}")" >&2
    fail "$FUNCNAME"
    return
  fi
  # A shebang-script stub cannot OBSERVE the preserved argv[0] — the kernel
  # rebuilds argv for the interpreter of a script, so only a native binary
  # (like the real mise) receives it, and argv[0] is what mise multiplexes on.
  # Pin the argv0-preserving exec form itself, as the wrapper case does.
  if ! grep -Fq 'exec -a "$exec_argv0" "$real" "$@"' "${ROOT_DIR}/lib/gate-lib.sh"; then
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
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tpython\t--gate\tinstall\t--op\tinstall\t--registry\thttps://packages.example' "$FUNCNAME" || return

  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='uv pip install --index-url=https://pypi.example blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tpython\t--gate\tinstall\t--op\tinstall\t--registry\thttps://pypi.example\t--python-isolated' "$FUNCNAME" || return

  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='uv run --index https://idx.example --with blockme script.py' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tpython\t--gate\tinstall\t--op\tinstall\t--registry\thttps://idx.example' "$FUNCNAME" || return
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
  # The find-links selector is also flagged for the private-registry lane,
  # which cannot probe a flat file page for a namesake (round-1 P2).
  assert_log_contains $'AUDIT\tpackage-audit\tblockme@1.0.0\t--ecosystem\tpython\t--gate\tinstall\t--op\tinstall\t--registry\thttps://evil.example/wheels https://pypi.org/simple\t--find-links-selected\t--python-isolated' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_python_private_route_context_reaches_audit() {
  prepare_case "python-private-route-context"
  # The private-registry lane trusts a private Python name only on the
  # routes whose delegate the gate isolates (trusted origins, ruling a37):
  # explicit pip / uv pip install specs carry --python-isolated; uv run and
  # uv tool do not. uv --config-file is flagged as a configuration the lane
  # does not model.
  SAFE_INSTALL_TEST_SCRIPT='pip install --no-deps okpkg==1.0.0' run_zsh
  assert_log_contains $'AUDIT\tpackage-audit\tokpkg@1.0.0\t--ecosystem\tpython\t--gate\tinstall\t--op\tinstall\t--python-isolated' "$FUNCNAME" || return
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='uv pip install okpkg==1.0.0' run_zsh
  assert_log_contains $'AUDIT\tpackage-audit\tokpkg@1.0.0\t--ecosystem\tpython\t--gate\tinstall\t--op\tinstall\t--python-isolated' "$FUNCNAME" || return
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='uv --config-file other.toml pip install okpkg==1.0.0' run_zsh
  assert_log_contains $'AUDIT\tpackage-audit\tokpkg@1.0.0\t--ecosystem\tpython\t--gate\tinstall\t--op\tinstall\t--python-isolated\t--uv-config-file-selected' "$FUNCNAME" || return
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='uv run --with okpkg==1.0.0 tool' run_zsh
  assert_log_contains $'AUDIT\tpackage-audit\tokpkg@1.0.0\t--ecosystem\tpython\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='uv tool install okpkg==1.0.0' run_zsh
  assert_log_contains $'AUDIT\tpackage-audit\tokpkg@1.0.0\t--ecosystem\tpython\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tpackage-audit\t@demo/pkg@1.2.3\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall\t--registry\t@demo:registry=https://scoped.example' "$FUNCNAME" || return

  # The prev-form scoped flag consumes its value: without that, the URL is
  # parsed as an extra PACKAGE and audited (delta-7 finding 3.2b).
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='npm install --@foo:registry https://foo.example @foo/pkg@1.2.3' run_zsh
  assert_log_contains $'AUDIT\tpackage-audit\t@foo/pkg@1.2.3\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall\t--registry\t@foo:registry=https://foo.example' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'check\thttps://foo.example' "$FUNCNAME" || return

  # Alternate config files thread as PATHS — value extraction lost key and
  # precedence semantics and copied credentials into argv (delta-7 findings
  # 3.2b/N2).
  : > "${LOG_FILE}"
  printf 'registry=https://userconf.example/\n@demo:registry=https://scopedconf.example\n' > "${WORK_DIR}/alt-npmrc"
  SAFE_INSTALL_TEST_SCRIPT='npm install --userconfig alt-npmrc okpkg@1.0.0' run_zsh
  assert_log_contains $'AUDIT\tpackage-audit\tokpkg@1.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall\t--npm-userconfig\talt-npmrc' "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tpackage-audit\tokpkg@1.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall\t--registry\thttps://alice:sekret@mirror.example' "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tpackage-audit\tokpkg@1.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall\t--registry\thttps://alice:sekret@mirror.example' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_npm_repeated_registry_keeps_true_last() {
  prepare_case "npm-repeated-registry-last"
  # npm is last-wins: A B A means npm installs from A. Deduplication must
  # move the repeat to the END so the resolver's last-word read matches
  # npm's choice (delta-4 finding 3.1).
  SAFE_INSTALL_TEST_SCRIPT='npm install -g --registry https://a.example --registry https://b.example --registry https://a.example okpkg@1.0.0' run_zsh
  assert_log_contains $'AUDIT\tpackage-audit\tokpkg@1.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall\t--registry\thttps://b.example https://a.example' "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tmise' "$FUNCNAME" || return

  SAFE_INSTALL_TEST_SCRIPT='mise use npm:okpkg@1.2.3' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tokpkg@1.2.3\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
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

case_mise_release_backends_share_one_notice() {
  prepare_case "mise-release-backends-one-notice"
  # Release-binary backends (mise verifies the asset itself) pass without an
  # audit and are summarized in ONE line, not one notice per tool.
  SAFE_INSTALL_TEST_SCRIPT='mise install aqua:sigstore/cosign@3.1.3 github:anchore/grype@0.120.0 http:ntn@0.23.16' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_err_contains_fragment 'safe: mise: 3 release binaries not advisory-audited (mise checksum/signature checks only): sigstore/cosign@3.1.3, anchore/grype@0.120.0, ntn@0.23.16' "$FUNCNAME" || return
  assert_count 1 'safe: mise: 3 release binaries not advisory-audited (mise checksum/signature checks only): sigstore/cosign@3.1.3, anchore/grype@0.120.0, ntn@0.23.16' "${ERR_FILE}" "$FUNCNAME" || return
  assert_err_not_contains_fragment 'no registry advisory source' "$FUNCNAME" || return
  assert_log_contains $'REAL\tmise\tinstall\taqua:sigstore/cosign@3.1.3\tgithub:anchore/grype@0.120.0\thttp:ntn@0.23.16' "$FUNCNAME" || return

  # A plugin backend keeps its per-tool notice next to the summary.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='mise install aqua:minio/mc@1.0.0 vfox:owner/plugin@1.0.0' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_err_contains_fragment 'safe: mise: 1 release binary not advisory-audited (mise checksum/signature checks only): minio/mc@1.0.0' "$FUNCNAME" || return
  assert_err_contains_fragment "'vfox' backend has no registry advisory source" "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_mise_bare_install_preflights_config() {
  prepare_case "mise-bare-install-preflight"
  # One backend tool not installed yet -> audited; blockme blocks the run.
  MISE_LS_JSON='{"node": [{"version": "22.0.0", "requested_version": "22.0.0", "installed": true}], "npm:blockme": [{"version": "1.0.0", "requested_version": "1.0.0", "installed": false}]}' \
    SAFE_INSTALL_TEST_SCRIPT='mise install' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tblockme@1.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return

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
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tpackage-audit\tokpkg\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tpackage-audit\tprettier@3\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tpackage-audit\tcowsay@22\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return

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
  assert_log_contains $'AUDIT\tpackage-audit\tokpkg@1.2.3\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return

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
  assert_log_contains $'AUDIT\tpackage-audit\tblockme@3\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return

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
  assert_log_contains $'AUDIT\tpackage-audit\tokpkg@1.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return

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
  assert_log_contains $'AUDIT\tpackage-audit\tokpkg@1.0.0\t--ecosystem\trust\t--gate\tinstall\t--op\tinstall\t--installer\tcargo' "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tpackage-audit\tblockme@1.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return

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
  assert_log_contains $'AUDIT\tpackage-audit\tblockme@1.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return

  # A configured allow_low_downloads approval is source-neutral too (it
  # lifts only the installer's reputation threshold): the audit still runs.
  : > "${LOG_FILE}"
  MISE_LS_JSON='{"npm:blockme": [{"version": "1.0.0", "requested_version": "1.0.0", "installed": false}]}' \
    MISE_TOOL_JSON='{"tool_options": {"allow_low_downloads": true}}' \
    SAFE_INSTALL_TEST_SCRIPT='mise install' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tblockme@1.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_mise_use_tool_option_modeled() {
  prepare_case "mise-use-tool-option"
  # `mise use --tool-option` is how mise itself prescribes approving a
  # package past its installer's own checks (allow_low_downloads past
  # aube's reputation threshold): the gate must parse it, not refuse it as
  # an unrecognized flag. The option changes no source, so the audit runs.
  SAFE_INSTALL_TEST_SCRIPT='mise use --tool-option allow_low_downloads=true npm:okpkg@1.2.3' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tokpkg@1.2.3\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_contains $'REAL\tmise\tuse\t--tool-option\tallow_low_downloads=true\tnpm:okpkg@1.2.3' "$FUNCNAME" || return

  # The equals form reaches the same audit; a blocked package still blocks.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='mise use --tool-option=allow_low_downloads=true npm:blockme@1.0.0' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tmise' "$FUNCNAME" || return

  # The bracket form of the same key keeps the audit too.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='mise use "npm:blockme[allow_low_downloads=true]@1.0.0"' run_zsh
  assert_status 104 "$FUNCNAME" || return

  # A source-changing CLI option takes the same notice path as its bracket
  # and configured forms: no verdict vouches for the redirected install.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='mise use --tool-option url=https://evil.example/x.tgz npm:okpkg@1.2.3' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_err_contains_fragment 'not audit-gated' "$FUNCNAME" || return
  assert_log_contains $'REAL\tmise\tuse\t--tool-option\turl=https://evil.example/x.tgz\tnpm:okpkg@1.2.3' "$FUNCNAME" || return

  # --postinstall runs a command safe cannot model: same notice path.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='mise use --postinstall "echo hi" npm:okpkg@1.2.3' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME" || return
  assert_err_contains_fragment 'not audit-gated' "$FUNCNAME" || return

  # Options bind to the tool that follows them: the second target is still
  # audited even though the first took the notice path.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='mise use --tool-option url=https://evil.example/x.tgz npm:okpkg@1.2.3 npm:blockme@1.0.0' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tblockme@1.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tmise' "$FUNCNAME" || return

  # A trailing option attributes to no tool: fail closed.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='mise use npm:okpkg@1.2.3 --tool-option allow_low_downloads=true' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'REAL' "$FUNCNAME" || return

  # A malformed option (no key=value) fails closed.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='mise use --tool-option justakey npm:okpkg@1.2.3' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'REAL' "$FUNCNAME" || return

  # CLI and bracket forms of one neutral key collide only inside mise
  # (duplicate keys are its parse error, after the gate): both classify
  # neutral here, so the audit still runs first and blocks.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='mise use --tool-option allow_low_downloads=true "npm:blockme[allow_low_downloads=false]@1.0.0"' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tmise' "$FUNCNAME" || return

  # install has no --tool-option in mise: still refused as unrecognized.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='mise install --tool-option allow_low_downloads=true npm:okpkg@1.2.3' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'REAL' "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tpackage-audit\tokpkg@1.0.0\t--ecosystem\tpython\t--gate\tinstall\t--op\tinstall\t--registry\thttps://private.example/pypi//simple\t--installer\tpipx' "$FUNCNAME" || return

  # A mise cargo registry NAME rides the same argv selector; the audit maps
  # it to its env-defined index or an opaque cargo-registry:<name> identity.
  : > "${LOG_FILE}"
  MISE_ENV_JSON='{"MISE_CARGO_REGISTRY_NAME": "private"}' \
    SAFE_INSTALL_TEST_SCRIPT='mise install cargo:okpkg@1.0.0' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tokpkg@1.0.0\t--ecosystem\trust\t--gate\tinstall\t--op\tinstall\t--registry\tprivate\t--installer\tcargo' "$FUNCNAME" || return

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
  assert_log_contains $'AUDIT\tpackage-audit\tblockme@1.0.0\t--ecosystem\trust\t--gate\tinstall\t--op\tinstall\t--installer\tcargo' "$FUNCNAME" || return

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
  assert_log_contains $'AUDIT\tpackage-audit\t@scope/blockme@1\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return

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
  assert_log_contains $'AUDIT\tpackage-audit\tblockme@2\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return

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

case_mise_c_physical_cd() {
  prepare_case "mise-c-physical-cd"
  # The -C directory is entered with PHYSICAL path semantics, matching mise's
  # own chdir (Rust set_current_dir -> chdir(2), verified physical against real
  # mise 2026.8.7): when -C reaches through a symlinked `..`, both the audit
  # lane (safe_gate_mise_check_with_env) and the inner-exec scan lane must land
  # on the real physical directory, not the lexical `..` collapse a bare `cd`
  # would produce — else safe audits/scans a different directory than the one
  # mise installs into. Expected is computed with the same physical resolution
  # so a symlinked temp prefix cannot skew the assertion. (Fibery #209; same
  # defect class as the composer #94/#95 fixes.)
  local phys_real="${CASE_DIR}/phys-realproj"
  local phys_wrong="${CASE_DIR}/phys-wrongdir"
  mkdir -p "${phys_real}/sub" "${phys_wrong}"
  ln -s "${phys_real}/sub" "${phys_wrong}/lnk"
  local phys_real_canon
  phys_real_canon="$(cd -P -- "${phys_real}" && pwd)"

  # Audit lane: `mise -C <symlinked-..> install npm:okpkg` audits the package
  # from the -C directory. Under a bare `cd` the audit runs in phys_wrong (the
  # lexical collapse); under `cd -P` it runs in phys_real.
  SAFE_AUDIT_EXPECT_PROJECT=1 \
    SAFE_INSTALL_TEST_SCRIPT="mise -C ${phys_wrong}/lnk/.. install npm:okpkg@1.0.0" run_zsh
  assert_status 0 "$FUNCNAME (audit lane)" || return
  assert_log_contains $'AUDITPROJECT\t'"${phys_real_canon}" "$FUNCNAME (audit lane)" || return
  assert_log_not_contains_fragment $'AUDITPROJECT\t'"${phys_wrong}" "$FUNCNAME (audit lane)" || return

  # Inner-exec scan lane: `mise -C <symlinked-..> exec -- npm install okpkg`
  # scans from the same -C directory under NO_EXEC. Same physical/lexical
  # discriminator on the twin `cd -P` site.
  : > "${LOG_FILE}"
  SAFE_AUDIT_EXPECT_PROJECT=1 \
    SAFE_INSTALL_TEST_SCRIPT="mise -C ${phys_wrong}/lnk/.. exec -- npm install okpkg@1.0.0" run_zsh
  assert_status 0 "$FUNCNAME (scan lane)" || return
  assert_log_contains $'AUDITPROJECT\t'"${phys_real_canon}" "$FUNCNAME (scan lane)" || return
  assert_log_not_contains_fragment $'AUDITPROJECT\t'"${phys_wrong}" "$FUNCNAME (scan lane)" || return

  # A RELATIVE -C value must resolve against the process cwd exactly as mise's
  # chdir(2) does, which never consults CDPATH. Bash's `cd` DOES search an
  # exported CDPATH, so a bare `cd -P -- project` could enter a same-named
  # directory elsewhere (and echo it to stdout) while mise installs in
  # ./project — the `cd -P` symlink fix above does not close this. `CDPATH=`
  # on both cd sites neutralizes it. Discriminator: a decoy `project-rel`
  # under CDPATH; the run must audit/scan the cwd-local one. (Fibery #209 F1,
  # DEEP round-1.) Expected computed with the same physical resolution.
  local rel_local="${WORK_DIR}/project-rel"
  local cdpath_dir="${CASE_DIR}/cdpath-decoy"
  mkdir -p "${rel_local}" "${cdpath_dir}/project-rel"
  local rel_local_canon
  rel_local_canon="$(cd -P -- "${rel_local}" && pwd)"

  : > "${LOG_FILE}"
  SAFE_AUDIT_EXPECT_PROJECT=1 \
    SAFE_INSTALL_TEST_SCRIPT="export CDPATH=${cdpath_dir}; mise -C project-rel install npm:okpkg@1.0.0" run_zsh
  assert_status 0 "$FUNCNAME (audit lane CDPATH)" || return
  assert_log_contains $'AUDITPROJECT\t'"${rel_local_canon}" "$FUNCNAME (audit lane CDPATH)" || return
  assert_log_not_contains_fragment $'AUDITPROJECT\t'"${cdpath_dir}" "$FUNCNAME (audit lane CDPATH)" || return

  : > "${LOG_FILE}"
  SAFE_AUDIT_EXPECT_PROJECT=1 \
    SAFE_INSTALL_TEST_SCRIPT="export CDPATH=${cdpath_dir}; mise -C project-rel exec -- npm install okpkg@1.0.0" run_zsh
  assert_status 0 "$FUNCNAME (scan lane CDPATH)" || return
  assert_log_contains $'AUDITPROJECT\t'"${rel_local_canon}" "$FUNCNAME (scan lane CDPATH)" || return
  assert_log_not_contains_fragment $'AUDITPROJECT\t'"${cdpath_dir}" "$FUNCNAME (scan lane CDPATH)" || return
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
  assert_log_contains $'AUDIT\tpackage-audit\tokpkg@1.0.0\t--ecosystem\trust\t--gate\tinstall\t--op\tinstall\t--installer\tcargo' "$FUNCNAME" || return
  assert_log_contains $'AUDITENV\tCARGO_REGISTRY_DEFAULT=private' "$FUNCNAME" || return

  # The inner exec route audits Composer and bun-backed npm now: their
  # sources are modeled (COMPOSER_HOME/config.json is read by the
  # derivation; bun via --installer bun).
  : > "${LOG_FILE}"
  MISE_ENV_JSON='{"COMPOSER_HOME": "/tmp/composer-home"}' \
    SAFE_INSTALL_TEST_SCRIPT='mise exec -- composer require vendor/blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tvendor/blockme\t--ecosystem\tcomposer\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_contains $'AUDITENV\tCOMPOSER_HOME=/tmp/composer-home' "$FUNCNAME" || return

  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='export BUN_CONFIG_REGISTRY=https://private.example; mise exec -- bun add blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall\t--installer\tbun' "$FUNCNAME" || return
  assert_log_contains $'AUDITENV\tBUN_CONFIG_REGISTRY=https://private.example' "$FUNCNAME" || return

  # ...and npm does not read bun's variable: same audit, no bun installer —
  # applying selectors by ecosystem removed the gate from artifacts safe
  # can model (delta-4 finding F4).
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='export BUN_CONFIG_REGISTRY=https://private.example; mise exec -- npm install blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return

  # An exported but EMPTY selector chooses nothing: it must not suppress
  # the audit either.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='export BUN_CONFIG_REGISTRY=; mise exec -- bun add blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return

  # Without any selector the inner route audits normally.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='mise exec -- npm install blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return

  : > "${LOG_FILE}"
  MISE_LS_JSON='{"npm:blockme": [{"version": "1.0.0", "requested_version": "1.0.0", "installed": true}]}' \
    SAFE_INSTALL_TEST_SCRIPT='mise upgrade --bump npm:blockme' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return

  # A VERSIONED argv target under --bump is a backend filter, not the
  # audited target: mise still moves it to the latest release (delta-5 F3).
  : > "${LOG_FILE}"
  MISE_LS_JSON='{"npm:blockme": [{"version": "1.0.0", "requested_version": "1.0.0", "installed": true}]}' \
    SAFE_INSTALL_TEST_SCRIPT='mise upgrade --bump npm:blockme@0.5.0' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
  assert_log_not_contains_fragment 'blockme@0.5.0' "$FUNCNAME" || return

  # install --force reinstalls the CONFIGURED version, so it keeps its
  # request rather than resolving latest.
  : > "${LOG_FILE}"
  MISE_LS_JSON='{"npm:blockme": [{"version": "1.0.0", "requested_version": "1.0.0", "installed": true}]}' \
    SAFE_INSTALL_TEST_SCRIPT='mise install --force' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tblockme@1.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
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
  assert_log_contains $'AUDIT\tpackage-audit\tprettier@3\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return

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
  assert_log_contains $'AUDIT\tpackage-audit\tblockme@1\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return

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
  assert_log_contains $'AUDIT\tpackage-audit\tokpkg@1.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall\t--installer\tbun' "$FUNCNAME" || return
  assert_log_contains $'AUDITENV\tBUN_CONFIG_REGISTRY=https://private.example' "$FUNCNAME" || return

  # The default installer reads no bun variable, so the audit proceeds.
  : > "${LOG_FILE}"
  MISE_NPM_PM=auto \
    SAFE_INSTALL_TEST_SCRIPT='export BUN_CONFIG_REGISTRY=https://private.example; mise install npm:blockme@1.0.0' run_zsh
  assert_status 104 "$FUNCNAME" || return
  assert_log_contains $'AUDIT\tpackage-audit\tblockme@1.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return

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
  assert_log_contains $'AUDIT\tpackage-audit\tblockme@1.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return

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
  assert_log_contains $'AUDIT\tpackage-audit\toktwo@2.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return

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
  assert_log_contains $'AUDIT\tpackage-audit\toktwo@2.0.0\t--ecosystem\tnpm\t--gate\tinstall\t--op\tinstall' "$FUNCNAME" || return
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

# Fetch-and-execute runners (npx/bunx/uvx) are links to safe-run owned by
# install.sh. A bare `bunx` used to resolve through the mise shim to the raw
# bun binary: ungated. These cases pin ownership, adoption, no-clobber,
# the mise second line, doctor/status reporting and uninstall.
runner_sandbox() {
  # $1 = dir. HOME with a mise shims dir, plus a place for a stand-in "real" mise.
  mkdir -p "$1/home/.local/share/mise/shims" "$1/real"
}

case_install_links_runners_ahead_of_mise_shims() {
  local dir="${TEST_ROOT}/${FUNCNAME}" home shims bin runner
  home="${dir}/home"; shims="${home}/.local/share/mise/shims"; bin="${home}/.local/bin"
  runner_sandbox "${dir}"
  printf '#!/usr/bin/env bash\necho real-mise\n' > "${dir}/real/mise"
  chmod +x "${dir}/real/mise"
  for runner in npx bunx uvx npm node; do ln -s "${dir}/real/mise" "${shims}/${runner}"; done

  HOME="${home}" SAFE_ZSHRC="${dir}/zshrc" bash "${ROOT_DIR}/install.sh" --wrappers \
    >"${dir}/out" 2>"${dir}/err" || { fail "$FUNCNAME: install failed"; return; }

  # Every runner resolves to a gate FIRST on PATH, shims dir present.
  local path="${bin}:${shims}:/usr/bin:/bin" resolved canon
  for runner in npx bunx uvx; do
    resolved="$(PATH="${path}" command -v "${runner}")"
    canon="$(readlink -f "${resolved}")"
    [[ "${resolved}" == "${bin}/${runner}" && "${canon}" == "$(readlink -f "${bin}/safe-run")" ]] \
      || { fail "$FUNCNAME: ${runner} resolved to ${resolved} (${canon})"; return; }
  done
  # pnpx is a gate wrapper; `bun x` enters through the bun wrapper.
  for runner in pnpx bun; do
    resolved="$(PATH="${path}" command -v "${runner}")"
    head -n 2 "${resolved}" | grep -Fqx "# safe-gate-wrapper v1 tool=${runner}" \
      || { fail "$FUNCNAME: ${runner} is not a gate wrapper (${resolved})"; return; }
  done
  # The shims themselves (the bypass layout) are bound to the mise wrapper.
  for runner in npx bunx uvx; do
    [[ "${shims}/${runner}" -ef "${bin}/mise" ]] || { fail "$FUNCNAME: shim ${runner} not bound to the wrapper"; return; }
  done
  [[ "$(cat "${home}/.config/safe/runner-links")" == $'npx\nbunx\nuvx' ]] || { fail "$FUNCNAME: manifest"; return; }
  pass "$FUNCNAME"
}

case_mise_wrapper_routes_runner_argv0_to_safe_run() {
  local dir="${TEST_ROOT}/${FUNCNAME}" home bin shims runner out rc=0
  home="${dir}/home"; bin="${home}/.local/bin"; shims="${home}/.local/share/mise/shims"
  runner_sandbox "${dir}"
  HOME="${home}" SAFE_ZSHRC="${dir}/zshrc" bash "${ROOT_DIR}/install.sh" --wrappers >/dev/null 2>&1
  # Swap safe-run for a recorder: what matters is that the shim reaches it
  # naming the runner, not the raw binary the real mise would pick.
  unlink "${bin}/safe-run"
  cat > "${bin}/safe-run" <<'STUB'
#!/usr/bin/env bash
printf 'SAFERUN argv0=%s args=%s\n' "${SAFE_RUN_RUNNER_ARGV0:-${0##*/}}" "$*"
STUB
  chmod +x "${bin}/safe-run"
  printf '#!/usr/bin/env bash\necho RAW-MISE-OR-BINARY\n' > "${dir}/real/mise"
  chmod +x "${dir}/real/mise"
  for runner in npx bunx uvx; do
    ln -sfn "${bin}/mise" "${shims}/${runner}"
    out="$(PATH="${shims}:${dir}/real:/usr/bin:/bin" "${shims}/${runner}" pkg@1.0.0 --flag 2>&1)"
    [[ "${out}" == "SAFERUN argv0=${runner} args=pkg@1.0.0 --flag" ]] \
      || { fail "$FUNCNAME: ${runner} -> ${out}"; return; }
  done
  # The real safe-run must take the runner path from that out-of-band name
  # (exec -a cannot rename a script): `status` is a package here, not the
  # subcommand.
  out="$(HOME="${dir}/runhome" SAFE_RUN_RUNNER_ARGV0=bunx bash "${ROOT_DIR}/bin/safe-run" status </dev/null 2>&1)" || true
  [[ "${out}" == *'BLOCKED: status@latest'* ]] || { fail "$FUNCNAME: real safe-run ignored the runner name: ${out}"; return; }
  # Fail closed: no safe-run reachable -> refusal 100, never the raw binary.
  unlink "${bin}/safe-run"
  out="$(PATH="/usr/bin:/bin" "${shims}/bunx" pkg 2>&1)" || rc=$?
  [[ "${rc}" -eq 100 && "${out}" == *'BLOCKED bunx'* ]] || { fail "$FUNCNAME: no safe-run -> rc=${rc} ${out}"; return; }
  pass "$FUNCNAME"
}

case_install_runner_links_adopt_keep_and_never_clobber() {
  local dir="${TEST_ROOT}/${FUNCNAME}" home bin
  home="${dir}/home"; bin="${home}/.local/bin"
  mkdir -p "${bin}"
  # Hand-made interim link (bunx), foreign regular file (npx), uv-installed uvx.
  ln -s "${bin}/safe-run" "${bin}/bunx"
  printf '#!/usr/bin/env bash\n# foreign npx\n' > "${bin}/npx"; chmod +x "${bin}/npx"
  printf '#!/usr/bin/env bash\n# real uvx\n' > "${bin}/uvx"; chmod +x "${bin}/uvx"

  HOME="${home}" SAFE_ZSHRC="${dir}/zshrc" bash "${ROOT_DIR}/install.sh" --wrappers \
    >"${dir}/out" 2>"${dir}/err" || { fail "$FUNCNAME: install failed"; return; }

  [[ "$(readlink "${bin}/bunx")" == "${bin}/safe-run" ]] || { fail "$FUNCNAME: bunx not kept"; return; }
  grep -Fqx '# foreign npx' "${bin}/npx" && [[ ! -L "${bin}/npx" ]] || { fail "$FUNCNAME: foreign npx overwritten"; return; }
  grep -Fq 'runner gating NOT active from' "${dir}/err" && grep -Fq ': npx' "${dir}/err" || { fail "$FUNCNAME: no foreign warning"; return; }
  [[ -L "${bin}/uvx" && "$(readlink -f "${bin}/uvx")" == "$(readlink -f "${bin}/safe-run")" ]] || { fail "$FUNCNAME: uvx not linked"; return; }
  grep -Fqx '# real uvx' "${bin}/uvx.original" || { fail "$FUNCNAME: uvx not displaced"; return; }
  [[ "$(jq -r '.runners.uvx_real' "${home}/.config/safe/run/config.json")" == "${bin}/uvx.original" ]] \
    || { fail "$FUNCNAME: uvx_real not recorded"; return; }
  [[ "$(cat "${home}/.config/safe/runner-links")" == $'bunx\nuvx' ]] || { fail "$FUNCNAME: manifest"; return; }

  # Reinstall: links kept, nothing re-displaced or clobbered.
  HOME="${home}" SAFE_ZSHRC="${dir}/zshrc" bash "${ROOT_DIR}/install.sh" --wrappers \
    >"${dir}/out2" 2>"${dir}/err2" || { fail "$FUNCNAME: reinstall failed"; return; }
  grep -Fqx '# real uvx' "${bin}/uvx.original" && [[ "$(readlink "${bin}/bunx")" == "${bin}/safe-run" ]] \
    || { fail "$FUNCNAME: reinstall changed links"; return; }
  grep -Fq 'already point to safe-run (kept): bunx uvx' "${dir}/err2" || { fail "$FUNCNAME: reinstall report"; return; }
  pass "$FUNCNAME"
}

case_doctor_and_status_report_runner_resolution() {
  local dir="${TEST_ROOT}/${FUNCNAME}" home bin shims out runner
  home="${dir}/home"; bin="${home}/.local/bin"; shims="${home}/.local/share/mise/shims"
  runner_sandbox "${dir}"
  printf '#!/usr/bin/env bash\necho real-mise\n' > "${dir}/real/mise"; chmod +x "${dir}/real/mise"
  HOME="${home}" SAFE_ZSHRC="${dir}/zshrc" bash "${ROOT_DIR}/install.sh" --wrappers >/dev/null 2>&1
  for runner in npx bunx uvx; do ln -sfn "${bin}/mise" "${shims}/${runner}"; done

  out="$(PATH="${bin}:${shims}:/usr/bin:/bin" HOME="${home}" "${bin}/safe" doctor --json 2>&1)"
  jq -e '.environment.install_wrappers.runner_links_healthy == true
         and .environment.install_wrappers.runner_links.bunx.state == "gated"' <<<"${out}" >/dev/null \
    || { fail "$FUNCNAME: healthy layout: ${out}"; return; }
  out="$(PATH="${bin}:${shims}:/usr/bin:/bin" HOME="${home}" "${bin}/safe" status 2>&1)"
  grep -Fq 'runners:        ok (3/3' <<<"${out}" || { fail "$FUNCNAME: status ok line: ${out}"; return; }

  # Shims ahead and no link: via the wrapper it is still gated (second line);
  # a shim pointed at the raw mise/binary must be flagged.
  unlink "${bin}/bunx"
  out="$(PATH="${shims}:/usr/bin:/bin" HOME="${home}" "${bin}/safe" doctor --json 2>&1)"
  jq -e '.environment.install_wrappers.runner_links.bunx.state == "gated-via-mise"
         and .environment.install_wrappers.runner_links_healthy == true' <<<"${out}" >/dev/null \
    || { fail "$FUNCNAME: via-mise: ${out}"; return; }
  ln -sfn "${dir}/real/mise" "${shims}/bunx"
  out="$(PATH="${shims}:/usr/bin:/bin" HOME="${home}" "${bin}/safe" doctor --json 2>&1)"
  jq -e '.environment.install_wrappers.runner_links.bunx.state == "ungated"
         and .environment.install_wrappers.runner_links_healthy == false' <<<"${out}" >/dev/null \
    || { fail "$FUNCNAME: ungated: ${out}"; return; }
  out="$(PATH="${shims}:/usr/bin:/bin" HOME="${home}" "${bin}/safe" doctor 2>&1)"
  grep -Fq 'bunx: UNGATED' <<<"${out}" || { fail "$FUNCNAME: human doctor: ${out}"; return; }
  out="$(PATH="${shims}:/usr/bin:/bin" HOME="${home}" "${bin}/safe" status 2>&1)"
  grep -Fq 'runners:        DEGRADED' <<<"${out}" || { fail "$FUNCNAME: status degraded"; return; }
  pass "$FUNCNAME"
}

case_uninstall_removes_only_runner_links_safe_made() {
  local dir="${TEST_ROOT}/${FUNCNAME}" home bin
  home="${dir}/home"; bin="${home}/.local/bin"
  mkdir -p "${bin}"
  printf '#!/usr/bin/env bash\n# foreign npx\n' > "${bin}/npx"; chmod +x "${bin}/npx"
  printf '#!/usr/bin/env bash\n# real uvx\n' > "${bin}/uvx"; chmod +x "${bin}/uvx"
  HOME="${home}" SAFE_ZSHRC="${dir}/zshrc" bash "${ROOT_DIR}/install.sh" --wrappers >/dev/null 2>&1
  # A link the operator made AFTER install (not in the manifest) must survive.
  ln -s /bin/true "${bin}/extra-link"
  HOME="${home}" SAFE_ZSHRC="${dir}/zshrc" bash "${ROOT_DIR}/uninstall.sh" >/dev/null 2>"${dir}/uerr" \
    || { fail "$FUNCNAME: uninstall failed"; return; }
  [[ ! -e "${bin}/bunx" && ! -L "${bin}/bunx" ]] || { fail "$FUNCNAME: bunx link left"; return; }
  grep -Fqx '# foreign npx' "${bin}/npx" || { fail "$FUNCNAME: foreign npx touched"; return; }
  grep -Fqx '# real uvx' "${bin}/uvx" && [[ ! -L "${bin}/uvx" ]] || { fail "$FUNCNAME: uvx not restored"; return; }
  [[ -L "${bin}/extra-link" ]] || { fail "$FUNCNAME: unrelated link removed"; return; }
  [[ ! -e "${home}/.config/safe/runner-links" ]] || { fail "$FUNCNAME: manifest left"; return; }
  pass "$FUNCNAME"
}

case_mise_wrapper_gates_a_gated_argv0() {
  # The hole closed in 1.56.0 (2026-08-31): a mise shim whose name is itself a
  # GATED tool forwarded to the real installer with zero audit, so on any PATH
  # carrying the shims dir `npm install` and `yarn install` ran unaudited while
  # the same command through $BIN_DIR audited. That argv[0] must enter the gate
  # under its own tool name. Driven against the INSTALLER's wrapper, not the
  # suite's copy of it.
  local dir="${TEST_ROOT}/${FUNCNAME}"
  mkdir -p "${dir}/home" "${dir}/stub" "${dir}/real"
  HOME="${dir}/home" SAFE_ZSHRC="${dir}/zshrc" bash "${ROOT_DIR}/install.sh" --wrappers >/dev/null 2>&1
  local wrapper="${dir}/home/.local/bin/mise"
  [[ -x "${wrapper}" ]] || { fail "$FUNCNAME"; return; }

  cat > "${dir}/stub/safe" <<STUB
#!/usr/bin/env bash
printf 'SAFEARGV\t%s\n' "\$*" >> "${dir}/argv.log"
STUB
  chmod +x "${dir}/stub/safe"
  # A real mise the forward-to-mise branch would reach: if the gated name took
  # that branch instead, REALMISE lands on stdout and the log stays empty.
  cat > "${dir}/real/mise" <<'STUB'
#!/usr/bin/env bash
printf 'REALMISE args=%s\n' "$*"
STUB
  chmod +x "${dir}/real/mise"
  ln -s "${wrapper}" "${dir}/stub/npm"
  : > "${dir}/argv.log"

  # Run from a scratch directory, never the caller's. The PATH below ends in
  # /usr/bin so the wrapper can find head/grep, which means a setup that
  # silently failed could reach the REAL npm — and a real `npm install` writes
  # package.json and node_modules into the CWD (it did once, into the repo
  # root). The assertions catch the fall-through; the cd keeps a fall-through
  # from touching anything that matters.
  local out
  out=$(cd "${dir}" && PATH="${dir}/stub:${dir}/real:/usr/bin:/bin" \
    "${dir}/stub/npm" install cowsay@1.5.0 2>&1)
  if [[ -n "$out" ]]; then
    printf 'gated argv0 did not enter the gate: %s\n' "$out" >&2
    fail "$FUNCNAME"
    return
  fi
  if ! grep -Fqx "$(printf 'SAFEARGV\tgate npm -- install cowsay@1.5.0')" "${dir}/argv.log"; then
    printf 'argv log: %s\n' "$(cat "${dir}/argv.log")" >&2
    fail "$FUNCNAME"
    return
  fi
  pass "$FUNCNAME"
}

case_mise_shims_ahead_of_the_gate_still_audit() {
  # The reported production shape: `mise activate` in a non-interactive shell
  # and agent harness PATHs put the shims dir AHEAD of $BIN_DIR, so a bare
  # `npm install` resolves to the shim rather than to the npm wrapper. It must
  # still reach `safe gate npm`.
  local dir="${TEST_ROOT}/${FUNCNAME}"
  mkdir -p "${dir}/home" "${dir}/shims" "${dir}/stub" "${dir}/real"
  HOME="${dir}/home" SAFE_ZSHRC="${dir}/zshrc" bash "${ROOT_DIR}/install.sh" --wrappers >/dev/null 2>&1
  # Without the wrapper the shim below is a dangling symlink, PATH resolution
  # walks past it, and the command reaches the real npm instead of proving
  # anything. Fail on the setup rather than on a confusing assertion.
  [[ -x "${dir}/home/.local/bin/mise" ]] || { fail "$FUNCNAME"; return; }
  ln -s "${dir}/home/.local/bin/mise" "${dir}/shims/npm"

  cat > "${dir}/stub/safe" <<STUB
#!/usr/bin/env bash
printf 'SAFEARGV\t%s\n' "\$*" >> "${dir}/argv.log"
STUB
  chmod +x "${dir}/stub/safe"
  cat > "${dir}/real/mise" <<'STUB'
#!/usr/bin/env bash
printf 'REALMISE args=%s\n' "$*"
STUB
  chmod +x "${dir}/real/mise"
  : > "${dir}/argv.log"

  # Scratch CWD for the same reason as the case above: a fall-through past the
  # shim reaches the real npm, and a real install writes into the CWD.
  local out
  out=$(cd "${dir}" && PATH="${dir}/stub:${dir}/shims:${dir}/home/.local/bin:${dir}/real:/usr/bin:/bin" \
    bash -c 'npm install cowsay@1.5.0' 2>&1)
  if [[ -n "$out" ]]; then
    printf 'shims-first npm did not enter the gate: %s\n' "$out" >&2
    fail "$FUNCNAME"
    return
  fi
  if ! grep -Fqx "$(printf 'SAFEARGV\tgate npm -- install cowsay@1.5.0')" "${dir}/argv.log"; then
    printf 'argv log: %s\n' "$(cat "${dir}/argv.log")" >&2
    fail "$FUNCNAME"
    return
  fi
  pass "$FUNCNAME"
}

case_install_normalizes_mise_shims() {
  # Coverage depends on the shims pointing at the wrapper: a shims dir bound to
  # the real mise never runs it, and the gated-argv0 dispatch above never fires.
  local dir="${TEST_ROOT}/${FUNCNAME}"
  local home="${dir}/home" shims="${dir}/home/.local/share/mise/shims"
  mkdir -p "${shims}" "${dir}/real"
  printf '#!/usr/bin/env bash\necho real-mise\n' > "${dir}/real/mise"
  chmod +x "${dir}/real/mise"
  ln -s "${dir}/real/mise" "${shims}/npm"
  ln -s "${dir}/real/mise" "${shims}/node"
  printf '#!/usr/bin/env bash\n# somebody else\n' > "${shims}/keepme"
  chmod +x "${shims}/keepme"

  HOME="${home}" SAFE_ZSHRC="${dir}/zshrc" bash "${ROOT_DIR}/install.sh" --wrappers \
    >"${dir}/out" 2>"${dir}/err"
  local install_status=$?
  if [[ "${install_status}" -ne 0 ]]; then
    printf 'install exited %s\n' "${install_status}" >&2
    fail "$FUNCNAME"
    return
  fi
  local wrapper="${home}/.local/bin/mise"
  [[ "${shims}/npm" -ef "${wrapper}" ]] || { fail "$FUNCNAME"; return; }
  [[ "${shims}/node" -ef "${wrapper}" ]] || { fail "$FUNCNAME"; return; }
  # A regular file in that directory is not something mise generated: it is
  # never rewritten, and the count says so.
  [[ ! -L "${shims}/keepme" ]] || { fail "$FUNCNAME"; return; }
  grep -Fqx '# somebody else' "${shims}/keepme" || { fail "$FUNCNAME"; return; }
  grep -Fq '2 re-pointed at the gate wrapper' "${dir}/err" || { fail "$FUNCNAME"; return; }
  grep -Fq '1 non-symlink left alone' "${dir}/err" || { fail "$FUNCNAME"; return; }

  # Second install: the shims are already bound, so nothing is rewritten.
  HOME="${home}" SAFE_ZSHRC="${dir}/zshrc" bash "${ROOT_DIR}/install.sh" --wrappers \
    >"${dir}/out2" 2>"${dir}/err2"
  grep -Fq '0 re-pointed at the gate wrapper, 2 already bound' "${dir}/err2" || { fail "$FUNCNAME"; return; }

  # A $BIN_DIR/mise that is NOT our wrapper is never a re-point target:
  # binding 36 shims to a foreign file is the 2026-08-02 breakage itself.
  local foreign="${dir}/foreign"
  local foreign_shims="${foreign}/.local/share/mise/shims"
  mkdir -p "${foreign}/.local/bin" "${foreign_shims}"
  printf '#!/usr/bin/env bash\n# not ours\n' > "${foreign}/.local/bin/mise"
  chmod +x "${foreign}/.local/bin/mise"
  ln -s "${dir}/real/mise" "${foreign_shims}/npm"
  HOME="${foreign}" SAFE_ZSHRC="${dir}/zshrc2" bash "${ROOT_DIR}/install.sh" --wrappers \
    >"${dir}/out3" 2>"${dir}/err3"
  [[ "${foreign_shims}/npm" -ef "${dir}/real/mise" ]] || { fail "$FUNCNAME"; return; }
  grep -Fq 'is not a safe gate wrapper' "${dir}/err3" || { fail "$FUNCNAME"; return; }
  pass "$FUNCNAME"
}

case_uninstall_restores_mise_shims() {
  # The twin of case_install_normalizes_mise_shims: install binds the shims to
  # our wrapper, so removing the gate must put them back. Otherwise uninstall
  # leaves EVERY mise-managed tool — node and java included, not just the gated
  # ones — a dangling symlink until someone runs `mise reshim`.
  local dir="${TEST_ROOT}/${FUNCNAME}"
  local home="${dir}/home" shims="${dir}/home/.local/share/mise/shims"
  mkdir -p "${shims}" "${dir}/real"
  printf '#!/usr/bin/env bash\necho real-mise\n' > "${dir}/real/mise"
  chmod +x "${dir}/real/mise"
  ln -s "${dir}/real/mise" "${shims}/npm"
  ln -s "${dir}/real/mise" "${shims}/node"
  printf '#!/usr/bin/env bash\n# somebody else\n' > "${shims}/keepme"
  chmod +x "${shims}/keepme"

  HOME="${home}" SAFE_ZSHRC="${dir}/zshrc" bash "${ROOT_DIR}/install.sh" --wrappers >/dev/null 2>&1
  [[ "${shims}/npm" -ef "${home}/.local/bin/mise" ]] || { fail "$FUNCNAME"; return; }

  PATH="${dir}/real:${PATH}" HOME="${home}" SAFE_ZSHRC="${dir}/zshrc" \
    bash "${ROOT_DIR}/uninstall.sh" >"${dir}/out" 2>"${dir}/err"
  local uninstall_status=$?
  if [[ "${uninstall_status}" -ne 0 ]]; then
    printf 'uninstall exited %s\n' "${uninstall_status}" >&2
    fail "$FUNCNAME"
    return
  fi
  [[ ! -e "${home}/.local/bin/mise" ]] || { fail "$FUNCNAME"; return; }
  # Every shim runs the real mise again, and none of them dangles.
  [[ "${shims}/npm" -ef "${dir}/real/mise" ]] || { fail "$FUNCNAME"; return; }
  [[ "${shims}/node" -ef "${dir}/real/mise" ]] || { fail "$FUNCNAME"; return; }
  [[ ! -L "${shims}/keepme" ]] || { fail "$FUNCNAME"; return; }
  grep -Fqx '# somebody else' "${shims}/keepme" || { fail "$FUNCNAME"; return; }
  grep -Fq '2 re-pointed at' "${dir}/err" || { fail "$FUNCNAME"; return; }
  grep -Fq '1 non-symlink left alone' "${dir}/err" || { fail "$FUNCNAME"; return; }

  # No non-wrapper mise anywhere: the shims are LEFT alone with a legible
  # reshim hint. Deleting them would be worse — a dangling shim is one command
  # from repaired, a deleted one is gone with no signal it existed.
  local bare="${dir}/bare" bare_shims="${dir}/bare/.local/share/mise/shims"
  local sysbin="${dir}/sysbin" cmd cmd_path
  mkdir -p "${bare_shims}" "${sysbin}"
  for cmd in bash sed grep find ln mv rm mktemp cat; do
    cmd_path="$(command -v "${cmd}")" || { fail "$FUNCNAME"; return; }
    ln -sf "${cmd_path}" "${sysbin}/${cmd}"
  done
  HOME="${bare}" SAFE_ZSHRC="${dir}/zshrc2" bash "${ROOT_DIR}/install.sh" --wrappers >/dev/null 2>&1
  ln -sfn "${bare}/.local/bin/mise" "${bare_shims}/npm"
  PATH="${sysbin}" HOME="${bare}" SAFE_ZSHRC="${dir}/zshrc2" \
    bash "${ROOT_DIR}/uninstall.sh" >"${dir}/out2" 2>"${dir}/err2"
  [[ -L "${bare_shims}/npm" ]] || { fail "$FUNCNAME"; return; }
  grep -Fq "run 'mise reshim' to rebuild them" "${dir}/err2" || {
    printf 'stderr: %s\n' "$(cat "${dir}/err2")" >&2
    fail "$FUNCNAME"
    return
  }
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

# Fragment match (assert_log_contains wants the whole line): for audit lines
# whose tail carries gate flags that are not the point of the case.
CASE_SEQ=0
assert_log_has() {
  local needle="$1"
  local label="$2"
  if ! grep -Fq -- "${needle}" "${LOG_FILE}"; then
    printf 'missing log fragment: %s\n' "${needle}" >&2
    printf 'log:\n%s\n' "$(cat "${LOG_FILE}")" >&2
    fail "${label}"
    return 1
  fi
  return 0
}

# --- gate verb parsing sweep (inbox 2026-10-14..2026-11-02) ------------------

# `mise exec -- <tool> <verb>` must classify the inner command exactly as the
# direct gate does. The audit-only exec used to RETURN instead of ending the
# scan, so a pass-through verb (`pnpm run`, `pack`) fell into the install lane
# and its script name or destination was audited as a package.
case_mise_exec_inner_non_install_verbs_pass_through() {
  local script
  for script in \
    'pnpm run check:docs' 'pnpm run check' 'pnpm run build:test' \
    'npm run build' 'yarn run build' 'bun run dev' \
    'pnpm pack --pack-destination /tmp/safe-pack-out' 'npm pack'; do
    prepare_case "mise-inner-passthrough-$((++CASE_SEQ))"
    touch "${WORK_DIR}/package.json"
    SAFE_INSTALL_TEST_SCRIPT="mise exec node@26.10.0 -- ${script}" run_zsh
    assert_status 0 "$FUNCNAME ${script}" || return
    assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME ${script}" || return
    assert_log_has "REAL"$'\t'"mise"$'\t'"exec"$'\t'"node@26.10.0"$'\t'"--"$'\t'"$(tr ' ' '\t' <<<"${script}")" "$FUNCNAME ${script}" || return
    # The direct gate agrees on every one of them.
    : > "${LOG_FILE}"
    SAFE_INSTALL_TEST_SCRIPT="${script}" run_zsh
    assert_status 0 "$FUNCNAME direct ${script}" || return
    assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME direct ${script}" || return
  done
  # The verb position is exact: the same words as package names still audit.
  for script in 'pnpm add blockme run' 'pnpm add blockme pack' 'npm install blockme pack' 'bun add blockme run'; do
    prepare_case "mise-inner-verb-position-$((++CASE_SEQ))"
    SAFE_INSTALL_TEST_SCRIPT="mise exec -- ${script}" run_zsh
    assert_status 104 "$FUNCNAME ${script}" || return
    assert_log_has $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tnpm' "$FUNCNAME ${script}" || return
    assert_log_not_contains_fragment $'REAL\tmise' "$FUNCNAME ${script}" || return
  done
  # An install verb through mise still takes the project scan.
  prepare_case "mise-inner-install-scans-$((++CASE_SEQ))"
  touch "${WORK_DIR}/package.json"
  SAFE_AUDIT_SCAN_STATUS=0 SAFE_AUDIT_SCAN_VERDICT=WARN SAFE_AUDIT_SCAN_CRITICAL=1 \
    SAFE_INSTALL_TEST_SCRIPT='mise exec -- pnpm install' run_zsh
  assert_status 102 "$FUNCNAME install" || return
  assert_log_not_contains_fragment $'REAL\tmise' "$FUNCNAME install" || return
  pass "$FUNCNAME"
}

# `bun -e <code>` / `-p <code>` take a separate value like their `=` forms.
case_bun_eval_print_separate_value() {
  local script
  for script in "bun -e 'console.log(1)'" "bun --eval 'console.log(1)'" "bun -p '1+1'" "bun --print '1+1'" \
    "bun --eval='console.log(1)'"; do
    prepare_case "bun-eval-separate-$((++CASE_SEQ))"
    SAFE_INSTALL_TEST_SCRIPT="${script}" run_zsh
    assert_status 0 "$FUNCNAME ${script}" || return
    assert_log_has $'REAL\tbun' "$FUNCNAME ${script}" || return
    assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME ${script}" || return
  done
  # The value is consumed, not the subcommand after it.
  for script in "bun --print 1 add blockme" "bun -e 'x' install blockme"; do
    prepare_case "bun-eval-then-install-$((++CASE_SEQ))"
    SAFE_INSTALL_TEST_SCRIPT="${script}" run_zsh
    assert_status 104 "$FUNCNAME ${script}" || return
    assert_log_has $'AUDIT\tpackage-audit\tblockme' "$FUNCNAME ${script}" || return
  done
  prepare_case "bun-eval-others-still-fail-closed-$((++CASE_SEQ))"
  SAFE_INSTALL_TEST_SCRIPT='bun --frobnicate add blockme' run_zsh
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tbun' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# `pkg@catalog:` / `pkg@catalog:<name>` resolve against the workspace catalog.
case_catalog_specifiers_resolve_against_workspace() {
  prepare_case "catalog-pnpm-$((++CASE_SEQ))"
  mkdir -p "${WORK_DIR}/packages/app"
  cat > "${WORK_DIR}/pnpm-workspace.yaml" <<'YAML'
packages:
  - 'packages/*'
catalog:
  okpkg: ^1.2.0   # trailing comment
  '@scope/lib': "2.0.1"
  blockme: 9.9.9
catalogs:
  ui:
    okpkg: ~3.1.0
YAML
  printf '{"name":"app"}\n' > "${WORK_DIR}/packages/app/package.json"
  printf '{"name":"root"}\n' > "${WORK_DIR}/package.json"
  SAFE_INSTALL_TEST_SCRIPT='cd packages/app && pnpm add okpkg@catalog: @scope/lib@catalog:' run_zsh
  assert_status 0 "$FUNCNAME pnpm default" || return
  assert_log_has $'AUDIT\tpackage-audit\tokpkg@^1.2.0\t' "$FUNCNAME" || return
  assert_log_has $'AUDIT\tpackage-audit\t@scope/lib@2.0.1\t' "$FUNCNAME" || return
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='cd packages/app && pnpm add okpkg@catalog:ui' run_zsh
  assert_status 0 "$FUNCNAME pnpm named" || return
  assert_log_has $'AUDIT\tpackage-audit\tokpkg@~3.1.0\t' "$FUNCNAME" || return
  assert_log_has $'REAL\tpnpm\tadd\tokpkg@catalog:ui' "$FUNCNAME" || return
  # The resolved version is what the verdict covers: a blocked catalog entry blocks.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='pnpm add blockme@catalog:' run_zsh
  assert_status 104 "$FUNCNAME pnpm blocked" || return
  assert_log_has $'AUDIT\tpackage-audit\tblockme@9.9.9\t' "$FUNCNAME" || return
  # No entry: the specifier stays as typed (today's honest refusal path).
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='pnpm add okpkg@catalog:nope missing@catalog:' run_zsh
  assert_log_has $'AUDIT\tpackage-audit\tokpkg@catalog@nope\t' "$FUNCNAME unresolved" || return
  assert_log_has $'AUDIT\tpackage-audit\tmissing@catalog\t' "$FUNCNAME unresolved" || return

  prepare_case "catalog-bun-$((++CASE_SEQ))"
  cat > "${WORK_DIR}/package.json" <<'JSON'
{"name":"root","workspaces":{"packages":["packages/*"],"catalog":{"okpkg":"^4.0.0"},"catalogs":{"native":{"@opentui/core":"0.1.5"}}}}
JSON
  SAFE_INSTALL_TEST_SCRIPT='bun install "--os=*" "--cpu=*" @opentui/core@catalog:native okpkg@catalog:' run_zsh
  assert_status 0 "$FUNCNAME bun" || return
  assert_log_has $'AUDIT\tpackage-audit\t@opentui/core@0.1.5\t' "$FUNCNAME bun" || return
  assert_log_has $'AUDIT\tpackage-audit\tokpkg@^4.0.0\t' "$FUNCNAME bun" || return
  # Top-level `catalog` of the root manifest, and a missing named catalog.
  printf '{"name":"root","workspaces":["packages/*"],"catalog":{"okpkg":"5.0.0"}}\n' > "${WORK_DIR}/package.json"
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='bun add okpkg@catalog: okpkg@catalog:absent' run_zsh
  assert_log_has $'AUDIT\tpackage-audit\tokpkg@5.0.0\t' "$FUNCNAME bun top-level" || return
  assert_log_has $'AUDIT\tpackage-audit\tokpkg@catalog@absent\t' "$FUNCNAME bun absent" || return
  # A non-registry value (git URL) is not read as a version.
  printf '{"name":"root","workspaces":["packages/*"],"catalog":{"okpkg":"github:foo/bar"}}\n' > "${WORK_DIR}/package.json"
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='bun add okpkg@catalog:' run_zsh
  assert_log_has $'AUDIT\tpackage-audit\tokpkg@catalog\t' "$FUNCNAME bun git value" || return
  # bun reads the workspace root's catalog and ignores a member's own: from
  # a member the root's entry is audited, and a member manifest that carries a
  # different entry (a decoy the gate would otherwise audit instead of what
  # bun installs) leaves the specifier unresolved.
  prepare_case "catalog-bun-member-$((++CASE_SEQ))"
  mkdir -p "${WORK_DIR}/packages/app" "${WORK_DIR}/packages/decoy"
  printf '{"name":"root","workspaces":{"packages":["packages/*"],"catalog":{"okpkg":"7.0.0"}}}\n' > "${WORK_DIR}/package.json"
  printf '{"name":"app"}\n' > "${WORK_DIR}/packages/app/package.json"
  printf '{"name":"decoy","catalog":{"okpkg":"6.0.0"}}\n' > "${WORK_DIR}/packages/decoy/package.json"
  SAFE_INSTALL_TEST_SCRIPT='cd packages/app && bun add okpkg@catalog:' run_zsh
  assert_log_has $'AUDIT\tpackage-audit\tokpkg@7.0.0\t' "$FUNCNAME bun member" || return
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='cd packages/decoy && bun add okpkg@catalog:' run_zsh
  assert_log_has $'AUDIT\tpackage-audit\tokpkg@catalog\t' "$FUNCNAME bun member decoy" || return
  assert_log_not_contains_fragment 'okpkg@6.0.0' "$FUNCNAME bun member decoy" || return
  assert_log_not_contains_fragment 'okpkg@7.0.0' "$FUNCNAME bun member decoy" || return
  # One manifest naming the entry at the top level AND under `workspaces`
  # with different values: which one bun takes is not the gate's to guess.
  printf '{"name":"root","catalog":{"okpkg":"6.0.0"},"workspaces":{"packages":["packages/*"],"catalog":{"okpkg":"7.0.0"}}}\n' > "${WORK_DIR}/package.json"
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='cd packages/app && bun add okpkg@catalog:' run_zsh
  assert_log_has $'AUDIT\tpackage-audit\tokpkg@catalog\t' "$FUNCNAME bun both locations" || return
  assert_log_not_contains_fragment 'okpkg@6.0.0' "$FUNCNAME bun both locations" || return
  # A root manifest bun can read and jq cannot (a comment) is an unknown
  # answer, not an absent root: the member's own catalog is not promoted.
  printf '{\n  // comment\n  "name":"root","workspaces":{"packages":["packages/*"],"catalog":{"okpkg":"7.0.0"}}}\n' > "${WORK_DIR}/package.json"
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='cd packages/decoy && bun add okpkg@catalog:' run_zsh
  assert_log_has $'AUDIT\tpackage-audit\tokpkg@catalog\t' "$FUNCNAME bun jsonc root" || return
  assert_log_not_contains_fragment 'okpkg@6.0.0' "$FUNCNAME bun jsonc root" || return
  # No manifest declares workspaces: bun refuses catalogs there, nothing resolves.
  printf '{"name":"root","catalog":{"okpkg":"5.0.0"}}\n' > "${WORK_DIR}/package.json"
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='bun add okpkg@catalog:' run_zsh
  assert_log_not_contains_fragment 'okpkg@5.0.0' "$FUNCNAME bun no workspaces" || return
  printf '{"name":"root","workspaces":{"packages":["packages/*"],"catalog":{"okpkg":"7.0.0"}}}\n' > "${WORK_DIR}/package.json"
  # A global install has no workspace: the specifier is never resolved.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='bun add -g okpkg@catalog:' run_zsh
  assert_log_not_contains_fragment 'okpkg@7.0.0' "$FUNCNAME bun global" || return
  : > "${LOG_FILE}"
  printf "catalog:\n  okpkg: 1.0.0\n" > "${WORK_DIR}/pnpm-workspace.yaml"
  SAFE_INSTALL_TEST_SCRIPT='pnpm add -g okpkg@catalog:' run_zsh
  assert_log_not_contains_fragment 'okpkg@1.0.0' "$FUNCNAME pnpm global" || return
  # npm has no catalogs: its specs are never rewritten.
  prepare_case "catalog-npm-untouched-$((++CASE_SEQ))"
  printf '{"name":"root","catalog":{"okpkg":"5.0.0"}}\n' > "${WORK_DIR}/package.json"
  SAFE_INSTALL_TEST_SCRIPT='npm install okpkg@catalog:' run_zsh
  assert_log_not_contains_fragment 'okpkg@5.0.0' "$FUNCNAME npm" || return
  pass "$FUNCNAME"
}

# uv's plural spellings and the format-control flags' values.
case_uv_plural_spellings_and_format_control() {
  local script
  prepare_case "uv-requirements-plural-$((++CASE_SEQ))"
  mkdir -p "${WORK_DIR}/deps"
  printf 'okpkg==1.0.0\n' > "${WORK_DIR}/deps/prod.txt"
  printf 'okpkg==1.0.0\n' > "${CASE_DIR}/outside.txt"
  for script in 'uv pip install --requirements deps/prod.txt' 'uv pip install --requirements=deps/prod.txt' \
    "uv pip install --requirements ${CASE_DIR}/outside.txt" 'uv pip install --requirements deps/prod.txt --constraints deps/prod.txt --overrides deps/prod.txt'; do
    : > "${LOG_FILE}"
    SAFE_INSTALL_TEST_SCRIPT="${script}" run_zsh
    assert_status 0 "$FUNCNAME ${script}" || return
    assert_project_scan_logged "$FUNCNAME ${script}" || return
    grep -Fq -- $'--pip-requirement\t' "${LOG_FILE}" || { fail "$FUNCNAME ${script}: no requirement reached the scan"; return; }
    assert_log_not_contains_fragment $'LOCAL_ARTIFACT' "$FUNCNAME ${script}" || return
  done
  # A remote requirement file is refused in the plural spelling too.
  : > "${LOG_FILE}"
  SAFE_INSTALL_TEST_SCRIPT='uv pip install --requirements https://example.invalid/req.txt' run_zsh
  assert_status 100 "$FUNCNAME remote" || return
  assert_log_not_contains_fragment $'REAL\tuv' "$FUNCNAME remote" || return
  # --only-binary / --no-binary take a value on pip and `uv pip install`:
  # `:all:` is not a package, the real package after it is audited.
  for script in 'uv pip install --only-binary :all: blockme' 'uv pip install --no-binary :none: blockme' \
    'pip install --only-binary :all: blockme' 'pip install --no-binary=:all: blockme'; do
    prepare_case "uv-format-control-$((++CASE_SEQ))"
    SAFE_INSTALL_TEST_SCRIPT="${script}" run_zsh
    assert_status 104 "$FUNCNAME ${script}" || return
    assert_log_has $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tpython' "$FUNCNAME ${script}" || return
    assert_log_not_contains_fragment $'package-audit\t:all:' "$FUNCNAME ${script}" || return
    assert_log_not_contains_fragment $'package-audit\t:none:' "$FUNCNAME ${script}" || return
  done
  prepare_case "uv-format-control-clean-$((++CASE_SEQ))"
  SAFE_INSTALL_TEST_SCRIPT="uv pip install --only-binary :all: okpkg --constraints ${CASE_DIR}/outside.txt" run_zsh
  assert_status 0 "$FUNCNAME clean" || return
  assert_log_has $'AUDIT\tpackage-audit\tokpkg\t--ecosystem\tpython' "$FUNCNAME clean" || return
  # On `uv tool install` --no-binary is a switch: it must not eat the package.
  prepare_case "uv-tool-install-no-binary-switch-$((++CASE_SEQ))"
  SAFE_INSTALL_TEST_SCRIPT='uv tool install --no-binary blockme' run_zsh
  assert_status 104 "$FUNCNAME tool" || return
  assert_log_has $'AUDIT\tpackage-audit\tblockme\t--ecosystem\tpython' "$FUNCNAME tool" || return
  # uv run / tool run: --no-binary is a switch there too.
  prepare_case "uv-run-no-binary-switch-$((++CASE_SEQ))"
  SAFE_INSTALL_TEST_SCRIPT='uv run --no-binary --with blockme python -c 1' run_zsh
  assert_status 104 "$FUNCNAME run" || return
  SAFE_INSTALL_TEST_SCRIPT='uv tool run --no-binary --from blockme prog' run_zsh
  assert_status 104 "$FUNCNAME tool run" || return
  pass "$FUNCNAME"
}

# pnpm verbs that run something must not install on their own.
case_pnpm_run_verbs_cannot_auto_install() {
  local script
  for script in 'pnpm exec vitest' 'pnpm run test' 'pnpm test' 'pnpm start' 'pnpm build' 'pnpm exec -- vitest run'; do
    prepare_case "pnpm-verify-deps-forced-$((++CASE_SEQ))"
    touch "${WORK_DIR}/package.json"
    SAFE_INSTALL_TEST_SCRIPT="${script}" run_zsh
    assert_status 0 "$FUNCNAME ${script}" || return
    assert_log_has "REAL"$'\t'"$(tr ' ' '\t' <<<"${script}")" "$FUNCNAME ${script}" || return
    assert_log_has $'VERIFYDEPS\twarn' "$FUNCNAME ${script}" || return
    assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME ${script}" || return
  done
  # Through mise exec the child that mise starts carries it too.
  prepare_case "pnpm-verify-deps-mise-$((++CASE_SEQ))"
  touch "${WORK_DIR}/package.json"
  SAFE_INSTALL_TEST_SCRIPT='mise exec node@26.10.0 -- pnpm exec vitest' run_zsh
  assert_status 0 "$FUNCNAME mise" || return
  assert_log_has $'REAL\tmise\texec' "$FUNCNAME mise" || return
  assert_log_has $'VERIFYDEPS\twarn' "$FUNCNAME mise" || return
  # A non-installing value the user set stands (command line outranks env).
  prepare_case "pnpm-verify-deps-user-cli-$((++CASE_SEQ))"
  SAFE_INSTALL_TEST_SCRIPT='pnpm --config.verify-deps-before-run=error exec vitest' run_zsh
  assert_status 0 "$FUNCNAME cli" || return
  assert_log_has $'REAL\tpnpm\t--config.verify-deps-before-run=error\texec\tvitest' "$FUNCNAME cli" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME cli" || return
  # The same spelling after the binary or script name belongs to the child,
  # not to pnpm: the environment is forced all the same.
  for script in 'pnpm exec vitest --config.verify-deps-before-run=false' 'pnpm run test --verify-deps-before-run=error'; do
    prepare_case "pnpm-verify-deps-child-arg-$((++CASE_SEQ))"
    touch "${WORK_DIR}/package.json"
    SAFE_INSTALL_TEST_SCRIPT="${script}" run_zsh
    assert_status 0 "$FUNCNAME ${script}" || return
    assert_log_has $'VERIFYDEPS\twarn' "$FUNCNAME ${script}" || return
  done
  prepare_case "pnpm-verify-deps-child-arg-env-install-$((++CASE_SEQ))"
  touch "${WORK_DIR}/package.json"
  pnpm_config_verify_deps_before_run=install SAFE_INSTALL_TEST_SCRIPT='pnpm exec vitest --config.verify-deps-before-run=false' run_zsh
  assert_status 0 "$FUNCNAME child arg over env install" || return
  assert_log_has $'VERIFYDEPS\twarn' "$FUNCNAME child arg over env install" || return
  prepare_case "pnpm-verify-deps-user-env-$((++CASE_SEQ))"
  pnpm_config_verify_deps_before_run=false SAFE_INSTALL_TEST_SCRIPT='pnpm exec vitest' run_zsh
  assert_status 0 "$FUNCNAME env" || return
  assert_log_has $'VERIFYDEPS\tfalse' "$FUNCNAME env" || return
  assert_log_not_contains_fragment 'AUDIT' "$FUNCNAME env" || return
  # An explicit installing value is an install: the project gate, as for
  # `pnpm install` — never a silent pass, never the verb's argument as a package.
  for script in 'pnpm exec --config.verify-deps-before-run=install vitest' \
    'pnpm --config.verifyDepsBeforeRun=prompt run test' 'pnpm exec --config.verify-deps-before-run vitest'; do
    prepare_case "pnpm-verify-deps-install-$((++CASE_SEQ))"
    touch "${WORK_DIR}/package.json"
    SAFE_AUDIT_SCAN_STATUS=0 SAFE_AUDIT_SCAN_VERDICT=WARN SAFE_AUDIT_SCAN_CRITICAL=1 \
      SAFE_INSTALL_TEST_SCRIPT="${script}" run_zsh
    assert_status 102 "$FUNCNAME ${script}" || return
    assert_log_not_contains_fragment $'REAL\tpnpm' "$FUNCNAME ${script}" || return
    assert_log_not_contains_fragment 'package-audit' "$FUNCNAME ${script}" || return
  done
  prepare_case "pnpm-verify-deps-install-clean-$((++CASE_SEQ))"
  touch "${WORK_DIR}/package.json"
  SAFE_INSTALL_TEST_SCRIPT='pnpm exec --config.verify-deps-before-run=install vitest' run_zsh
  assert_status 0 "$FUNCNAME install clean" || return
  assert_project_scan_logged "$FUNCNAME install clean" || return
  assert_log_not_contains_fragment 'package-audit' "$FUNCNAME install clean" || return
  assert_log_has $'REAL\tpnpm\texec' "$FUNCNAME install clean" || return
  prepare_case "pnpm-verify-deps-install-env-$((++CASE_SEQ))"
  touch "${WORK_DIR}/package.json"
  pnpm_config_verify_deps_before_run=install SAFE_AUDIT_SCAN_STATUS=0 SAFE_AUDIT_SCAN_VERDICT=WARN SAFE_AUDIT_SCAN_CRITICAL=1 \
    SAFE_INSTALL_TEST_SCRIPT='pnpm exec vitest' run_zsh
  assert_status 102 "$FUNCNAME env install" || return
  assert_log_not_contains_fragment $'REAL\tpnpm' "$FUNCNAME env install" || return
  prepare_case "pnpm-verify-deps-install-mise-$((++CASE_SEQ))"
  touch "${WORK_DIR}/package.json"
  SAFE_AUDIT_SCAN_STATUS=0 SAFE_AUDIT_SCAN_VERDICT=WARN SAFE_AUDIT_SCAN_CRITICAL=1 \
    SAFE_INSTALL_TEST_SCRIPT='mise exec -- pnpm exec --config.verify-deps-before-run=install vitest' run_zsh
  assert_status 102 "$FUNCNAME mise install" || return
  assert_log_not_contains_fragment $'REAL\tmise' "$FUNCNAME mise install" || return
  # Install verbs are untouched: audited as before.
  prepare_case "pnpm-verify-deps-add-still-audited-$((++CASE_SEQ))"
  SAFE_INSTALL_TEST_SCRIPT='pnpm add blockme' run_zsh
  assert_status 104 "$FUNCNAME add" || return
  pass "$FUNCNAME"
}

# ---------------------------------------------------------------------------
# Project lane (install.project_lane): hermetic cases
# ---------------------------------------------------------------------------

# A sha512 integrity token that is a function of its seed.
lane_integrity() {
  printf 'sha512-%s' "$(printf '%s' "$1" | sha512sum | cut -d' ' -f1 | xxd -r -p | base64 -w0)"
}

# A lockfileVersion 3 document with canonical registry entries for the
# name@version arguments. A "name@version:flag" argument adds a lockfile flag
# (dev, optional, install) to the entry.
lane_lock() {
  local out='{"lockfileVersion":3,"requires":true,"packages":{"":{"name":"lane-test","version":"1.0.0"}}}'
  local arg spec flag name version
  for arg in "$@"; do
    spec="${arg%%:*}"
    flag=""
    [[ "${arg}" == *:* ]] && flag="${arg#*:}"
    name="${spec%@*}"
    version="${spec##*@}"
    out="$(jq -c --arg p "node_modules/${name}" --arg v "${version}" \
      --arg r "https://registry.npmjs.org/${name}/-/${name##*/}-${version}.tgz" \
      --arg i "$(lane_integrity "${name}@${version}")" --arg f "${flag}" '
      .packages[$p] = ({version: $v, resolved: $r, integrity: $i}
        + (if $f == "dev" then {dev: true} elif $f == "optional" then {optional: true}
           elif $f == "install" then {hasInstallScript: true} else {} end))' <<<"${out}")"
  done
  printf '%s\n' "${out}"
}

# A project with the lane on: a manifest, the baseline lockfile named by the
# arguments, both committed. WORK_DIR is a disposable git repository inside the
# suite's own temporary directory.
lane_prepare() {
  local name="$1"
  shift
  prepare_lockdiff_case "${name}"
  rmdir "${WORK_DIR}/node_modules"
  mkdir -p "${HOME_DIR}/.config/safe/run"
  printf '{"install":{"project_lane":true}}\n' > "${HOME_DIR}/.config/safe/run/config.json"
  LANE_MANIFEST='{"name":"lane-test","version":"1.0.0","dependencies":{"kept":"^1.0.0"}}'
  printf '%s\n' "${LANE_MANIFEST}" > "${WORK_DIR}/package.json"
  lane_lock "$@" > "${WORK_DIR}/package-lock.json"
  lane_commit
  [[ "${SAFE_CORE_TEST_AVAILABLE}" != "1" ]] || lane_core_wrapper
}

# safe-core as the gate finds it, tamperable: every subcommand reaches the real
# binary; SAFE_CORE_TAMPER=<what> rewrites what project-decide or project-bind
# printed or exited with, to show the gate refuses a result that is not whole.
lane_core_wrapper() {
  rm -f "${BIN_DIR}/safe-core"
  cat > "${BIN_DIR}/safe-core" <<'WRAP'
#!/usr/bin/env bash
real="${SAFE_CORE_REAL:?}"
sub="${1:-}"
tamper="${SAFE_CORE_TAMPER:-}"
if [[ "${sub}" == "project-bind" && -n "${SAFE_INSTALL_COMMAND_LOG:-}" ]]; then
  { printf 'CORE_BIND_ARGS'; for a in "$@"; do printf '\t%q' "${a}"; done; printf '\n'; } >> "${SAFE_INSTALL_COMMAND_LOG}"
fi
if [[ "${sub}" == "project-bind" && "${SAFE_CORE_SIGNAL_EARLY:-0}" == "1" ]]; then
  # A signal to the shell right after the binder is started, while it is still starting up:
  # the forwarded signal ends it before it has produced any document.
  kill -TERM "${PPID}"
  sleep 5
  exec "${real}" "$@"
fi
if [[ "${sub}" == "project-baseline" ]]; then
  case "${tamper}:${2:-}" in
  esac
  exec "${real}" "$@"
fi
case "${sub}" in project-decide|project-bind|project-graph|project-diff|project-admit) ;; *) exec "${real}" "$@" ;; esac
[[ -n "${tamper}" ]] || exec "${real}" "$@"
last="${*: -1}"
out="$("${real}" "$@")"
rc=$?
emit() { printf '%s\n' "${out}"; exit "${rc}"; }
case "${tamper}:${sub}" in
  decide-clear-with-gaps:project-decide)
    jq -c '.outcome = {status: "clear", class: "", exit: 0} | .classes |= map(.outstanding = 0) | .malice = []' <<<"${out}"; exit 0 ;;
  decide-two-documents:project-decide)   printf '%s\n%s\n' "${out}" "${out}"; exit "${rc}" ;;
  decide-clear-nonzero:project-decide)   printf '%s\n' "${out}"; exit 100 ;;
  decide-stopped-zero:project-decide)    printf '%s\n' "${out}"; exit 0 ;;
  decide-empty-classes:project-decide)
    jq -c '.classes = [] | .outcome = {status: "clear", class: "", exit: 0}' <<<"${out}"; exit 0 ;;
  bind-published-nonzero:project-bind)   printf '%s\n' "${out}"; exit 32 ;;
  bind-label-and-status:project-bind)    jq -c '.exit = 32' <<<"${out}"; exit 32 ;;
  bind-no-verification:project-bind)     jq -c '.verification = null' <<<"${out}"; exit "${rc}" ;;
  bind-not-committed:project-bind)       jq -c '.publication.state = "not_started"' <<<"${out}"; exit "${rc}" ;;
  bind-two-documents:project-bind)       printf '%s\n%s\n' "${out}" "${out}"; exit "${rc}" ;;
  # the committed graph (the snapshot's) and the projected one
  graph-two-documents:project-graph)     [[ "${last}" != */projection/* ]] || emit; printf '%s\n%s\n' "${out}" "${out}"; exit "${rc}" ;;
  graph-fails:project-graph)             [[ "${last}" != */projection/* ]] || emit; exit 3 ;;
  graph-wrong-schema:project-graph)      [[ "${last}" != */projection/* ]] || emit; jq -c '.schema_version = 9' <<<"${out}"; exit "${rc}" ;;
  target-graph-two-documents:project-graph) [[ "${last}" == */projection/* ]] || emit; printf '%s\n%s\n' "${out}" "${out}"; exit "${rc}" ;;
  target-graph-truncated:project-graph)  [[ "${last}" == */projection/* ]] || emit; printf '{"schema_version":1,'; exit 0 ;;
  diff-two-documents:project-diff)       printf '%s\n%s\n' "${out}" "${out}"; exit "${rc}" ;;
  diff-no-request:project-diff)          jq -c 'del(.evidence_request)' <<<"${out}"; exit "${rc}" ;;
  diff-bad-request:project-diff)         jq -c '.evidence_request = [{"name": 1}]' <<<"${out}"; exit "${rc}" ;;
  admit-ok-with-refusals:project-admit)  jq -c '.ok = true | .refusals = [{"where": "x", "text": "", "reason": "y"}]' <<<"${out}"; exit 0 ;;
  admit-two-documents:project-admit)     printf '%s\n%s\n' "${out}" "${out}"; exit "${rc}" ;;
  admit-fails:project-admit)             exit 2 ;;
  admit-bad-names:project-admit)         jq -c '.names = [1]' <<<"${out}"; exit "${rc}" ;;
  graph-bound-contradiction:project-graph) [[ "${last}" != */projection/* ]] || emit; jq -c '.bindability.bound = true | .bindability.unbound = [{"path":"x","name":"x","version":"1","origin":"","reason":"y"}]' <<<"${out}"; exit "${rc}" ;;
  bind-lose-result:project-bind)         for f in "${TMPDIR:-/tmp}"/safe-mise-lane.*/result; do rm -f "$f"; mkdir "$f"; done; printf '%s\n' "${out}"; exit "${rc}" ;;
  bind-retained:project-bind)            jq -c '.publication.retained = [{"name":"x","location":"staging","observed":"y"}]' <<<"${out}"; exit "${rc}" ;;
  bind-one-file:project-bind)            jq -c '.publication.published = ["package.json"]' <<<"${out}"; exit "${rc}" ;;
  bind-no-problems:project-bind)         jq -c 'del(.verification.problems)' <<<"${out}"; exit "${rc}" ;;
  bind-no-inputs-changed:project-bind)   jq -c 'del(.inputs_changed)' <<<"${out}"; exit "${rc}" ;;
esac
emit
WRAP
  chmod +x "${BIN_DIR}/safe-core"
}

lane_commit() {
  (
    cd "${WORK_DIR}" || exit 1
    export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
    [[ -d .git ]] || git init -q -b main
    git add -A
    git -c user.name=lane -c user.email=lane@example.invalid commit -q -m base --allow-empty
  ) >/dev/null 2>&1
}

lane_run() {
  SAFE_INSTALL_TEST_SCRIPT="$1" NPM_CI_MATERIALISE=1 run_zsh
}

lane_digests() {
  sha256sum "${WORK_DIR}/package.json" "${WORK_DIR}/package-lock.json" | cut -d' ' -f1 | tr '\n' ' '
}

# A refusal of the lane ends on exactly one stderr line of the contract's form.
assert_lane_final_line() {
  local verb="$1" label="$2" last
  last="$(tail -n 1 "${ERR_FILE}")"
  if [[ "${last}" != "safe: BLOCKED npm ${verb} [lane: project] — "*"; details: safe explain" ]]; then
    printf 'final stderr line is not the lane form: %s\n' "${last}" >&2
    printf 'stderr:\n%s\n' "$(cat "${ERR_FILE}")" >&2
    fail "${label}"
    return 1
  fi
  if [[ "$(grep -c '^safe: BLOCKED' "${ERR_FILE}")" -ne 1 ]]; then
    printf 'more than one BLOCKED line:\n%s\n' "$(cat "${ERR_FILE}")" >&2
    fail "${label}"
    return 1
  fi
  return 0
}

# The guards probe npm's configuration (REAL ... config list); nothing else of
# npm may have run: not the user's verb and not the frozen one.
assert_lane_no_delegate() {
  local label="$1"
  if grep -P '^REAL\tnpm\t(?!config\t)' "${LOG_FILE}" >/dev/null; then
    printf 'npm was delegated to:\n%s\n' "$(grep -P '^REAL\tnpm\t(?!config\t)' "${LOG_FILE}")" >&2
    fail "${label}"
    return 1
  fi
  return 0
}

assert_lane_no_leftover() {
  local label="$1"
  if compgen -G "${WORK_DIR}/.safe-bind-*" >/dev/null || compgen -G "${WORK_DIR}/*.safe-lane.*" >/dev/null; then
    fail "${label}: a staging directory or temporary file is left in the project"
    return 1
  fi
  return 0
}

# The project is as it was: files byte-identical, no tree, nothing left behind.
assert_lane_untouched() {
  local before="$1" label="$2"
  if [[ "$(lane_digests)" != "${before}" ]]; then
    fail "${label}: the manifest or the lockfile changed"
    return 1
  fi
  if [[ -e "${WORK_DIR}/node_modules" ]]; then
    fail "${label}: a tree was produced"
    return 1
  fi
  assert_lane_no_leftover "${label}" || return 1
  assert_lane_no_delegate "${label}" || return 1
  return 0
}

LANE_HIT_CRITICAL='[{"id":"GHSA-crit-0001","severity":"critical","malware":false}]'
LANE_HIT_HIGH='[{"id":"GHSA-high-0001","severity":"high","malware":false}]'
LANE_HIT_MEDIUM='[{"id":"GHSA-med-00001","severity":"moderate","malware":false}]'
LANE_CLEAN_ADD_MANIFEST='{"name":"lane-test","version":"1.0.0","dependencies":{"kept":"^1.0.0","clean":"^2.0.0"}}'

case_project_lane_switch_off_keeps_todays_gate() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-switch-off" kept@1.0.0
  mkdir -p "${WORK_DIR}/node_modules"
  install_lockdiff_package kept 1.0.0
  local value
  # Only a document that parses as ONE object with the boolean true switches it on.
  for value in '{"install":{"project_lane":false}}' '{"install":{"project_lane":"true"}}' '{"install":{}}' '[]' '{"install":{"project_lane":true}}{"install"' \
      '{"install":{"project_lane":true}}{}' '{"install":{"project_lane":true}} trailing' ''; do
    printf '%s\n' "${value}" > "${HOME_DIR}/.config/safe/run/config.json"
    : > "${LOG_FILE}"
    NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0)" SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
    assert_status 0 "$FUNCNAME: ${value}" || return
    assert_log_contains $'REAL\tnpm\tdedupe' "$FUNCNAME" || return
    assert_log_not_contains_fragment $'REAL\tnpm\tci' "$FUNCNAME" || return
    assert_log_not_contains_fragment 'EVIDENCE_INPUT' "$FUNCNAME" || return
  done
  rm -f "${HOME_DIR}/.config/safe/run/config.json"
  : > "${LOG_FILE}"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0)" SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'EVIDENCE_INPUT' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# With the switch off, the environment of an unrelated delegate is what the
# caller gave it: the lane's own variables are neither assigned nor exported at
# source time, and node's start-up options are untouched.
case_project_lane_switch_off_leaves_the_delegate_environment_alone() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-switch-off-env" kept@1.0.0
  printf '{"install":{"project_lane":false}}\n' > "${HOME_DIR}/.config/safe/run/config.json"
  mkdir -p "${WORK_DIR}/node_modules"
  install_lockdiff_package kept 1.0.0
  # dedupe reaches the probe hook; the caller's values reach the delegate untouched.
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0)" SAFE_GATE_LANE_SCRATCH=caller-value NODE_OPTIONS=--max-old-space-size=512 \
    SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tdedupe' "$FUNCNAME" || return
  assert_log_contains $'LANEVAR\tcaller-value' "$FUNCNAME" || return
  assert_log_contains $'NODEOPT\t--max-old-space-size=512' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_project_lane_update_that_fixes_a_critical_passes() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-update-fixes" kept@1.0.0 vuln@1.0.0
  local target
  target="$(lane_lock kept@1.0.0 vuln@1.0.1)"
  NPM_LOCK_MUTATION_JSON="${target}" \
    SAFE_AUDIT_EVIDENCE_HITS="{\"vuln@1.0.0\":${LANE_HIT_CRITICAL}}" \
    lane_run 'npm update'
  assert_status 0 "$FUNCNAME" || return
  assert_err_contains_fragment '1 fixed' "$FUNCNAME" || return
  assert_err_contains_fragment '0 introduced below high' "$FUNCNAME" || return
  assert_err_contains_fragment '0 packages added, 1 changed, 0 removed' "$FUNCNAME" || return
  grep -q $'^PROJECTION\tnpm\t--package-lock-only\t--ignore-scripts\t--no-audit\t--no-fund\t' "${LOG_FILE}" || { fail "$FUNCNAME: no projection"; return; }
  assert_log_contains $'EVIDENCE_INPUT\t["kept@1.0.0","vuln@1.0.0","vuln@1.0.1"]' "$FUNCNAME" || return
  # Every target name is checked against the blocklist, whatever the request holds.
  assert_log_contains $'EVIDENCE_NAMES\t["kept","vuln"]' "$FUNCNAME" || return
  # The delegated command is the frozen one, run in the binder's staging directory.
  assert_log_not_contains_fragment $'REAL\tnpm\tupdate' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm\tinstall' "$FUNCNAME" || return
  grep -qP '^REAL\tnpm\tci\t--ignore-scripts\t--no-audit\t--no-fund\t' "${LOG_FILE}" || { fail "$FUNCNAME: no frozen ci"; return; }
  grep -q $'^CICWD\t.safe-bind-' "${LOG_FILE}" || { fail "$FUNCNAME: ci did not run in staging"; return; }
  [[ "$(cat "${WORK_DIR}/package-lock.json")" == "${target}" ]] || { fail "$FUNCNAME: lockfile is not the judged one"; return; }
  assert_log_contains $'CILOCK\t'"$(printf '%s\n' "${target}" | sha256sum | cut -d' ' -f1)" "$FUNCNAME" || return
  jq -e '.version == "1.0.1"' "${WORK_DIR}/node_modules/vuln/package.json" >/dev/null || { fail "$FUNCNAME: tree"; return; }
  assert_lane_no_leftover "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_project_lane_clean_add_in_a_project_with_findings_passes() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-clean-add" kept@1.0.0 vuln@1.0.0:install
  local target
  target="$(lane_lock kept@1.0.0 vuln@1.0.0:install clean@2.0.0:install)"
  chmod 0644 "${WORK_DIR}/package.json" "${WORK_DIR}/package-lock.json"
  NPM_LOCK_MUTATION_JSON="${target}" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" \
    SAFE_AUDIT_EVIDENCE_HITS="{\"vuln@1.0.0\":${LANE_HIT_CRITICAL}}" \
    lane_run 'npm install clean@2.0.0'
  assert_status 0 "$FUNCNAME" || return
  assert_err_contains_fragment '1 already present (highest: critical)' "$FUNCNAME" || return
  assert_err_contains_fragment 'install scripts are declared by clean@2.0.0, vuln@1.0.0' "$FUNCNAME" || return
  assert_err_contains_fragment 'scripts do not run on this lane yet' "$FUNCNAME" || return
  grep -qP '^PROJECTION\tnpm\t--package-lock-only\t--ignore-scripts\t--no-audit\t--no-fund\t--git=/bin/false\t--allow-git=none\t--cache=\S+\t--logs-dir=\S+\t--logs-max=0\t--replace-registry-host=never\t--update-notifier=false\tinstall\tclean@2.0.0$' "${LOG_FILE}" || { fail "$FUNCNAME: the projection's command line"; return; }
  assert_log_not_contains_fragment $'REAL\tnpm\tinstall' "$FUNCNAME" || return
  [[ "$(cat "${WORK_DIR}/package.json")" == "${LANE_CLEAN_ADD_MANIFEST}" ]] || { fail "$FUNCNAME: manifest is not the judged one"; return; }
  [[ "$(cat "${WORK_DIR}/package-lock.json")" == "${target}" ]] || { fail "$FUNCNAME: lockfile is not the judged one"; return; }
  jq -e '.version == "2.0.0"' "${WORK_DIR}/node_modules/clean/package.json" >/dev/null || { fail "$FUNCNAME: tree"; return; }
  # The files keep their mode.
  [[ "$(stat -c %a "${WORK_DIR}/package.json")" == "644" && "$(stat -c %a "${WORK_DIR}/package-lock.json")" == "644" ]] || { fail "$FUNCNAME: file modes changed"; return; }
  assert_log_not_contains_fragment 'repo-audit' "$FUNCNAME" || return
  assert_log_not_contains_fragment 'package-audit' "$FUNCNAME" || return
  assert_lane_no_leftover "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_project_lane_introduced_critical_refuses_104_untouched() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-introduced-critical" kept@1.0.0
  local before
  before="$(lane_digests)"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 dirty@3.0.0)" \
    SAFE_AUDIT_EVIDENCE_HITS="{\"dirty@3.0.0\":${LANE_HIT_CRITICAL}}" \
    lane_run 'npm install dirty@3.0.0'
  assert_status 104 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  assert_err_contains_fragment 'dirty@3.0.0 carries GHSA-crit-0001 (critical)' "$FUNCNAME" || return
  assert_lane_untouched "${before}" "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_project_lane_introduced_high_refuses_100_untouched() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-introduced-high" kept@1.0.0
  local before
  before="$(lane_digests)"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 risky@3.0.0)" \
    SAFE_AUDIT_EVIDENCE_HITS="{\"risky@3.0.0\":${LANE_HIT_HIGH}}" \
    lane_run 'npm install risky@3.0.0'
  assert_status 100 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  assert_err_contains_fragment 'risky@3.0.0 carries GHSA-high-0001 (high)' "$FUNCNAME" || return
  assert_lane_untouched "${before}" "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_project_lane_below_high_introduction_informs_and_passes() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-below-high" kept@1.0.0
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 meh@1.0.0)" \
    SAFE_AUDIT_EVIDENCE_HITS="{\"meh@1.0.0\":${LANE_HIT_MEDIUM}}" \
    lane_run 'npm install meh@1.0.0'
  assert_status 0 "$FUNCNAME" || return
  assert_err_contains_fragment '1 introduced below high' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_project_lane_known_malware_on_an_untouched_package_blocks() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-malware-untouched" kept@1.0.0 old@1.0.0
  local before
  before="$(lane_digests)"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 old@1.0.0 clean@1.0.0)" \
    SAFE_AUDIT_EVIDENCE_HITS='{"old@1.0.0":[{"id":"MAL-2026-0001","severity":"critical","malware":true}]}' \
    lane_run 'npm install clean@1.0.0'
  assert_status 104 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  assert_err_contains_fragment 'known-malware record on old@1.0.0' "$FUNCNAME" || return
  assert_lane_untouched "${before}" "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_project_lane_blocklisted_untouched_package_blocks() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-blocklist-untouched" kept@1.0.0 old@1.0.0
  local before
  before="$(lane_digests)"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 old@1.0.0 clean@1.0.0)" \
    SAFE_AUDIT_EVIDENCE_BLOCKLIST='[{"name":"old","reason":"operator blocklist"}]' \
    lane_run 'npm install clean@1.0.0'
  assert_status 104 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  assert_err_contains_fragment 'blocklist entry on old@1.0.0' "$FUNCNAME" || return
  assert_lane_untouched "${before}" "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# The evidence reaches the decision as the reader wrote it: a partial, a
# duplicated-member or a missing document is a refusal, never a pass.
case_project_lane_helper_output_that_is_not_a_complete_document_refuses() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-helper-output" kept@1.0.0
  local before target raw
  before="$(lane_digests)"
  target="$(lane_lock kept@1.0.0 clean@1.0.0)"
  for raw in '{"schema_version":1}' \
      '{"schema_version":1,"policy":{"block_severities":["critical"]},"identities":[],"blocklist":[],"blocklist":[{"name":"clean","reason":"x"}]}' \
      'garbage' 'not json'; do
    : > "${LOG_FILE}"
    NPM_LOCK_MUTATION_JSON="${target}" SAFE_AUDIT_EVIDENCE_RAW="${raw}" lane_run 'npm install clean@1.0.0'
    assert_status 102 "$FUNCNAME: ${raw}" || return
    assert_lane_final_line install "$FUNCNAME" || return
    assert_lane_untouched "${before}" "$FUNCNAME" || return
  done
  pass "$FUNCNAME"
}

case_project_lane_missing_evidence_refuses_102() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-missing-evidence" kept@1.0.0
  local before
  before="$(lane_digests)"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@1.0.0)" \
    SAFE_AUDIT_EVIDENCE_MISSING='["clean@1.0.0"]' \
    lane_run 'npm install clean@1.0.0'
  assert_status 102 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  assert_err_contains_fragment 'advisory evidence is missing (clean@1.0.0' "$FUNCNAME" || return
  assert_lane_untouched "${before}" "$FUNCNAME" || return
  : > "${LOG_FILE}"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@1.0.0)" SAFE_AUDIT_EVIDENCE_STATUS=4 \
    lane_run 'npm install clean@1.0.0'
  assert_status 102 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  assert_err_contains_fragment 'audit-infrastructure breakage, not a package finding' "$FUNCNAME" || return
  assert_lane_untouched "${before}" "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_project_lane_unbound_entry_refuses_before_any_write() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-unbound" kept@1.0.0
  local before target
  before="$(lane_digests)"
  target="$(lane_lock kept@1.0.0 clean@1.0.0 | jq -c '.packages["node_modules/clean"].resolved = "https://evil.example/clean-1.0.0.tgz"')"
  NPM_LOCK_MUTATION_JSON="${target}" lane_run 'npm install clean@1.0.0'
  assert_status 102 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  assert_err_contains_fragment 'safe cannot bind (clean@1.0.0: kind_not_admitted)' "$FUNCNAME" || return
  assert_lane_untouched "${before}" "$FUNCNAME" || return
  # Malice outranks an unbound graph: that route would not judge the closure.
  : > "${LOG_FILE}"
  NPM_LOCK_MUTATION_JSON="${target}" \
    SAFE_AUDIT_EVIDENCE_HITS='{"kept@1.0.0":[{"id":"MAL-2026-0002","severity":"critical","malware":true}]}' \
    lane_run 'npm install clean@1.0.0'
  assert_status 104 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# A committed lockfile with an entry the lane cannot bind is refused before npm
# resolves anything.
case_project_lane_committed_lockfile_entries_are_admitted_before_npm_runs() {
  skip_lockdiff_case "$FUNCNAME" || return
  local label mutate
  for mutate in '.packages["node_modules/kept"].resolved = "https://evil.example/kept-1.0.0.tgz"' \
      '.packages["node_modules/kept"].resolved = "git+ssh://git@example.invalid/kept.git#abc"' \
      'del(.packages["node_modules/kept"].integrity)' \
      '.packages["node_modules/kept"] = {"resolved": "../kept", "link": true}'; do
    label="lane-admit-lock-${RANDOM}"
    lane_prepare "${label}" kept@1.0.0
    lane_lock kept@1.0.0 | jq -c "${mutate}" > "${WORK_DIR}/package-lock.json"
    lane_commit
    if [[ "${mutate}" == *'"link": true'* ]]; then
      # a link that leaves the project is UNSAFE: refused, committed or not
      lane_run 'npm install clean@1.0.0'
      lane_unsupported_case "$FUNCNAME: ${mutate}" install 'a committed link outside the project' || return
      continue
    fi
    # committed: an established shape the lane cannot bind: today's gate, after the one-shot line
    lane_oneshot_case "$FUNCNAME: ${mutate}" install 'lockfile' 'npm install clean@1.0.0' || return
    # the same lockfile in uncommitted changes: a refusal, before npm runs
    lane_prepare "${label}-dirty" kept@1.0.0
    lane_lock kept@1.0.0 | jq -c "${mutate}" > "${WORK_DIR}/package-lock.json"
    lane_run 'npm install clean@1.0.0'
    assert_status 100 "$FUNCNAME: dirty ${mutate}" || return
    assert_lane_final_line install "$FUNCNAME" || return
    assert_err_contains_fragment 'is not covered by the project lane' "$FUNCNAME" || return
    assert_err_contains_fragment 'exists only in uncommitted changes' "$FUNCNAME" || return
    assert_log_not_contains_fragment 'PROJECTION' "$FUNCNAME" || return
    assert_lane_no_delegate "$FUNCNAME" || return
  done
  pass "$FUNCNAME"
}

# ---- binding: what the transaction leaves ---------------------------------

lane_bind_failure_case() {
  local label="$1" name="$2" status="$3" knob="$4"
  skip_lockdiff_case "${label}" || return 1
  lane_prepare "${name}" kept@1.0.0
  local before target
  before="$(lane_digests)"
  target="$(lane_lock kept@1.0.0 clean@2.0.0 dev@1.0.0:dev)"
  export "${knob%%=*}=${knob#*=}"
  NPM_LOCK_MUTATION_JSON="${target}" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" \
    lane_run 'npm install clean@2.0.0'
  unset "${knob%%=*}"
  assert_status "${status}" "${label}" || return 1
  assert_lane_final_line install "${label}" || return 1
  [[ "$(lane_digests)" == "${before}" ]] || { fail "${label}: the manifest or the lockfile changed"; return 1; }
  [[ ! -e "${WORK_DIR}/node_modules" ]] || { fail "${label}: a tree is in place"; return 1; }
  assert_lane_no_leftover "${label}" || return 1
  grep -qP '^REAL\tnpm\tci\t' "${LOG_FILE}" || { fail "${label}: the frozen install did not run"; return 1; }
  return 0
}

case_project_lane_required_entry_missing_from_the_tree_fails() {
  lane_bind_failure_case "$FUNCNAME" lane-tree-missing 100 NPM_CI_SKIP='node_modules/clean' || return
  assert_err_contains_fragment 'the installed tree differs from the judged lockfile' "$FUNCNAME" || return
  assert_err_contains_fragment 'the project is as it was' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_project_lane_entry_under_another_version_fails() {
  lane_bind_failure_case "$FUNCNAME" lane-tree-version 100 NPM_CI_WRONG_VERSION='node_modules/clean=2.0.1' || return
  assert_err_contains_fragment 'the installed tree differs from the judged lockfile' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_project_lane_entry_under_another_name_fails() {
  lane_bind_failure_case "$FUNCNAME" lane-tree-name 100 NPM_CI_WRONG_NAME='node_modules/clean=cl3an' || return
  assert_err_contains_fragment 'the installed tree differs from the judged lockfile' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_project_lane_entry_the_lockfile_lacks_fails() {
  lane_bind_failure_case "$FUNCNAME" lane-tree-extra 100 NPM_CI_EXTRA='surprise@1.0.0' || return
  assert_err_contains_fragment 'the installed tree differs from the judged lockfile' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# A frozen install that fails shows npm's own diagnostic, exits with npm's
# status and leaves the project as it was: there is nothing to restore.
case_project_lane_failed_install_leaves_the_project_untouched_and_stays_npms() {
  lane_bind_failure_case "$FUNCNAME" lane-npm-fails 7 NPM_CI_STATUS=7 || return
  assert_err_contains_fragment 'the frozen installation failed (npm exit 7' "$FUNCNAME" || return
  assert_err_contains_fragment 'the project is as it was' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_project_lane_interruption_leaves_the_project_untouched() {
  lane_bind_failure_case "$FUNCNAME" lane-interrupted 130 NPM_CI_INTERRUPT=1 || return
  assert_err_contains_fragment 'interrupted before publication; the project is as it was' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# A project file that changes while the command is judged or installed is
# refused at publication, and the change survives.
case_project_lane_input_changed_since_judging_is_never_overwritten() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-inputs-changed" kept@1.0.0
  local before_lock
  before_lock="$(sha256sum "${WORK_DIR}/package-lock.json" | cut -d' ' -f1)"
  # Edited during the projection (an editor, a git operation).
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" NPM_LANE_MUTATE_FILE="${WORK_DIR}/package.json" \
    lane_run 'npm install clean@2.0.0'
  assert_status 100 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  assert_err_contains_fragment 'a project input changed since it was judged (package.json)' "$FUNCNAME" || return
  [[ "$(tail -c 1 "${WORK_DIR}/package.json" | xxd -p)" == "0a" && "$(wc -l < "${WORK_DIR}/package.json")" -ge 2 ]] || { fail "$FUNCNAME: the concurrent edit was lost"; return; }
  [[ "$(sha256sum "${WORK_DIR}/package-lock.json" | cut -d' ' -f1)" == "${before_lock}" ]] || { fail "$FUNCNAME: lockfile written"; return; }
  [[ ! -e "${WORK_DIR}/node_modules" ]] || { fail "$FUNCNAME: tree published"; return; }
  assert_lane_no_leftover "$FUNCNAME" || return
  # Edited while the frozen install runs.
  lane_prepare "lane-inputs-changed-late" kept@1.0.0
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" NPM_CI_MUTATE_PROJECT="${WORK_DIR}/package-lock.json" \
    lane_run 'npm install clean@2.0.0'
  assert_status 100 "$FUNCNAME" || return
  assert_err_contains_fragment 'a project input changed since it was judged (package-lock.json)' "$FUNCNAME" || return
  [[ ! -e "${WORK_DIR}/node_modules" ]] || { fail "$FUNCNAME: tree published"; return; }
  assert_lane_no_leftover "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# A shrinkwrap that appears after the check is a competing lockfile name.
case_project_lane_competing_lockfile_appearing_meanwhile_refuses() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-shrinkwrap-appears" kept@1.0.0
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" NPM_LANE_MUTATE_FILE="${WORK_DIR}/npm-shrinkwrap.json" \
    lane_run 'npm install clean@2.0.0'
  assert_status 100 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  [[ ! -e "${WORK_DIR}/node_modules" ]] || { fail "$FUNCNAME: tree published"; return; }
  assert_lane_no_leftover "$FUNCNAME" || return
  # And one that was there at the start refuses before npm runs.
  lane_prepare "lane-shrinkwrap-present" kept@1.0.0
  printf '{}\n' > "${WORK_DIR}/npm-shrinkwrap.json"
  lane_commit
  lane_run 'npm install clean@2.0.0'
  assert_status 100 "$FUNCNAME" || return
  assert_err_contains_fragment 'npm-shrinkwrap.json' "$FUNCNAME" || return
  assert_log_not_contains_fragment 'PROJECTION' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# What the binder reports reaches the operator: a staging directory left by an
# earlier run that safe did not record is named, never removed.
case_project_lane_binder_report_reaches_the_operator() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-recovery-left" kept@1.0.0
  mkdir -p "${WORK_DIR}/.safe-bind-0123456789abcdef"
  printf 'x' > "${WORK_DIR}/.safe-bind-0123456789abcdef/note"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" \
    lane_run 'npm install clean@2.0.0'
  assert_status 0 "$FUNCNAME" || return
  assert_err_contains_fragment 'left in the project, not removed: .safe-bind-0123456789abcdef' "$FUNCNAME" || return
  [[ -f "${WORK_DIR}/.safe-bind-0123456789abcdef/note" ]] || { fail "$FUNCNAME: an unrecorded directory was removed"; return; }
  pass "$FUNCNAME"
}

# ---- the one npm ------------------------------------------------------------

# The installed layout: a gate wrapper first, then a version manager's shim (a
# marked wrapper whose dispatch routes back into the gate), the real mise
# behind it, the real npm behind that. The lane must reach the real npm every
# time (probes, projection, frozen install) without passing through either.
lane_mise_layout() {
  local name="$1"
  shift
  lane_prepare "${name}" "$@"
  local shims="${CASE_DIR}/shims" real="${CASE_DIR}/realmise" pinned="${CASE_DIR}/pinned"
  mkdir -p "${shims}" "${real}" "${pinned}/bin" "${pinned}/lib/node_modules/npm/bin"
  cat > "${shims}/npm" <<SHIM
#!/usr/bin/env bash
# safe-gate-wrapper v1 tool=mise
printf 'SHIM_REENTRY\t%s\n' "\$*" >> "${LOG_FILE}"
exec safe gate npm -- "\$@"
SHIM
  chmod +x "${shims}/npm"
  # A version manager's installations (what `mise which npm` answers): a launcher that
  # runs its OWN sibling node on its own npm-cli.js, as mise's does.
  lane_forwarding_launcher() { # <installation dir>
    printf '#!/usr/bin/env bash\nexec "$(dirname "$0")/node" "$(dirname "$0")/../lib/node_modules/npm/bin/npm-cli.js" "$@"\n' > "$1/bin/npm"
    chmod +x "$1/bin/npm"
  }
  rm -f "${NODE_BIN}/npm"
  lane_forwarding_launcher "${NODE_DIR}"
  # A second installation, the one a project pins: its launcher, its Node, its npm-cli.js.
  cp "${NODE_BIN}/node" "${pinned}/bin/node"
  cp "${NODE_DIR}/lib/node_modules/npm/bin/npm-cli.js" "${pinned}/lib/node_modules/npm/bin/npm-cli.js"
  lane_forwarding_launcher "${pinned}"
  # The real mise answers `which` in the directory it is run in: a project that
  # pins its own tools (a .pin file here) gets the pinned installation.
  cat > "${real}/mise" <<REALMISE
#!/usr/bin/env bash
printf 'MISE_REACHED\t%s\t%s\n' "\$*" "\$PWD" >> "${LOG_FILE}"
if [[ "\${1:-}" == "which" ]]; then
  base="${NODE_DIR}"
  [[ -e "\${PWD}/.pin" ]] && base="${pinned}"
  printf '%s/bin/%s\n' "\${base}" "\${2:-}"
  exit 0
fi
exit 98
REALMISE
  chmod +x "${real}/mise"
  # The gate wrapper's own mise shadows the real one on PATH, as installed; the
  # installed Node is reached only through the shim.
  rm -f "${BIN_DIR}/mise"
  NODE_BIN=""
  SAFE_TEST_PATH_MID="${shims}:${real}"
}

case_project_lane_reaches_one_npm_through_a_version_manager_shim() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_mise_layout "lane-mise-layout" kept@1.0.0
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" \
    lane_run 'npm install clean@2.0.0'
  local status_now="${STATUS}"
  unset SAFE_TEST_PATH_MID
  STATUS="${status_now}"
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'SHIM_REENTRY' "$FUNCNAME" || return
  grep -q $'^PROJECTION\tnpm' "${LOG_FILE}" || { fail "$FUNCNAME: the projection did not reach npm"; return; }
  grep -qP '^REAL\tnpm\tci\t' "${LOG_FILE}" || { fail "$FUNCNAME: the frozen install did not reach npm"; return; }
  # The version manager answers once, in the project, for npm and for node; every
  # run of every phase is then the same binary.
  [[ "$(grep -c $'^MISE_REACHED\twhich ' "${LOG_FILE}")" -eq 1 ]] || { fail "$FUNCNAME: mise was asked more than once"; return; }
  [[ "$(grep '^MISE_REACHED' "${LOG_FILE}" | cut -f3 | sort -u)" == "$(cd "${WORK_DIR}" && pwd -P)" ]] || { fail "$FUNCNAME: mise was not asked in the project"; return; }
  [[ "$(grep '^NPMBIN' "${LOG_FILE}" | sort -u)" == $'NPMBIN\t'"${NODE_DIR}/lib/node_modules/npm/bin/npm-cli.js" ]] || { fail "$FUNCNAME: runs used another npm"; return; }
  [[ "$(grep '^NODEBIN' "${LOG_FILE}" | sort -u)" == $'NODEBIN\t'"${NODE_DIR}/bin/node" ]] || { fail "$FUNCNAME: another node ran"; return; }
  jq -e '.version == "2.0.0"' "${WORK_DIR}/node_modules/clean/package.json" >/dev/null || { fail "$FUNCNAME: tree"; return; }
  pass "$FUNCNAME"
}

# A project that pins another Node and npm than the user default is projected,
# probed and installed by the same pair, from every working directory.
case_project_lane_pinned_project_runs_one_pair_in_every_phase() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_mise_layout "lane-pinned" kept@1.0.0
  touch "${WORK_DIR}/.pin"
  lane_commit
  local pinned="${CASE_DIR}/pinned"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" \
    lane_run 'npm install clean@2.0.0'
  local status_now="${STATUS}"
  unset SAFE_TEST_PATH_MID
  STATUS="${status_now}"
  assert_status 0 "$FUNCNAME" || return
  [[ "$(grep '^NPMBIN' "${LOG_FILE}" | sort -u)" == $'NPMBIN\t'"${pinned}/lib/node_modules/npm/bin/npm-cli.js" ]] || { fail "$FUNCNAME: a phase did not use the pinned npm: $(grep '^NPMBIN' "${LOG_FILE}" | sort -u)"; return; }
  # the interpreter of every npm invocation is the pinned installation's own node
  [[ "$(grep '^NODEBIN' "${LOG_FILE}" | sort -u)" == $'NODEBIN\t'"${pinned}/bin/node" ]] || { fail "$FUNCNAME: the node is not the pinned one: $(grep '^NODEBIN' "${LOG_FILE}" | sort -u)"; return; }
  [[ "$(grep -c '^NODEBIN' "${LOG_FILE}")" -ge "$(grep -c '^NPMBIN' "${LOG_FILE}")" ]] || { fail "$FUNCNAME: an npm run was not started by the pinned node"; return; }
  grep -q $'^CICWD\t.safe-bind-' "${LOG_FILE}" || { fail "$FUNCNAME: ci did not run in staging"; return; }
  [[ "$(grep -c '^NPMBIN' "${LOG_FILE}")" -ge 6 ]] || { fail "$FUNCNAME: too few npm runs seen"; return; }
  pass "$FUNCNAME"
}

# `mise exec -- npm ...` runs this gate for an outer process that would run the
# ORIGINAL arguments next: the lane cannot own the installation there and must
# never return success.
case_project_lane_audit_only_mode_refuses() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-audit-only" kept@1.0.0
  local before
  before="$(lane_digests)"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" SAFE_GATE_NO_EXEC=1 lane_run 'npm install clean@2.0.0'
  [[ "${STATUS}" -ne 0 ]] || { fail "$FUNCNAME: audit-only mode returned success"; return; }
  assert_status 100 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  assert_err_contains_fragment 'audit-only pass (SAFE_GATE_NO_EXEC)' "$FUNCNAME" || return
  assert_lane_untouched "${before}" "$FUNCNAME" || return
  assert_log_not_contains_fragment 'PROJECTION' "$FUNCNAME" || return
  : > "${LOG_FILE}"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" SAFE_GATE_NO_EXEC=1 lane_run 'npm install clean@2.0.0 --dry-run'
  assert_status 100 "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# Node's start-up options: a preload cannot be carried and refuses before any npm
# runs; a benign one is carried to every run; unrelated delegates keep theirs.
case_project_lane_controls_the_npm_startup_environment() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-node-options" kept@1.0.0
  local before
  before="$(lane_digests)"
  NODE_OPTIONS='--require /tmp/preload.js' NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" lane_run 'npm install clean@2.0.0'
  assert_status 100 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  assert_err_contains_fragment 'NODE_OPTIONS carrying --require' "$FUNCNAME" || return
  assert_lane_untouched "${before}" "$FUNCNAME" || return
  assert_log_not_contains_fragment 'REAL' "$FUNCNAME" || return
  : > "${LOG_FILE}"
  NODE_OPTIONS='--max-old-space-size=512' NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" \
    NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" lane_run 'npm install clean@2.0.0'
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'NODEOPT\t--max-old-space-size=512' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# Every child of the lane gets exactly the allow-listed environment, from the
# first probe; nothing else of the caller's reaches it.
case_project_lane_every_npm_run_gets_exactly_the_listed_environment() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-env-allowlist" kept@1.0.0
  : > "${HOME_DIR}/.stub-log-env"
  local project
  project="$(cd "${WORK_DIR}" && pwd -P)"
  MISE_CANARY=1 NODE_PATH=/x SAFE_CANARY=1 BASH_ENV=/dev/null CI=1 SSH_AUTH_SOCK=/x GIT_DIR=/x \
    npm_config_cache_canary=ok HTTPS_PROXY=http://proxy.example:3128 LC_MESSAGES=C LANE_TEST_PROJECT="${project}" \
    NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" \
    lane_run 'npm install clean@2.0.0'
  assert_status 0 "$FUNCNAME" || return
  local line name
  while IFS= read -r line; do
    for name in ${line#ENVNAMES$'\t'}; do
      case "${name}" in
        PWD|OLDPWD|SHLVL|_) continue ;;
        PATH|HOME|USER|LOGNAME|LANG|LANGUAGE|TZ|TMPDIR|NODE_ENV|SSL_CERT_FILE|SSL_CERT_DIR|NODE_EXTRA_CA_CERTS|NODE_OPTIONS) continue ;;
        HTTP_PROXY|HTTPS_PROXY|NO_PROXY|ALL_PROXY|http_proxy|https_proxy|no_proxy|all_proxy) continue ;;
        LC_*|npm_config_*|NPM_CONFIG_*) continue ;;
      esac
      fail "$FUNCNAME: ${name} reached an npm run, which is not on the list"
      return
    done
  done < <(grep '^ENVNAMES' "${LOG_FILE}")
  [[ "$(grep -c '^ENVNAMES' "${LOG_FILE}")" -ge 5 ]] || { fail "$FUNCNAME: too few runs seen"; return; }
  [[ "$(grep '^ENVNAMES' "${LOG_FILE}" | grep -c 'npm_config_cache_canary')" == "$(grep -c '^ENVNAMES' "${LOG_FILE}")" ]] || { fail "$FUNCNAME: an npm_config_* setting was not carried to every run"; return; }
  [[ "$(grep '^ENVNAMES' "${LOG_FILE}" | grep -c 'HTTPS_PROXY')" == "$(grep -c '^ENVNAMES' "${LOG_FILE}")" ]] || { fail "$FUNCNAME: the proxy was not carried to every run"; return; }
  # The lock descriptor is closed in every child, the reused probes included.
  assert_log_not_contains_fragment 'LOCKFD_INHERITED' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# ---- admission --------------------------------------------------------------

# The one-shot route: today's gate, after ONE line naming the reason, and exactly what it does with
# the switch off (the same status, the same delegation). $1 label, $2 verb, $3 a fragment of the
# reason, $4 the command, then VAR=value pairs the case needs in the environment.
# What today's gate did, in ORDER: its audits and delegations with each delegate's environment, without
# the lane's own probes of npm (a configuration probe carrying the lane's fixed destinations, and the
# lines that describe that probe's run). $1 the log, $2 and $3 a path of the other fixture to rewrite.
lane_delegation_of_log() {
  local log="${1:-${LOG_FILE}}"
  # Each event is preceded by lines that describe it (the environment names, the node used) and
  # followed by the npm file it ran: those travel with the event, kept or dropped as it is.
  awk '
    function flush(   i) { for (i = 0; i < n; i++) print held[i]; n = 0 }
    /^(ENVNAMES|NODEBIN|LOCKFD_INHERITED|PRIVATE_PATH)\t/ { held[n++] = $0; next }
    /^NPMBIN\t/ { if (!skip) print; next }
    /^REAL\tnpm\tconfig\t/ && /replace-registry-host=never/ { n = 0; skip = 1; next }
    /^(REAL|AUDIT|MISEQ|MISE_REACHED|PROJECTION|EVIDENCE_INPUT|EVIDENCE_NAMES|CORE_BIND_ARGS)\t/ { skip = 0; flush(); print; next }
    { flush(); print }
    END { flush() }
  ' "${log}" | sed -E 's#(safe-gate-scan\.)[A-Za-z0-9]+#\1X#' | { if [[ -n "${2:-}" ]]; then sed "s#${2}#${3}#g"; else cat; fi; }
}

# The one-shot route: today's gate, after ONE line naming the reason, and EXACTLY what it does with the
# switch off, run on a second, independent fixture (a copy of the project and of the home, the switch
# off): the same status, the same standard output, the same standard error but for the one line, the
# same events in the same order, the same delegate environments. The switch-on trace is kept in
# ${LANE_ONESHOT_TRACE} for the caller's own assertions. A case where today's gate itself refuses is
# fine: its refusal is today's gate's, never the lane's.
# $1 label, $2 verb, $3 a fragment of the reason, $4 the command, then VAR=value pairs.
lane_oneshot_case() {
  local label="$1" verb="$2" fragment="$3" script="$4" kv
  shift 4
  local on_status on_out on_err off_status off_out off_err on_events off_events
  local twin="${CASE_DIR}/off-fixture" work_on="${WORK_DIR}" home_on="${HOME_DIR}"
  rm -rf "${twin}"
  mkdir -p "${twin}"
  cp -a "${work_on}" "${twin}/work" && cp -a "${home_on}" "${twin}/home" || { fail "${label}: cannot build the second fixture"; return 1; }
  : > "${home_on}/.stub-log-env"
  : > "${twin}/home/.stub-log-env"
  for kv in "$@"; do export "${kv?}"; done
  : > "${LOG_FILE}"
  lane_run "${script}"
  on_status="${STATUS}"
  on_out="$(cat "${OUT_FILE}")"
  on_err="$(cat "${ERR_FILE}")"
  LANE_ONESHOT_TRACE="${CASE_DIR}/oneshot-on.log"
  cp -- "${LOG_FILE}" "${LANE_ONESHOT_TRACE}"
  on_events="$(lane_delegation_of_log "${LANE_ONESHOT_TRACE}" "${work_on}" "<W>" | sed "s#${home_on}#<H>#g")"
  # the same command on the independent fixture, the switch off
  printf '{"install":{"project_lane":false}}\n' > "${twin}/home/.config/safe/run/config.json"
  local saved_work="${WORK_DIR}" saved_home_install="${SAFE_INSTALL_HOME:-}"
  WORK_DIR="${twin}/work"
  SAFE_INSTALL_HOME="${twin}/home"
  : > "${LOG_FILE}"
  lane_run "${script}"
  off_status="${STATUS}"
  off_out="$(cat "${OUT_FILE}")"
  off_err="$(cat "${ERR_FILE}")"
  off_events="$(lane_delegation_of_log "${LOG_FILE}" "${twin}/work" "<W>" | sed "s#${twin}/home#<H>#g")"
  WORK_DIR="${saved_work}"
  if [[ -n "${saved_home_install}" ]]; then SAFE_INSTALL_HOME="${saved_home_install}"; else unset SAFE_INSTALL_HOME; fi
  for kv in "$@"; do unset "${kv%%=*}"; done
  local fragment_re line_re
  fragment_re="$(printf '%s' "${fragment}" | sed 's/[][\.*^$()+?{}|]/\\&/g')"
  line_re="^safe: project lane: npm ${verb} \\[lane: one-shot, .*${fragment_re}.*\\] — the closure is not judged on this route$"
  if [[ "$(printf '%s\n' "${on_err}" | grep -cE "^safe: project lane: ")" -ne 1 ]] || ! printf '%s\n' "${on_err}" | grep -qE -- "${line_re}"; then
    printf 'stderr with the switch on:\n%s\n' "${on_err}" >&2
    fail "${label}: no single one-shot line for ${fragment}"
    return 1
  fi
  if printf '%s\n' "${on_err}" | grep -q '\[lane: project\]'; then
    fail "${label}: a lane refusal came with the one-shot line"
    return 1
  fi
  [[ "${on_status}" == "${off_status}" ]] || { fail "${label}: status ${on_status} with the switch on, ${off_status} with it off"; return 1; }
  [[ "${on_out}" == "${off_out}" ]] || { printf 'on:\n%s\noff:\n%s\n' "${on_out}" "${off_out}" >&2; fail "${label}: standard output differs"; return 1; }
  [[ "${on_events}" == "${off_events}" ]] || { diff <(printf '%s\n' "${on_events}") <(printf '%s\n' "${off_events}") >&2; fail "${label}: today's gate did not run as with the switch off (events, order or delegate environment)"; return 1; }
  [[ -n "${on_events}" ]] || { fail "${label}: nothing was delegated or audited: today's gate did not run"; return 1; }
  [[ "$(printf '%s\n' "${on_err}" | grep -v '^safe: project lane: ' | sed "s#${work_on}#<W>#g; s#${home_on}#<H>#g")" == "$(printf '%s\n' "${off_err}" | sed "s#${twin}/work#<W>#g; s#${twin}/home#<H>#g")" ]] \
    || { printf 'on:\n%s\noff:\n%s\n' "${on_err}" "${off_err}" >&2; fail "${label}: today's gate printed something else"; return 1; }
  ! grep -q $'^PROJECTION\ttnpm' "${LANE_ONESHOT_TRACE}" || { fail "${label}: the lane projected"; return 1; }
  ! grep -q '^PROJECTION' "${LANE_ONESHOT_TRACE}" || { fail "${label}: the lane projected"; return 1; }
  return 0
}

lane_unsupported_case() {
  local label="$1" expected="$2" script="$3"
  assert_status 100 "${label}" || return 1
  assert_lane_final_line "${expected}" "${label}" || return 1
  grep -qE 'is not (covered by|routed by) the project lane' "${ERR_FILE}" || { fail "${label}: the refusal does not say the lane does not cover it"; return 1; }
  # no refusal tells the caller to turn the lane off
  ! grep -qiE 'lane off|turn.*lane|switch' "${ERR_FILE}" || { fail "${label}: the refusal mentions the switch"; return 1; }
  [[ "$(wc -l < "${ERR_FILE}")" -eq 1 ]] || { fail "${label}: ${script}: more than one stderr line"; return 1; }
  assert_lane_no_delegate "${label}" || return 1
  assert_log_not_contains_fragment $'PROJECTION\tnpm' "${label}" || return 1
  assert_log_not_contains_fragment 'AUDIT' "${label}" || return 1
  return 0
}

case_project_lane_unsupported_commands_refuse_without_a_fallback() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-unsupported-commands" kept@1.0.0
  local before pair script verb
  before="$(lane_digests)"
  for pair in 'ci|npm ci' 'dedupe|npm dedupe' 'prune|npm prune' \
      'install|npm install clean' 'install|npm install clean@^2.0.0' 'install|npm install clean@latest' \
      'install|npm install fixture.tgz' 'install|npm install ./fixture.tgz' 'install|npm install file:../x' \
      'install|npm install github:user/repo' 'install|npm install clean@2.0.0 --package-lock-only=false' \
      'install|npm install clean@2.0.0 -w pkg' 'install|npm install clean@2.0.0 --workspaces' \
      'install|npm install clean@2.0.0 --no-save' 'install|npm install clean@2.0.0 --legacy-peer-deps' \
      'install|npm install clean@2.0.0 --registry=https://r.example/' 'install|npm install clean@2.0.0 --omit=weird' \
      'install|npm install clean@2.0.0 --' 'install|npm install -- -g' 'update|npm update clean' 'install|npm i ../other' \
      'install|npm install npm:clean@2.0.0' 'install|npm install clean@2.0.0 --node-options=--require=x'; do
    verb="${pair%%|*}"
    script="${pair#*|}"
    : > "${LOG_FILE}"
    lane_run "${script}"
    lane_unsupported_case "$FUNCNAME" "${verb}" "${script}" || return
    assert_lane_untouched "${before}" "$FUNCNAME: ${script}" || return
  done
  pass "$FUNCNAME"
}

case_project_lane_unsupported_project_shapes_refuse() {
  skip_lockdiff_case "$FUNCNAME" || return
  # A version 1 lockfile.
  lane_prepare "lane-shape-v1" kept@1.0.0
  lane_lock kept@1.0.0 | jq -c '.lockfileVersion = 1' > "${WORK_DIR}/package-lock.json"
  lane_commit
  # committed: an established shape: today's gate
  lane_oneshot_case "$FUNCNAME" install 'is not a version 2 or 3 lockfile' 'npm install clean@2.0.0' || return
  # a version 1 lockfile that is a DIRTY replacement of a supported one cannot reach it
  lane_prepare "lane-shape-v1-dirty" kept@1.0.0
  lane_lock kept@1.0.0 | jq -c '.lockfileVersion = 1' > "${WORK_DIR}/package-lock.json"
  lane_run 'npm install clean@2.0.0'
  lane_unsupported_case "$FUNCNAME" install 'dirty v1 lockfile' || return
  assert_err_contains_fragment 'is not a version 2 or 3 lockfile' "$FUNCNAME" || return
  assert_err_contains_fragment 'uncommitted changes' "$FUNCNAME" || return
  # outside a git work tree there is no established state to appeal to
  lane_prepare "lane-shape-v1-nogit" kept@1.0.0
  lane_lock kept@1.0.0 | jq -c '.lockfileVersion = 1' > "${WORK_DIR}/package-lock.json"
  lane_commit
  rm -rf "${WORK_DIR}/.git"
  lane_run 'npm install clean@2.0.0'
  lane_unsupported_case "$FUNCNAME" install 'v1 lockfile outside git' || return
  assert_err_contains_fragment 'not in a git work tree' "$FUNCNAME" || return
  # A manifest that names a source that is not a registry range.
  local spec
  for spec in 'git+https://example.invalid/x.git' 'github:user/repo' 'https://example.invalid/x.tgz' 'file:../elsewhere' 'file:./local' \
      'user/repo' 'fixture.tgz' './fixture.tgz' 'npm:other@1.0.0' 'workspace:*' '1.0.0 || ../x' 'link:../x' 'git@github.com:u/r.git'; do
    lane_prepare "lane-shape-manifest-source-${spec//[^a-z]/}${RANDOM}" kept@1.0.0
    jq -c --arg s "${spec}" '.dependencies.odd = $s' "${WORK_DIR}/package.json" > "${WORK_DIR}/package.json.new"
    mv "${WORK_DIR}/package.json.new" "${WORK_DIR}/package.json"
    lane_commit
    # committed: today's gate; the same in uncommitted changes: a refusal
    lane_oneshot_case "$FUNCNAME" install 'manifest.dependencies.odd' 'npm install clean@2.0.0' || return
    lane_prepare "lane-shape-manifest-source-dirty-${RANDOM}" kept@1.0.0
    jq -c --arg s "${spec}" '.dependencies.odd = $s' "${WORK_DIR}/package.json" > "${WORK_DIR}/package.json.new"
    mv "${WORK_DIR}/package.json.new" "${WORK_DIR}/package.json"
    lane_run 'npm install clean@2.0.0'
    lane_unsupported_case "$FUNCNAME" install "dirty manifest ${spec}" || return
  done
  # Ranges that are registry ranges stay admitted.
  local range
  for range in '^1.0.0' '~1.2.3' '>=1.0.0 <2.0.0' '1.x' '*' 'latest' '1.0.0 - 2.0.0' '^1.0.0 || ^2.0.0' ''; do
    lane_prepare "lane-shape-range-ok-${RANDOM}" kept@1.0.0
    jq -c --arg s "${range}" '.dependencies.kept = $s' "${WORK_DIR}/package.json" > "${WORK_DIR}/package.json.new"
    mv "${WORK_DIR}/package.json.new" "${WORK_DIR}/package.json"
    lane_commit
    NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0)" lane_run 'npm install'
    assert_status 0 "$FUNCNAME: range '${range}'" || return
  done
  # Overrides are admitted the same way: selectors and values.
  for spec in '{"kept":{"inner":"git+https://example.invalid/x.git"}}' '{"kept":"file:../x"}' '{"git+https://example.invalid/x.git":"1.0.0"}' \
      '{"kept@https://example.invalid/x":"1.0.0"}'; do
    lane_prepare "lane-shape-override-${RANDOM}" kept@1.0.0
    jq -c --argjson o "${spec}" '.overrides = $o' "${WORK_DIR}/package.json" > "${WORK_DIR}/package.json.new"
    mv "${WORK_DIR}/package.json.new" "${WORK_DIR}/package.json"
    lane_commit
    lane_oneshot_case "$FUNCNAME" install 'manifest.overrides' 'npm install clean@2.0.0' || return
  done
  # A workspaces project.
  lane_prepare "lane-shape-workspaces" kept@1.0.0
  jq -c '.workspaces = ["packages/*"]' "${WORK_DIR}/package.json" > "${WORK_DIR}/package.json.new"
  mv "${WORK_DIR}/package.json.new" "${WORK_DIR}/package.json"
  lane_commit
  lane_run 'npm install clean@2.0.0'
  lane_unsupported_case "$FUNCNAME" install 'workspaces' || return
  # A symbolic-link manifest and a symbolic-link tree root.
  lane_prepare "lane-shape-symlink-manifest" kept@1.0.0
  mv "${WORK_DIR}/package.json" "${WORK_DIR}/real-package.json"
  ln -s real-package.json "${WORK_DIR}/package.json"
  lane_commit
  lane_run 'npm install clean@2.0.0'
  lane_unsupported_case "$FUNCNAME" install 'symlinked manifest' || return
  # A project selector.
  lane_prepare "lane-shape-prefix" kept@1.0.0
  lane_run 'npm install clean@2.0.0 --prefix .'
  lane_unsupported_case "$FUNCNAME" install 'prefix' || return
  pass "$FUNCNAME"
}

# npm would empty a symbolic-linked tree root's destination: the lane refuses
# before npm runs, and nothing behind the link is touched.
case_project_lane_symlinked_tree_root_refuses_before_npm() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-tree-root-link" kept@1.0.0
  mkdir -p "${CASE_DIR}/elsewhere/precious"
  printf 'keep' > "${CASE_DIR}/elsewhere/precious/file"
  ln -s "${CASE_DIR}/elsewhere" "${WORK_DIR}/node_modules"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" lane_run 'npm install clean@2.0.0'
  assert_status 100 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  assert_err_contains_fragment 'node_modules that is a symbolic link' "$FUNCNAME" || return
  assert_lane_no_delegate "$FUNCNAME" || return
  assert_log_not_contains_fragment 'PROJECTION' "$FUNCNAME" || return
  [[ "$(cat "${CASE_DIR}/elsewhere/precious/file")" == "keep" && -L "${WORK_DIR}/node_modules" ]] || { fail "$FUNCNAME: the link or its destination changed"; return; }
  pass "$FUNCNAME"
}

# An existing real tree is replaced as a whole, only once verified.
case_project_lane_replaces_an_existing_tree_only_when_verified() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-tree-replace" kept@1.0.0
  mkdir -p "${WORK_DIR}/node_modules/old"
  printf '{"name":"old","version":"1.0.0"}\n' > "${WORK_DIR}/node_modules/old/package.json"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" \
    NPM_CI_SKIP='node_modules/clean' lane_run 'npm install clean@2.0.0'
  assert_status 100 "$FUNCNAME" || return
  [[ -f "${WORK_DIR}/node_modules/old/package.json" ]] || { fail "$FUNCNAME: the old tree was lost to an unverified one"; return; }
  : > "${LOG_FILE}"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" \
    lane_run 'npm install clean@2.0.0'
  assert_status 0 "$FUNCNAME" || return
  [[ ! -e "${WORK_DIR}/node_modules/old" && -f "${WORK_DIR}/node_modules/clean/package.json" ]] || { fail "$FUNCNAME: the verified tree is not in place"; return; }
  assert_lane_no_leftover "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# ---- registry, configuration ------------------------------------------------

case_project_lane_registry_must_be_the_canonical_public_one() {
  skip_lockdiff_case "$FUNCNAME" || return
  local registry
  # A registry (or a scope's registry used by the project) that is not the canonical public one is a
  # property of the host's configuration: today's gate, which keeps the private-origin rules, after the
  # one-shot line.
  for registry in 'http://registry.npmjs.org/' 'https://registry.npmjs.org:8443/' 'https://registry.npmjs.org/prefix/' 'https://npm.private.example/'; do
    lane_prepare "lane-registry-${RANDOM}" kept@1.0.0
    lane_oneshot_case "$FUNCNAME" install 'a registry other than the canonical public one over https' 'npm install clean@2.0.0' \
      "NPM_LOCKDIFF_REGISTRY_CONFIG_JSON={\"registry\":\"${registry}\"}" || return
  done
  lane_prepare "lane-registry-scope" kept@1.0.0
  jq -c '.dependencies["@priv/lib"] = "^1.0.0"' "${WORK_DIR}/package.json" > "${WORK_DIR}/package.json.new"
  mv "${WORK_DIR}/package.json.new" "${WORK_DIR}/package.json"
  lane_commit
  lane_oneshot_case "$FUNCNAME" install 'the package @priv/lib resolves through a registry other than the canonical public one' 'npm install clean@2.0.0' \
    'NPM_LOCKDIFF_REGISTRY_CONFIG_JSON={"registry":"https://registry.npmjs.org/","@priv:registry":"https://npm.private.example/"}' || return
  # A used scope mapped to the canonical public registry is accepted.
  lane_prepare "lane-registry-scope-public" kept@1.0.0
  jq -c '.dependencies["@pub/lib"] = "^1.0.0"' "${WORK_DIR}/package.json" > "${WORK_DIR}/package.json.new"
  mv "${WORK_DIR}/package.json.new" "${WORK_DIR}/package.json"
  lane_commit
  NPM_LOCKDIFF_REGISTRY_CONFIG_JSON='{"registry":"https://registry.npmjs.org/","@pub:registry":"https://registry.npmjs.org/"}' \
    NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" lane_run 'npm install clean@2.0.0'
  assert_status 0 "$FUNCNAME" || return
  # The default scope picks the registry of an unscoped package.
  lane_prepare "lane-registry-default-scope" kept@1.0.0
  lane_oneshot_case "$FUNCNAME" install 'the package' 'npm install clean@2.0.0' \
    'NPM_LOCKDIFF_REGISTRY_CONFIG_JSON={"registry":"https://registry.npmjs.org/","scope":"@priv","@priv:registry":"https://npm.private.example/"}' || return
  # A scope first discovered by the projection refuses before anything else is decided.
  lane_prepare "lane-registry-discovered-scope" kept@1.0.0
  local before
  before="$(lane_digests)"
  NPM_LOCKDIFF_REGISTRY_CONFIG_JSON='{"registry":"https://registry.npmjs.org/","@priv:registry":"https://npm.private.example/"}' \
    NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0 @priv/found@1.0.0)" lane_run 'npm install clean@2.0.0'
  assert_status 100 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  assert_err_contains_fragment 'the package @priv/found resolves through a registry other than' "$FUNCNAME" || return
  assert_log_not_contains_fragment 'EVIDENCE_INPUT' "$FUNCNAME" || return
  assert_lane_untouched "${before}" "$FUNCNAME" || return
  # ... and an unused scope mapping, as on a machine with a private registry, does not.
  lane_prepare "lane-registry-unused-scope" kept@1.0.0
  NPM_LOCKDIFF_REGISTRY_CONFIG_JSON='{"registry":"https://registry.npmjs.org/","@priv:registry":"https://npm.private.example/"}' \
    NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" \
    lane_run 'npm install clean@2.0.0'
  assert_status 0 "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# The frozen invocation is probed as npm will see it.
case_project_lane_frozen_invocation_is_probed_apart() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-frozen-probe" kept@1.0.0
  local before key
  before="$(lane_digests)"
  # An ambient lockfile-only or dry-run mode would make `npm ci` clear the tree and extract nothing.
  for key in 'package-lock-only' 'dry-run' 'install-strategy:"nested"' 'legacy-peer-deps' 'node-options:"--require x"'; do
    : > "${LOG_FILE}"
    if [[ "${key}" == *:* ]]; then
      value="${key#*:}"
      key="${key%%:*}"
    else
      value=true
    fi
    # a property of the host's configuration: today's gate, after the one-shot line
    lane_oneshot_case "$FUNCNAME: ${key}" install '' 'npm install clean@2.0.0' \
      "NPM_LOCKDIFF_EFFECTIVE_CONFIG_JSON={\"package-lock\":true,\"ignore-scripts\":true,\"${key}\":${value}}" "NPM_LOCK_MUTATION_JSON=$(lane_lock kept@1.0.0 clean@2.0.0)" || return
  done
  pass "$FUNCNAME"
}

# The selection verified comes from npm's effective configuration, not from NODE_ENV.
case_project_lane_selection_comes_from_the_effective_configuration() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-selection" kept@1.0.0
  local target
  target="$(lane_lock kept@1.0.0 clean@2.0.0 dev@1.0.0:dev)"
  # NODE_ENV=production alone is not an omission for the verifier: npm said none,
  # and the stub (like npm here) installs the dev entry... which is then required.
  NODE_ENV=production NPM_LOCK_MUTATION_JSON="${target}" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" \
    NPM_CI_SKIP='node_modules/dev' lane_run 'npm install clean@2.0.0'
  assert_status 100 "$FUNCNAME" || return
  assert_err_contains_fragment 'node_modules/dev: missing' "$FUNCNAME" || return
  # npm's own effective omit list (here: the one of --omit=dev) excuses it.
  lane_prepare "lane-selection-omit" kept@1.0.0
  NPM_LOCKDIFF_EFFECTIVE_CONFIG_JSON='{"package-lock":true,"ignore-scripts":true,"omit":["dev"]}' \
    NPM_LOCK_MUTATION_JSON="${target}" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" \
    NPM_CI_SKIP='node_modules/dev' lane_run 'npm install clean@2.0.0'
  assert_status 0 "$FUNCNAME" || return
  [[ ! -e "${WORK_DIR}/node_modules/dev" ]] || { fail "$FUNCNAME: dev installed"; return; }
  pass "$FUNCNAME"
}

# ---- route ------------------------------------------------------------------

case_project_lane_global_exception_follows_npms_effective_setting() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-global" kept@1.0.0
  # A real global install, by flag, is today's gate (its own package audit, its own delegate).
  lane_run 'npm install -g clean@2.0.0'
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tinstall\t-g\tclean@2.0.0' "$FUNCNAME" || return
  assert_err_not_contains_fragment '[lane: project]' "$FUNCNAME" || return
  # A global-looking operand after the terminator does not make a local command global,
  # and the terminator refuses in the lane's form.
  : > "${LOG_FILE}"
  lane_run 'npm install clean@2.0.0 -- -g'
  assert_status 100 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm\tinstall' "$FUNCNAME" || return
  # A global install selected by configuration is not the lane's either.
  : > "${LOG_FILE}"
  NPM_LOCKDIFF_EFFECTIVE_CONFIG_JSON='{"package-lock":true,"ignore-scripts":true,"global":true}' lane_run 'npm install clean@2.0.0'
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tinstall\tclean@2.0.0' "$FUNCNAME" || return
  assert_err_not_contains_fragment '[lane: project]' "$FUNCNAME" || return
  assert_log_not_contains_fragment 'PROJECTION' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# ---- one lock ---------------------------------------------------------------

case_project_lane_takes_one_exclusive_lock_before_reading() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-flock" kept@1.0.0
  local before holder
  before="$(lane_digests)"
  # Another holder of the project's lock (another lane command, a binder).
  ( exec {holdfd}<"${WORK_DIR}"; flock -x "${holdfd}"; exec sleep 20 ) &
  holder=$!
  sleep 0.5
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" lane_run 'npm install clean@2.0.0'
  assert_status 100 "$FUNCNAME" || { kill "${holder}" 2>/dev/null; return; }
  assert_lane_final_line install "$FUNCNAME" || { kill "${holder}" 2>/dev/null; return; }
  assert_err_contains_fragment "another command holds this project's lock" "$FUNCNAME" || { kill "${holder}" 2>/dev/null; return; }
  assert_lane_untouched "${before}" "$FUNCNAME" || { kill "${holder}" 2>/dev/null; return; }
  assert_lane_no_delegate "$FUNCNAME" || { kill "${holder}" 2>/dev/null; return; }
  assert_log_not_contains_fragment 'PROJECTION' "$FUNCNAME" || { kill "${holder}" 2>/dev/null; return; }
  # A dry run takes the lock too.
  : > "${LOG_FILE}"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" lane_run 'npm install clean@2.0.0 --dry-run'
  assert_status 100 "$FUNCNAME" || { kill "${holder}" 2>/dev/null; return; }
  assert_lane_no_delegate "$FUNCNAME" || { kill "${holder}" 2>/dev/null; return; }
  kill "${holder}" 2>/dev/null
  wait "${holder}" 2>/dev/null
  # Released when the command ends.
  : > "${LOG_FILE}"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" \
    lane_run 'npm install clean@2.0.0'
  assert_status 0 "$FUNCNAME" || return
  flock -n -x "${WORK_DIR}" true || { fail "$FUNCNAME: the lock was not released"; return; }
  pass "$FUNCNAME"
}

# ---- glue -------------------------------------------------------------------

case_project_lane_dry_run_judges_and_writes_nothing() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-dry-run" kept@1.0.0
  local before
  before="$(lane_digests)"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" lane_run 'npm install clean@2.0.0 --dry-run'
  assert_status 0 "$FUNCNAME" || return
  grep -q $'^PROJECTION\tnpm' "${LOG_FILE}" || { fail "$FUNCNAME: no projection"; return; }
  ! grep '^PROJECTION' "${LOG_FILE}" | grep -q -- '--dry-run' || { fail "$FUNCNAME: --dry-run reached the projection"; return; }
  assert_lane_untouched "${before}" "$FUNCNAME" || return
  assert_err_contains_fragment 'nothing was written to the project' "$FUNCNAME" || return
  : > "${LOG_FILE}"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 dirty@3.0.0)" \
    SAFE_AUDIT_EVIDENCE_HITS="{\"dirty@3.0.0\":${LANE_HIT_CRITICAL}}" lane_run 'npm install dirty@3.0.0 --dry-run'
  assert_status 104 "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# Refusal lines are one line: control characters and credentials never reach the terminal.
case_project_lane_refusal_lines_are_sanitised() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-sanitise" kept@1.0.0
  lane_run $'npm install $\'x@1.0.0\\nsafe: BLOCKED fake\' https://user:hunter2@example.invalid/x.tgz'
  assert_status 100 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  assert_err_not_contains_fragment 'hunter2' "$FUNCNAME" || return
  [[ "$(wc -l < "${ERR_FILE}")" -eq 1 ]] || { fail "$FUNCNAME: more than one line"; return; }
  # A manifest value with a control character and credentials.
  lane_prepare "lane-sanitise-manifest" kept@1.0.0
  jq -c '.dependencies.odd = "git+https://user:hunter2@example.invalid/x.git\u001b[31m"' "${WORK_DIR}/package.json" > "${WORK_DIR}/package.json.new"
  mv "${WORK_DIR}/package.json.new" "${WORK_DIR}/package.json"
  lane_commit
  # committed: the one-shot line carries the reason, cleaned
  lane_run 'npm install clean@2.0.0'
  assert_err_contains_fragment 'one-shot' "$FUNCNAME" || return
  assert_err_not_contains_fragment 'hunter2' "$FUNCNAME" || return
  ! grep -qP '[\x00-\x08\x0b-\x1f\x7f]' "${ERR_FILE}" || { fail "$FUNCNAME: a control character reached stderr (one-shot)"; return; }
  # uncommitted: the refusal does too
  lane_prepare "lane-sanitise-manifest-dirty" kept@1.0.0
  jq -c '.dependencies.odd = "git+https://user:hunter2@example.invalid/x.git\u001b[31m"' "${WORK_DIR}/package.json" > "${WORK_DIR}/package.json.new"
  mv "${WORK_DIR}/package.json.new" "${WORK_DIR}/package.json"
  lane_run 'npm install clean@2.0.0'
  assert_status 100 "$FUNCNAME" || return
  assert_err_not_contains_fragment 'hunter2' "$FUNCNAME" || return
  ! grep -qP '[\x00-\x08\x0b-\x1f\x7f]' "${ERR_FILE}" || { fail "$FUNCNAME: a control character reached stderr"; return; }
  pass "$FUNCNAME"
}

# A failed projection is npm's: its own (cleaned) diagnostic, its own status.
case_project_lane_projection_failure_stays_npms() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-projection-fails" kept@1.0.0
  local before
  before="$(lane_digests)"
  NPM_PROJECTION_FAIL=1 lane_run 'npm install clean@2.0.0'
  assert_status 1 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  assert_err_contains_fragment 'npm: npm error code E404' "$FUNCNAME" || return
  assert_err_contains_fragment 'the projection failed with npm exit 1' "$FUNCNAME" || return
  assert_err_not_contains_fragment 'hunter2' "$FUNCNAME" || return
  assert_lane_untouched "${before}" "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_project_lane_guards_refuse_in_the_lane_form() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-guards" kept@1.0.0
  local before
  before="$(lane_digests)"
  # A hidden-config guard of the dedupe/prune lane, reused unchanged, speaks in the lane's form.
  printf '//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n' > "${HOME_DIR}/.npmrc"
  lane_run 'npm install clean@2.0.0'
  assert_status 100 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  assert_lane_untouched "${before}" "$FUNCNAME" || return
  pass "$FUNCNAME"
}


# ---- second review: what returns a wrong success, what changes a host with the switch off ----

# A private-registry refusal keeps its status and ends on the lane's line, through
# the REAL private store and the REAL project check, with nothing reading a terminal:
# a registered scope that npm does not map to its origin, the project not touching it.
lane_private_store() {
  mkdir -p "${HOME_DIR}/.config/safe/run"
  "${SAFE_CORE_TEST_BIN}" private-trust registry-add --policy "${HOME_DIR}/.config/safe/run/private-registries.json" \
    --id p-npm --ecosystem npm --origin https://npm.private.example --namespace '@p/*' >/dev/null || return 1
}

# A project that touches an entry of a non-empty private store refuses BEFORE the
# auditor runs anything (it resolves an npm of its own): trusted private origins
# are the routing ticket's.
case_project_lane_project_touching_the_private_store_refuses_before_the_auditor() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-private-touch" kept@1.0.0
  lane_private_store || { fail "$FUNCNAME: cannot seed the private store"; return; }
  jq -c '.dependencies["@p/lib"] = "^1.0.0"' "${WORK_DIR}/package.json" > "${WORK_DIR}/package.json.new"
  mv "${WORK_DIR}/package.json.new" "${WORK_DIR}/package.json"
  lane_commit
  local before
  before="$(lane_digests)"
  SAFE_AUDIT_REAL_PRIVATE=1 SAFE_CORE_BIN_FOR_AUDIT="${SAFE_CORE_TEST_BIN}" NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" \
    lane_run 'npm install clean@2.0.0'
  assert_status 100 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  assert_err_contains_fragment 'touches the private-registry store (@p/lib)' "$FUNCNAME" || return
  assert_log_not_contains_fragment 'private-npm-project' "$FUNCNAME" || return
  assert_log_not_contains_fragment 'PROJECTION' "$FUNCNAME" || return
  assert_lane_untouched "${before}" "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# The caller's SAFE_GATE_LANE_* environment changes nothing: not with the switch
# off (an existing dedupe reaches the probe hook), not with it on.
case_project_lane_inherited_runner_state_is_discarded() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-inherited-state" kept@1.0.0
  mkdir -p "${WORK_DIR}/node_modules"
  install_lockdiff_package kept 1.0.0
  printf '{"install":{"project_lane":false}}\n' > "${HOME_DIR}/.config/safe/run/config.json"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0)" SAFE_GATE_LANE_NPM=/nonexistent/npm SAFE_GATE_LANE_EXTRA_ENV=BOGUS=1 \
    SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tdedupe' "$FUNCNAME" || return
  # With the switch on, nothing inherited is evaluated or obeyed.
  rm -rf "${WORK_DIR}/node_modules"
  printf '{"install":{"project_lane":true}}\n' > "${HOME_DIR}/.config/safe/run/config.json"
  : > "${LOG_FILE}"
  local marker="${CASE_DIR}/evaluated"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" \
    SAFE_GATE_LANE_NPM=/nonexistent/npm SAFE_GATE_LANE_EXTRA_ENV=BOGUS=1 SAFE_GATE_LANE_LOCKFD="1; touch ${marker}" \
    lane_run 'npm install clean@2.0.0'
  assert_status 0 "$FUNCNAME" || return
  [[ ! -e "${marker}" ]] || { fail "$FUNCNAME: an inherited value was evaluated"; return; }
  assert_log_not_contains_fragment 'BOGUS' "$FUNCNAME" || return
  jq -e '.version == "2.0.0"' "${WORK_DIR}/node_modules/clean/package.json" >/dev/null || { fail "$FUNCNAME: tree"; return; }
  # ... and dedupe with the switch on is the lane's refusal, not a mis-run.
  : > "${LOG_FILE}"
  SAFE_GATE_LANE_NPM=/nonexistent/npm lane_run 'npm dedupe'
  assert_status 100 "$FUNCNAME" || return
  assert_lane_final_line dedupe "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# The switch is the operator's canonical configuration; a redirected run-config
# directory (inside a project, say) cannot turn it on.
case_project_lane_redirected_configuration_does_not_enable_the_lane() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-redirected-config" kept@1.0.0
  mkdir -p "${WORK_DIR}/node_modules"
  install_lockdiff_package kept 1.0.0
  printf '{"install":{"project_lane":false}}\n' > "${HOME_DIR}/.config/safe/run/config.json"
  mkdir -p "${WORK_DIR}/redirected"
  printf '{"install":{"project_lane":true}}\n' > "${WORK_DIR}/redirected/config.json"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0)" SAFE_RUN_CONFIG_DIR_FOR_CASE="${WORK_DIR}/redirected" \
    SAFE_INSTALL_TEST_SCRIPT='npm dedupe' run_zsh
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tdedupe' "$FUNCNAME" || return
  assert_log_not_contains_fragment 'EVIDENCE_INPUT' "$FUNCNAME" || return
  assert_err_not_contains_fragment '[lane: project]' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# Graph and difference documents travel in files: a supported graph larger than
# one argument may be reaches its verdict.
case_project_lane_large_graph_reaches_a_verdict() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-large-graph" kept@1.0.0
  local file="${CASE_DIR}/big-lock.json" integrity
  integrity="$(lane_integrity bulk)"
  jq -nc --arg i "${integrity}" '{lockfileVersion: 3, requires: true,
    packages: ({"": {name: "lane-test", version: "1.0.0"}}
      + ([range(0; 1500) | {key: "node_modules/bulk-package-\(.)", value: {version: "1.0.0",
          resolved: "https://registry.npmjs.org/bulk-package-\(.)/-/bulk-package-\(.)-1.0.0.tgz", integrity: $i}}] | from_entries))}' > "${file}"
  local size
  size="$("${SAFE_CORE_TEST_BIN}" project-graph "${file}" | wc -c)"
  (( size > 131072 )) || { fail "$FUNCNAME: the fixture's graph is only ${size} bytes"; return; }
  NPM_LOCK_MUTATION_FILE="${file}" NPM_PROJECTION_MANIFEST_JSON="${LANE_MANIFEST}" lane_run 'npm install'
  assert_status 0 "$FUNCNAME" || return
  assert_err_contains_fragment '1500 packages added' "$FUNCNAME" || return
  [[ -f "${WORK_DIR}/node_modules/bulk-package-1499/package.json" ]] || { fail "$FUNCNAME: tree"; return; }
  pass "$FUNCNAME"
}

# Success needs a zero status and a complete, consistent document from the
# decision and from the binder; each producer is tampered in turn.
case_project_lane_success_needs_a_whole_decision_and_a_whole_bind_document() {
  skip_lockdiff_case "$FUNCNAME" || return
  local kind before
  for kind in decide-clear-with-gaps decide-two-documents decide-clear-nonzero decide-stopped-zero decide-empty-classes \
      bind-published-nonzero bind-label-and-status bind-no-verification bind-not-committed bind-two-documents; do
    lane_prepare "lane-tamper-${kind}" kept@1.0.0
    before="$(lane_digests)"
    : > "${LOG_FILE}"
    case "${kind}" in
      decide-clear-with-gaps|decide-empty-classes)
        # Missing coverage (a gap) is what the tampered "clear" hides.
        SAFE_AUDIT_EVIDENCE_MISSING='["clean@1.0.0"]' ;;
      decide-stopped-zero)
        SAFE_AUDIT_EVIDENCE_HITS="{\"clean@1.0.0\":${LANE_HIT_CRITICAL}}" ;;
      *) : ;;
    esac
    SAFE_CORE_TAMPER="${kind}" NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@1.0.0)" \
      SAFE_AUDIT_EVIDENCE_MISSING="$([[ "${kind}" == decide-clear-with-gaps || "${kind}" == decide-empty-classes ]] && printf '["clean@1.0.0"]')" \
      SAFE_AUDIT_EVIDENCE_HITS="$([[ "${kind}" == decide-stopped-zero ]] && printf '{"clean@1.0.0":%s}' "${LANE_HIT_CRITICAL}")" \
      lane_run 'npm install clean@1.0.0'
    [[ "${STATUS}" -ne 0 ]] || { printf 'stderr:\n%s\n' "$(cat "${ERR_FILE}")" >&2; fail "$FUNCNAME: ${kind} was accepted"; return; }
    assert_lane_final_line install "$FUNCNAME: ${kind}" || return
    if [[ "${kind}" == decide-* ]]; then
      # Refused before anything was written.
      assert_lane_untouched "${before}" "$FUNCNAME: ${kind}" || return
    fi
  done
  pass "$FUNCNAME"
}

# The empty-tree success of the binder stays a success.
case_project_lane_empty_tree_still_succeeds() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-empty-tree"
  printf '{"name":"lane-test","version":"1.0.0"}\n' > "${WORK_DIR}/package.json"
  lane_commit
  NPM_LOCK_MUTATION_JSON="$(lane_lock)" lane_run 'npm install'
  assert_status 0 "$FUNCNAME" || return
  [[ ! -e "${WORK_DIR}/node_modules" ]] || { fail "$FUNCNAME: a tree for an empty lockfile"; return; }
  assert_lane_no_leftover "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# A projected link is the decision's to rule on: a known block elsewhere in the
# graph outranks it (104); alone it is refused by the binder before anything runs.
case_project_lane_projected_link_does_not_mask_a_known_block() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-projected-link" kept@1.0.0
  local before target
  before="$(lane_digests)"
  target="$(lane_lock kept@1.0.0 evil@1.0.0 | jq -c '.packages["node_modules/loc"] = {"resolved": "packages/loc", "link": true} | .packages["packages/loc"] = {"name": "loc", "version": "1.0.0"}')"
  NPM_LOCK_MUTATION_JSON="${target}" \
    SAFE_AUDIT_EVIDENCE_HITS='{"evil@1.0.0":[{"id":"MAL-2026-0007","severity":"critical","malware":true}]}' \
    lane_run 'npm install evil@1.0.0'
  assert_status 104 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  assert_err_contains_fragment 'known-malware record on evil@1.0.0' "$FUNCNAME" || return
  assert_lane_untouched "${before}" "$FUNCNAME" || return
  : > "${LOG_FILE}"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 | jq -c '.packages["node_modules/loc"] = {"resolved": "packages/loc", "link": true} | .packages["packages/loc"] = {"name": "loc", "version": "1.0.0"}')" \
    lane_run 'npm install'
  [[ "${STATUS}" -ne 0 ]] || { fail "$FUNCNAME: a projected link alone was installed"; return; }
  assert_lane_final_line install "$FUNCNAME" || return
  assert_lane_untouched "${before}" "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# A genuine global install is not the lane's: it is recognised before the lock and
# before the terminator refusal, and goes to today's gate with its own delegate.
case_project_lane_genuine_global_install_goes_to_todays_gate() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-genuine-global" kept@1.0.0
  local holder
  # Even while another command holds the project's lock.
  ( exec {holdfd}<"${WORK_DIR}"; flock -x "${holdfd}"; exec sleep 20 ) &
  holder=$!
  sleep 0.5
  lane_run 'npm install -g clean@2.0.0'
  assert_status 0 "$FUNCNAME" || { kill "${holder}" 2>/dev/null; return; }
  assert_log_contains $'REAL\tnpm\tinstall\t-g\tclean@2.0.0' "$FUNCNAME" || { kill "${holder}" 2>/dev/null; return; }
  assert_err_not_contains_fragment '[lane: project]' "$FUNCNAME" || { kill "${holder}" 2>/dev/null; return; }
  # With a terminator: the operand after it is a package, still global.
  : > "${LOG_FILE}"
  lane_run 'npm install -g -- clean@2.0.0'
  assert_status 0 "$FUNCNAME" || { kill "${holder}" 2>/dev/null; return; }
  assert_log_contains $'REAL\tnpm\tinstall\t-g\t--\tclean@2.0.0' "$FUNCNAME" || { kill "${holder}" 2>/dev/null; return; }
  kill "${holder}" 2>/dev/null
  wait "${holder}" 2>/dev/null
  # An option-like operand after the terminator stays local: the lane refuses it.
  : > "${LOG_FILE}"
  lane_run 'npm install clean@2.0.0 -- -g'
  assert_status 100 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  assert_err_contains_fragment 'the option terminator --' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm\tinstall' "$FUNCNAME" || return
  # Global by npm's effective setting: today's gate as well, with its delegate.
  : > "${LOG_FILE}"
  NPM_LOCKDIFF_EFFECTIVE_CONFIG_JSON='{"package-lock":true,"ignore-scripts":true,"global":true}' lane_run 'npm install clean@2.0.0'
  assert_status 0 "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tinstall\tclean@2.0.0' "$FUNCNAME" || return
  assert_err_not_contains_fragment '[lane: project]' "$FUNCNAME" || return
  assert_log_not_contains_fragment 'PROJECTION' "$FUNCNAME" || return
  pass "$FUNCNAME"
}


# ---- hardening (ticket 1648) ------------------------------------------------

# A listing of the project, to show nothing was written into it.
lane_listing() {
  (cd "${WORK_DIR}" && find . -path ./.git -prune -o -print | LC_ALL=C sort)
}

# Nothing is written to the project before publication: a dry run and every
# refused command leave no file or directory in it, npm's cache and logs included.
case_project_lane_nothing_is_written_to_the_project_before_publication() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-no-writes" kept@1.0.0
  # A project-relative cache: npm creates it in the directory it runs in.
  printf 'cache=./.npm-cache\n' > "${WORK_DIR}/.npmrc"
  local before
  before="$(lane_listing)"
  # refused: a cache inside the project is not carried (by the parity probe)
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" lane_run 'npm install clean@2.0.0'
  [[ "${STATUS}" -ne 0 ]] || { fail "$FUNCNAME: a project-relative cache was accepted"; return; }
  assert_lane_final_line install "$FUNCNAME" || return
  [[ "$(lane_listing)" == "${before}" ]] || { fail "$FUNCNAME: the refused command wrote into the project: $(diff <(printf '%s\n' "${before}") <(lane_listing) | head -3)"; return; }
  # an absolute cache inside the project
  printf 'x\n' > /dev/null
  rm -f "${WORK_DIR}/.npmrc"
  lane_commit
  before="$(lane_listing)"
  NPM_LOCKDIFF_EFFECTIVE_CONFIG_JSON="{\"package-lock\":true,\"ignore-scripts\":true,\"cache\":\"${WORK_DIR}/.npm\"}" \
    NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" lane_run 'npm install clean@2.0.0'
  assert_status 100 "$FUNCNAME" || return
  assert_err_contains_fragment 'npm setting cache inside the project' "$FUNCNAME" || return
  [[ "$(lane_listing)" == "${before}" ]] || { fail "$FUNCNAME: wrote into the project"; return; }
  # a dry run
  : > "${LOG_FILE}"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" lane_run 'npm install clean@2.0.0 --dry-run'
  assert_status 0 "$FUNCNAME" || return
  [[ "$(lane_listing)" == "${before}" ]] || { fail "$FUNCNAME: a dry run wrote into the project"; return; }
  # a decision refusal
  : > "${LOG_FILE}"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 dirty@3.0.0)" SAFE_AUDIT_EVIDENCE_HITS="{\"dirty@3.0.0\":${LANE_HIT_CRITICAL}}" \
    lane_run 'npm install dirty@3.0.0'
  assert_status 104 "$FUNCNAME" || return
  [[ "$(lane_listing)" == "${before}" ]] || { fail "$FUNCNAME: a refusal wrote into the project"; return; }
  # safe's own data directory inside the project: refused before anything is written.
  : > "${LOG_FILE}"
  SAFE_DATA_DIR_FOR_CASE="${WORK_DIR}/.safe-data" NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" lane_run 'npm install clean@2.0.0 --dry-run'
  assert_status 100 "$FUNCNAME" || return
  assert_err_contains_fragment "data directory or the temporary directory overlaps the project" "$FUNCNAME" || return
  [[ "$(lane_listing)" == "${before}" ]] || { fail "$FUNCNAME: a data root inside the project was written to"; return; }
  # a data directory that is a link into the project is judged by where it leads
  : > "${LOG_FILE}"
  mkdir -p "${HOME_DIR}/.local/share" "${WORK_DIR}/.inside-data"
  rm -rf "${HOME_DIR}/.local/share/safe"
  ln -s "${WORK_DIR}/.inside-data" "${HOME_DIR}/.local/share/safe"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" lane_run 'npm install clean@2.0.0 --dry-run'
  assert_status 100 "$FUNCNAME" || return
  assert_err_contains_fragment "overlaps the project" "$FUNCNAME" || return
  [[ -z "$(ls -A "${WORK_DIR}/.inside-data")" ]] || { fail "$FUNCNAME: safe wrote behind a link into the project"; return; }
  rm -rf "${HOME_DIR}/.local/share/safe" "${WORK_DIR}/.inside-data"
  pass "$FUNCNAME"
}

# A FIFO as the project's configuration file must not hold the command.
case_project_lane_special_file_as_configuration_does_not_hang() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-fifo" kept@1.0.0
  mkfifo "${WORK_DIR}/.npmrc"
  local before
  before="$(lane_digests)"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" lane_run 'npm install clean@2.0.0'
  assert_status 100 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  assert_err_contains_fragment '.npmrc that is not a regular file' "$FUNCNAME" || return
  assert_lane_untouched "${before}" "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# The HEAD comparison ignores replacement objects: an edited lockfile cannot be
# made to look committed with `git replace` (it is judged against the real blob).
case_project_lane_head_comparison_ignores_replacement_objects() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-replace-objects" kept@1.0.0
  local before blob edited
  lane_lock kept@1.0.0 other@1.0.0 > "${WORK_DIR}/package-lock.json"
  blob="$(git -C "${WORK_DIR}" rev-parse HEAD:package-lock.json)"
  edited="$(git -C "${WORK_DIR}" hash-object -w package-lock.json)"
  GIT_CONFIG_GLOBAL=/dev/null git -C "${WORK_DIR}" replace "${blob}" "${edited}"
  [[ "$(git -C "${WORK_DIR}" show HEAD:package-lock.json | sha256sum)" == "$(sha256sum < "${WORK_DIR}/package-lock.json")" ]] || { fail "$FUNCNAME: the fixture's replacement does not take"; return; }
  # With the replacement honoured the edited file would BE the baseline and nothing would
  # be introduced by it; ignored, the real committed blob is the baseline and the edit is judged.
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 other@1.0.0 clean@2.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" lane_run 'npm install clean@2.0.0'
  assert_status 0 "$FUNCNAME" || return
  assert_err_contains_fragment 'baseline: the lockfile committed at the head' "$FUNCNAME" || return
  assert_err_contains_fragment 'the lockfile on disk is not the baseline: 1 entries added on disk and kept in the judged target were judged as introduced' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# Admission is npm's: spellings the old shell patterns took are refused.
case_project_lane_admission_is_npms_not_a_pattern() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-admission-npm" kept@1.0.0
  local before arg
  before="$(lane_digests)"
  for arg in 'clean@1.2.3-x.tgz' 'clean@1.2.3-X.TGZ' 'clean@99999999999999999999.0.0' 'fixture.tgz' 'clean@npm:other@1.0.0' 'clean@1.0.0.tar'; do
    : > "${LOG_FILE}"
    NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" lane_run "npm install ${arg}"
    lane_unsupported_case "$FUNCNAME" install "${arg}" || return
    assert_lane_untouched "${before}" "$FUNCNAME: ${arg}" || return
  done
  # manifest: a mixed-case archive suffix, and typed overrides
  local body
  for body in '.dependencies.odd = "1.2.3-X.TGZ"' '.overrides = {"kept": 7}' '.overrides = {"kept": {"inner": ["1.0.0"]}}' \
      '.overrides = {"kept": {".": "file:../x"}}' '.dependencies.odd = "workspace:*"' '.dependencies.odd = "npm:other@^1"'; do
    lane_prepare "lane-admission-manifest-${RANDOM}" kept@1.0.0
    jq -c "${body}" "${WORK_DIR}/package.json" > "${WORK_DIR}/package.json.new"
    mv "${WORK_DIR}/package.json.new" "${WORK_DIR}/package.json"
    lane_commit
    lane_oneshot_case "$FUNCNAME" install 'manifest' 'npm install clean@2.0.0' || return
  done
  # the committed lockfile's own dependency edges
  lane_prepare "lane-admission-edge" kept@1.0.0
  lane_lock kept@1.0.0 | jq -c '.packages["node_modules/kept"].dependencies = {"sneaky": "github:user/repo"}' > "${WORK_DIR}/package-lock.json"
  lane_commit
  lane_oneshot_case "$FUNCNAME" install 'lockfile[node_modules/kept].dependencies.sneaky' 'npm install clean@2.0.0' || return
  # the capability of the delegated npm is read from ITS definitions: one that
  # merely echoes the options in its configuration listing (npm 10.9.2) refuses
  lane_prepare "lane-admission-capability" kept@1.0.0
  lane_oneshot_case "$FUNCNAME" install 'older than 11.12.1 or does not define allow-git' 'npm install clean@2.0.0' \
    'NODE_CAPABILITY_JSON={"version":"10.9.2","atFloor":false,"missing":["allow-git"]}' || return
  pass "$FUNCNAME"
}

# The malformed output of every producer the gate reads refuses; an unreadable
# committed graph is missing evidence (102), not a policy refusal.
case_project_lane_malformed_output_of_every_producer_refuses() {
  skip_lockdiff_case "$FUNCNAME" || return
  local pair kind status before
  for pair in 'graph-fails:102' 'graph-two-documents:102' 'graph-wrong-schema:102' 'target-graph-two-documents:100' 'target-graph-truncated:100' \
      'diff-two-documents:100' 'diff-no-request:100' 'diff-bad-request:100' 'admit-ok-with-refusals:100' 'admit-two-documents:100' 'admit-fails:100'; do
    kind="${pair%%:*}"
    status="${pair##*:}"
    lane_prepare "lane-producer-${kind}" kept@1.0.0
    before="$(lane_digests)"
    : > "${LOG_FILE}"
    SAFE_CORE_TAMPER="${kind}" NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" lane_run 'npm install clean@2.0.0'
    assert_status "${status}" "$FUNCNAME: ${kind}" || return
    assert_lane_final_line install "$FUNCNAME: ${kind}" || return
    assert_lane_untouched "${before}" "$FUNCNAME: ${kind}" || return
  done
  # npm's configuration probe, and the platform query of the selected node
  for kind in 'config:{"a":1}{"b":2}' 'config:not json' 'config:[]'; do
    lane_prepare "lane-producer-config-${RANDOM}" kept@1.0.0
    before="$(lane_digests)"
    NPM_CONFIG_LIST_RAW="${kind#config:}" NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" lane_run 'npm install clean@2.0.0'
    assert_status 100 "$FUNCNAME: ${kind}" || return
    assert_lane_final_line install "$FUNCNAME: ${kind}" || return
    assert_lane_untouched "${before}" "$FUNCNAME: ${kind}" || return
  done
  for kind in 'garbage' '{"os":"linux"}{"os":"linux","cpu":"x64","libc":null}' '{"os":"","cpu":"x64","libc":null}' '{"os":"linux","cpu":7,"libc":null}'; do
    lane_prepare "lane-producer-selection-${RANDOM}" kept@1.0.0
    before="$(lane_digests)"
    NODE_SELECTION_RAW="${kind}" NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" lane_run 'npm install clean@2.0.0'
    lane_unsupported_case "$FUNCNAME" install "selection ${kind}" || return
    assert_lane_untouched "${before}" "$FUNCNAME: selection ${kind}" || return
  done
  lane_prepare "lane-producer-selection-status" kept@1.0.0
  NODE_PROBE_STATUS=3 NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" lane_run 'npm install clean@2.0.0'
  lane_unsupported_case "$FUNCNAME" install 'selection status' || return
  pass "$FUNCNAME"
}

# The platform comes from the selected Node runtime, exactly: a 32-bit node on a
# 64-bit kernel selects ia32, and a value is passed untouched.
case_project_lane_selection_comes_from_the_selected_node_exactly() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-selection-node" kept@1.0.0
  NODE_SELECTION_JSON='{"os":"linux","cpu":"ia32","libc":"musl"}' NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" \
    NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" lane_run 'npm install clean@2.0.0'
  assert_status 0 "$FUNCNAME" || return
  grep -q $'^CORE_BIND_ARGS\t.*\t--os\tlinux\t--cpu\tia32\t--libc\tmusl\t' "${LOG_FILE}" || { fail "$FUNCNAME: the selection is not the node's: $(grep '^CORE_BIND_ARGS' "${LOG_FILE}" | tr '\t' ' ' | cut -c1-300)"; return; }
  # a value with trailing whitespace reaches the binder exactly (a command
  # substitution would have stripped it)
  lane_prepare "lane-selection-exact" kept@1.0.0
  NODE_SELECTION_JSON='{"os":"linux","cpu":"x64\n","libc":null}' NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" lane_run 'npm install clean@2.0.0'
  grep -qF -- $'--cpu\t$\'x64\\n\'' "${LOG_FILE}" || { fail "$FUNCNAME: a value was altered on its way: $(grep '^CORE_BIND_ARGS' "${LOG_FILE}" | cut -c1-200)"; return; }
  # npm's own os/cpu setting wins over the runtime
  lane_prepare "lane-selection-config" kept@1.0.0
  NODE_SELECTION_JSON='{"os":"linux","cpu":"x64","libc":"glibc"}' NPM_LOCKDIFF_EFFECTIVE_CONFIG_JSON='{"package-lock":true,"ignore-scripts":true,"cpu":"arm64"}' \
    NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" lane_run 'npm install clean@2.0.0'
  grep -qF -- $'--cpu\tarm64' "${LOG_FILE}" || { fail "$FUNCNAME: the configured cpu did not win"; return; }
  pass "$FUNCNAME"
}

# Everything npm and the binder print is cleaned at the lane's boundary; npm's
# status is kept, its diagnostic stays npm's.
case_project_lane_frozen_diagnostics_are_cleaned_and_npms_status_kept() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-diagnostics" kept@1.0.0
  NPM_CI_DIAGNOSTIC=1 NPM_CI_STATUS=7 NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" lane_run 'npm install clean@2.0.0'
  assert_status 7 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  assert_err_contains_fragment 'npm error code E500' "$FUNCNAME" || return
  assert_err_contains_fragment 'the frozen installation failed (npm exit 7' "$FUNCNAME" || return
  assert_err_not_contains_fragment 'hunter2' "$FUNCNAME" || return
  assert_err_not_contains_fragment 'abc123' "$FUNCNAME" || return
  ! grep -qP '[\x00-\x08\x0b-\x1f\x7f]' "${ERR_FILE}" || { fail "$FUNCNAME: a control character reached stderr"; return; }
  # the reused guard's own text is cleaned too
  lane_prepare "lane-guard-clean" kept@1.0.0
  printf '\033[31mevil=${FOO}\n' > "${HOME_DIR}/.npmrc"
  lane_run 'npm install clean@2.0.0'
  assert_status 100 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  ! grep -qP '[\x00-\x08\x0b-\x1f\x7f]' "${ERR_FILE}" || { fail "$FUNCNAME: a control character from a guard reached stderr"; return; }
  # a credential-bearing second operand is examined (the first one is valid)
  lane_prepare "lane-diagnostics-args" kept@1.0.0
  lane_run "npm install clean@2.0.0 'https://user:hunter2@example.invalid/x.tgz?token=abc123'"
  assert_status 100 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  assert_err_not_contains_fragment 'hunter2' "$FUNCNAME" || return
  assert_err_not_contains_fragment 'abc123' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# A signal to the shell while the binder runs is forwarded to it, and the
# binder's report still reaches the operator.
case_project_lane_signal_to_the_shell_is_forwarded_and_the_report_still_arrives() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-signal-shell" kept@1.0.0
  mkdir -p "${WORK_DIR}/.safe-bind-0123456789abcdef"
  local before
  before="$(lane_digests)"
  NPM_CI_SIGNAL_GATE=1 NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" lane_run 'npm install clean@2.0.0'
  assert_status 130 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  assert_err_contains_fragment 'interrupted before publication; the project is as it was' "$FUNCNAME" || return
  assert_err_contains_fragment 'left in the project, not removed: .safe-bind-0123456789abcdef' "$FUNCNAME" || return
  [[ "$(lane_digests)" == "${before}" && ! -e "${WORK_DIR}/node_modules" ]] || { fail "$FUNCNAME: the project changed"; return; }
  pass "$FUNCNAME"
}

# ---- review of the hardening (ticket 1648) ------------------------------------

# How many npm runs happened in the project's context: every `config list` but
# the first (the neutral probe that recognises a global command) and everything
# else that is npm.
lane_project_npm_runs() {
  grep -cP '^(PROJECTION|REAL)\tnpm\t' "${LOG_FILE}"
}

# S1. The project's own .npmrc is read as text, before any npm run in the
# project's context, against a short allow-list; a refusal names the setting and
# never its value.
case_project_lane_project_npmrc_is_admitted_as_text_before_any_npm_run() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-npmrc" kept@1.0.0
  local before line name
  before="$(lane_digests)"
  # a scoped registry whose URL carries a password: refused before npm runs, redacted
  printf '@p:registry=https://user:hunter2@npm.private.example/\n' > "${WORK_DIR}/.npmrc"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" lane_run 'npm install clean@2.0.0'
  lane_unsupported_case "$FUNCNAME" install 'a scoped registry with a password' || return
  assert_err_contains_fragment '.npmrc line 1' "$FUNCNAME" || return
  assert_err_contains_fragment '@p:registry' "$FUNCNAME" || return
  assert_err_not_contains_fragment 'hunter2' "$FUNCNAME" || return
  [[ "$(lane_project_npm_runs)" == "1" ]] || { fail "$FUNCNAME: npm ran in the project's context before the refusal ($(lane_project_npm_runs))"; return; }
  assert_lane_untouched "${before}" "$FUNCNAME" || return
  # each of these settings refuses, by name, with no npm run in the project's context
  for line in 'cache=./.npm' 'logs-dir=/tmp/x' 'prefix=/tmp/x' 'location=global' 'global=true' 'registry=https://npm.private.example/' \
      'registry=http://registry.npmjs.org/' '//registry.npmjs.org/:_authToken=abc' 'proxy=http://p' 'https-proxy=http://p' 'cafile=/x' \
      'strict-ssl=false' 'script-shell=/bin/x' 'git=/bin/git' 'allow-git=all' 'min-release-age=3' 'before=2020-01-01' 'workspaces=true' \
      'package-lock=false' 'package-lock-only=true' 'dry-run=true' 'ignore-scripts=false' 'registry=${REG}' '[section]' 'fund=false \'; do
    name="${line%%=*}"
    : > "${LOG_FILE}"
    printf '%s\n' "${line}" > "${WORK_DIR}/.npmrc"
    NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" lane_run 'npm install clean@2.0.0'
    lane_unsupported_case "$FUNCNAME" install "npmrc ${line}" || return
    [[ "$(lane_project_npm_runs)" == "1" ]] || { fail "$FUNCNAME: ${line}: npm ran in the project's context"; return; }
  done
  # the allow-list itself passes, and a repeated setting does not
  : > "${LOG_FILE}"
  printf '; kept small\nsave-exact=true\nsave-prefix=~\nengine-strict=false\nfund=false\naudit=false\nloglevel=warn\nprogress=false\nregistry=https://registry.npmjs.org/\n@scope:registry=https://registry.npmjs.org/\n' > "${WORK_DIR}/.npmrc"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" lane_run 'npm install clean@2.0.0'
  assert_status 0 "$FUNCNAME" || return
  printf 'fund=true\nfund=false\n' > "${WORK_DIR}/.npmrc"
  : > "${LOG_FILE}"
  lane_run 'npm install clean@2.0.0'
  lane_unsupported_case "$FUNCNAME" install 'a repeated setting' || return
  pass "$FUNCNAME"
}

# S2. Every npm run carries an explicit cache and log destination outside the
# project and no registry rewriting; the operator's destinations in the
# environment are checked as strings before the first npm run.
case_project_lane_every_npm_command_line_fixes_its_destinations() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-destinations" kept@1.0.0
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" lane_run 'npm install clean@2.0.0'
  assert_status 0 "$FUNCNAME" || return
  local line total=0
  while IFS= read -r line; do
    total=$((total + 1))
    [[ "${line}" == *"--cache=${HOME_DIR}/.local/share/safe/project-lane/npm-cache"* && "${line}" == *"--logs-dir=${HOME_DIR}/.local/share/safe/project-lane/npm-logs"* \
      && "${line}" == *"--replace-registry-host=never"* ]] || { fail "$FUNCNAME: a command line lacks its destinations: ${line}"; return; }
  done < <(grep -P '^(PROJECTION|REAL)\tnpm\t' "${LOG_FILE}")
  (( total >= 5 )) || { fail "$FUNCNAME: too few npm command lines seen"; return; }
  grep -q $'^REAL\tnpm\tci\t' "${LOG_FILE}" || { fail "$FUNCNAME: no frozen install"; return; }
  # operator-level destinations in the environment that lie inside the project refuse before any npm run
  local name
  for name in npm_config_cache NPM_CONFIG_CACHE npm_config_logs_dir npm_config_prefix npm_config_userconfig npm_config_globalconfig; do
    lane_prepare "lane-destinations-${name}" kept@1.0.0
    export "${name}=${WORK_DIR}/.inside"
    lane_run 'npm install clean@2.0.0'
    unset "${name}"
    lane_unsupported_case "$FUNCNAME" install "${name}" || return
    assert_err_contains_fragment "the environment setting ${name}" "$FUNCNAME" || return
    [[ "$(grep -c '^REAL' "${LOG_FILE}")" == "0" ]] || { fail "$FUNCNAME: ${name}: npm ran before the refusal"; return; }
  done
  lane_prepare "lane-destinations-relative" kept@1.0.0
  export npm_config_cache="relative-cache"
  lane_run 'npm install clean@2.0.0'
  unset npm_config_cache
  lane_unsupported_case "$FUNCNAME" install 'a relative cache' || return
  # one outside the project is carried (the command-line destination still wins)
  lane_prepare "lane-destinations-outside" kept@1.0.0
  export npm_config_cache="${CASE_DIR}/operator-cache"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" lane_run 'npm install clean@2.0.0'
  unset npm_config_cache
  assert_status 0 "$FUNCNAME" || return
  # report and state destinations are checked in both directions: the project inside the lane's directory
  lane_prepare "lane-destinations-overlap" kept@1.0.0
  mkdir -p "${CASE_DIR}/dr/project-lane"
  mv "${WORK_DIR}" "${CASE_DIR}/dr/project-lane/work"
  WORK_DIR="${CASE_DIR}/dr/project-lane/work"
  local before
  before="$(lane_listing)"
  SAFE_DATA_DIR_FOR_CASE="${CASE_DIR}/dr" NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" lane_run 'npm install clean@2.0.0 --dry-run'
  assert_status 100 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  assert_err_contains_fragment 'overlaps the project' "$FUNCNAME" || return
  [[ "$(lane_listing)" == "${before}" ]] || { fail "$FUNCNAME: the project was written to"; return; }
  [[ -z "$(ls -A "${CASE_DIR}/dr/project-lane" | grep -v '^work$')" ]] || { fail "$FUNCNAME: something was created beside the project in the lane's directory"; return; }
  pass "$FUNCNAME"
}

# S3. The capability is READ from the selected npm's own definitions: the floor, and
# every option the lane passes defined. One that merely echoes an option refuses.
case_project_lane_capability_is_read_from_the_npms_definitions() {
  skip_lockdiff_case "$FUNCNAME" || return
  local json
  # an npm that lacks them is a property of the host (see the routing cases); one whose probe cannot be read is breakage
  for json in 'not json' '{"version":"11.20.0","atFloor":true}'; do
    lane_prepare "lane-capability-${RANDOM}" kept@1.0.0
    : > "${LOG_FILE}"
    NODE_CAPABILITY_JSON="${json}" lane_run 'npm install clean@2.0.0'
    [[ "${STATUS}" -ne 0 ]] || { fail "$FUNCNAME: ${json} was accepted"; return; }
    assert_lane_final_line install "$FUNCNAME: ${json}" || return
    assert_log_not_contains_fragment 'PROJECTION' "$FUNCNAME" || return
  done
  lane_prepare "lane-capability-ok" kept@1.0.0
  NODE_CAPABILITY_JSON='{"version":"11.12.1","atFloor":true,"missing":[]}' NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" lane_run 'npm install clean@2.0.0'
  assert_status 0 "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# S4. One pair: the Node of the resolved npm's own installation; a launcher that
# cannot be followed refuses; NODE_ENV is carried.
case_project_lane_launcher_that_cannot_be_followed_refuses() {
  skip_lockdiff_case "$FUNCNAME" || return
  # a launcher that is neither a version manager's nor npm's own CLI file: it exits without running npm
  lane_prepare "lane-launcher-opaque" kept@1.0.0
  rm -f "${NODE_BIN}/npm"
  printf '#!/bin/sh\nexit 99\n' > "${NODE_BIN}/npm"
  chmod +x "${NODE_BIN}/npm"
  # its provenance cannot be established (which npm, which Node, from which search path): the lane's line,
  # never today's gate. The refusal of ci, dedupe and prune comes first.
  lane_run 'npm install clean@2.0.0'
  lane_unsupported_case "$FUNCNAME" install 'an opaque launcher' || return
  assert_err_contains_fragment 'an npm launcher the lane cannot follow' "$FUNCNAME" || return
  : > "${LOG_FILE}"
  lane_run 'npm ci'
  assert_status 100 "$FUNCNAME: ci" || return
  assert_err_contains_fragment 'npm ci is not routed by the project lane yet' "$FUNCNAME: ci" || return
  # npm's own CLI file with no Node beside its link
  lane_prepare "lane-launcher-no-node" kept@1.0.0
  rm -f "${NODE_BIN}/node"
  lane_run 'npm install clean@2.0.0'
  lane_unsupported_case "$FUNCNAME" install 'a launcher with no node beside it' || return
  assert_err_contains_fragment 'an npm launcher the lane cannot follow' "$FUNCNAME" || return
  # a version manager's launcher with no Node beside it
  lane_mise_layout "lane-launcher-manager-no-node" kept@1.0.0
  rm -f "${NODE_DIR}/bin/node"
  lane_run 'npm install clean@2.0.0'
  unset SAFE_TEST_PATH_MID
  lane_unsupported_case "$FUNCNAME" install 'a manager launcher with no node' || return
  assert_err_contains_fragment 'a version manager' "$FUNCNAME" || return
  # the launcher the manager names is the one that runs: a launcher that refuses an invocation is obeyed
  lane_mise_layout "lane-launcher-obeyed" kept@1.0.0
  printf '#!/usr/bin/env bash\nprintf "refused by the operator wrapper\\n" >&2\nexit 77\n' > "${NODE_DIR}/bin/npm"
  lane_run 'npm install clean@2.0.0'
  unset SAFE_TEST_PATH_MID
  [[ "${STATUS}" -ne 0 ]] || { fail "$FUNCNAME: a launcher that exits without running npm was bypassed"; return; }
  assert_lane_final_line install "$FUNCNAME" || return
  assert_log_not_contains_fragment 'PROJECTION' "$FUNCNAME" || return
  # NODE_ENV reaches every run (it changes npm's default omission)
  lane_prepare "lane-node-env" kept@1.0.0
  : > "${HOME_DIR}/.stub-log-env"
  NODE_ENV=production NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" lane_run 'npm install clean@2.0.0'
  assert_status 0 "$FUNCNAME" || return
  [[ "$(grep '^ENVNAMES' "${LOG_FILE}" | grep -c 'NODE_ENV')" == "$(grep -c '^ENVNAMES' "${LOG_FILE}")" ]] || { fail "$FUNCNAME: NODE_ENV was not carried to every run"; return; }
  pass "$FUNCNAME"
}

# S5. After the Go admission, the selected npm's own parser reads the same strings.
case_project_lane_the_selected_npms_parser_must_agree() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-agreement" kept@1.0.0
  local before
  before="$(lane_digests)"
  NODE_AGREEMENT_JSON='{"disagreements":[{"kind":"dep","name":"a","spec":"1.x"}]}' lane_run 'npm install clean@2.0.0'
  lane_unsupported_case "$FUNCNAME" install 'a disagreement' || return
  assert_err_contains_fragment "which npm's own parser does not read as a registry request" "$FUNCNAME" || return
  assert_log_not_contains_fragment 'PROJECTION' "$FUNCNAME" || return
  assert_lane_untouched "${before}" "$FUNCNAME" || return
  for json in 'garbage' '{"disagreements":"x"}'; do
    : > "${LOG_FILE}"
    NODE_AGREEMENT_JSON="${json}" lane_run 'npm install clean@2.0.0'
    assert_status 100 "$FUNCNAME" || return
    assert_lane_final_line install "$FUNCNAME" || return
  done
  pass "$FUNCNAME"
}

# 7. The documents the gate consumes, the rest of them; a committed lockfile that
# cannot be parsed is missing evidence.
case_project_lane_the_consumed_fields_of_every_document_are_checked() {
  skip_lockdiff_case "$FUNCNAME" || return
  local pair kind status before
  for pair in 'bind-no-problems:100' 'bind-no-inputs-changed:100' 'graph-bound-contradiction:102' 'admit-bad-names:100'; do
    kind="${pair%%:*}"
    status="${pair##*:}"
    lane_prepare "lane-consumed-${kind}" kept@1.0.0
    before="$(lane_digests)"
    : > "${LOG_FILE}"
    SAFE_CORE_TAMPER="${kind}" NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" lane_run 'npm install clean@2.0.0'
    assert_status "${status}" "$FUNCNAME: ${kind}" || return
    assert_lane_final_line install "$FUNCNAME: ${kind}" || return
    [[ "${kind}" == bind-* ]] || assert_lane_untouched "${before}" "$FUNCNAME: ${kind}" || return
  done
  # a committed lockfile that is not JSON: missing evidence, at the first step that meets it
  lane_prepare "lane-unparsable-lock" kept@1.0.0
  lane_lock kept@1.0.0 | head -c 60 > "${WORK_DIR}/package-lock.json"
  lane_commit
  before="$(lane_digests)"
  lane_run 'npm install clean@2.0.0'
  assert_status 102 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  assert_err_contains_fragment 'committed lockfile cannot be parsed' "$FUNCNAME" || return
  assert_lane_untouched "${before}" "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# 8. One renderer: bearer values, URL fragments, non-ASCII controls and a last line
# without a newline.
case_project_lane_one_renderer_for_every_child_diagnostic() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-renderer" kept@1.0.0
  NPM_CI_DIAGNOSTIC=2 NPM_CI_STATUS=9 NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" lane_run 'npm install clean@2.0.0'
  assert_status 9 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  assert_err_contains_fragment 'npm error code E500' "$FUNCNAME" || return
  assert_err_contains_fragment 'npm error last-line' "$FUNCNAME" || return
  local secret
  for secret in 'ghi123456' 'frag-secret' 'abc999'; do
    assert_err_not_contains_fragment "${secret}" "$FUNCNAME" || return
  done
  ! LC_ALL=C grep -qP '\xc2[\x80-\x9f]' "${ERR_FILE}" || { fail "$FUNCNAME: a C1 control reached stderr"; return; }
  pass "$FUNCNAME"
}

# 7. A cancellation that reaches the binder before it has produced any document (it is
# killed by the forwarded signal at start-up) is an interruption of the command: 128 plus
# the signal, one final line saying so, the project as it was, nothing left behind.
case_project_lane_a_binder_killed_at_start_up_is_an_interruption() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-signal-early" kept@1.0.0
  local before
  before="$(lane_digests)"
  SAFE_CORE_SIGNAL_EARLY=1 NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" \
    lane_run 'npm install clean@2.0.0'
  assert_status 143 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  assert_err_contains_fragment 'interrupted before the binder reported anything' "$FUNCNAME" || return
  assert_lane_untouched "${before}" "$FUNCNAME" || return
  assert_lane_no_leftover "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# After the projection, the decision runs before an unsupported edge refuses: a
# known block outranks it.
case_project_lane_a_known_block_outranks_an_unsupported_dependency_edge() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-edge-vs-block" kept@1.0.0
  local before target
  before="$(lane_digests)"
  target="$(lane_lock kept@1.0.0 evil@1.0.0 | jq -c '.packages["node_modules/kept"].dependencies = {"sneaky": "github:user/repo"}')"
  NPM_LOCK_MUTATION_JSON="${target}" SAFE_AUDIT_EVIDENCE_HITS='{"evil@1.0.0":[{"id":"MAL-2026-0009","severity":"critical","malware":true}]}' \
    lane_run 'npm install evil@1.0.0'
  assert_status 104 "$FUNCNAME" || return
  assert_err_contains_fragment 'known-malware record on evil@1.0.0' "$FUNCNAME" || return
  assert_lane_untouched "${before}" "$FUNCNAME" || return
  : > "${LOG_FILE}"
  NPM_LOCK_MUTATION_JSON="${target}" lane_run 'npm install evil@1.0.0'
  assert_status 100 "$FUNCNAME" || return
  assert_err_contains_fragment 'lockfile[node_modules/kept].dependencies.sneaky' "$FUNCNAME" || return
  pass "$FUNCNAME"
}


# ---- second review of the hardening (ticket 1648) -----------------------------

# 1. Configuration-file selectors and destination options in the caller's arguments
# refuse at the shell, before any npm run; the routing probe is given only what it
# needs; environment destinations are compared after npm's own trimming; storage is
# canonical and absolute.
case_project_lane_config_selectors_in_the_arguments_refuse_before_any_npm() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-selectors" kept@1.0.0
  local before opt
  before="$(lane_digests)"
  for opt in '--userconfig=/x/rc' '--userconfig /x/rc' '--globalconfig=/x/rc' '--globalconfig /x/rc' '--prefix=.' '--prefix .' '-C .' \
      '--cache=/x' '--cache /x' '--logs-dir=/x' '--logs-dir /x'; do
    : > "${LOG_FILE}"
    lane_run "npm install clean@2.0.0 ${opt}"
    lane_unsupported_case "$FUNCNAME" install "${opt}" || return
    assert_err_contains_fragment 'selects a configuration file or a destination before it can be admitted' "$FUNCNAME" || return
    [[ "$(grep -c '^REAL' "${LOG_FILE}")" == "0" ]] || { fail "$FUNCNAME: ${opt}: npm ran before the refusal"; return; }
  done
  # a special file named as a configuration file never reaches npm
  mkfifo "${WORK_DIR}/rc-fifo"
  : > "${LOG_FILE}"
  lane_run "npm install clean@2.0.0 --userconfig=${WORK_DIR}/rc-fifo"
  lane_unsupported_case "$FUNCNAME" install 'a fifo as userconfig' || return
  rm -f "${WORK_DIR}/rc-fifo"
  # the routing probe is given only the flags that decide global or local
  lane_prepare "lane-route-args" kept@1.0.0
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" lane_run 'npm install clean@2.0.0 --save-exact'
  assert_status 0 "$FUNCNAME" || return
  local first
  first="$(grep -m1 $'^REAL\tnpm\tconfig\t' "${LOG_FILE}")"
  [[ "${first}" != *clean@2.0.0* && "${first}" != *install* && "${first}" != *--save-exact* && "${first}" != *--prefix* ]] || { fail "$FUNCNAME: the routing probe saw the caller's arguments: ${first}"; return; }
  pass "$FUNCNAME"
}

case_project_lane_environment_destinations_are_compared_after_npms_trimming() {
  skip_lockdiff_case "$FUNCNAME" || return
  local label value
  for label in trimmed-ok blank envref tilde dotrel rel dotdot-ok newline inside-trailing-space; do
    lane_prepare "lane-envtrim-${label}" kept@1.0.0
    case "${label}" in
      trimmed-ok) value=" ${CASE_DIR}/x" ;;
      blank) value='   ' ;;
      envref) value='${HOME}/.cache' ;;
      tilde) value='~/.cache' ;;
      dotrel) value='./rel' ;;
      rel) value='rel' ;;
      dotdot-ok) value="${CASE_DIR}/a/../b" ;;
      newline) value="${CASE_DIR}/a"$'\n'"b" ;;
      inside-trailing-space) value="${WORK_DIR}/.inside " ;;
    esac
    : > "${LOG_FILE}"
    npm_config_cache="${value}" NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" lane_run 'npm install clean@2.0.0'
    case "${label}" in
      trimmed-ok|dotdot-ok)
        assert_status 0 "$FUNCNAME: ${label}" || return ;;
      *)
        lane_unsupported_case "$FUNCNAME" install "env ${label}" || return
        assert_err_contains_fragment 'npm_config_cache' "$FUNCNAME: ${label}" || return
        [[ "$(grep -c '^REAL' "${LOG_FILE}")" == "0" ]] || { fail "$FUNCNAME: ${label}: npm ran before the refusal"; return; } ;;
    esac
  done
  # a relative SAFE_DATA_DIR is made absolute from the caller's directory: here, the project
  lane_prepare "lane-relative-data" kept@1.0.0
  local before
  before="$(lane_listing)"
  SAFE_DATA_DIR_FOR_CASE="relative-data" NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" lane_run 'npm install clean@2.0.0 --dry-run'
  assert_status 100 "$FUNCNAME" || return
  assert_err_contains_fragment 'overlaps the project' "$FUNCNAME" || return
  [[ "$(lane_listing)" == "${before}" ]] || { fail "$FUNCNAME: a relative data directory wrote into the project"; return; }
  pass "$FUNCNAME"
}

# 2. The launcher the version manager names is the one that runs.
# (the cases are in case_project_lane_launcher_that_cannot_be_followed_refuses)

# 3. The routing probe keeps the operator's own configuration sources; a project
# inside a workspace root refuses.
case_project_lane_routing_keeps_the_operators_configuration_sources() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-route-global" kept@1.0.0
  mkdir -p "${HOME_DIR}/etc"
  printf 'location=global\n' > "${HOME_DIR}/etc/npmrc"
  lane_run 'npm install clean@2.0.0'
  assert_status 0 "$FUNCNAME" || return
  assert_err_not_contains_fragment '[lane: project]' "$FUNCNAME" || return
  assert_log_contains $'REAL\tnpm\tinstall\tclean@2.0.0' "$FUNCNAME" || return
  assert_log_not_contains_fragment 'PROJECTION' "$FUNCNAME" || return
  first="$(grep -m1 $'^REAL\tnpm\tconfig\t' "${LOG_FILE}")"
  [[ "${first}" != *--prefix* ]] || { fail "$FUNCNAME: the routing probe overrode the prefix"; return; }
  pass "$FUNCNAME"
}

case_project_lane_a_project_inside_a_workspace_root_refuses() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-workspace-member" kept@1.0.0
  local root="${CASE_DIR}/ws" member
  mkdir -p "${root}/packages"
  member="${root}/packages/member"
  mv "${WORK_DIR}" "${member}"
  rm -rf "${member}/.git"
  printf '{"name":"root","private":true,"workspaces":["packages/*"]}\n' > "${root}/package.json"
  (cd "${root}" && export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null && git init -q -b main && git add -A \
    && git -c user.name=l -c user.email=l@example.invalid commit -q -m base) >/dev/null 2>&1
  WORK_DIR="${member}"
  local before
  before="$(lane_digests)"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" lane_run 'npm install clean@2.0.0'
  lane_unsupported_case "$FUNCNAME" install 'a workspace member' || return
  assert_err_contains_fragment 'a project inside the workspace root' "$FUNCNAME" || return
  assert_lane_untouched "${before}" "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# 4. The lane runs no auditor; one matcher over every name it knows.
lane_private_case() { # <name> -- prepares a project and a registered namespace @p/*
  lane_prepare "$1" kept@1.0.0
  lane_private_store || return 1
}

case_project_lane_the_private_store_is_matched_over_every_name_without_an_auditor() {
  skip_lockdiff_case "$FUNCNAME" || return
  local before kind
  # by the manifest
  lane_private_case "lane-pm-manifest" || { fail "$FUNCNAME: store"; return; }
  jq -c '.dependencies["@p/lib"] = "^1.0.0"' "${WORK_DIR}/package.json" > "${WORK_DIR}/package.json.new"
  mv "${WORK_DIR}/package.json.new" "${WORK_DIR}/package.json"
  lane_commit
  before="$(lane_digests)"
  SAFE_AUDIT_REAL_PRIVATE=1 SAFE_CORE_BIN_FOR_AUDIT="${SAFE_CORE_TEST_BIN}" lane_run 'npm install clean@2.0.0'
  assert_status 100 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  assert_err_contains_fragment 'touches the private-registry store' "$FUNCNAME" || return
  assert_log_not_contains_fragment 'private-npm-project' "$FUNCNAME" || return
  assert_lane_untouched "${before}" "$FUNCNAME" || return
  # by a nested entry path of the committed lockfile
  lane_private_case "lane-pm-path" || { fail "$FUNCNAME: store"; return; }
  lane_lock kept@1.0.0 | jq -c '.packages["node_modules/kept/node_modules/@p/inner"] = {"version":"1.0.0","resolved":"https://registry.npmjs.org/@p/inner/-/inner-1.0.0.tgz","integrity":"'"$(lane_integrity inner)"'"}' > "${WORK_DIR}/package-lock.json"
  lane_commit
  lane_run 'npm install clean@2.0.0'
  assert_status 100 "$FUNCNAME" || return
  assert_err_contains_fragment 'touches the private-registry store' "$FUNCNAME" || return
  # by a legacy (version 2) identity
  lane_private_case "lane-pm-legacy" || { fail "$FUNCNAME: store"; return; }
  lane_lock kept@1.0.0 | jq -c '.lockfileVersion = 2 | .dependencies = {"legacyone": {"version": "1.0.0", "dependencies": {"x": {"version": "npm:@p/aliased@1.0.0"}}}}' > "${WORK_DIR}/package-lock.json"
  lane_commit
  lane_run 'npm install clean@2.0.0'
  assert_status 100 "$FUNCNAME" || return
  assert_err_contains_fragment 'touches the private-registry store' "$FUNCNAME" || return
  # by a name first found by the projection, before any public evidence is asked for
  lane_private_case "lane-pm-projected" || { fail "$FUNCNAME: store"; return; }
  before="$(lane_digests)"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0 @p/found@1.0.0)" lane_run 'npm install clean@2.0.0'
  assert_status 100 "$FUNCNAME" || return
  assert_err_contains_fragment 'touches the private-registry store' "$FUNCNAME" || return
  assert_log_not_contains_fragment 'EVIDENCE_INPUT' "$FUNCNAME" || return
  assert_lane_untouched "${before}" "$FUNCNAME" || return
  # a project that touches nothing goes on, with no auditor at all
  lane_private_case "lane-pm-untouched" || { fail "$FUNCNAME: store"; return; }
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" \
    SAFE_AUDIT_REAL_PRIVATE=1 SAFE_CORE_BIN_FOR_AUDIT="${SAFE_CORE_TEST_BIN}" lane_run 'npm install clean@2.0.0'
  assert_status 0 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'private-npm-project' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# 5. Agreement on the final admission too, before a dry run returns and before binding;
# a reference is resolved as Arborist resolves it, or refuses.
case_project_lane_the_final_admission_is_read_by_npms_parser_too() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-final-agreement" kept@1.0.0
  local before
  before="$(lane_digests)"
  NODE_AGREEMENT_SECOND_JSON='{"disagreements":[{"kind":"dep","name":"found","spec":"1.x"}]}' NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" \
    lane_run 'npm install clean@2.0.0 --dry-run'
  assert_status 100 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  assert_err_contains_fragment "which npm's own parser does not read as a registry request" "$FUNCNAME" || return
  assert_err_not_contains_fragment 'nothing was written to the project' "$FUNCNAME" || return
  assert_lane_untouched "${before}" "$FUNCNAME" || return
  : > "${LOG_FILE}"
  NODE_AGREEMENT_SECOND_JSON='{"disagreements":[{"kind":"dep","name":"found","spec":"1.x"}]}' NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" \
    lane_run 'npm install clean@2.0.0'
  assert_status 100 "$FUNCNAME" || return
  assert_log_not_contains_fragment 'CORE_BIND_ARGS' "$FUNCNAME" || return
  assert_lane_untouched "${before}" "$FUNCNAME" || return
  # a reference the root does not declare refuses; one it declares is admitted as the spec it denotes
  lane_prepare "lane-override-ref" kept@1.0.0
  jq -c '.overrides = {"kept": "$ghost"}' "${WORK_DIR}/package.json" > "${WORK_DIR}/package.json.new"
  mv "${WORK_DIR}/package.json.new" "${WORK_DIR}/package.json"
  lane_commit
  # committed: an established shape, today's gate
  lane_oneshot_case "$FUNCNAME" install 'a dependency the root does not declare' 'npm install clean@2.0.0' || return
  # the same edit made after the commit exists only in uncommitted changes: a refusal
  lane_prepare "lane-override-ref-dirty" kept@1.0.0
  jq -c '.overrides = {"kept": "$ghost"}' "${WORK_DIR}/package.json" > "${WORK_DIR}/package.json.new"
  mv "${WORK_DIR}/package.json.new" "${WORK_DIR}/package.json"
  lane_run 'npm install clean@2.0.0'
  lane_unsupported_case "$FUNCNAME" install 'an uncommitted undeclared reference' || return
  assert_err_contains_fragment 'a dependency the root does not declare' "$FUNCNAME" || return
  lane_prepare "lane-override-ref-ok" kept@1.0.0
  jq -c '.dependencies.other = "^2.0.0" | .overrides = {"kept": "$other"}' "${WORK_DIR}/package.json" > "${WORK_DIR}/package.json.new"
  mv "${WORK_DIR}/package.json.new" "${WORK_DIR}/package.json"
  lane_commit
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" lane_run 'npm install clean@2.0.0'
  assert_status 0 "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# 6. A committed lockfile the core cannot decode is missing evidence (102): the wrong
# shape and repeated members, beside the truncated one.
case_project_lane_a_committed_lockfile_of_the_wrong_shape_is_missing_evidence() {
  skip_lockdiff_case "$FUNCNAME" || return
  local body before
  for body in '{"lockfileVersion":3,"packages":{"":{},"node_modules/kept":{"version":"1.0.0","dependencies":["x"]}}}' \
      '{"lockfileVersion":3,"packages":{"":{}},"packages":{"":{}}}'; do
    lane_prepare "lane-wrong-shape-${RANDOM}" kept@1.0.0
    printf '%s\n' "${body}" > "${WORK_DIR}/package-lock.json"
    lane_commit
    before="$(lane_digests)"
    lane_run 'npm install clean@2.0.0'
    assert_status 102 "$FUNCNAME: ${body}" || return
    assert_lane_final_line install "$FUNCNAME" || return
    assert_err_contains_fragment 'committed lockfile cannot be decoded' "$FUNCNAME" || return
    assert_lane_untouched "${before}" "$FUNCNAME" || return
  done
  # a readable, unsupported source is never missing evidence: committed it takes the one-shot route,
  # uncommitted it is a policy refusal
  lane_prepare "lane-readable-unsupported" kept@1.0.0
  lane_lock kept@1.0.0 | jq -c '.packages["node_modules/kept"].dependencies = {"s": "github:u/r"}' > "${WORK_DIR}/package-lock.json"
  lane_commit
  lane_oneshot_case "$FUNCNAME" install 'lockfile[node_modules/kept]' 'npm install clean@2.0.0' || return
  lane_prepare "lane-readable-unsupported-dirty" kept@1.0.0
  lane_lock kept@1.0.0 | jq -c '.packages["node_modules/kept"].dependencies = {"s": "github:u/r"}' > "${WORK_DIR}/package-lock.json"
  lane_run 'npm install clean@2.0.0'
  assert_status 100 "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# 7. Header casing, format characters; a binder that dies of the forwarded signal before
# it produced a document is an interruption.
case_project_lane_the_renderer_ignores_case_and_filters_format_characters() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-renderer-case" kept@1.0.0
  NPM_CI_DIAGNOSTIC=3 NPM_CI_STATUS=9 NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" lane_run 'npm install clean@2.0.0'
  assert_status 9 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  assert_err_contains_fragment 'npm error code E500' "$FUNCNAME" || return
  assert_err_not_contains_fragment 'UPPERTOKEN12345' "$FUNCNAME" || return
  assert_err_not_contains_fragment 'dXNlcjpwYXNzd29yZA' "$FUNCNAME" || return
  ! LC_ALL=C grep -qP '\xe2\x80[\x8b-\x8f\xa8-\xae]' "${ERR_FILE}" || { fail "$FUNCNAME: a directional mark reached stderr"; return; }
  assert_err_contains_fragment 'npm error mark RTLX' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# 8. smaller points
case_project_lane_the_update_notifier_is_forced_off_and_a_nul_platform_refuses() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-notifier" kept@1.0.0
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" lane_run 'npm install clean@2.0.0'
  assert_status 0 "$FUNCNAME" || return
  local line
  while IFS= read -r line; do
    [[ "${line}" == *"--update-notifier=false"* && "${line}" == *"--logs-max=0"* ]] || { fail "$FUNCNAME: a command line lacks them: ${line}"; return; }
  done < <(grep -P '^(PROJECTION|REAL)\tnpm\t' "${LOG_FILE}")
  grep -q $'^CORE_BIND_ARGS\t.*--update-notifier=false' "${LOG_FILE}" || { fail "$FUNCNAME: the frozen install does not force it off"; return; }
  lane_prepare "lane-notifier-rc" kept@1.0.0
  printf 'update-notifier=false\n' > "${WORK_DIR}/.npmrc"
  lane_run 'npm install clean@2.0.0'
  lane_unsupported_case "$FUNCNAME" install 'update-notifier in the npmrc' || return
  assert_err_contains_fragment '.npmrc line 1' "$FUNCNAME" || return
  assert_err_contains_fragment 'update-notifier' "$FUNCNAME" || return
  lane_prepare "lane-nul-platform" kept@1.0.0
  NODE_SELECTION_JSON='{"os":"linux","cpu":"x\u00006","libc":null}' lane_run 'npm install clean@2.0.0'
  lane_unsupported_case "$FUNCNAME" install 'a NUL in a platform value' || return
  assert_err_contains_fragment "platform selection cannot be read" "$FUNCNAME" || return
  pass "$FUNCNAME"
}


# ---- the baseline (ticket 1632) ---------------------------------------------------

# Where safe keeps its record of the last judged lockfile of a project, and what it holds.
lane_baseline_records() {
  compgen -G "${HOME_DIR}/.local/share/safe/project-lane/state/project-baseline/*/package-lock.json/*" || true
}

lane_stored_digest() { # the digest of the most recently written record, "none" without one
  local newest
  newest="$(lane_baseline_records | xargs -r ls -t 2>/dev/null | head -n 1)"
  [[ -n "${newest}" ]] || { printf 'none'; return 0; }
  basename -- "${newest}"
}

lane_record_count() { lane_baseline_records | wc -l; }

# the digest a lockfile is recorded under
lane_digest_of() { sha256sum < "$1" | cut -d' ' -f1; }

LANE_TWO_DEPS_MANIFEST='{"name":"lane-test","version":"1.0.0","dependencies":{"kept":"^1.0.0","clean":"^2.0.0","other":"^1.0.0"}}'

# A first passing command in a committed project, leaving the stored baseline behind.
lane_first_command() { # <case label>
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" lane_run 'npm install clean@2.0.0'
  assert_status 0 "$1: the first command" || return 1
  [[ "$(lane_stored_digest)" == "$(sha256sum < "${WORK_DIR}/package-lock.json" | cut -d' ' -f1)" ]] || { fail "$1: the stored baseline is not the lockfile published"; return 1; }
}

case_project_lane_baseline_a_hand_edited_lockfile_is_judged_against_the_committed_one() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-baseline-edited" kept@1.0.0
  local before
  # the edit brings in vuln@1.0.0, which carries a critical advisory: introduced, not "already present"
  lane_lock kept@1.0.0 vuln@1.0.0 > "${WORK_DIR}/package-lock.json"
  before="$(lane_digests)"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 vuln@1.0.0 clean@2.0.0)" SAFE_AUDIT_EVIDENCE_HITS="{\"vuln@1.0.0\":${LANE_HIT_CRITICAL}}" \
    lane_run 'npm install clean@2.0.0'
  assert_status 104 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  assert_err_contains_fragment 'baseline: the lockfile committed at the head of the git work tree' "$FUNCNAME" || return
  assert_err_contains_fragment 'the lockfile on disk is not the baseline: 1 entries added on disk and kept in the judged target were judged as introduced' "$FUNCNAME" || return
  assert_lane_untouched "${before}" "$FUNCNAME" || return
  [[ "$(lane_stored_digest)" == none ]] || { fail "$FUNCNAME: a refusal advanced the stored baseline"; return; }
  # the same edit with a clean evidence: judged, passes, and what it published is the new baseline
  : > "${LOG_FILE}"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 vuln@1.0.0 clean@2.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" lane_run 'npm install clean@2.0.0'
  assert_status 0 "$FUNCNAME" || return
  assert_err_contains_fragment 'the lockfile on disk is not the baseline' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_project_lane_baseline_a_generated_lockfile_in_a_project_that_had_none_is_entirely_introduced() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-baseline-generated" kept@1.0.0
  git -C "${WORK_DIR}" rm -q --cached package-lock.json
  git -C "${WORK_DIR}" -c user.name=l -c user.email=l@example.invalid commit -q -m "no lockfile"
  local before
  before="$(lane_digests)"
  # kept@1.0.0 carries a critical advisory; with no established baseline everything is introduced
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" SAFE_AUDIT_EVIDENCE_HITS="{\"kept@1.0.0\":${LANE_HIT_CRITICAL}}" lane_run 'npm install clean@2.0.0'
  assert_status 104 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  assert_err_contains_fragment 'baseline: empty' "$FUNCNAME" || return
  assert_err_contains_fragment 'the lockfile on disk is not the baseline: 1 entries added on disk and kept in the judged target were judged as introduced' "$FUNCNAME" || return
  assert_lane_untouched "${before}" "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_project_lane_baseline_no_lockfile_anywhere_introduces_the_whole_resolved_graph() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-baseline-none" kept@1.0.0
  git -C "${WORK_DIR}" rm -q package-lock.json
  git -C "${WORK_DIR}" -c user.name=l -c user.email=l@example.invalid commit -q -m "no lockfile"
  [[ ! -e "${WORK_DIR}/package-lock.json" ]] || { fail "$FUNCNAME: fixture"; return; }
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" SAFE_AUDIT_EVIDENCE_HITS="{\"kept@1.0.0\":${LANE_HIT_CRITICAL}}" lane_run 'npm install clean@2.0.0'
  assert_status 104 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  assert_err_contains_fragment 'baseline: empty' "$FUNCNAME" || return
  [[ ! -e "${WORK_DIR}/package-lock.json" && ! -e "${WORK_DIR}/node_modules" ]] || { fail "$FUNCNAME: the refusal wrote something"; return; }
  # no advisory: the generated lockfile is published, the tree is installed, and it is the baseline
  : > "${LOG_FILE}"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" lane_run 'npm install clean@2.0.0'
  assert_status 0 "$FUNCNAME" || return
  assert_err_contains_fragment 'baseline: empty' "$FUNCNAME" || return
  assert_err_contains_fragment '2 packages added' "$FUNCNAME" || return
  [[ -f "${WORK_DIR}/package-lock.json" && -f "${WORK_DIR}/node_modules/clean/package.json" ]] || { fail "$FUNCNAME: not published"; return; }
  [[ "$(lane_stored_digest)" == "$(sha256sum < "${WORK_DIR}/package-lock.json" | cut -d' ' -f1)" ]] || { fail "$FUNCNAME: not stored"; return; }
  pass "$FUNCNAME"
}

case_project_lane_baseline_two_commands_in_a_row_the_second_starts_from_the_first() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-baseline-two" kept@1.0.0
  lane_first_command "$FUNCNAME" || return
  assert_err_contains_fragment 'baseline: the lockfile committed' "$FUNCNAME" || return
  # nothing is committed; clean@2.0.0 now carries an advisory, and the second command adds other
  : > "${LOG_FILE}"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0 other@1.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_TWO_DEPS_MANIFEST}" \
    SAFE_AUDIT_EVIDENCE_HITS="{\"clean@2.0.0\":${LANE_HIT_CRITICAL}}" lane_run 'npm install other@1.0.0'
  assert_status 0 "$FUNCNAME" || return
  assert_err_contains_fragment 'baseline: a lockfile safe judged clear and recorded' "$FUNCNAME" || return
  assert_err_not_contains_fragment 'the lockfile on disk is not the baseline' "$FUNCNAME" || return
  assert_err_contains_fragment '1 already present (highest: critical)' "$FUNCNAME" || return
  assert_err_contains_fragment '1 packages added' "$FUNCNAME" || return
  [[ "$(lane_stored_digest)" == "$(sha256sum < "${WORK_DIR}/package-lock.json" | cut -d' ' -f1)" ]] || { fail "$FUNCNAME: the second result is not stored"; return; }
  pass "$FUNCNAME"
}

case_project_lane_baseline_a_dirty_edit_after_a_verified_uncommitted_install_is_judged() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-baseline-dirty" kept@1.0.0
  lane_first_command "$FUNCNAME" || return
  local stored before
  stored="$(lane_stored_digest)"
  lane_lock kept@1.0.0 clean@2.0.0 vuln@1.0.0 > "${WORK_DIR}/package-lock.json"
  before="$(lane_digests)"
  : > "${LOG_FILE}"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0 vuln@1.0.0 other@1.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_TWO_DEPS_MANIFEST}" \
    SAFE_AUDIT_EVIDENCE_HITS="{\"vuln@1.0.0\":${LANE_HIT_CRITICAL}}" lane_run 'npm install other@1.0.0'
  assert_status 104 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  # neither the committed nor the stored lockfile: judged against the committed one
  assert_err_contains_fragment 'baseline: the lockfile committed at the head' "$FUNCNAME" || return
  assert_err_contains_fragment 'the lockfile on disk is not the baseline: 2 entries added on disk and kept in the judged target were judged as introduced' "$FUNCNAME" || return
  [[ "$(lane_digests)" == "${before}" ]] || { fail "$FUNCNAME: a refusal changed the project"; return; }
  [[ "$(lane_stored_digest)" == "${stored}" ]] || { fail "$FUNCNAME: a refusal advanced the stored baseline"; return; }
  pass "$FUNCNAME"
}

case_project_lane_baseline_a_fresh_clone_starts_from_its_committed_lockfile() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-baseline-clone" kept@1.0.0
  lane_first_command "$FUNCNAME" || return
  # a clone of the committed state: its lockfile is the committed one, whatever the first project stored
  local clone="${CASE_DIR}/clone"
  GIT_CONFIG_GLOBAL=/dev/null git clone -q "${WORK_DIR}" "${clone}" || { fail "$FUNCNAME: clone"; return; }
  WORK_DIR="${clone}"
  : > "${LOG_FILE}"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" \
    SAFE_AUDIT_EVIDENCE_HITS="{\"kept@1.0.0\":${LANE_HIT_CRITICAL}}" lane_run 'npm install clean@2.0.0'
  assert_status 0 "$FUNCNAME" || return
  assert_err_contains_fragment 'baseline: the lockfile committed at the head' "$FUNCNAME" || return
  assert_err_contains_fragment '1 already present (highest: critical)' "$FUNCNAME" || return
  assert_err_not_contains_fragment 'the lockfile on disk is not the baseline' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_project_lane_baseline_a_project_outside_git_starts_empty_then_from_what_safe_stored() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-baseline-no-git" kept@1.0.0
  rm -rf "${WORK_DIR}/.git"
  local before
  before="$(lane_digests)"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" SAFE_AUDIT_EVIDENCE_HITS="{\"kept@1.0.0\":${LANE_HIT_CRITICAL}}" lane_run 'npm install clean@2.0.0'
  assert_status 104 "$FUNCNAME" || return
  assert_err_contains_fragment 'baseline: empty' "$FUNCNAME" || return
  assert_lane_untouched "${before}" "$FUNCNAME" || return
  : > "${LOG_FILE}"
  lane_first_command "$FUNCNAME" || return
  assert_err_contains_fragment 'baseline: empty' "$FUNCNAME" || return
  # now the stored one is the baseline: the advisory kept@1.0.0 carries is already present
  : > "${LOG_FILE}"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0 other@1.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_TWO_DEPS_MANIFEST}" \
    SAFE_AUDIT_EVIDENCE_HITS="{\"kept@1.0.0\":${LANE_HIT_CRITICAL}}" lane_run 'npm install other@1.0.0'
  assert_status 0 "$FUNCNAME" || return
  assert_err_contains_fragment 'baseline: a lockfile safe judged clear and recorded' "$FUNCNAME" || return
  assert_err_contains_fragment '1 already present (highest: critical)' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_project_lane_baseline_nothing_is_recorded_unless_the_decision_is_clear() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-baseline-advance" kept@1.0.0
  lane_first_command "$FUNCNAME" || return
  local stored label before want records
  stored="$(lane_stored_digest)"
  records="$(lane_record_count)"
  before="$(lane_digests)"
  for label in refusal failed-materialisation tree-mismatch dry-run missing-evidence package-lock-only-refusal; do
    : > "${LOG_FILE}"
    case "${label}" in
      refusal)
        NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0 dirty@3.0.0)" SAFE_AUDIT_EVIDENCE_HITS="{\"dirty@3.0.0\":${LANE_HIT_CRITICAL}}" \
          NPM_PROJECTION_MANIFEST_JSON="${LANE_TWO_DEPS_MANIFEST}" lane_run 'npm install dirty@3.0.0' ;;
      failed-materialisation)
        NPM_CI_STATUS=7 NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0 other@1.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_TWO_DEPS_MANIFEST}" \
          lane_run 'npm install other@1.0.0' ;;
      tree-mismatch)
        NPM_CI_SKIP="node_modules/other" NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0 other@1.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_TWO_DEPS_MANIFEST}" \
          lane_run 'npm install other@1.0.0' ;;
      dry-run)
        NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0 other@1.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_TWO_DEPS_MANIFEST}" \
          lane_run 'npm install other@1.0.0 --dry-run' ;;
      missing-evidence)
        NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0 other@1.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_TWO_DEPS_MANIFEST}" \
          SAFE_AUDIT_EVIDENCE_MISSING="other@1.0.0" lane_run 'npm install other@1.0.0' ;;
      package-lock-only-refusal)
        NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0 dirty@3.0.0)" SAFE_AUDIT_EVIDENCE_HITS="{\"dirty@3.0.0\":${LANE_HIT_CRITICAL}}" \
          NPM_PROJECTION_MANIFEST_JSON="${LANE_TWO_DEPS_MANIFEST}" lane_run 'npm install dirty@3.0.0 --package-lock-only' ;;
    esac
    case "${label}" in
      refusal|package-lock-only-refusal) want=104 ;;
      failed-materialisation) want=7 ;;
      tree-mismatch) want=100 ;;
      missing-evidence) want=102 ;;
      dry-run) want=0 ;;
    esac
    assert_status "${want}" "$FUNCNAME: ${label}" || return
    # A refusal, a dry run and missing evidence record nothing: the decision was not clear, or
    # nothing was to be written. A lockfile judged clear IS recorded before the binder runs; when
    # the materialisation then fails the record is harmless (see the case that follows).
    case "${label}" in
      failed-materialisation|tree-mismatch) ;;
      *) [[ "$(lane_stored_digest)" == "${stored}" && "$(lane_record_count)" == "${records}" ]] || { fail "$FUNCNAME: ${label} recorded something"; return; } ;;
    esac
    [[ "$(lane_digests)" == "${before}" ]] || { fail "$FUNCNAME: ${label} changed the project's files"; return; }
    stored="$(lane_stored_digest)"
    records="$(lane_record_count)"
    assert_lane_no_leftover "$FUNCNAME: ${label}" || return
  done
  pass "$FUNCNAME"
}

case_project_lane_baseline_a_committed_lockfile_that_cannot_be_decoded_is_not_an_empty_baseline() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-baseline-bad-committed" kept@1.0.0
  lane_lock kept@1.0.0 | head -c 60 > "${WORK_DIR}/package-lock.json"
  lane_commit
  lane_lock kept@1.0.0 clean@2.0.0 > "${WORK_DIR}/package-lock.json"
  local before
  before="$(lane_digests)"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" lane_run 'npm install clean@2.0.0'
  assert_status 102 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  assert_err_contains_fragment 'the committed lockfile cannot be parsed' "$FUNCNAME" || return
  [[ "$(lane_digests)" == "${before}" ]] || { fail "$FUNCNAME: the project changed"; return; }
  pass "$FUNCNAME"
}

case_project_lane_package_lock_only_publishes_the_judged_files_and_installs_nothing() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-lock-only" kept@1.0.0
  mkdir -p "${WORK_DIR}/node_modules/precious"
  printf 'keep' > "${WORK_DIR}/node_modules/precious/file"
  local target
  target="$(lane_lock kept@1.0.0 clean@2.0.0)"
  NPM_LOCK_MUTATION_JSON="${target}" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" lane_run 'npm install clean@2.0.0 --package-lock-only'
  assert_status 0 "$FUNCNAME" || return
  assert_err_contains_fragment 'project lane: --package-lock-only: the judged package.json and package-lock.json were published; no tree was installed' "$FUNCNAME" || return
  [[ "$(cat "${WORK_DIR}/package-lock.json")" == "${target}" ]] || { fail "$FUNCNAME: the lockfile is not the judged one"; return; }
  [[ "$(cat "${WORK_DIR}/package.json")" == "${LANE_CLEAN_ADD_MANIFEST}" ]] || { fail "$FUNCNAME: the manifest is not the judged one"; return; }
  [[ "$(cat "${WORK_DIR}/node_modules/precious/file")" == keep && ! -e "${WORK_DIR}/node_modules/clean" ]] || { fail "$FUNCNAME: the tree was touched"; return; }
  assert_log_not_contains_fragment $'REAL\tnpm\tci' "$FUNCNAME" || return
  grep -q $'^CORE_BIND_ARGS\t.*--files-only' "${LOG_FILE}" || { fail "$FUNCNAME: the binder was not asked for a files-only publication"; return; }
  ! grep -q $'^CORE_BIND_ARGS\t.*--env-file' "${LOG_FILE}" || { fail "$FUNCNAME: a files-only publication was given an environment"; return; }
  assert_lane_no_leftover "$FUNCNAME" || return
  [[ "$(lane_stored_digest)" == "$(sha256sum < "${WORK_DIR}/package-lock.json" | cut -d' ' -f1)" ]] || { fail "$FUNCNAME: the baseline was not advanced"; return; }
  # the next command starts from it
  : > "${LOG_FILE}"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0 other@1.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_TWO_DEPS_MANIFEST}" lane_run 'npm install other@1.0.0'
  assert_status 0 "$FUNCNAME" || return
  assert_err_contains_fragment 'baseline: a lockfile safe judged clear and recorded' "$FUNCNAME" || return
  # a dry run beside it writes nothing
  lane_prepare "lane-lock-only-dry" kept@1.0.0
  local before
  before="$(lane_digests)"
  NPM_LOCK_MUTATION_JSON="${target}" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" lane_run 'npm install clean@2.0.0 --package-lock-only --dry-run'
  assert_status 0 "$FUNCNAME" || return
  assert_lane_untouched "${before}" "$FUNCNAME" || return
  [[ "$(lane_stored_digest)" == none ]] || { fail "$FUNCNAME: a dry run advanced the baseline"; return; }
  pass "$FUNCNAME"
}


# ---- review of the baseline (ticket 1632, second pass) ---------------------------------

# 2. Every lockfile on disk is admitted before npm uses it.
case_project_lane_baseline_a_hand_edited_lockfile_is_admitted_before_the_projection() {
  skip_lockdiff_case "$FUNCNAME" || return
  local how
  for how in other-host no-hash link; do
    lane_prepare "lane-baseline-admit-${how}" kept@1.0.0
    case "${how}" in
      other-host) lane_lock kept@1.0.0 evil@1.0.0 | jq -c '.packages["node_modules/evil"].resolved = "https://evil.example/evil/-/evil-1.0.0.tgz"' > "${WORK_DIR}/package-lock.json" ;;
      no-hash) lane_lock kept@1.0.0 evil@1.0.0 | jq -c 'del(.packages["node_modules/evil"].integrity)' > "${WORK_DIR}/package-lock.json" ;;
      link) lane_lock kept@1.0.0 | jq -c '.packages["node_modules/lnk"] = {"resolved": "../outside", "link": true}' > "${WORK_DIR}/package-lock.json" ;;
    esac
    local before
    before="$(lane_digests)"
    : > "${LOG_FILE}"
    NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" lane_run 'npm install clean@2.0.0'
    lane_unsupported_case "$FUNCNAME" install "${how}" || return
    assert_err_contains_fragment 'the lockfile on disk' "$FUNCNAME: ${how}" || return
    assert_log_not_contains_fragment 'PROJECTION' "$FUNCNAME: ${how}" || return
    assert_lane_untouched "${before}" "$FUNCNAME: ${how}" || return
  done
  pass "$FUNCNAME"
}

# 3. The committed lockfile is read with three outcomes.
lane_break_repo() { # <how> -- damages the project's repository
  local how="$1" commit tree blob
  commit="$(git -C "${WORK_DIR}" rev-parse HEAD)"
  tree="$(git -C "${WORK_DIR}" rev-parse 'HEAD^{tree}')"
  blob="$(git -C "${WORK_DIR}" rev-parse HEAD:package-lock.json)"
  case "${how}" in
    commit) rm -f "${WORK_DIR}/.git/objects/${commit:0:2}/${commit:2}" ;;
    tree) rm -f "${WORK_DIR}/.git/objects/${tree:0:2}/${tree:2}" ;;
    blob) rm -f "${WORK_DIR}/.git/objects/${blob:0:2}/${blob:2}" ;;
    blob-corrupt) chmod u+w "${WORK_DIR}/.git/objects/${blob:0:2}/${blob:2}"; printf 'not a zlib stream' > "${WORK_DIR}/.git/objects/${blob:0:2}/${blob:2}" ;;
    head) printf 'garbage\n' > "${WORK_DIR}/.git/HEAD" ;;
    head-to-tree) printf '%s\n' "${tree}" > "${WORK_DIR}/.git/HEAD" ;;
    symlink)
      rm -f "${WORK_DIR}/package-lock.json"
      ln -s real-lock.json "${WORK_DIR}/package-lock.json"
      lane_lock kept@1.0.0 > "${WORK_DIR}/real-lock.json"
      lane_commit
      rm -f "${WORK_DIR}/package-lock.json"
      ;;
    submodule)
      git -C "${WORK_DIR}" rm -q --cached package-lock.json
      git -C "${WORK_DIR}" update-index --add --cacheinfo "160000,${commit},package-lock.json"
      git -C "${WORK_DIR}" -c user.name=l -c user.email=l@example.invalid commit -q -m sub
      ;;
  esac
}

case_project_lane_baseline_the_committed_lockfile_is_read_with_three_outcomes() {
  skip_lockdiff_case "$FUNCNAME" || return
  local how before
  # unreadable: never an established absence, so neither the stored baseline nor the empty one applies
  for how in commit tree blob blob-corrupt head head-to-tree symlink submodule; do
    lane_prepare "lane-committed-${how}" kept@1.0.0
    lane_first_command "$FUNCNAME: ${how}" || return
    lane_break_repo "${how}"
    lane_lock kept@1.0.0 clean@2.0.0 other@1.0.0 > "${WORK_DIR}/package-lock.json"
    before="$(lane_digests)"
    : > "${LOG_FILE}"
    NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0 other@1.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_TWO_DEPS_MANIFEST}" lane_run 'npm install other@1.0.0'
    assert_status 102 "$FUNCNAME: ${how}" || return
    assert_lane_final_line install "$FUNCNAME: ${how}" || return
    assert_err_contains_fragment 'the committed lockfile cannot be read' "$FUNCNAME: ${how}" || return
    assert_log_not_contains_fragment 'EVIDENCE_INPUT' "$FUNCNAME: ${how}" || return
    [[ "$(lane_digests)" == "${before}" ]] || { fail "$FUNCNAME: ${how}: the project changed"; return; }
  done
  # established absence: an unborn branch (the stored baseline then applies), and a path absent from the tree
  lane_prepare "lane-committed-unborn" kept@1.0.0
  lane_first_command "$FUNCNAME: unborn" || return
  git -C "${WORK_DIR}" checkout -q --orphan fresh
  git -C "${WORK_DIR}" rm -rfq --cached . >/dev/null 2>&1
  : > "${LOG_FILE}"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0 other@1.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_TWO_DEPS_MANIFEST}" lane_run 'npm install other@1.0.0'
  assert_status 0 "$FUNCNAME: unborn branch" || return
  assert_err_contains_fragment 'baseline: a lockfile safe judged clear and recorded' "$FUNCNAME: unborn branch" || return
  # present, in a subdirectory of the repository
  lane_prepare "lane-committed-subdir" kept@1.0.0
  mkdir -p "${WORK_DIR}/pkg"
  mv "${WORK_DIR}/package.json" "${WORK_DIR}/package-lock.json" "${WORK_DIR}/pkg/"
  lane_commit
  WORK_DIR="${WORK_DIR}/pkg"
  : > "${LOG_FILE}"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" lane_run 'npm install clean@2.0.0'
  assert_status 0 "$FUNCNAME: subdirectory" || return
  assert_err_contains_fragment 'baseline: the lockfile committed at the head' "$FUNCNAME: subdirectory" || return
  # the caller's GIT_* variables name another repository: they do not reach the lane's git
  lane_prepare "lane-committed-git-env" kept@1.0.0
  : > "${LOG_FILE}"
  GIT_DIR="${CASE_DIR}/not-a-repository" NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" \
    lane_run 'npm install clean@2.0.0'
  assert_status 0 "$FUNCNAME: GIT_DIR" || return
  assert_err_contains_fragment 'baseline: the lockfile committed at the head' "$FUNCNAME: GIT_DIR" || return
  pass "$FUNCNAME"
}

# 4. No private name in a public evidence request, the baseline side included.
case_project_lane_baseline_a_private_name_only_the_baseline_carries_never_reaches_the_evidence_request() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-private-baseline-only" kept@1.0.0 @p/lib@1.0.0
  lane_private_store || { fail "$FUNCNAME: cannot seed the private store"; return; }
  # the edit removes it from the lockfile on disk (the manifest never named it)
  lane_lock kept@1.0.0 > "${WORK_DIR}/package-lock.json"
  local before
  before="$(lane_digests)"
  : > "${LOG_FILE}"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" lane_run 'npm install clean@2.0.0'
  assert_status 100 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  assert_err_contains_fragment 'touches the private-registry store (@p/lib)' "$FUNCNAME" || return
  assert_log_not_contains_fragment 'EVIDENCE_INPUT' "$FUNCNAME" || return
  assert_lane_untouched "${before}" "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# 6. The workspace refusal does not depend on git.
case_project_lane_a_member_of_a_workspace_that_is_not_a_repository_refuses() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-workspace-no-git" kept@1.0.0
  local root="${CASE_DIR}/ws" member
  mkdir -p "${root}/packages"
  member="${root}/packages/member"
  mv "${WORK_DIR}" "${member}"
  rm -rf "${member}/.git"
  printf '{"name":"root","private":true,"workspaces":["packages/*"]}\n' > "${root}/package.json"
  WORK_DIR="${member}"
  local before
  before="$(lane_digests)"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" lane_run 'npm install clean@2.0.0'
  lane_unsupported_case "$FUNCNAME" install 'a workspace member outside git' || return
  assert_err_contains_fragment 'a project inside the workspace root' "$FUNCNAME" || return
  assert_lane_untouched "${before}" "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# Smaller points: what a successful publication must show.
case_project_lane_baseline_a_publication_report_must_be_whole_to_count() {
  skip_lockdiff_case "$FUNCNAME" || return
  local kind
  for kind in bind-retained bind-one-file; do
    lane_prepare "lane-report-${kind}" kept@1.0.0
    SAFE_CORE_TAMPER="${kind}" NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" lane_run 'npm install clean@2.0.0'
    assert_status 100 "$FUNCNAME: ${kind}" || return
    assert_err_contains_fragment 'project-bind returned no usable result' "$FUNCNAME: ${kind}" || return
  done
  pass "$FUNCNAME"
}


# ---- the recorded baselines (ticket 1632, closing pass) ------------------------------

case_project_lane_baseline_a_lockfile_restored_by_hand_to_a_judged_one_is_a_baseline() {
  # A lockfile on disk whose bytes are one safe judged clear is a baseline whenever and however
  # it came to be there: this is the case of an old commit checked out (the record stands for it).
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-restored" kept@1.0.0
  lane_first_command "$FUNCNAME" || return
  cp -- "${WORK_DIR}/package-lock.json" "${CASE_DIR}/judged.json"
  # a hand edit, then the judged lockfile put back by hand
  lane_lock kept@1.0.0 clean@2.0.0 junk@1.0.0 > "${WORK_DIR}/package-lock.json"
  cp -- "${CASE_DIR}/judged.json" "${WORK_DIR}/package-lock.json"
  : > "${LOG_FILE}"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0 other@1.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_TWO_DEPS_MANIFEST}" \
    SAFE_AUDIT_EVIDENCE_HITS="{\"clean@2.0.0\":${LANE_HIT_CRITICAL}}" lane_run 'npm install other@1.0.0'
  assert_status 0 "$FUNCNAME" || return
  assert_err_contains_fragment 'baseline: a lockfile safe judged clear and recorded' "$FUNCNAME" || return
  assert_err_contains_fragment '1 already present (highest: critical)' "$FUNCNAME" || return
  assert_err_not_contains_fragment 'the lockfile on disk is not the baseline' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_project_lane_baseline_a_failed_materialisation_leaves_a_record_that_is_harmless() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-record-harmless" kept@1.0.0
  lane_first_command "$FUNCNAME" || return
  local first records
  first="$(lane_stored_digest)"
  records="$(lane_record_count)"
  # clear on complete evidence (so recorded) but the installation fails: nothing is published
  NPM_CI_STATUS=7 NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0 other@1.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_TWO_DEPS_MANIFEST}" \
    lane_run 'npm install other@1.0.0'
  assert_status 7 "$FUNCNAME" || return
  [[ "$(lane_record_count)" == "$((records + 1))" && "$(lane_stored_digest)" != "${first}" ]] || { fail "$FUNCNAME: the judged lockfile should be recorded"; return; }
  [[ "$(lane_digest_of "${WORK_DIR}/package-lock.json")" == "${first}" ]] || { fail "$FUNCNAME: the lockfile on disk changed"; return; }
  # the next command starts from the lockfile on disk, which is still the previous baseline;
  # what the failed command would have brought (other@1.0.0, here with a critical advisory) is introduced
  : > "${LOG_FILE}"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0 other@1.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_TWO_DEPS_MANIFEST}" \
    SAFE_AUDIT_EVIDENCE_HITS="{\"other@1.0.0\":${LANE_HIT_CRITICAL}}" lane_run 'npm install other@1.0.0'
  assert_status 104 "$FUNCNAME: the next command" || return
  assert_err_contains_fragment 'baseline: a lockfile safe judged clear and recorded' "$FUNCNAME" || return
  assert_err_not_contains_fragment 'the lockfile on disk is not the baseline' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_project_lane_baseline_a_lockfile_that_cannot_be_recorded_refuses_before_any_publication() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-record-unwritable" kept@1.0.0
  local state="${HOME_DIR}/.local/share/safe/project-lane/state" d before
  for d in "${HOME_DIR}/.local" "${HOME_DIR}/.local/share" "${HOME_DIR}/.local/share/safe" "${HOME_DIR}/.local/share/safe/project-lane" "${state}"; do
    mkdir -p "${d}" && chmod 700 "${d}"
  done
  : > "${state}/project-baseline"   # a file where the record directory must be
  before="$(lane_digests)"
  : > "${LOG_FILE}"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" lane_run 'npm install clean@2.0.0'
  assert_status 102 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  assert_err_contains_fragment 'the judged lockfile cannot be recorded' "$FUNCNAME" || return
  assert_err_contains_fragment 'nothing was published' "$FUNCNAME" || return
  assert_lane_untouched "${before}" "$FUNCNAME" || return
  assert_log_not_contains_fragment 'CORE_BIND_ARGS' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_project_lane_baseline_a_record_that_cannot_be_trusted_is_ignored_and_more_is_judged() {
  skip_lockdiff_case "$FUNCNAME" || return
  local how record
  for how in content truncated empty link loose-mode directory; do
    lane_prepare "lane-record-ignored-${how}" kept@1.0.0
    lane_first_command "$FUNCNAME: ${how}" || return
    record="$(lane_baseline_records | head -n 1)"
    cp -- "${record}" "${CASE_DIR}/record.good"
    case "${how}" in
      content) printf '%s\n' '{"lockfileVersion":3,"packages":{}}' > "${record}" ;;
      truncated) head -c 40 "${CASE_DIR}/record.good" > "${record}" ;;
      empty) : > "${record}" ;;
      link) rm -f "${record}"; ln -s "${CASE_DIR}/record.good" "${record}" ;;
      loose-mode) chmod 644 "${record}" ;;
      directory) rm -f "${record}"; mkdir "${record}" ;;
    esac
    # the lockfile on disk IS the recorded one, but its record cannot be trusted: it is not a
    # baseline, so the committed lockfile is, and what the lockfile on disk adds is introduced
    : > "${LOG_FILE}"
    NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0 other@1.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_TWO_DEPS_MANIFEST}" \
      SAFE_AUDIT_EVIDENCE_HITS="{\"clean@2.0.0\":${LANE_HIT_CRITICAL}}" lane_run 'npm install other@1.0.0'
    assert_status 104 "$FUNCNAME: ${how}" || return
    assert_err_contains_fragment 'baseline: the lockfile committed at the head' "$FUNCNAME: ${how}" || return
    assert_err_contains_fragment 'ignored record' "$FUNCNAME: ${how}" || return
    assert_err_contains_fragment 'the lockfile on disk is not the baseline: 1 entries added on disk' "$FUNCNAME: ${how}" || return
  done
  # outside git and with nothing to trust: the baseline is empty, the whole graph introduced
  lane_prepare "lane-record-ignored-nogit" kept@1.0.0
  rm -rf "${WORK_DIR}/.git"
  lane_first_command "$FUNCNAME: no git" || return
  record="$(lane_baseline_records | head -n 1)"
  printf 'x' > "${record}"
  : > "${LOG_FILE}"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0 other@1.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_TWO_DEPS_MANIFEST}" \
    SAFE_AUDIT_EVIDENCE_HITS="{\"kept@1.0.0\":${LANE_HIT_CRITICAL}}" lane_run 'npm install other@1.0.0'
  assert_status 104 "$FUNCNAME: no git" || return
  assert_err_contains_fragment 'baseline: empty' "$FUNCNAME: no git" || return
  assert_err_contains_fragment 'ignored record' "$FUNCNAME: no git" || return
  pass "$FUNCNAME"
}

# Git: the invocation is bound to local reads, the repository is pinned, the mode is the raw one.
case_project_lane_baseline_a_git_that_may_fetch_is_not_used() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-old-git" kept@1.0.0
  local real_git
  real_git="$(command -v git)"
  mkdir -p "${CASE_DIR}/oldgit"
  cat > "${CASE_DIR}/oldgit/git" <<OLDGIT
#!/usr/bin/env bash
# a git that does not know the no-lazy-fetch switch
for a in "\$@"; do [[ "\$a" != --no-lazy-fetch ]] || { echo "unknown option: --no-lazy-fetch" >&2; exit 129; }; done
exec "${real_git}" "\$@"
OLDGIT
  chmod +x "${CASE_DIR}/oldgit/git"
  local before
  before="$(lane_digests)"
  SAFE_TEST_PATH_MID="${CASE_DIR}/oldgit" NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" lane_run 'npm install clean@2.0.0'
  unset SAFE_TEST_PATH_MID
  assert_status 102 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  assert_err_contains_fragment 'does not support disabling lazy fetches (git 2.45.0 or newer is required)' "$FUNCNAME" || return
  assert_lane_untouched "${before}" "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_project_lane_baseline_a_damaged_repository_is_not_replaced_by_the_one_around_it() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-pinned-repo" kept@1.0.0
  # the project is its own repository, inside another one that also commits it
  local outer="${CASE_DIR}/outer" proj
  mkdir -p "${outer}"
  mv "${WORK_DIR}" "${outer}/proj"
  proj="${outer}/proj"
  rm -rf "${proj}/.git"
  (cd "${outer}" && export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null && git init -q -b main && git add -A \
    && git -c user.name=l -c user.email=l@example.invalid commit -q -m outer) >/dev/null 2>&1
  (cd "${proj}" && export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null && git init -q -b main && git add -A \
    && git -c user.name=l -c user.email=l@example.invalid commit -q -m inner) >/dev/null 2>&1
  rm -f "${proj}/.git/HEAD"      # the inner repository is damaged: git itself would walk up to the outer one
  WORK_DIR="${proj}"
  local before
  before="$(lane_digests)"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" lane_run 'npm install clean@2.0.0'
  assert_status 102 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  assert_err_contains_fragment 'the committed lockfile cannot be read' "$FUNCNAME" || return
  assert_err_contains_fragment 'another repository' "$FUNCNAME" || return
  [[ "$(lane_digests)" == "${before}" ]] || { fail "$FUNCNAME: the project changed"; return; }
  pass "$FUNCNAME"
}

lane_commit_with_raw_mode() { # <raw mode> -- commits package-lock.json under a hand-made tree entry of that raw mode
  local mode="$1" blob tree commit
  (
    cd "${WORK_DIR}" || exit 1
    export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
    blob="$(git hash-object -w package-lock.json)"
    manifest="$(git hash-object -w package.json)"
    tree="$( { printf '%s package-lock.json\0' "${mode}"; printf '%s' "${blob}" | xxd -r -p; printf '100644 package.json\0'; printf '%s' "${manifest}" | xxd -r -p; } \
      | git hash-object -w -t tree --literally --stdin)"
    commit="$(git -c user.name=l -c user.email=l@example.invalid commit-tree "${tree}" -p HEAD -m rawmode)"
    git update-ref HEAD "${commit}"
  ) >/dev/null 2>&1
}

case_project_lane_baseline_the_committed_lockfile_is_read_with_its_raw_mode() {
  skip_lockdiff_case "$FUNCNAME" || return
  local mode
  for mode in 100664 100600 100777 100645; do
    lane_prepare "lane-raw-mode-${mode}" kept@1.0.0
    lane_commit_with_raw_mode "${mode}"
    [[ "$(git -C "${WORK_DIR}" ls-tree HEAD -- package-lock.json | cut -d' ' -f1)" == "$([[ "${mode}" == 100664 || "${mode}" == 100600 || "${mode}" == 100645 ]] && echo 100644 || echo 100755)" ]] || { fail "$FUNCNAME: ${mode}: the fixture is not the intended one"; return; }
    : > "${LOG_FILE}"
    NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" lane_run 'npm install clean@2.0.0'
    case "${mode}" in
      100664) assert_status 0 "$FUNCNAME: ${mode}" || return ;; # what git itself writes for a legacy regular file
      *)
        assert_status 102 "$FUNCNAME: ${mode}" || return
        assert_err_contains_fragment "not a regular file in the head commit (raw mode ${mode})" "$FUNCNAME: ${mode}" || return ;;
    esac
  done
  # a reference that git cannot look up is a failed lookup, not an unborn branch
  lane_prepare "lane-bad-ref" kept@1.0.0
  printf 'garbage\n' > "${WORK_DIR}/.git/refs/heads/main"
  : > "${LOG_FILE}"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" lane_run 'npm install clean@2.0.0'
  assert_status 102 "$FUNCNAME: a garbage reference" || return
  assert_err_contains_fragment 'the committed lockfile cannot be read' "$FUNCNAME: a garbage reference" || return
  pass "$FUNCNAME"
}

# The lockfile on disk passes the binder's own admission before npm reads it.
case_project_lane_baseline_every_entry_of_the_lockfile_on_disk_is_admitted_before_the_projection() {
  skip_lockdiff_case "$FUNCNAME" || return
  local how before
  for how in outside-key inside-link malformed; do
    lane_prepare "lane-admit-all-${how}" kept@1.0.0
    case "${how}" in
      outside-key) lane_lock kept@1.0.0 | jq -c '.packages["vendor/x"] = {"version":"1.0.0","resolved":"https://registry.npmjs.org/x/-/x-1.0.0.tgz","integrity":"'"$(lane_integrity x)"'"}' > "${WORK_DIR}/package-lock.json" ;;
      inside-link) lane_lock kept@1.0.0 | jq -c '.packages["packages/l"] = {"name":"l","version":"1.0.0"} | .packages["node_modules/l"] = {"resolved":"packages/l","link":true}' > "${WORK_DIR}/package-lock.json" ;;
      malformed) printf '{"lockfileVersion":3,"packages":{"":{},"node_modules/kept":{"version":"1.0.0"}},"packages":{}}\n' > "${WORK_DIR}/package-lock.json" ;;
    esac
    before="$(lane_digests)"
    : > "${LOG_FILE}"
    NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" lane_run 'npm install clean@2.0.0'
    if [[ "${how}" == malformed ]]; then
      assert_status 102 "$FUNCNAME: ${how}" || return
      # a malformed lockfile that differs from the committed one is named for what it is
      assert_err_contains_fragment 'the lockfile on disk' "$FUNCNAME: ${how}" || return
      assert_err_not_contains_fragment 'committed lockfile cannot' "$FUNCNAME: ${how}" || return
    else
      lane_unsupported_case "$FUNCNAME" install "${how}" || return
      if [[ "${how}" == outside-key ]]; then
        assert_err_contains_fragment 'the lockfile on disk names a path outside the tree' "$FUNCNAME: ${how}" || return
      else
        assert_err_contains_fragment 'the lockfile on disk that the lane cannot admit' "$FUNCNAME: ${how}" || return
      fi
    fi
    assert_log_not_contains_fragment 'PROJECTION' "$FUNCNAME: ${how}" || return
    assert_lane_untouched "${before}" "$FUNCNAME: ${how}" || return
  done
  pass "$FUNCNAME"
}

# The privacy of the evidence request: names are compared case-folded for refusing, versions must be exact.
case_project_lane_baseline_the_evidence_request_never_carries_a_private_name_in_another_spelling_or_a_version_that_is_not_one() {
  skip_lockdiff_case "$FUNCNAME" || return
  local how before
  for how in scope-case exact-grant-case bundled-version; do
    case "${how}" in
      scope-case) lane_prepare "lane-private-${how}" kept@1.0.0 @P/lib@1.0.0 ;;
      exact-grant-case) lane_prepare "lane-private-${how}" kept@1.0.0 @Q/Internal-Tool@1.0.0 ;;
      bundled-version) lane_prepare "lane-private-${how}" kept@1.0.0 ;;
    esac
    lane_private_store || { fail "$FUNCNAME: store"; return; }
    if [[ "${how}" == exact-grant-case ]]; then
      "${SAFE_CORE_TEST_BIN}" private-trust registry-add --policy "${HOME_DIR}/.config/safe/run/private-registries.json" \
        --id p-exact --ecosystem npm --origin https://npm.private.example --namespace '@q/internal-tool' >/dev/null || { fail "$FUNCNAME: exact grant"; return; }
    fi
    if [[ "${how}" == bundled-version ]]; then
      # a bundled member of a public package whose version field names something else
      lane_lock kept@1.0.0 | jq -c '.packages["node_modules/kept/node_modules/inner"] = {"version":"npm:@p/secret@1.0.0","inBundle":true}' > "${WORK_DIR}/package-lock.json"
      lane_commit
    fi
    # the edit drops it from the lockfile on disk: it is on the baseline side of the request only
    lane_lock kept@1.0.0 > "${WORK_DIR}/package-lock.json"
    before="$(lane_digests)"
    : > "${LOG_FILE}"
    NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" lane_run 'npm install clean@2.0.0'
    assert_status 100 "$FUNCNAME: ${how}" || return
    assert_lane_final_line install "$FUNCNAME: ${how}" || return
    assert_log_not_contains_fragment 'EVIDENCE_INPUT' "$FUNCNAME: ${how}" || return
    [[ "$(lane_digests)" == "${before}" ]] || { fail "$FUNCNAME: ${how}: the project changed"; return; }
    if [[ "${how}" == bundled-version ]]; then
      assert_err_contains_fragment 'whose version is not an exact version' "$FUNCNAME: ${how}" || return
    else
      assert_err_contains_fragment 'touches the private-registry store' "$FUNCNAME: ${how}" || return
    fi
  done
  pass "$FUNCNAME"
}


case_project_lane_baseline_a_plan_whose_installation_failed_is_not_the_baseline_of_its_retry() {
  skip_lockdiff_case "$FUNCNAME" || return
  # The reviewer's sequence: no lockfile and no commit; a first add is judged clear (so recorded)
  # and its installation fails; an advisory is then disclosed on that version; the retry must be
  # judged against an EMPTY baseline: the project never carried the package.
  lane_prepare "lane-failed-plan-retry" kept@1.0.0
  rm -rf "${WORK_DIR}/.git" "${WORK_DIR}/package-lock.json"
  NPM_CI_STATUS=7 NPM_LOCK_MUTATION_JSON="$(lane_lock clean@2.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" lane_run 'npm install clean@2.0.0'
  assert_status 7 "$FUNCNAME: the first add" || return
  [[ "$(lane_record_count)" == 1 && ! -e "${WORK_DIR}/package-lock.json" ]] || { fail "$FUNCNAME: expected a record and no lockfile on disk"; return; }
  : > "${LOG_FILE}"
  NPM_LOCK_MUTATION_JSON="$(lane_lock clean@2.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" \
    SAFE_AUDIT_EVIDENCE_HITS="{\"clean@2.0.0\":${LANE_HIT_CRITICAL}}" lane_run 'npm install clean@2.0.0'
  assert_status 104 "$FUNCNAME: the retry" || return
  assert_lane_final_line install "$FUNCNAME" || return
  assert_err_contains_fragment 'baseline: empty' "$FUNCNAME" || return
  assert_err_contains_fragment 'introduces a blocking advisory' "$FUNCNAME" || return
  [[ ! -e "${WORK_DIR}/package-lock.json" && ! -e "${WORK_DIR}/node_modules" ]] || { fail "$FUNCNAME: the refusal wrote something"; return; }
  pass "$FUNCNAME"
}

case_project_lane_baseline_without_a_commit_a_lockfile_edited_by_hand_is_judged_whole() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-edit-no-commit" kept@1.0.0
  rm -rf "${WORK_DIR}/.git"
  lane_first_command "$FUNCNAME" || return
  # a hand edit: it matches no record, there is no commit: the baseline is empty, everything introduced
  lane_lock kept@1.0.0 clean@2.0.0 other@1.0.0 > "${WORK_DIR}/package-lock.json"
  : > "${LOG_FILE}"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0 other@1.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_TWO_DEPS_MANIFEST}" \
    SAFE_AUDIT_EVIDENCE_HITS="{\"kept@1.0.0\":${LANE_HIT_CRITICAL}}" lane_run 'npm install other@1.0.0'
  assert_status 104 "$FUNCNAME" || return
  assert_err_contains_fragment 'baseline: empty' "$FUNCNAME" || return
  assert_err_contains_fragment 'the lockfile on disk is not the baseline: 3 entries added on disk' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# 2. The case-folded private-name check is the first matcher's too.
case_project_lane_baseline_a_mixed_case_private_name_in_the_manifest_refuses_before_the_projection() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-private-case-manifest" kept@1.0.0
  lane_private_store || { fail "$FUNCNAME: store"; return; }
  jq -c '.dependencies["@P/Lib"] = "^1.0.0"' "${WORK_DIR}/package.json" > "${WORK_DIR}/package.json.new"
  mv "${WORK_DIR}/package.json.new" "${WORK_DIR}/package.json"
  lane_commit
  local before
  before="$(lane_digests)"
  : > "${LOG_FILE}"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" lane_run 'npm install clean@2.0.0'
  lane_unsupported_case "$FUNCNAME" install 'a mixed-case private name' || return
  assert_err_contains_fragment 'touches the private-registry store' "$FUNCNAME" || return
  assert_log_not_contains_fragment 'PROJECTION' "$FUNCNAME" || return
  assert_log_not_contains_fragment 'EVIDENCE_INPUT' "$FUNCNAME" || return
  assert_lane_untouched "${before}" "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# 3. A project directory named like pathspec syntax selects its own subtree, not a sibling's.
case_project_lane_baseline_a_directory_named_like_pathspec_syntax_is_read_literally() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-literal-pathspec" kept@1.0.0
  local root="${CASE_DIR}/lit" proj
  mkdir -p "${root}/p" "${root}/:(top)p"
  # the sibling p carries ANOTHER lockfile (with an extra package)
  cp "${WORK_DIR}/package.json" "${root}/p/package.json"
  lane_lock kept@1.0.0 sibling@1.0.0 > "${root}/p/package-lock.json"
  cp "${WORK_DIR}/package.json" "${WORK_DIR}/package-lock.json" "${root}/:(top)p/"
  rm -rf "${WORK_DIR}/.git"
  (cd "${root}" && export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null && git init -q -b main && git add -A \
    && git -c user.name=l -c user.email=l@example.invalid commit -q -m lit) >/dev/null 2>&1
  proj="${root}/:(top)p"
  WORK_DIR="${proj}"
  : > "${LOG_FILE}"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" lane_run 'npm install clean@2.0.0'
  assert_status 0 "$FUNCNAME" || return
  # its own committed lockfile is the baseline (the lockfile on disk IS it), not the sibling's
  assert_err_contains_fragment 'baseline: the lockfile committed at the head' "$FUNCNAME" || return
  assert_err_not_contains_fragment 'the lockfile on disk is not the baseline' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# 4. A committed lockfile that is present is decoded before any record is considered.
case_project_lane_baseline_a_malformed_committed_lockfile_is_not_hidden_by_a_recorded_match() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-malformed-committed-record" kept@1.0.0
  lane_lock kept@1.0.0 | head -c 60 > "${WORK_DIR}/package-lock.json"
  lane_commit
  # the lockfile on disk is a valid one, recorded as judged clear
  lane_lock kept@1.0.0 clean@2.0.0 > "${WORK_DIR}/package-lock.json"
  local state="${HOME_DIR}/.local/share/safe/project-lane/state" d project
  for d in "${HOME_DIR}/.local" "${HOME_DIR}/.local/share" "${HOME_DIR}/.local/share/safe" "${HOME_DIR}/.local/share/safe/project-lane" "${state}"; do
    mkdir -p "${d}" && chmod 700 "${d}"
  done
  project="$(cd "${WORK_DIR}" && pwd -P)"
  "${SAFE_CORE_TEST_BIN}" project-baseline record --state-dir "${state}" --project "${project}" --name package-lock.json --file "${WORK_DIR}/package-lock.json" \
    || { fail "$FUNCNAME: cannot record"; return; }
  [[ "$(lane_record_count)" == 1 ]] || { fail "$FUNCNAME: record"; return; }
  local before
  before="$(lane_digests)"
  : > "${LOG_FILE}"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" lane_run 'npm install clean@2.0.0'
  assert_status 102 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  assert_err_contains_fragment 'the committed lockfile cannot be parsed' "$FUNCNAME" || return
  assert_log_not_contains_fragment 'EVIDENCE_INPUT' "$FUNCNAME" || return
  [[ "$(lane_digests)" == "${before}" ]] || { fail "$FUNCNAME: the project changed"; return; }
  pass "$FUNCNAME"
}

# 5. A project path the shell cannot capture exactly refuses before anything is opened or locked.
case_project_lane_baseline_a_project_path_ending_with_a_newline_refuses() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-newline-path" kept@1.0.0
  local parent="${CASE_DIR}/nl" proj sibling
  mkdir -p "${parent}"
  proj="${parent}/proj"$'\n'
  sibling="${parent}/proj"
  cp -a "${WORK_DIR}" "${sibling}"
  cp -a "${WORK_DIR}" "${proj}"
  WORK_DIR="${proj}"
  local before_sibling
  before_sibling="$(cd "${sibling}" && sha256sum package.json package-lock.json | cut -d' ' -f1 | tr '\n' ' ')"
  : > "${LOG_FILE}"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" lane_run 'npm install clean@2.0.0'
  assert_status 100 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  assert_err_contains_fragment "path contains a newline" "$FUNCNAME" || return
  assert_log_not_contains_fragment 'PROJECTION' "$FUNCNAME" || return
  [[ "$(lane_record_count)" == 0 && ! -e "${sibling}/node_modules" && ! -e "${proj}/node_modules" ]] || { fail "$FUNCNAME: something was written"; return; }
  [[ "$(cd "${sibling}" && sha256sum package.json package-lock.json | cut -d' ' -f1 | tr '\n' ' ')" == "${before_sibling}" ]] || { fail "$FUNCNAME: the sibling changed"; return; }
  pass "$FUNCNAME"
}


# ---- routing (ticket 1633) ----------------------------------------------------------------

case_project_lane_routing_a_committed_npmrc_outside_the_allow_list_takes_the_one_shot_route() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-route-npmrc" kept@1.0.0
  printf 'strict-ssl=false\n' > "${WORK_DIR}/.npmrc"
  lane_commit
  lane_oneshot_case "$FUNCNAME" install '.npmrc line 1' 'npm install clean@2.0.0' || return
  # in uncommitted changes it is a refusal
  lane_prepare "lane-route-npmrc-dirty" kept@1.0.0
  printf 'strict-ssl=false\n' > "${WORK_DIR}/.npmrc"
  lane_run 'npm install clean@2.0.0'
  lane_unsupported_case "$FUNCNAME" install 'an uncommitted .npmrc' || return
  assert_err_contains_fragment 'exists only in uncommitted changes' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_project_lane_routing_an_npm_without_the_capabilities_takes_the_one_shot_route() {
  skip_lockdiff_case "$FUNCNAME" || return
  local json
  for json in '{"version":"10.9.2","atFloor":false,"missing":["allow-git"]}' '{"version":"11.20.0","atFloor":true,"missing":["allow-git"]}' \
      '{"version":"11.0.0","atFloor":false,"missing":[]}'; do
    lane_prepare "lane-route-capability-${RANDOM}" kept@1.0.0
    lane_oneshot_case "$FUNCNAME: ${json}" install 'npm' 'npm install clean@2.0.0' "NODE_CAPABILITY_JSON=${json}" || return
  done
  # a probe that cannot be answered is breakage, not a property of npm
  lane_prepare "lane-route-capability-broken" kept@1.0.0
  NODE_CAPABILITY_JSON='not json' lane_run 'npm install clean@2.0.0'
  assert_status 100 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_project_lane_routing_a_flag_an_environment_setting_a_broken_guard_and_a_dirty_lockfile_cannot_reach_the_one_shot_route() {
  skip_lockdiff_case "$FUNCNAME" || return
  # an established shape (a committed git dependency) ...
  lane_prepare "lane-route-no-weaker" kept@1.0.0
  jq -c '.dependencies.odd = "git+https://example.invalid/x.git"' "${WORK_DIR}/package.json" > "${WORK_DIR}/package.json.new"
  mv "${WORK_DIR}/package.json.new" "${WORK_DIR}/package.json"
  lane_commit
  lane_oneshot_case "$FUNCNAME: the shape alone" install 'manifest.dependencies.odd' 'npm install clean@2.0.0' || return
  # ... with a flag: refuses
  : > "${LOG_FILE}"
  lane_run 'npm install clean@2.0.0 --registry=https://r.example/'
  lane_unsupported_case "$FUNCNAME" install 'a flag' || return
  : > "${LOG_FILE}"
  lane_run 'npm install clean@2.0.0 --save-peer-x'
  lane_unsupported_case "$FUNCNAME" install 'an unknown flag' || return
  # ... with a failing guard (a hidden credential interpolation in the user's npmrc): refuses, never one-shot
  printf '//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n' > "${HOME_DIR}/.npmrc"
  : > "${LOG_FILE}"
  lane_run 'npm install clean@2.0.0'
  assert_status 100 "$FUNCNAME: a failing guard" || return
  assert_lane_final_line install "$FUNCNAME: a failing guard" || return
  assert_err_not_contains_fragment 'one-shot' "$FUNCNAME: a failing guard" || return
  assert_lane_no_delegate "$FUNCNAME: a failing guard" || return
  rm -f "${HOME_DIR}/.npmrc"
  # a host registry reason with an environment setting that names it: refuses, naming the key
  lane_prepare "lane-route-env" kept@1.0.0
  npm_config_registry='https://r.example/' NPM_LOCKDIFF_REGISTRY_CONFIG_JSON='{"registry":"https://r.example/"}' lane_run 'npm install clean@2.0.0'
  assert_status 100 "$FUNCNAME: an environment setting" || return
  assert_lane_final_line install "$FUNCNAME: an environment setting" || return
  assert_err_contains_fragment 'npm_config_registry' "$FUNCNAME" || return
  assert_err_not_contains_fragment 'one-shot' "$FUNCNAME" || return
  assert_lane_no_delegate "$FUNCNAME: an environment setting" || return
  # a dirty version 1 lockfile: the shapes case; here the same on a lockfile REPLACED after a supported commit
  lane_prepare "lane-route-dirty-v1" kept@1.0.0
  lane_lock kept@1.0.0 | jq -c '.lockfileVersion = 1' > "${WORK_DIR}/package-lock.json"
  lane_run 'npm install clean@2.0.0'
  lane_unsupported_case "$FUNCNAME" install 'a dirty v1 lockfile' || return
  assert_err_not_contains_fragment 'one-shot' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_project_lane_routing_no_refusal_tells_the_caller_to_turn_the_lane_off() {
  skip_lockdiff_case "$FUNCNAME" || return
  local script
  for script in 'npm ci' 'npm dedupe' 'npm prune' 'npm install clean' 'npm install clean@2.0.0 --workspaces' 'npm install clean@2.0.0 --' \
      'npm install clean@2.0.0 --prefix .' 'npm update clean'; do
    lane_prepare "lane-no-switch-hint-${RANDOM}" kept@1.0.0
    lane_run "${script}"
    assert_status 100 "$FUNCNAME: ${script}" || return
    ! grep -qiE 'lane off|turn the lane|switch it|install\.project_lane|while the lane|wait for the ticket' "${ERR_FILE}" || { fail "$FUNCNAME: ${script}: the refusal mentions the switch: $(cat "${ERR_FILE}")"; return; }
  done
  pass "$FUNCNAME"
}

case_project_lane_routing_ci_dedupe_and_prune_are_refused_where_there_is_nothing_to_fall_back_to() {
  skip_lockdiff_case "$FUNCNAME" || return
  local verb
  for verb in ci dedupe prune; do
    lane_prepare "lane-route-${verb}" kept@1.0.0
    lane_run "npm ${verb}"
    assert_status 100 "$FUNCNAME: ${verb}" || return
    assert_lane_final_line "${verb}" "$FUNCNAME: ${verb}" || return
    assert_err_contains_fragment "npm ${verb} is not routed by the project lane yet" "$FUNCNAME: ${verb}" || return
    assert_lane_no_delegate "$FUNCNAME: ${verb}" || return
  done
  pass "$FUNCNAME"
}

case_project_lane_routing_the_install_test_families_keep_todays_gate_with_a_one_shot_line() {
  skip_lockdiff_case "$FUNCNAME" || return
  local pair
  for pair in 'install-test|install-test' 'it|install-test' 'cit|install-ci-test' 'install-ci-test|install-ci-test' 'sit|install-ci-test' 'clean-install-test|install-ci-test'; do
    lane_prepare "lane-route-testfam-${RANDOM}" kept@1.0.0
    lane_oneshot_case "$FUNCNAME: ${pair%%|*}" "${pair#*|}" 'its test phase runs project code' "npm ${pair%%|*}" || return
  done
  pass "$FUNCNAME"
}

case_project_lane_routing_aliases_and_prefixes_of_every_verb_keep_their_route() {
  skip_lockdiff_case "$FUNCNAME" || return
  local verb
  # the lane's own verbs, spelled every way npm accepts
  for verb in i in ins inst insta instal add isntall install; do
    lane_prepare "lane-route-alias-${verb}" kept@1.0.0
    : > "${LOG_FILE}"
    NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" lane_run "npm ${verb} clean@2.0.0"
    assert_status 0 "$FUNCNAME: ${verb}" || return
    grep -q $'^PROJECTION\tnpm' "${LOG_FILE}" || { fail "$FUNCNAME: ${verb} did not take the lane"; return; }
  done
  for verb in up upgrade udpate update updat; do
    lane_prepare "lane-route-alias-${verb}" kept@1.0.0 vuln@1.0.0
    : > "${LOG_FILE}"
    NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 vuln@1.0.1)" lane_run "npm ${verb}"
    assert_status 0 "$FUNCNAME: ${verb}" || return
    grep -q $'^PROJECTION\tnpm' "${LOG_FILE}" || { fail "$FUNCNAME: ${verb} did not take the lane"; return; }
  done
  # ci, dedupe and prune, spelled every way: refused by the lane
  for verb in ic clean-install install-clean isntall-clean ddp dedupe prune; do
    lane_prepare "lane-route-alias-${verb}" kept@1.0.0
    lane_run "npm ${verb}"
    assert_status 100 "$FUNCNAME: ${verb}" || return
    assert_err_contains_fragment 'is not routed by the project lane yet' "$FUNCNAME: ${verb}" || return
  done
  # everything else is untouched: no lane line, today's delegation
  for verb in uninstall un rm remove ls view; do
    lane_prepare "lane-route-alias-${verb}" kept@1.0.0
    : > "${LOG_FILE}"
    lane_run "npm ${verb} kept"
    assert_err_not_contains_fragment 'project lane' "$FUNCNAME: ${verb}" || return
    assert_log_not_contains_fragment 'PROJECTION' "$FUNCNAME: ${verb}" || return
  done
  pass "$FUNCNAME"
}

# mise exec -- npm <lane command>: the OUTER process runs the lane, in the directory mise would run
# it in, and does not then run the original command.
case_project_lane_routing_mise_exec_runs_the_lane_once_and_nothing_else() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-mise-exec" kept@1.0.0
  : > "${LOG_FILE}"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" lane_run 'mise exec -- npm install clean@2.0.0'
  assert_status 0 "$FUNCNAME" || return
  assert_err_contains_fragment 'project lane: npm install: 1 packages added' "$FUNCNAME" || return
  [[ "$(grep -c $'^PROJECTION\tnpm' "${LOG_FILE}")" == 1 ]] || { fail "$FUNCNAME: the projection did not run exactly once"; return; }
  [[ "$(grep -cP '^REAL\tnpm\tci\t' "${LOG_FILE}")" == 1 ]] || { fail "$FUNCNAME: the frozen install did not run exactly once"; return; }
  assert_log_not_contains_fragment $'REAL\tmise\texec' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tnpm\tinstall' "$FUNCNAME" || return
  [[ "$(cat "${WORK_DIR}/package-lock.json")" == "$(lane_lock kept@1.0.0 clean@2.0.0)" && -d "${WORK_DIR}/node_modules/clean" ]] || { fail "$FUNCNAME: the judged project was not published"; return; }
  # the lane's refusals are the command's status, and the original command does not run either
  lane_prepare "lane-mise-exec-refused" kept@1.0.0
  : > "${LOG_FILE}"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 dirty@3.0.0)" SAFE_AUDIT_EVIDENCE_HITS="{\"dirty@3.0.0\":${LANE_HIT_CRITICAL}}" lane_run 'mise exec -- npm install dirty@3.0.0'
  assert_status 104 "$FUNCNAME: a refusal" || return
  assert_log_not_contains_fragment $'REAL\tmise\texec' "$FUNCNAME" || return
  [[ ! -e "${WORK_DIR}/node_modules" ]] || { fail "$FUNCNAME: a tree was produced"; return; }
  # the lane's own flags and unsupported shapes are the lane's, under mise as anywhere
  lane_prepare "lane-mise-exec-ci" kept@1.0.0
  lane_run 'mise exec -- npm ci'
  assert_status 100 "$FUNCNAME: npm ci" || return
  assert_err_contains_fragment 'npm ci is not routed by the project lane yet' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tmise\texec' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_project_lane_routing_mise_exec_runs_the_lane_in_the_directory_mise_would() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-mise-exec-C" kept@1.0.0
  local project="${WORK_DIR}"
  : > "${LOG_FILE}"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" \
    lane_run "cd / && mise -C '${project}' exec -- npm install clean@2.0.0"
  assert_status 0 "$FUNCNAME" || return
  [[ -d "${project}/node_modules/clean" && "$(cat "${project}/package-lock.json")" == "$(lane_lock kept@1.0.0 clean@2.0.0)" ]] || { fail "$FUNCNAME: the project named by -C was not the one installed"; return; }
  assert_log_not_contains_fragment $'REAL\tmise\texec' "$FUNCNAME" || return
  # a -C directory that cannot be entered refuses
  : > "${LOG_FILE}"
  lane_run "cd / && mise -C '${CASE_DIR}/nowhere' exec -- npm install clean@2.0.0"
  [[ "${STATUS}" -ne 0 ]] || { fail "$FUNCNAME: an unreachable -C directory was accepted"; return; }
  assert_log_not_contains_fragment $'REAL\tmise\texec' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_project_lane_routing_mise_exec_overlay_is_carried_only_as_far_as_the_allow_list() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-mise-exec-overlay" kept@1.0.0
  : > "${HOME_DIR}/.stub-log-env"
  : > "${LOG_FILE}"
  MISE_ENV_JSON='{"FOO_SECRET_KEY":"s3cret","NPM_CONFIG_LOGLEVEL":"warn"}' NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" \
    NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" lane_run 'mise exec -- npm install clean@2.0.0'
  assert_status 0 "$FUNCNAME" || return
  [[ "$(grep -c '^ENVNAMES' "${LOG_FILE}")" -ge 5 ]] || { fail "$FUNCNAME: too few runs seen"; return; }
  ! grep '^ENVNAMES' "${LOG_FILE}" | grep -q 'FOO_SECRET_KEY' || { fail "$FUNCNAME: an overlay key outside the allow-list reached the lane's npm"; return; }
  grep '^ENVNAMES' "${LOG_FILE}" | grep -qi 'NPM_CONFIG_LOGLEVEL' || { fail "$FUNCNAME: an allow-listed overlay key was not carried"; return; }
  # a key the lane fixes itself and cannot carry: refuse and name it
  local key
  for key in npm_config_git NPM_CONFIG_ALLOW_GIT npm_config_node_options; do
    lane_prepare "lane-mise-exec-overlay-${key}" kept@1.0.0
    : > "${LOG_FILE}"
    MISE_ENV_JSON="{\"${key}\":\"x\"}" lane_run 'mise exec -- npm install clean@2.0.0'
    assert_status 100 "$FUNCNAME: ${key}" || return
    assert_err_contains_fragment "${key}" "$FUNCNAME: ${key}" || return
    assert_log_not_contains_fragment $'REAL\tmise\texec' "$FUNCNAME: ${key}" || return
    assert_log_not_contains_fragment 'PROJECTION' "$FUNCNAME: ${key}" || return
  done
  # the overlay the gate reads holds only npm settings and source selectors: anything else mise
  # sets (NODE_OPTIONS, a PATH) never reaches the lane's npm, which builds its own environment
  lane_prepare "lane-mise-exec-overlay-nodeoptions" kept@1.0.0
  : > "${HOME_DIR}/.stub-log-env"
  : > "${LOG_FILE}"
  MISE_ENV_JSON='{"NODE_OPTIONS":"--require /x.js"}' NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" \
    lane_run 'mise exec -- npm install clean@2.0.0'
  assert_status 0 "$FUNCNAME: NODE_OPTIONS" || return
  ! grep '^ENVNAMES' "${LOG_FILE}" | grep -q 'NODE_OPTIONS' || { fail "$FUNCNAME: an overlay NODE_OPTIONS reached the lane's npm"; return; }
  pass "$FUNCNAME"
}

case_project_lane_routing_mise_exec_with_an_inner_command_that_is_not_the_lanes_is_unchanged() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-mise-exec-other" kept@1.0.0
  local script
  # byte for byte: the output with the switch on is the output with it off
  for script in 'mise exec -- npm view kept' 'mise exec -- npm install -g okpkg' 'mise exec -- pnpm add okpkg' 'mise exec -- node script.js' 'mise exec -- npm uninstall kept' 'mise exec -- npm install-test'; do
    : > "${LOG_FILE}"
    lane_run "${script}"
    local status_on="${STATUS}" err_on real_on
    err_on="$(cat "${ERR_FILE}")"
    real_on="$(lane_delegation_of_log)"
    printf '{"install":{"project_lane":false}}\n' > "${HOME_DIR}/.config/safe/run/config.json"
    : > "${LOG_FILE}"
    lane_run "${script}"
    [[ "${STATUS}" == "${status_on}" && "$(cat "${ERR_FILE}")" == "${err_on}" && "$(lane_delegation_of_log)" == "${real_on}" ]] \
      || { printf 'on: %s\n%s\noff: %s\n%s\n' "${status_on}" "${err_on}" "${STATUS}" "$(cat "${ERR_FILE}")" >&2; fail "$FUNCNAME: ${script} differs with the switch on"; return; }
    printf '{"install":{"project_lane":true}}\n' > "${HOME_DIR}/.config/safe/run/config.json"
  done
  # a global install under mise: the lane hands it on, and the outer mise runs the original command, as today
  : > "${LOG_FILE}"
  lane_run 'mise exec -- npm install -g okpkg'
  assert_log_contains $'REAL\tmise\texec\t--\tnpm\tinstall\t-g\tokpkg' "$FUNCNAME" || return
  assert_log_not_contains_fragment 'PROJECTION' "$FUNCNAME" || return
  pass "$FUNCNAME"
}


# ---- routing, review of the first pass (ticket 1633) ----------------------------------------

# 1. Safety before compatibility: a reason that is only UNSUPPORTED never outranks a safety check.
case_project_lane_routing_a_compatibility_reason_never_outranks_a_safety_check() {
  skip_lockdiff_case "$FUNCNAME" || return
  local before
  # a committed version 1 lockfile together with a refused argument: the argument refuses
  lane_prepare "lane-safety-arg" kept@1.0.0
  lane_lock kept@1.0.0 | jq -c '.lockfileVersion = 1' > "${WORK_DIR}/package-lock.json"
  lane_commit
  : > "${LOG_FILE}"
  lane_run 'npm install clean'
  lane_unsupported_case "$FUNCNAME" install 'a refused argument beside a v1 lockfile' || return
  assert_err_not_contains_fragment 'one-shot' "$FUNCNAME" || return
  # ... with a private name: the private-name guard refuses
  lane_prepare "lane-safety-private" kept@1.0.0
  lane_private_store || { fail "$FUNCNAME: store"; return; }
  lane_lock kept@1.0.0 | jq -c '.lockfileVersion = 1' > "${WORK_DIR}/package-lock.json"
  jq -c '.dependencies["@p/lib"] = "^1.0.0"' "${WORK_DIR}/package.json" > "${WORK_DIR}/package.json.new"
  mv "${WORK_DIR}/package.json.new" "${WORK_DIR}/package.json"
  lane_commit
  : > "${LOG_FILE}"
  lane_run 'npm install clean@2.0.0'
  lane_unsupported_case "$FUNCNAME" install 'a private name beside a v1 lockfile' || return
  assert_err_contains_fragment 'touches the private-registry store' "$FUNCNAME" || return
  assert_err_not_contains_fragment 'one-shot' "$FUNCNAME" || return
  # ... with an .npmrc that is not admitted: both are compatibility reasons, both established, and NO npm of
  # the lane reads that project (only the route probe, in a scratch directory, ran) before today's gate
  lane_prepare "lane-safety-npmrc" kept@1.0.0
  lane_lock kept@1.0.0 | jq -c '.lockfileVersion = 1' > "${WORK_DIR}/package-lock.json"
  printf 'strict-ssl=false\n' > "${WORK_DIR}/.npmrc"
  lane_commit
  lane_oneshot_case "$FUNCNAME" install 'is not a version 2 or 3 lockfile; .npmrc line 1' 'npm install clean@2.0.0' || return
  [[ "$(grep -c 'replace-registry-host=never' "${LANE_ONESHOT_TRACE}")" == 1 ]] || { fail "$FUNCNAME: the lane probed a project whose .npmrc was not admitted ($(grep -c 'replace-registry-host=never' "${LANE_ONESHOT_TRACE}") lane probes)"; return; }
  # contrast: the same v1 lockfile with an admitted configuration is probed by the guards before the one-shot
  lane_prepare "lane-safety-guards-ran" kept@1.0.0
  lane_lock kept@1.0.0 | jq -c '.lockfileVersion = 1' > "${WORK_DIR}/package-lock.json"
  lane_commit
  lane_oneshot_case "$FUNCNAME" install 'is not a version 2 or 3 lockfile' 'npm install clean@2.0.0' || return
  [[ "$(grep -c 'replace-registry-host=never' "${LANE_ONESHOT_TRACE}")" -ge 3 ]] || { fail "$FUNCNAME: the guards did not run before the one-shot"; return; }
  # a committed lockfile with a path outside the tree is UNSAFE: refused, committed or not
  local how
  for how in committed uncommitted; do
    lane_prepare "lane-safety-outside-${how}" kept@1.0.0
    lane_lock kept@1.0.0 | jq -c '.packages["../outside/pkg"] = {"version":"1.0.0"}' > "${WORK_DIR}/package-lock.json"
    [[ "${how}" == committed ]] && lane_commit
    before="$(lane_digests)"
    : > "${LOG_FILE}"
    lane_run 'npm install clean@2.0.0'
    lane_unsupported_case "$FUNCNAME" install "a path outside the tree (${how})" || return
    assert_err_contains_fragment 'names a path outside the tree' "$FUNCNAME: ${how}" || return
    assert_err_not_contains_fragment 'one-shot' "$FUNCNAME: ${how}" || return
    assert_lane_untouched "${before}" "$FUNCNAME: ${how}" || return
  done
  # mixed causes: one established (a committed v1 lockfile), one not (a manifest source in uncommitted changes): refused
  lane_prepare "lane-safety-mixed" kept@1.0.0
  lane_lock kept@1.0.0 | jq -c '.lockfileVersion = 1' > "${WORK_DIR}/package-lock.json"
  lane_commit
  jq -c '.dependencies.odd = "git+https://example.invalid/x.git"' "${WORK_DIR}/package.json" > "${WORK_DIR}/package.json.new"
  mv "${WORK_DIR}/package.json.new" "${WORK_DIR}/package.json"
  : > "${LOG_FILE}"
  lane_run 'npm install clean@2.0.0'
  lane_unsupported_case "$FUNCNAME" install 'mixed causes' || return
  assert_err_contains_fragment 'package.json differs from the committed one' "$FUNCNAME" || return
  assert_err_not_contains_fragment 'one-shot' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# the one-shot route where today's gate itself refuses: its refusal is the delegate's, never the lane's
case_project_lane_routing_the_one_shot_route_carries_todays_gates_own_refusal() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-oneshot-refusal" kept@1.0.0
  jq -c '.dependencies.odd = "git+https://example.invalid/x.git"' "${WORK_DIR}/package.json" > "${WORK_DIR}/package.json.new"
  mv "${WORK_DIR}/package.json.new" "${WORK_DIR}/package.json"
  lane_commit
  lane_oneshot_case "$FUNCNAME" install 'manifest.dependencies.odd' 'npm install blockme@1.0.0' || return
  [[ "${STATUS}" == 0 ]] || true
  pass "$FUNCNAME"
}

# 2. Provenance of the host decision.
case_project_lane_routing_a_configuration_file_chosen_through_the_environment_refuses() {
  skip_lockdiff_case "$FUNCNAME" || return
  local name
  for name in npm_config_userconfig NPM_CONFIG_USERCONFIG npm_config_globalconfig NPM_CONFIG_GLOBALCONFIG; do
    lane_prepare "lane-provenance-${RANDOM}" kept@1.0.0
    : > "${LOG_FILE}"
    export "${name}=${CASE_DIR}/some-npmrc"
    NPM_LOCKDIFF_REGISTRY_CONFIG_JSON='{"registry":"https://r.example/"}' lane_run 'npm install clean@2.0.0'
    unset "${name}"
    assert_status 100 "$FUNCNAME: ${name}" || return
    assert_lane_final_line install "$FUNCNAME: ${name}" || return
    assert_err_contains_fragment "${name}" "$FUNCNAME: ${name}" || return
    assert_err_contains_fragment 'selects a configuration file for this command' "$FUNCNAME: ${name}" || return
    assert_err_not_contains_fragment 'one-shot' "$FUNCNAME: ${name}" || return
    assert_lane_no_delegate "$FUNCNAME: ${name}" || return
  done
  pass "$FUNCNAME"
}

case_project_lane_routing_a_probe_that_fails_to_load_is_a_refusal_never_missing_capabilities() {
  skip_lockdiff_case "$FUNCNAME" || return
  # the gate: a probe that exits non-zero or answers nothing
  local status
  for status in 3 1; do
    lane_prepare "lane-probe-status-${status}" kept@1.0.0
    : > "${LOG_FILE}"
    NODE_PROBE_STATUS="${status}" lane_run 'npm install clean@2.0.0'
    assert_status 100 "$FUNCNAME: probe status ${status}" || return
    assert_lane_final_line install "$FUNCNAME: probe status ${status}" || return
    assert_err_not_contains_fragment 'one-shot' "$FUNCNAME: probe status ${status}" || return
  done
  # the probe itself, on a real node, against an npm whose definitions module THROWS
  local real_node="${REAL_NODE_BIN}"
  [[ -n "${real_node}" ]] || { printf '# %s: no node here for the throwing-module check\n' "$FUNCNAME"; pass "$FUNCNAME"; return; }
  local npm_dir="${CASE_DIR}/fake-npm" script="${CASE_DIR}/lane-probe.cjs" out
  mkdir -p "${npm_dir}/node_modules/@npmcli/config/lib" "${npm_dir}/node_modules/semver"
  printf '{"name":"npm","version":"11.20.0"}\n' > "${npm_dir}/package.json"
  printf 'exports.valid = (v) => v; exports.gte = () => true\n' > "${npm_dir}/node_modules/semver/index.js"
  printf 'throw new Error("cannot load")\n' > "${npm_dir}/node_modules/@npmcli/config/lib/definitions.js"
  ( source "${ROOT_DIR}/lib/gate-lib.sh"; safe_gate_lane_write_probe_script "${script}" ) || { fail "$FUNCNAME: cannot write the probe"; return; }
  out="$(printf '{"floor":"11.12.1","options":["allow-git"]}' | "${real_node}" "${script}" "${npm_dir}" capability 2>/dev/null)"
  local rc=$?
  [[ "${rc}" == 3 && -z "${out}" ]] || { fail "$FUNCNAME: a definitions module that throws answered (rc ${rc}: ${out})"; return; }
  # ... and one that loads but lacks the option is the positive "missing" answer
  printf 'exports.definitions = { cache: {}, git: {} }\n' > "${npm_dir}/node_modules/@npmcli/config/lib/definitions.js"
  out="$(printf '{"floor":"11.12.1","options":["allow-git","cache"]}' | "${real_node}" "${script}" "${npm_dir}" capability 2>/dev/null)"
  [[ "$(jq -c '.missing' <<<"${out}")" == '["allow-git"]' ]] || { fail "$FUNCNAME: a definitions module without the option did not answer 'missing' (${out})"; return; }
  pass "$FUNCNAME"
}

# 3. mise exec: the lane owns the plain form only.
case_project_lane_routing_mise_exec_owns_only_the_plain_form() {
  skip_lockdiff_case "$FUNCNAME" || return
  local script
  for script in 'mise exec node@20 -- npm install clean@2.0.0' 'mise x node@20 -- npm install clean@2.0.0' 'mise exec --raw -- npm install clean@2.0.0' \
      'mise --raw exec -- npm install clean@2.0.0' 'mise exec -E dev -- npm install clean@2.0.0'; do
    lane_prepare "lane-mise-plain-${RANDOM}" kept@1.0.0
    : > "${LOG_FILE}"
    NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" lane_run "${script}"
    assert_status 100 "$FUNCNAME: ${script}" || return
    assert_lane_final_line install "$FUNCNAME: ${script}" || return
    assert_err_contains_fragment 'is not covered by the project lane' "$FUNCNAME: ${script}" || return
    assert_err_contains_fragment 'run npm in the project directory directly, or drop the option' "$FUNCNAME: ${script}" || return
    assert_log_not_contains_fragment $'REAL\tmise\texec' "$FUNCNAME: ${script}" || return
    assert_log_not_contains_fragment 'PROJECTION' "$FUNCNAME: ${script}" || return
  done
  # the plain forms, -C included, are the lane's
  lane_prepare "lane-mise-plain-ok" kept@1.0.0
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" lane_run "mise x --cd '${WORK_DIR}' -- npm install clean@2.0.0"
  assert_status 0 "$FUNCNAME: --cd" || return
  grep -q $'^PROJECTION\tnpm' "${LOG_FILE}" || { fail "$FUNCNAME: --cd did not reach the lane"; return; }
  # a global install under mise exec behaves exactly as with the switch off, an overlay key the lane could not carry included
  lane_prepare "lane-mise-global-overlay" kept@1.0.0
  lane_oneshot_global_equal "$FUNCNAME" 'mise exec -- npm install -g okpkg' 'MISE_ENV_JSON={"npm_config_git":"/bin/x"}' || return
  lane_oneshot_global_equal "$FUNCNAME" 'mise exec node@20 -- npm install -g okpkg' || return
  pass "$FUNCNAME"
}

# A command that is not the lane's runs as with the switch off: same status, standard output and error, events.
lane_oneshot_global_equal() { # label script [VAR=value ...]
  local label="$1" script="$2" kv on_status on_out on_err on_events
  shift 2
  for kv in "$@"; do export "${kv?}"; done
  : > "${LOG_FILE}"
  lane_run "${script}"
  on_status="${STATUS}"; on_out="$(cat "${OUT_FILE}")"; on_err="$(cat "${ERR_FILE}")"; on_events="$(lane_delegation_of_log "${LOG_FILE}")"
  printf '{"install":{"project_lane":false}}\n' > "${HOME_DIR}/.config/safe/run/config.json"
  : > "${LOG_FILE}"
  lane_run "${script}"
  local same=1
  [[ "${STATUS}" == "${on_status}" && "$(cat "${OUT_FILE}")" == "${on_out}" && "$(cat "${ERR_FILE}")" == "${on_err}" && "$(lane_delegation_of_log "${LOG_FILE}")" == "${on_events}" ]] || same=0
  printf '{"install":{"project_lane":true}}\n' > "${HOME_DIR}/.config/safe/run/config.json"
  for kv in "$@"; do unset "${kv%%=*}"; done
  (( same )) || { printf 'on: %s\n%s\n' "${on_status}" "${on_err}" >&2; fail "${label}: ${script} differs from the switch off"; return 1; }
  [[ -n "${on_events}" ]] || { fail "${label}: ${script}: nothing ran"; return 1; }
  return 0
}

# 4. The result channel.
case_project_lane_routing_the_original_command_never_runs_when_the_lanes_result_is_lost() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-mise-result-lost" kept@1.0.0
  : > "${LOG_FILE}"
  SAFE_CORE_TAMPER=bind-lose-result NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" \
    lane_run 'mise exec -- npm install clean@2.0.0'
  assert_status 100 "$FUNCNAME" || return
  assert_lane_final_line install "$FUNCNAME" || return
  assert_err_contains_fragment 'result' "$FUNCNAME" || return
  assert_log_not_contains_fragment $'REAL\tmise\texec' "$FUNCNAME" || return
  [[ "$(grep -cP '^REAL\tnpm\tci\t' "${LOG_FILE}")" == 1 ]] || { fail "$FUNCNAME: the lane did not run exactly once"; return; }
  # the lane's own failure still ends the command with its status, and the original is not run either
  lane_prepare "lane-mise-result-failure" kept@1.0.0
  : > "${LOG_FILE}"
  NPM_CI_STATUS=7 NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" lane_run 'mise exec -- npm install clean@2.0.0'
  assert_status 7 "$FUNCNAME: a failed materialisation" || return
  assert_log_not_contains_fragment $'REAL\tmise\texec' "$FUNCNAME: a failed materialisation" || return
  pass "$FUNCNAME"
}

case_project_lane_routing_inherited_ownership_state_changes_nothing_at_the_wrapper_entry() {
  skip_lockdiff_case "$FUNCNAME" || return
  local state='export SAFE_GATE_MISE_LANE_RESULT=/inherited/result SAFE_GATE_MISE_LANE_DONE=1 SAFE_GATE_MISE_LANE_NONPLAIN=x; '
  # switch off: identical to the same command without it
  lane_prepare "lane-inherit-off" kept@1.0.0
  printf '{"install":{"project_lane":false}}\n' > "${HOME_DIR}/.config/safe/run/config.json"
  : > "${LOG_FILE}"
  lane_run 'npm install clean@2.0.0'
  local status_plain="${STATUS}" events_plain err_plain
  events_plain="$(lane_delegation_of_log)"; err_plain="$(cat "${ERR_FILE}")"
  : > "${LOG_FILE}"
  lane_run "${state}npm install clean@2.0.0"
  [[ "${STATUS}" == "${status_plain}" && "$(lane_delegation_of_log)" == "${events_plain}" && "$(cat "${ERR_FILE}")" == "${err_plain}" ]] \
    || { fail "$FUNCNAME: inherited state changed a command with the switch off"; return; }
  assert_log_contains $'REAL\tnpm\tinstall\tclean@2.0.0' "$FUNCNAME" || return
  # switch on: the lane runs as always, the inherited result path is never written
  lane_prepare "lane-inherit-on" kept@1.0.0
  : > "${LOG_FILE}"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" lane_run "${state}npm install clean@2.0.0"
  assert_status 0 "$FUNCNAME: switch on" || return
  grep -q $'^PROJECTION\tnpm' "${LOG_FILE}" || { fail "$FUNCNAME: the lane did not run"; return; }
  [[ ! -e /inherited ]] || { fail "$FUNCNAME: something was written under the inherited path"; return; }
  # mise exec with the same inherited state and the switch on: the lane is the command
  lane_prepare "lane-inherit-mise" kept@1.0.0
  : > "${LOG_FILE}"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" lane_run "${state}mise exec -- npm install clean@2.0.0"
  assert_status 0 "$FUNCNAME: mise exec" || return
  assert_log_not_contains_fragment $'REAL\tmise\texec' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_project_lane_routing_mise_exec_with_a_relative_directory() {
  skip_lockdiff_case "$FUNCNAME" || return
  lane_prepare "lane-mise-relative-C" kept@1.0.0
  local rel="${WORK_DIR#${CASE_DIR}/}"
  : > "${LOG_FILE}"
  NPM_LOCK_MUTATION_JSON="$(lane_lock kept@1.0.0 clean@2.0.0)" NPM_PROJECTION_MANIFEST_JSON="${LANE_CLEAN_ADD_MANIFEST}" \
    lane_run "cd '${CASE_DIR}' && mise -C '${rel}' exec -- npm install clean@2.0.0"
  assert_status 0 "$FUNCNAME" || return
  [[ -d "${WORK_DIR}/node_modules/clean" ]] || { fail "$FUNCNAME: the relative -C directory was not the project"; return; }
  assert_log_not_contains_fragment $'REAL\tmise\texec' "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# 5. Every refusal goes through the lane's renderer.
case_project_lane_routing_every_new_refusal_has_the_lanes_final_line() {
  skip_lockdiff_case "$FUNCNAME" || return
  # the guards' copy of the project cannot be made (the fallback helper)
  local out rc
  out="$(bash -c '
    source "$1/lib/gate-lib.sh"
    verb=install lane_sub="install [lane: project]" dest=() proj_args=() orig_args=() snap=/nonexistent proj=/nonexistent SAFE_GATE_LANE_GIT=/bin/false
    safe_gate_lane_guard() { return 0; }
    safe_gate_lane_cp() { return 1; }
    safe_gate_project_lane_guards_first
    echo "rc=$?"' _ "${ROOT_DIR}" 2>&1)"
  [[ "$(printf '%s\n' "${out}" | tail -n 1)" == "rc=100" ]] || { fail "$FUNCNAME: the copy failure did not return 100 ($out)"; return; }
  printf '%s\n' "${out}" | grep -qE '^safe: BLOCKED npm install \[lane: project\] — .*; details: safe explain$' || { fail "$FUNCNAME: the copy failure has no lane line ($out)"; return; }
  # the overlay refusal, under mise exec
  lane_prepare "lane-final-line-overlay" kept@1.0.0
  MISE_ENV_JSON='{"npm_config_git":"/bin/x"}' lane_run 'mise exec -- npm install clean@2.0.0'
  assert_status 100 "$FUNCNAME: overlay" || return
  assert_lane_final_line install "$FUNCNAME: overlay" || return
  assert_err_contains_fragment 'npm_config_git' "$FUNCNAME: overlay" || return
  pass "$FUNCNAME"
}

# 6. Nothing of the lane reaches today's gate.
case_project_lane_routing_whatever_the_lane_or_its_probes_set_is_put_back() {
  skip_lockdiff_case "$FUNCNAME" || return
  local out
  out="$(bash -c '
    source "$1/lib/gate-lib.sh"
    export SAFE_GATE_LOCKDIFF_KEEP=before SAFE_GATE_LANE_FOREIGN=theirs
    SAFE_GATE_LOCKDIFF_PLAIN=plain
    safe_gate_project_lane_run() {
      SAFE_GATE_LOCKDIFF_KEEP=changed; SAFE_GATE_LOCKDIFF_NEW=probe; unset SAFE_GATE_LOCKDIFF_PLAIN
      SAFE_GATE_LANE_PASS=1; return 0
    }
    safe_gate_project_lane_npm; rc=$?
    printf "%s|%s|%s|%s|%s|%s|%s\n" "${rc}" "${SAFE_GATE_LOCKDIFF_KEEP-unset}" "${SAFE_GATE_LOCKDIFF_NEW-unset}" "${SAFE_GATE_LOCKDIFF_PLAIN-unset}" "${SAFE_GATE_LANE_FOREIGN-unset}" "${SAFE_GATE_LANE_PASS-unset}" "$(env | grep -c "^SAFE_GATE_LOCKDIFF_KEEP=before$")"' _ "${ROOT_DIR}" 2>&1)"
  [[ "${out}" == "0|before|unset|plain|theirs|1|1" ]] || { fail "$FUNCNAME: the lane's state reached the delegate (${out})"; return; }
  # and through the one-shot route: the delegate's environment names are the switch-off ones (lane_oneshot_case)
  lane_prepare "lane-state-oneshot" kept@1.0.0
  jq -c '.dependencies.odd = "git+https://example.invalid/x.git"' "${WORK_DIR}/package.json" > "${WORK_DIR}/package.json.new"
  mv "${WORK_DIR}/package.json.new" "${WORK_DIR}/package.json"
  lane_commit
  lane_oneshot_case "$FUNCNAME" install 'manifest.dependencies.odd' 'npm install clean@2.0.0' || return
  [[ ! -d "${WORK_DIR}/.safe-bind-"* ]] 2>/dev/null || { fail "$FUNCNAME: a staging directory is left"; return; }
  pass "$FUNCNAME"
}


main() {
  local case
  for case in \
    case_gate_lib_missing_fails_closed \
    case_wrapper_passthrough_is_cheap \
    case_refusal_message_contract \
    case_large_pinned_install_and_socket_rate_nontty \
    case_infra_only_warn_no_host_allow_and_needs_a_tty \
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
    case_composer_reinstall_create_project \
    case_composer_nonglobal_working_dir \
    case_composer_working_dir_missing_audit_warns_once \
    case_composer_global_canonical_routing \
    case_npm_dedupe_lockdiff_empty_delegates_without_scan \
    case_npm_lockdiff_absent_node_modules_refuses \
    case_npm_lockdiff_partial_tree_audits_reify_candidates \
    case_npm_lockdiff_version_mismatched_tree_is_a_reify_candidate \
    case_npm_lockdiff_exempts_never_installed_optional_entries \
    case_npm_lockdiff_symlinked_entry_is_audited \
    case_npm_lockdiff_target_platform_follows_npm_argv \
    case_npm_lockdiff_dash_led_target_platform_travels_verbatim \
    case_npm_lockdiff_target_platform_follows_npm_environment \
    case_npm_lockdiff_target_platform_follows_project_npmrc \
    case_npm_lockdiff_refuses_relative_config_paths \
    case_npm_lockdiff_mirrors_workspace_member_manifests \
    case_npm_lockdiff_refuses_escaping_workspace_pattern \
    case_npm_lockdiff_member_set_belt_refuses_dropped_member \
    case_npm_lockdiff_mirrors_file_dependency_manifest \
    case_npm_lockdiff_manifest_copy_failure_is_one_line \
    case_npm_lockdiff_refuses_cwd_dependent_config \
    case_npm_lockdiff_refuses_hidden_config_expansion \
    case_npm_lockdiff_refuses_nonregistry_reify_candidate \
    case_npm_lockdiff_projection_sees_project_npmrc \
    case_npm_dedupe_lockdiff_introduced_block_refuses_without_delegation \
    case_npm_dedupe_lockdiff_parse_failure_fails_closed \
    case_npm_prune_lockdiff_introduced_block_refuses_without_delegation \
    case_npm_lockdiff_prefixes_route_to_projection \
    case_project_lane_switch_off_keeps_todays_gate \
    case_project_lane_switch_off_leaves_the_delegate_environment_alone \
    case_project_lane_update_that_fixes_a_critical_passes \
    case_project_lane_clean_add_in_a_project_with_findings_passes \
    case_project_lane_introduced_critical_refuses_104_untouched \
    case_project_lane_introduced_high_refuses_100_untouched \
    case_project_lane_below_high_introduction_informs_and_passes \
    case_project_lane_known_malware_on_an_untouched_package_blocks \
    case_project_lane_blocklisted_untouched_package_blocks \
    case_project_lane_helper_output_that_is_not_a_complete_document_refuses \
    case_project_lane_missing_evidence_refuses_102 \
    case_project_lane_unbound_entry_refuses_before_any_write \
    case_project_lane_committed_lockfile_entries_are_admitted_before_npm_runs \
    case_project_lane_required_entry_missing_from_the_tree_fails \
    case_project_lane_entry_under_another_version_fails \
    case_project_lane_entry_under_another_name_fails \
    case_project_lane_entry_the_lockfile_lacks_fails \
    case_project_lane_failed_install_leaves_the_project_untouched_and_stays_npms \
    case_project_lane_interruption_leaves_the_project_untouched \
    case_project_lane_input_changed_since_judging_is_never_overwritten \
    case_project_lane_competing_lockfile_appearing_meanwhile_refuses \
    case_project_lane_binder_report_reaches_the_operator \
    case_project_lane_pinned_project_runs_one_pair_in_every_phase \
    case_project_lane_every_npm_run_gets_exactly_the_listed_environment \
    case_project_lane_reaches_one_npm_through_a_version_manager_shim \
    case_project_lane_audit_only_mode_refuses \
    case_project_lane_controls_the_npm_startup_environment \
    case_project_lane_unsupported_commands_refuse_without_a_fallback \
    case_project_lane_unsupported_project_shapes_refuse \
    case_project_lane_symlinked_tree_root_refuses_before_npm \
    case_project_lane_replaces_an_existing_tree_only_when_verified \
    case_project_lane_registry_must_be_the_canonical_public_one \
    case_project_lane_frozen_invocation_is_probed_apart \
    case_project_lane_selection_comes_from_the_effective_configuration \
    case_project_lane_global_exception_follows_npms_effective_setting \
    case_project_lane_takes_one_exclusive_lock_before_reading \
    case_project_lane_dry_run_judges_and_writes_nothing \
    case_project_lane_refusal_lines_are_sanitised \
    case_project_lane_projection_failure_stays_npms \
    case_project_lane_guards_refuse_in_the_lane_form \
    case_project_lane_project_touching_the_private_store_refuses_before_the_auditor \
    case_project_lane_inherited_runner_state_is_discarded \
    case_project_lane_redirected_configuration_does_not_enable_the_lane \
    case_project_lane_large_graph_reaches_a_verdict \
    case_project_lane_success_needs_a_whole_decision_and_a_whole_bind_document \
    case_project_lane_empty_tree_still_succeeds \
    case_project_lane_projected_link_does_not_mask_a_known_block \
    case_project_lane_genuine_global_install_goes_to_todays_gate \
    case_project_lane_nothing_is_written_to_the_project_before_publication \
    case_project_lane_special_file_as_configuration_does_not_hang \
    case_project_lane_head_comparison_ignores_replacement_objects \
    case_project_lane_admission_is_npms_not_a_pattern \
    case_project_lane_malformed_output_of_every_producer_refuses \
    case_project_lane_selection_comes_from_the_selected_node_exactly \
    case_project_lane_frozen_diagnostics_are_cleaned_and_npms_status_kept \
    case_project_lane_signal_to_the_shell_is_forwarded_and_the_report_still_arrives \
    case_project_lane_project_npmrc_is_admitted_as_text_before_any_npm_run \
    case_project_lane_every_npm_command_line_fixes_its_destinations \
    case_project_lane_capability_is_read_from_the_npms_definitions \
    case_project_lane_launcher_that_cannot_be_followed_refuses \
    case_project_lane_the_selected_npms_parser_must_agree \
    case_project_lane_the_consumed_fields_of_every_document_are_checked \
    case_project_lane_one_renderer_for_every_child_diagnostic \
    case_project_lane_a_binder_killed_at_start_up_is_an_interruption \
    case_project_lane_a_known_block_outranks_an_unsupported_dependency_edge \
    case_project_lane_baseline_a_hand_edited_lockfile_is_judged_against_the_committed_one \
    case_project_lane_baseline_a_generated_lockfile_in_a_project_that_had_none_is_entirely_introduced \
    case_project_lane_baseline_no_lockfile_anywhere_introduces_the_whole_resolved_graph \
    case_project_lane_baseline_two_commands_in_a_row_the_second_starts_from_the_first \
    case_project_lane_baseline_a_dirty_edit_after_a_verified_uncommitted_install_is_judged \
    case_project_lane_baseline_a_fresh_clone_starts_from_its_committed_lockfile \
    case_project_lane_baseline_a_project_outside_git_starts_empty_then_from_what_safe_stored \
    case_project_lane_baseline_nothing_is_recorded_unless_the_decision_is_clear \
    case_project_lane_routing_a_compatibility_reason_never_outranks_a_safety_check \
    case_project_lane_routing_the_one_shot_route_carries_todays_gates_own_refusal \
    case_project_lane_routing_a_configuration_file_chosen_through_the_environment_refuses \
    case_project_lane_routing_a_probe_that_fails_to_load_is_a_refusal_never_missing_capabilities \
    case_project_lane_routing_mise_exec_owns_only_the_plain_form \
    case_project_lane_routing_the_original_command_never_runs_when_the_lanes_result_is_lost \
    case_project_lane_routing_inherited_ownership_state_changes_nothing_at_the_wrapper_entry \
    case_project_lane_routing_mise_exec_with_a_relative_directory \
    case_project_lane_routing_every_new_refusal_has_the_lanes_final_line \
    case_project_lane_routing_whatever_the_lane_or_its_probes_set_is_put_back \
    case_project_lane_routing_a_committed_npmrc_outside_the_allow_list_takes_the_one_shot_route \
    case_project_lane_routing_an_npm_without_the_capabilities_takes_the_one_shot_route \
    case_project_lane_routing_a_flag_an_environment_setting_a_broken_guard_and_a_dirty_lockfile_cannot_reach_the_one_shot_route \
    case_project_lane_routing_no_refusal_tells_the_caller_to_turn_the_lane_off \
    case_project_lane_routing_ci_dedupe_and_prune_are_refused_where_there_is_nothing_to_fall_back_to \
    case_project_lane_routing_the_install_test_families_keep_todays_gate_with_a_one_shot_line \
    case_project_lane_routing_aliases_and_prefixes_of_every_verb_keep_their_route \
    case_project_lane_routing_mise_exec_runs_the_lane_once_and_nothing_else \
    case_project_lane_routing_mise_exec_runs_the_lane_in_the_directory_mise_would \
    case_project_lane_routing_mise_exec_overlay_is_carried_only_as_far_as_the_allow_list \
    case_project_lane_routing_mise_exec_with_an_inner_command_that_is_not_the_lanes_is_unchanged \
    case_project_lane_baseline_a_plan_whose_installation_failed_is_not_the_baseline_of_its_retry \
    case_project_lane_baseline_without_a_commit_a_lockfile_edited_by_hand_is_judged_whole \
    case_project_lane_baseline_a_mixed_case_private_name_in_the_manifest_refuses_before_the_projection \
    case_project_lane_baseline_a_directory_named_like_pathspec_syntax_is_read_literally \
    case_project_lane_baseline_a_malformed_committed_lockfile_is_not_hidden_by_a_recorded_match \
    case_project_lane_baseline_a_project_path_ending_with_a_newline_refuses \
    case_project_lane_baseline_a_lockfile_restored_by_hand_to_a_judged_one_is_a_baseline \
    case_project_lane_baseline_a_failed_materialisation_leaves_a_record_that_is_harmless \
    case_project_lane_baseline_a_lockfile_that_cannot_be_recorded_refuses_before_any_publication \
    case_project_lane_baseline_a_record_that_cannot_be_trusted_is_ignored_and_more_is_judged \
    case_project_lane_baseline_a_git_that_may_fetch_is_not_used \
    case_project_lane_baseline_a_damaged_repository_is_not_replaced_by_the_one_around_it \
    case_project_lane_baseline_the_committed_lockfile_is_read_with_its_raw_mode \
    case_project_lane_baseline_every_entry_of_the_lockfile_on_disk_is_admitted_before_the_projection \
    case_project_lane_baseline_the_evidence_request_never_carries_a_private_name_in_another_spelling_or_a_version_that_is_not_one \
    case_project_lane_baseline_a_hand_edited_lockfile_is_admitted_before_the_projection \
    case_project_lane_baseline_the_committed_lockfile_is_read_with_three_outcomes \
    case_project_lane_baseline_a_private_name_only_the_baseline_carries_never_reaches_the_evidence_request \
    case_project_lane_a_member_of_a_workspace_that_is_not_a_repository_refuses \
    case_project_lane_baseline_a_publication_report_must_be_whole_to_count \
    case_project_lane_baseline_a_committed_lockfile_that_cannot_be_decoded_is_not_an_empty_baseline \
    case_project_lane_package_lock_only_publishes_the_judged_files_and_installs_nothing \
    case_project_lane_config_selectors_in_the_arguments_refuse_before_any_npm \
    case_project_lane_environment_destinations_are_compared_after_npms_trimming \
    case_project_lane_routing_keeps_the_operators_configuration_sources \
    case_project_lane_a_project_inside_a_workspace_root_refuses \
    case_project_lane_the_private_store_is_matched_over_every_name_without_an_auditor \
    case_project_lane_the_final_admission_is_read_by_npms_parser_too \
    case_project_lane_a_committed_lockfile_of_the_wrong_shape_is_missing_evidence \
    case_project_lane_the_renderer_ignores_case_and_filters_format_characters \
    case_project_lane_the_update_notifier_is_forced_off_and_a_nul_platform_refuses \
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
    case_scan_failed_outright_non_tty_blocks \
    case_critical_in_result_blocks_despite_exit_zero \
    case_scan_scope_other_ecosystem_reported_not_gating \
    case_scan_scope_own_ecosystem_still_gates \
    case_scan_scope_unattributed_or_inconsistent_gates \
    case_yarn_version_or_help_is_not_an_install \
    case_mise_exec_inner_non_install_verbs_pass_through \
    case_bun_eval_print_separate_value \
    case_catalog_specifiers_resolve_against_workspace \
    case_uv_plural_spellings_and_format_control \
    case_pnpm_run_verbs_cannot_auto_install \
    case_broken_scanner_warns_and_proceeds \
    case_malformed_result_document_is_not_read_as_clean \
    case_unwritable_result_destination_blocks_without_operator \
    case_no_verdict_scan_warns_and_proceeds_at_operator_terminal \
    case_clean_result_proceeds_quietly \
    case_missing_safe_audit_warns_per_command \
    case_non_install_passthrough \
    case_npm_complex_flags \
    case_pip_complex_flags \
    case_requirement_install_scans \
    case_pip_local_wheel \
    case_pip_requirement_any_basename \
    case_cargo_parser \
    case_go_parser \
    case_composer_parser \
    case_pip_cumulative_sources_all_reach_audit \
    case_python_private_route_context_reaches_audit \
    case_npm_scoped_and_userconfig_sources_reach_audit \
    case_source_credentials_preserved_for_audit \
    case_gate_never_leaks_sources_to_the_real_tool \
    case_npm_repeated_registry_keeps_true_last \
    case_stale_evidence_is_source_scoped \
    case_install_idempotent_no_wrappers \
    case_install_idempotent_with_completions \
    case_install_agent_skills \
    case_install_writes_gate_wrappers \
    case_uv_binary_is_displaced_and_gated \
    case_uv_displacement_refuses_to_clobber_an_existing_original \
    case_failed_wrapper_write_restores_the_displaced_binary \
    case_uninstall_restores_the_displaced_binary \
    case_gate_resolves_a_displaced_original \
    case_gate_marker_probe_is_nul_safe \
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
    case_doctor_podman_probe_states \
    case_doctor_mise_shim_repair_is_actionable \
    case_doctor_ecosystem_auditors_are_advisory_not_prereq \
    case_uv_index_selectors_reach_audit \
    case_uninstall_removes_gate_wrappers \
    case_install_cleans_legacy_safe_install_artifacts \
    case_install_preserves_symlinked_zshrc \
    case_install_merges_legacy_state_into_new_schema \
    case_uninstall_preserves_symlinked_zshrc \
    case_mise_use_backend_audits \
    case_mise_runtime_and_other_backends_pass \
    case_mise_release_backends_share_one_notice \
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
    case_mise_use_tool_option_modeled \
    case_mise_entry_schema_is_strict \
    case_mise_unmodeled_sources_are_not_vouched \
    case_mise_scoped_exclusion_and_interactive \
    case_mise_infra_refusals_are_one_line \
    case_mise_c_physical_cd \
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
    case_mise_wrapper_gates_a_gated_argv0 \
    case_mise_shims_ahead_of_the_gate_still_audit \
    case_install_normalizes_mise_shims \
    case_install_links_runners_ahead_of_mise_shims \
    case_mise_wrapper_routes_runner_argv0_to_safe_run \
    case_install_runner_links_adopt_keep_and_never_clobber \
    case_doctor_and_status_report_runner_resolution \
    case_uninstall_removes_only_runner_links_safe_made \
    case_uninstall_restores_mise_shims \
    case_uninstall_cleans_shell_and_legacy_binaries \
    case_safe_run_gated_tool_delegation
  do
    "$case"
  done

  printf '%s passed, %s failed\n' "${PASS_COUNT}" "${FAIL_COUNT}"
  [[ "${FAIL_COUNT}" -eq 0 ]]
}

main "$@"
