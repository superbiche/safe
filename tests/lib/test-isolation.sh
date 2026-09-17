#!/usr/bin/env bash
# SAFE_TEST_ISOLATION_MARKER
# Shared environment setup for every standalone test script.

safe_test_cleanup() {
  local root="${SAFE_TEST_ROOT:-}"
  [[ -n "$root" && -f "$root/.safe-test-root" ]] || return 0
  rm -rf -- "$root"
  SAFE_TEST_ROOT=""
  export SAFE_TEST_ROOT
}

safe_test_compose_exit_trap() {
  local command="$1"
  # The suite supplies a trap payload whose variables must expand on EXIT.
  # shellcheck disable=SC2064
  trap "${command}; safe_test_cleanup" EXIT
}

safe_test_normalize_path() {
  local path="${1:-}"
  while [[ "$path" != "/" && "$path" == */ ]]; do
    path="${path%/}"
  done
  printf '%s' "$path"
}

safe_test_real_home() {
  if command -v getent >/dev/null 2>&1; then
    getent passwd "$(id -u)" | cut -d: -f6
  elif [[ -n "${HOME:-}" ]]; then
    printf '%s' "$HOME"
  fi
}

safe_test_path_under_real_home() {
  local path="${1:-}" real_home
  real_home="$(safe_test_normalize_path "${SAFE_TEST_INVOKING_HOME:-}")"
  [[ -n "$path" && -n "$real_home" ]] || return 1
  case "$real_home" in
    /) [[ "$path" == /* ]] ;;
    *) [[ "$path" == "$real_home" || "$path" == "$real_home"/* ]] ;;
  esac
}

safe_test_assert_isolated_paths() {
  local name path
  local invoking_home
  invoking_home="$(safe_test_normalize_path "${SAFE_TEST_INVOKING_HOME:-}")"
  local -a path_vars=(
    SAFE_CONFIG_DIR SAFE_DATA_DIR SAFE_RUN_CONFIG_DIR SAFE_RUN_DATA_DIR
    SAFE_RUN_SEED_DIR SAFE_AUDIT_CONFIG_DIR SAFE_AUDIT_DATA_DIR
    SAFE_AUDIT_BIN_DIR SAFE_AUDIT_SCANNER_DIR SAFE_AUDIT_SOCKET_CACHE_DIR
    SAFE_BIN_DIR SAFE_ZSH_COMPLETION_DIR SAFE_AUDIT_DEFAULT_SCAN_ROOT
    SAFE_AUDIT_REMOTE_ROOT SAFE_AUDIT_IOC_ROOT SAFE_AUDIT_SETUP_VALIDATE_PATH
    SAFE_AUDIT_HOST_ALLOW_LOG SAFE_AUDIT_PATH SAFE_AUDIT_BIN
    SAFE_RUN_BLOCKED_FILE SAFE_RUN_CANONICAL_CONFIG_DIR SAFE_RUN_CONFIG_FILE
    SAFE_RUN_HOST_ALLOW_FILE SAFE_RUN_SCRIPTS_ALLOW_FILE SAFE_RUN_PATH
    SAFE_CONFIG_ROOT SAFE_DATA_ROOT SAFE_BIN_ROOT SAFE_DIR SAFE_REPO_DIR
    SAFE_GATE_LIB SAFE_GATE_AUDIT_BIN SAFE_RUN_BIN SAFE_CORE_BIN
    SAFE_INSTALL_NPM_GLOBALCONFIG SAFE_INSTALL_NPM_USERCONFIG
    SAFE_AGENT_CONTRACT SAFE_SELF AUBE_SECURITY_SCANNER COMPOSER_HOME
    CARGO_HOME PIP_CONFIG_FILE SAFE_ZSHRC SAFE_GATE_NPM_USERCONFIG
    SAFE_GATE_NPM_GLOBALCONFIG SAFE_GATE_PROJECT_DIR SAFE_INSTALL_PROJECT_DIR
  )
  if [[ -z "$invoking_home" ]]; then
    printf 'safe-test: FATAL: invoking HOME resolved empty\n' >&2
    return 1
  fi
  for name in HOME XDG_CONFIG_HOME XDG_DATA_HOME XDG_STATE_HOME XDG_CACHE_HOME GNUPGHOME; do
    path="${!name:-}"
    if safe_test_path_under_real_home "$path"; then
      printf 'safe-test: FATAL: %s resolves under invoking HOME: %s\n' "$name" "$path" >&2
      return 1
    fi
  done
  for name in "${path_vars[@]}"; do
    path="${!name:-}"
    if safe_test_path_under_real_home "$path"; then
      printf 'safe-test: FATAL: %s resolves under invoking HOME: %s\n' "$name" "$path" >&2
      return 1
    fi
  done
}

safe_test_setup_isolation() {
  local parent_tmp root original_home original_path original_mise_config
  local original_mise_data original_mise_cache original_prefix
  local prefix_present=0
  original_home="${HOME:-$(safe_test_real_home)}"
  original_path="${SAFE_TEST_ORIGINAL_PATH:-${PATH:-/usr/local/bin:/usr/bin:/bin}}"
  original_mise_config="${SAFE_TEST_ORIGINAL_MISE_CONFIG_DIR:-${MISE_CONFIG_DIR:-}}"
  original_mise_data="${SAFE_TEST_ORIGINAL_MISE_DATA_DIR:-${MISE_DATA_DIR:-}}"
  original_mise_cache="${SAFE_TEST_ORIGINAL_MISE_CACHE_DIR:-${MISE_CACHE_DIR:-}}"
  if [[ ${SAFE_TEST_ORIGINAL_NPM_PREFIX_PRESENT+x} ]]; then
    prefix_present="$SAFE_TEST_ORIGINAL_NPM_PREFIX_PRESENT"
    original_prefix="${SAFE_TEST_ORIGINAL_NPM_PREFIX:-}"
  elif [[ ${npm_config_prefix+x} || ${NPM_CONFIG_PREFIX+x} ]]; then
    prefix_present=1
    original_prefix="${npm_config_prefix:-${NPM_CONFIG_PREFIX:-}}"
  fi
  export SAFE_TEST_ORIGINAL_PATH="$original_path"
  export SAFE_TEST_ORIGINAL_MISE_CONFIG_DIR="$original_mise_config"
  export SAFE_TEST_ORIGINAL_MISE_DATA_DIR="$original_mise_data"
  export SAFE_TEST_ORIGINAL_MISE_CACHE_DIR="$original_mise_cache"
  export SAFE_TEST_ORIGINAL_NPM_PREFIX="${original_prefix:-}"
  export SAFE_TEST_ORIGINAL_NPM_PREFIX_PRESENT="$prefix_present"
  # run-all exports its original HOME so child suites can guard against it.
  SAFE_TEST_INVOKING_HOME="${SAFE_TEST_INVOKING_HOME:-$original_home}"
  SAFE_TEST_INVOKING_HOME="$(safe_test_normalize_path "$SAFE_TEST_INVOKING_HOME")"
  export SAFE_TEST_INVOKING_HOME
  [[ -n "$SAFE_TEST_INVOKING_HOME" ]] || {
    printf 'safe-test: FATAL: invoking HOME resolved empty\n' >&2
    return 1
  }

  parent_tmp="${TMPDIR:-/tmp}"
  export SAFE_TEST_PARENT_TMPDIR="$parent_tmp"
  root="$(mktemp -d "$parent_tmp/safe-test-env.XXXXXX")" || {
    printf 'safe-test: FATAL: cannot create an isolation tree under %s\n' "$parent_tmp" >&2
    return 1
  }
  : > "$root/.safe-test-root"
  SAFE_TEST_ROOT="$root"
  export SAFE_TEST_ROOT

  export HOME="$root/home"
  export XDG_CONFIG_HOME="$root/xdg/config"
  export XDG_DATA_HOME="$root/xdg/data"
  export XDG_STATE_HOME="$root/xdg/state"
  export XDG_CACHE_HOME="$root/xdg/cache"
  export GNUPGHOME="$root/gnupg"

  # Package managers accept path-bearing environment overrides before they
  # read HOME. Scrub every inherited npm_config spelling; the ordinary
  # config/cache defaults then resolve below the scratch HOME. KEEP_TOOLS
  # preserves only an inherited npm prefix so a real npm can find its
  # installed tree; it is never a cache or user/global config target.
  safe_test_sanitize_package_env() {
    local env_name
    local saved_prefix="${original_prefix:-}"
    local saved_prefix_present="$prefix_present"
    while IFS= read -r env_name; do
      case "$env_name" in
        npm_config_*|NPM_CONFIG_*) unset "$env_name" ;;
      esac
    done < <(compgen -e)
    unset COMPOSER_HOME CARGO_HOME PIP_CONFIG_FILE SAFE_ZSHRC \
      SAFE_GATE_NPM_USERCONFIG SAFE_GATE_NPM_GLOBALCONFIG AUBE_SECURITY_SCANNER
    # These defaults then resolve below the scratch HOME. Leaving them unset
    # also lets suites that exercise the variables set them per command.
    if [[ "$saved_prefix_present" == 1 && "${SAFE_TEST_ISOLATION_KEEP_TOOLS:-0}" == 1 ]]; then
      export npm_config_prefix="$saved_prefix"
    else
      export npm_config_prefix="$root/npm/prefix"
    fi
  }
  safe_test_sanitize_package_env

  # These are the directory-valued SAFE_* inputs used by bin/ and lib/.
  export SAFE_CONFIG_DIR="$root/config"
  export SAFE_DATA_DIR="$root/data"
  export SAFE_RUN_CONFIG_DIR="$root/run-config"
  export SAFE_RUN_DATA_DIR="$root/run-data"
  export SAFE_RUN_SEED_DIR="$root/run-seed"
  export SAFE_AUDIT_CONFIG_DIR="$root/audit-config"
  export SAFE_AUDIT_DATA_DIR="$root/audit-data"
  export SAFE_AUDIT_BIN_DIR="$root/audit-bin"
  export SAFE_AUDIT_SCANNER_DIR="$root/scanners"
  export SAFE_AUDIT_SOCKET_CACHE_DIR="$root/socket-cache"
  export SAFE_BIN_DIR="$root/bin"
  export SAFE_ZSH_COMPLETION_DIR="$root/zsh/site-functions"
  export SAFE_AUDIT_DEFAULT_SCAN_ROOT="$root/scan-root"
  export SAFE_AUDIT_REMOTE_ROOT="$root/remote-root"
  export SAFE_AUDIT_IOC_ROOT="$root/ioc-root"
  export SAFE_AUDIT_SETUP_VALIDATE_PATH="$root/validate"

  # Live npm/composer/shim probes opt into real tool discovery explicitly. That
  # opt preserves PATH and mise roots, while every HOME/XDG/SAFE root remains
  # scratch-isolated. All other suites get a clean tool lookup and mise state.
  if [[ "${SAFE_TEST_ISOLATION_KEEP_TOOLS:-0}" == "1" ]]; then
    tool_home="$(safe_test_real_home)"
    tool_home="${tool_home:-$original_home}"
    export MISE_CONFIG_DIR="${original_mise_config:-$tool_home/.config/mise}"
    export MISE_DATA_DIR="${original_mise_data:-$tool_home/.local/share/mise}"
    export MISE_CACHE_DIR="${original_mise_cache:-$tool_home/.cache/mise}"
  else
    export MISE_CONFIG_DIR="$root/mise/config"
    export MISE_DATA_DIR="$root/mise/data"
    export MISE_CACHE_DIR="$root/mise/cache"
  fi

  mkdir -p "$HOME" "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" "$XDG_STATE_HOME" \
    "$XDG_CACHE_HOME" "$GNUPGHOME" "$SAFE_CONFIG_DIR" "$SAFE_DATA_DIR" \
    "$SAFE_RUN_CONFIG_DIR" "$SAFE_RUN_DATA_DIR" "$SAFE_RUN_SEED_DIR" \
    "$SAFE_AUDIT_CONFIG_DIR" "$SAFE_AUDIT_DATA_DIR" "$SAFE_AUDIT_BIN_DIR" \
    "$SAFE_AUDIT_SCANNER_DIR" "$SAFE_AUDIT_SOCKET_CACHE_DIR" "$SAFE_BIN_DIR" \
    "$SAFE_ZSH_COMPLETION_DIR" "$SAFE_AUDIT_DEFAULT_SCAN_ROOT" \
    "$SAFE_AUDIT_REMOTE_ROOT" "$SAFE_AUDIT_IOC_ROOT" \
    "$SAFE_AUDIT_SETUP_VALIDATE_PATH" "$MISE_CONFIG_DIR" "$MISE_DATA_DIR" \
    "$MISE_CACHE_DIR"
  chmod 700 "$GNUPGHOME"

  export TMPDIR="$root/tmp"
  mkdir -p "$TMPDIR"
  # Default mode does not inherit user-installed safe wrappers or version-manager
  # shims. The keep-tools opt below is reserved for the four live tool probes.
  if [[ "${SAFE_TEST_ISOLATION_KEEP_TOOLS:-0}" == "1" ]]; then
    export PATH="$root/bin:$original_path"
  else
    export PATH="$root/bin:/usr/local/bin:/usr/bin:/bin"
  fi
  export GOFLAGS="${GOFLAGS:+$GOFLAGS }-buildvcs=false"
  safe_test_assert_isolated_paths || return 1
  trap 'safe_test_cleanup' EXIT
}
