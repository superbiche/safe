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

safe_test_real_home() {
  if [[ -n "${HOME:-}" ]]; then
    printf '%s' "$HOME"
  elif command -v getent >/dev/null 2>&1; then
    getent passwd "$(id -u)" | cut -d: -f6
  fi
}

safe_test_path_under_real_home() {
  local path="${1:-}" real_home="${SAFE_TEST_INVOKING_HOME:-}"
  [[ -n "$path" && -n "$real_home" ]] || return 1
  case "$real_home" in
    /) [[ "$path" == /* ]] ;;
    *) [[ "$path" == "$real_home" || "$path" == "$real_home"/* ]] ;;
  esac
}

safe_test_assert_isolated_paths() {
  local name path
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
    SAFE_AGENT_CONTRACT SAFE_SELF
  )
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
  local parent_tmp root
  # run-all exports its original HOME so child suites can guard against it.
  SAFE_TEST_INVOKING_HOME="${SAFE_TEST_INVOKING_HOME:-$(safe_test_real_home)}"
  export SAFE_TEST_INVOKING_HOME

  parent_tmp="${TMPDIR:-/tmp}"
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

  # mise is consulted by several real-tool probes; keep its config and cache
  # outside the invoking HOME even when the caller has a configured mise.
  export MISE_CONFIG_DIR="$root/mise/config"
  export MISE_DATA_DIR="$root/mise/data"
  export MISE_CACHE_DIR="$root/mise/cache"

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
  # Do not inherit user-installed safe wrappers or version-manager shims. The
  # suites add their own fixture bins explicitly, and system tools remain.
  export PATH="$root/bin:/usr/local/bin:/usr/bin:/bin"
  export GOFLAGS="${GOFLAGS:+$GOFLAGS }-buildvcs=false"
  safe_test_assert_isolated_paths || return 1
  trap 'safe_test_cleanup' EXIT
}
