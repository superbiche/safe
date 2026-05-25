# safe-install persistent install wrappers
# Source from .zshrc after installing with ./install.sh.

typeset -g _SAFE_INSTALL_WARNED_MISSING=0
typeset -g _SAFE_INSTALL_TIMEOUT_SECONDS="${SAFE_INSTALL_TIMEOUT_SECONDS:-30}"

_safe_install_real() {
  command "$@"
}

_safe_install_has_arg() {
  local needle="$1"
  shift
  local arg

  for arg in "$@"; do
    [[ "$arg" == "$needle" ]] && return 0
  done

  return 1
}

_safe_install_has_prefix_arg() {
  local prefix="$1"
  shift
  local arg

  for arg in "$@"; do
    [[ "$arg" == ${prefix}* ]] && return 0
  done

  return 1
}

_safe_install_warn_missing() {
  if (( _SAFE_INSTALL_WARNED_MISSING == 0 )); then
    print -u2 -- "safe-audit not installed, skipping pre-install check"
    _SAFE_INSTALL_WARNED_MISSING=1
  fi
}

_safe_install_run_audit() {
  if (( $+commands[timeout] )); then
    command timeout "${_SAFE_INSTALL_TIMEOUT_SECONDS}" safe-audit check "$@"
  else
    command safe-audit check "$@"
  fi
}

_safe_install_confirm_critical() {
  if [[ -t 0 && -t 1 ]]; then
    local reply
    printf 'Proceed anyway? [y/N] '
    read -r reply
    [[ "${reply}" == "y" || "${reply}" == "Y" || "${reply}" == "yes" || "${reply}" == "YES" ]]
    return $?
  fi

  print -u2 -- "safe-install: critical findings detected; aborting in non-TTY"
  return 1
}

_safe_install_scan_project() {
  local scan_output
  local scan_status

  if ! (( $+commands[safe-audit] )); then
    _safe_install_warn_missing
    return 0
  fi

  scan_output="$(command safe-audit scan --project . 2>&1)"
  scan_status=$?

  [[ -n "${scan_output}" ]] && print -r -- "${scan_output}"

  if (( scan_status == 0 )); then
    return 0
  fi

  if [[ "${scan_output:l}" == *critical* || "${scan_status}" -ge 2 ]]; then
    print -u2 -- "safe-install: safe-audit scan reported critical findings"
    _safe_install_confirm_critical
    return $?
  fi

  print -u2 -- "safe-install: safe-audit scan failed with exit ${scan_status}; proceeding"
  return 0
}

_safe_install_any_file() {
  local file

  for file in "$@"; do
    [[ -e "${file}" ]] && return 0
  done

  return 1
}

_safe_install_npm_project_present() {
  _safe_install_any_file package-lock.json npm-shrinkwrap.json package.json
}

_safe_install_pnpm_project_present() {
  _safe_install_any_file pnpm-lock.yaml package.json
}

_safe_install_yarn_project_present() {
  _safe_install_any_file yarn.lock package.json
}

_safe_install_bun_project_present() {
  _safe_install_any_file bun.lock bun.lockb package.json
}

_safe_install_uv_project_present() {
  _safe_install_any_file uv.lock pyproject.toml
}

_safe_install_composer_project_present() {
  _safe_install_any_file composer.lock composer.json
}

_safe_install_cargo_project_present() {
  _safe_install_any_file Cargo.lock Cargo.toml
}

_safe_install_go_project_present() {
  _safe_install_any_file go.sum go.mod
}

_pip_has_flag() {
  local flag_short="$1"
  local flag_long="$2"
  shift 2
  local arg

  for arg in "$@"; do
    [[ "${arg}" == "${flag_short}" || "${arg}" == "${flag_long}" || "${arg}" == "${flag_long}="* ]] && return 0
  done

  return 1
}

_safe_install_pip_project_install() {
  local arg
  local next_is_requirement=0
  local next_is_editable=0

  for arg in "$@"; do
    if (( next_is_requirement )); then
      [[ "${arg}" == requirements.txt || "${arg}" == requirements-*.txt ]] && return 0
      next_is_requirement=0
      continue
    fi

    if (( next_is_editable )); then
      return 0
    fi

    case "${arg}" in
      -r|--requirement)
        next_is_requirement=1
        ;;
      --requirement=requirements.txt|--requirement=requirements-*.txt)
        return 0
        ;;
      -e|--editable|--editable=*)
        return 0
        ;;
    esac
  done

  return 1
}

# Check one package via safe-audit.
# Returns: 0=GO/proceed, 2=abort.
_safe_install_check() {
  local package="$1"
  local ecosystem="$2"
  local audit_status

  if ! (( $+commands[safe-audit] )); then
    _safe_install_warn_missing
    return 0
  fi

  _safe_install_run_audit "${package}" --ecosystem "${ecosystem}"
  audit_status=$?

  case "${audit_status}" in
    0)
      return 0
      ;;
    1|10)
      print -u2 -- "safe-install: safe-audit warned for ${package}; aborting install"
      return 2
      ;;
    2|20)
      print -u2 -- "safe-install: blocked install of ${package}"
      return 2
      ;;
    124|137)
      print -u2 -- "safe-install: safe-audit timed out for ${package}; aborting install"
      return 2
      ;;
    *)
      print -u2 -- "safe-install: safe-audit failed for ${package} with exit ${audit_status}; aborting install"
      return 2
      ;;
  esac
}

_safe_install_check_many() {
  local ecosystem="$1"
  shift
  local package

  for package in "$@"; do
    _safe_install_check "${package}" "${ecosystem}" || return 2
  done

  return 0
}

_safe_install_check_packages() {
  _safe_install_check_many "$@"
}

_safe_install_npm_like_packages() {
  local -a packages
  local arg
  local skip_next=0
  local after_double_dash=0

  packages=()
  for arg in "$@"; do
    if (( skip_next )); then
      skip_next=0
      continue
    fi

    if (( after_double_dash )); then
      packages+=("${arg}")
      continue
    fi

    case "${arg}" in
      --)
        after_double_dash=1
        continue
        ;;
      -g|--global|-f|--force|-D|--dev|-P|--peer|-O|--optional|-E|--exact|-T|--tilde|--cached|--save|--save-prod|--save-dev|--save-optional|--save-peer|--no-save|--prefer-offline|--prefer-online|--legacy-peer-deps|--strict-peer-deps|--dry-run|--package-lock-only|--workspace-root|--ignore-scripts|--foreground-scripts)
        continue
        ;;
      --tag|--registry|--cache|--prefix|--userconfig|--globalconfig|--workspace|-w|--filter|--omit|--include|--install-strategy|--save-prefix|--mode|--cwd)
        skip_next=1
        continue
        ;;
      --tag=*|--registry=*|--cache=*|--prefix=*|--userconfig=*|--globalconfig=*|--workspace=*|--filter=*|--omit=*|--include=*|--install-strategy=*|--save-prefix=*|--mode=*|--cwd=*|--ignore-scripts=*)
        continue
        ;;
      -*)
        continue
        ;;
      *)
        packages+=("${arg}")
        ;;
    esac
  done

  print -r -l -- "${packages[@]}"
}

_safe_install_npm_packages() {
  _safe_install_npm_like_packages "$@"
}

_safe_install_pnpm_packages() {
  _safe_install_npm_like_packages "$@"
}

_safe_install_bun_packages() {
  _safe_install_npm_like_packages "$@"
}

_safe_install_yarn_packages() {
  _safe_install_npm_like_packages "$@"
}

_safe_install_volta_packages() {
  _safe_install_npm_like_packages "$@"
}

_safe_install_cargo_packages() {
  local -a packages
  local arg
  local skip_next=0

  packages=()
  for arg in "$@"; do
    if (( skip_next )); then
      skip_next=0
      continue
    fi

    case "${arg}" in
      --version|--vers|--index|--registry|--root|--target|--features|--bin|--example)
        skip_next=1
        continue
        ;;
      --version=*|--vers=*|--index=*|--registry=*|--root=*|--target=*|--features=*|--bin=*|--example=*)
        continue
        ;;
      --locked|--offline|--quiet|--debug|--force|-f|--list|--no-track|--all-features|--no-default-features)
        continue
        ;;
      -*)
        continue
        ;;
      *)
        packages+=("${arg}@latest")
        ;;
    esac
  done

  print -r -l -- "${packages[@]}"
}

_safe_install_go_packages() {
  local -a packages
  local arg
  local skip_next=0

  packages=()
  for arg in "$@"; do
    if (( skip_next )); then
      skip_next=0
      continue
    fi

    case "${arg}" in
      .|./*|../*|/*)
        return 1
        ;;
      -tags|-modfile|-overlay|-p|-gcflags|-ldflags|-asmflags|-buildmode|-compiler|-gccgoflags)
        skip_next=1
        continue
        ;;
      -tags=*|-modfile=*|-overlay=*|-p=*|-gcflags=*|-ldflags=*|-asmflags=*|-buildmode=*|-compiler=*|-gccgoflags=*)
        continue
        ;;
      -*)
        continue
        ;;
      *)
        packages+=("$(_safe_install_go_spec "${arg}")")
        ;;
    esac
  done

  print -r -l -- "${packages[@]}"
}

_safe_install_composer_packages() {
  local -a packages
  local arg
  local skip_next=0

  packages=()
  for arg in "$@"; do
    if (( skip_next )); then
      skip_next=0
      continue
    fi

    case "${arg}" in
      --dev|--update-no-dev|--update-with-dependencies|--update-with-all-dependencies|--ignore-platform-reqs|--no-update|--no-scripts|--no-progress|--no-install|--prefer-source|--prefer-dist|--prefer-install|--sort-packages|--optimize-autoloader|--classmap-authoritative|--apcu-autoloader)
        continue
        ;;
      --working-dir|--repository)
        skip_next=1
        continue
        ;;
      --working-dir=*|--repository=*|--prefer-install=*)
        continue
        ;;
      -*)
        continue
        ;;
      *)
        packages+=("$(_safe_install_colon_spec "${arg}")")
        ;;
    esac
  done

  print -r -l -- "${packages[@]}"
}

_safe_install_npm_spec() {
  local spec="$1"
  local name version

  if [[ "${spec}" == @*/*@* ]]; then
    name="${spec%@*}"
    version="${spec##*@}"
  elif [[ "${spec}" == *@* && "${spec}" != @* ]]; then
    name="${spec%@*}"
    version="${spec##*@}"
  else
    name="${spec}"
    version="latest"
  fi

  print -r -- "${name}@${version}"
}

_safe_install_python_spec() {
  local spec="$1"
  local name version

  if [[ "${spec}" == *"=="* ]]; then
    name="${spec%%==*}"
    version="${spec#*==}"
  elif [[ "${spec}" == *@* && "${spec}" != @* ]]; then
    name="${spec%@*}"
    version="${spec##*@}"
  else
    name="${spec}"
    version="latest"
  fi

  print -r -- "${name}@${version}"
}

_safe_install_colon_spec() {
  local spec="$1"
  local name version

  if [[ "${spec}" == *":"* ]]; then
    name="${spec%%:*}"
    version="${spec#*:}"
  else
    name="${spec}"
    version="latest"
  fi

  print -r -- "${name}@${version}"
}

_safe_install_go_spec() {
  local spec="$1"
  local name version

  if [[ "${spec}" == *@* ]]; then
    name="${spec%@*}"
    version="${spec##*@}"
  else
    name="${spec}"
    version="latest"
  fi

  print -r -- "${name}@${version}"
}

_safe_install_npm_like() {
  local tool="$1"
  shift
  local subcommand="${1:-}"
  local -a raw packages
  local parser="_safe_install_${tool}_packages"
  local raw_package
  local project_present=1

  case "${subcommand}" in
    install|i|add|ci) ;;
    *) _safe_install_real "${tool}" "$@"; return $? ;;
  esac

  if _safe_install_has_arg "-g" "$@" || _safe_install_has_arg "--global" "$@"; then
    raw=("${(@f)$(${parser} "${@:2}")}")
    packages=()
    for raw_package in "${raw[@]}"; do
      [[ -n "${raw_package}" ]] && packages+=("$(_safe_install_npm_spec "${raw_package}")")
    done

    if (( ${#packages[@]} > 0 )); then
      _safe_install_check_many npm "${packages[@]}" || return 2
    fi

    _safe_install_real "${tool}" "$@"
    return $?
  fi

  case "${tool}" in
    npm) _safe_install_npm_project_present; project_present=$? ;;
    pnpm) _safe_install_pnpm_project_present; project_present=$? ;;
    bun) _safe_install_bun_project_present; project_present=$? ;;
  esac

  if (( project_present == 0 )); then
    _safe_install_scan_project || return 1
  fi

  raw=("${(@f)$(${parser} "${@:2}")}")
  packages=()
  for raw_package in "${raw[@]}"; do
    [[ -n "${raw_package}" ]] && packages+=("$(_safe_install_npm_spec "${raw_package}")")
  done

  if (( ${#packages[@]} > 0 )); then
    _safe_install_check_many npm "${packages[@]}" || return 2
  fi

  _safe_install_real "${tool}" "$@"
}

npm() {
  _safe_install_npm_like npm "$@"
}

pnpm() {
  _safe_install_npm_like pnpm "$@"
}

bun() {
  _safe_install_npm_like bun "$@"
}

yarn() {
  local first="${1:-}"
  local second="${2:-}"
  local -a raw packages
  local raw_package

  if [[ "${first}" == "global" && "${second}" == "add" ]]; then
    raw=("${(@f)$(_safe_install_yarn_packages "${@:3}")}")
    packages=()
    for raw_package in "${raw[@]}"; do
      [[ -n "${raw_package}" ]] && packages+=("$(_safe_install_npm_spec "${raw_package}")")
    done

    if (( ${#packages[@]} > 0 )); then
      _safe_install_check_many npm "${packages[@]}" || return 2
    fi

    _safe_install_real yarn "$@"
    return $?
  fi

  if [[ "${first}" == "install" || "${first}" == "add" || -z "${first}" ]]; then
    if _safe_install_yarn_project_present; then
      _safe_install_scan_project || return 1
    fi

    if [[ "${first}" == "add" ]]; then
      raw=("${(@f)$(_safe_install_yarn_packages "${@:2}")}")
      packages=()
      for raw_package in "${raw[@]}"; do
        [[ -n "${raw_package}" ]] && packages+=("$(_safe_install_npm_spec "${raw_package}")")
      done

      if (( ${#packages[@]} > 0 )); then
        _safe_install_check_many npm "${packages[@]}" || return 2
      fi
    fi
  fi

  _safe_install_real yarn "$@"
}

_safe_install_python_packages() {
  local -a packages
  local arg
  local skip_next=0

  packages=()
  for arg in "$@"; do
    if (( skip_next )); then
      skip_next=0
      continue
    fi

    case "${arg}" in
      -r|--requirement|--requirement=*|-e|--editable|--editable=*)
        return 1
        ;;
      -c|--constraint|--index-url|--extra-index-url|--find-links|--trusted-host|--platform|--python-version|--implementation|--abi|--target|--prefix|--src|--upgrade-strategy|--config-settings|-C)
        skip_next=1
        continue
        ;;
      --constraint=*|--index-url=*|--extra-index-url=*|--find-links=*|--trusted-host=*|--platform=*|--python-version=*|--implementation=*|--abi=*|--target=*|--prefix=*|--src=*|--upgrade-strategy=*|--config-settings=*)
        continue
        ;;
      --upgrade|-U|--force-reinstall|--ignore-installed|--user|--break-system-packages|--no-deps|--pre)
        continue
        ;;
      -*)
        continue
        ;;
      .|./*|../*|/*|git+*|http://*|https://*)
        return 1
        ;;
      *)
        packages+=("$(_safe_install_python_spec "${arg}")")
        ;;
    esac
  done

  print -r -l -- "${packages[@]}"
}

_safe_install_pip_like() {
  local tool="$1"
  shift
  local subcommand="${1:-}"
  local -a packages

  [[ "${subcommand}" == "install" || "${subcommand}" == "upgrade" ]] || { _safe_install_real "${tool}" "$@"; return $?; }

  if _safe_install_pip_project_install "${@:2}"; then
    _safe_install_scan_project || return 1
    _safe_install_real "${tool}" "$@"
    return $?
  fi

  packages=("${(@f)$(_safe_install_python_packages "${@:2}")}")
  if (( $? != 0 || ${#packages[@]} == 0 )); then
    _safe_install_real "${tool}" "$@"
    return $?
  fi

  _safe_install_check_many python "${packages[@]}" || return 2
  _safe_install_real "${tool}" "$@"
}

pip() {
  _safe_install_pip_like pip "$@"
}

pip3() {
  _safe_install_pip_like pip3 "$@"
}

uv() {
  local first="${1:-}"
  local second="${2:-}"
  local -a packages

  if [[ "${first}" == "sync" ]]; then
    if _safe_install_uv_project_present; then
      _safe_install_scan_project || return 1
    fi

    _safe_install_real uv "$@"
    return $?
  fi

  if [[ "${first}" == "tool" && "${second}" == "install" ]]; then
    packages=("${(@f)$(_safe_install_python_packages "${@:3}")}")
    if (( $? != 0 || ${#packages[@]} == 0 )); then
      _safe_install_real uv "$@"
      return $?
    fi

    _safe_install_check_many python "${packages[@]}" || return 2
    _safe_install_real uv "$@"
    return $?
  fi

  if [[ "${first}" == "pip" && "${second}" == "install" ]]; then
    if _safe_install_pip_project_install "${@:3}"; then
      _safe_install_scan_project || return 1
      _safe_install_real uv "$@"
      return $?
    fi

    packages=("${(@f)$(_safe_install_python_packages "${@:3}")}")
    if (( $? != 0 || ${#packages[@]} == 0 )); then
      _safe_install_real uv "$@"
      return $?
    fi

    _safe_install_check_many python "${packages[@]}" || return 2
    _safe_install_real uv "$@"
    return $?
  fi

  _safe_install_real uv "$@"
}

cargo() {
  local subcommand="${1:-}"
  local -a packages

  if [[ "${subcommand}" != "install" ]]; then
    case "${subcommand}" in
      build|check|test|update)
        if _safe_install_cargo_project_present; then
          _safe_install_scan_project || return 1
        fi
        ;;
    esac

    _safe_install_real cargo "$@"
    return $?
  fi

  if _safe_install_has_arg "--path" "$@" || _safe_install_has_prefix_arg "--path=" "$@" ||
     _safe_install_has_arg "--git" "$@" || _safe_install_has_prefix_arg "--git=" "$@"; then
    _safe_install_real cargo "$@"
    return $?
  fi

  packages=("${(@f)$(_safe_install_cargo_packages "${@:2}")}")
  if (( ${#packages[@]} > 0 )); then
    _safe_install_check_many cargo "${packages[@]}" || return 2
  fi

  _safe_install_real cargo "$@"
}

go() {
  local subcommand="${1:-}"
  local second="${2:-}"
  local -a packages

  if [[ "${subcommand}" != "install" ]]; then
    if [[ "${subcommand}" == "build" || "${subcommand}" == "test" ||
          ( "${subcommand}" == "mod" && ( "${second}" == "download" || "${second}" == "tidy" ) ) ]]; then
      if _safe_install_go_project_present; then
        _safe_install_scan_project || return 1
      fi
    fi

    _safe_install_real go "$@"
    return $?
  fi

  packages=("${(@f)$(_safe_install_go_packages "${@:2}")}") || {
    _safe_install_real go "$@"
    return $?
  }

  if (( ${#packages[@]} > 0 )); then
    _safe_install_check_many go "${packages[@]}" || return 2
  fi

  _safe_install_real go "$@"
}

composer() {
  local first="${1:-}"
  local second="${2:-}"
  local -a packages

  if [[ "${first}" != "global" || "${second}" != "require" ]]; then
    if [[ "${first}" == "install" || "${first}" == "update" || "${first}" == "require" ]]; then
      if _safe_install_composer_project_present; then
        _safe_install_scan_project || return 1
      fi

      if [[ "${first}" == "require" ]]; then
        packages=("${(@f)$(_safe_install_composer_packages "${@:2}")}")
        if (( ${#packages[@]} > 0 )); then
          _safe_install_check_many composer "${packages[@]}" || return 2
        fi
      fi
    fi

    _safe_install_real composer "$@"
    return $?
  fi

  packages=("${(@f)$(_safe_install_composer_packages "${@:3}")}")
  if (( ${#packages[@]} > 0 )); then
    _safe_install_check_many composer "${packages[@]}" || return 2
  fi

  _safe_install_real composer "$@"
}

volta() {
  local subcommand="${1:-}"
  local -a packages
  local -a raw
  local raw_package

  if [[ "${subcommand}" != "install" ]]; then
    _safe_install_real volta "$@"
    return $?
  fi

  raw=("${(@f)$(_safe_install_volta_packages "${@:2}")}")
  packages=()
  for raw_package in "${raw[@]}"; do
    [[ -n "${raw_package}" ]] && packages+=("$(_safe_install_npm_spec "${raw_package}")")
  done

  if (( ${#packages[@]} > 0 )); then
    _safe_install_check_many npm "${packages[@]}" || return 2
  fi

  _safe_install_real volta "$@"
}
