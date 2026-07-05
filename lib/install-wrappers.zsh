# safe persistent install wrappers
# Source from .zshrc after installing with ./install.sh.

typeset -g _SAFE_INSTALL_WARNED_MISSING=0
typeset -g _SAFE_INSTALL_TIMEOUT_SECONDS="${SAFE_INSTALL_TIMEOUT_SECONDS:-30}"

safe_install_real() {
  command "$@"
}

safe_install_has_arg() {
  local needle="$1"
  shift
  local arg

  for arg in "$@"; do
    [[ "$arg" == "$needle" ]] && return 0
  done

  return 1
}

safe_install_has_prefix_arg() {
  local prefix="$1"
  shift
  local arg

  for arg in "$@"; do
    [[ "$arg" == ${prefix}* ]] && return 0
  done

  return 1
}

safe_install_warn_missing() {
  if (( ${_SAFE_INSTALL_WARNED_MISSING:-0} == 0 )); then
    print -u2 -- "safe audit not installed, skipping pre-install check"
    _SAFE_INSTALL_WARNED_MISSING=1
  fi
}

safe_install_run_audit() {
  if (( $+commands[timeout] )); then
    command timeout "${_SAFE_INSTALL_TIMEOUT_SECONDS:-${SAFE_INSTALL_TIMEOUT_SECONDS:-30}}" safe audit check "$@"
  else
    command safe audit check "$@"
  fi
}

safe_install_host_allow_file() {
  print -r -- "${SAFE_RUN_CONFIG_DIR:-${SAFE_CONFIG_DIR:-$HOME/.config/safe}/run}/host-allow.json"
}

safe_install_split_spec() {
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

  printf '%s\t%s\n' "${name}" "${version}"
}

safe_install_host_allow_matches() {
  local package="$1"
  local ecosystem="$2"
  local host_allow_file name version entry_version entry_ecosystem

  [[ "${ecosystem}" == "npm" ]] || return 1
  (( $+commands[jq] )) || return 1

  host_allow_file="$(safe_install_host_allow_file)"
  [[ -r "${host_allow_file}" ]] || return 1

  IFS=$'\t' read -r name version <<< "$(safe_install_split_spec "${package}")"
  [[ -n "${name}" && -n "${version}" && "${version}" != "latest" ]] || return 1

  entry_version="$(jq -r --arg p "${name}" '.packages[$p].version // empty' "${host_allow_file}" 2>/dev/null || true)"
  entry_ecosystem="$(jq -r --arg p "${name}" '.packages[$p].ecosystem // "npm"' "${host_allow_file}" 2>/dev/null || true)"

  [[ "${entry_version}" == "${version}" && "${entry_ecosystem}" == "npm" ]]
}

safe_install_confirm_critical() {
  if [[ -t 0 && -t 1 ]]; then
    local reply
    printf 'Proceed anyway? [y/N] '
    read -r reply
    [[ "${reply}" == "y" || "${reply}" == "Y" || "${reply}" == "yes" || "${reply}" == "YES" ]]
    return $?
  fi

  print -u2 -- "safe: BLOCKED install — safe audit scan found critical findings and this shell is non-interactive; to allow: ask the operator to re-run interactively and review; details: safe explain"
  return 102
}

safe_install_scan_project() {
  local scan_output
  local scan_status

  if ! (( $+commands[safe] )); then
    safe_install_warn_missing
    return 0
  fi

  scan_output="$(command safe audit scan --project . 2>&1)"
  scan_status=$?

  [[ -n "${scan_output}" ]] && print -r -- "${scan_output}"

  if (( scan_status == 0 )); then
    return 0
  fi

  if [[ "${scan_output:l}" == *critical* || "${scan_status}" -ge 2 ]]; then
    # Preamble only ahead of the interactive prompt; the non-TTY path emits a
    # single self-contained BLOCKED line instead.
    if [[ -t 0 && -t 1 ]]; then
      print -u2 -- "safe install: safe audit scan reported critical findings"
    fi
    safe_install_confirm_critical
    return $?
  fi

  print -u2 -- "safe install: safe audit scan failed with exit ${scan_status}; proceeding"
  return 0
}

safe_install_any_file() {
  local file

  for file in "$@"; do
    [[ -e "${file}" ]] && return 0
  done

  return 1
}

safe_install_npm_project_present() {
  safe_install_any_file package-lock.json npm-shrinkwrap.json package.json
}

safe_install_pnpm_project_present() {
  safe_install_any_file pnpm-lock.yaml package.json
}

safe_install_yarn_project_present() {
  safe_install_any_file yarn.lock package.json
}

safe_install_bun_project_present() {
  safe_install_any_file bun.lock bun.lockb package.json
}

safe_install_uv_project_present() {
  safe_install_any_file uv.lock pyproject.toml
}

safe_install_composer_project_present() {
  safe_install_any_file composer.lock composer.json
}

safe_install_cargo_project_present() {
  safe_install_any_file Cargo.lock Cargo.toml
}

safe_install_go_project_present() {
  safe_install_any_file go.sum go.mod
}

safe_install_pip_has_flag() {
  local flag_short="$1"
  local flag_long="$2"
  shift 2
  local arg

  for arg in "$@"; do
    [[ "${arg}" == "${flag_short}" || "${arg}" == "${flag_long}" || "${arg}" == "${flag_long}="* ]] && return 0
  done

  return 1
}

safe_install_pip_project_install() {
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

# One-line operator hint for a refused package. host-allow only unlocks npm
# installs, so other ecosystems point at the audit detail command instead.
safe_install_allow_hint() {
  local package="$1"
  local ecosystem="$2"

  if [[ "${ecosystem}" == "npm" ]]; then
    print -rn -- "to allow: ask the operator to run: safe run host-allow add ${package} --reason \"...\" — then retry"
  else
    print -rn -- "to allow: operator review — safe audit check ${package} --ecosystem ${ecosystem}"
  fi
}

# Check one package via safe audit.
# Returns: 0=GO/proceed, 100=policy refusal, 104=audit BLOCK verdict.
safe_install_check() {
  local package="$1"
  local ecosystem="$2"
  local audit_status

  if ! (( $+commands[safe] )); then
    safe_install_warn_missing
    return 0
  fi

  safe_install_run_audit "${package}" --ecosystem "${ecosystem}"
  audit_status=$?

  case "${audit_status}" in
    0)
      return 0
      ;;
    1|10)
      if safe_install_host_allow_matches "${package}" "${ecosystem}"; then
        print -u2 -- "safe install: safe audit warned for ${package}; exact host-allow entry permits install"
        return 0
      fi
      print -u2 -- "safe: BLOCKED ${ecosystem} install of ${package} — safe audit verdict WARN; $(safe_install_allow_hint "${package}" "${ecosystem}"); details: safe explain"
      return 100
      ;;
    2|20)
      print -u2 -- "safe: BLOCKED ${ecosystem} install of ${package} — safe audit verdict BLOCK; $(safe_install_allow_hint "${package}" "${ecosystem}"); details: safe explain"
      return 104
      ;;
    124|137)
      print -u2 -- "safe: BLOCKED ${ecosystem} install of ${package} — safe audit timed out (fail closed); retry or ask the operator; details: safe explain"
      return 100
      ;;
    *)
      print -u2 -- "safe: BLOCKED ${ecosystem} install of ${package} — safe audit failed with exit ${audit_status} (fail closed); ask the operator; details: safe explain"
      return 100
      ;;
  esac
}

safe_install_check_many() {
  local ecosystem="$1"
  shift
  local package

  for package in "$@"; do
    safe_install_check "${package}" "${ecosystem}" || return $?
  done

  return 0
}

safe_install_check_packages() {
  safe_install_check_many "$@"
}

safe_install_npm_like_packages() {
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

safe_install_npm_packages() {
  safe_install_npm_like_packages "$@"
}

safe_install_pnpm_packages() {
  safe_install_npm_like_packages "$@"
}

safe_install_bun_packages() {
  safe_install_npm_like_packages "$@"
}

safe_install_yarn_packages() {
  safe_install_npm_like_packages "$@"
}

safe_install_volta_packages() {
  safe_install_npm_like_packages "$@"
}

safe_install_cargo_packages() {
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

safe_install_go_packages() {
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
        packages+=("$(safe_install_go_spec "${arg}")")
        ;;
    esac
  done

  print -r -l -- "${packages[@]}"
}

safe_install_composer_packages() {
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
        packages+=("$(safe_install_colon_spec "${arg}")")
        ;;
    esac
  done

  print -r -l -- "${packages[@]}"
}

safe_install_npm_spec() {
  local spec="$1"
  local name version

  if [[ "${spec}" == *@npm:* ]]; then
    spec="${spec#*@npm:}"
  fi

  if [[ "${spec}" == @*/*:* ]]; then
    name="${spec%:*}"
    version="${spec##*:}"
  elif [[ "${spec}" != @* && "${spec}" == *:* ]]; then
    name="${spec%:*}"
    version="${spec##*:}"
  elif [[ "${spec}" == @*/*@* ]]; then
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

safe_install_python_spec() {
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

safe_install_colon_spec() {
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

safe_install_go_spec() {
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

safe_install_npm_like() {
  local tool="$1"
  shift
  local subcommand="${1:-}"
  local -a raw packages
  local parser="safe_install_${tool}_packages"
  local raw_package
  local project_present=1

  case "${subcommand}" in
    install|i|add|ci) ;;
    *) safe_install_real "${tool}" "$@"; return $? ;;
  esac

  if safe_install_has_arg "-g" "$@" || safe_install_has_arg "--global" "$@"; then
    raw=("${(@f)$(${parser} "${@:2}")}")
    packages=()
    for raw_package in "${raw[@]}"; do
      [[ -n "${raw_package}" ]] && packages+=("$(safe_install_npm_spec "${raw_package}")")
    done

    if (( ${#packages[@]} > 0 )); then
      safe_install_check_many npm "${packages[@]}" || return $?
    fi

    safe_install_real "${tool}" "$@"
    return $?
  fi

  case "${tool}" in
    npm) safe_install_npm_project_present; project_present=$? ;;
    pnpm) safe_install_pnpm_project_present; project_present=$? ;;
    bun) safe_install_bun_project_present; project_present=$? ;;
  esac

  if (( project_present == 0 )); then
    safe_install_scan_project || return $?
  fi

  raw=("${(@f)$(${parser} "${@:2}")}")
  packages=()
  for raw_package in "${raw[@]}"; do
    [[ -n "${raw_package}" ]] && packages+=("$(safe_install_npm_spec "${raw_package}")")
  done

  if (( ${#packages[@]} > 0 )); then
    safe_install_check_many npm "${packages[@]}" || return $?
  fi

  safe_install_real "${tool}" "$@"
}

# Every public wrapper starts with an inlined degraded-mode guard: some shell
# harnesses snapshot these public functions but strip the safe_install_*
# helpers (Claude Code drops single-underscore names, hence the helper rename).
# Without the guard a partial load dies with a silent 127 mid-function and
# agents read it as a broken toolchain. The guard refuses install/exec-ish
# subcommands legibly (exit 100) and passes everything else to the real tool.
# It must stay inlined — a shared guard helper could be stripped too.

npm() {
  if ! typeset -f safe_install_npm_like safe_install_check >/dev/null 2>&1; then
    case "${1:-}" in
      install|i|it|install-test|add|ci|exec|x|update|up|upgrade)
        print -u2 -- "safe: BLOCKED npm ${1} — safe install wrappers are partially loaded (helpers stripped by shell snapshot); ask the operator to run this in a regular terminal; details: safe explain"
        return 100 ;;
      *) command npm "$@"; return $? ;;
    esac
  fi
  safe_install_npm_like npm "$@"
}

pnpm() {
  if ! typeset -f safe_install_npm_like safe_install_check >/dev/null 2>&1; then
    case "${1:-}" in
      install|i|add|ci|dlx|exec|update|up|upgrade)
        print -u2 -- "safe: BLOCKED pnpm ${1} — safe install wrappers are partially loaded (helpers stripped by shell snapshot); ask the operator to run this in a regular terminal; details: safe explain"
        return 100 ;;
      *) command pnpm "$@"; return $? ;;
    esac
  fi
  safe_install_npm_like pnpm "$@"
}

bun() {
  if ! typeset -f safe_install_npm_like safe_install_check >/dev/null 2>&1; then
    case "${1:-}" in
      install|i|add|ci|x|update)
        print -u2 -- "safe: BLOCKED bun ${1} — safe install wrappers are partially loaded (helpers stripped by shell snapshot); ask the operator to run this in a regular terminal; details: safe explain"
        return 100 ;;
      *) command bun "$@"; return $? ;;
    esac
  fi
  safe_install_npm_like bun "$@"
}

yarn() {
  if ! typeset -f safe_install_yarn_packages safe_install_check >/dev/null 2>&1; then
    case "${1:-}" in
      ""|install|add|global|dlx|up|upgrade|upgrade-interactive)
        print -u2 -- "safe: BLOCKED yarn ${1:-install} — safe install wrappers are partially loaded (helpers stripped by shell snapshot); ask the operator to run this in a regular terminal; details: safe explain"
        return 100 ;;
      *) command yarn "$@"; return $? ;;
    esac
  fi
  local first="${1:-}"
  local second="${2:-}"
  local -a raw packages
  local raw_package

  if [[ "${first}" == "global" && "${second}" == "add" ]]; then
    raw=("${(@f)$(safe_install_yarn_packages "${@:3}")}")
    packages=()
    for raw_package in "${raw[@]}"; do
      [[ -n "${raw_package}" ]] && packages+=("$(safe_install_npm_spec "${raw_package}")")
    done

    if (( ${#packages[@]} > 0 )); then
      safe_install_check_many npm "${packages[@]}" || return $?
    fi

    safe_install_real yarn "$@"
    return $?
  fi

  if [[ "${first}" == "install" || "${first}" == "add" || -z "${first}" ]]; then
    if safe_install_yarn_project_present; then
      safe_install_scan_project || return $?
    fi

    if [[ "${first}" == "add" ]]; then
      raw=("${(@f)$(safe_install_yarn_packages "${@:2}")}")
      packages=()
      for raw_package in "${raw[@]}"; do
        [[ -n "${raw_package}" ]] && packages+=("$(safe_install_npm_spec "${raw_package}")")
      done

      if (( ${#packages[@]} > 0 )); then
        safe_install_check_many npm "${packages[@]}" || return $?
      fi
    fi
  fi

  safe_install_real yarn "$@"
}

safe_install_python_packages() {
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
        packages+=("$(safe_install_python_spec "${arg}")")
        ;;
    esac
  done

  print -r -l -- "${packages[@]}"
}

safe_install_pip_like() {
  local tool="$1"
  shift
  local subcommand="${1:-}"
  local -a packages

  [[ "${subcommand}" == "install" || "${subcommand}" == "upgrade" ]] || { safe_install_real "${tool}" "$@"; return $?; }

  if safe_install_pip_project_install "${@:2}"; then
    safe_install_scan_project || return $?
    safe_install_real "${tool}" "$@"
    return $?
  fi

  packages=("${(@f)$(safe_install_python_packages "${@:2}")}")
  if (( $? != 0 || ${#packages[@]} == 0 )); then
    safe_install_real "${tool}" "$@"
    return $?
  fi

  safe_install_check_many python "${packages[@]}" || return $?
  safe_install_real "${tool}" "$@"
}

pip() {
  if ! typeset -f safe_install_pip_like safe_install_check >/dev/null 2>&1; then
    case "${1:-}" in
      install|upgrade)
        print -u2 -- "safe: BLOCKED pip ${1} — safe install wrappers are partially loaded (helpers stripped by shell snapshot); ask the operator to run this in a regular terminal; details: safe explain"
        return 100 ;;
      *) command pip "$@"; return $? ;;
    esac
  fi
  safe_install_pip_like pip "$@"
}

pip3() {
  if ! typeset -f safe_install_pip_like safe_install_check >/dev/null 2>&1; then
    case "${1:-}" in
      install|upgrade)
        print -u2 -- "safe: BLOCKED pip3 ${1} — safe install wrappers are partially loaded (helpers stripped by shell snapshot); ask the operator to run this in a regular terminal; details: safe explain"
        return 100 ;;
      *) command pip3 "$@"; return $? ;;
    esac
  fi
  safe_install_pip_like pip3 "$@"
}

uv() {
  if ! typeset -f safe_install_python_packages safe_install_check >/dev/null 2>&1; then
    case "${1:-}" in
      sync|add|tool|pip|run)
        print -u2 -- "safe: BLOCKED uv ${1} — safe install wrappers are partially loaded (helpers stripped by shell snapshot); ask the operator to run this in a regular terminal; details: safe explain"
        return 100 ;;
      *) command uv "$@"; return $? ;;
    esac
  fi
  local first="${1:-}"
  local second="${2:-}"
  local -a packages

  if [[ "${first}" == "sync" ]]; then
    if safe_install_uv_project_present; then
      safe_install_scan_project || return $?
    fi

    safe_install_real uv "$@"
    return $?
  fi

  if [[ "${first}" == "tool" && "${second}" == "install" ]]; then
    packages=("${(@f)$(safe_install_python_packages "${@:3}")}")
    if (( $? != 0 || ${#packages[@]} == 0 )); then
      safe_install_real uv "$@"
      return $?
    fi

    safe_install_check_many python "${packages[@]}" || return $?
    safe_install_real uv "$@"
    return $?
  fi

  if [[ "${first}" == "pip" && "${second}" == "install" ]]; then
    if safe_install_pip_project_install "${@:3}"; then
      safe_install_scan_project || return $?
      safe_install_real uv "$@"
      return $?
    fi

    packages=("${(@f)$(safe_install_python_packages "${@:3}")}")
    if (( $? != 0 || ${#packages[@]} == 0 )); then
      safe_install_real uv "$@"
      return $?
    fi

    safe_install_check_many python "${packages[@]}" || return $?
    safe_install_real uv "$@"
    return $?
  fi

  safe_install_real uv "$@"
}

cargo() {
  if ! typeset -f safe_install_cargo_packages safe_install_check >/dev/null 2>&1; then
    case "${1:-}" in
      install)
        print -u2 -- "safe: BLOCKED cargo ${1} — safe install wrappers are partially loaded (helpers stripped by shell snapshot); ask the operator to run this in a regular terminal; details: safe explain"
        return 100 ;;
      *) command cargo "$@"; return $? ;;
    esac
  fi
  local subcommand="${1:-}"
  local -a packages

  if [[ "${subcommand}" != "install" ]]; then
    case "${subcommand}" in
      build|check|test|update)
        if safe_install_cargo_project_present; then
          safe_install_scan_project || return $?
        fi
        ;;
    esac

    safe_install_real cargo "$@"
    return $?
  fi

  if safe_install_has_arg "--path" "$@" || safe_install_has_prefix_arg "--path=" "$@" ||
     safe_install_has_arg "--git" "$@" || safe_install_has_prefix_arg "--git=" "$@"; then
    safe_install_real cargo "$@"
    return $?
  fi

  packages=("${(@f)$(safe_install_cargo_packages "${@:2}")}")
  if (( ${#packages[@]} > 0 )); then
    safe_install_check_many cargo "${packages[@]}" || return $?
  fi

  safe_install_real cargo "$@"
}

go() {
  if ! typeset -f safe_install_go_packages safe_install_check >/dev/null 2>&1; then
    case "${1:-}" in
      install|run)
        print -u2 -- "safe: BLOCKED go ${1} — safe install wrappers are partially loaded (helpers stripped by shell snapshot); ask the operator to run this in a regular terminal; details: safe explain"
        return 100 ;;
      *) command go "$@"; return $? ;;
    esac
  fi
  local subcommand="${1:-}"
  local second="${2:-}"
  local -a packages

  if [[ "${subcommand}" != "install" ]]; then
    if [[ "${subcommand}" == "build" || "${subcommand}" == "test" ||
          ( "${subcommand}" == "mod" && ( "${second}" == "download" || "${second}" == "tidy" ) ) ]]; then
      if safe_install_go_project_present; then
        safe_install_scan_project || return $?
      fi
    fi

    safe_install_real go "$@"
    return $?
  fi

  packages=("${(@f)$(safe_install_go_packages "${@:2}")}") || {
    safe_install_real go "$@"
    return $?
  }

  if (( ${#packages[@]} > 0 )); then
    safe_install_check_many go "${packages[@]}" || return $?
  fi

  safe_install_real go "$@"
}

composer() {
  if ! typeset -f safe_install_composer_packages safe_install_check >/dev/null 2>&1; then
    case "${1:-}" in
      install|update|require|global|exec)
        print -u2 -- "safe: BLOCKED composer ${1} — safe install wrappers are partially loaded (helpers stripped by shell snapshot); ask the operator to run this in a regular terminal; details: safe explain"
        return 100 ;;
      *) command composer "$@"; return $? ;;
    esac
  fi
  local first="${1:-}"
  local second="${2:-}"
  local -a packages

  if [[ "${first}" != "global" || "${second}" != "require" ]]; then
    if [[ "${first}" == "install" || "${first}" == "update" || "${first}" == "require" ]]; then
      if safe_install_composer_project_present; then
        safe_install_scan_project || return $?
      fi

      if [[ "${first}" == "require" ]]; then
        packages=("${(@f)$(safe_install_composer_packages "${@:2}")}")
        if (( ${#packages[@]} > 0 )); then
          safe_install_check_many composer "${packages[@]}" || return $?
        fi
      fi
    fi

    safe_install_real composer "$@"
    return $?
  fi

  packages=("${(@f)$(safe_install_composer_packages "${@:3}")}")
  if (( ${#packages[@]} > 0 )); then
    safe_install_check_many composer "${packages[@]}" || return $?
  fi

  safe_install_real composer "$@"
}

volta() {
  if ! typeset -f safe_install_volta_packages safe_install_check >/dev/null 2>&1; then
    case "${1:-}" in
      install|run)
        print -u2 -- "safe: BLOCKED volta ${1} — safe install wrappers are partially loaded (helpers stripped by shell snapshot); ask the operator to run this in a regular terminal; details: safe explain"
        return 100 ;;
      *) command volta "$@"; return $? ;;
    esac
  fi
  local subcommand="${1:-}"
  local -a packages
  local -a raw
  local raw_package

  if [[ "${subcommand}" != "install" ]]; then
    safe_install_real volta "$@"
    return $?
  fi

  raw=("${(@f)$(safe_install_volta_packages "${@:2}")}")
  packages=()
  for raw_package in "${raw[@]}"; do
    [[ -n "${raw_package}" ]] && packages+=("$(safe_install_npm_spec "${raw_package}")")
  done

  if (( ${#packages[@]} > 0 )); then
    safe_install_check_many npm "${packages[@]}" || return $?
  fi

  safe_install_real volta "$@"
}
