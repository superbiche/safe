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

# A bare command name has no package-spec syntax: no version/tag/alias.
# Only such names are eligible for the local-bin passthrough, because a
# versioned or aliased spec (foo@latest, foo@npm:bar) can still fetch
# remotely even when a same-named local bin exists (npm matches a local
# dep only on exact name AND version).
safe_install_is_bare_name() {
  case "$1" in
    *@*|*:*) return 1 ;;
    *) return 0 ;;
  esac
}

# Project-local bin lookup for the exec-gate passthrough: walk
# node_modules/.bin from the PHYSICAL cwd upward, nearest first — npm's own
# bin resolution, so hoisted monorepo workspaces resolve their tools.
# Builtins and parameter expansion only: exported functions or PATH shadowing
# must never steer the walk (mirrors find_local_project_bin in bin/safe-run;
# see PR #19 review rounds 1-3 for the symlinked-cwd and shadowing attacks).
safe_install_local_bin_exists() {
  local name="$1" dir
  dir=$(builtin pwd -P 2>/dev/null) || return 1
  [[ -n "$dir" ]] || return 1
  while :; do
    if [[ -x "$dir/node_modules/.bin/$name" && -f "$dir/node_modules/.bin/$name" ]]; then
      return 0
    fi
    [[ "$dir" == "/" ]] && return 1
    dir="${dir%/*}"
    [[ -n "$dir" ]] || dir="/"
  done
}

# Locate the real subcommand token, skipping any leading GLOBAL flags a tool
# accepts before its command (`npm --loglevel=error install evil`,
# `yarn --cwd sub add evil`, `pnpm --filter x dlx cmd`). Without this the
# wrappers read the subcommand as $1 and a leading flag slips the whole gate.
#
# Sets SAFE_INSTALL_SUBCMD (token, "" if none) and SAFE_INSTALL_SUBCMD_IDX
# (1-based index in "$@", 0 if none). Returns 0 on success (subcommand found
# or genuinely absent), 2 fail-closed on an ambiguous unrecognized space-form
# flag (SAFE_INSTALL_SUBCMD_BADFLAG names it).
#
# Classification discipline (both directions can bypass, so correctness — not
# completeness — is load-bearing):
# - `=`-form flags (`--x=y`) are unambiguous → always skipped.
# - <val_alt>: flags KNOWN to take a space-form value → skip flag + its value.
#   A boolean wrongly listed here eats the real subcommand → bypass.
# - <bool_alt>: flags KNOWN to take NO value → skip flag only.
#   A value-taker wrongly listed here exposes its value as the subcommand →
#   bypass.
# - Any OTHER space-form dash flag is ambiguous → FAIL CLOSED (return 2),
#   escapable by rewriting as `--flag=value`. So gaps in either list merely
#   over-refuse; only MISCLASSIFICATION bypasses. Lists validated per tool
#   against its --help and are load-bearing.
safe_install_locate_subcommand() {
  local val_alt="$1" bool_alt="$2"; shift 2
  local arg i=0 skip=0 boolval=0
  SAFE_INSTALL_SUBCMD=""; SAFE_INSTALL_SUBCMD_IDX=0; SAFE_INSTALL_SUBCMD_BADFLAG=""
  for arg in "$@"; do
    i=$((i + 1))
    if (( skip )); then skip=0; continue; fi
    if (( boolval )); then
      boolval=0
      # A bare true/false immediately after a boolean flag is that flag's
      # explicit space-form value: npm/pnpm config booleans accept it
      # (`npm --global false install ...` means --global=false, subcommand
      # install). Consume it. This can never swallow a real subcommand — no
      # gated subcommand is named true/false — so it is safe on every tool;
      # any OTHER token here is the subcommand or next flag → fall through.
      case "${arg:l}" in
        true|false) continue ;;
      esac
    fi
    case "${arg}" in
      --)
        # Options terminated: the next token, if any, is the subcommand.
        if (( i < $# )); then
          SAFE_INSTALL_SUBCMD="${@[i+1]}"; SAFE_INSTALL_SUBCMD_IDX=$((i + 1))
        fi
        return 0 ;;
      --*=*|-*=*) continue ;;
      ${~val_alt}) skip=1; continue ;;
      ${~bool_alt}) boolval=1; continue ;;
      -?*) SAFE_INSTALL_SUBCMD_BADFLAG="${arg}"; return 2 ;;
      *) SAFE_INSTALL_SUBCMD="${arg}"; SAFE_INSTALL_SUBCMD_IDX=$i; return 0 ;;
    esac
  done
  return 0
}

# Per-tool leading-global-flag tables (val|bool), kept deliberately small: a
# gap only over-refuses (fail-closed, escapable via =form); a MISclassified
# flag bypasses. `go` accepts no pre-command flags → empty tables (any leading
# flag fails closed, matching go's own grammar).
safe_install_global_flags() {
  case "$1" in
    npm)
      SAFE_INSTALL_GVAL='--loglevel|--prefix|--cache|--registry|--userconfig|--globalconfig|--workspace|-w|--script-shell|--node-options|--omit|--include|--tag'
      SAFE_INSTALL_GBOOL='-q|--quiet|--silent|-d|-dd|-ddd|--verbose|--global|-g|--foreground-scripts|--no-fund|--no-audit|--offline|--prefer-offline|--prefer-online|--ignore-scripts|--workspaces|--include-workspace-root|--no-workspaces|--no-color|--json' ;;
    pnpm)
      # --config is a no-value switch on `pnpm add` (configurational deps),
      # NOT a value-taker — keep it out of GVAL or it eats the subcommand.
      SAFE_INSTALL_GVAL='--filter|-F|--dir|-C|--reporter|--workspace-concurrency'
      SAFE_INSTALL_GBOOL='-w|--workspace-root|-r|--recursive|--stream|--silent|--no-color|--global|-g|--aggregate-output|--config' ;;
    bun)
      # bun's --cwd/--config/-c are EQUALS-ONLY (`--config=<val>`); bun does
      # not consume a following space-form token, so they must not sit in the
      # space-form value table (that would eat the subcommand). The =form is
      # covered by the generic --*=* skip; bare space-form fails closed.
      SAFE_INSTALL_GVAL=''
      SAFE_INSTALL_GBOOL='--silent|--global|-g|--no-cache|--no-progress' ;;
    yarn)
      SAFE_INSTALL_GVAL='--cwd|--registry|--modules-folder|--cache-folder|--mutex|--network-timeout|--network-concurrency|--proxy|--https-proxy'
      SAFE_INSTALL_GBOOL='--verbose|--silent|-s|--offline|--prefer-offline|--no-progress|--json|--flat|--force|--ignore-scripts|--non-interactive|--no-lockfile|--frozen-lockfile' ;;
    pip|pip3)
      # --use-feature takes a value (e.g. fast-deps) — GVAL, not GBOOL.
      SAFE_INSTALL_GVAL='--log|--proxy|--retries|--timeout|--cache-dir|--python|--index-url|-i|--cert|--client-cert|--use-feature'
      SAFE_INSTALL_GBOOL='-q|--quiet|-v|-vv|-vvv|--verbose|--isolated|--no-input|--no-color|--require-virtualenv|--no-cache-dir|--disable-pip-version-check' ;;
    uv)
      SAFE_INSTALL_GVAL='--cache-dir|--config-file|--directory|--project|--color'
      SAFE_INSTALL_GBOOL='--offline|-q|--quiet|-v|--verbose|--native-tls|--no-cache|-n|--no-progress|--no-config' ;;
    cargo)
      SAFE_INSTALL_GVAL='--color|--config|-Z|-C'
      SAFE_INSTALL_GBOOL='-v|--verbose|-q|--quiet|--offline|--frozen|--locked' ;;
    composer)
      SAFE_INSTALL_GVAL='-d|--working-dir'
      SAFE_INSTALL_GBOOL='-v|-vv|-vvv|--verbose|-q|--quiet|-n|--no-interaction|--profile|--no-plugins|--no-scripts|--ansi|--no-ansi|-h|--help|-V|--version' ;;
    volta)
      SAFE_INSTALL_GVAL=''
      SAFE_INSTALL_GBOOL='-v|--verbose|-q|--quiet' ;;
    go|*)
      SAFE_INSTALL_GVAL=''
      SAFE_INSTALL_GBOOL='' ;;
  esac
}

# Resolve the subcommand for <tool> over "$@"; on ambiguity print the legible
# fail-closed refusal and return 100 so the caller can `|| return $?`.
safe_install_route() {
  local tool="$1"; shift
  safe_install_global_flags "${tool}"
  safe_install_locate_subcommand "${SAFE_INSTALL_GVAL}" "${SAFE_INSTALL_GBOOL}" "$@"
  case $? in
    2)
      print -u2 -- "safe: BLOCKED ${tool} — cannot find the subcommand past unrecognized flag '${SAFE_INSTALL_SUBCMD_BADFLAG}'; to allow: rewrite it as '${SAFE_INSTALL_SUBCMD_BADFLAG}=<value>', then retry; details: safe explain"
      return 100 ;;
  esac
  return 0
}

# Gate exec-style invocations that can fetch and run registry packages
# (npm exec/x, bun x, pnpm dlx, yarn dlx, uv tool run). Audits every package
# the invocation would fetch, then the caller delegates to the real tool.
#
# Args: <label> <ecosystem> <local_bin_ok> <post_positional> \
#       <from_alt> <extra_alt> <val_alt> <bool_alt> <refuse_alt> <args...>
#   Each *_alt is a glob-alternation of flags (e.g. '--package|-p'); '' = none.
# - <from_alt>  flags whose value SELECTS the package to run (npm/pnpm/yarn/bun
#   --package/-p, uv --from). Its value is audited AND it means the positional
#   is the command name provided by that package, so the positional is NOT
#   itself audited.
# - <extra_alt> flags whose value is an ADDITIONAL fetched package (uv
#   --with/-w). Audited on top of the from/positional package.
# - <val_alt>   known value-taking flags whose space-form value is skipped.
# - <bool_alt>  known switches (take no value).
# - <refuse_alt> flags we cannot vet inline (e.g. --with-requirements names a
#   file of packages); always FAIL CLOSED, space or =form.
# - <post_positional> 1 for tools that parse option flags even AFTER the
#   command (npm's greedy config parser: `npm exec cmd --package X` still
#   fetches X). When 1, from/extra/refuse flags keep being collected after the
#   first positional until `--`; other post-command tokens are the command's
#   own args and ignored. 0 for tools that stop options at the command.
# - Any OTHER bare (space-form) flag BEFORE the package is ambiguous — its
#   value cannot be told from the package — so we FAIL CLOSED with a legible
#   refusal (escapable with the flag's =form). Misclassifying a flag can
#   bypass, so the per-tool lists are load-bearing and validated against each
#   tool's --help; unknown flags fail closed rather than guess.
# - With local_bin_ok=1 a BARE positional (no from-flag given) resolving to
#   node_modules/.bin/<name> in the physical cwd or a parent (npm's own bin
#   resolution) is project-local (no fetch) and skipped.
safe_install_exec_gate() {
  local label="$1" ecosystem="$2" local_bin_ok="$3" post_positional="$4"
  local from_alt="$5" extra_alt="$6" val_alt="$7" bool_alt="$8" refuse_alt="$9"
  shift 9
  local -a from_specs extra_specs audit_specs normalized
  local arg flag spec positional="" refuse_msg=""
  local expect_from=0 expect_extra=0 skip_next=0 after_dd=0 seen_pos=0
  refuse_msg="safe: BLOCKED ${label} — cannot vet the packages named by a requirements file inline; to allow: ask the operator to review them (safe audit check <pkg> --ecosystem ${ecosystem}), then retry; details: safe explain"

  from_specs=(); extra_specs=()

  for arg in "$@"; do
    if (( expect_from )); then
      from_specs+=("${arg}"); expect_from=0; continue
    fi
    if (( expect_extra )); then
      extra_specs+=("${arg}"); expect_extra=0; continue
    fi
    if (( skip_next )); then
      skip_next=0; continue
    fi
    if (( after_dd )); then
      # Only a bare positional command (no from-flag yet) still matters here.
      (( seen_pos )) || positional="${arg}"
      break
    fi

    if [[ "${arg}" == "--" ]]; then
      after_dd=1; continue
    fi

    # Attached =form is unambiguous (value cannot be mistaken for the package).
    if [[ "${arg}" == --*=* ]]; then
      flag="${arg%%=*}"
      if [[ -n "${refuse_alt}" && "${flag}" == (${~refuse_alt}) ]]; then
        print -u2 -- "${refuse_msg}"; return 100
      elif [[ -n "${from_alt}" && "${flag}" == (${~from_alt}) ]]; then
        from_specs+=("${arg#*=}")
      elif [[ -n "${extra_alt}" && "${flag}" == (${~extra_alt}) ]]; then
        extra_specs+=("${arg#*=}")
      fi
      continue
    fi

    case "${arg}" in
      -*)
        if [[ -n "${refuse_alt}" && "${arg}" == (${~refuse_alt}) ]]; then
          print -u2 -- "${refuse_msg}"; return 100
        elif (( seen_pos )) && [[ "${arg}" != --* ]]; then
          # Phase 2 (post-command): only npm's greedy long-form config flags
          # (--package) are parsed after the command; short flags like -p are
          # NOT, so ignore them here rather than mistaking the value for the
          # package. Everything short post-command is a command arg.
          :
        elif [[ -n "${from_alt}" && "${arg}" == (${~from_alt}) ]]; then
          expect_from=1
        elif [[ -n "${extra_alt}" && "${arg}" == (${~extra_alt}) ]]; then
          expect_extra=1
        elif (( seen_pos )); then
          # Phase 2 unmatched long flag: the command's own option, ignored.
          :
        elif [[ -n "${val_alt}" && "${arg}" == (${~val_alt}) ]]; then
          skip_next=1
        elif [[ -n "${bool_alt}" && "${arg}" == (${~bool_alt}) ]]; then
          :
        else
          print -u2 -- "safe: BLOCKED ${label} — cannot identify the package to audit past unrecognized option '${arg}'; to allow: rewrite it as '${arg}=<value>' (or pass the package via an explicit spec), then retry; details: safe explain"
          return 100
        fi
        ;;
      *)
        if (( seen_pos == 0 )); then
          positional="${arg}"; seen_pos=1
          (( post_positional )) || break
        fi
        ;;
    esac
  done

  audit_specs=("${extra_specs[@]}")
  if (( ${#from_specs[@]} > 0 )); then
    audit_specs+=("${from_specs[@]}")
  elif [[ -n "${positional}" ]]; then
    if ! { (( local_bin_ok )) && safe_install_is_bare_name "${positional}" && \
           safe_install_local_bin_exists "${positional}"; }; then
      audit_specs+=("${positional}")
    fi
  fi

  (( ${#audit_specs[@]} > 0 )) || return 0

  normalized=()
  for spec in "${audit_specs[@]}"; do
    case "${ecosystem}" in
      python) normalized+=("$(safe_install_python_spec "${spec}")") ;;
      *) normalized+=("$(safe_install_npm_spec "${spec}")") ;;
    esac
  done

  safe_install_check_many "${ecosystem}" "${normalized[@]}"
}

safe_install_npm_like() {
  local tool="$1"
  shift
  safe_install_route "${tool}" "$@" || return $?
  local subcommand="${SAFE_INSTALL_SUBCMD}"
  local -a rest raw packages
  rest=("${@:$((SAFE_INSTALL_SUBCMD_IDX + 1))}")
  local parser="safe_install_${tool}_packages"
  local raw_package
  local project_present=1

  case "${tool}:${subcommand}" in
    npm:exec|npm:x)
      # npm's config parser is greedy: --package is honored even after the
      # command, so post_positional=1.
      safe_install_exec_gate "npm ${subcommand}" npm 1 1 \
        '--package|-p' '' \
        '-c|--call|-w|--workspace|--cache|--prefix|--registry|--userconfig|--globalconfig|--loglevel|--script-shell|--node-options|--omit|--include' \
        '-y|--yes|--no|--offline|--prefer-offline|--prefer-online|--ignore-existing|--foreground-scripts|--silent|--quiet|--workspaces|--include-workspace-root' \
        '' \
        "${rest[@]}" || return $?
      safe_install_real "${tool}" "$@"
      return $?
      ;;
    bun:x)
      safe_install_exec_gate "bun x" npm 1 0 \
        '--package|-p' '' '' \
        '--bun|--silent|--no-install|--verbose' \
        '' \
        "${rest[@]}" || return $?
      safe_install_real "${tool}" "$@"
      return $?
      ;;
    pnpm:dlx)
      safe_install_exec_gate "pnpm dlx" npm 0 0 \
        '--package' '' \
        '--allow-build|--reporter' \
        '-c|--shell-mode|--silent|-s' \
        '' \
        "${rest[@]}" || return $?
      safe_install_real "${tool}" "$@"
      return $?
      ;;
  esac

  case "${subcommand}" in
    install|i|it|install-test|add|ci|update|u|up|upgrade|udpate) ;;
    *) safe_install_real "${tool}" "$@"; return $? ;;
  esac

  if safe_install_has_arg "-g" "$@" || safe_install_has_arg "--global" "$@"; then
    raw=("${(@f)$(${parser} "${rest[@]}")}")
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

  raw=("${(@f)$(${parser} "${rest[@]}")}")
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
# It must stay inlined — a shared guard helper could be stripped too. Each
# guard scans EVERY token (not just $1) for its gated keywords so a leading
# global flag can't hide the subcommand in degraded mode either; this is
# conservative (may over-refuse a positional literally named like a
# subcommand) but never under-refuses. yarn (bare/flags-only installs) and go
# (run <mod>@<ver>) need slightly different inline shapes, noted at each.

npm() {
  if ! typeset -f safe_install_npm_like safe_install_check >/dev/null 2>&1; then
    # Degraded mode can't run the leading-flag resolver (helpers stripped), so
    # it scans EVERY token for a gated subcommand — a gated keyword is always
    # present regardless of leading flags, so a leading flag can no longer hide
    # it. Conservative: may over-refuse (e.g. a positional literally named
    # "install"); never under-refuses a real install/exec.
    local __a
    for __a in "$@"; do
      case "${__a}" in
        install|i|it|install-test|add|ci|exec|x|u|update|up|upgrade|udpate)
          print -u2 -- "safe: BLOCKED npm ${__a} — safe install wrappers are partially loaded (helpers stripped by shell snapshot); ask the operator to run this in a regular terminal; details: safe explain"
          return 100 ;;
      esac
    done
    command npm "$@"; return $?
  fi
  safe_install_npm_like npm "$@"
}

pnpm() {
  if ! typeset -f safe_install_npm_like safe_install_check >/dev/null 2>&1; then
    local __a
    for __a in "$@"; do
      case "${__a}" in
        install|i|add|ci|dlx|update|up|upgrade)
          print -u2 -- "safe: BLOCKED pnpm ${__a} — safe install wrappers are partially loaded (helpers stripped by shell snapshot); ask the operator to run this in a regular terminal; details: safe explain"
          return 100 ;;
      esac
    done
    command pnpm "$@"; return $?
  fi
  safe_install_npm_like pnpm "$@"
}

bun() {
  if ! typeset -f safe_install_npm_like safe_install_check >/dev/null 2>&1; then
    local __a
    for __a in "$@"; do
      case "${__a}" in
        install|i|add|ci|x|update)
          print -u2 -- "safe: BLOCKED bun ${__a} — safe install wrappers are partially loaded (helpers stripped by shell snapshot); ask the operator to run this in a regular terminal; details: safe explain"
          return 100 ;;
      esac
    done
    command bun "$@"; return $?
  fi
  safe_install_npm_like bun "$@"
}

yarn() {
  if ! typeset -f safe_install_yarn_packages safe_install_check >/dev/null 2>&1; then
    # yarn is the one tool where a bare or flags-only invocation installs, so a
    # positional-scan is not enough (`yarn --cwd sub` installs with no gated
    # keyword). Conservative rule: refuse when the first token is absent, a
    # leading flag (can't parse safely without helpers), or a gated keyword.
    case "${1:-}" in
      ""|-*|install|add|global|dlx|up|upgrade|upgrade-interactive)
        print -u2 -- "safe: BLOCKED yarn ${1:-install} — safe install wrappers are partially loaded (helpers stripped by shell snapshot); ask the operator to run this in a regular terminal; details: safe explain"
        return 100 ;;
      *) command yarn "$@"; return $? ;;
    esac
  fi
  safe_install_route yarn "$@" || return $?
  local first="${SAFE_INSTALL_SUBCMD}"
  local subidx=$SAFE_INSTALL_SUBCMD_IDX
  local second="${@[subidx+1]:-}"
  local -a raw packages
  local raw_package

  if [[ "${first}" == "dlx" ]]; then
    safe_install_exec_gate "yarn dlx" npm 0 0 \
      '--package|-p' '' '' '-q|--quiet' '' \
      "${@:$((subidx + 1))}" || return $?
    safe_install_real yarn "$@"
    return $?
  fi

  if [[ "${first}" == "global" && ( "${second}" == "add" || "${second}" == "upgrade" ) ]]; then
    raw=("${(@f)$(safe_install_yarn_packages "${@:$((subidx + 2))}")}")
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

  case "${first}" in
    ""|install|add|up|upgrade|upgrade-interactive)
      if safe_install_yarn_project_present; then
        safe_install_scan_project || return $?
      fi

      if [[ "${first}" == "add" || "${first}" == "up" || "${first}" == "upgrade" ]]; then
        raw=("${(@f)$(safe_install_yarn_packages "${@:$((subidx + 1))}")}")
        packages=()
        for raw_package in "${raw[@]}"; do
          [[ -n "${raw_package}" ]] && packages+=("$(safe_install_npm_spec "${raw_package}")")
        done

        if (( ${#packages[@]} > 0 )); then
          safe_install_check_many npm "${packages[@]}" || return $?
        fi
      fi
      ;;
  esac

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
  safe_install_route "${tool}" "$@" || return $?
  local subcommand="${SAFE_INSTALL_SUBCMD}"
  local subidx=$SAFE_INSTALL_SUBCMD_IDX
  local -a packages

  [[ "${subcommand}" == "install" || "${subcommand}" == "upgrade" ]] || { safe_install_real "${tool}" "$@"; return $?; }

  if safe_install_pip_project_install "${@:$((subidx + 1))}"; then
    safe_install_scan_project || return $?
    safe_install_real "${tool}" "$@"
    return $?
  fi

  packages=("${(@f)$(safe_install_python_packages "${@:$((subidx + 1))}")}")
  if (( $? != 0 || ${#packages[@]} == 0 )); then
    safe_install_real "${tool}" "$@"
    return $?
  fi

  safe_install_check_many python "${packages[@]}" || return $?
  safe_install_real "${tool}" "$@"
}

pip() {
  if ! typeset -f safe_install_pip_like safe_install_check >/dev/null 2>&1; then
    local __a
    for __a in "$@"; do
      case "${__a}" in
        install|upgrade)
          print -u2 -- "safe: BLOCKED pip ${__a} — safe install wrappers are partially loaded (helpers stripped by shell snapshot); ask the operator to run this in a regular terminal; details: safe explain"
          return 100 ;;
      esac
    done
    command pip "$@"; return $?
  fi
  safe_install_pip_like pip "$@"
}

pip3() {
  if ! typeset -f safe_install_pip_like safe_install_check >/dev/null 2>&1; then
    local __a
    for __a in "$@"; do
      case "${__a}" in
        install|upgrade)
          print -u2 -- "safe: BLOCKED pip3 ${__a} — safe install wrappers are partially loaded (helpers stripped by shell snapshot); ask the operator to run this in a regular terminal; details: safe explain"
          return 100 ;;
      esac
    done
    command pip3 "$@"; return $?
  fi
  safe_install_pip_like pip3 "$@"
}

uv() {
  if ! typeset -f safe_install_python_packages safe_install_check >/dev/null 2>&1; then
    # Scan every token for a gated subcommand so a leading global flag can't
    # hide it (`uv --offline tool run x`). `tool` covers tool run/install.
    local __a
    for __a in "$@"; do
      case "${__a}" in
        sync|add|tool|pip)
          print -u2 -- "safe: BLOCKED uv ${__a} — safe install wrappers are partially loaded (helpers stripped by shell snapshot); ask the operator to run this in a regular terminal; details: safe explain"
          return 100 ;;
      esac
    done
    # uv run --with/-w and --with-requirements pull registry packages. Degraded
    # mode can't parse the command boundary safely, so it is conservative: any
    # such token anywhere refuses (may over-refuse a program's own --with; it
    # never under-refuses a real fetch). `-w`, `-w=pkg`, `-wpkg` are short
    # --with forms uv accepts.
    if [[ " ${*} " == *" --with "* || " ${*} " == *" --with="* || " ${*} " == *" -w"* || \
          " ${*} " == *" --with-requirements "* || " ${*} " == *" --with-requirements="* ]]; then
      print -u2 -- "safe: BLOCKED uv run --with — safe install wrappers are partially loaded (helpers stripped by shell snapshot); ask the operator to run this in a regular terminal; details: safe explain"
      return 100
    fi
    command uv "$@"; return $?
  fi
  safe_install_route uv "$@" || return $?
  local first="${SAFE_INSTALL_SUBCMD}"
  local subidx=$SAFE_INSTALL_SUBCMD_IDX
  local second="${@[subidx+1]:-}"
  local -a packages

  if [[ "${first}" == "sync" ]]; then
    if safe_install_uv_project_present; then
      safe_install_scan_project || return $?
    fi

    safe_install_real uv "$@"
    return $?
  fi

  if [[ "${first}" == "run" ]]; then
    # `uv run [uv-options] <command> [command-args]` executes project code;
    # only --with/-w pulls extra registry packages. uv options appear only
    # BEFORE the command, so parsing must stop at the command token — else a
    # `--with` in the program's own args gets mis-audited. Unknown bare
    # options before the command are ambiguous → fail closed (safe: an
    # incomplete list over-refuses but never lets a --with slip past).
    local -a with_specs normalized_with
    local run_arg expect_with=0 skip_with_next=0
    # --with-requirements names a file of packages we cannot vet inline → refuse.
    local uv_val='--python|-p|--with-editable|--index|--index-url|--extra-index-url|--default-index|--constraint|-c|--index-strategy|--keyring-provider|--resolution|--prerelease|--exclude-newer|--config-setting|--refresh-package|--group|--only-group|--no-group|--extra|--no-extra|--project|--directory|--python-preference'
    local uv_bool='--frozen|--locked|--no-sync|--offline|--isolated|--no-project|--all-extras|--no-dev|--dev|--only-dev|--no-default-groups|--all-groups|--refresh|--reinstall|--upgrade|--all-packages|--no-editable|--exact|--inexact|--no-binary|--no-build|--compile-bytecode|--no-compile-bytecode|--native-tls|--no-cache|-n|-q|--quiet|-v|--verbose|--managed-python|--no-managed-python|--script|-s|-m|--module'
    with_specs=()
    for run_arg in "${@:$((subidx + 1))}"; do
      if (( expect_with )); then
        with_specs+=("${run_arg}")
        expect_with=0
        continue
      fi
      if (( skip_with_next )); then
        skip_with_next=0
        continue
      fi
      if [[ "${run_arg}" == "--" ]]; then
        break
      fi
      if [[ "${run_arg}" == "--with-requirements" || "${run_arg}" == --with-requirements=* ]]; then
        print -u2 -- "safe: BLOCKED uv run — cannot vet the packages named by --with-requirements inline; to allow: ask the operator to review them (safe audit check <pkg> --ecosystem python), then retry; details: safe explain"
        return 100
      fi
      if [[ "${run_arg}" == --*=* ]]; then
        [[ "${run_arg}" == (--with=*) ]] && with_specs+=("${run_arg#--with=}")
        continue
      fi
      case "${run_arg}" in
        --with|-w) expect_with=1 ;;
        ${~uv_val}) skip_with_next=1 ;;
        ${~uv_bool}) ;;
        -*)
          print -u2 -- "safe: BLOCKED uv run — cannot identify --with packages past unrecognized option '${run_arg}'; to allow: rewrite it as '${run_arg}=<value>', then retry; details: safe explain"
          return 100
          ;;
        *) break ;;
      esac
    done
    if (( ${#with_specs[@]} > 0 )); then
      normalized_with=()
      for run_arg in "${with_specs[@]}"; do
        normalized_with+=("$(safe_install_python_spec "${run_arg}")")
      done
      safe_install_check_many python "${normalized_with[@]}" || return $?
    fi
    safe_install_real uv "$@"
    return $?
  fi

  if [[ "${first}" == "tool" && "${second}" == "run" ]]; then
    safe_install_exec_gate "uv tool run" python 0 0 \
      '--from' '--with|-w' \
      '--python|-p|--with-editable|--index|--index-url|--extra-index-url|--default-index|--constraint|-c|--index-strategy|--keyring-provider|--resolution|--prerelease|--exclude-newer|--config-setting|--refresh-package' \
      '--offline|--isolated|--system|--no-project|--refresh|--reinstall|--upgrade|-q|--quiet|-v|--verbose|--native-tls|--no-cache|-n' \
      '--with-requirements' \
      "${@:$((subidx + 2))}" || return $?
    safe_install_real uv "$@"
    return $?
  fi

  if [[ "${first}" == "tool" && "${second}" == "install" ]]; then
    packages=("${(@f)$(safe_install_python_packages "${@:$((subidx + 2))}")}")
    if (( $? != 0 || ${#packages[@]} == 0 )); then
      safe_install_real uv "$@"
      return $?
    fi

    safe_install_check_many python "${packages[@]}" || return $?
    safe_install_real uv "$@"
    return $?
  fi

  if [[ "${first}" == "pip" && "${second}" == "install" ]]; then
    if safe_install_pip_project_install "${@:$((subidx + 2))}"; then
      safe_install_scan_project || return $?
      safe_install_real uv "$@"
      return $?
    fi

    packages=("${(@f)$(safe_install_python_packages "${@:$((subidx + 2))}")}")
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
    local __a
    for __a in "$@"; do
      case "${__a}" in
        install)
          print -u2 -- "safe: BLOCKED cargo ${__a} — safe install wrappers are partially loaded (helpers stripped by shell snapshot); ask the operator to run this in a regular terminal; details: safe explain"
          return 100 ;;
      esac
    done
    command cargo "$@"; return $?
  fi
  safe_install_route cargo "$@" || return $?
  local subcommand="${SAFE_INSTALL_SUBCMD}"
  local subidx=$SAFE_INSTALL_SUBCMD_IDX
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

  packages=("${(@f)$(safe_install_cargo_packages "${@:$((subidx + 1))}")}")
  if (( ${#packages[@]} > 0 )); then
    safe_install_check_many cargo "${packages[@]}" || return $?
  fi

  safe_install_real cargo "$@"
}

go() {
  if ! typeset -f safe_install_go_packages safe_install_check >/dev/null 2>&1; then
    # Scan every token: `go install` (any position) and `go run <mod>@<ver>`
    # fetch. `go get` stays out of scope (its fetch runs no code), so the '@'
    # check is scoped to a `run` present — not any '@' anywhere.
    local __a __has_run=0 __has_at=0
    for __a in "$@"; do
      case "${__a}" in
        install)
          print -u2 -- "safe: BLOCKED go install — safe install wrappers are partially loaded (helpers stripped by shell snapshot); ask the operator to run this in a regular terminal; details: safe explain"
          return 100 ;;
        run) __has_run=1 ;;
        *@*) __has_at=1 ;;
      esac
    done
    if (( __has_run && __has_at )); then
      print -u2 -- "safe: BLOCKED go run — safe install wrappers are partially loaded (helpers stripped by shell snapshot); ask the operator to run this in a regular terminal; details: safe explain"
      return 100
    fi
    command go "$@"; return $?
  fi
  safe_install_route go "$@" || return $?
  local subcommand="${SAFE_INSTALL_SUBCMD}"
  local subidx=$SAFE_INSTALL_SUBCMD_IDX
  local second="${@[subidx+1]:-}"
  local -a packages

  if [[ "${subcommand}" == "run" ]]; then
    # `go run <module>@<version>` fetches and executes a remote module; local
    # package paths pass through unaudited. Build flags precede the target and
    # some take a space-form value — a value flag NOT skipped would let its
    # value become the "target" and hide a later module@version. So we
    # classify go build flags (value vs boolean) and FAIL CLOSED on an
    # unrecognized dash flag before the target rather than assume no value.
    # Lists validated against `go help build`; =form values are unambiguous.
    local run_arg run_target="" run_skip_next=0
    local go_val='-C|-p|-asmflags|-buildmode|-compiler|-covermode|-coverpkg|-gccgoflags|-gcflags|-installsuffix|-ldflags|-mod|-modfile|-overlay|-pgo|-pkgdir|-tags|-toolexec|-exec'
    local go_bool='-a|-n|-race|-msan|-asan|-cover|-v|-work|-x|-i|-linkshared|-modcacherw|-trimpath|-buildvcs|-json'
    for run_arg in "${@:$((subidx + 1))}"; do
      if (( run_skip_next )); then
        run_skip_next=0
        continue
      fi
      if [[ "${run_arg}" == "--" ]]; then
        continue
      fi
      if [[ "${run_arg}" == -*=* ]]; then
        # Attached =value is unambiguous.
        continue
      fi
      case "${run_arg}" in
        ${~go_val}) run_skip_next=1 ;;
        ${~go_bool}) ;;
        -*)
          print -u2 -- "safe: BLOCKED go run — cannot identify the run target past unrecognized flag '${run_arg}'; to allow: rewrite it as '${run_arg}=<value>', then retry; details: safe explain"
          return 100
          ;;
        *) run_target="${run_arg}"; break ;;
      esac
    done
    if [[ -n "${run_target}" && "${run_target}" == *@* && "${run_target}" != .* && "${run_target}" != /* ]]; then
      safe_install_check_many go "$(safe_install_go_spec "${run_target}")" || return $?
    fi
    safe_install_real go "$@"
    return $?
  fi

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

  packages=("${(@f)$(safe_install_go_packages "${@:$((subidx + 1))}")}") || {
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
    local __a
    for __a in "$@"; do
      case "${__a}" in
        install|update|require|global)
          print -u2 -- "safe: BLOCKED composer ${__a} — safe install wrappers are partially loaded (helpers stripped by shell snapshot); ask the operator to run this in a regular terminal; details: safe explain"
          return 100 ;;
      esac
    done
    command composer "$@"; return $?
  fi
  safe_install_route composer "$@" || return $?
  local first="${SAFE_INSTALL_SUBCMD}"
  local subidx=$SAFE_INSTALL_SUBCMD_IDX
  local second="${@[subidx+1]:-}"
  local -a packages

  if [[ "${first}" != "global" || "${second}" != "require" ]]; then
    if [[ "${first}" == "install" || "${first}" == "update" || "${first}" == "require" ]]; then
      if safe_install_composer_project_present; then
        safe_install_scan_project || return $?
      fi

      if [[ "${first}" == "require" ]]; then
        packages=("${(@f)$(safe_install_composer_packages "${@:$((subidx + 1))}")}")
        if (( ${#packages[@]} > 0 )); then
          safe_install_check_many composer "${packages[@]}" || return $?
        fi
      fi
    fi

    safe_install_real composer "$@"
    return $?
  fi

  packages=("${(@f)$(safe_install_composer_packages "${@:$((subidx + 2))}")}")
  if (( ${#packages[@]} > 0 )); then
    safe_install_check_many composer "${packages[@]}" || return $?
  fi

  safe_install_real composer "$@"
}

volta() {
  if ! typeset -f safe_install_volta_packages safe_install_check >/dev/null 2>&1; then
    local __a
    for __a in "$@"; do
      case "${__a}" in
        install)
          print -u2 -- "safe: BLOCKED volta ${__a} — safe install wrappers are partially loaded (helpers stripped by shell snapshot); ask the operator to run this in a regular terminal; details: safe explain"
          return 100 ;;
      esac
    done
    command volta "$@"; return $?
  fi
  safe_install_route volta "$@" || return $?
  local subcommand="${SAFE_INSTALL_SUBCMD}"
  local subidx=$SAFE_INSTALL_SUBCMD_IDX
  local -a packages
  local -a raw
  local raw_package

  if [[ "${subcommand}" != "install" ]]; then
    safe_install_real volta "$@"
    return $?
  fi

  raw=("${(@f)$(safe_install_volta_packages "${@:$((subidx + 1))}")}")
  packages=()
  for raw_package in "${raw[@]}"; do
    [[ -n "${raw_package}" ]] && packages+=("$(safe_install_npm_spec "${raw_package}")")
  done

  if (( ${#packages[@]} > 0 )); then
    safe_install_check_many npm "${packages[@]}" || return $?
  fi

  safe_install_real volta "$@"
}
