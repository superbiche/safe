# safe gate library (bash)
#
# Routing and audit logic for `safe gate <tool> -- <args...>`, the centralized
# entrypoint the generated PATH wrappers exec into. This is a faithful port of
# the retired zsh install wrappers (lib/install-wrappers.zsh through PR #28):
# the routing tables, flag classifications, and fail-closed refusals below were
# hardened over six adversarial review rounds and are load-bearing security
# logic — change them only with the same scrutiny.
#
# What did NOT come across from the zsh original, deliberately:
# - the inlined degraded-mode guards (they defended against a zsh shell
#   snapshot stripping helper FUNCTIONS; an executable wrapper either runs or
#   does not exist, so the failure mode is gone);
# - `volta()` (retired from the safe integration).
#
# Sourced by bin/safe. It defines functions only — sourcing must never exit or
# mutate the caller's shell state. Entry point: safe_gate_main <tool> <args...>.

SAFE_GATE_TIMEOUT_SECONDS="${SAFE_INSTALL_TIMEOUT_SECONDS:-30}"
SAFE_GATE_WARNED_MISSING=0
SAFE_GATE_SUBCMD=""
SAFE_GATE_SUBCMD_IDX=0
SAFE_GATE_SUBCMD_BADFLAG=""
SAFE_GATE_GVAL=""
SAFE_GATE_GBOOL=""

safe_gate_err() {
  printf '%s\n' "$*" >&2
}

# Exact membership in a '|'-separated flag table. The zsh original used glob
# alternation (`[[ $arg == (${~alt}) ]]`); every table entry is a literal flag,
# so exact per-entry comparison is the same test. Substring matching would not
# be: it can classify a crafted argument as a known flag instead of failing
# closed.
safe_gate_alt_match() {
  local needle="$1" alt="$2"
  [[ -n "$alt" ]] || return 1
  local -a parts=()
  local part
  IFS='|' read -r -a parts <<< "$alt"
  for part in "${parts[@]}"; do
    [[ "$needle" == "$part" ]] && return 0
  done
  return 1
}

safe_gate_has_arg() {
  local needle="$1"
  shift
  local arg

  for arg in "$@"; do
    [[ "$arg" == "$needle" ]] && return 0
  done

  return 1
}

safe_gate_has_prefix_arg() {
  local prefix="$1"
  shift
  local arg

  for arg in "$@"; do
    [[ "$arg" == "${prefix}"* ]] && return 0
  done

  return 1
}

safe_gate_warn_missing() {
  # Per-process: unlike the zsh wrappers (one long-lived shell), each gated
  # command is its own process, so this warns once per invocation.
  if (( SAFE_GATE_WARNED_MISSING == 0 )); then
    safe_gate_err "safe audit not installed, skipping pre-install check"
    SAFE_GATE_WARNED_MISSING=1
  fi
}

# ---------------------------------------------------------------------------
# Real-tool resolution
# ---------------------------------------------------------------------------

# A generated wrapper carries `# safe-gate-wrapper` in its first two lines.
safe_gate_is_wrapper() {
  local path="$1" line i=0
  while (( i < 2 )) && IFS= read -r line; do
    i=$((i + 1))
    case "$line" in
      *'# safe-gate-wrapper'*) return 0 ;;
    esac
  done < "$path" 2>/dev/null
  return 1
}

# First executable <tool> on PATH that is not one of our wrappers. For node
# tools that is normally the version-manager shim (mise), which is what we
# want: per-project tool versions keep resolving.
safe_gate_resolve_real() {
  local tool="$1" dir candidate
  local -a dirs=()

  IFS=':' read -r -a dirs <<< "${PATH}"
  for dir in "${dirs[@]}"; do
    [[ -n "$dir" ]] || dir="."
    candidate="${dir}/${tool}"
    [[ -f "$candidate" && -x "$candidate" ]] || continue
    safe_gate_is_wrapper "$candidate" && continue
    printf '%s\n' "$candidate"
    return 0
  done

  return 1
}

# Delegate to the real tool. Never returns.
safe_gate_exec_real() {
  local tool="$1"
  shift
  local real

  real="$(safe_gate_resolve_real "$tool")"
  if [[ -z "$real" ]]; then
    # 127 is the agent contract's "genuinely missing command" (safe explain);
    # a policy refusal is never 127.
    safe_gate_err "safe: gate: ${tool}: command not found (no non-wrapper ${tool} on PATH)"
    exit 127
  fi

  exec "$real" "$@"
}

# ---------------------------------------------------------------------------
# Audit invocation
# ---------------------------------------------------------------------------

safe_gate_resolve_audit_bin() {
  if [[ -n "${SAFE_AUDIT_BIN:-}" && -x "${SAFE_AUDIT_BIN}" ]]; then
    printf '%s\n' "${SAFE_AUDIT_BIN}"
    return 0
  fi
  if [[ -n "${SAFE_AUDIT_PATH:-}" && -x "${SAFE_AUDIT_PATH}" ]]; then
    printf '%s\n' "${SAFE_AUDIT_PATH}"
    return 0
  fi
  local found
  found="$(command -v safe-audit 2>/dev/null || true)"
  [[ -n "$found" ]] || return 1
  printf '%s\n' "$found"
}

safe_gate_audit_available() {
  if [[ -z "${SAFE_GATE_AUDIT_BIN+x}" ]]; then
    SAFE_GATE_AUDIT_BIN="$(safe_gate_resolve_audit_bin)"
  fi
  [[ -n "${SAFE_GATE_AUDIT_BIN}" ]]
}

safe_gate_run_audit() {
  local rc=0
  local -a extra=()
  [[ -n "${SAFE_GATE_DIST_TAG:-}" ]] && extra+=(--dist-tag "${SAFE_GATE_DIST_TAG}")
  [[ -n "${SAFE_GATE_REGISTRY:-}" ]] && extra+=(--registry "${SAFE_GATE_REGISTRY}")
  [[ -n "${SAFE_GATE_PROJECT_DIR:-}" ]] && extra+=(--project-dir "${SAFE_GATE_PROJECT_DIR}")
  if command -v timeout >/dev/null 2>&1; then
    timeout "${SAFE_GATE_TIMEOUT_SECONDS}" "${SAFE_GATE_AUDIT_BIN}" check "$@" "${extra[@]}"
    rc=$?
  else
    "${SAFE_GATE_AUDIT_BIN}" check "$@" "${extra[@]}"
    rc=$?
  fi
  return "$rc"
}

# Target-altering selectors change what the package manager actually installs
# (tag, source registry/index, project dir). They were previously stripped
# from the audit while staying in the real command — the audit then judged
# the wrong target (PR#29 review finding 3). Scanned from the original argv;
# safe-audit resolves with them or fails closed.
# Source selectors are cumulative (pip considers --find-links AND the index):
# accumulate every one — a later trusted selector must never erase an earlier
# untrusted one (PR#29 delta-2 finding 3).
safe_gate_add_source() {
  local value="$1"
  while [[ "${value}" == */ ]]; do value="${value%/}"; done
  [[ -n "${value}" ]] || return 0
  # A repeat moves to the END rather than being dropped: npm is last-wins, so
  # `--registry A --registry B --registry A` installs from A, and the
  # resolver's last-word read must see A last (delta-4 finding 3.1).
  local out="" w
  for w in ${SAFE_GATE_REGISTRY}; do
    [[ "$w" == "$value" ]] || out="${out:+$out }$w"
  done
  SAFE_GATE_REGISTRY="${out:+$out }$value"
}

safe_gate_scan_target_flags() {
  local family="$1"
  shift
  SAFE_GATE_DIST_TAG=""
  SAFE_GATE_REGISTRY=""
  SAFE_GATE_PROJECT_DIR=""
  local prev="" arg
  for arg in "$@"; do
    case "${family}" in
      npm)
        case "${prev}" in
          --tag) SAFE_GATE_DIST_TAG="${arg}" ;;
          --registry) safe_gate_add_source "${arg}" ;;
          --prefix|-C|--cwd|--dir) SAFE_GATE_PROJECT_DIR="${arg}" ;;
        esac
        case "${arg}" in
          --tag=*) SAFE_GATE_DIST_TAG="${arg#*=}" ;;
          --registry=*) safe_gate_add_source "${arg#*=}" ;;
          --prefix=*|--cwd=*|--dir=*) SAFE_GATE_PROJECT_DIR="${arg#*=}" ;;
        esac
        ;;
      python)
        case "${prev}" in
          --index-url|-i|--extra-index-url|--default-index|--index) safe_gate_add_source "${arg}" ;;
          --find-links|-f) safe_gate_add_source "local:find-links" ;;
        esac
        case "${arg}" in
          --index-url=*|--extra-index-url=*|--default-index=*|--index=*) safe_gate_add_source "${arg#*=}" ;;
          --find-links=*) safe_gate_add_source "local:find-links" ;;
          --no-index) safe_gate_add_source "local:no-index" ;;
        esac
        ;;
      cargo)
        case "${prev}" in
          --registry|--index) safe_gate_add_source "${arg}" ;;
        esac
        case "${arg}" in
          --registry=*|--index=*) safe_gate_add_source "${arg#*=}" ;;
        esac
        ;;
      composer)
        case "${prev}" in
          --repository) safe_gate_add_source "${arg}" ;;
          --working-dir|-d) SAFE_GATE_PROJECT_DIR="${arg}" ;;
        esac
        case "${arg}" in
          --repository=*) safe_gate_add_source "${arg#*=}" ;;
          --working-dir=*) SAFE_GATE_PROJECT_DIR="${arg#*=}" ;;
        esac
        ;;
    esac
    prev="${arg}"
  done
}

# Update-family subcommands resolve in-range instead of to the dist-tag; the
# audit needs to know which semantics apply to resolve the real target.
safe_gate_audit_op() {
  case "${SAFE_GATE_SUBCMD:-}" in
    update|u|up|upgrade|udpate) printf '%s' "update" ;;
    *) printf '%s' "install" ;;
  esac
}

# Persistent record of install-gate decisions, mirroring safe-run's audit_log
# field format (ts | runner | pkg | tier | context | decision | extra).
safe_gate_audit_log() {
  local ecosystem="$1" package="$2" decision="$3" extra="${4:-}"
  local data_dir="${SAFE_RUN_DATA_DIR:-${SAFE_DATA_DIR:-$HOME/.local/share/safe}/run}"
  local context="non-tty"
  [[ -t 0 && -t 1 ]] && context="interactive"
  mkdir -p "${data_dir}" 2>/dev/null || return 0
  local line
  line="$(date -Iseconds) | install:${ecosystem} | ${package} | GATE | ${context} | ${decision}${extra:+ | ${extra}}"
  printf '%s\n' "${line//[$'\r\n']/ }" >> "${data_dir}/audit.log" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Offline / allow fallbacks
# ---------------------------------------------------------------------------

safe_gate_run_config_dir() {
  printf '%s' "${SAFE_RUN_CONFIG_DIR:-${SAFE_CONFIG_DIR:-$HOME/.config/safe}/run}"
}

safe_gate_split_spec() {
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

# Offline fallback: when the audit itself timed out, an exact-version request
# matching a fresh install-known entry (a previously recorded clean check) may
# proceed on that stale evidence. Unpinned requests never qualify.
safe_gate_known_matches() {
  local package="$1"
  local ecosystem="$2"
  local known_file name version entry ttl_days entry_epoch now_epoch

  # install-known entries are keyed by the canonical resolver ecosystem
  # (safe-audit normalizes at check entry); the gate speaks tool labels.
  case "${ecosystem}" in
    cargo) ecosystem="rust" ;;
    composer) ecosystem="php" ;;
    pip|uv) ecosystem="python" ;;
  esac

  command -v jq >/dev/null 2>&1 || return 1
  known_file="$(safe_gate_run_config_dir)/install-known.json"
  [[ -r "${known_file}" ]] || return 1

  IFS=$'\t' read -r name version <<< "$(safe_gate_split_spec "${package}")"
  [[ -n "${name}" && -n "${version}" && "${version}" != "latest" ]] || return 1

  # Only fully clean GO evidence may satisfy the offline fallback — a
  # tolerated-WARN record is not clean evidence (PR#29 review finding 5).
  # The source identity (implicit-default vs explicit:<set>, delta-3
  # finding 5) must be byte-identical to what safe-audit's receipt writer
  # recorded; the derivation (argv + env + rc precedence, per ecosystem) is
  # centralized in safe-audit — ask it instead of mirroring (delta-4
  # findings 3.2 and N1). Local-only plumbing, no network. No identity ->
  # fail closed: stale evidence never applies without a trustworthy match.
  #
  # A disabled reuse path must not be invisible: silently never reusing
  # evidence looks like flaky refusals, so the failure says so once, on
  # stderr, without changing the fail-closed outcome (same principle as the
  # Socket-outage ruling).
  if ! safe_gate_audit_available; then
    safe_gate_err "safe gate: effective-sources unavailable — stale-evidence reuse disabled, run safe doctor"
    return 1
  fi
  local -a es_args=("${name}" --ecosystem "${ecosystem}")
  [[ -n "${SAFE_GATE_REGISTRY:-}" ]] && es_args+=(--registry "${SAFE_GATE_REGISTRY}")
  [[ -n "${SAFE_GATE_PROJECT_DIR:-}" ]] && es_args+=(--project-dir "${SAFE_GATE_PROJECT_DIR}")
  local current_source
  if ! current_source="$("${SAFE_GATE_AUDIT_BIN}" effective-sources "${es_args[@]}" 2>/dev/null)" \
     || [[ -z "${current_source}" ]]; then
    safe_gate_err "safe gate: effective-sources unavailable — stale-evidence reuse disabled, run safe doctor"
    return 1
  fi
  entry="$(jq -r --arg k "${ecosystem}:${name}" --arg v "${version}" --arg src "${current_source}" \
    '.packages[$k] | select(.version == $v and .verdict == "GO" and ((.source // "implicit-default") == $src)) | .first_allowed // empty' "${known_file}" 2>/dev/null || true)"
  [[ -n "${entry}" ]] || return 1

  ttl_days="$(jq -r '.install.auto_allow_ttl_days // 30' \
    "$(safe_gate_run_config_dir)/config.json" 2>/dev/null || printf '30')"
  [[ "${ttl_days}" =~ ^[0-9]+$ ]] || ttl_days=30
  entry_epoch="$(date -d "${entry}" +%s 2>/dev/null || true)"
  [[ -n "${entry_epoch}" ]] || return 1
  now_epoch="$(date +%s)"
  (( now_epoch - entry_epoch <= ttl_days * 86400 ))
}

safe_gate_host_allow_matches() {
  local package="$1"
  local ecosystem="$2"
  local host_allow_file name version entry_version entry_ecosystem

  [[ "${ecosystem}" == "npm" ]] || return 1
  command -v jq >/dev/null 2>&1 || return 1

  host_allow_file="$(safe_gate_run_config_dir)/host-allow.json"
  [[ -r "${host_allow_file}" ]] || return 1

  IFS=$'\t' read -r name version <<< "$(safe_gate_split_spec "${package}")"
  [[ -n "${name}" && -n "${version}" && "${version}" != "latest" ]] || return 1

  entry_version="$(jq -r --arg p "${name}" '.packages[$p].version // empty' "${host_allow_file}" 2>/dev/null || true)"
  entry_ecosystem="$(jq -r --arg p "${name}" '.packages[$p].ecosystem // "npm"' "${host_allow_file}" 2>/dev/null || true)"

  [[ "${entry_version}" == "${version}" && "${entry_ecosystem}" == "npm" ]]
}

# ---------------------------------------------------------------------------
# Project scan preflight
# ---------------------------------------------------------------------------

safe_gate_confirm_critical() {
  if [[ -t 0 && -t 1 ]]; then
    local reply
    printf 'Proceed anyway? [y/N] '
    read -r reply
    [[ "${reply}" == "y" || "${reply}" == "Y" || "${reply}" == "yes" || "${reply}" == "YES" ]]
    return $?
  fi

  safe_gate_err "safe: BLOCKED install — safe audit scan found critical findings and this shell is non-interactive; to allow: ask the operator to re-run interactively and review; details: safe explain"
  return 102
}

safe_gate_scan_project() {
  local scan_output
  local scan_status

  if ! safe_gate_audit_available; then
    safe_gate_warn_missing
    return 0
  fi

  scan_output="$("${SAFE_GATE_AUDIT_BIN}" scan --project . 2>&1)"
  scan_status=$?

  [[ -n "${scan_output}" ]] && printf '%s\n' "${scan_output}"

  if (( scan_status == 0 )); then
    return 0
  fi

  if [[ "${scan_output,,}" == *critical* || "${scan_status}" -ge 2 ]]; then
    # Preamble only ahead of the interactive prompt; the non-TTY path emits a
    # single self-contained BLOCKED line instead.
    if [[ -t 0 && -t 1 ]]; then
      safe_gate_err "safe install: safe audit scan reported critical findings"
    fi
    safe_gate_confirm_critical
    return $?
  fi

  safe_gate_err "safe install: safe audit scan failed with exit ${scan_status}; proceeding"
  return 0
}

safe_gate_any_file() {
  local file

  for file in "$@"; do
    [[ -e "${file}" ]] && return 0
  done

  return 1
}

safe_gate_npm_project_present() {
  safe_gate_any_file package-lock.json npm-shrinkwrap.json package.json
}

safe_gate_pnpm_project_present() {
  safe_gate_any_file pnpm-lock.yaml package.json
}

safe_gate_yarn_project_present() {
  safe_gate_any_file yarn.lock package.json
}

safe_gate_bun_project_present() {
  safe_gate_any_file bun.lock bun.lockb package.json
}

safe_gate_uv_project_present() {
  safe_gate_any_file uv.lock pyproject.toml
}

safe_gate_composer_project_present() {
  safe_gate_any_file composer.lock composer.json
}

safe_gate_cargo_project_present() {
  safe_gate_any_file Cargo.lock Cargo.toml
}

safe_gate_go_project_present() {
  safe_gate_any_file go.sum go.mod
}

safe_gate_pip_project_install() {
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

# ---------------------------------------------------------------------------
# Gate decision
# ---------------------------------------------------------------------------

# One-line operator hint for a refused package. host-allow only unlocks npm
# installs, so other ecosystems point at the audit detail command instead.
# Fallback hint when the audit could not supply a pinned suggestion (the gate
# prints resolved-version hints itself). Must never render an @latest shape:
# allow entries are always pinned to an exact resolved version.
safe_gate_allow_hint() {
  local package="$1"
  local ecosystem="$2"
  local name version

  IFS=$'\t' read -r name version <<< "$(safe_gate_split_spec "${package}")"
  if [[ "${ecosystem}" == "npm" ]]; then
    if [[ -n "${version}" && "${version}" != "latest" ]]; then
      printf 'to allow: ask the operator to run: safe run host-allow add %s --reason "..." — then retry' "${package}"
    else
      printf 'to allow: pin an exact version first (see the resolved-version hint above) — allow entries are never @latest'
    fi
  else
    printf 'to allow: operator review — safe audit check %s --ecosystem %s' "${package}" "${ecosystem}"
  fi
}

# Check one package via safe audit's install gate.
# Returns: 0=GO/proceed, 100=policy refusal, 104=audit BLOCK verdict.
safe_gate_check() {
  local package="$1"
  local ecosystem="$2"
  local audit_status

  if ! safe_gate_audit_available; then
    safe_gate_warn_missing
    return 0
  fi

  safe_gate_run_audit "${package}" --ecosystem "${ecosystem}" \
    --gate install --op "$(safe_gate_audit_op)"
  audit_status=$?

  case "${audit_status}" in
    0)
      safe_gate_audit_log "${ecosystem}" "${package}" "PROCEED"
      return 0
      ;;
    1|10)
      if safe_gate_host_allow_matches "${package}" "${ecosystem}"; then
        safe_gate_err "safe install: safe audit warned for ${package}; exact host-allow entry permits install"
        safe_gate_audit_log "${ecosystem}" "${package}" "HOST_ALLOW_OVERRIDE"
        return 0
      fi
      safe_gate_err "safe: BLOCKED ${ecosystem} install of ${package} — safe audit verdict WARN; $(safe_gate_allow_hint "${package}" "${ecosystem}"); details: safe explain"
      safe_gate_audit_log "${ecosystem}" "${package}" "REFUSED_WARN"
      return 100
      ;;
    2|20)
      safe_gate_err "safe: BLOCKED ${ecosystem} install of ${package} — safe audit verdict BLOCK; $(safe_gate_allow_hint "${package}" "${ecosystem}"); details: safe explain"
      safe_gate_audit_log "${ecosystem}" "${package}" "REFUSED_BLOCK"
      return 104
      ;;
    124|137)
      if safe_gate_known_matches "${package}" "${ecosystem}"; then
        safe_gate_err "safe install: safe audit timed out; proceeding on recorded clean check for ${package} (stale evidence)"
        safe_gate_audit_log "${ecosystem}" "${package}" "STALE_EVIDENCE"
        return 0
      fi
      safe_gate_err "safe: BLOCKED ${ecosystem} install of ${package} — safe audit timed out (fail closed); retry or ask the operator; details: safe explain"
      safe_gate_audit_log "${ecosystem}" "${package}" "TIMEOUT_FAILCLOSED"
      return 100
      ;;
    *)
      safe_gate_err "safe: BLOCKED ${ecosystem} install of ${package} — safe audit failed with exit ${audit_status} (fail closed); ask the operator; details: safe explain"
      safe_gate_audit_log "${ecosystem}" "${package}" "REFUSED_AUDIT_ERROR" "exit=${audit_status}"
      return 100
      ;;
  esac
}

safe_gate_check_many() {
  local ecosystem="$1"
  shift
  local package

  for package in "$@"; do
    safe_gate_check "${package}" "${ecosystem}" || return $?
  done

  return 0
}

# ---------------------------------------------------------------------------
# Per-ecosystem package extractors
# ---------------------------------------------------------------------------

safe_gate_print_list() {
  (( $# > 0 )) || return 0
  printf '%s\n' "$@"
}

safe_gate_npm_like_packages() {
  local -a packages=()
  local arg
  local skip_next=0
  local after_double_dash=0

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

  safe_gate_print_list "${packages[@]}"
}

safe_gate_npm_packages() {
  safe_gate_npm_like_packages "$@"
}

safe_gate_pnpm_packages() {
  safe_gate_npm_like_packages "$@"
}

safe_gate_bun_packages() {
  safe_gate_npm_like_packages "$@"
}

safe_gate_yarn_packages() {
  safe_gate_npm_like_packages "$@"
}

safe_gate_cargo_packages() {
  local -a packages=()
  local arg
  local skip_next=0
  local capture_version=0
  local crate_version=""

  for arg in "$@"; do
    if (( capture_version )); then
      crate_version="${arg}"
      capture_version=0
      continue
    fi
    if (( skip_next )); then
      skip_next=0
      continue
    fi

    case "${arg}" in
      --version|--vers)
        # `cargo install <crate> --version <v>` pins the crate; dropping the
        # value would audit the bare name (PR#29 review finding 7).
        capture_version=1
        continue
        ;;
      --version=*|--vers=*)
        crate_version="${arg#*=}"
        continue
        ;;
      --index|--registry|--root|--target|--features|--bin|--example)
        skip_next=1
        continue
        ;;
      --index=*|--registry=*|--root=*|--target=*|--features=*|--bin=*|--example=*)
        continue
        ;;
      --locked|--offline|--quiet|--debug|--force|-f|--list|--no-track|--all-features|--no-default-features)
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

  if [[ -n "${crate_version}" && ${#packages[@]} -gt 0 ]]; then
    local -a versioned=()
    for arg in "${packages[@]}"; do
      versioned+=("${arg}@${crate_version}")
    done
    packages=("${versioned[@]}")
  fi

  safe_gate_print_list "${packages[@]}"
}

safe_gate_go_packages() {
  local -a packages=()
  local arg
  local skip_next=0

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
        packages+=("$(safe_gate_go_spec "${arg}")")
        ;;
    esac
  done

  safe_gate_print_list "${packages[@]}"
}

safe_gate_composer_packages() {
  local -a packages=()
  local arg
  local skip_next=0

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
        packages+=("$(safe_gate_colon_spec "${arg}")")
        ;;
    esac
  done

  safe_gate_print_list "${packages[@]}"
}

safe_gate_python_packages() {
  local -a packages=()
  local arg
  local skip_next=0

  for arg in "$@"; do
    if (( skip_next )); then
      skip_next=0
      continue
    fi

    case "${arg}" in
      -r|--requirement|--requirement=*|-e|--editable|--editable=*)
        return 1
        ;;
      -c|--constraint|-i|--index-url|--index|--default-index|--extra-index-url|--find-links|--trusted-host|--platform|--python-version|--implementation|--abi|--target|--prefix|--src|--upgrade-strategy|--config-settings|-C)
        # -i/--index/--default-index take a value: dropping it made the URL
        # look like a package spec and fail-opened the extractor (PR#30
        # review finding 1 sibling). The selector itself is threaded to the
        # audit by safe_gate_scan_target_flags.
        skip_next=1
        continue
        ;;
      --constraint=*|--index-url=*|--index=*|--default-index=*|--extra-index-url=*|--find-links=*|--trusted-host=*|--platform=*|--python-version=*|--implementation=*|--abi=*|--target=*|--prefix=*|--src=*|--upgrade-strategy=*|--config-settings=*)
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
        packages+=("$(safe_gate_python_spec "${arg}")")
        ;;
    esac
  done

  safe_gate_print_list "${packages[@]}"
}

# ---------------------------------------------------------------------------
# Spec builders
# ---------------------------------------------------------------------------

safe_gate_npm_spec() {
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

  safe_gate_print_spec "${name}" "${version}"
}

safe_gate_python_spec() {
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

  safe_gate_print_spec "${name}" "${version}"
}

safe_gate_colon_spec() {
  local spec="$1"
  local name version

  if [[ "${spec}" == *":"* ]]; then
    name="${spec%%:*}"
    version="${spec#*:}"
  else
    name="${spec}"
    version="latest"
  fi

  safe_gate_print_spec "${name}" "${version}"
}

safe_gate_go_spec() {
  local spec="$1"
  local name version

  if [[ "${spec}" == *@* ]]; then
    name="${spec%@*}"
    version="${spec##*@}"
  else
    name="${spec}"
    version="latest"
  fi

  safe_gate_print_spec "${name}" "${version}"
}

# An unpinned request is audited as the bare name: safe audit resolves the
# real target version itself (a fabricated @latest is version-blind and made
# pinned host-allow entries unmatchable).
safe_gate_print_spec() {
  local name="$1"
  local version="$2"

  if [[ -z "${version}" || "${version}" == "latest" ]]; then
    printf '%s\n' "${name}"
  else
    printf '%s\n' "${name}@${version}"
  fi
}

# Collect the newline-separated output of an extractor into an array, dropping
# empty entries. Usage: safe_gate_collect <array-name> <extractor output>
# The locals are underscore-prefixed on purpose: a plain name would shadow the
# caller's variable of the same name and the nameref would resolve to the local.
safe_gate_collect() {
  local -n _safe_gate_out_ref="$1"
  local _safe_gate_raw="$2"
  local _safe_gate_line

  _safe_gate_out_ref=()
  [[ -n "${_safe_gate_raw}" ]] || return 0
  while IFS= read -r _safe_gate_line; do
    [[ -n "${_safe_gate_line}" ]] && _safe_gate_out_ref+=("${_safe_gate_line}")
  done <<< "${_safe_gate_raw}"
  return 0
}

# A bare command name has no package-spec syntax: no version/tag/alias.
# Only such names are eligible for the local-bin passthrough, because a
# versioned or aliased spec (foo@latest, foo@npm:bar) can still fetch
# remotely even when a same-named local bin exists (npm matches a local
# dep only on exact name AND version).
safe_gate_is_bare_name() {
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
safe_gate_local_bin_exists() {
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

# ---------------------------------------------------------------------------
# Subcommand resolution
# ---------------------------------------------------------------------------

# Locate the real subcommand token, skipping any leading GLOBAL flags a tool
# accepts before its command (`npm --loglevel=error install evil`,
# `yarn --cwd sub add evil`, `pnpm --filter x dlx cmd`). Without this the
# wrappers read the subcommand as $1 and a leading flag slips the whole gate.
#
# Sets SAFE_GATE_SUBCMD (token, "" if none) and SAFE_GATE_SUBCMD_IDX
# (1-based index in "$@", 0 if none). Returns 0 on success (subcommand found
# or genuinely absent), 2 fail-closed on an ambiguous unrecognized space-form
# flag (SAFE_GATE_SUBCMD_BADFLAG names it).
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
safe_gate_locate_subcommand() {
  local val_alt="$1" bool_alt="$2"; shift 2
  local arg i=0 skip=0 boolval=0
  SAFE_GATE_SUBCMD=""; SAFE_GATE_SUBCMD_IDX=0; SAFE_GATE_SUBCMD_BADFLAG=""
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
      case "${arg,,}" in
        true|false) continue ;;
      esac
    fi
    case "${arg}" in
      --)
        # Options terminated: the next token, if any, is the subcommand.
        if (( i < $# )); then
          SAFE_GATE_SUBCMD="${@:i+1:1}"; SAFE_GATE_SUBCMD_IDX=$((i + 1))
        fi
        return 0 ;;
      --*=*|-*=*) continue ;;
      -?*)
        if safe_gate_alt_match "${arg}" "${val_alt}"; then
          skip=1; continue
        elif safe_gate_alt_match "${arg}" "${bool_alt}"; then
          boolval=1; continue
        fi
        SAFE_GATE_SUBCMD_BADFLAG="${arg}"; return 2 ;;
      *) SAFE_GATE_SUBCMD="${arg}"; SAFE_GATE_SUBCMD_IDX=$i; return 0 ;;
    esac
  done
  return 0
}

# Per-tool leading-global-flag tables (val|bool), kept deliberately small: a
# gap only over-refuses (fail-closed, escapable via =form); a MISclassified
# flag bypasses. `go` accepts no pre-command flags → empty tables (any leading
# flag fails closed, matching go's own grammar).
#
# Added over the zsh tables: the version/help switches (--version, -v or -V per
# tool, --help, -h). They were a gap, not a policy: the zsh wrappers refused a
# bare `npm --version`, which nothing noticed while gating only existed inside
# an interactive zsh. As PATH wrappers they are on the path of every tool
# detection script, and they take no value in any of these tools, so they are
# classified as switches like any other boolean.
safe_gate_global_flags() {
  case "$1" in
    npm)
      SAFE_GATE_GVAL='--loglevel|--prefix|--cache|--registry|--userconfig|--globalconfig|--workspace|-w|--script-shell|--node-options|--omit|--include|--tag'
      SAFE_GATE_GBOOL='--version|-v|--help|-h|-q|--quiet|--silent|-d|-dd|-ddd|--verbose|--global|-g|--foreground-scripts|--no-fund|--no-audit|--offline|--prefer-offline|--prefer-online|--ignore-scripts|--workspaces|--include-workspace-root|--no-workspaces|--no-color|--json' ;;
    pnpm)
      # --config is a no-value switch on `pnpm add` (configurational deps),
      # NOT a value-taker — keep it out of GVAL or it eats the subcommand.
      SAFE_GATE_GVAL='--filter|-F|--dir|-C|--reporter|--workspace-concurrency'
      SAFE_GATE_GBOOL='--version|-v|--help|-h|-w|--workspace-root|-r|--recursive|--stream|--silent|--no-color|--global|-g|--aggregate-output|--config' ;;
    bun)
      # bun's --cwd/--config/-c are EQUALS-ONLY (`--config=<val>`); bun does
      # not consume a following space-form token, so they must not sit in the
      # space-form value table (that would eat the subcommand). The =form is
      # covered by the generic --*=* skip; bare space-form fails closed.
      SAFE_GATE_GVAL=''
      SAFE_GATE_GBOOL='--version|-v|--help|-h|--silent|--global|-g|--no-cache|--no-progress' ;;
    yarn)
      SAFE_GATE_GVAL='--cwd|--registry|--modules-folder|--cache-folder|--mutex|--network-timeout|--network-concurrency|--proxy|--https-proxy'
      SAFE_GATE_GBOOL='--version|-v|--help|-h|--verbose|--silent|-s|--offline|--prefer-offline|--no-progress|--json|--flat|--force|--ignore-scripts|--non-interactive|--no-lockfile|--frozen-lockfile' ;;
    pip|pip3)
      # --use-feature takes a value (e.g. fast-deps) — GVAL, not GBOOL.
      SAFE_GATE_GVAL='--log|--proxy|--retries|--timeout|--cache-dir|--python|--index-url|-i|--cert|--client-cert|--use-feature'
      SAFE_GATE_GBOOL='--version|-V|--help|-h|-q|--quiet|-v|-vv|-vvv|--verbose|--isolated|--no-input|--no-color|--require-virtualenv|--no-cache-dir|--disable-pip-version-check' ;;
    uv)
      SAFE_GATE_GVAL='--cache-dir|--config-file|--directory|--project|--color'
      SAFE_GATE_GBOOL='--version|-V|--help|-h|--offline|-q|--quiet|-v|--verbose|--native-tls|--no-cache|-n|--no-progress|--no-config' ;;
    cargo)
      SAFE_GATE_GVAL='--color|--config|-Z|-C'
      SAFE_GATE_GBOOL='--version|-V|--help|-h|-v|--verbose|-q|--quiet|--offline|--frozen|--locked' ;;
    composer)
      SAFE_GATE_GVAL='-d|--working-dir'
      SAFE_GATE_GBOOL='-v|-vv|-vvv|--verbose|-q|--quiet|-n|--no-interaction|--profile|--no-plugins|--no-scripts|--ansi|--no-ansi|-h|--help|-V|--version' ;;
    go|*)
      SAFE_GATE_GVAL=''
      SAFE_GATE_GBOOL='' ;;
  esac
}

# Resolve the subcommand for <tool> over "$@"; on ambiguity print the legible
# fail-closed refusal and return 100 so the caller can `|| return $?`.
safe_gate_route() {
  local tool="$1"; shift
  safe_gate_global_flags "${tool}"
  safe_gate_locate_subcommand "${SAFE_GATE_GVAL}" "${SAFE_GATE_GBOOL}" "$@"
  case $? in
    2)
      safe_gate_err "safe: BLOCKED ${tool} — cannot find the subcommand past unrecognized flag '${SAFE_GATE_SUBCMD_BADFLAG}'; to allow: rewrite it as '${SAFE_GATE_SUBCMD_BADFLAG}=<value>', then retry; details: safe explain"
      return 100 ;;
  esac
  return 0
}

# ---------------------------------------------------------------------------
# Exec-style (fetch-and-run) gate
# ---------------------------------------------------------------------------

# Gate exec-style invocations that can fetch and run registry packages
# (npm exec/x, bun x, pnpm dlx, yarn dlx, uv tool run). Audits every package
# the invocation would fetch, then the caller delegates to the real tool.
#
# Args: <label> <ecosystem> <local_bin_ok> <post_positional> \
#       <from_alt> <extra_alt> <val_alt> <bool_alt> <refuse_alt> <args...>
#   Each *_alt is a '|'-separated flag table (e.g. '--package|-p'); '' = none.
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
safe_gate_exec_gate() {
  local label="$1" ecosystem="$2" local_bin_ok="$3" post_positional="$4"
  local from_alt="$5" extra_alt="$6" val_alt="$7" bool_alt="$8" refuse_alt="$9"
  shift 9
  local -a from_specs=() extra_specs=() audit_specs=() normalized=()
  local arg flag spec positional="" refuse_msg=""
  local expect_from=0 expect_extra=0 skip_next=0 after_dd=0 seen_pos=0
  refuse_msg="safe: BLOCKED ${label} — cannot vet the packages named by a requirements file inline; to allow: ask the operator to review them (safe audit check <pkg> --ecosystem ${ecosystem}), then retry; details: safe explain"

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
      if safe_gate_alt_match "${flag}" "${refuse_alt}"; then
        safe_gate_err "${refuse_msg}"; return 100
      elif safe_gate_alt_match "${flag}" "${from_alt}"; then
        from_specs+=("${arg#*=}")
      elif safe_gate_alt_match "${flag}" "${extra_alt}"; then
        extra_specs+=("${arg#*=}")
      fi
      continue
    fi

    case "${arg}" in
      -*)
        if safe_gate_alt_match "${arg}" "${refuse_alt}"; then
          safe_gate_err "${refuse_msg}"; return 100
        elif (( seen_pos )) && [[ "${arg}" != --* ]]; then
          # Phase 2 (post-command): only npm's greedy long-form config flags
          # (--package) are parsed after the command; short flags like -p are
          # NOT, so ignore them here rather than mistaking the value for the
          # package. Everything short post-command is a command arg.
          :
        elif safe_gate_alt_match "${arg}" "${from_alt}"; then
          expect_from=1
        elif safe_gate_alt_match "${arg}" "${extra_alt}"; then
          expect_extra=1
        elif (( seen_pos )); then
          # Phase 2 unmatched long flag: the command's own option, ignored.
          :
        elif safe_gate_alt_match "${arg}" "${val_alt}"; then
          skip_next=1
        elif safe_gate_alt_match "${arg}" "${bool_alt}"; then
          :
        else
          safe_gate_err "safe: BLOCKED ${label} — cannot identify the package to audit past unrecognized option '${arg}'; to allow: rewrite it as '${arg}=<value>' (or pass the package via an explicit spec), then retry; details: safe explain"
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
    if ! { (( local_bin_ok )) && safe_gate_is_bare_name "${positional}" && \
           safe_gate_local_bin_exists "${positional}"; }; then
      audit_specs+=("${positional}")
    fi
  fi

  (( ${#audit_specs[@]} > 0 )) || return 0

  for spec in "${audit_specs[@]}"; do
    case "${ecosystem}" in
      python) normalized+=("$(safe_gate_python_spec "${spec}")") ;;
      *) normalized+=("$(safe_gate_npm_spec "${spec}")") ;;
    esac
  done

  safe_gate_check_many "${ecosystem}" "${normalized[@]}"
}

# ---------------------------------------------------------------------------
# Per-tool routing
# ---------------------------------------------------------------------------

safe_gate_npm_like() {
  local tool="$1"
  shift
  safe_gate_route "${tool}" "$@" || return $?
  safe_gate_scan_target_flags npm "$@"
  local subcommand="${SAFE_GATE_SUBCMD}"
  local -a rest=() raw=() packages=()
  rest=("${@:SAFE_GATE_SUBCMD_IDX+1}")
  local parser="safe_gate_${tool}_packages"
  local raw_package
  local project_present=1

  case "${tool}:${subcommand}" in
    npm:exec|npm:x)
      # npm's config parser is greedy: --package is honored even after the
      # command, so post_positional=1.
      safe_gate_exec_gate "npm ${subcommand}" npm 1 1 \
        '--package|-p' '' \
        '-c|--call|-w|--workspace|--cache|--prefix|--registry|--userconfig|--globalconfig|--loglevel|--script-shell|--node-options|--omit|--include' \
        '-y|--yes|--no|--offline|--prefer-offline|--prefer-online|--ignore-existing|--foreground-scripts|--silent|--quiet|--workspaces|--include-workspace-root' \
        '' \
        "${rest[@]}" || return $?
      safe_gate_exec_real "${tool}" "$@"
      ;;
    bun:x)
      safe_gate_exec_gate "bun x" npm 1 0 \
        '--package|-p' '' '' \
        '--bun|--silent|--no-install|--verbose' \
        '' \
        "${rest[@]}" || return $?
      safe_gate_exec_real "${tool}" "$@"
      ;;
    pnpm:dlx)
      safe_gate_exec_gate "pnpm dlx" npm 0 0 \
        '--package' '' \
        '--allow-build|--reporter' \
        '-c|--shell-mode|--silent|-s' \
        '' \
        "${rest[@]}" || return $?
      safe_gate_exec_real "${tool}" "$@"
      ;;
  esac

  case "${subcommand}" in
    install|i|it|install-test|add|ci|update|u|up|upgrade|udpate) ;;
    *) safe_gate_exec_real "${tool}" "$@" ;;
  esac

  if safe_gate_has_arg "-g" "$@" || safe_gate_has_arg "--global" "$@"; then
    safe_gate_collect raw "$("${parser}" "${rest[@]}")"
    packages=()
    for raw_package in "${raw[@]}"; do
      packages+=("$(safe_gate_npm_spec "${raw_package}")")
    done

    if (( ${#packages[@]} > 0 )); then
      safe_gate_check_many npm "${packages[@]}" || return $?
    fi

    safe_gate_exec_real "${tool}" "$@"
  fi

  case "${tool}" in
    npm) safe_gate_npm_project_present; project_present=$? ;;
    pnpm) safe_gate_pnpm_project_present; project_present=$? ;;
    bun) safe_gate_bun_project_present; project_present=$? ;;
  esac

  if (( project_present == 0 )); then
    safe_gate_scan_project || return $?
  fi

  safe_gate_collect raw "$("${parser}" "${rest[@]}")"
  packages=()
  for raw_package in "${raw[@]}"; do
    packages+=("$(safe_gate_npm_spec "${raw_package}")")
  done

  if (( ${#packages[@]} > 0 )); then
    safe_gate_check_many npm "${packages[@]}" || return $?
  fi

  safe_gate_exec_real "${tool}" "$@"
}

# pnpx is pnpm dlx with the subcommand implied: every argument is already a
# dlx argument, so it routes through the same exec gate.
safe_gate_pnpx() {
  SAFE_GATE_SUBCMD="dlx"
  SAFE_GATE_SUBCMD_IDX=0
  safe_gate_exec_gate "pnpx" npm 0 0 \
    '--package' '' \
    '--allow-build|--reporter' \
    '-c|--shell-mode|--silent|-s' \
    '' \
    "$@" || return $?
  safe_gate_exec_real pnpx "$@"
}

safe_gate_yarn() {
  safe_gate_route yarn "$@" || return $?
  safe_gate_scan_target_flags npm "$@"
  local first="${SAFE_GATE_SUBCMD}"
  local subidx=$SAFE_GATE_SUBCMD_IDX
  local second="${@:subidx+1:1}"
  local -a raw=() packages=()
  local raw_package

  if [[ "${first}" == "dlx" ]]; then
    safe_gate_exec_gate "yarn dlx" npm 0 0 \
      '--package|-p' '' '' '-q|--quiet' '' \
      "${@:subidx+1}" || return $?
    safe_gate_exec_real yarn "$@"
  fi

  if [[ "${first}" == "global" && ( "${second}" == "add" || "${second}" == "upgrade" ) ]]; then
    safe_gate_collect raw "$(safe_gate_yarn_packages "${@:subidx+2}")"
    packages=()
    for raw_package in "${raw[@]}"; do
      packages+=("$(safe_gate_npm_spec "${raw_package}")")
    done

    if (( ${#packages[@]} > 0 )); then
      safe_gate_check_many npm "${packages[@]}" || return $?
    fi

    safe_gate_exec_real yarn "$@"
  fi

  case "${first}" in
    ""|install|add|up|upgrade|upgrade-interactive)
      if safe_gate_yarn_project_present; then
        safe_gate_scan_project || return $?
      fi

      if [[ "${first}" == "add" || "${first}" == "up" || "${first}" == "upgrade" ]]; then
        safe_gate_collect raw "$(safe_gate_yarn_packages "${@:subidx+1}")"
        packages=()
        for raw_package in "${raw[@]}"; do
          packages+=("$(safe_gate_npm_spec "${raw_package}")")
        done

        if (( ${#packages[@]} > 0 )); then
          safe_gate_check_many npm "${packages[@]}" || return $?
        fi
      fi
      ;;
  esac

  safe_gate_exec_real yarn "$@"
}

safe_gate_pip_like() {
  local tool="$1"
  shift
  safe_gate_route "${tool}" "$@" || return $?
  safe_gate_scan_target_flags python "$@"
  local subcommand="${SAFE_GATE_SUBCMD}"
  local subidx=$SAFE_GATE_SUBCMD_IDX
  local -a packages=()
  local extractor_out extractor_rc

  [[ "${subcommand}" == "install" || "${subcommand}" == "upgrade" ]] || safe_gate_exec_real "${tool}" "$@"

  if safe_gate_pip_project_install "${@:subidx+1}"; then
    safe_gate_scan_project || return $?
    safe_gate_exec_real "${tool}" "$@"
  fi

  extractor_out="$(safe_gate_python_packages "${@:subidx+1}")"
  extractor_rc=$?
  safe_gate_collect packages "${extractor_out}"
  if (( extractor_rc != 0 || ${#packages[@]} == 0 )); then
    safe_gate_exec_real "${tool}" "$@"
  fi

  safe_gate_check_many python "${packages[@]}" || return $?
  safe_gate_exec_real "${tool}" "$@"
}

safe_gate_uv() {
  safe_gate_route uv "$@" || return $?
  # uv accepts index selectors on every fetch path (tool install/run, run
  # --with, pip install); dropping them audited PyPI while uv installed from
  # elsewhere (PR#30 review finding 1).
  safe_gate_scan_target_flags python "$@"
  local first="${SAFE_GATE_SUBCMD}"
  local subidx=$SAFE_GATE_SUBCMD_IDX
  local second="${@:subidx+1:1}"
  local -a packages=()
  local extractor_out extractor_rc

  if [[ "${first}" == "sync" ]]; then
    if safe_gate_uv_project_present; then
      safe_gate_scan_project || return $?
    fi

    safe_gate_exec_real uv "$@"
  fi

  if [[ "${first}" == "run" ]]; then
    # `uv run [uv-options] <command> [command-args]` executes project code;
    # only --with/-w pulls extra registry packages. uv options appear only
    # BEFORE the command, so parsing must stop at the command token — else a
    # `--with` in the program's own args gets mis-audited. Unknown bare
    # options before the command are ambiguous → fail closed (safe: an
    # incomplete list over-refuses but never lets a --with slip past).
    local -a with_specs=() normalized_with=()
    local run_arg expect_with=0 skip_with_next=0
    # --with-requirements names a file of packages we cannot vet inline → refuse.
    local uv_val='--python|-p|--with-editable|--index|--index-url|--extra-index-url|--default-index|--constraint|-c|--index-strategy|--keyring-provider|--resolution|--prerelease|--exclude-newer|--config-setting|--refresh-package|--group|--only-group|--no-group|--extra|--no-extra|--project|--directory|--python-preference'
    local uv_bool='--frozen|--locked|--no-sync|--offline|--isolated|--no-project|--all-extras|--no-dev|--dev|--only-dev|--no-default-groups|--all-groups|--refresh|--reinstall|--upgrade|--all-packages|--no-editable|--exact|--inexact|--no-binary|--no-build|--compile-bytecode|--no-compile-bytecode|--native-tls|--no-cache|-n|-q|--quiet|-v|--verbose|--managed-python|--no-managed-python|--script|-s|-m|--module'
    for run_arg in "${@:subidx+1}"; do
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
        safe_gate_err "safe: BLOCKED uv run — cannot vet the packages named by --with-requirements inline; to allow: ask the operator to review them (safe audit check <pkg> --ecosystem python), then retry; details: safe explain"
        return 100
      fi
      if [[ "${run_arg}" == --*=* ]]; then
        [[ "${run_arg}" == --with=* ]] && with_specs+=("${run_arg#--with=}")
        continue
      fi
      case "${run_arg}" in
        --with|-w) expect_with=1 ;;
        -*)
          if safe_gate_alt_match "${run_arg}" "${uv_val}"; then
            skip_with_next=1
          elif safe_gate_alt_match "${run_arg}" "${uv_bool}"; then
            :
          else
            safe_gate_err "safe: BLOCKED uv run — cannot identify --with packages past unrecognized option '${run_arg}'; to allow: rewrite it as '${run_arg}=<value>', then retry; details: safe explain"
            return 100
          fi
          ;;
        *) break ;;
      esac
    done
    if (( ${#with_specs[@]} > 0 )); then
      for run_arg in "${with_specs[@]}"; do
        normalized_with+=("$(safe_gate_python_spec "${run_arg}")")
      done
      safe_gate_check_many python "${normalized_with[@]}" || return $?
    fi
    safe_gate_exec_real uv "$@"
  fi

  if [[ "${first}" == "tool" && "${second}" == "run" ]]; then
    safe_gate_exec_gate "uv tool run" python 0 0 \
      '--from' '--with|-w' \
      '--python|-p|--with-editable|--index|--index-url|--extra-index-url|--default-index|--constraint|-c|--index-strategy|--keyring-provider|--resolution|--prerelease|--exclude-newer|--config-setting|--refresh-package' \
      '--offline|--isolated|--system|--no-project|--refresh|--reinstall|--upgrade|-q|--quiet|-v|--verbose|--native-tls|--no-cache|-n' \
      '--with-requirements' \
      "${@:subidx+2}" || return $?
    safe_gate_exec_real uv "$@"
  fi

  if [[ "${first}" == "tool" && "${second}" == "install" ]]; then
    extractor_out="$(safe_gate_python_packages "${@:subidx+2}")"
    extractor_rc=$?
    safe_gate_collect packages "${extractor_out}"
    if (( extractor_rc != 0 || ${#packages[@]} == 0 )); then
      safe_gate_exec_real uv "$@"
    fi

    safe_gate_check_many python "${packages[@]}" || return $?
    safe_gate_exec_real uv "$@"
  fi

  if [[ "${first}" == "pip" && "${second}" == "install" ]]; then
    if safe_gate_pip_project_install "${@:subidx+2}"; then
      safe_gate_scan_project || return $?
      safe_gate_exec_real uv "$@"
    fi

    extractor_out="$(safe_gate_python_packages "${@:subidx+2}")"
    extractor_rc=$?
    safe_gate_collect packages "${extractor_out}"
    if (( extractor_rc != 0 || ${#packages[@]} == 0 )); then
      safe_gate_exec_real uv "$@"
    fi

    safe_gate_check_many python "${packages[@]}" || return $?
    safe_gate_exec_real uv "$@"
  fi

  safe_gate_exec_real uv "$@"
}

safe_gate_cargo() {
  safe_gate_route cargo "$@" || return $?
  safe_gate_scan_target_flags cargo "$@"
  local subcommand="${SAFE_GATE_SUBCMD}"
  local subidx=$SAFE_GATE_SUBCMD_IDX
  local -a packages=()

  if [[ "${subcommand}" != "install" ]]; then
    case "${subcommand}" in
      build|check|test|update)
        if safe_gate_cargo_project_present; then
          safe_gate_scan_project || return $?
        fi
        ;;
    esac

    safe_gate_exec_real cargo "$@"
  fi

  if safe_gate_has_arg "--path" "$@" || safe_gate_has_prefix_arg "--path=" "$@" ||
     safe_gate_has_arg "--git" "$@" || safe_gate_has_prefix_arg "--git=" "$@"; then
    safe_gate_exec_real cargo "$@"
  fi

  safe_gate_collect packages "$(safe_gate_cargo_packages "${@:subidx+1}")"
  if (( ${#packages[@]} > 0 )); then
    safe_gate_check_many cargo "${packages[@]}" || return $?
  fi

  safe_gate_exec_real cargo "$@"
}

safe_gate_go() {
  safe_gate_route go "$@" || return $?
  safe_gate_scan_target_flags go "$@"
  local subcommand="${SAFE_GATE_SUBCMD}"
  local subidx=$SAFE_GATE_SUBCMD_IDX
  local second="${@:subidx+1:1}"
  local -a packages=()
  local extractor_out extractor_rc

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
    for run_arg in "${@:subidx+1}"; do
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
        -*)
          if safe_gate_alt_match "${run_arg}" "${go_val}"; then
            run_skip_next=1
          elif safe_gate_alt_match "${run_arg}" "${go_bool}"; then
            :
          else
            safe_gate_err "safe: BLOCKED go run — cannot identify the run target past unrecognized flag '${run_arg}'; to allow: rewrite it as '${run_arg}=<value>', then retry; details: safe explain"
            return 100
          fi
          ;;
        *) run_target="${run_arg}"; break ;;
      esac
    done
    if [[ -n "${run_target}" && "${run_target}" == *@* && "${run_target}" != .* && "${run_target}" != /* ]]; then
      safe_gate_check_many go "$(safe_gate_go_spec "${run_target}")" || return $?
    fi
    safe_gate_exec_real go "$@"
  fi

  if [[ "${subcommand}" != "install" ]]; then
    if [[ "${subcommand}" == "build" || "${subcommand}" == "test" ||
          ( "${subcommand}" == "mod" && ( "${second}" == "download" || "${second}" == "tidy" ) ) ]]; then
      if safe_gate_go_project_present; then
        safe_gate_scan_project || return $?
      fi
    fi

    safe_gate_exec_real go "$@"
  fi

  extractor_out="$(safe_gate_go_packages "${@:subidx+1}")"
  extractor_rc=$?
  if (( extractor_rc != 0 )); then
    safe_gate_exec_real go "$@"
  fi
  safe_gate_collect packages "${extractor_out}"

  if (( ${#packages[@]} > 0 )); then
    safe_gate_check_many go "${packages[@]}" || return $?
  fi

  safe_gate_exec_real go "$@"
}

safe_gate_composer() {
  safe_gate_route composer "$@" || return $?
  safe_gate_scan_target_flags composer "$@"
  local first="${SAFE_GATE_SUBCMD}"
  local subidx=$SAFE_GATE_SUBCMD_IDX
  local second="${@:subidx+1:1}"
  local -a packages=()

  if [[ "${first}" != "global" || "${second}" != "require" ]]; then
    if [[ "${first}" == "install" || "${first}" == "update" || "${first}" == "require" ]]; then
      if safe_gate_composer_project_present; then
        safe_gate_scan_project || return $?
      fi

      if [[ "${first}" == "require" ]]; then
        safe_gate_collect packages "$(safe_gate_composer_packages "${@:subidx+1}")"
        if (( ${#packages[@]} > 0 )); then
          safe_gate_check_many composer "${packages[@]}" || return $?
        fi
      fi
    fi

    safe_gate_exec_real composer "$@"
  fi

  safe_gate_collect packages "$(safe_gate_composer_packages "${@:subidx+2}")"
  if (( ${#packages[@]} > 0 )); then
    safe_gate_check_many composer "${packages[@]}" || return $?
  fi

  safe_gate_exec_real composer "$@"
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

safe_gate_main() {
  local tool="${1:-}"
  shift || true

  # This body is a port of code written for a shell without errexit; a bare
  # `[[ ... ]] &&` test returning false must not abort the gate. Disable it
  # for the routing logic (the caller restores its own shell options).
  set +e

  [[ -n "${tool}" ]] || {
    safe_gate_err "safe: gate: missing tool name"
    return 2
  }

  # No re-entry guard by design: recursion cannot loop (safe_gate_exec_real
  # only ever execs a resolved non-wrapper path), and child processes that
  # invoke a wrapped tool SHOULD be gated — an env-var skip switch would be
  # both a forgeable bypass and a coverage hole for lifecycle scripts.
  case "${tool}" in
    npm|pnpm|bun) safe_gate_npm_like "${tool}" "$@" ;;
    pnpx) safe_gate_pnpx "$@" ;;
    yarn) safe_gate_yarn "$@" ;;
    pip|pip3) safe_gate_pip_like "${tool}" "$@" ;;
    uv) safe_gate_uv "$@" ;;
    cargo) safe_gate_cargo "$@" ;;
    go) safe_gate_go "$@" ;;
    composer) safe_gate_composer "$@" ;;
    *)
      # Fail closed: a wrapper exists for a tool this library has no routing
      # table for, so nothing can vouch for the command.
      safe_gate_err "safe: BLOCKED ${tool} — safe gate has no routing table for '${tool}'; to allow: ask the operator to remove the stale wrapper or update safe; details: safe explain"
      return 100
      ;;
  esac
}
