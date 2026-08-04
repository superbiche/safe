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

# Socket budget handed to the audit child (SAFE_AUDIT_SOCKET_TIMEOUT). The
# audit's own default is 30s — tuned for direct operator runs; under the gate
# a hanging Socket backend should cost less wall-clock, and the leash
# arithmetic below has to be able to rely on the value it passed down.
SAFE_GATE_SOCKET_BUDGET_DEFAULT=15
# Sequential multiplicity inside one `safe-audit check`, mirrored from
# bin/safe-audit (PR#65 review F1 — the leash must cover the real bounded
# path, not a one-of-each sketch):
# - socket_score_json can run TWICE with the full budget: the first attempt
#   plus the vault-injected retry after a late auth failure (delta N1).
# - resolve_target_versions caps RESOLVED_VERSIONS at 4; GuardDog runs a
#   --version probe plus one scan per resolved version, each with the full
#   configured budget.
# - osv_query_package_json is bounded at 10 pages x curl --max-time 8 = 80s
#   per invocation; it runs once per resolved version plus once more for the
#   cooldown security-fix exemption.
SAFE_GATE_SOCKET_ATTEMPTS=2
SAFE_GATE_MAX_RESOLVED_VERSIONS=4
SAFE_GATE_OSV_QUERY_BUDGET=80
# Fixed allowance for the remaining individually bounded fetches: packument
# resolution, artifact identity, release-age lookups (curl --max-time 5-10).
SAFE_GATE_AUDIT_OVERHEAD_SECONDS=120
SAFE_GATE_WARNED_MISSING=0
SAFE_GATE_SUBCMD=""
SAFE_GATE_SUBCMD_IDX=0
SAFE_GATE_SUBCMD_BADFLAG=""
SAFE_GATE_GVAL=""
SAFE_GATE_GBOOL=""
SAFE_GATE_NPM_USERCONFIG=""
SAFE_GATE_NPM_GLOBALCONFIG=""
SAFE_GATE_ENV_SCRUB=()

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

# Tool field of a wrapper's canonical marker line (line 2, per install.sh
# gate_wrapper_marked). Empty output when the line is not a marker.
safe_gate_wrapper_marker_tool() {
  local path="$1" line
  line="$(LC_ALL=C sed -n '2p' -- "$path" 2>/dev/null)"
  case "$line" in
    '# safe-gate-wrapper '*' tool='*) printf '%s\n' "${line##* tool=}" ;;
  esac
}

# First executable <tool> on PATH that is not one of our wrappers. For node
# tools that is normally the version-manager shim (mise), which is what we
# want: per-project tool versions keep resolving.
safe_gate_resolve_real() {
  local tool="$1" dir candidate
  local displaced=""
  local -a dirs=()

  IFS=':' read -r -a dirs <<< "${PATH}"
  for dir in "${dirs[@]}"; do
    [[ -n "$dir" ]] || dir="."
    candidate="${dir}/${tool}"
    [[ -f "$candidate" && -x "$candidate" ]] || continue
    if safe_gate_is_wrapper "$candidate"; then
      # A mise reshim run while our mise wrapper shadows the real binary
      # binds every shim to the wrapper: a file named <tool> whose marker
      # says tool=mise. Its argv0 dispatch still reaches the real mise, so
      # it IS the version-manager shim we want as the delegate — skipping
      # it left node tools with zero candidates and exit 127 (2026-08-03).
      if [[ "$tool" != "mise" ]] \
        && [[ "$(safe_gate_wrapper_marker_tool "$candidate")" == "mise" ]]; then
        printf '%s\n' "$candidate"
        return 0
      fi
      # A tool whose only installation sits at the path the wrapper occupies is
      # moved to <tool>.original at install time (uv, which installs itself to
      # ~/.local/bin/uv). Remember it and keep walking: a real tool further
      # along PATH — a mise shim, say — must still win, so per-project versions
      # are never overridden by the displaced copy.
      if [[ -z "$displaced" && -f "${candidate}.original" && -x "${candidate}.original" ]]; then
        displaced="${candidate}.original"
      fi
      continue
    fi
    printf '%s\n' "$candidate"
    return 0
  done

  [[ -n "$displaced" ]] || return 1
  printf '%s\n' "$displaced"
}

# Delegate to the real tool. Never returns — except in audit-only mode
# (SAFE_GATE_NO_EXEC=1, used when mise wraps an inner gated command: the
# routing/audit runs, the exec is the outer tool's job). A stray external
# SAFE_GATE_NO_EXEC makes commands audit-then-not-run: fail-safe, not a
# bypass.
safe_gate_exec_real() {
  local tool="$1"
  shift
  local real

  if [[ "${SAFE_GATE_NO_EXEC:-}" == "1" ]]; then
    return 0
  fi

  real="$(safe_gate_resolve_real "$tool")"
  if [[ -z "$real" ]]; then
    # 127 is the agent contract's "genuinely missing command" (safe explain);
    # a policy refusal is never 127.
    safe_gate_err "safe: gate: ${tool}: command not found (no non-wrapper ${tool} on PATH)"
    exit 127
  fi

  # Install-time security scanner (Bun Security Scanner API): when the safe
  # adapter is deployed and the caller has not chosen its own scanner, point
  # hosts that honor the contract (mise's embedded aube installer) at it.
  # Inert everywhere else — only aube reads the variable — and deliberately
  # injected for every delegate: any child of the delegate that ends up
  # running an aube install inherits the gate.
  if [[ -z "${AUBE_SECURITY_SCANNER:-}" \
    && -f "${SAFE_CONFIG_DIR:-${HOME}/.config/safe}/scanner.mjs" ]]; then
    export AUBE_SECURITY_SCANNER="${SAFE_CONFIG_DIR:-${HOME}/.config/safe}/scanner.mjs"
  fi

  # Bash assignment PRESERVES a pre-existing export attribute: if the caller
  # exported any scanner name, the scan would overwrite it with the
  # credential-bearing operational set and the delegate would inherit it
  # (PR#30 delta-2 finding P2). De-export all five before every delegate
  # exec — the audit child receives its values via argv flags, never env.
  export -n SAFE_GATE_DIST_TAG SAFE_GATE_REGISTRY SAFE_GATE_PROJECT_DIR \
    SAFE_GATE_NPM_USERCONFIG SAFE_GATE_NPM_GLOBALCONFIG 2>/dev/null || true

  # Environment names that are not valid shell identifiers (npm accepts
  # hyphenated npm_config_* keys) cannot be unset from bash: the scrub
  # records them and the delegate is exec'd through env -u so they never
  # reach the child.
  if (( ${#SAFE_GATE_ENV_SCRUB[@]} > 0 )); then
    local -a env_u=()
    local scrub_name
    for scrub_name in "${SAFE_GATE_ENV_SCRUB[@]}"; do
      env_u+=(-u "${scrub_name}")
    done
    exec env "${env_u[@]}" "$real" "$@"
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

# Timeout values are accepted only in 1..99999 seconds. Unbounded digit-only
# values are NOT harmless: a large enough integer wraps the signed shell
# arithmetic in the leash computation to zero, and GNU `timeout 0` DISABLES
# the timeout entirely — an unbounded hang instead of a backstop (PR#65
# review F2). Out-of-range values fall back to the component default.
safe_gate_timeout_value_ok() {
  [[ "$1" =~ ^[1-9][0-9]{0,4}$ ]]
}

safe_gate_socket_budget() {
  local budget="${SAFE_AUDIT_SOCKET_TIMEOUT:-}"
  safe_gate_timeout_value_ok "${budget}" || budget="${SAFE_GATE_SOCKET_BUDGET_DEFAULT}"
  printf '%s\n' "${budget}"
}

# The leash on the audit child must EXCEED the worst-case sum of the audit's
# own component budgets: every network probe inside `safe-audit check` is
# individually bounded (Socket score, GuardDog wall-clock, curl --max-time),
# so a leash smaller than their sequential worst case guarantees the kill
# lands here first and converts a legible per-component infra WARN into an
# illegible TIMEOUT_FAILCLOSED — which host-allow cannot rescue, and which
# the audit-infrastructure ruling forbids reading as a package signal. Live
# failure shape (Socket outage 2026-08-04): Socket's internal 30s hang alone
# consumed the whole 30s leash, so every uncached install died as a generic
# timeout instead of completing with "socket unavailable — infra WARN".
# The leash is therefore a BACKSTOP against unbounded regressions, not the
# operative timeout; the component budgets are. With defaults it computes to
# 15*2 + 120*(1+4) + 80*(4+1) + 120 = 1150s — deliberately generous: it only
# fires when a component escapes its own bound, which previously meant an
# indefinite hang. SAFE_INSTALL_TIMEOUT_SECONDS still overrides the
# computation absolutely (an out-of-range value is ignored, not passed to
# timeout(1) where garbage would fail the audit as exit 125 and 0 would
# disable the timeout).
safe_gate_audit_leash_seconds() {
  if safe_gate_timeout_value_ok "${SAFE_INSTALL_TIMEOUT_SECONDS:-}"; then
    printf '%s\n' "${SAFE_INSTALL_TIMEOUT_SECONDS}"
    return 0
  fi
  local guarddog_budget
  guarddog_budget="$(jq -r '.install.guarddog.timeout_seconds // 120' \
    "$(safe_gate_run_config_dir)/config.json" 2>/dev/null || true)"
  safe_gate_timeout_value_ok "${guarddog_budget}" || guarddog_budget=120
  printf '%s\n' "$(( $(safe_gate_socket_budget) * SAFE_GATE_SOCKET_ATTEMPTS \
    + guarddog_budget * (1 + SAFE_GATE_MAX_RESOLVED_VERSIONS) \
    + SAFE_GATE_OSV_QUERY_BUDGET * (SAFE_GATE_MAX_RESOLVED_VERSIONS + 1) \
    + SAFE_GATE_AUDIT_OVERHEAD_SECONDS ))"
}

safe_gate_run_audit() {
  # 125, not 0: the real status is assigned INSIDE the redirected group
  # below, and a group whose own fd setup fails (fd exhaustion) never runs
  # its body — a 0 here would return as a false audit GO (delta-3 N4,
  # reproduced under ulimit -n 4). 125 lands in the generic fail-closed arm.
  local rc=125
  local -a extra=()
  [[ -n "${SAFE_GATE_DIST_TAG:-}" ]] && extra+=(--dist-tag "${SAFE_GATE_DIST_TAG}")
  [[ -n "${SAFE_GATE_REGISTRY:-}" ]] && extra+=(--registry "${SAFE_GATE_REGISTRY}")
  [[ -n "${SAFE_GATE_INSTALLER:-}" ]] && extra+=(--installer "${SAFE_GATE_INSTALLER}")
  [[ -n "${SAFE_GATE_PROJECT_DIR:-}" ]] && extra+=(--project-dir "${SAFE_GATE_PROJECT_DIR}")
  [[ -n "${SAFE_GATE_NPM_USERCONFIG:-}" ]] && extra+=(--npm-userconfig "${SAFE_GATE_NPM_USERCONFIG}")
  [[ -n "${SAFE_GATE_NPM_GLOBALCONFIG:-}" ]] && extra+=(--npm-globalconfig "${SAFE_GATE_NPM_GLOBALCONFIG}")
  local socket_budget
  socket_budget="$(safe_gate_socket_budget)"
  # --kill-after: TERM-only timeout is not a backstop — a TERM-resistant
  # child outlives it indefinitely (delta N2; reproduced with
  # `trap '' TERM`). Tests observe the exact argv through a PATH-injected
  # timeout recorder, so the leash value handed here is pinned at the real
  # call site, not self-reported.
  if command -v timeout >/dev/null 2>&1; then
    # fd shuffle: the audit child's stderr stays on the real stderr (via fd
    # 3) while the SHELL's own job-death diagnostic is discarded — GNU
    # timeout without --foreground signals its own process group, so a KILL
    # escalation kills timeout itself and bash prints "Killed ..." before
    # the refusal, breaking the single-final-stderr-line contract
    # (delta-2 N3).
    {
      SAFE_AUDIT_SOCKET_TIMEOUT="${socket_budget}" \
        timeout --kill-after=2s "$(safe_gate_audit_leash_seconds)" \
        "${SAFE_GATE_AUDIT_BIN}" check "$@" "${extra[@]}" 2>&3
      rc=$?
    } 3>&2 2>/dev/null
  else
    SAFE_AUDIT_SOCKET_TIMEOUT="${socket_budget}" \
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
  # The accumulated set stays OPERATIONAL (credentials included): safe-audit
  # fetches packuments from it, and pre-redacting here broke authenticated
  # registries (PR#29 delta-6 finding N2). Redaction happens centrally in
  # safe-audit at every identity/receipt/display sink — never here.
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
  SAFE_GATE_NPM_USERCONFIG=""
  SAFE_GATE_NPM_GLOBALCONFIG=""
  # The installer is set by the tool handler AFTER this reset (bun for the
  # bun wrapper and bun-selected mise npm installs); safe-audit defaults it
  # from the ecosystem otherwise.
  SAFE_GATE_INSTALLER=""
  local prev="" arg
  for arg in "$@"; do
    case "${family}" in
      npm)
        case "${prev}" in
          --tag) SAFE_GATE_DIST_TAG="${arg}" ;;
          # --@scope:registry is a scoped source selector npm accepts on the
          # command line. It is threaded as a KEYED token (@scope:registry=URL)
          # — flattening the bare URL loses the key and lets the resolver pick
          # a different scope's registry (PR#29 delta-6 finding 3.2b).
          # --userconfig/--globalconfig swap in whole config files whose
          # registry keys become effective; the PATH is threaded to safe-audit,
          # which reads them (delta-7/8 config-path threading) — the gate never
          # parses a config file itself.
          --registry) safe_gate_add_source "${arg}" ;;
          --@*:registry) safe_gate_add_source "${prev#--}=${arg}" ;;
          --userconfig) SAFE_GATE_NPM_USERCONFIG="${arg}" ;;
          --globalconfig) SAFE_GATE_NPM_GLOBALCONFIG="${arg}" ;;
          --prefix|-C|--cwd|--dir) SAFE_GATE_PROJECT_DIR="${arg}" ;;
        esac
        case "${arg}" in
          --tag=*) SAFE_GATE_DIST_TAG="${arg#*=}" ;;
          --registry=*) safe_gate_add_source "${arg#*=}" ;;
          --@*:registry=*) safe_gate_add_source "${arg#--}" ;;
          --userconfig=*) SAFE_GATE_NPM_USERCONFIG="${arg#*=}" ;;
          --globalconfig=*) SAFE_GATE_NPM_GLOBALCONFIG="${arg#*=}" ;;
          --prefix=*|--cwd=*|--dir=*) SAFE_GATE_PROJECT_DIR="${arg#*=}" ;;
        esac
        ;;
      python)
        case "${prev}" in
          --index-url|-i|--extra-index-url|--default-index|--index) safe_gate_add_source "${arg}" ;;
          # find-links names a real endpoint: record it so operators can trust
          # a specific location instead of a blanket sentinel (PR#29 delta-5
          # finding 3.2 mitigation). --no-index keeps its sentinel: it is a
          # boolean switch with no endpoint to record.
          --find-links|-f) safe_gate_add_source "${arg}" ;;
        esac
        case "${arg}" in
          --index-url=*|--extra-index-url=*|--default-index=*|--index=*) safe_gate_add_source "${arg#*=}" ;;
          --find-links=*) safe_gate_add_source "${arg#*=}" ;;
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
# Disclose weaker-isolation provenance at REUSE time (review F9).
safe_gate_known_provenance() {
  local package="$1" ecosystem="$2" known_file name version
  case "${ecosystem}" in
    cargo) ecosystem="rust" ;;
    composer) ecosystem="php" ;;
    pip|uv) ecosystem="python" ;;
  esac
  command -v jq >/dev/null 2>&1 || return 0
  known_file="$(safe_gate_run_config_dir)/install-known.json"
  [[ -r "${known_file}" ]] || return 0
  IFS=$'\t' read -r name version <<< "$(safe_gate_split_spec "${package}")"
  [[ -n "${name}" ]] || return 0
  if jq -e --arg k "${ecosystem}:${name}" \
    '(.packages[$k].reasons // []) | index("guarddog_clean_for_versions_nosandbox") != null' \
    "${known_file}" >/dev/null 2>&1; then
    printf '%s' " — behavioral evidence was gathered WITHOUT the kernel sandbox"
  fi
}

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
  [[ -n "${SAFE_GATE_INSTALLER:-}" ]] && es_args+=(--installer "${SAFE_GATE_INSTALLER}")
  [[ -n "${SAFE_GATE_PROJECT_DIR:-}" ]] && es_args+=(--project-dir "${SAFE_GATE_PROJECT_DIR}")
  [[ -n "${SAFE_GATE_NPM_USERCONFIG:-}" ]] && es_args+=(--npm-userconfig "${SAFE_GATE_NPM_USERCONFIG}")
  [[ -n "${SAFE_GATE_NPM_GLOBALCONFIG:-}" ]] && es_args+=(--npm-globalconfig "${SAFE_GATE_NPM_GLOBALCONFIG}")
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

# Grant-time spellings (py|uv|pipx…) and audit-time spellings (python) must
# compare equal, or an operator grant goes silently inert.
safe_gate_canonical_eco() {
  case "$1" in
    py|python|uv|pipx|pypi) printf 'python' ;;
    npm|bun) printf 'npm' ;;
    *) printf '%s' "$1" ;;
  esac
}

safe_gate_host_allow_matches() {
  local package="$1"
  local ecosystem="$2"
  local host_allow_file name version entry_version entry_ecosystem

  command -v jq >/dev/null 2>&1 || return 1

  host_allow_file="$(safe_gate_run_config_dir)/host-allow.json"
  [[ -r "${host_allow_file}" ]] || return 1

  IFS=$'\t' read -r name version <<< "$(safe_gate_split_spec "${package}")"
  [[ -n "${name}" && -n "${version}" && "${version}" != "latest" ]] || return 1

  entry_version="$(jq -r --arg p "${name}" '.packages[$p].version // empty' "${host_allow_file}" 2>/dev/null || true)"
  entry_ecosystem="$(jq -r --arg p "${name}" '.packages[$p].ecosystem // "npm"' "${host_allow_file}" 2>/dev/null || true)"

  [[ "${entry_version}" == "${version}" ]] || return 1
  # Only grantable ecosystems are matchable: hand-edited entries for
  # unsupported ecosystems carry no authority (review PR#61 F3).
  local canon_eco
  canon_eco="$(safe_gate_canonical_eco "${ecosystem}")"
  case "${canon_eco}" in npm|python) ;; *) return 1 ;; esac
  [[ "$(safe_gate_canonical_eco "${entry_ecosystem}")" == "${canon_eco}" ]]
}

# ---------------------------------------------------------------------------
# scripts-allow: operator-reviewed lifecycle-script grants (exact identity)
# ---------------------------------------------------------------------------

safe_gate_scripts_allow_file() {
  printf '%s/scripts-allow.json' "$(safe_gate_run_config_dir)"
}

# Prints the granted version for a package name; fails when none.
safe_gate_scripts_allow_version() {
  local name="$1" file version
  command -v jq >/dev/null 2>&1 || return 1
  file="$(safe_gate_scripts_allow_file)"
  [[ -r "${file}" ]] || return 1
  version="$(jq -r --arg p "${name}" \
    '.packages[$p] | select((.ecosystem // "npm") == "npm") | .version // empty' \
    "${file}" 2>/dev/null || true)"
  [[ -n "${version}" ]] || return 1
  printf '%s' "${version}"
}

# Scrub inherited npm script-policy env from THIS process. npm accepts
# npm_config_* keys in any case and with hyphen or underscore spellings;
# hyphenated names are not valid shell identifiers and cannot be unset from
# bash, so they are recorded in SAFE_GATE_ENV_SCRUB and stripped at exec
# time via env -u (safe_gate_exec_real). Must run in the process that will
# exec the delegate — a subshell's scrub dies with the subshell.
safe_gate_npm_scrub_script_env() {
  SAFE_GATE_ENV_SCRUB=()
  local env_name env_key
  while IFS='=' read -r env_name _; do
    env_key="${env_name,,}"
    env_key="${env_key//-/_}"
    case "${env_key}" in
      npm_config_ignore_scripts|npm_config_allow_scripts|npm_config_strict_allow_scripts|npm_config_dangerously_allow_all_scripts)
        if [[ "${env_name}" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
          unset "${env_name}" 2>/dev/null || true
        else
          SAFE_GATE_ENV_SCRUB+=("${env_name}")
        fi
        ;;
    esac
  done < <(env)
}

# True when a mise [env] overlay (name b64 lines) defines an npm
# script-policy key under any spelling; sets SAFE_GATE_MISE_POLICY_KEY to
# the offending name.
safe_gate_mise_overlay_scripts_policy() {
  local overlay="$1" name _ key
  SAFE_GATE_MISE_POLICY_KEY=""
  [[ -n "${overlay}" ]] || return 1
  while IFS=' ' read -r name _; do
    [[ -n "${name}" ]] || continue
    key="${name,,}"
    key="${key//-/_}"
    case "${key}" in
      npm_config_ignore_scripts|npm_config_allow_scripts|npm_config_strict_allow_scripts|npm_config_dangerously_allow_all_scripts)
        SAFE_GATE_MISE_POLICY_KEY="${name}"
        return 0
        ;;
    esac
  done <<<"${overlay}"
  return 1
}

# npm's effective --global value across its boolean grammar: bare flag,
# `=value`, a following true/false token, and the --no- negation. Last
# occurrence wins, matching npm's parser. npm-only — pnpm/bun would parse a
# following "false" as a package name.
safe_gate_npm_global_true() {
  local -a args=("$@")
  local i state=1
  for (( i=0; i<${#args[@]}; i++ )); do
    case "${args[$i]}" in
      -g|--global)
        if (( i + 1 < ${#args[@]} )) && [[ "${args[$((i+1))]}" == "true" || "${args[$((i+1))]}" == "false" ]]; then
          if [[ "${args[$((i+1))]}" == "true" ]]; then state=0; else state=1; fi
          i=$((i + 1))
        else
          state=0
        fi
        ;;
      --global=true|-g=true) state=0 ;;
      --global=false|-g=false) state=1 ;;
      --no-global|--no-global=true) state=1 ;;
      --no-global=false) state=0 ;;
    esac
  done
  return "${state}"
}

# For an npm global install whose requested spec exactly matches an operator
# scripts grant: inject npm 12's per-command allow-scripts policy so the
# reviewed scripts run. The allow list carries every SOURCE-VERIFIED granted
# identity (a reviewed transitive dependency may run too, but only when its
# effective source is the default registry the review fetched from); any
# script-bearing dependency OUTSIDE the list hard-fails the install
# (strict). The global ignore-scripts default is never touched — the policy
# lives and dies with this one invocation. npm < 12 has no per-command
# policy: state the manual fallback instead of silently skipping scripts.
safe_gate_npm_scripts_env() {
  local package matched="" name version granted
  for package in "$@"; do
    IFS=$'\t' read -r name version <<< "$(safe_gate_split_spec "${package}")"
    granted="$(safe_gate_scripts_allow_version "${name}")" || continue
    if [[ "${version}" == "${granted}" ]]; then
      matched="${matched:+${matched},}${name}@${version}"
    else
      safe_gate_err "safe: scripts grant for ${name} is pinned to ${name}@${granted} — run npm i -g ${name}@${granted} to execute its reviewed install scripts"
    fi
  done
  [[ -n "${matched}" ]] || return 0

  # Grants were reviewed against the default public registry, and npm's
  # allow matcher binds name@version but NOT registry host: any identity in
  # the injected list whose effective source is custom (argv/env/rc
  # registry, ambient @scope:registry overrides) could resolve a DIFFERENT
  # artifact. So EVERY identity entering the allow list is source-verified
  # per name; unbound identities are excluded, and if a requested match is
  # excluded, injection is skipped entirely. Unverifiable fails closed (the
  # install proceeds script-less, exactly as without a grant).
  if ! safe_gate_audit_available; then
    safe_gate_err "safe: scripts grant matched (${matched}) but the effective install source cannot be verified (safe audit unavailable) — install scripts stay skipped"
    return 0
  fi
  local granted_spec granted_name current_source
  local -a verified=()
  while IFS= read -r granted_spec; do
    [[ -n "${granted_spec}" ]] || continue
    IFS=$'\t' read -r granted_name _ <<< "$(safe_gate_split_spec "${granted_spec}")"
    local -a es_args=("${granted_name}" --ecosystem npm)
    [[ -n "${SAFE_GATE_REGISTRY:-}" ]] && es_args+=(--registry "${SAFE_GATE_REGISTRY}")
    [[ -n "${SAFE_GATE_INSTALLER:-}" ]] && es_args+=(--installer "${SAFE_GATE_INSTALLER}")
    [[ -n "${SAFE_GATE_PROJECT_DIR:-}" ]] && es_args+=(--project-dir "${SAFE_GATE_PROJECT_DIR}")
    [[ -n "${SAFE_GATE_NPM_USERCONFIG:-}" ]] && es_args+=(--npm-userconfig "${SAFE_GATE_NPM_USERCONFIG}")
    [[ -n "${SAFE_GATE_NPM_GLOBALCONFIG:-}" ]] && es_args+=(--npm-globalconfig "${SAFE_GATE_NPM_GLOBALCONFIG}")
    if current_source="$("${SAFE_GATE_AUDIT_BIN}" effective-sources "${es_args[@]}" 2>/dev/null)" \
      && [[ "${current_source}" == "implicit-default" ]]; then
      verified+=("${granted_spec}")
    else
      safe_gate_err "safe: scripts grant ${granted_spec} is not bound to the default registry here (source '${current_source:-unverifiable}') — excluded from script authorization"
    fi
  done < <(jq -r \
    '.packages | to_entries[] | select((.value.ecosystem // "npm") == "npm") | "\(.key)@\(.value.version)"' \
    "$(safe_gate_scripts_allow_file)" 2>/dev/null)

  local requested_match match_verified
  local -a matched_specs=()
  IFS=',' read -r -a matched_specs <<< "${matched}"
  for requested_match in "${matched_specs[@]}"; do
    match_verified=1
    for granted_spec in ${verified[@]+"${verified[@]}"}; do
      [[ "${granted_spec}" == "${requested_match}" ]] && match_verified=0
    done
    if (( match_verified != 0 )); then
      safe_gate_err "safe: scripts grant for ${requested_match} was reviewed against the default registry; the effective source here differs — install scripts stay skipped"
      return 0
    fi
  done

  local real npm_version major allow_list
  real="$(safe_gate_resolve_real npm)" || real=""
  npm_version="$("${real:-npm}" --version 2>/dev/null || true)"
  major="${npm_version%%.*}"
  if [[ ! "${major}" =~ ^[0-9]+$ ]] || (( major < 12 )); then
    safe_gate_err "safe: scripts grant matched (${matched}) but npm ${npm_version:-unknown} has no per-command allow-scripts (needs >= 12) — scripts stay skipped; fallback: after the install, run only the audited script from the package directory"
    return 0
  fi
  allow_list="$(IFS=,; printf '%s' "${verified[*]}")"
  [[ -n "${allow_list}" ]] || return 0
  export npm_config_ignore_scripts=false
  export npm_config_allow_scripts="${allow_list}"
  export npm_config_strict_allow_scripts=true
  safe_gate_audit_log "npm" "${matched}" "SCRIPTS_ALLOW_INJECTED"
  safe_gate_err "safe: running operator-reviewed install scripts for ${matched} (npm allow-scripts, strict; unreviewed script-bearing dependencies fail the install)"
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

  # The decision comes from the RESULT DOCUMENT, not the exit code: a scan
  # that finds a critical advisory still exits 0 (its verdict lives in the
  # document), so gating on the exit code let every finding through. The copy
  # is private because the published result is one file per machine per day.
  local result_file=""
  local fallback_dir="${SAFE_DATA_DIR:-${HOME}/.local/share/safe}/gate"
  result_file="$(mktemp "${TMPDIR:-/tmp}/safe-gate-scan.XXXXXX" 2>/dev/null)" || result_file=""
  if [[ -z "${result_file}" ]]; then
    # Fall back to safe's own state directory before giving up: a full or
    # unwritable TMPDIR must not quietly downgrade the gate.
    mkdir -p "${fallback_dir}" 2>/dev/null &&
      result_file="$(mktemp "${fallback_dir}/scan.XXXXXX" 2>/dev/null)" || result_file=""
  fi
  if [[ -z "${result_file}" ]]; then
    # Without a private destination there is no verdict to read, and a scan
    # that exits 0 says nothing about what it found. Say that plainly rather
    # than treating "no answer" as "clean".
    safe_gate_err "safe install: cannot allocate a scan result file (TMPDIR and ${fallback_dir} both unwritable); the project was NOT audit-gated — safe doctor"
    "${SAFE_GATE_AUDIT_BIN}" scan --deps-only --allow-missing-tools --project . 2>&1 || true
    return 0
  fi

  # --deps-only: the preflight only cares about the dependency evidence the
  # install is about to change, and that mode is the one the scan cache can
  # replay — a bare `npm ci` in an unchanged tree costs a cache hit, not a
  # full scanner run. --allow-missing-tools keeps an uninstalled ecosystem
  # auditor from aborting the scan: it comes back as reported-but-not-run.
  scan_output="$("${SAFE_GATE_AUDIT_BIN}" scan --deps-only --allow-missing-tools \
    --result-out "${result_file}" --project . 2>&1)"
  scan_status=$?

  [[ -n "${scan_output}" ]] && printf '%s\n' "${scan_output}"

  local critical=0 broken="" have_verdict=0
  # Non-empty is not the same as readable. Against a truncated or malformed
  # document every jq expression below falls back to its default, and a
  # defaulted 0 criticals with no broken scanners is indistinguishable from
  # "scanned the project, found nothing" — the gate would report a clean
  # verdict it never read. Require parseable JSON carrying the exact field
  # the decision is made from; anything else is no verdict at all, which the
  # have_verdict==0 branch already says out loud.
  if [[ -s "${result_file}" ]] && command -v jq >/dev/null 2>&1 &&
     jq -e 'type == "object"
            and ((.audit_totals.critical? // .cve_scan.critical? // null) | type == "number")' \
       "${result_file}" >/dev/null 2>&1; then
    have_verdict=1
    critical="$(jq -r '.audit_totals.critical // .cve_scan.critical // 0' "${result_file}" 2>/dev/null || printf '0')"
    [[ "${critical}" =~ ^[0-9]+$ ]] || critical=0
    broken="$(jq -r '
      def broken: (.status // "ok") as $s
        | ($s == "error") or (($s != "ok") and (((.note // "") | test("fail|error"; "i"))));
      [ (.tool_status // {} | to_entries[]? | select(.value | broken) | .key),
        (.ecosystem_audits[]? | select(broken) | (.scanner // "unknown"))
      ] | unique | join(", ")
    ' "${result_file}" 2>/dev/null || printf '')"
  fi
  rm -f "${result_file}"

  if (( critical > 0 )); then
    if [[ -t 0 && -t 1 ]]; then
      safe_gate_err "safe install: safe audit scan reported ${critical} critical finding(s) in this project's dependencies"
    fi
    safe_gate_confirm_critical
    return $?
  fi

  if (( scan_status == 0 )); then
    if (( have_verdict == 0 )); then
      safe_gate_err "safe install: safe audit scan produced no readable result; the project was NOT audit-gated — safe doctor"
      return 0
    fi
    # A scanner that broke does not stop an install — the documented policy is
    # that non-critical scan failures warn and continue — but it is never
    # silent: what was not checked is said out loud.
    [[ -n "${broken}" ]] && safe_gate_err "safe install: scanner failure (${broken}); that coverage is missing — safe doctor"
    return 0
  fi

  # The scan failed, so there is no verdict to read. If it managed to say
  # "critical" before dying, that is still the strongest evidence available
  # and it gates — but the wording says the scan FAILED, because calling
  # infrastructure breakage a vulnerability finding is the one thing a
  # security tool must never do.
  if [[ "${scan_output,,}" == *critical* ]]; then
    if [[ -t 0 && -t 1 ]]; then
      safe_gate_err "safe install: safe audit scan failed with exit ${scan_status} after reporting critical findings"
    fi
    safe_gate_confirm_critical
    return $?
  fi

  safe_gate_err "safe install: safe audit scan failed with exit ${scan_status}; the project was not fully audited — safe doctor; proceeding"
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

# One-line operator hint for a refused package. host-allow covers the npm and
# python families; other ecosystems point at the audit detail command instead.
# Fallback hint when the audit could not supply a pinned suggestion (the gate
# prints resolved-version hints itself). Must never render an @latest shape:
# allow entries are always pinned to an exact resolved version.
safe_gate_allow_hint() {
  local package="$1"
  local ecosystem="$2"
  local name version

  IFS=$'\t' read -r name version <<< "$(safe_gate_split_spec "${package}")"
  case "$(safe_gate_canonical_eco "${ecosystem}")" in
    npm)
      if [[ -n "${version}" && "${version}" != "latest" ]]; then
        printf 'to allow: ask the operator to run: safe run host-allow add %s --reason "..." — then retry' "${package}"
      else
        printf 'to allow: pin an exact version first (see the resolved-version hint above) — allow entries are never @latest'
      fi
      ;;
    python)
      if [[ -n "${version}" && "${version}" != "latest" ]]; then
        printf 'to allow: ask the operator to run: safe run host-allow add %s --ecosystem python --reason "..." — then retry' "${package}"
      else
        printf 'to allow: pin an exact version first (see the resolved-version hint above) — allow entries are never @latest'
      fi
      ;;
    *)
      printf 'to allow: operator review — safe audit check %s --ecosystem %s' "${package}" "${ecosystem}"
      ;;
  esac
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
      # No allow hint on BLOCK: host-allow is a WARN-tier escape hatch and
      # can never clear a BLOCK verdict — and for a known-malware record the
      # hint would contradict the audit's own "do not pin around it"
      # (review PR#55 F2). Operator review is the only next step.
      safe_gate_err "safe: BLOCKED ${ecosystem} install of ${package} — safe audit verdict BLOCK; operator review required: safe audit check ${package} --ecosystem ${ecosystem} --json; details: safe explain"
      safe_gate_audit_log "${ecosystem}" "${package}" "REFUSED_BLOCK"
      return 104
      ;;
    124|137)
      if safe_gate_known_matches "${package}" "${ecosystem}"; then
        safe_gate_err "safe install: safe audit timed out; proceeding on recorded clean check for ${package} (stale evidence)$(safe_gate_known_provenance "${package}" "${ecosystem}")"
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
      --tag|--registry|--@*:registry|--cache|--prefix|--userconfig|--globalconfig|--workspace|-w|--filter|--omit|--include|--install-strategy|--save-prefix|--mode|--cwd)
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
  # npm's boolean grammar allows `--global true|false` after the subcommand;
  # the shared extractor would misread the value as a package name and audit
  # a spurious package "true"/"false" (fail-closed friction). Consume the
  # pair here — npm only; pnpm/bun parse a following token as a package.
  local -a args=("$@") filtered=()
  local i
  for (( i=0; i<${#args[@]}; i++ )); do
    filtered+=("${args[$i]}")
    if [[ "${args[$i]}" == "-g" || "${args[$i]}" == "--global" ]] \
      && (( i + 1 < ${#args[@]} )) \
      && [[ "${args[$((i+1))]}" == "true" || "${args[$((i+1))]}" == "false" ]]; then
      i=$((i + 1))
    fi
  done
  safe_gate_npm_like_packages ${filtered[@]+"${filtered[@]}"}
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
      -c|--constraint|-i|--index-url|--index|--default-index|--extra-index-url|--find-links|--trusted-host|--platform|--python-version|--implementation|--abi|--target|--prefix|--src|--upgrade-strategy|--config-settings|-C|--python|-p)
        # -i/--index/--default-index take a value: dropping it made the URL
        # look like a package spec and fail-opened the extractor (PR#30
        # review finding 1 sibling). The selector itself is threaded to the
        # audit by safe_gate_scan_target_flags.
        # --python/-p (uv everywhere, pip >= 23): interpreter selector whose
        # value ("3.12") otherwise reads as a package positional and turns
        # the invocation into a false refusal for an unresolvable package.
        skip_next=1
        continue
        ;;
      --constraint=*|--index-url=*|--index=*|--default-index=*|--extra-index-url=*|--find-links=*|--trusted-host=*|--platform=*|--python-version=*|--implementation=*|--abi=*|--target=*|--prefix=*|--src=*|--upgrade-strategy=*|--config-settings=*|--python=*)
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
  # bun reads its own source config (BUN_CONFIG_REGISTRY, its npmrc chain)
  # for the same npm ecosystem; the audit models that only when told which
  # installer runs (delta-4 finding F4: selectors key off the installer).
  [[ "${tool}" == "bun" ]] && SAFE_GATE_INSTALLER="bun"
  local subcommand="${SAFE_GATE_SUBCMD}"
  # bun --config=<file> swaps in an arbitrary bunfig.toml — a TOML surface
  # the source derivation does not read, and install.registry there
  # redirects the fetch. Same class as cargo --config: per-invocation
  # config injection must not become a default-source verdict, so gated
  # subcommands fail closed. (The implicit ./bunfig.toml is host/project
  # state and stays under the documented boundary.)
  if [[ "${tool}" == "bun" ]]; then
    case "${subcommand}" in
      x|install|i|it|install-test|add|ci|update|u|up|upgrade|udpate)
        local bun_arg
        for bun_arg in "$@"; do
          [[ "${bun_arg}" == "--" ]] && break
          if [[ "${bun_arg}" == --config=* || "${bun_arg}" == -c=* ]]; then
            safe_gate_err "safe: BLOCKED bun ${subcommand} — --config swaps in a bunfig.toml whose install.registry can redirect the install source in ways safe cannot audit; use the project bunfig.toml or drop the flag, then retry; details: safe explain"
            return 100
          fi
        done
        ;;
    esac
  fi
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

  if [[ "${tool}" == "npm" ]]; then
    # Script-policy argv on a gated install could widen or replace the
    # operator's script policy (npm gives CLI config precedence over env):
    # refuse legibly. An explicit narrowing --ignore-scripts (bare, =true)
    # stays allowed; the widening forms (=false, separated false,
    # --no-ignore-scripts) are refused like the rest.
    local -a gate_args=("$@")
    local arg_i scripts_flag
    for (( arg_i=0; arg_i<${#gate_args[@]}; arg_i++ )); do
      scripts_flag="${gate_args[$arg_i]}"
      case "${scripts_flag}" in
        --allow-scripts|--allow-scripts=*|--no-allow-scripts|--no-allow-scripts=*|\
        --strict-allow-scripts|--strict-allow-scripts=*|--no-strict-allow-scripts|--no-strict-allow-scripts=*|\
        --dangerously-allow-all-scripts|--dangerously-allow-all-scripts=*|--no-dangerously-allow-all-scripts|--no-dangerously-allow-all-scripts=*|\
        --ignore-scripts=false|--no-ignore-scripts|--no-ignore-scripts=*)
          safe_gate_err "safe: BLOCKED npm ${subcommand} — ${scripts_flag%%=*} overrides the operator's script policy; install scripts run only via an operator grant (safe run scripts-allow add <pkg>@<x.y.z>); details: safe explain"
          return 100
          ;;
        --ignore-scripts)
          if (( arg_i + 1 < ${#gate_args[@]} )) && [[ "${gate_args[$((arg_i+1))]}" == "false" ]]; then
            safe_gate_err "safe: BLOCKED npm ${subcommand} — --ignore-scripts false overrides the operator's script policy; install scripts run only via an operator grant (safe run scripts-allow add <pkg>@<x.y.z>); details: safe explain"
            return 100
          fi
          ;;
      esac
    done
    # Inherited script-policy env survives into the delegate with
    # env-over-rc precedence: scrub it. The gate's own injection re-exports
    # after this.
    safe_gate_npm_scrub_script_env
  fi

  local global_requested=1
  if [[ "${tool}" == "npm" ]]; then
    safe_gate_npm_global_true "$@" && global_requested=0
  elif safe_gate_has_arg "-g" "$@" || safe_gate_has_arg "--global" "$@"; then
    global_requested=0
  fi

  if (( global_requested == 0 )); then
    safe_gate_collect raw "$("${parser}" "${rest[@]}")"
    packages=()
    for raw_package in "${raw[@]}"; do
      packages+=("$(safe_gate_npm_spec "${raw_package}")")
    done

    if (( ${#packages[@]} > 0 )); then
      safe_gate_check_many npm "${packages[@]}" || return $?
    fi

    if [[ "${tool}" == "npm" ]] && (( ${#packages[@]} > 0 )); then
      safe_gate_npm_scripts_env "${packages[@]}"
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

  # `--config KEY=VALUE` injects any cargo config key from the command line
  # — [source] replacement and registry.default included, which redirect the
  # install to a source the audit cannot see (cargo docs: --config takes
  # precedence over environment variables and config files). Those keys are
  # not env-settable, so this flag is the one argv route around the source
  # model: fail closed on installs rather than vouch for the wrong source.
  if safe_gate_has_arg "--config" "$@" || safe_gate_has_prefix_arg "--config=" "$@"; then
    safe_gate_err "safe: BLOCKED cargo install — --config can redirect the install source ([source] replacement, registry.default) in ways safe cannot audit; put persistent configuration in a config.toml and drop --config, then retry; details: safe explain"
    return 100
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

# ---------------------------------------------------------------------------
# mise: the runtime manager also installs BACKEND packages (npm:*, pipx:*,
# cargo:*, go:*) with lifecycle scripts — completely unaudited before this.
# Runtime installs (node@22, python@3.12) pass through: official runtimes,
# not registry packages. Non-registry backends (aqua/ubi/gem/asdf plugins)
# have no advisory source to audit against; they pass with a notice.
# ---------------------------------------------------------------------------

safe_gate_mise_backend_ecosystem() {
  case "$1" in
    npm) printf '%s' "npm" ;;
    pipx|pip) printf '%s' "python" ;;
    cargo) printf '%s' "rust" ;;
    go) printf '%s' "go" ;;
    *) return 1 ;;
  esac
}

safe_gate_mise_infra_refuse() {
  safe_gate_err "safe: BLOCKED mise — $1; this is safe/mise infrastructure breakage, not a package verdict — run safe doctor; details: safe explain"
  return 100
}

# mise tool options attach in brackets (npm:prettier[package_manager=npm]@3);
# the audited identity must be the canonical name, never name-plus-options.
# Only "@version" (or nothing) may follow the option group.
#
# Options are not decoration: mise passes some straight to the installer
# (npm_args, install_env, ...), so they can change the SOURCE the package
# comes from. Discarding them silently made a default-registry verdict
# vouch for a redirected install (delta-1 finding 2). Only an allowlist of
# identity-neutral keys keeps the audit; anything else takes the honest
# not-audit-gated notice path. Prints "canonical<TAB>opts-verdict" where the
# verdict is empty (neutral) or the first non-neutral key.
# `package_manager` is NOT neutral: it selects npm/pnpm/bun, whose native
# source inputs differ — a "neutral" classification audited npm's default
# source for a bun-selected install (delta-2 finding F1). The CONFIGURED
# npm.package_manager setting routes through the installer-aware audit; a
# per-spec bracket option still takes the notice path.
SAFE_GATE_MISE_NEUTRAL_OPTS='bin_path|exe|strip_components|platform|version_prefix|os|arch|depends'

safe_gate_mise_strip_opts() {
  local spec="$1" head tail opts offender="" kv key
  [[ "$spec" == *'['* ]] || { printf '%s\t\n' "$spec"; return 0; }
  head="${spec%%\[*}"
  tail="${spec#*\[}"
  [[ "$tail" == *']'* ]] || return 1
  opts="${tail%%\]*}"
  tail="${tail#*\]}"
  [[ -z "$tail" || "$tail" == @* ]] || return 1
  local old_ifs="$IFS"
  IFS=','
  for kv in $opts; do
    IFS="$old_ifs"
    [[ -n "$kv" ]] || continue
    key="${kv%%=*}"
    key="${key# }"
    key="${key% }"
    if ! safe_gate_alt_match "$key" "$SAFE_GATE_MISE_NEUTRAL_OPTS"; then
      offender="$key"
      break
    fi
    IFS=','
  done
  IFS="$old_ifs"
  printf '%s\t%s\n' "${head}${tail}" "$offender"
}

# Effective backend for a colonless shorthand: `mise registry <name>` prints
# the backend spec(s) mise would use — core:node for runtimes, npm:prettier
# for registry shorthands — and reflects MISE_BACKENDS_* overrides itself
# (verified live). The first listed backend is mise's default pick; a
# settings-driven reorder of multi-backend tools is a documented residual.
safe_gate_mise_resolve_bare() {
  local name="$1" mise_real out first
  mise_real="$(safe_gate_resolve_real mise)" || return 1
  # Under the SAME context as the delegate: a project's disable_backends
  # changes which backend mise picks, so a context-free query can classify a
  # registry package as a runtime (delta-1 finding 1).
  out="$("$mise_real" ${SAFE_GATE_MISE_CTX[@]+"${SAFE_GATE_MISE_CTX[@]}"} registry -- "$name" 2>/dev/null)" || return 1
  first="${out%%[[:space:]]*}"
  [[ -n "$first" && "$first" == *:* ]] || return 1
  printf '%s\n' "$first"
}

# Source-relevant vars from mise's computed environment (project [env] can
# set NPM_CONFIG_REGISTRY, PIP_INDEX_URL, ...). The audit must see the same
# sources mise will install under, or a clean default-registry verdict
# vouches for a different artifact.
#
# Framing is base64 per value, one "NAME<space>b64" record per line: a raw
# key=value stream let a single value containing a newline split into two
# exported variables and inject a source the original never named (delta-1
# finding N2). A relevant key whose value is not a string is malformed
# helper output, not "absent": the whole derivation fails so the caller
# refuses instead of auditing a default source.
safe_gate_mise_env_overlay() {
  local mise_real json
  mise_real="$(safe_gate_resolve_real mise)" || return 1
  command -v jq >/dev/null 2>&1 || return 1
  command -v base64 >/dev/null 2>&1 || return 1
  json="$("$mise_real" "$@" env --json 2>/dev/null)" || return 1
  printf '%s' "$json" | jq -r '
    def relevant:
      # npm parses npm_config_* env keys case-insensitively: the collector
      # must too, or a mixed-case [env] key (a valid identifier mise will
      # export) slips past the script-policy refusal while npm honors it
      # (PR#52 delta-3 finding F3).
      (test("^npm_config_"; "i"))
      or IN("PIP_INDEX_URL","PIP_EXTRA_INDEX_URL","PIP_FIND_LINKS",
            "PIP_NO_INDEX","PIP_CONFIG_FILE","UV_INDEX_URL",
            "UV_DEFAULT_INDEX","UV_INDEX","UV_EXTRA_INDEX_URL",
            "UV_FIND_LINKS","UV_NO_INDEX","GOPROXY","GOPRIVATE",
            "GONOSUMDB","GONOSUMCHECK","GOFLAGS","GONOSUMVERIFY",
            "CARGO_REGISTRY_DEFAULT","CARGO_REGISTRIES_CRATES_IO_PROTOCOL",
            "CARGO_HOME","COMPOSER_HOME","COMPOSER_AUTH",
            "MISE_PIPX_REGISTRY_URL",
            "MISE_CARGO_REGISTRY_NAME","MISE_GO_PROXY",
            "BUN_CONFIG_REGISTRY","XDG_CONFIG_HOME",
            "MISE_NPM_PACKAGE_MANAGER")
      or (test("^CARGO_REGISTRIES_[A-Za-z0-9_]+$"));
    if type != "object" then error("schema") else . end
    | to_entries
    | map(select(.key | relevant))
    | map(
        if (.value | type) != "string" then error("schema")
        elif (.key | test("^[A-Za-z_][A-Za-z0-9_]*$") | not) then error("schema")
        # A NUL cannot exist in an environment value: reject it HERE, before
        # decoded bytes reach a command substitution, so bash never prints
        # its own "ignored null byte" warning alongside the one-line
        # refusal (delta-3 finding F2). NOTE: this jq program is a
        # single-quoted bash string — no apostrophes in these comments.
        elif (.value | contains("\u0000")) then error("schema")
        else .key + " " + (.value | @base64) end
      )
    | .[]
  ' 2>/dev/null || return 1
}

# Export one overlay record set into the current (sub)shell. Any decode or
# export failure is fatal: a partially applied source environment is the
# wrong-source class all over again.
safe_gate_mise_apply_overlay() {
  local overlay="$1" name b64 value
  [[ -n "$overlay" ]] || return 0
  while IFS=' ' read -r name b64; do
    [[ -n "$name" ]] || continue
    # Command substitution strips EVERY trailing newline, so a value ending
    # in LF reached the audit truncated and could name a different config
    # file than mise loads (delta-2 finding F2). A sentinel byte outside the
    # payload survives the strip; it is removed after capture. A NUL cannot
    # exist in an environment value at all: that is malformed, not empty.
    value="$(printf '%s' "$b64" | base64 -d 2>/dev/null; printf 'x')" || return 1
    value="${value%x}"
    # Byte-for-byte, in BYTES on both sides: ${#value} counts CHARACTERS in
    # the caller's locale, so a valid UTF-8 path like /tmp/café.conf was
    # rejected as malformed (delta-3 finding F2). A local LC_ALL makes the
    # parameter expansion count bytes too. (NUL is rejected earlier, in the
    # jq producer, so bash never has to warn about it here.)
    local decoded_len
    decoded_len="$(printf '%s' "$b64" | base64 -d 2>/dev/null | LC_ALL=C wc -c)" || return 1
    local LC_ALL=C
    (( decoded_len == ${#value} )) || return 1
    export "${name}=${value}" 2>/dev/null || return 1
  done <<<"$overlay"
  return 0
}

# Effective-value reader for one selector variable. Historically the
# derivation covered npm/Python/Go only and every other selector took the
# not-audit-gated notice path (delta-2 finding F4); it now models cargo,
# composer and bun sources too, and the notice survives only for CARGO_HOME
# (an unread config.toml). The union rule still matters: the delegate's
# environment is what mise computes AND what it inherits — mise env --json
# omits inherited variables, so an ambient CARGO_REGISTRY_DEFAULT reached
# the installer while a pure-overlay detector saw nothing (delta-3 finding
# F4).
# Effective value of one variable: the mise overlay wins over the ambient
# environment (that is the precedence the delegate sees). Empty counts as
# unset — an exported but empty selector chooses nothing, and treating it
# as a source suppressed audits safe could have done (delta-4 finding F4).
safe_gate_mise_env_value() {
  local want="$1" overlay="$2" name b64
  if [[ -n "$overlay" ]]; then
    while IFS=' ' read -r name b64; do
      if [[ "$name" == "$want" ]]; then
        printf '%s' "$b64" | base64 -d 2>/dev/null
        return 0
      fi
    done <<<"$overlay"
  fi
  printf '%s' "${!want:-}"
}

# Selector variables that point an install at a source safe-audit cannot
# resolve advisories against — keyed by the INSTALLER that actually reads
# them, not by a coarse ecosystem: bun's variable does not affect an npm
# install, and pipx's does not affect pip, so applying them by ecosystem
# removed the gate from artifacts safe can model (delta-4 finding F4).
# Since the source derivation learned cargo/composer/bun env selectors and
# the gate translates the mise-only ones (registry_name, pipx registry_url)
# into audit argv, the only survivor is CARGO_HOME: it points cargo at a
# config.toml safe does not read — [source] replacement included — which no
# env sweep can represent. (COMPOSER_AUTH carried credentials, not a
# source, and COMPOSER_REPOSITORIES does not exist in composer at all;
# both were over-refusals.)
safe_gate_mise_unmodeled_source() {
  local installer="$1" overlay="$2" value
  case "$installer" in
    cargo)
      value="$(safe_gate_mise_env_value CARGO_HOME "$overlay")"
      if [[ -n "$value" ]]; then
        printf '%s' "CARGO_HOME"
        return 0
      fi
      ;;
  esac
  return 1
}

# Mirror of mise's pipx get_index_url() (src/backend/pipx.rs): the raw
# pipx.registry_url setting is a {}-templated LISTING url, but the
# installer receives the normalized PEP-503 /simple endpoint via
# PIP_INDEX_URL (pipx) / UV_INDEX (uvx) — that endpoint is the source
# identity the audit must judge. Normalization: strip {} and trailing
# slashes; pypi.org URLs collapse /pypi/<x>/json|simple tails (or anything
# before a /simple segment) to <base>/simple; other hosts replace every
# /json segment with /simple when the URL ends in /json, else append
# /simple.
safe_gate_pipx_index_url() {
  local url="${1//\{\}/}"
  while [[ "$url" == */ ]]; do url="${url%/}"; done
  if [[ "$url" == *pypi.org* ]]; then
    if [[ "$url" == */pypi/* ]]; then
      if [[ "$url" =~ ^(.*)/pypi/[^/]*/(json|simple)$ ]]; then
        url="${BASH_REMATCH[1]}/simple"
      fi
    elif [[ "$url" != */simple ]]; then
      url="${url%%/simple*}"
      while [[ "$url" == */ ]]; do url="${url%/}"; done
      url="${url}/simple"
    fi
  else
    if [[ "$url" == */json ]]; then
      url="${url//\/json//simple}"
    elif [[ "$url" != */simple ]]; then
      url="${url}/simple"
    fi
  fi
  printf '%s' "$url"
}

# Which installer actually performs an npm-backend install: mise's
# package-manager setting selects npm/pnpm/bun, and only bun reads
# BUN_CONFIG_REGISTRY.
# Environment/overlay first, then mise's own setting: `mise env --json`
# does not export npm.package_manager, so a configured `bun` was invisible
# and safe audited npm's source for a bun install (delta-5 finding F4).
# An unreadable or unrecognized value fails closed. "auto" resolves per
# directory (lockfile-driven), which is part of the documented
# directory-config residual.
# ONE strict validator for both inputs: an unvalidated environment value
# was passed through verbatim, so an invalid selector became a package
# verdict instead of an infrastructure refusal (delta-6 finding F4). The
# accepted set is the pinned mise contract (2026.7.16, verified live:
# `aube`/`aube_cli` are accepted, `yarn` is rejected by mise itself).
# bun reads its own source surface (BUN_CONFIG_REGISTRY, its npmrc chain),
# which the audit models when passed --installer bun; the others read
# npm-compatible sources and audit normally.
safe_gate_mise_valid_npm_installer() {
  case "$1" in
    auto|npm|aube|aube_cli) printf 'npm'; return 0 ;;
    pnpm) printf 'pnpm'; return 0 ;;
    bun) printf 'bun'; return 0 ;;
    *) return 2 ;;
  esac
}

safe_gate_mise_npm_installer() {
  local overlay="$1" pm mise_real out
  pm="$(safe_gate_mise_env_value MISE_NPM_PACKAGE_MANAGER "$overlay")"
  if [[ -n "$pm" ]]; then
    safe_gate_mise_valid_npm_installer "$pm"
    return $?
  fi
  mise_real="$(safe_gate_resolve_real mise)" || return 2
  out="$("$mise_real" ${SAFE_GATE_MISE_CTX[@]+"${SAFE_GATE_MISE_CTX[@]}"} settings get npm.package_manager 2>/dev/null)" || return 2
  # No first-line truncation: command substitution already strips trailing
  # newlines, so truncating here only turned malformed multi-line output
  # into an apparently valid scalar (delta-7 finding F4).
  safe_gate_mise_valid_npm_installer "$out"
  return $?
}

# Installer behind a mise BACKEND spec (npm:/pipx:/cargo:/go:).
safe_gate_mise_backend_installer() {
  local backend="$1" overlay="$2"
  case "$backend" in
    npm) safe_gate_mise_npm_installer "$overlay" ;;
    pipx|pip) printf 'pipx' ;;
    cargo) printf 'cargo' ;;
    *) return 1 ;;
  esac
}

# One validated snapshot of every configured row, shared by enumeration,
# selection and attribution so they cannot disagree with one another
# (delta-5 finding F1). Cached per invocation; returns 2 on failure.
# One validated snapshot of every configured row, shared by enumeration,
# selection and attribution so they cannot disagree. Loaded in the CURRENT
# shell: a `$(...)` capture ran the assignments in a subshell, so the cache
# never survived and every reader re-queried mise (delta-6 finding F1).
# Returns 2 on failure; the rows live in SAFE_GATE_MISE_ROWS.
safe_gate_mise_load_rows() {
  (( ${SAFE_GATE_MISE_ROWS_LOADED:-0} )) && return 0
  local rows
  rows="$(safe_gate_mise_config_entries ${SAFE_GATE_MISE_CTX[@]+"${SAFE_GATE_MISE_CTX[@]}"})" || return 2
  SAFE_GATE_MISE_ROWS="$rows"
  SAFE_GATE_MISE_ROWS_LOADED=1
  return 0
}

# Rows an operation could fetch, selected from that same snapshot rather
# than a second `mise ls`: 0 = not installed; 1 = also installed entries
# whose request is not an exact pin (mise can move "3", ranges, tags on
# `up`); 2 = every row (`up --bump`, `install --force`).
safe_gate_mise_select_rows() {
  local mode="$1" key req inst
  while IFS=$'\t' read -r key req inst; do
    [[ -n "$key" ]] || continue
    if (( mode == 2 )) || [[ "$inst" != "1" ]]; then
      printf '%s\t%s\n' "$key" "$req"
      continue
    fi
    if (( mode == 1 )) && [[ ! "$req" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$ ]]; then
      printf '%s\t%s\n' "$key" "$req"
    fi
  done <<<"$SAFE_GATE_MISE_ROWS"
  return 0
}

# How many configured requests a key has. `mise tool --json` reports ONE
# option set per key, so more than one request means its options cannot be
# attributed to the target being installed.
safe_gate_mise_key_multiplicity() {
  local want="$1" key count=0
  safe_gate_mise_load_rows || return 2
  while IFS=$'\t' read -r key _; do
    [[ "$key" == "$want" ]] && count=$((count + 1))
  done <<<"$SAFE_GATE_MISE_ROWS"
  printf '%s' "$count"
  return 0
}

# Canonical backend key of a spec: options stripped, version dropped, bare
# shorthand resolved. Exclusions and targets must be compared as keys, not
# as the strings the user happened to type (delta-5 finding F3).
safe_gate_mise_canon_key() {
  local spec="$1" parsed stripped name
  parsed="$(safe_gate_mise_strip_opts "$spec")" || return 1
  IFS=$'\t' read -r stripped _ <<<"$parsed"
  name="$(safe_gate_mise_spec_name "$stripped")"
  if [[ "$name" != *:* ]]; then
    name="$(safe_gate_mise_resolve_bare "$name")" || return 1
  fi
  printf '%s' "$name"
  return 0
}

# Ecosystem a gated inner `mise exec -- <tool>` command installs for, so
# the same unmodeled-source honesty applies there (delta-3 finding F4: the
# Composer and bun routes reached a package verdict through inner exec).
safe_gate_mise_tool_installer() {
  case "$1" in
    bun) printf 'bun' ;;
    cargo) printf 'cargo' ;;
    composer) printf 'composer' ;;
    # npm/pnpm/yarn, pip/pip3/uv and go read sources safe-audit models.
    *) return 1 ;;
  esac
}

# Run one audit under mise's computed source environment AND its effective
# directory: -C changes which npmrc / Cargo config / pip config the audit's
# own source derivation reads, so the audit process must stand where the
# install will happen (delta-1 finding 8).
safe_gate_mise_check_with_env() {
  local overlay="$1" pkg="$2" eco="$3" installer="${4:-}" unmodeled
  if [[ -n "$installer" ]] && unmodeled="$(safe_gate_mise_unmodeled_source "$installer" "$overlay")"; then
    safe_gate_err "safe: mise ${pkg}: ${unmodeled} selects a ${installer} source safe cannot resolve advisories against — not audit-gated; review manually, or install from the default source to get a checked verdict"
    return 0
  fi
  (
    if [[ -n "${SAFE_GATE_MISE_CD:-}" ]]; then
      cd -- "${SAFE_GATE_MISE_CD}" 2>/dev/null || {
        safe_gate_mise_infra_refuse "cannot enter the -C directory '${SAFE_GATE_MISE_CD}' to audit from the same place mise installs"
        exit 100
      }
    fi
    safe_gate_mise_apply_overlay "$overlay" || {
      safe_gate_mise_infra_refuse "cannot apply the mise environment (malformed value transport)"
      exit 100
    }
    # mise-only selectors reach the installer as cargo argv / pip env the
    # audit process will not see — translate them into the audit's own argv
    # selector so they floor and degrade like any other custom source.
    # Real installer env (BUN_CONFIG_REGISTRY, CARGO_REGISTRY_DEFAULT,
    # COMPOSER_HOME, ...) needs no translation: the overlay is applied and
    # safe-audit's derivation reads it directly.
    case "$installer" in
      bun) SAFE_GATE_INSTALLER="bun" ;;
      cargo)
        SAFE_GATE_INSTALLER="cargo"
        [[ -n "${MISE_CARGO_REGISTRY_NAME:-}" ]] && SAFE_GATE_REGISTRY="${MISE_CARGO_REGISTRY_NAME}"
        ;;
      pipx)
        SAFE_GATE_INSTALLER="pipx"
        [[ -n "${MISE_PIPX_REGISTRY_URL:-}" ]] && SAFE_GATE_REGISTRY="$(safe_gate_pipx_index_url "${MISE_PIPX_REGISTRY_URL}")"
        ;;
    esac
    safe_gate_check "$pkg" "$eco"
  )
}

# Audit one explicit tool spec (argv or config-derived). The audited identity
# is canonicalized first: tool options stripped, bare shorthands resolved to
# their effective backend, and source-bearing forms (git+/URL, pipx GitHub
# shorthand owner/repo, non-registry name shapes) take the notice path — a
# public-registry audit must never vouch for code fetched elsewhere.
safe_gate_mise_check_spec() {
  local spec="$1" overlay="${2:-}" skip_config_opts="${3:-0}"
  local stripped opt_offender backend rest name version="" eco pkg
  local parsed
  if ! parsed="$(safe_gate_mise_strip_opts "$spec")"; then
    safe_gate_err "safe: BLOCKED mise — malformed tool options in '${spec}'; details: safe explain"
    return 100
  fi
  IFS=$'\t' read -r stripped opt_offender <<<"$parsed"
  if [[ -n "$opt_offender" ]]; then
    safe_gate_err "safe: mise ${spec}: tool option '${opt_offender}' can change the install source or run installer arguments safe cannot model — not audit-gated; review manually, or install without the option to get a checked verdict"
    return 0
  fi
  if [[ "$stripped" != *:* ]]; then
    local bare_name="$stripped" bare_ver=""
    if [[ "$stripped" == *@* ]]; then
      bare_name="${stripped%%@*}"
      bare_ver="${stripped#*@}"
    fi
    if [[ -z "$bare_name" ]]; then
      safe_gate_err "safe: BLOCKED mise — malformed tool spec '${spec}'; details: safe explain"
      return 100
    fi
    local eff
    if ! eff="$(safe_gate_mise_resolve_bare "$bare_name")"; then
      safe_gate_mise_infra_refuse "cannot resolve '${bare_name}' to its backend (mise registry unavailable or unknown tool); use an explicit backend spec (npm:${bare_name})"
      return 100
    fi
    stripped="$eff"
    [[ -n "$bare_ver" ]] && stripped="${eff}@${bare_ver}"
  fi
  backend="${stripped%%:*}"
  rest="${stripped#*:}"
  if [[ -z "$backend" || -z "$rest" ]]; then
    safe_gate_err "safe: BLOCKED mise — malformed tool spec '${spec}'; details: safe explain"
    return 100
  fi
  # Official runtimes (core:node) are not registry packages.
  [[ "$backend" == "core" ]] && return 0
  if ! eco="$(safe_gate_mise_backend_ecosystem "$backend")"; then
    safe_gate_err "safe: mise ${spec}: '${backend}' backend has no registry advisory source; not audit-gated — review manually if untrusted"
    return 0
  fi
  # Source-bearing variants inside registry backends: pipx owner/repo is a
  # GitHub shorthand, git+/URL forms fetch arbitrary sources, and a slashed
  # npm (unscoped) or cargo name is not a registry identity. Go module paths
  # are the registry identity, so go keeps its slashes.
  if [[ "$rest" == git+* || "$rest" == *://* ]] \
     || { [[ "$backend" == pipx || "$backend" == pip || "$backend" == cargo ]] && [[ "$rest" == */* ]]; } \
     || { [[ "$backend" == npm && "$rest" == */* && "$rest" != @* ]]; }; then
    safe_gate_err "safe: mise ${spec}: fetches from a source location, not the ${eco} registry — no advisory source; not audit-gated — review manually if untrusted"
    return 0
  fi
  if [[ "$rest" == @*/*@* ]]; then
    name="${rest%@*}"
    version="${rest##*@}"
  elif [[ "$rest" == *@* && "$rest" != @* ]]; then
    name="${rest%@*}"
    version="${rest##*@}"
  else
    name="$rest"
  fi
  # An explicit CLI target INHERITS the configured tool options for its key
  # — mise applies them — so the same attribution check the preflight does
  # must run here too (delta-4 finding F1). The collector already asked for
  # its own entries, so it passes skip_config_opts=1.
  if (( skip_config_opts == 0 )); then
    local ckey coffender corc cmult cmrc
    ckey="${backend}:${name}"
    # Several configured requests share one reported option set, so the
    # options cannot be attributed to THIS target (delta-5 finding F1).
    # Zero rows is a new install and stays auditable.
    # Load in the CURRENT shell first: the capture below would otherwise
    # run the loader in a subshell and lose the snapshot, so every target
    # of a multi-target command re-queried mise and could see a different
    # configuration (delta-7 finding F1).
    if ! safe_gate_mise_load_rows; then
      safe_gate_mise_infra_refuse "cannot enumerate configured tools to attribute the options of '${ckey}' (mise ls or jq unavailable, or malformed output)"
      return 100
    fi
    cmult="$(safe_gate_mise_key_multiplicity "$ckey")"
    cmrc=$?
    if (( cmrc != 0 )); then
      safe_gate_mise_infra_refuse "cannot enumerate configured tools to attribute the options of '${ckey}' (mise ls or jq unavailable, or malformed output)"
      return 100
    fi
    if (( cmult > 1 )); then
      safe_gate_err "safe: mise ${spec}: several configured versions share this tool and mise reports one option set for all of them — safe cannot tell which install carries which source; not audit-gated, review manually"
      return 0
    fi
    coffender="$(safe_gate_mise_entry_option_offender "$ckey")"
    corc=$?
    if (( corc != 0 )); then
      safe_gate_mise_infra_refuse "cannot read the configured tool options for '${ckey}' (mise tool --json failed or returned no tool_options) — the install would proceed without knowing its source"
      return 100
    fi
    if [[ -n "$coffender" ]]; then
      safe_gate_err "safe: mise ${spec}: configured tool option '${coffender}' can change the install source or run installer arguments safe cannot model — not audit-gated; review manually"
      return 0
    fi
  fi
  pkg="$name"
  # "latest" is the unpinned marker, not a version: audit the bare name and
  # let safe-audit resolve the real target (never audit a literal @latest).
  [[ -n "$version" && "$version" != "latest" ]] && pkg="${name}@${version}"
  # rc 1 = this backend has no installer-specific source surface (go);
  # rc 2 = the installer could NOT be determined, which must fail closed
  # rather than silently audit the default source (delta-5 finding F4).
  local installer="" irc
  installer="$(safe_gate_mise_backend_installer "$backend" "$overlay")"
  irc=$?
  if (( irc == 2 )); then
    safe_gate_mise_infra_refuse "cannot determine which installer mise will use for '${spec}' (npm.package_manager unreadable or unrecognized)"
    return 100
  fi
  (( irc != 0 )) && installer=""
  safe_gate_mise_check_with_env "$overlay" "$pkg" "$eco" "$installer"
}

# Configured entries a bare `mise install`/`mise up` could fetch, as
# "key<TAB>requested_version" lines. Modes: 0 = not-installed entries only;
# 1 = also installed entries whose requested version is not an exact pin
# (mise can move "3", "3.1", "latest", ranges on `up`); 2 = every entry
# (`up --bump` and `install --force` reach even exact pins); 3 = every row
# with no operation filter, used to count how many configured requests a
# key has BEFORE mode selection hides some of them (delta-4 finding F1:
# one installed + one missing row for a key looked unique after mode 0
# filtering, while `mise tool --json` still reported only the first row's
# options). Fail-closed contract: ANY
# producer/schema failure returns 2 and the caller refuses — only a
# validated (possibly empty) enumeration returns 0.
safe_gate_mise_config_entries() {
  local mise_real json out
  mise_real="$(safe_gate_resolve_real mise)" || return 2
  command -v jq >/dev/null 2>&1 || return 2
  json="$("$mise_real" "$@" ls --current --json 2>/dev/null)" || return 2
  # Every field selection depends on must be PRESENT and correctly typed:
  # defaulting a missing `installed` to false silently reclassified a
  # malformed entry as installable and reported a package verdict for it
  # (delta-1 finding 3). jq diagnostics stay internal so a refusal is still
  # exactly one line.
  out="$(printf '%s' "$json" | jq -r '
    if type != "object" then error("schema") else . end
    | to_entries[]
    | (.key | if (type == "string" and length > 0) then . else error("schema") end) as $k
    | (.value | if type != "array" then error("schema") else . end)[]
    | if type != "object" then error("schema") else . end
    | (if has("installed") then .installed else error("schema") end
       | if type != "boolean" then error("schema") else . end) as $inst
    | (if has("requested_version") then .requested_version else error("schema") end
       | if type != "string" then error("schema") else . end) as $req
    | $k + "\t" + $req + "\t" + (if $inst then "1" else "0" end)
  ' 2>/dev/null)" || return 2
  printf '%s\n' "$out"
}

# --- subcommand argv model (exact tables from `mise <sub> --help`, 2026.7) ---
# Unknown flags fail closed; scope-changing flags we cannot faithfully model
# refuse with a hint. Parsed results land in the SAFE_GATE_MISE_* globals
# (namerefs bit us before; see the nameref-shadowing note above).

SAFE_GATE_MISE_SPECS=()
SAFE_GATE_MISE_CMD=()
SAFE_GATE_MISE_CTX=()
SAFE_GATE_MISE_EXCLUDE=()
SAFE_GATE_MISE_MODE=0
SAFE_GATE_MISE_SAW_REMOVE=0
SAFE_GATE_MISE_OVERLAY=""
SAFE_GATE_MISE_CD=""
SAFE_GATE_MISE_ROWS=""
SAFE_GATE_MISE_ROWS_LOADED=0

# One place where a recognized value flag's SEMANTICS are recorded. Being in
# the table only means safe can parse it; a flag that changes the target set
# or the resolved version must also change what safe audits, or safe audits
# one thing while mise installs another (delta-1 findings 4/N1).
safe_gate_mise_record_ctx() {
  local sub="$1" flag="$2" value="$3"
  case "$flag" in
    -C|--cd)
      SAFE_GATE_MISE_CTX+=(-C "$value")
      SAFE_GATE_MISE_CD="$value"
      ;;
    -E|--env)
      SAFE_GATE_MISE_CTX+=(-E "$value")
      ;;
    -e)
      # `use -e` is the config-environment selector, same as top-level -E.
      [[ "$sub" == "use" ]] && SAFE_GATE_MISE_CTX+=(-E "$value")
      ;;
    -x|--exclude)
      # mise will NOT touch these: auditing them blocks an install that is
      # not happening.
      SAFE_GATE_MISE_EXCLUDE+=("$value")
      ;;
    --minimum-release-age)
      # mise deliberately selects an OLDER release than the newest matching
      # one; safe's resolver has no such notion, so for anything but an
      # exact pin it would audit a version mise will not install.
      SAFE_GATE_MISE_MIN_AGE=1
      ;;
  esac
  return 0
}

safe_gate_mise_parse_sub() {
  local sub="$1"
  shift
  SAFE_GATE_MISE_SPECS=()
  SAFE_GATE_MISE_CMD=()
  SAFE_GATE_MISE_EXCLUDE=()
  SAFE_GATE_MISE_MODE=0
  SAFE_GATE_MISE_SAW_REMOVE=0
  SAFE_GATE_MISE_MIN_AGE=0
  SAFE_GATE_MISE_BUMP=0

  local gval gbool grefuse="" grefuse_interactive=""
  case "$sub" in
    install)
      gval='-j|--jobs|--minimum-release-age|--shared|-C|--cd|-E|--env'
      gbool='-f|--force|-n|--dry-run|-v|--verbose|-vv|--dry-run-code|--raw|--system|-q|--quiet|-y|--yes|--locked|--silent|-h|--help'
      grefuse='--monorepo'
      ;;
    upgrade)
      gval='-j|--jobs|-x|--exclude|--minimum-release-age|-C|--cd|-E|--env'
      gbool='-n|--dry-run|--dry-run-code|--raw|-q|--quiet|-v|--verbose|-vv|-y|--yes|--locked|--silent|-h|--help'
      # --interactive opens a multiselect: auditing every candidate blocks
      # the picker over a tool the user may not pick, and letting it open
      # installs a choice safe never saw. Same class as bare `mise use`
      # (operator-ratified): decline with the explicit-target rewrite.
      grefuse_interactive='-i|--interactive'
      grefuse='--monorepo|--inactive|--local'
      SAFE_GATE_MISE_MODE=1
      ;;
    use)
      gval='-e|--env|-j|--jobs|-p|--path|--remove|--minimum-release-age|-C|--cd'
      gbool='-f|--force|-g|--global|-n|--dry-run|--dry-run-code|--fuzzy|--pin|--raw|-q|--quiet|-v|--verbose|-vv|-y|--yes|--locked|--silent|-h|--help'
      ;;
    exec)
      gval='-j|--jobs|--allow-env|--allow-net|--allow-read|--allow-write|-C|--cd|-E|--env'
      gbool='--deny-all|--deny-env|--deny-net|--deny-read|--deny-write|--fresh-env|--no-deps|--raw|-q|--quiet|-v|--verbose|-vv|-y|--yes|--locked|--silent|-h|--help'
      ;;
    *) return 0 ;;
  esac

  local -a args=("$@")
  local i=0 arg base
  while (( i < ${#args[@]} )); do
    arg="${args[$i]}"
    if [[ "$sub" == "exec" && "$arg" == "--" ]]; then
      SAFE_GATE_MISE_CMD=("${args[@]:$((i + 1))}")
      break
    fi
    case "$arg" in
      -c|--command|-c=*|--command=*)
        if [[ "$sub" == "exec" ]]; then
          safe_gate_err "safe: BLOCKED mise exec — '-c' hides the command in a shell string that cannot be audited; rerun as: mise exec -- <command> [args...]; details: safe explain"
          return 100
        fi
        safe_gate_err "safe: BLOCKED mise ${sub} — unrecognized flag '${arg}'; details: safe explain"
        return 100
        ;;
      -*)
        base="${arg%%=*}"
        if [[ -n "$grefuse_interactive" ]] && safe_gate_alt_match "$base" "$grefuse_interactive"; then
          safe_gate_err "safe: BLOCKED mise ${sub} — interactive selection cannot be audited; rerun naming each tool with an exact version, e.g. mise ${sub} <tool>@<version>; details: safe explain"
          return 100
        fi
        if [[ -n "$grefuse" ]] && safe_gate_alt_match "$base" "$grefuse"; then
          safe_gate_err "safe: BLOCKED mise ${sub} — '${base}' changes which configuration is enumerated and cannot be audited faithfully; rerun without it (per-directory -C/--cd is supported); details: safe explain"
          return 100
        fi
        if [[ "$sub" == "upgrade" ]] && { [[ "$arg" == "-l" || "$arg" == "--bump" ]]; }; then
          # --bump can move even an exact configured pin: audit everything,
          # and audit it at the target mise will pick (latest), not the old
          # request.
          SAFE_GATE_MISE_MODE=2
          SAFE_GATE_MISE_BUMP=1
          i=$((i + 1))
          continue
        fi
        # --force reinstalls entries mise already reports as installed, so
        # the not-installed-only enumeration audits nothing while every
        # configured package (lifecycle scripts included) is refetched
        # (delta-1 finding N1).
        if [[ "$sub" == "install" ]] && { [[ "$arg" == "-f" || "$arg" == "--force" ]]; }; then
          SAFE_GATE_MISE_MODE=2
          i=$((i + 1))
          continue
        fi
        [[ "$arg" == "--remove" || "$arg" == --remove=* ]] && SAFE_GATE_MISE_SAW_REMOVE=1
        # Counted verbosity: clap accepts -v, -vv, -vvv, ... Refusing -vvv
        # was an avoidable usability regression (delta-1 finding 10).
        if [[ "$arg" =~ ^-v+$ ]]; then
          i=$((i + 1))
          continue
        fi
        if [[ "$arg" == *=* ]]; then
          if safe_gate_alt_match "$base" "$gval"; then
            safe_gate_mise_record_ctx "$sub" "$base" "${arg#*=}" || return $?
            i=$((i + 1))
            continue
          fi
          safe_gate_err "safe: BLOCKED mise ${sub} — unrecognized flag '${base}'; details: safe explain"
          return 100
        fi
        if safe_gate_alt_match "$arg" "$gval"; then
          if (( i + 1 >= ${#args[@]} )); then
            safe_gate_err "safe: BLOCKED mise ${sub} — flag '${arg}' is missing its value; details: safe explain"
            return 100
          fi
          safe_gate_mise_record_ctx "$sub" "$arg" "${args[$((i + 1))]}" || return $?
          i=$((i + 2))
          continue
        fi
        if safe_gate_alt_match "$arg" "$gbool"; then
          i=$((i + 1))
          continue
        fi
        safe_gate_err "safe: BLOCKED mise ${sub} — unrecognized flag '${arg}' (rewrite a value flag as --flag=value if safe lags mise); details: safe explain"
        return 100
        ;;
      *)
        SAFE_GATE_MISE_SPECS+=("$arg")
        i=$((i + 1))
        continue
        ;;
    esac
  done
  return 0
}

# Derive the env overlay once per invocation, only when something will be
# audited (mise env is a subprocess; passthroughs stay cheap). Refusing on
# failure is deliberate: an audit that cannot see the effective sources
# would vouch for the wrong artifact.

# Drop excluded targets from an enumerated set (name-of-array argument;
# bash 4.3+ nameref, matching the rest of this file's helpers).
# Name half of a spec, backend-aware: an npm scope starts with '@', so a
# blind ${spec%@*} reduced every unversioned scoped name to "npm:" and made
# unrelated tools compare equal (delta-2 finding F3).
safe_gate_mise_spec_name() {
  # Separate statements on purpose: bash expands every RHS of a single
  # `local` before the new locals exist, so `local spec="$1" rest="$spec"`
  # gave `rest` the value of an OUTER `spec` — which, called for an
  # exclusion from inside the target loop, rewrote the exclusion as the
  # current target and dropped it from the audit set (delta-6 finding F3).
  local spec="$1"
  local backend=""
  local rest="$spec"
  if [[ "$spec" == *:* ]]; then
    backend="${spec%%:*}:"
    rest="${spec#*:}"
  fi
  if [[ "$rest" == @*/*@* ]]; then
    rest="${rest%@*}"
  elif [[ "$rest" == *@* && "$rest" != @* ]]; then
    rest="${rest%@*}"
  fi
  printf '%s%s' "$backend" "$rest"
}

safe_gate_mise_filter_excluded() {
  local -n _specs="$1"
  (( ${#SAFE_GATE_MISE_EXCLUDE[@]} == 0 )) && return 0
  local -a kept=()
  local spec ex ex_name spec_name
  for spec in ${_specs[@]+"${_specs[@]}"}; do
    # Compare canonical KEYS: `mise upgrade blockme --exclude npm:blockme`
    # names one tool in two spellings, and mise excludes it (delta-5 F3).
    # No fallback on canonicalization failure: manufacturing a name here
    # once matched an unrelated exclusion and silently dropped a real
    # target (delta-6 finding F3). A resolution failure is infrastructure
    # breakage, and the caller refuses.
    spec_name="$(safe_gate_mise_canon_key "$spec")" || {
      safe_gate_mise_infra_refuse "cannot resolve '${spec}' to its backend to compare it against --exclude (mise registry unavailable or unknown tool)"
      return 100
    }
    local skip=0
    for ex in "${SAFE_GATE_MISE_EXCLUDE[@]}"; do
      ex_name="$(safe_gate_mise_canon_key "$ex")" || {
        safe_gate_mise_infra_refuse "cannot resolve the --exclude target '${ex}' to its backend (mise registry unavailable or unknown tool); name it as <backend>:<tool>"
        return 100
      }
      [[ "$spec_name" == "$ex_name" || "$spec" == "$ex" ]] && { skip=1; break; }
    done
    (( skip )) || kept+=("$spec")
  done
  _specs=(${kept[@]+"${kept[@]}"})
  return 0
}

# Configured tool options are invisible in `mise ls` output, so a bare
# install of a tool carrying npm_args/install_env would be audited as if it
# came from the default source (delta-2 finding F1). `mise tool --json`
# does expose them: any non-neutral option set on an enumerated entry sends
# that entry to the notice path. A failed query fails closed.
safe_gate_mise_entry_option_offender() {
  local key="$1" mise_real json
  mise_real="$(safe_gate_resolve_real mise)" || return 2
  command -v jq >/dev/null 2>&1 || return 2
  json="$("$mise_real" ${SAFE_GATE_MISE_CTX[@]+"${SAFE_GATE_MISE_CTX[@]}"} tool --json -- "$key" 2>/dev/null)" || return 2
  # tool_options must be PRESENT: defaulting a missing field to {} read
  # malformed helper output as "no options" and produced a package verdict
  # for an entry safe could not actually read (delta-3 finding F1).
  printf '%s' "$json" | jq -r --arg neutral "$SAFE_GATE_MISE_NEUTRAL_OPTS" '
    if type != "object" then error("schema") else . end
    | (if has("tool_options") then .tool_options else error("schema") end)
    | if type != "object" then error("schema") else . end
    | ($neutral | split("|")) as $ok
    | to_entries
    | map(select(
        (.value != null)
        and (.value != {}) and (.value != []) and (.value != "")
        and ((.key | IN($ok[])) | not)
      ))
    | if length > 0 then .[0].key else "" end
  ' 2>/dev/null || return 2
}

# ONE option-aware enumerator for every configured-tool preflight (bare
# install/upgrade AND exec auto-install, which previously reconstructed
# entries straight from `mise ls` and never asked about options — delta-3
# finding F1). Appends audit-eligible specs to the named array; prints a
# notice and skips an entry whose options safe cannot model, or whose key
# carries several requested versions (mise tool --json reports one option
# set per KEY, so it cannot say which version the options belong to).
# Returns 100 if the enumeration or an option query fails.
safe_gate_mise_collect_entries() {
  local mode="$1" what="$2"
  local -n _out="$3"
  local entries key req offender orc
  # ONE snapshot: selection and multiplicity attribution must describe the
  # same configuration, and a second `mise ls` could disagree with the
  # first (delta-6 finding F1).
  if ! safe_gate_mise_load_rows; then
    safe_gate_mise_infra_refuse "cannot enumerate configured tools (mise ls or jq unavailable, or malformed output) — ${what} would install unaudited"
    return 100
  fi
  entries="$(safe_gate_mise_select_rows "$mode")"
  local -a keys=() reqs=()
  while IFS=$'\t' read -r key req; do
    [[ -n "$key" ]] || continue
    keys+=("$key")
    reqs+=("$req")
  done <<<"$entries"
  # Multiplicity comes from the UNFILTERED row set: mode selection hides
  # sibling requests that still share one reported option set (delta-4 F1).
  local -a all_keys=()
  local akey
  while IFS=$'\t' read -r akey _; do
    [[ -n "$akey" ]] && all_keys+=("$akey")
  done <<<"$SAFE_GATE_MISE_ROWS"
  local i j count
  for (( i = 0; i < ${#keys[@]}; i++ )); do
    key="${keys[$i]}"
    req="${reqs[$i]}"
    count=0
    for (( j = 0; j < ${#all_keys[@]}; j++ )); do
      [[ "${all_keys[$j]}" == "$key" ]] && count=$((count + 1))
    done
    offender="$(safe_gate_mise_entry_option_offender "$key")"
    orc=$?
    if (( orc != 0 )); then
      safe_gate_mise_infra_refuse "cannot read the configured tool options for '${key}' (mise tool --json failed or returned no tool_options) — ${what} would install without knowing its source"
      return 100
    fi
    if (( count > 1 )); then
      safe_gate_err "safe: mise ${key}: several configured versions share this tool and mise reports one option set for all of them — safe cannot tell which install carries which source; not audit-gated, review manually"
      continue
    fi
    if [[ -n "$offender" ]]; then
      safe_gate_err "safe: mise ${key}: configured tool option '${offender}' can change the install source or run installer arguments safe cannot model — not audit-gated; review manually"
      continue
    fi
    # `upgrade --bump` moves to the LATEST release, potentially outside the
    # configured request, so auditing the old pin checked a version that
    # will not be installed (delta-4 finding F3). A bare name lets
    # safe-audit resolve the same target mise will pick. `install --force`
    # also uses mode 2 but reinstalls the CONFIGURED version, so it keeps
    # its request.
    if (( ${SAFE_GATE_MISE_BUMP:-0} )); then
      _out+=("$key")
    elif [[ -n "$req" ]]; then
      _out+=("${key}@${req}")
    else
      _out+=("$key")
    fi
  done
  return 0
}

# --minimum-release-age makes mise pick an older release than the newest
# matching one. safe's resolver has no equivalent, so a non-exact target
# would be audited at a version mise will not install: refuse rather than
# report a verdict for the wrong version. Exact pins are unaffected.
safe_gate_mise_min_age_guard() {
  (( ${SAFE_GATE_MISE_MIN_AGE:-0} )) || return 0
  local spec ver
  for spec in "$@"; do
    ver=""
    [[ "$spec" == *@* ]] && ver="${spec##*@}"
    if [[ ! "$ver" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$ ]]; then
      safe_gate_err "safe: BLOCKED mise — --minimum-release-age selects an older release than safe would check for '${spec}'; pin the exact version you want installed; details: safe explain"
      return 100
    fi
  done
  return 0
}

safe_gate_mise_overlay_or_refuse() {
  if ! SAFE_GATE_MISE_OVERLAY="$(safe_gate_mise_env_overlay ${SAFE_GATE_MISE_CTX[@]+"${SAFE_GATE_MISE_CTX[@]}"})"; then
    safe_gate_mise_infra_refuse "cannot derive the mise environment (mise env failed) — audits would not see project [env] package sources"
    return 100
  fi
  return 0
}

# `mise upgrade npm:pkg` (no version) upgrades WITHIN the configured
# request, but a bare package check resolves the install/latest target —
# safe would report a verdict for a version mise will not select (delta-3
# finding F3). Replace each unversioned explicit upgrade target with its
# configured request; refuse if it cannot be found.
safe_gate_mise_pin_upgrade_targets() {
  local -n _specs="$1"
  local -a pinned=()
  local spec entries rc key req canon matched parsed stripped offender name version
  # Under --bump EVERY target moves to the latest release, so an argv
  # version is a backend filter, not the audited target (delta-5 F3).
  local need="${SAFE_GATE_MISE_BUMP:-0}"
  if (( need == 0 )); then
    for spec in ${_specs[@]+"${_specs[@]}"}; do
      [[ "$(safe_gate_mise_spec_name "$spec")" == "$spec" ]] && need=1
    done
  fi
  if (( need == 0 )); then
    return 0
  fi
  if ! safe_gate_mise_load_rows; then
    safe_gate_mise_infra_refuse "cannot read the configured request for an upgrade target (mise ls or jq unavailable, or malformed output)"
    return 100
  fi
  entries="$SAFE_GATE_MISE_ROWS"
  for spec in ${_specs[@]+"${_specs[@]}"}; do
    # Normalize ONCE: a bracket option must not end up inside the key that
    # is compared against configured rows, which refused a supported
    # invocation as unconfigured (delta-5 finding F3).
    parsed="$(safe_gate_mise_strip_opts "$spec")" || {
      pinned+=("$spec")
      continue
    }
    IFS=$'\t' read -r stripped offender <<<"$parsed"
    if [[ -n "$offender" ]]; then
      # A source-changing option reaches its notice path through check_spec.
      pinned+=("$spec")
      continue
    fi
    name="$(safe_gate_mise_spec_name "$stripped")"
    version=""
    [[ "$stripped" != "$name" ]] && version="${stripped#${name}@}"
    canon="$name"
    if [[ "$canon" != *:* ]]; then
      canon="$(safe_gate_mise_resolve_bare "$canon")" || {
        safe_gate_mise_infra_refuse "cannot resolve '${name}' to its backend (mise registry unavailable or unknown tool); use an explicit backend spec"
        return 100
      }
    fi
    if (( ${SAFE_GATE_MISE_BUMP:-0} )); then
      # --bump moves a CONFIGURED request; with none, mise installs
      # nothing, so auditing the latest release reported a verdict for a
      # no-op (delta-6 finding F3).
      matched=0
      while IFS=$'\t' read -r key _; do
        [[ "$key" == "$canon" ]] && { matched=1; break; }
      done <<<"$entries"
      if (( matched == 0 )); then
        safe_gate_err "safe: BLOCKED mise upgrade — '${spec}' has no configured version request to check against; name the exact version: mise upgrade ${canon}@<version>; details: safe explain"
        return 100
      fi
      pinned+=("$canon")
      continue
    fi
    if [[ -n "$version" ]]; then
      pinned+=("${canon}@${version}")
      continue
    fi
    # EVERY configured request for the key can move on a plain upgrade,
    # not just the first; an exact pin cannot move at all, so auditing it
    # reported a verdict for a no-op (delta-4 finding F3).
    matched=0
    while IFS=$'\t' read -r key req _; do
      [[ "$key" == "$canon" ]] || continue
      matched=1
      [[ "$req" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$ ]] && continue
      if [[ -n "$req" ]]; then
        pinned+=("${canon}@${req}")
      else
        pinned+=("$canon")
      fi
    done <<<"$entries"
    if (( matched == 0 )); then
      safe_gate_err "safe: BLOCKED mise upgrade — '${spec}' has no configured version request to check against; name the exact version: mise upgrade ${canon}@<version>; details: safe explain"
      return 100
    fi
  done
  _specs=(${pinned[@]+"${pinned[@]}"})
  return 0
}

safe_gate_mise_gate_install() {
  local sub="$1"
  shift
  safe_gate_mise_parse_sub "$sub" "$@" || return $?

  local -a specs=("${SAFE_GATE_MISE_SPECS[@]+"${SAFE_GATE_MISE_SPECS[@]}"}")
  if (( ${#specs[@]} == 0 )); then
    safe_gate_mise_collect_entries "$SAFE_GATE_MISE_MODE" "a bare ${sub}" specs || return $?
  fi

  # Exclusions first: a target mise will not touch must not be refused for
  # being unconfigured (delta-4 finding F3).
  safe_gate_mise_filter_excluded specs || return $?

  # An explicit UNVERSIONED upgrade target keeps its configured request in
  # mise, while a bare package check resolves the install/latest target:
  # audit the configured request(s) instead (delta-3/4 finding F3).
  if [[ "$sub" == "upgrade" && ${#SAFE_GATE_MISE_SPECS[@]} -gt 0 ]]; then
    safe_gate_mise_pin_upgrade_targets specs || return $?
  fi
  (( ${#specs[@]} == 0 )) && return 0
  safe_gate_mise_min_age_guard ${specs[@]+"${specs[@]}"} || return $?
  safe_gate_mise_overlay_or_refuse || return $?
  local spec
  # Config-derived specs already went through the collector option
  # check; argv specs still need theirs.
  local from_config=0
  (( ${#SAFE_GATE_MISE_SPECS[@]} == 0 )) && from_config=1
  for spec in "${specs[@]}"; do
    safe_gate_mise_check_spec "$spec" "$SAFE_GATE_MISE_OVERLAY" "$from_config" || return $?
  done
  return 0
}

safe_gate_mise_gate_use() {
  safe_gate_mise_parse_sub use "$@" || return $?
  if (( ${#SAFE_GATE_MISE_SPECS[@]} == 0 )); then
    # Removal installs nothing; anything else here is the interactive
    # registry selector, which installs a choice safe never saw.
    (( SAFE_GATE_MISE_SAW_REMOVE )) && return 0
    safe_gate_err "safe: BLOCKED mise use — interactive tool selection cannot be audited; rerun as: mise use <tool>@<version>; details: safe explain"
    return 100
  fi
  # `use` honors --minimum-release-age too: without the guard it audited an
  # unconstrained target while mise selected an older one (delta-2 F3).
  safe_gate_mise_min_age_guard "${SAFE_GATE_MISE_SPECS[@]}" || return $?
  safe_gate_mise_overlay_or_refuse || return $?
  local spec
  for spec in "${SAFE_GATE_MISE_SPECS[@]}"; do
    safe_gate_mise_check_spec "$spec" "$SAFE_GATE_MISE_OVERLAY" || return $?
  done
  return 0
}

# `mise settings get exec_auto_install`: only a validated explicit "false"
# skips the exec preflight; unknown/unreadable assumes enabled (fail closed
# means enumerating, not skipping).
safe_gate_mise_exec_auto_install_enabled() {
  local mise_real out
  mise_real="$(safe_gate_resolve_real mise)" || return 0
  out="$("$mise_real" "$@" settings get exec_auto_install 2>/dev/null)" || return 0
  [[ "$out" == "false" ]] && return 1
  return 0
}

safe_gate_mise_gate_exec() {
  safe_gate_mise_parse_sub exec "$@" || return $?

  local -a audit=("${SAFE_GATE_MISE_SPECS[@]+"${SAFE_GATE_MISE_SPECS[@]}"}")
  local -a cmd=("${SAFE_GATE_MISE_CMD[@]+"${SAFE_GATE_MISE_CMD[@]}"}")
  local -a ctx=("${SAFE_GATE_MISE_CTX[@]+"${SAFE_GATE_MISE_CTX[@]}"}")

  # exec auto-installs missing configured tools before running the command
  # (unless the setting disables it): enumerate them like a bare install.
  if safe_gate_mise_exec_auto_install_enabled ${ctx[@]+"${ctx[@]}"}; then
    # Same option-aware enumerator as bare install: reconstructing entries
    # straight from `mise ls` here skipped the option check entirely
    # (delta-3 finding F1).
    SAFE_GATE_MISE_CTX=("${ctx[@]+"${ctx[@]}"}")
    safe_gate_mise_collect_entries 0 "exec auto-install" audit || return $?
  fi

  local need_overlay=0
  (( ${#audit[@]} > 0 )) && need_overlay=1
  local gate_inner=0
  if (( ${#cmd[@]} > 0 )); then
    case "${cmd[0]}" in
      npm|pnpm|pnpx|bun|yarn|pip|pip3|uv|cargo|go|composer) gate_inner=1; need_overlay=1 ;;
    esac
  fi
  if (( need_overlay )); then
    SAFE_GATE_MISE_CTX=("${ctx[@]+"${ctx[@]}"}")
    safe_gate_mise_overlay_or_refuse || return $?
  fi

  local spec i_spec=0
  for spec in ${audit[@]+"${audit[@]}"}; do
    # The first entries are the argv tool specs; the rest came from
    # the collector, which already asked about their options.
    local skip_opts=1
    (( i_spec < ${#SAFE_GATE_MISE_SPECS[@]} )) && skip_opts=0
    i_spec=$((i_spec + 1))
    safe_gate_mise_check_spec "$spec" "$SAFE_GATE_MISE_OVERLAY" "$skip_opts" || return $?
  done

  # A gated tool behind -- gets the full routing/audit pass with the exec
  # suppressed (the outer mise owns execution and its env). The inner scan
  # runs under the same overlay so its source floor sees mise's [env].
  # A launcher first word (env, sh, time, ...) is a documented residual:
  # refusing it would break ordinary `mise exec -- <binary>` use.
  if (( gate_inner )); then
    # The source derivation models cargo/composer/bun env selectors, so the
    # inner route audits them like any other tool; the one survivor is
    # CARGO_HOME (an unread config.toml, [source] replacement included) —
    # same honesty rule as the backend-install path (delta-3 finding F4).
    local inner_installer inner_unmodeled
    if inner_installer="$(safe_gate_mise_tool_installer "${cmd[0]}")" \
       && inner_unmodeled="$(safe_gate_mise_unmodeled_source "$inner_installer" "$SAFE_GATE_MISE_OVERLAY")"; then
      safe_gate_err "safe: mise exec ${cmd[0]}: ${inner_unmodeled} selects a ${inner_installer} source safe cannot resolve advisories against — not audit-gated; review manually"
      return 0
    fi
    # mise re-applies its [env] tables after the outer exec, where the
    # gate's own scrub cannot reach: a script-policy key in the overlay
    # would resurrect exactly what the scrub removed. Fail closed and name
    # the key — the operator removes it from the mise config if intended.
    case "${cmd[0]}" in
      npm|pnpm|bun)
        if safe_gate_mise_overlay_scripts_policy "$SAFE_GATE_MISE_OVERLAY"; then
          safe_gate_err "safe: BLOCKED mise exec ${cmd[0]} — the mise [env] overlay sets ${SAFE_GATE_MISE_POLICY_KEY}, which overrides the operator's script policy; remove it from the mise config (operator) and retry; details: safe explain"
          return 100
        fi
        ;;
    esac
    (
      if [[ -n "${SAFE_GATE_MISE_CD:-}" ]]; then
        cd -- "${SAFE_GATE_MISE_CD}" 2>/dev/null || {
          safe_gate_mise_infra_refuse "cannot enter the -C directory '${SAFE_GATE_MISE_CD}' to scan from the same place mise runs"
          exit 100
        }
      fi
      safe_gate_mise_apply_overlay "$SAFE_GATE_MISE_OVERLAY" || {
        safe_gate_mise_infra_refuse "cannot apply the mise environment (malformed value transport)"
        exit 100
      }
      SAFE_GATE_NO_EXEC=1
      safe_gate_main "${cmd[0]}" "${cmd[@]:1}"
    ) || return $?
  fi
  return 0
}

# Display-only and no-install invocations: mise prints help/version or
# reports a plan and installs nothing, so gating them blocked a read-only
# command (delta-1 finding N3) — and blocking `--help` hides the very hints
# the refusals point at. Scanned before `--` only: flags after it belong to
# the inner command.
safe_gate_mise_is_noop_invocation() {
  local sub="$1"
  shift
  local arg
  for arg in "$@"; do
    [[ "$arg" == "--" ]] && break
    case "$arg" in
      -h|--help|-V|--version) return 0 ;;
      -n|--dry-run|--dry-run-code|-n=*|--dry-run=*|--dry-run-code=*)
        case "$sub" in
          install|i|upgrade|up|use|u) return 0 ;;
        esac
        ;;
    esac
  done
  return 1
}

safe_gate_mise() {
  local -a args=("$@")
  local i=0 subcommand="" subidx=-1 arg base
  SAFE_GATE_MISE_CTX=()
  SAFE_GATE_MISE_OVERLAY=""
  SAFE_GATE_MISE_CD=""
  # The row snapshot is per invocation: context flags parsed below
  # change which configuration it must describe.
  SAFE_GATE_MISE_ROWS=""
  SAFE_GATE_MISE_ROWS_LOADED=0
  # Exact top-level table from `mise --help` (2026.7): value flags consume,
  # switches step over, anything else fails closed — including unknown
  # equals-forms (a blanket -*=* accept violated the fail-closed contract).
  local gval='-C|--cd|-E|--env|-j|--jobs|--output|--log-level'
  local gbool='-q|--quiet|-v|--verbose|-vv|-y|--yes|--no-config|--no-env|--no-hooks|--raw|--locked|--silent|--debug|--trace|-V|--version|-h|--help'
  while (( i < ${#args[@]} )); do
    arg="${args[$i]}"
    case "$arg" in
      -*)
        base="${arg%%=*}"
        # Counted verbosity (-vvv) is legal mise (delta-1 finding 10).
        if [[ "$arg" =~ ^-v+$ ]]; then
          i=$((i + 1))
          continue
        fi
        if [[ "$arg" == *=* ]]; then
          if safe_gate_alt_match "$base" "$gval"; then
            safe_gate_mise_record_ctx "" "$base" "${arg#*=}"
            i=$((i + 1))
            continue
          fi
          safe_gate_err "safe: BLOCKED mise — unrecognized leading flag '${base}' hides the subcommand; details: safe explain"
          return 100
        fi
        if safe_gate_alt_match "$arg" "$gval"; then
          if (( i + 1 >= ${#args[@]} )); then
            safe_gate_err "safe: BLOCKED mise — flag '${arg}' is missing its value; details: safe explain"
            return 100
          fi
          safe_gate_mise_record_ctx "" "$arg" "${args[$((i + 1))]}"
          i=$((i + 2))
          continue
        fi
        if safe_gate_alt_match "$arg" "$gbool"; then
          # Config/env-disabling switches change what every helper query
          # sees: they must travel with the context or safe enumerates and
          # audits a configuration the delegate never loads (delta-1
          # findings 6/8).
          case "$arg" in
            --no-config|--no-env|--no-hooks) SAFE_GATE_MISE_CTX+=("$arg") ;;
            # A LEADING global help prints and installs nothing —
            # `mise --help install npm:x` exits 0 with help — but the
            # subcommand scan never saw it, so the install gate ran and
            # could block a display-only command (delta-2 finding F5).
            # --version does NOT get this treatment: verified against mise
            # 2026.7.16, `mise --version install npm:cowsay@1.6.0` still
            # installs, so early-delegating it was an unaudited bypass
            # (delta-3 finding F5). With no subcommand it falls through to
            # the no-subcommand delegate below anyway.
            -h|--help)
              safe_gate_exec_real mise "$@"
              return $?
              ;;
          esac
          i=$((i + 1))
          continue
        fi
        safe_gate_err "safe: BLOCKED mise — unrecognized leading flag '${arg}' hides the subcommand (rewrite as --flag=value); details: safe explain"
        return 100
        ;;
      *)
        subcommand="$arg"
        subidx=$i
        break
        ;;
    esac
  done

  if [[ -z "$subcommand" ]]; then
    safe_gate_exec_real mise "$@"
    return $?
  fi

  # Top-level -C/-E context carries into the gated subcommand's preflight
  # and env derivation; the subcommand parser appends its own.
  local -a rest=("${args[@]:$((subidx + 1))}")

  if safe_gate_mise_is_noop_invocation "$subcommand" ${rest[@]+"${rest[@]}"}; then
    safe_gate_exec_real mise "$@"
    return $?
  fi

  case "$subcommand" in
    install|i)
      safe_gate_mise_gate_install install ${rest[@]+"${rest[@]}"} || return $?
      ;;
    upgrade|up)
      safe_gate_mise_gate_install upgrade ${rest[@]+"${rest[@]}"} || return $?
      ;;
    use|u)
      safe_gate_mise_gate_use ${rest[@]+"${rest[@]}"} || return $?
      ;;
    exec|x)
      safe_gate_mise_gate_exec ${rest[@]+"${rest[@]}"} || return $?
      ;;
  esac

  # The inner gate ran in a subshell (audit only, exec suppressed): its env
  # scrub died there. The scrub must happen HERE, in the process that execs
  # mise, or inherited script-policy env reaches mise's managed npm intact
  # (delta-2 finding F3).
  safe_gate_npm_scrub_script_env
  safe_gate_exec_real mise "$@"
}

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
    mise) safe_gate_mise "$@" ;;
    *)
      # Fail closed: a wrapper exists for a tool this library has no routing
      # table for, so nothing can vouch for the command.
      safe_gate_err "safe: BLOCKED ${tool} — safe gate has no routing table for '${tool}'; to allow: ask the operator to remove the stale wrapper or update safe; details: safe explain"
      return 100
      ;;
  esac
}
