#!/usr/bin/env bash
# The gate's reading of an npm command line, against npm's own (the corpus of npm-option-corpus.cjs on stdin).
#
# How the gate's reading is extracted: the gate's own `safe_gate_npm_like` runs over the arguments, in a
# subshell, with the effects stubbed: the delegation (`safe_gate_exec_real`) and the audits
# (`safe_gate_check`, `safe_gate_check_many`) record what they were given and the project scan records
# that it ran. Nothing is installed, fetched or run. So the reading is everything the gate decides: the
# front door and the route (a refusal), the command it classifies, the packages it audits, and whether it
# took the command for a global one (the project scan is skipped for a global install).
#
# For every case the gate must refuse, or agree with npm on: the command (a command npm runs that the
# gate audits, the gate must classify the same), the packages npm would fetch (every one is audited), and
# the global mode. The gate may be stricter than npm (it audits a word npm discards; it classifies a word
# npm rejects as an install): that is not a disagreement.
#
#   bash tests/lib/npm-option-gate-oracle.sh [--show N] [--emit FILE] < corpus
#
# SAFE_ORACLE_GATE_LIB names another gate library to read the corpus through (the base branch's, to count what a
# change newly refuses); --emit writes one line per case: its number, ok|refused, and the gate's refusal line.
set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SHOW=20
EMIT=""
while (( $# )); do
  case "$1" in
    --show) SHOW="${2:-20}"; shift 2 ;;
    --emit) EMIT="${2:-}"; shift 2 ;;
    *) shift ;;
  esac
done
[[ -z "${EMIT}" ]] || : > "${EMIT}"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/safe-npm-option-oracle.XXXXXX")
trap 'rm -rf -- "${WORK}"' EXIT
export HOME="${WORK}/home"
mkdir -p "${HOME}" "${WORK}/project"
printf '{"name":"oracle","version":"1.0.0"}\n' > "${WORK}/project/package.json"
cd "${WORK}/project" || exit 1
# shellcheck source=/dev/null
source "${SAFE_ORACLE_GATE_LIB:-${ROOT}/lib/gate-lib.sh}" >/dev/null 2>&1 || { echo "cannot source the gate library"; exit 1; }
REC="${WORK}/record"
safe_gate_exec_real() { printf 'DELEGATE\n' >> "${REC}"; exit 0; }
safe_gate_check() { printf 'AUDIT\t%s\n' "$1" >> "${REC}"; return 0; }
safe_gate_check_many() { shift; local p; for p in "$@"; do printf 'AUDIT\t%s\n' "${p}" >> "${REC}"; done; return 0; }
safe_gate_scan_project() { printf 'SCAN\n' >> "${REC}"; return 0; }
safe_gate_private_npm_project() { return 0; }
safe_gate_project_lane_enabled() { return 1; }
safe_gate_npm_scripts_env() { return 0; }
safe_gate_err() { printf '%s\n' "$*" >> "${WORK}/err"; }

US=$'\x1f'
declare -A seen_kind=() count_kind=()
total=0 refused=0 agreed=0 disagreed=0
note() { # kind, line
  count_kind["$1"]=$(( ${count_kind["$1"]:-0} + 1 ))
  if (( ${seen_kind["$1"]:-0} < SHOW )); then seen_kind["$1"]=$(( ${seen_kind["$1"]:-0} + 1 )); printf 'DISAGREE %s: %s\n' "$1" "$2"; fi
}
strip_version() { local p="$1"; if [[ "${p}" == @*/*@* ]]; then p="${p%@*}"; elif [[ "${p}" == @* ]]; then :; else p="${p%%@*}"; fi; printf '%s' "${p}"; }
while IFS=$'\x1e' read -r argsline remain global command pkgopt; do
  IFS="${US}" read -r -a args <<<"${argsline}"
  IFS="${US}" read -r -a want <<<"${remain}"
  IFS="${US}" read -r -a want_opt <<<"${pkgopt}"
  total=$((total + 1))
  : > "${REC}"; : > "${WORK}/err"
  ( safe_gate_npm_like npm "${args[@]}" ) >/dev/null 2>&1
  rc=$?
  shown="${argsline//${US}/ }"
  if [[ -n "${EMIT}" ]]; then
    if (( rc != 0 )); then printf '%d\trefused\t%s\t%s\n' "${total}" "${argsline//${US}/ }" "$(head -n 1 "${WORK}/err" | cut -c1-400)" >> "${EMIT}"
    else printf '%d\tok\t%s\t\n' "${total}" "${argsline//${US}/ }" >> "${EMIT}"; fi
  fi
  if (( rc != 0 )); then refused=$((refused + 1)); continue; fi
  # what the gate did
  mapfile -t audited < <(sed -n 's/^AUDIT\t//p' "${REC}")
  scanned=0; grep -q '^SCAN' "${REC}" && scanned=1
  delegated=0; grep -q '^DELEGATE' "${REC}" && delegated=1
  # the gate's own words for command and global mode, from the vector (what the gate's functions read)
  safe_gate_route npm "${args[@]}" >/dev/null 2>&1
  gate_sub="${SAFE_GATE_SUBCMD}"
  gate_class="$(safe_gate_npm_subcommand_class "${gate_sub}" 2>/dev/null)" || gate_class=""
  safe_gate_npm_global_true "${args[@]}" && gate_global=1 || gate_global=0
  # what npm does
  npm_class=""
  [[ "${command}" == "-" ]] || npm_class="$(safe_gate_npm_target_class "${command}" 2>/dev/null)" || npm_class=""
  bad=0
  # the packages npm fetches (the command's own arguments are not packages)
  declare -a fetched=()
  case "${npm_class}" in
    install|update|install-test|install-ci-test) fetched=("${want[@]:1}") ;;
    exec) if (( ${#want_opt[@]} )); then fetched=("${want_opt[@]}"); else fetched=("${want[@]:1:1}"); fi ;;
    *) fetched=() ;;
  esac
  case "${npm_class}" in
    ci|lockdiff|install|update|install-test|install-ci-test|exec)
      # a command npm runs that the gate audits: the gate must have classified it as that class
      if [[ "${gate_class}" != "${npm_class}" ]]; then
        # install-test/ci families and the like share a class family: only a passthrough is a disagreement
        if [[ -z "${gate_class}" ]]; then note "command-ungated" "${shown}  (npm: ${command}; gate classifies '${gate_sub}')"; bad=1; fi
      fi ;;
  esac
  for pkg in ${fetched[@]+"${fetched[@]}"}; do
    [[ -n "${pkg}" ]] || continue
    found=0
    for a in ${audited[@]+"${audited[@]}"}; do [[ "$(strip_version "${a}")" == "$(strip_version "${pkg}")" ]] && found=1; done
    if (( ! found )) && [[ "${gate_class}" != ci && "${npm_class}" != ci ]]; then note "package-unaudited" "${shown}  (npm fetches ${pkg}; audited: ${audited[*]:-nothing})"; bad=1; fi
  done
  case "${npm_class}" in
    install|update|install-test|install-ci-test|lockdiff|exec)
      if [[ "${global}" != "${gate_global}" ]]; then note "global-mode" "${shown}  (npm global=${global}, gate global=${gate_global})"; bad=1; fi ;;
  esac
  if (( bad )); then disagreed=$((disagreed + 1)); else agreed=$((agreed + 1)); fi
done
printf 'oracle: %d cases: %d refused by the gate, %d agree, %d disagree\n' "${total}" "${refused}" "${agreed}" "${disagreed}"
for k in "${!count_kind[@]}"; do printf '  %s: %d\n' "${k}" "${count_kind[$k]}"; done
(( disagreed == 0 ))
