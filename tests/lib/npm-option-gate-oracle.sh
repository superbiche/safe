#!/usr/bin/env bash
# The gate's reading of an npm command line, against npm's own (the corpus of npm-option-corpus.cjs on stdin).
#
# How the gate's reading is observed: the gate's own `safe_gate_npm_like` runs over the arguments, in a subshell,
# with the effects stubbed. The delegation (`safe_gate_exec_real`) records the command word the gate held and every
# argument it was given; the audits (`safe_gate_check`, `safe_gate_check_many`) record the exact identities; the project
# scan records that it ran; and the gate's own question "is this command global?" (`safe_gate_npm_global_true`,
# wrapped) records each answer it gave in that invocation. Nothing is installed, fetched or run.
#
# For every case the gate must refuse (exit 100 with ONE line of its own: any other status or shape is a harness
# error, not a refusal) or let it through and agree with npm on the command word and its canonical command (exactly),
# the identities it audits (exactly: name and version), the delegation (exactly the arguments given, once), the
# project scan decision and the global mode it decided. The judging is tests/lib/npm-option-judge.sh; --selftest feeds
# it a wrong observation of each kind and requires a reported disagreement.
#
#   bash tests/lib/npm-option-gate-oracle.sh [--show N] [--emit FILE] [--expect CASES] < corpus
#   bash tests/lib/npm-option-gate-oracle.sh --selftest
#
# SAFE_ORACLE_GATE_LIB names another gate library to read the corpus through (the base branch's, to count what a
# change newly refuses); --emit (an absolute path) writes one line per case: its number, ok|refused, the arguments,
# the gate's refusal line. The run fails unless it evaluated every case it was given (and --expect of them).
set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
# shellcheck source=tests/lib/npm-option-judge.sh
source "${ROOT}/tests/lib/npm-option-judge.sh"
# shellcheck source=tests/lib/npm-option-corpus.sh
source "${ROOT}/tests/lib/npm-option-corpus.sh"
SHOW=20
EMIT=""
EXPECT=""
SELFTEST=0
while (( $# )); do
  case "$1" in
    --show) SHOW="${2:-20}"; shift 2 ;;
    --emit) EMIT="${2:-}"; shift 2 ;;
    --expect) EXPECT="${2:-}"; shift 2 ;;
    --selftest) SELFTEST=1; shift ;;
    *) shift ;;
  esac
done

# --- the checker must be able to fail ---------------------------------------------------------------------
if (( SELFTEST )); then
  failures=0
  expect_kind() { # <kind> <label>: the judge was run on a wrong observation; it must have reported <kind>
    local kind="$1" label="$2" out
    out="$(npm_oracle_judge)"
    if ! grep -q "^${kind}"$'\t' <<<"${out}"; then printf 'SELFTEST FAIL: %s was not reported (%s)\n' "${label}" "${out:-nothing}"; failures=$((failures + 1)); fi
  }
  expect_clean() {
    local out
    out="$(npm_oracle_judge)"
    [[ -z "${out}" ]] || { printf 'SELFTEST FAIL: a correct observation was reported (%s)\n' "${out}"; failures=$((failures + 1)); }
  }
  right() { # a correct observation of `npm install -g sample@1.0.0`
    J_ARGS=(install -g sample@1.0.0); J_RC=0; J_ERR_LINES=0; J_ERR_FIRST=""
    J_DELEGATIONS=("install"$'\x1f'"-g"$'\x1f'"sample@1.0.0"$'\x1f'); J_SUBCMDS=(install); J_CANON=install
    J_AUDITS=(sample@1.0.0); J_SCANNED=0; J_GLOBALS=(1)
    NPM_REMAIN=(install sample@1.0.0); NPM_GLOBAL=1; NPM_COMMAND=install; NPM_CLASS=install
    EXPECTED=(sample@1.0.0)
  }
  right; expect_clean
  right; J_CANON=install-test; expect_kind command "another command of the same family"
  right; J_SUBCMDS=(i); expect_kind command-word "another word taken for the command"
  right; J_AUDITS=(sample@2.0.0); expect_kind package-unaudited "a different version audited"
  right; J_AUDITS=(sample@1.0.0 other@1.0.0); EXPECTED=(sample@1.0.0); expect_clean   # an extra audit of another name is an over-audit, not a miss
  right; J_AUDITS=(sample@2.0.0 sample@1.0.0); EXPECTED=(sample@1.0.0); expect_kind package-wrong-version "an extra version of the same name"
  right; J_AUDITS=(); expect_kind package-unaudited "nothing audited"
  right; J_DELEGATIONS=(); expect_kind delegation-count "no delegation"
  right; J_DELEGATIONS=("install"$'\x1f'"sample@1.0.0"$'\x1f'); expect_kind delegation-args "other arguments delegated"
  right; J_SCANNED=1; expect_kind scan-decision "a scan of a global command"
  right; NPM_GLOBAL=0; J_SCANNED=0; expect_kind scan-decision "no scan of a project command"
  right; J_GLOBALS=(0); expect_kind global-mode "the wrong global mode"
  right; J_GLOBALS=(); expect_kind global-not-read "global mode never decided"
  right; J_RC=1; expect_kind harness-error "a harness error"
  right; J_RC=100; J_ERR_LINES=2; J_ERR_FIRST="safe: BLOCKED x"; expect_kind harness-error "a refusal of two lines"
  right; J_RC=100; J_ERR_LINES=1; J_ERR_FIRST="something else"; expect_kind harness-error "a refusal that is not the gate's"
  right; J_RC=100; J_ERR_LINES=1; J_ERR_FIRST="safe: BLOCKED npm — x"; expect_clean
  # `ci` hides nothing: a command npm reads as ci and the gate as install
  right; NPM_COMMAND=ci; NPM_CLASS=ci; NPM_REMAIN=(ci); EXPECTED=(); expect_kind command "npm ci read as install"
  if (( failures )); then printf 'selftest: %d failure(s)\n' "${failures}"; exit 1; fi
  printf 'selftest: the judge reports every kind of wrong observation\n'
  exit 0
fi

SHOW="${SHOW}"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/safe-npm-option-oracle.XXXXXX")
trap 'rm -rf -- "${WORK}"' EXIT
export HOME="${WORK}/home"
mkdir -p "${HOME}" "${WORK}/project"
printf '{"name":"oracle","version":"1.0.0"}\n' > "${WORK}/project/package.json"
cd "${WORK}/project" || exit 1
[[ -z "${EMIT}" ]] || : > "${EMIT}"
# shellcheck source=/dev/null
source "${SAFE_ORACLE_GATE_LIB:-${ROOT}/lib/gate-lib.sh}" >/dev/null 2>&1 || { echo "cannot source the gate library"; exit 1; }
REC="${WORK}/record"
US=$'\x1f'
# one record per line, fields separated by `|`, every value percent-encoded (an argument may hold any byte)
enc() { local LC_ALL=C s="$1" out="" c h i; [[ -n "${s}" ]] || { printf '%%00'; return; }
  for (( i=0; i<${#s}; i++ )); do c="${s:i:1}"; case "${c}" in [A-Za-z0-9_.:/@=+-]) out+="${c}" ;; *) printf -v h '%%%02x' "'${c}"; out+="${h}" ;; esac; done; printf '%s' "${out}"; }
safe_gate_exec_real() { { printf 'DELEGATE|%s|' "$(enc "${SAFE_GATE_SUBCMD-}")"; local a first=1; for a in "${@:2}"; do (( first )) || printf ','; first=0; enc "${a}"; done; (( $# > 1 )) || printf '%%'; printf '\n'; } >> "${REC}"; exit 0; }
safe_gate_check() { printf 'AUDIT|%s\n' "$(enc "$1")" >> "${REC}"; return 0; }
safe_gate_check_many() { shift; local p; for p in "$@"; do printf 'AUDIT|%s\n' "$(enc "${p}")" >> "${REC}"; done; return 0; }
safe_gate_scan_project() { printf 'SCAN|\n' >> "${REC}"; return 0; }
safe_gate_private_npm_project() { return 0; }
safe_gate_project_lane_enabled() { return 1; }
safe_gate_npm_scripts_env() { return 0; }
safe_gate_err() { printf '%s\n' "$*" >> "${WORK}/err"; }
eval "$(declare -f safe_gate_npm_global_true | sed '1s/safe_gate_npm_global_true/safe_gate_npm_global_true_real/')"
safe_gate_npm_global_true() { local rc; safe_gate_npm_global_true_real "$@"; rc=$?; printf 'GLOBAL|%d\n' "$(( rc == 0 ? 1 : 0 ))" >> "${REC}"; return "${rc}"; }

declare -A count_kind=() seen_kind=()
total=0 refused=0 agreed=0 disagreed=0 harness=0 over=0
while IFS=$'\t' read -r f_args f_remain f_global f_command f_pkgopt f_call; do
  npm_corpus_list "${f_args}" J_ARGS
  npm_corpus_list "${f_remain}" NPM_REMAIN
  npm_corpus_list "${f_pkgopt}" pkgopt
  NPM_GLOBAL="${f_global}"; NPM_COMMAND="${f_command}"
  total=$((total + 1))
  : > "${REC}"; : > "${WORK}/err"
  ( safe_gate_npm_like npm "${J_ARGS[@]}" ) >/dev/null 2>&1
  J_RC=$?
  J_ERR_LINES="$(wc -l < "${WORK}/err")"; J_ERR_FIRST="$(head -n 1 "${WORK}/err")"
  J_DELEGATIONS=(); J_SUBCMDS=(); J_AUDITS=(); J_GLOBALS=(); J_SCANNED=0
  while IFS='|' read -r kind a b; do
    case "${kind}" in
      DELEGATE) npm_corpus_list "${a}" one; J_SUBCMDS+=("${one[0]-}"); npm_corpus_list "${b}" dargs; printf -v dj '%s\x1f' "${dargs[@]}"; J_DELEGATIONS+=("${dj}") ;;
      AUDIT) npm_corpus_list "${a}" one; J_AUDITS+=("${one[0]-}") ;;
      SCAN) J_SCANNED=1 ;;
      GLOBAL) J_GLOBALS+=("${a}") ;;
    esac
  done < "${REC}"
  if [[ -n "${EMIT}" ]]; then
    if (( J_RC == 100 )); then printf '%d\trefused\t%s\t%s\n' "${total}" "${J_ARGS[*]}" "$(head -n 1 "${WORK}/err" | cut -c1-400)" >> "${EMIT}"
    else printf '%d\tok\t%s\t\n' "${total}" "${J_ARGS[*]}" >> "${EMIT}"; fi
  fi
  J_CANON=""
  if (( ${#J_SUBCMDS[@]} )); then J_CANON="$(safe_gate_npm_canonical_command "${J_SUBCMDS[0]}" 2>/dev/null)" || J_CANON=""; fi
  NPM_CLASS=""
  [[ "${NPM_COMMAND}" == "-" ]] || NPM_CLASS="$(safe_gate_npm_target_class "${NPM_COMMAND}" 2>/dev/null)" || NPM_CLASS=""
  # the identities npm fetches
  EXPECTED=()
  case "${NPM_CLASS}" in
    install|update|install-test|install-ci-test) for p in "${NPM_REMAIN[@]:1}"; do [[ -z "${p}" ]] || EXPECTED+=("$(safe_gate_npm_spec "${p}")"); done ;;
    exec)
      if (( ${#pkgopt[@]} )); then for p in "${pkgopt[@]}"; do [[ -z "${p}" ]] || EXPECTED+=("$(safe_gate_npm_spec "${p}")"); done
      elif [[ "${f_call}" != 1 && ${#NPM_REMAIN[@]} -gt 1 && -n "${NPM_REMAIN[1]}" ]]; then EXPECTED+=("$(safe_gate_npm_spec "${NPM_REMAIN[1]}")"); fi ;;
  esac
  mapfile -t verdicts < <(npm_oracle_judge)
  if (( J_RC == 100 && ${#verdicts[@]} == 0 )); then refused=$((refused + 1)); continue; fi
  if (( ${#verdicts[@]} == 0 )); then agreed=$((agreed + 1)); continue; fi
  disagreed=$((disagreed + 1))
  for v in "${verdicts[@]}"; do
    k="${v%%$'\t'*}"
    [[ "${k}" != harness-error ]] || harness=$((harness + 1))
    count_kind["${k}"]=$(( ${count_kind["${k}"]:-0} + 1 ))
    if (( ${seen_kind["${k}"]:-0} < SHOW )); then
      seen_kind["${k}"]=$(( ${seen_kind["${k}"]:-0} + 1 ))
      shown="${J_ARGS[*]}"
      printf 'DISAGREE %s: %q  (%s)\n' "${k}" "${shown}" "${v#*$'\t'}"
    fi
  done
done
printf 'oracle: %d cases: %d refused by the gate, %d agree, %d disagree (%d harness errors)\n' "${total}" "${refused}" "${agreed}" "${disagreed}" "${harness}"
for k in "${!count_kind[@]}"; do printf '  %s: %d\n' "${k}" "${count_kind[$k]}"; done
if [[ -n "${EXPECT}" && "${total}" != "${EXPECT}" ]]; then printf 'oracle: INCOMPLETE: evaluated %d of the %s cases it was expected to\n' "${total}" "${EXPECT}"; exit 2; fi
(( total > 0 )) || { printf 'oracle: INCOMPLETE: no case was read\n'; exit 2; }
(( disagreed == 0 ))
