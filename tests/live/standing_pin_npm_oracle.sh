#!/usr/bin/env bash
# LIVE suite (ticket 1690): the question the lane asks npm about a pinned project, against the REAL npm.
#
# The standing decision is honoured only when `npm prefix` and `npm root` (the command's own arguments, the housekeeping on the command line) both exit 0 and print
# one line, the root being exactly <prefix>/node_modules and the prefix a stored pin by identity. This suite holds what the real npm prints (the table of the design
# note lives HERE, not in a note) on every npm build installed under ~/.local/share/mise/installs/node: 8.1.0, 10.9.2, 11.20.0 and
# 12.2.1 (a missing build is skipped, said). It is read-only: `npm root` in scratch directories with an isolated home; the store is
# written by the core's own writer at a pty, in that isolated home. The verdict is the core's (`one-shot-store verify <prefix> <root>`).
set -uo pipefail

# SAFE_TEST_ISOLATION_MARKER: every suite owns a scratch HOME and safe state.
# shellcheck source=tests/lib/test-isolation.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/test-isolation.sh"
safe_test_setup_isolation || exit 1

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
PASS=0
FAIL=0
pass() { printf 'ok - %s\n' "$1"; PASS=$((PASS + 1)); }
fail() { printf 'FAIL - %s\n' "$1"; FAIL=$((FAIL + 1)); }

# shellcheck source=tests/lib/safe-core.sh
source "${ROOT}/tests/lib/safe-core.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/safe-live-pin.XXXXXX")" || exit 1
safe_test_compose_exit_trap "rm -rf -- \"\${WORK}\""
safe_core_test_prepare "${ROOT}" "${WORK}/safe-core" || { printf 'SKIP: safe-core cannot be built\n'; exit 0; }
CORE="${WORK}/safe-core"
MISE="${HOME_MISE_ROOT:-$(getent passwd "$(id -u)" | cut -d: -f6)/.local/share/mise/installs/node}"

# version -> the node installation that carries it
declare -A NODE_OF=([8.1.0]=16.13.0 [10.9.2]=22.14.0 [11.20.0]=26.13.1 [12.2.1]=24.22.1)

# the project layout: R is a workspaces root, R/pkg a member that is its own git repository, P a plain project
mkdir -p "${WORK}/R/pkg" "${WORK}/P" "${WORK}/other" "${WORK}/home"
printf '{"name":"root","version":"1.0.0","workspaces":["pkg"]}\n' > "${WORK}/R/package.json"
printf '{"name":"pkg","version":"1.0.0"}\n' > "${WORK}/R/pkg/package.json"
printf '{"name":"p","version":"1.0.0"}\n' > "${WORK}/P/package.json"
printf '{"name":"o","version":"1.0.0"}\n' > "${WORK}/other/package.json"
git -C "${WORK}/R/pkg" init -q . >/dev/null 2>&1
STORE_HOME="${WORK}/store-home"
mkdir -p "${STORE_HOME}/.config/safe/run"

# a pin by the core's own writer, at a terminal (a pty), in the isolated store home
pin() {
  rm -f "${STORE_HOME}/.config/safe/run/one-shot-projects.json"
  local dir
  for dir in "$@"; do
    printf 'y\n' > "${WORK}/ans"
    ( cd "${dir}" && env -u CLAUDECODE -u CODEX_THREAD_ID -u CODEX_CI -u OPENCODE HOME="${STORE_HOME}" bash -c 'exec python3 -c "import os,pty,sys; sys.exit(os.waitstatus_to_exitcode(pty.spawn(sys.argv[1:])))" "$@" <"'"${WORK}"'/ans"' bash "${CORE}" one-shot-store add >/dev/null 2>&1 ) || return 1
  done
}

# the two questions, put by the PRODUCTION helper (safe_gate_project_lane_pin_npm_line: the delegate, the environment preparation, the
# options in front, the scratch directory) to the real npm: `root` in the arguments given here marks the command word. The raw
# standard output goes to $WORK/answer.<word>; the status is npm's own.
ask() { # <node> <cwd> <word> <scratch> <env…> -- <args…>
  local node="$1" cwd="$2" word="$3" scratch="$4" arg index=0 i=0
  shift 4
  local -a envs=()
  while (( $# )) && [[ "$1" != -- ]]; do envs+=("$1"); shift; done
  shift
  for arg in "$@"; do i=$((i + 1)); [[ "${arg}" != root ]] || { index=${i}; break; }; done
  (( index > 0 )) || return 125
  ( cd "${cwd}" && env -i HOME="${ORACLE_HOME}" PATH="${node}/bin:/usr/bin:/bin" GATE_LIB="${ROOT}/lib/gate-lib.sh" SCRATCH="${scratch}" WORD="${word}" IDX="${index}" ANSWER="${WORK}/answer.${word}" \
      ${envs[@]+"${envs[@]}"} bash -c 'source "${GATE_LIB}"; SAFE_GATE_SUBCMD_IDX="${IDX}"; safe_gate_project_lane_pin_npm_line "${WORD}" "${SCRATCH}" "$@"; rc=$?; printf "%s" "${SAFE_GATE_PIN_ANSWER}" > "${ANSWER}"; exit "${rc}"' bash "$@" )
}

# the verdict of both answers, with the raw paths and the statuses kept: sets PREFIX_RAW, ROOT_RAW, PREFIX_RC, ROOT_RC
ORACLE_HOME="${WORK}/home"
read_answers() { # <version> <cwd> <env…> -- <args…>
  local version="$1" cwd="$2" node scratch
  shift 2
  node="${MISE}/${NODE_OF[${version}]}"
  scratch="$(mktemp -d "${WORK}/scratch.XXXXXX")"
  rm -f "${WORK}/answer.prefix" "${WORK}/answer.root"
  ask "${node}" "${cwd}" prefix "${scratch}" "$@"; PREFIX_RC=$?
  PREFIX_RAW="$(cat "${WORK}/answer.prefix" 2>/dev/null; printf x)"; PREFIX_RAW="${PREFIX_RAW%x}"
  ask "${node}" "${cwd}" root "${scratch}" "$@"; ROOT_RC=$?
  ROOT_RAW="$(cat "${WORK}/answer.root" 2>/dev/null; printf x)"; ROOT_RAW="${ROOT_RAW%x}"
  rm -rf "${scratch}"
}

# honoured <version> <cwd> <pin dir…> -- <env assignments…> -- <npm args…>: 0 honoured, 1 not honoured by the core after two successful
# answers, 2 the pin setup failed, 3 npm failed on a question (an error, which is what some rows expect)
honoured() {
  local version="$1" cwd="$2"
  shift 2
  local -a pins=() rest=()
  while (( $# )) && [[ "$1" != -- ]]; do pins+=("$1"); shift; done
  shift
  rest=("$@")
  pin "${pins[@]}" || return 2
  read_answers "${version}" "${cwd}" "${rest[@]}"
  (( PREFIX_RC == 0 && ROOT_RC == 0 )) || return 3
  HOME="${STORE_HOME}" "${CORE}" one-shot-store verify "${PREFIX_RAW}" "${ROOT_RAW}" >/dev/null 2>&1
}

# expect <label> <want yes|no|error> <version> <cwd> <pins…> -- <envs> -- <npm args>
expect() {
  local label="$1" want="$2" version="$3" got rc
  shift 3
  honoured "${version}" "$@"; rc=$?
  case "${rc}" in 0) got=yes ;; 1) got=no ;; 3) got=error ;; *) fail "${version}: ${label}: the setup failed (${rc})"; return ;; esac
  if [[ "${got}" == "${want}" ]]; then pass "${version}: ${label}"; else fail "${version}: ${label}: got ${got}, want ${want}"; fi
}

# expect_paths <label> <version> <want prefix> <want root> <cwd> <pins…> -- <envs> -- <npm args>: both questions exit 0 and print exactly these
expect_paths() {
  local label="$1" version="$2" want_prefix="$3" want_root="$4"
  shift 4
  local cwd="$1"
  shift
  local -a pins=()
  while (( $# )) && [[ "$1" != -- ]]; do pins+=("$1"); shift; done
  shift
  pin "${pins[@]}" || { fail "${version}: ${label}: the setup failed"; return; }
  read_answers "${version}" "${cwd}" "$@"
  if (( PREFIX_RC == 0 && ROOT_RC == 0 )) && [[ "${PREFIX_RAW}" == "${want_prefix}"$'\n' && "${ROOT_RAW}" == "${want_root}"$'\n' ]]; then
    pass "${version}: ${label} (prefix ${want_prefix#"${WORK}"/}, root ${want_root#"${WORK}"/})"
  else
    fail "${version}: ${label}: statuses ${PREFIX_RC}/${ROOT_RC}, prefix [${PREFIX_RAW%$'\n'}], root [${ROOT_RAW%$'\n'}]; want [${want_prefix}] [${want_root}]"
  fi
}

ran=0
for version in 8.1.0 10.9.2 11.20.0 12.2.1; do
  node="${MISE}/${NODE_OF[${version}]}"
  if [[ ! -x "${node}/bin/npm" ]] || [[ "$(PATH="${node}/bin:/usr/bin:/bin" npm --version 2>/dev/null)" != "${version}" ]]; then
    printf "SKIP: npm %s is not installed under %s (%s; found %s)\n" "${version}" "${MISE}" "${NODE_OF[${version}]}" "$(PATH="${node}/bin:/usr/bin:/bin" npm --version 2>&1 | head -1)"
    continue
  fi
  ran=$((ran + 1))
  printf '# npm %s\n' "${version}"
  R="${WORK}/R" M="${WORK}/R/pkg" P="${WORK}/P"
  R="$(cd "${R}" && pwd -P)"; M="$(cd "${M}" && pwd -P)"; P="$(cd "${P}" && pwd -P)"
  # a plain project, pinned, in project mode
  expect "a plain pinned project" yes "${version}" "${P}" "${P}" -- -- root clean@2.0.0 --save-exact
  expect "-g on the pinned project's prefix is global mode" no "${version}" "${P}" "${P}" -- -- root clean@2.0.0 -g --prefix="${P}"
  expect "an explicit prefix elsewhere" no "${version}" "${P}" "${P}" -- -- root --prefix="${WORK}/other"
  expect "npm_config_global=true in the environment" no "${version}" "${P}" "${P}" -- npm_config_global=true -- root
  expect "NPM_CONFIG_GLOBAL=true, another case" no "${version}" "${P}" "${P}" -- NPM_CONFIG_GLOBAL=true -- root
  expect "npm_config_prefix alone does not move a local command" yes "${version}" "${P}" "${P}" -- npm_config_prefix="${WORK}/other" -- root
  # configuration files
  printf 'global=true\n' > "${P}/.npmrc"
  expect "global=true in the project .npmrc" no "${version}" "${P}" "${P}" -- -- root
  printf 'location=global\n' > "${P}/.npmrc"
  if [[ "${version}" == 8.1.0 ]]; then
    expect "location=global in a file: 8.1.0 ignores it, as today's gate's npm does" yes "${version}" "${P}" "${P}" -- -- root
  else
    expect "location=global in the project .npmrc" no "${version}" "${P}" "${P}" -- -- root
  fi
  printf 'workspaces=true\n' > "${P}/.npmrc"
  expect "workspaces=true in the project .npmrc: npm errors (no pin)" error "${version}" "${P}" "${P}" -- -- root
  rm -f "${P}/.npmrc"
  # the workspace member that is its own git repository
  if [[ "${version}" == 8.1.0 ]]; then
    expect "8.1.0 does not search for a workspace root: a pinned member is honoured" yes "${version}" "${M}" "${M}" -- -- root
    expect "8.1.0: a pinned root is not what npm acts on from the member" no "${version}" "${M}" "${R}" -- -- root
  else
    expect "a pinned member: npm acts on the root above (the search crosses the git root)" no "${version}" "${M}" "${M}" -- -- root
    expect "a pinned root, a command typed in the member" yes "${version}" "${M}" "${R}" -- -- root
  fi
  expect "a pinned root, typed in the root" yes "${version}" "${R}" "${R}" -- -- root
  expect "an explicit prefix on the member beats the search" yes "${version}" "${M}" "${M}" -- -- root --prefix="${M}"
  expect "a workspace selection: npm errors (no pin)" error "${version}" "${R}" "${R}" -- -- root -w pkg
  # an abbreviation npm reads as --prefix
  if [[ "${version}" == 12.2.1 ]]; then
    expect "--prefi is an error on 12 (no pin)" error "${version}" "${M}" "${M}" -- -- root --prefi="${M}"
  else
    expect "--prefi is --prefix to npm" yes "${version}" "${M}" "${M}" -- -- root --prefi="${M}"
  fi
  # the project named `lib` under a global prefix: the roots coincide, the PREFIX tells the mode. The raw paths npm printed are asserted
  GP="${WORK}/gp"; mkdir -p "${GP}/lib/node_modules"
  printf '{"name":"lib","version":"1.0.0"}\n' > "${GP}/lib/package.json"
  GP="$(cd "${GP}" && pwd -P)"
  expect_paths "a project named lib under the global prefix, local mode" "${version}" "${GP}/lib" "${GP}/lib/node_modules" "${GP}/lib" "${GP}/lib" -- npm_config_prefix="${GP}" -- root
  expect_paths "the same directory, global mode: the roots coincide, the prefixes do not" "${version}" "${GP}" "${GP}/lib/node_modules" "${GP}/lib" "${GP}/lib" -- npm_config_prefix="${GP}" -- root -g
  expect "the local pair is honoured" yes "${version}" "${GP}/lib" "${GP}/lib" -- npm_config_prefix="${GP}" -- root
  expect "the global pair is not honoured (the project is pinned)" no "${version}" "${GP}/lib" "${GP}/lib" -- npm_config_prefix="${GP}" -- root -g
  expect_paths "global mode from the environment" "${version}" "${GP}" "${GP}/lib/node_modules" "${GP}/lib" "${GP}/lib" -- npm_config_prefix="${GP}" npm_config_global=true -- root
  expect "global mode from the environment is not honoured" no "${version}" "${GP}/lib" "${GP}/lib" -- npm_config_prefix="${GP}" npm_config_global=true -- root
  # global mode from every configuration file (project, user, global), the raw paths first
  printf 'global=true\nprefix=%s\n' "${GP}" > "${GP}/lib/.npmrc"
  expect_paths "global=true in the project .npmrc" "${version}" "${GP}" "${GP}/lib/node_modules" "${GP}/lib" "${GP}/lib" -- -- root
  expect "global=true in the project .npmrc is not honoured" no "${version}" "${GP}/lib" "${GP}/lib" -- -- root
  rm -f "${GP}/lib/.npmrc"
  printf 'global=true\nprefix=%s\n' "${GP}" > "${ORACLE_HOME}/.npmrc"
  expect_paths "global=true in the user config file" "${version}" "${GP}" "${GP}/lib/node_modules" "${GP}/lib" "${GP}/lib" -- -- root
  rm -f "${ORACLE_HOME}/.npmrc"
  printf 'global=true\nprefix=%s\n' "${GP}" > "${WORK}/globalrc"
  expect_paths "global=true in the global config file" "${version}" "${GP}" "${GP}/lib/node_modules" "${GP}/lib" "${GP}/lib" -- npm_config_globalconfig="${WORK}/globalrc" -- root
  expect "global=true in the global config file is not honoured" no "${version}" "${GP}/lib" "${GP}/lib" -- npm_config_globalconfig="${WORK}/globalrc" -- root
  rm -f "${WORK}/globalrc"
  # an original --logs-max=1, a terminator and --- change no answer
  expect "an earlier --logs-max=1 and a terminator" yes "${version}" "${P}" "${P}" -- -- root clean@2.0.0 --logs-max=1 -- --extra
  expect "--- is a terminator" yes "${version}" "${P}" "${P}" -- -- root clean@2.0.0 --- --extra
  expect "a trailing option that takes a value, given none" yes "${version}" "${P}" "${P}" -- -- root clean@2.0.0 --fetch-retries
  # an option BEFORE the command word stays in place: the question is the command with its word replaced
  expect "an option before the verb moves npm's target" no "${version}" "${P}" "${P}" -- -- --prefix="${WORK}/other" root clean@2.0.0

  # ---- the populated home: nothing of the operator's changes, whatever the question is -----------------------------------------
  # The production route (the helper, in the production order) runs both questions against a home that holds a debug log, an update-check
  # stamp and a cache; the home (names, kinds, sizes, modes, nanosecond times, contents) is byte-identical after, for a plain command, a
  # failing question (a workspace selection), a trailing value-taking option with no value, `---` and a terminator.
  node="${MISE}/${NODE_OF[${version}]}"
  POP="${WORK}/pop-${version}"
  populate() {
    rm -rf "${POP}"; mkdir -p "${POP}/.npm/_logs" "${POP}/.npm/_cacache/content-v2"
    printf 'old debug log\n' > "${POP}/.npm/_logs/2020-01-01T00_00_00_000Z-debug-0.log"
    printf 'stamp\n' > "${POP}/.npm/_update-notifier-last-checked"
    printf 'cache entry\n' > "${POP}/.npm/_cacache/content-v2/entry"
    touch -d '2020-01-01 00:00:00.123456789' "${POP}/.npm" "${POP}/.npm/_logs" "${POP}/.npm/_logs/"* "${POP}/.npm/_update-notifier-last-checked" "${POP}/.npm/_cacache" "${POP}/.npm/_cacache/content-v2" "${POP}/.npm/_cacache/content-v2/entry"
  }
  snapshot() { ( cd "${POP}" && find . -printf '%p %y %s %m %T@\n' | LC_ALL=C sort; find . -type f -exec sha256sum {} + | LC_ALL=C sort ) | sha256sum | cut -d' ' -f1; }
  for variant in "plain|clean@2.0.0 --save-exact" "a workspace selection (the question fails)|clean@2.0.0 -w nothere" "a trailing option with no value|clean@2.0.0 --fetch-retries" "---|clean@2.0.0 --- --extra" "a terminator|clean@2.0.0 -- --extra"; do
    label="${variant%%|*}"; line="${variant#*|}"
    populate
    before="$(snapshot)"
    saved_home="${ORACLE_HOME}"; ORACLE_HOME="${POP}"
    read -r -a vargs <<<"${line}"
    read_answers "${version}" "${P}" -- root "${vargs[@]}"
    ORACLE_HOME="${saved_home}"
    after="$(snapshot)"
    if [[ "${before}" == "${after}" ]]; then pass "${version}: populated home unchanged: ${label} (statuses ${PREFIX_RC}/${ROOT_RC})"; else fail "${version}: populated home CHANGED: ${label}"; fi
  done
  # what is written when the caller's own line names a cache or a logs directory: npm writes there as the command itself would
  populate; before="$(snapshot)"
  mkdir -p "${WORK}/callers-cache"; rm -rf "${WORK}/callers-cache"/*
  saved_home="${ORACLE_HOME}"; ORACLE_HOME="${POP}"
  read_answers "${version}" "${P}" -- root clean@2.0.0 --cache="${WORK}/callers-cache"
  ORACLE_HOME="${saved_home}"
  printf '# npm %s, the caller names --cache: %s file(s) appeared in it; the home itself: %s\n' "${version}" "$(find "${WORK}/callers-cache" -type f | wc -l)" "$([[ "$(snapshot)" == "${before}" ]] && echo unchanged || echo changed)"
  # the environment naming a cache or a logs directory loses to the question's own options
  populate; before="$(snapshot)"
  rm -rf "${WORK}/env-cache"; mkdir -p "${WORK}/env-cache"
  saved_home="${ORACLE_HOME}"; ORACLE_HOME="${POP}"
  read_answers "${version}" "${P}" npm_config_cache="${WORK}/env-cache" npm_config_logs_dir="${WORK}/env-cache/_logs" -- root clean@2.0.0
  ORACLE_HOME="${saved_home}"
  if [[ "$(snapshot)" == "${before}" && -z "$(find "${WORK}/env-cache" -type f | head -1)" ]]; then pass "${version}: a cache and a logs directory named by the environment receive nothing"; else fail "${version}: the environment's cache or logs directory was written"; fi

  # ---- no connection, no file, on a FRESH home (the trace's own status counts; the class claimed is any internet-family connect) ----
  FRESH="${WORK}/fresh-${version}"; rm -rf "${FRESH}"; mkdir -p "${FRESH}"
  : > "${WORK}/trace"
  ( cd "${P}" && env -i HOME="${FRESH}" PATH="${node}/bin:/usr/bin:/bin" GATE_LIB="${ROOT}/lib/gate-lib.sh" WD="${WORK}" \
      strace -f -q -e trace=connect -o "${WORK}/trace" \
      bash -c 'source "${GATE_LIB}"; SAFE_GATE_SUBCMD_IDX=1; s="$(mktemp -d "${WD}/tr.XXXXXX")"; safe_gate_project_lane_pin_npm_line root "${s}" install clean@2.0.0 --logs-max=1 -- --extra; rc=$?; rm -rf "${s}"; exit "${rc}"' </dev/null >/dev/null 2>&1 ); rc=$?
  if (( rc == 0 )) && grep -q '+++ exited with 0 +++' "${WORK}/trace" && [[ -z "$(find "${FRESH}" -type f | head -1)" ]] && ! grep -qE 'AF_INET6?, ' "${WORK}/trace"; then
    pass "${version}: the question writes no file and opens no internet connection (the trace ran: status 0, exit recorded)"
  else
    fail "${version}: the question wrote a file ($(find "${FRESH}" -type f | head -2)), connected ($(grep -E 'AF_INET' "${WORK}/trace" | head -2)) or its trace failed (status ${rc})"
  fi
done
(( ran > 0 )) || { printf 'SKIP: no npm build to ask\n'; exit 0; }

printf '\n%d passed, %d failed\n' "${PASS}" "${FAIL}"
[[ "${FAIL}" -eq 0 ]]
