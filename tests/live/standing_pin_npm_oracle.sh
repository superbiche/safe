#!/usr/bin/env bash
# LIVE suite (ticket 1690): the question the lane asks npm about a pinned project, against the REAL npm.
#
# The standing decision is honoured only when `npm root <the command's own arguments>` exits 0 and prints one line, ending in
# /node_modules, whose directory is a stored pin by identity. This suite holds what the real npm prints (the table of the design
# note lives HERE, not in a note) on every npm build installed under ~/.local/share/mise/installs/node: 8.1.0, 10.9.2, 11.20.0 and
# 12.2.1 (a missing build is skipped, said). It is read-only: `npm root` in scratch directories with an isolated home; the store is
# written by the core's own writer at a pty, in that isolated home. The verdict is the core's (`one-shot-store verify-root`).
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
    ( cd "${dir}" && env -u CLAUDECODE -u CODEX_THREAD_ID -u CODEX_CI -u OPENCODE bash -c 'exec python3 -c "import os,pty,sys; sys.exit(os.waitstatus_to_exitcode(pty.spawn(sys.argv[1:])))" "$@" <"'"${WORK}"'/ans"' bash "${CORE}" one-shot-store add --home "${STORE_HOME}" >/dev/null 2>&1 ) || return 1
  done
}

# honoured <version> <cwd> <pin dir…> -- <env assignments…> -- <npm args…>: the core's verdict on the real npm's answer
honoured() {
  local version="$1" cwd="$2" node out rc
  shift 2
  local -a pins=() envs=() args=()
  while (( $# )) && [[ "$1" != -- ]]; do pins+=("$1"); shift; done
  shift
  while (( $# )) && [[ "$1" != -- ]]; do envs+=("$1"); shift; done
  shift
  args=("$@")
  node="${MISE}/${NODE_OF[${version}]}"
  pin "${pins[@]}" || return 2
  ( cd "${cwd}" && env -i HOME="${WORK}/home" PATH="${node}/bin:/usr/bin:/bin" npm_config_update_notifier=false npm_config_logs_max=0 ${envs[@]+"${envs[@]}"} \
      timeout 20 npm "${args[@]}" </dev/null 2>/dev/null ) | "${CORE}" one-shot-store verify-root --home "${STORE_HOME}"
  rc=("${PIPESTATUS[@]}")
  (( rc[0] == 0 && rc[1] == 0 ))
}

# expect <label> <want yes|no> <version> <cwd> <pins…> -- <envs> -- <npm args>
expect() {
  local label="$1" want="$2" version="$3" got=no
  shift 3
  honoured "${version}" "$@" && got=yes
  if [[ "${got}" == "${want}" ]]; then pass "${version}: ${label}"; else fail "${version}: ${label}: honoured=${got}, want ${want}"; fi
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
  expect "workspaces=true in the project .npmrc is undetermined (no pin)" no "${version}" "${P}" "${P}" -- -- root
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
  expect "a workspace selection is undetermined" no "${version}" "${R}" "${R}" -- -- root -w pkg
  # an abbreviation npm reads as --prefix
  if [[ "${version}" == 12.2.1 ]]; then
    expect "--prefi is an error on 12 (undetermined)" no "${version}" "${M}" "${M}" -- -- root --prefi="${M}"
  else
    expect "--prefi is --prefix to npm" yes "${version}" "${M}" "${M}" -- -- root --prefi="${M}"
  fi
  # an option BEFORE the command word stays in place: the question is the command with its word replaced
  expect "an option before the verb moves npm's target" no "${version}" "${P}" "${P}" -- -- --prefix="${WORK}/other" root clean@2.0.0
done
(( ran > 0 )) || { printf 'SKIP: no npm build to ask\n'; exit 0; }

printf '\n%d passed, %d failed\n' "${PASS}" "${FAIL}"
[[ "${FAIL}" -eq 0 ]]
