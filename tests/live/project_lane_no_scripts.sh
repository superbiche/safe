#!/usr/bin/env bash
# LIVE suite (ticket 1638): the project lane runs no lifecycle script, with the REAL npm.
#
# What it holds: after the lane's install (bare, naming a package), update and ci, on npm 11.20.0 and 12.2.1, no marker exists: not
# for a dependency's preinstall, install or postinstall, not for a bundled member's, not for an implicit native build (a binding.gyp
# with no script), not for the project's own seven install-time scripts. The fixture packages' scripts only append a line to one
# marker file.
#
# How the fixtures reach the lane. The lane takes registry artifacts from the canonical registry only, so a package served from
# 127.0.0.1 cannot go through the gate. This suite therefore runs what the lane runs, with the flags and the environment the lane
# gives them (lib/gate-lib.sh): the projection (`npm <verb> --package-lock-only --ignore-scripts ...`) in a scratch copy, then
# `safe-core project-bind` with the frozen `npm ci --ignore-scripts ...`, an `env -i` environment holding only PATH and HOME, and the
# target selection. The registry is a static local one (tests/live/fixture_registry.py). What that leaves unproven is the gate's own
# wiring around the binder (the hermetic suite pins the frozen command's flags and that the lane starts no other npm), and a
# canonical-registry artifact whose scripts a real publisher wrote.
#
# It also holds the measures the report's few sentences about running them rest on (npm 11.20.0 and 12.2.1, every npm call's exit status
# checked: an absence is asserted only after a success): for a package whose lockfile entry lacks hasInstallScript, `npm ci` and
# `npm rebuild <path>` run nothing for an install-time script (the one clause the report's command carries: npm can skip a script a
# lockfile entry does not declare); a bundled member's script runs when its host's path is rebuilt, also when the host has no script,
# and not by the member's own path; `npm run <event> --ignore-scripts` runs the event alone, for each of the seven events, also with
# ignore-scripts=true in the user configuration; and what `npm rebuild .` runs for the project's own scripts and binding.gyp (the report
# states a project's binding.gyp as a fact because that command is not one command: it also runs the project's postinstall, and on
# npm 12 nothing unless the policy allows).
#
# No test here ever runs a lifecycle script of a package from a real registry: scripts run only for this suite's own loopback fixtures.
#
# Controls, so that the suite can fail: the same project installed by plain `npm ci` with scripts on writes the markers (the
# dependency's, the bundled member's, the native build's and the project's own seven); and the binder given a frozen command without
# --ignore-scripts writes the dependencies' markers.
#
# Needs npm 11.20.0 and 12.2.1 under ~/.local/share/mise/installs/node (a missing build is skipped, said); nothing leaves the machine.
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
WORK="$(mktemp -d "${TMPDIR:-/tmp}/safe-live-noscripts.XXXXXX")" || exit 1
safe_test_compose_exit_trap "[[ -z \"\${REG_PID:-}\" ]] || kill \"\${REG_PID}\" 2>/dev/null; rm -rf -- \"\${WORK}\""
safe_core_test_prepare "${ROOT}" "${WORK}/safe-core" || { printf 'SKIP: safe-core cannot be built\n'; exit 0; }
CORE="${WORK}/safe-core"
command -v python3 >/dev/null 2>&1 || { printf 'SKIP: python3 is unavailable\n'; exit 0; }
MISE="${HOME_MISE_ROOT:-$(getent passwd "$(id -u)" | cut -d: -f6)/.local/share/mise/installs/node}"
declare -A NODE_OF=([11.20.0]=26.13.1 [12.2.1]=24.22.1)

MARKS="${WORK}/marks/marks.log"
mkdir -p "${WORK}/marks" "${WORK}/home" "${WORK}/state"
chmod 700 "${WORK}/state"
python3 -I "${ROOT}/tests/live/fixture_registry.py" "${WORK}/reg" "${MARKS}" > "${WORK}/port" &
REG_PID=$!
for _ in $(seq 1 50); do [[ -s "${WORK}/port" ]] && break; sleep 0.1; done
PORT="$(head -n 1 "${WORK}/port")"
[[ "${PORT}" =~ ^[0-9]+$ ]] || { printf 'SKIP: the fixture registry did not start\n'; exit 0; }

DEPS='"dep-install":"1.0.0","dep-all":"1.0.0","dep-bin":"1.0.0","dep-gyp":"1.0.0","dep-host":"1.0.0","dep-chain-a":"1.0.0"'
# the project's own seven, by a script file outside the project, so that they work wherever npm would run them (staging included): a run
# of any of them, in the lane's staging directory or after publication, would write its marker
printf "const fs=require('fs'),e=process.env;fs.appendFileSync(%s,['root',e.npm_lifecycle_event].join(' ')+'\\\\n');\n" "'${MARKS}'" > "${WORK}/marks/root.js"
ROOT_SCRIPTS="\"scripts\":{$(for e in preinstall install postinstall prepublish preprepare prepare postprepare; do printf '"%s":"node %s/marks/root.js",' "${e}" "${WORK}"; done | sed 's/,$//')}"

# the lane's npm environment: PATH and HOME only (safe_gate_lane_build_env, with nothing of the caller's to carry)
lane_env_file() { printf 'PATH=%s:/usr/local/bin:/usr/bin:/bin\0HOME=%s\0' "$1/bin" "${WORK}/home" > "${WORK}/env"; }
npm_in() { # <node dir> <cwd> <npm args…>
  local node="$1" cwd="$2"
  shift 2
  ( cd "${cwd}" && env -i HOME="${WORK}/home" PATH="${node}/bin:/usr/local/bin:/usr/bin:/bin" "${node}/bin/npm" "$@" )
}
# the arguments every npm command of the lane carries
dest() { [[ "${TAG}" != 12.* ]] || printf '%s\n' "--allow-remote=all"; printf '%s\n' "--git=/bin/false" "--allow-git=none" "--cache=${WORK}/npm-cache-${TAG}" "--logs-dir=${WORK}/npm-logs-${TAG}" "--logs-max=0" "--replace-registry-host=never" "--update-notifier=false"; }

new_project() { # <dir> <manifest members after name/version>
  rm -rf "$1"; mkdir -p "$1"
  printf 'registry=http://127.0.0.1:%s/\n' "${PORT}" > "$1/.npmrc"
  printf '{"name":"root","version":"1.0.0",%s}\n' "$2" > "$1/package.json"
  printf "const fs=require('fs'),e=process.env;fs.appendFileSync(%s,[e.npm_package_name,e.npm_lifecycle_event].join(' ')+'\\\\n');\n" "'${MARKS}'" > "$1/m.js"
}

# bind <node dir> <project> <judged dir> <frozen npm args…>: the lane's binder, for the judged files
bind() {
  local node="$1" project="$2" judged="$3" status
  shift 3
  local sel_os sel_cpu sel_libc
  sel_os="$("${node}/bin/node" -p 'process.platform')"; sel_cpu="$("${node}/bin/node" -p 'process.arch')"
  sel_libc=""; [[ "${sel_os}" != linux ]] || sel_libc="glibc"
  lane_env_file "${node}"
  "${CORE}" project-bind --project "${project}" --take-lock --state-dir "${WORK}/state" \
    --publish "package.json=${judged}/package.json" --publish "package-lock.json=${judged}/package-lock.json" \
    --copy ".npmrc=${project}/.npmrc" \
    --live "package.json=sha256:$(sha256sum "${project}/package.json" | cut -d' ' -f1)" \
    --live "package-lock.json=$([[ -f ${project}/package-lock.json ]] && echo "sha256:$(sha256sum "${project}/package-lock.json" | cut -d' ' -f1)" || echo absent)" \
    --live "npm-shrinkwrap.json=absent" --live ".npmrc=sha256:$(sha256sum "${project}/.npmrc" | cut -d' ' -f1)" \
    --env-file "${WORK}/env" --os "${sel_os}" --cpu "${sel_cpu}" ${sel_libc:+--libc "${sel_libc}"} \
    -- "${node}/bin/npm" "$@" > "${WORK}/bind.json" 2> "${WORK}/bind.err" </dev/null
}

# the projection of a verb in a scratch copy (what the lane resolves, with scripts off): prints the judged directory
project_verb() { # <node dir> <project> <verb> [args…]
  local node="$1" project="$2" verb="$3" judged="${WORK}/judged"
  shift 3
  rm -rf "${judged}"; mkdir -p "${judged}"
  cp "${project}/package.json" "${project}/.npmrc" "${judged}/"
  [[ ! -f "${project}/package-lock.json" ]] || cp "${project}/package-lock.json" "${judged}/"
  npm_in "${node}" "${judged}" "${verb}" --package-lock-only --ignore-scripts --no-audit --no-fund $(dest) "$@" >/dev/null 2>&1 || return 1
  printf '%s' "${judged}"
}

markers_absent() { [[ ! -s "${MARKS}" ]]; }
tree_has() { local project="$1" d; shift; for d in "$@"; do [[ -f "${project}/node_modules/${d}/package.json" ]] || return 1; done; }

lane_case() { # <version> <label> <verb> <setup>: runs the lane's way, asserts no marker and a verified tree
  local version="$1" label="$2" verb="$3" node="${MISE}/${NODE_OF[$1]}" project="${WORK}/proj" judged frozen_verb=ci
  : > "${MARKS}"
  case "${label}" in
    "install (bare)")
      new_project "${project}" "\"dependencies\":{${DEPS}},${ROOT_SCRIPTS}"
      judged="$(project_verb "${node}" "${project}" install)" || { fail "${version}: ${label}: the projection failed"; return; } ;;
    "install (naming a package)")
      new_project "${project}" "\"dependencies\":{\"dep-install\":\"1.0.0\"},${ROOT_SCRIPTS}"
      judged="$(project_verb "${node}" "${project}" install)" || { fail "${version}: ${label}: the base projection failed"; return; }
      cp "${judged}/package-lock.json" "${project}/package-lock.json"
      judged="$(project_verb "${node}" "${project}" install dep-host@1.0.0 dep-gyp@1.0.0 dep-all@1.0.0 dep-bin@1.0.0 dep-chain-a@1.0.0)" || { fail "${version}: ${label}: the projection failed"; return; } ;;
    "update")
      new_project "${project}" "\"dependencies\":{\"dep-update\":\"^1.0.0\",\"dep-host\":\"1.0.0\",\"dep-gyp\":\"1.0.0\"},${ROOT_SCRIPTS}"
      judged="$(project_verb "${node}" "${project}" install dep-update@1.0.0)" || { fail "${version}: ${label}: the base projection failed"; return; }
      cp "${judged}/package-lock.json" "${project}/package-lock.json"
      judged="$(project_verb "${node}" "${project}" update)" || { fail "${version}: ${label}: the projection failed"; return; }
      jq -e '.packages["node_modules/dep-update"].version == "1.0.1"' "${judged}/package-lock.json" >/dev/null || { fail "${version}: ${label}: the update did not move dep-update"; return; } ;;
    "ci")
      new_project "${project}" "\"dependencies\":{${DEPS}},${ROOT_SCRIPTS}"
      judged="$(project_verb "${node}" "${project}" install)" || { fail "${version}: ${label}: the projection failed"; return; }
      cp "${judged}/package-lock.json" "${project}/package-lock.json" ;;
  esac
  bind "${node}" "${project}" "${judged}" ci --ignore-scripts --no-audit --no-fund $(dest)
  status=$?
  if (( status != 0 )); then fail "${version}: ${label}: the binder exited ${status}: $(head -c 300 "${WORK}/bind.json") $(head -c 300 "${WORK}/bind.err")"; return; fi
  jq -e '.outcome == "published" and .verification.ok == true' "${WORK}/bind.json" >/dev/null 2>&1 || { fail "${version}: ${label}: not a verified publication: $(head -c 300 "${WORK}/bind.json")"; return; }
  # the tree is there (so that no marker is not an empty tree), bundled member, native-build package and bin package included
  case "${label}" in
    "update") tree_has "${project}" dep-update dep-host dep-host/node_modules/dep-bundled dep-gyp || { fail "${version}: ${label}: the tree lacks its packages"; return; } ;;
    *) tree_has "${project}" dep-install ${verb:+dep-host dep-host/node_modules/dep-bundled dep-gyp dep-all dep-bin dep-chain-a dep-chain-b} || { fail "${version}: ${label}: the tree lacks its packages"; return; } ;;
  esac
  if markers_absent; then pass "${version}: lane ${label}: verified tree published, no marker (no dependency, bundled member, native build or project script ran)"
  else fail "${version}: lane ${label}: a script ran: $(tr '\n' ';' < "${MARKS}")"; fi
}

control_case() { # <version>: the same fixtures with scripts ON write the markers (or the suite could not fail)
  local version="$1" node="${MISE}/${NODE_OF[$1]}" project="${WORK}/proj-control" judged extra=() want got
  : > "${MARKS}"
  new_project "${project}" "\"dependencies\":{${DEPS}},${ROOT_SCRIPTS}"
  judged="$(project_verb "${node}" "${project}" install)" || { fail "${version}: control: the projection failed"; return; }
  cp "${judged}/package-lock.json" "${project}/package-lock.json"
  [[ "${version}" != 12.* ]] || extra=(--dangerously-allow-all-scripts)
  if ! npm_in "${node}" "${project}" ci --no-audit --no-fund "${extra[@]}" $(dest) >"${WORK}/control.out" 2>&1; then
    fail "${version}: control: npm ci with scripts on exited ${?}: $(tail -n 2 "${WORK}/control.out" | tr '\n' ' ')"; return
  fi
  got="$(sort -u "${MARKS}" 2>/dev/null | tr '\n' ';')"
  for want in "dep-install install" "dep-all postinstall" "dep-host postinstall" "dep-bundled postinstall" "dep-gyp install" "dep-bin postinstall" "root preinstall" "root install" "root postinstall" "root prepublish" "root preprepare" "root prepare" "root postprepare"; do
    [[ "${got}" == *"${want};"* ]] || { fail "${version}: control (scripts on): no marker for ${want} (got ${got})"; return; }
  done
  pass "${version}: control: the same fixtures installed with scripts on write the markers (dependency, bundled member, native build, the project's seven)"
  # the binder given a frozen command without --ignore-scripts runs the dependencies' scripts
  : > "${MARKS}"
  new_project "${project}" "\"dependencies\":{${DEPS}}"
  judged="$(project_verb "${node}" "${project}" install)" || { fail "${version}: control: the second projection failed"; return; }
  cp "${judged}/package-lock.json" "${project}/package-lock.json"
  bind "${node}" "${project}" "${judged}" ci --no-audit --no-fund "${extra[@]}" $(dest)
  if [[ -s "${MARKS}" ]] && grep -q "^dep-install install$" "${MARKS}"; then pass "${version}: control: a frozen install without --ignore-scripts runs scripts (the suite detects the flag's absence)"
  else fail "${version}: control: the frozen install without --ignore-scripts wrote no marker: $(head -c 400 "${WORK}/bind.json") $(head -c 400 "${WORK}/bind.err")"; fi
}


# What the report says about running the scripts it names (measured on the lane's own published tree).
okrun() { # <label> <npm call…>: runs an npm call and fails the case unless it exits 0 (an absence of markers is no claim after a failure)
  local label="$1"
  shift
  "$@" >"${WORK}/okrun.out" 2>&1 || { fail "${label}: npm exited ${?}: $(tail -n 2 "${WORK}/okrun.out" | tr '\n' ' ')"; return 1; }
}
marks() { sort -u "${MARKS}" | tr '\n' ';'; }

claims_case() { # <version>
  local version="$1" node="${MISE}/${NODE_OF[$1]}" project="${WORK}/proj-claims" judged name flag expect got_ci got_rb extra=() ev
  [[ "${version}" != 12.* ]] || extra=(--dangerously-allow-all-scripts)
  # 1. a script-only package whose lockfile entry lacks hasInstallScript: npm ci and npm rebuild <path> run nothing (control: flag present)
  for flag in absent present; do
    name=dep-install
    new_project "${project}" "\"dependencies\":{\"${name}\":\"1.0.0\"}"
    judged="$(project_verb "${node}" "${project}" install)" || { fail "${version}: claims: the projection failed"; return; }
    if [[ "${flag}" == absent ]]; then
      jq -c 'del(.packages["node_modules/'"${name}"'"].hasInstallScript)' "${judged}/package-lock.json" > "${judged}/lock.new" && mv "${judged}/lock.new" "${judged}/package-lock.json"
    fi
    : > "${MARKS}"; rm -rf "${WORK}/proj-claims-ci"; mkdir -p "${WORK}/proj-claims-ci"
    cp "${project}/package.json" "${project}/.npmrc" "${WORK}/proj-claims-ci/"; cp "${judged}/package-lock.json" "${WORK}/proj-claims-ci/"
    okrun "${version}: claims ${flag}: npm ci" npm_in "${node}" "${WORK}/proj-claims-ci" ci --no-audit --no-fund "${extra[@]}" $(dest) || return
    got_ci="$(marks)"
    : > "${MARKS}"
    bind "${node}" "${project}" "${judged}" ci --ignore-scripts --no-audit --no-fund $(dest) || { fail "${version}: claims ${flag}: the binder failed"; return; }
    okrun "${version}: claims ${flag}: npm rebuild" npm_in "${node}" "${project}" rebuild "./node_modules/${name}" --no-audit --no-fund "${extra[@]}" $(dest) || return
    got_rb="$(marks)"
    if [[ "${flag}" == absent ]]; then expect=""; else expect="dep-install install;"; fi
    if [[ "${got_rb}" == "${expect}" && ( "${flag}" == present || -z "${got_ci}" ) ]]; then
      pass "${version}: ${name}, lockfile flag ${flag}: npm ci ran [${got_ci}] and npm rebuild on the lane's tree ran [${got_rb}], both exit 0"
    else
      fail "${version}: ${name}, lockfile flag ${flag}: npm ci ran [${got_ci}], npm rebuild ran [${got_rb}] (want rebuild [${expect}], and nothing from npm ci when the flag is absent)"
    fi
  done
  # 2. a bundled member's script runs when its host's path is rebuilt, also when the host has no script, and not by the member's own path
  new_project "${project}" "\"dependencies\":{\"dep-shell\":\"1.0.0\"}"
  judged="$(project_verb "${node}" "${project}" install)" || { fail "${version}: claims bundled: the projection failed"; return; }
  : > "${MARKS}"
  bind "${node}" "${project}" "${judged}" ci --ignore-scripts --no-audit --no-fund $(dest) || { fail "${version}: claims bundled: the binder failed"; return; }
  okrun "${version}: claims bundled: rebuild by the member's own path" npm_in "${node}" "${project}" rebuild ./node_modules/dep-shell/node_modules/dep-bundled --no-audit --no-fund "${extra[@]}" $(dest) || return
  got_ci="$(marks)"
  okrun "${version}: claims bundled: rebuild by the host's path" npm_in "${node}" "${project}" rebuild ./node_modules/dep-shell --no-audit --no-fund "${extra[@]}" $(dest) || return
  got_rb="$(marks)"
  if [[ -z "${got_ci}" && "${got_rb}" == "dep-bundled postinstall;" ]]; then pass "${version}: a bundled member's script (host without script) did not run by the member's own path [${got_ci}] and ran through the host's path [${got_rb}]"
  else fail "${version}: bundled member: own path ran [${got_ci}], host path ran [${got_rb}]"; fi
  # 3. `npm run <event> --ignore-scripts` runs the named event alone: each of the seven, with the user's configuration saying ignore-scripts=true
  local rootdir="${WORK}/proj-run" names=()
  for ev in preinstall install postinstall prepublish preprepare prepare postprepare; do names+=("${ev}" "pre${ev}" "post${ev}"); done
  rm -rf "${rootdir}"; mkdir -p "${rootdir}"
  printf '%s\n' "${names[@]}" | sort -u | jq -R --arg w "${WORK}" '{(.): ("node " + $w + "/marks/event.js")}' | jq -sc '{name:"root",version:"1.0.0",scripts:add}' > "${rootdir}/package.json"
  printf "const fs=require('fs');fs.appendFileSync(%s,process.env.npm_lifecycle_event+'\\\\n');\n" "'${MARKS}'" > "${WORK}/marks/event.js"
  printf 'ignore-scripts=true\n' > "${WORK}/home/.npmrc"
  local bad=""
  for ev in preinstall install postinstall prepublish preprepare prepare postprepare; do
    : > "${MARKS}"
    okrun "${version}: npm run ${ev}" npm_in "${node}" "${rootdir}" run "${ev}" --ignore-scripts || { rm -f "${WORK}/home/.npmrc"; return; }
    [[ "$(tr '\n' ' ' < "${MARKS}")" == "${ev} " ]] || bad="${bad} ${ev}=[$(tr '\n' ' ' < "${MARKS}")]"
  done
  : > "${MARKS}"; rm -f "${WORK}/home/.npmrc"
  okrun "${version}: npm run postinstall (control)" npm_in "${node}" "${rootdir}" run postinstall || return
  [[ "$(tr '\n' ' ' < "${MARKS}")" == "prepostinstall postinstall postpostinstall " ]] || bad="${bad} control=[$(tr '\n' ' ' < "${MARKS}")]"
  if [[ -z "${bad}" ]]; then pass "${version}: npm run <event> --ignore-scripts runs the named event alone, for each of the seven, with ignore-scripts=true in the user configuration (control: without the flag the pre- and post- hooks run too)"
  else fail "${version}: npm run <event> --ignore-scripts:${bad}"; fi
  # 4. what `npm rebuild .` runs for the project's own scripts and binding.gyp, on a published project (a lockfile and a tree built with scripts off)
  local shape id gyp script policy want got
  printf "const fs=require('fs');fs.appendFileSync(%s,['root',process.env.npm_lifecycle_event].join(' ')+'\\\\n');\n" "'${MARKS}'" > "${WORK}/marks/gyp.js"
  for shape in "a||" "b||postinstall" "c||install" "d|nogyp|postinstall"; do
    IFS='|' read -r id gyp script <<<"${shape}"
    rootdir="${WORK}/proj-root-${id}"; rm -rf "${rootdir}"; mkdir -p "${rootdir}"
    if [[ -n "${script}" ]]; then printf '{"name":"root","version":"1.0.0","scripts":{"%s":"node %s/marks/root.js"}}\n' "${script}" "${WORK}" > "${rootdir}/package.json"
    else printf '{"name":"root","version":"1.0.0"}\n' > "${rootdir}/package.json"; fi
    [[ "${gyp}" == nogyp ]] || printf '{"targets":[{"target_name":"x","type":"none","actions":[{"action_name":"mark","inputs":[],"outputs":["o"],"action":["node","%s/marks/gyp.js"]}]}]}\n' "${WORK}" > "${rootdir}/binding.gyp"
    okrun "${version}: root ${id}: lockfile" npm_in "${node}" "${rootdir}" install --package-lock-only --ignore-scripts --no-audit --no-fund || return
    okrun "${version}: root ${id}: tree" npm_in "${node}" "${rootdir}" ci --ignore-scripts --no-audit --no-fund || return
    for policy in plain allowed; do
      : > "${MARKS}"
      okrun "${version}: root ${id}: npm rebuild ." npm_in "${node}" "${rootdir}" rebuild . --no-audit --no-fund $([[ "${policy}" == allowed ]] && printf '%s' --dangerously-allow-all-scripts) || return
      got="$(marks)"
      case "${id}:${policy}:${version%%.*}" in
        a:*:11|a:allowed:12) want="root install;" ;;
        b:*:11|b:allowed:12) want="root install;root postinstall;" ;;
        c:*:11|c:allowed:12) want="root install;" ;;
        d:*:11|d:allowed:12) want="root postinstall;" ;;
        *) want="" ;;
      esac
      if [[ "${got}" == "${want}" ]]; then pass "${version}: npm rebuild . in a published project (binding.gyp: ${gyp:-yes}, script: ${script:-none}), policy ${policy}: ran [${got}]"
      else fail "${version}: npm rebuild . (shape ${id}, ${policy}) ran [${got}], want [${want}]"; fi
    done
  done
}

TAG=none
ran=0
for version in 11.20.0 12.2.1; do
  node="${MISE}/${NODE_OF[${version}]}"
  if [[ ! -x "${node}/bin/npm" ]] || [[ "$(PATH="${node}/bin:/usr/bin:/bin" npm --version 2>/dev/null)" != "${version}" ]]; then
    printf 'SKIP: npm %s is not installed under %s\n' "${version}" "${MISE}"
    continue
  fi
  ran=$((ran + 1))
  printf '# npm %s\n' "${version}"
  TAG="${version}"
  control_case "${version}"
  claims_case "${version}"
  for label in "install (bare)" "install (naming a package)" "update" "ci"; do lane_case "${version}" "${label}" "${label}"; done
done
(( ran > 0 )) || { printf 'SKIP: no npm build to run\n'; exit 0; }
printf '\n%d passed, %d failed\n' "${PASS}" "${FAIL}"
[[ "${FAIL}" -eq 0 ]]
