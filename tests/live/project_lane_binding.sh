#!/usr/bin/env bash
# LIVE suite (opt-in, network) — the project lane installs exactly what it
# judged, with the REAL npm, when the registry answers differently between the
# projection and the materialisation.
#
# Why this exists: the hermetic install suite stubs npm. The claim of spec 1625
# ("the tree on disk after the command is the graph that was judged") is a claim
# about npm: that the frozen install of the judged lockfile cannot resolve
# again, and that safe's strict verifier accepts the tree npm really produces
# (staged in a directory of the project, published once verified).
#
# Two scenarios, both through the checkout's gate:
#
#   A. the fleet chain. `npm` on PATH is a gate wrapper and the next candidate a
#      version manager's shim; the lane asks the real manager (`mise which`),
#      once, in the project, for node and npm and runs that pair directly.
#      npm's `before` date dates the whole invocation, so the projection
#      resolves the historical graph and the tree must equal it.
#
#   B. a delegate that answers differently per phase. An unmarked `npm` on PATH
#      (what the gate's delegate resolves to) dates only the projection (the
#      call that carries --package-lock-only) to <T1> and runs everything else
#      against the registry as it is NOW, logging every call. A lane that
#      resolved again at materialisation would install today's graph. The suite
#      captures the successful projection independently, then asserts: the final
#      npm command is `ci` exactly once and nothing else resolved outside the
#      dated projection; the lockfile published is that projection byte for
#      byte; the installed tree is it (strict verifier, npm's own record, and a
#      version-by-version read); and it is NOT today's resolution.
#
#   The negative control: the same scenario B against a copy of the gate whose
#   frozen install is `update` (a resolving command) must FAIL its assertions.
#
# Only the npm registry is live. The advisory reader is a local stand-in that
# reports every identity as read completely with no advisory: the judging core
# is covered by the hermetic suite, and OSV must not make this probe flaky.
#
# Run it explicitly: SAFE_LIVE_NETWORK=1 bash tests/live/project_lane_binding.sh
# (excluded from tests/run-all.sh because it makes real network calls).
set -uo pipefail

# SAFE_TEST_ISOLATION_MARKER: every suite owns a scratch HOME and safe state.
# shellcheck source=tests/lib/test-isolation.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/test-isolation.sh"
export SAFE_TEST_ISOLATION_KEEP_TOOLS=1
safe_test_setup_isolation || exit 1

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
PASS=0
FAIL=0
pass() { printf 'ok - %s\n' "$1"; PASS=$((PASS + 1)); }
fail() { printf 'FAIL - %s\n' "$1"; FAIL=$((FAIL + 1)); }

if [[ "${SAFE_LIVE_NETWORK:-}" != "1" ]]; then
  printf 'SKIP: project_lane_binding makes real registry calls; set SAFE_LIVE_NETWORK=1 to run it\n'
  exit 0
fi
for tool in jq git curl flock; do
  command -v "${tool}" >/dev/null 2>&1 || { printf 'SKIP: %s is unavailable\n' "${tool}"; exit 0; }
done

# The genuine node and npm, found the way the gate finds them: a real npm on
# PATH, or the real version manager's answer (`mise which`) behind a shim, or
# SAFE_LIVE_NPM.
real_npm_bin=""
real_node_bin=""
while IFS= read -r candidate; do
  [[ -x "${candidate}" ]] || continue
  head=$(LC_ALL=C head -n 2 -- "${candidate}" 2>/dev/null)
  if grep -q '^# safe-gate-wrapper' <<<"${head}"; then
    if grep -q 'tool=mise' <<<"${head}" && [[ -z "${real_npm_bin}" ]]; then
      while IFS= read -r m; do
        [[ -x "${m}" ]] || continue
        LC_ALL=C head -n 2 -- "${m}" 2>/dev/null | grep -q '^# safe-gate-wrapper' && continue
        real_npm_bin="$("${m}" which npm 2>/dev/null)" && real_node_bin="$("${m}" which node 2>/dev/null)" && break
        real_npm_bin=""
      done < <(type -a -p mise 2>/dev/null)
    fi
    [[ -n "${real_npm_bin}" ]] && break
    continue
  fi
  real_npm_bin="${candidate}"
  break
done < <(type -a -p npm 2>/dev/null)
if [[ -z "${real_npm_bin}" && -n "${SAFE_LIVE_NPM:-}" && -x "${SAFE_LIVE_NPM}" ]]; then
  real_npm_bin="${SAFE_LIVE_NPM}"
fi
[[ -n "${real_node_bin}" ]] || real_node_bin="$(dirname -- "${real_npm_bin}")/node"
if [[ -z "${real_npm_bin}" || ! -x "${real_node_bin}" ]]; then
  printf 'SKIP: no real npm and node available (set SAFE_LIVE_NPM to name an npm)\n'
  exit 0
fi
npm_dir="$(cd -- "$(dirname -- "${real_npm_bin}")/../lib/node_modules/npm" 2>/dev/null && pwd -P)" \
  || npm_dir="$(cd -- "$(dirname -- "$(realpath -- "${real_npm_bin}")")/.." && pwd -P)"
npm_cli="${npm_dir}/bin/npm-cli.js"
[[ -f "${npm_cli}" ]] || { printf 'SKIP: npm-cli.js not found for %s\n' "${real_npm_bin}"; exit 0; }
real_npm() { env PATH="$(dirname -- "${real_node_bin}"):${PATH}" "${real_node_bin}" "${npm_cli}" "$@"; }
printf '# npm: %s (%s), node: %s\n' "${real_npm_bin}" "$(real_npm --version 2>/dev/null || printf '?')" "${real_node_bin}"
if ! curl -fsS --max-time 15 -o /dev/null https://registry.npmjs.org/express; then
  printf 'SKIP: the npm registry is not reachable\n'
  exit 0
fi

# shellcheck source=tests/lib/real-tool.sh
source "${ROOT}/tests/lib/real-tool.sh"
if ! GO_BIN="$(real_tool go)"; then
  printf 'SKIP: Go is unavailable; safe-core cannot be built\n'
  exit 0
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/safe-live-lane.XXXXXX")" || exit 1
safe_test_compose_exit_trap "rm -rf -- \"\${WORK}\""
mkdir -p "${WORK}/safe/bin" "${WORK}/control" "${WORK}/independent" "${WORK}/delegate"
cp "${ROOT}/bin/safe" "${WORK}/safe/bin/safe"
ln -s "${ROOT}/bin/safe-run" "${WORK}/safe/bin/safe-run"
ln -s "${ROOT}/lib" "${WORK}/safe/lib"
if ! ( cd "${ROOT}" && "${GO_BIN}" build -trimpath -ldflags "-X main.version=$(tr -d '[:space:]' < VERSION)" \
    -o "${WORK}/safe/bin/safe-core" ./cmd/safe-core ); then
  fail "safe-core builds"
  exit 1
fi
cat > "${WORK}/safe/bin/safe-audit" <<'AUDIT'
#!/usr/bin/env bash
if [[ "${1:-}" == "scanner-batch" ]]; then
  jq -c '{schema_version: 1, policy: {block_severities: ["critical"]},
          identities: [.packages[] | {name, version, coverage: "complete", gap: "", advisories: []}],
          blocklist: []}'
  exit 0
fi
exit 0
AUDIT
chmod +x "${WORK}/safe/bin/safe-audit"
# The operator's canonical configuration (the switch is read from there only).
mkdir -p "${HOME}/.config/safe/run"
printf '{"install":{"project_lane":true}}\n' > "${HOME}/.config/safe/run/config.json"
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null

T1="2025-04-02"
entries() { jq -r '.packages | to_entries[] | select(.key | test("node_modules/")) | "\(.key)@\(.value.version)"' "$1" | LC_ALL=C sort; }

# A starting project: no dependency, the lockfile npm writes for it, committed.
new_project() { # <dir>
  mkdir -p "$1"
  ( cd "$1" || exit 1
    printf '{"name":"live-lane","version":"1.0.0"}\n' > package.json
    real_npm install --package-lock-only --ignore-scripts --no-audit --no-fund >/dev/null 2>&1 || exit 1
    git init -q -b main && git add package.json package-lock.json \
      && git -c user.name=lane -c user.email=lane@example.invalid commit -q -m base )
}

# Both resolutions must succeed and carry the requested root; a control that
# failed would make "the registry answers differently" vacuously true.
resolve() { # <dir> [--before=<date>]
  local dir="$1"
  shift
  ( cd "${dir}" && real_npm install express@5.1.0 --package-lock-only --ignore-scripts --no-audit --no-fund "$@" >"${dir}/resolve.log" 2>&1 ) || return 1
  jq -e '.packages["node_modules/express"].version == "5.1.0"' "${dir}/package-lock.json" >/dev/null
}
new_project "${WORK}/control" && new_project "${WORK}/independent" || { fail "the starting projects are written"; exit 1; }
if resolve "${WORK}/control"; then
  pass "the control resolution (now) succeeds and holds express@5.1.0"
else
  fail "the control resolution (now) succeeds: $(tail -n 3 "${WORK}/control/resolve.log")"
  exit 1
fi
if resolve "${WORK}/independent" "--before=${T1}"; then
  pass "the independent projection (as of ${T1}) succeeds and holds express@5.1.0"
else
  fail "the independent projection (as of ${T1}) succeeds: $(tail -n 3 "${WORK}/independent/resolve.log")"
  exit 1
fi
judged="${WORK}/independent/package-lock.json"
entries "${judged}" > "${WORK}/judged.txt"
entries "${WORK}/control/package-lock.json" > "${WORK}/now.txt"
differing="$(LC_ALL=C comm -3 "${WORK}/judged.txt" "${WORK}/now.txt" | wc -l)"
if (( differing > 0 )); then
  pass "the registry answers differently now: ${differing} lockfile lines differ between the judged graph and what a resolving command gives today"
else
  fail "the fixture is vacuous: the registry answers today as it did at ${T1}"
  exit 1
fi

selection=(--os "$("${real_node_bin}" -p 'process.platform')" --cpu "$("${real_node_bin}" -p 'process.arch')")

# --- scenario A: the fleet chain, the whole invocation dated -------------------
new_project "${WORK}/a" || { fail "scenario A project"; exit 1; }
( cd "${WORK}/a" && npm_config_before="${T1}" SAFE_AUDIT_PATH="${WORK}/safe/bin/safe-audit" "${WORK}/safe/bin/safe" gate npm install express@5.1.0 --ignore-scripts \
    >"${WORK}/a.out" 2>"${WORK}/a.err" )
status=$?
sed 's/^/# A gate: /' "${WORK}/a.err" | tail -n 8
if (( status == 0 )) && cmp -s "${WORK}/a/package-lock.json" "${judged}"; then
  pass "A (fleet chain): the lane installs express@5.1.0 and publishes the independently captured projection byte for byte"
else
  fail "A (fleet chain): exit ${status}; lockfile $(cmp -s "${WORK}/a/package-lock.json" "${judged}" && echo equal || echo differs)"
fi

# --- scenario B: a delegate that answers differently per phase -----------------
# The delegate's dating is by what is asked: the projection (the call that begins
# with --package-lock-only) as of T1, everything else as of now; every call is
# logged.
cat > "${WORK}/delegate/npm" <<DELEGATE
#!/usr/bin/env bash
printf '%s\\n' "\$*" >> "${WORK}/delegate.log"
# the projection itself (its first argument), not a configuration probe
if [[ "\${1:-}" == "--package-lock-only" ]]; then
  set -- "\$@" "--before=${T1}"
fi
exec "${real_node_bin}" "${npm_cli}" "\$@"
DELEGATE
chmod +x "${WORK}/delegate/npm"
ln -sf "${real_node_bin}" "${WORK}/delegate/node"
# The lane finds npm's own platform module beside the npm it was given: here, in
# the directory above the delegate.
ln -sfn "${npm_dir}/node_modules" "${WORK}/node_modules"

run_b() { # <name> <lib dir>
  local name="$1" lib="$2"
  new_project "${WORK}/${name}" || return 99
  : > "${WORK}/delegate.log"
  rm -rf "${WORK}/safe/lib"
  ln -s "${lib}" "${WORK}/safe/lib"
  ( cd "${WORK}/${name}" && PATH="${WORK}/delegate:${PATH}" SAFE_AUDIT_PATH="${WORK}/safe/bin/safe-audit" \
      "${WORK}/safe/bin/safe" gate npm install express@5.1.0 --ignore-scripts >"${WORK}/${name}.out" 2>"${WORK}/${name}.err" )
  return $?
}
# The assertions of B, as a function: returns non-zero when any fails.
assert_b() { # <name>
  local name="$1" ok=0 dir="${WORK}/$1" log="${WORK}/delegate.log"
  if cmp -s "${dir}/package-lock.json" "${judged}"; then :; else echo "# the published lockfile is not the captured projection"; ok=1; fi
  # the final npm command: ci, once, with scripts off; nothing else resolved outside the dated projection
  if [[ "$(grep -c '^ci --ignore-scripts --no-audit --no-fund ' "${log}")" != "1" ]]; then echo "# the frozen install was not 'ci' exactly once: $(grep -v '^config' "${log}" | cut -c1-80 | tr '\n' '|')"; ok=1; fi
  if grep -v '^config ' "${log}" | grep -v -e '^ci ' -e '^--package-lock-only ' | grep -q .; then echo "# npm resolved outside the dated projection: $(grep -v '^config ' "${log}" | grep -v -e '^ci ' -e '^--package-lock-only ' | head -2 | tr '\n' '|')"; ok=1; fi
  # the tree is the judged lockfile (strict verifier), npm's own record agrees, and it is not today's graph
  if ! "${WORK}/safe/bin/safe-core" project-tree "${selection[@]}" "${judged}" "${dir}" 2>/dev/null | jq -e '.ok == true and .checked > 10' >/dev/null 2>&1; then echo "# the tree is not the judged lockfile"; ok=1; fi
  if [[ -f "${dir}/node_modules/.package-lock.json" ]]; then
    entries "${dir}/node_modules/.package-lock.json" > "${WORK}/${name}.installed.txt"
    cmp -s "${WORK}/${name}.installed.txt" "${WORK}/judged.txt" || { echo "# npm's record differs from the judged graph"; ok=1; }
    ! cmp -s "${WORK}/${name}.installed.txt" "${WORK}/now.txt" || { echo "# the installed graph IS today's resolution"; ok=1; }
  else
    echo "# npm left no record of what it installed"; ok=1
  fi
  return "${ok}"
}

run_b b "${ROOT}/lib"
status=$?
sed 's/^/# B gate: /' "${WORK}/b.err" | tail -n 5
if (( status == 0 )) && problems="$(assert_b b)"; then
  pass "B (per-phase registry): the final npm command is ci once, the lockfile published is the captured projection, the tree is it and not today's"
else
  fail "B (per-phase registry): exit ${status} ${problems:-}"
fi
if compgen -G "${WORK}/b/.safe-bind-*" >/dev/null; then fail "a staging directory is left in the project"; else pass "no staging directory is left in the project"; fi
flock -n -x "${WORK}/b" true && pass "the project lock was released" || fail "the project lock was not released"

# --- the negative control: a lane that resolves again at materialisation -------
mkdir -p "${WORK}/broken-lib"
cp -r "${ROOT}/lib/." "${WORK}/broken-lib/"
if grep -q 'frozen_args=(ci ' "${WORK}/broken-lib/gate-lib.sh"; then
  sed -i 's/frozen_args=(ci /frozen_args=(update /' "${WORK}/broken-lib/gate-lib.sh"
  run_b broken "${WORK}/broken-lib"
  status=$?
  if (( status == 0 )) && assert_b broken >"${WORK}/broken.problems"; then
    fail "the assertions of B cannot tell a lane that resolves again at materialisation (it passed)"
  else
    pass "the assertions of B fail on a lane that resolves again at materialisation ($(head -n 1 "${WORK}/broken.problems" 2>/dev/null || echo "gate exit ${status}"))"
  fi
else
  fail "the negative control cannot be built: frozen_args is not where it was"
fi

printf '%s passed, %s failed\n' "${PASS}" "${FAIL}"
(( FAIL == 0 ))
