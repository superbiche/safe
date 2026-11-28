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
# Four scenarios, all through the checkout's gate:
#
#   A. the fleet chain. `npm` on PATH is a gate wrapper and the next candidate a
#      version manager's shim; the lane asks the real manager (`mise which`),
#      once, in the project, for node and npm and runs that pair directly.
#      the window of the lane's cooldown (install.cooldown_days, set to the days since <T1>, so
#      that its cutoff is T1) dates the whole invocation, so the projection resolves the
#      historical graph and the tree must equal it. (An invocation cannot be dated with
#      `npm_config_before`: the lane sets npm's release-age window on its own command line, which
#      outranks every `before`, and refuses a `before` it cannot honour.)
#
#   B. a delegate that answers differently per phase. A version manager's
#      installation reached the supported way (a shim on PATH, a manager that
#      names a FORWARDING launcher, the Node beside it a recording wrapper) dates
#      only the projection (the call that carries --package-lock-only) to <T1> and
#      runs everything else against the registry as it is NOW, logging every call. A lane that
#      resolved again at materialisation would install today's graph. The suite
#      captures the successful projection independently, then asserts: the final
#      npm command is `ci` exactly once and nothing else resolved outside the
#      dated projection; the lockfile published is that projection byte for
#      byte; the installed tree is it (strict verifier, npm's own record, and a
#      version-by-version read); and it is NOT today's resolution.
#
#   The negative controls (each must fail on the intended assertion ONLY, after a
#   set-up that itself succeeded): the same scenario B against a copy of the gate
#   whose frozen install is `update` (a resolving command); a second resolution
#   that gives the same graph; a launcher that exits 99 (the lane executes the
#   launcher the manager names, so the gate cannot succeed and the launcher ran).
#
# Only the npm registry is live. The advisory reader is a local stand-in that
# reports every identity as read completely with no advisory: the judging core
# is covered by the hermetic suite, and OSV must not make this probe flaky.
# Scenario R is the exception, on purpose (ticket 1884): it runs the REAL auditor of the checkout, end to end, with the real advisory reading over
# the network and no Socket credential (a `ci`, an install that names no root, a named root, and a named root in a home where Socket is not set up).
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
# The advisory reader and the operator-side doors are a stand-in written to a file of its own (tests/lib/lane_stand_in_auditor.sh): the
# hermetic contract suite holds it to the members of the real auditor's answers. Scenario R below runs the REAL auditor instead.
cp "${ROOT}/tests/lib/lane_stand_in_auditor.sh" "${WORK}/safe/bin/safe-audit"
chmod +x "${WORK}/safe/bin/safe-audit"
# The operator's canonical configuration (the switch is read from there only).
mkdir -p "${HOME}/.config/safe/run"
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null

# T1 dates the historical graph: the cooldown window is the number of days from T1 to now, plus one, so that the
# cutoff of npm's release-age filter is at (just before) T1 and every version of the graph is older than the window
T1="2025-04-02"
WINDOW=$(( ( $(date +%s) - $(date -u -d "${T1}" +%s) ) / 86400 + 1 ))
write_cooldown_config() { # <days>
  printf '{"install":{"project_lane":true,"cooldown_days":%s}}\n' "$1" > "${HOME}/.config/safe/run/config.json"
}
write_cooldown_config "${WINDOW}"
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
resolve() { # <dir> [--min-release-age=<days>]
  local dir="$1"
  shift
  ( cd "${dir}" && real_npm install express@5.1.0 --package-lock-only --ignore-scripts --no-audit --no-fund "$@" >"${dir}/resolve.log" 2>&1 ) || return 1
  jq -e '.packages["node_modules/express"].version == "5.1.0"' "${dir}/package-lock.json" >/dev/null
}
new_project "${WORK}/control" && new_project "${WORK}/independent" || { fail "the starting projects are written"; exit 1; }
# today's resolution under the window the lane runs everything but the dated projection with in scenario B (3 days)
if resolve "${WORK}/control" "--min-release-age=3"; then
  pass "the control resolution (now, 3-day window) succeeds and holds express@5.1.0"
else
  fail "the control resolution (now) succeeds: $(tail -n 3 "${WORK}/control/resolve.log")"
  exit 1
fi
if resolve "${WORK}/independent" "--min-release-age=${WINDOW}"; then
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
( cd "${WORK}/a" && SAFE_AUDIT_PATH="${WORK}/safe/bin/safe-audit" "${WORK}/safe/bin/safe" gate npm install express@5.1.0 --ignore-scripts \
    >"${WORK}/a.out" 2>"${WORK}/a.err" )
status=$?
sed 's/^/# A gate: /' "${WORK}/a.err" | tail -n 8
if (( status == 0 )) && cmp -s "${WORK}/a/package-lock.json" "${judged}"; then
  pass "A (fleet chain): the lane installs express@5.1.0 and publishes the independently captured projection byte for byte"
else
  fail "A (fleet chain): exit ${status}; lockfile $(cmp -s "${WORK}/a/package-lock.json" "${judged}" && echo equal || echo differs)"
fi

# --- scenario C: two commands in a row before a commit, on the real npm --------------
# The second starts from the lockfile the first judged and recorded (its lockfile is neither committed
# nor edited by hand), then a lockfile-only command publishes the files, installs no
# tree and advances the baseline again.
new_project "${WORK}/c" || { fail "scenario C project"; exit 1; }
gate_c() { ( cd "${WORK}/c" && SAFE_AUDIT_PATH="${WORK}/safe/bin/safe-audit" "${WORK}/safe/bin/safe" gate npm "$@" >"${WORK}/c.out" 2>"${WORK}/c.err" ); }
gate_c install express@5.1.0 --ignore-scripts
status=$?
if (( status == 0 )) && grep -q 'baseline: the lockfile committed' "${WORK}/c.err" && [[ -d "${WORK}/c/node_modules/express" ]] \
    && [[ -n "$(git -C "${WORK}/c" status --porcelain -- package-lock.json)" ]]; then
  pass "C1: the first command installs express and leaves its lockfile uncommitted"
else
  fail "C1: exit ${status}; $(tail -n 3 "${WORK}/c.err")"
fi
lock_after_first="$(sha256sum < "${WORK}/c/package-lock.json")"
gate_c install ms@2.1.3 --ignore-scripts
status=$?
if (( status == 0 )) && grep -q 'baseline: a lockfile safe judged clear and recorded' "${WORK}/c.err" \
    && ! grep -q 'the lockfile on disk is not the baseline' "${WORK}/c.err" \
    && [[ -d "${WORK}/c/node_modules/ms" && -d "${WORK}/c/node_modules/express" ]] \
    && [[ "$(sha256sum < "${WORK}/c/package-lock.json")" != "${lock_after_first}" ]]; then
  pass "C2: the second command starts from the lockfile the first judged and recorded and installs both"
else
  fail "C2: exit ${status}; $(tail -n 4 "${WORK}/c.err")"
fi
if "${WORK}/safe/bin/safe-core" project-tree "${selection[@]}" "${WORK}/c/package-lock.json" "${WORK}/c" 2>/dev/null | jq -e '.ok == true and .checked > 10' >/dev/null 2>&1; then
  pass "C3: the tree on disk is the lockfile the second command published (strict verifier)"
else
  fail "C3: the tree is not the published lockfile"
fi
lock_before_only="$(sha256sum < "${WORK}/c/package-lock.json")"
gate_c install ms@2.1.2 --ignore-scripts --package-lock-only
status=$?
if (( status == 0 )) && grep -q 'package-lock-only: the judged package.json and package-lock.json were published' "${WORK}/c.err" \
    && [[ "$(sha256sum < "${WORK}/c/package-lock.json")" != "${lock_before_only}" ]] \
    && jq -e '.packages["node_modules/ms"].version == "2.1.2"' "${WORK}/c/package-lock.json" >/dev/null 2>&1 \
    && [[ "$(jq -r .version "${WORK}/c/node_modules/ms/package.json")" == "2.1.3" ]]; then
  pass "C4: --package-lock-only publishes the judged files and leaves the installed tree alone"
else
  fail "C4: exit ${status}; $(tail -n 4 "${WORK}/c.err")"
fi
gate_c install ms@2.1.2 --ignore-scripts
status=$?
if (( status == 0 )) && grep -q 'baseline: a lockfile safe judged clear and recorded' "${WORK}/c.err" && [[ "$(jq -r .version "${WORK}/c/node_modules/ms/package.json")" == "2.1.2" ]]; then
  pass "C5: the next command starts from the lockfile-only result"
else
  fail "C5: exit ${status}; $(tail -n 4 "${WORK}/c.err")"
fi

# --- scenario D: `mise exec -- npm install` through the REAL mise is refused ----------------------
# The lane does not take `mise exec` over (mise would run the original command after an audit that binds
# nothing): the lane's line names the way out, and nothing is installed or written.
if real_mise_bin="$(command -v mise 2>/dev/null)" && [[ -n "${real_mise_bin}" ]]; then
  while IFS= read -r candidate; do
    LC_ALL=C head -n 2 -- "${candidate}" 2>/dev/null | grep -q '^# safe-gate-wrapper' && continue
    real_mise_bin="${candidate}"
    break
  done < <(type -a -p mise 2>/dev/null)
fi
if [[ -n "${real_mise_bin:-}" ]] && ! LC_ALL=C head -n 2 -- "${real_mise_bin}" 2>/dev/null | grep -q '^# safe-gate-wrapper'; then
  new_project "${WORK}/d" || { fail "scenario D project"; exit 1; }
  before_d="$(sha256sum "${WORK}/d/package.json" "${WORK}/d/package-lock.json" | cut -d' ' -f1 | tr '\n' ' ')"
  ( cd "${WORK}/d" && PATH="$(dirname -- "${real_mise_bin}"):${PATH}" SAFE_AUDIT_PATH="${WORK}/safe/bin/safe-audit" \
      "${WORK}/safe/bin/safe" gate mise exec -- npm install express@5.1.0 --ignore-scripts >"${WORK}/d.out" 2>"${WORK}/d.err" )
  status=$?
  sed 's/^/# D gate: /' "${WORK}/d.err" | tail -n 3
  if (( status == 100 )) && grep -q 'mise would run the original command after an audit that binds nothing' "${WORK}/d.err" \
      && grep -q 'run npm in the project directory instead' "${WORK}/d.err" && [[ ! -e "${WORK}/d/node_modules" ]] \
      && [[ "$(sha256sum "${WORK}/d/package.json" "${WORK}/d/package-lock.json" | cut -d' ' -f1 | tr '\n' ' ')" == "${before_d}" ]]; then
    pass "D (mise exec): the lane refuses with its line and the way out, and nothing is installed or written"
  else
    fail "D (mise exec): exit ${status}; $(tail -n 3 "${WORK}/d.err")"
  fi
else
  printf '# D (mise exec) skipped: no real mise on this machine\n'
fi

# --- scenarios E, F, G: ci, dedupe and prune on the REAL npm ------------------------------------------
# The fixtures are hand-written lockfiles of registry packages (integrity hashes read from the registry), so
# the plans are known in advance: E. a fresh clone's `npm ci`; F. a dedupe that needs doing; G. a prune that
# changes the lockfile, and one that changes only the tree.
MS_211='"node_modules/debug/node_modules/ms":{"version":"2.1.1","resolved":"https://registry.npmjs.org/ms/-/ms-2.1.1.tgz","integrity":"sha512-tgp+dl5cGk28utYktBsrFqA7HKgrhgPsg6Z/EfhWI4gl1Hwq8B/GmY/0oXZ6nF8hDVesS/FpnYaD/kOWhYQvyg=="}'
MS_213='"node_modules/ms":{"version":"2.1.3","resolved":"https://registry.npmjs.org/ms/-/ms-2.1.3.tgz","integrity":"sha512-6FlzubTLZG3J2a/NVCAleEhjzq5oxgHyaCU9yYXvcLsvoVaHJq/s5xXI6/XXP6tz7R9xAOtHnSO/tXtF3WRTlA=="}'
DEBUG_411='"node_modules/debug":{"version":"4.1.1","resolved":"https://registry.npmjs.org/debug/-/debug-4.1.1.tgz","integrity":"sha512-pYAIzeRo8J6KPEaJ0VWOh5Pzkbw/RetuzehGM7QRRX5he4fPHx2rdKMB256ehJCkX+XRQm16eZLqLNS8RSZXZw==","dependencies":{"ms":"^2.1.1"}}'
ISNUMBER_700='"node_modules/is-number":{"version":"7.0.0","resolved":"https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz","integrity":"sha512-41Cifkg6e8TylSpdtTpeLVMqvSBEVzTttHvERD741+pnZ8ANv0004MRL43QKPDlK9cGvNp6NZWZUBlbGXYxxng=="}'
fixture_project() { # <dir> <dependencies json> <packages entries (after the root)>
  mkdir -p "$1"
  ( cd "$1" || exit 1
    printf '{"name":"live-lane","version":"1.0.0","dependencies":%s}\n' "$2" > package.json
    printf '{"name":"live-lane","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"live-lane","version":"1.0.0","dependencies":%s},%s}}\n' "$2" "$3" > package-lock.json
    git init -q -b main && git add package.json package-lock.json && git -c user.name=lane -c user.email=lane@example.invalid commit -q -m base )
}
gate_in() { # <dir> <out prefix> <args...> : runs the checkout's gate in <dir>
  local dir="$1" out="$2"
  shift 2
  ( cd "${dir}" && SAFE_AUDIT_PATH="${WORK}/safe/bin/safe-audit" "${WORK}/safe/bin/safe" gate npm "$@" >"${out}.out" 2>"${out}.err" )
}

# E. ci in a fresh clone of a project whose committed lockfile carries an advisory
fixture_project "${WORK}/e-origin" '{"debug":"4.1.1","ms":"2.1.3"}' "${DEBUG_411},${MS_211},${MS_213}"
git clone -q "${WORK}/e-origin" "${WORK}/e1" && git clone -q "${WORK}/e-origin" "${WORK}/e2" && git clone -q "${WORK}/e-origin" "${WORK}/e3"
lock_e="$(sha256sum < "${WORK}/e1/package-lock.json")"
LIVE_ADVISORY_NAME=ms gate_in "${WORK}/e1" "${WORK}/e1" ci --ignore-scripts
status=$?
sed 's/^/# E gate: /' "${WORK}/e1.err" | tail -n 8
if (( status == 0 )) && grep -q 'npm ci: 3 entries of the lockfile checked for malice' "${WORK}/e1.err" && grep -q 'baseline: committed' "${WORK}/e1.err" \
    && grep -q '1 advisories already present (critical 1)' "${WORK}/e1.err" && [[ -d "${WORK}/e1/node_modules/debug/node_modules/ms" ]] \
    && [[ "$(sha256sum < "${WORK}/e1/package-lock.json")" == "${lock_e}" ]]; then
  pass "E1 (ci, fresh clone): installs without stopping on the advisory its committed lockfile carries, reports it, leaves the lockfile as committed"
else
  fail "E1 (ci, fresh clone): exit ${status}; $(tail -n 3 "${WORK}/e1.err")"
fi
if "${WORK}/safe/bin/safe-core" project-tree "${selection[@]}" "${WORK}/e1/package-lock.json" "${WORK}/e1" 2>/dev/null | jq -e '.ok == true and .checked >= 3' >/dev/null 2>&1; then
  pass "E2: the tree the real npm built is the lockfile (strict verifier)"
else
  fail "E2: the tree is not the lockfile"
fi
LIVE_MALWARE_NAME=debug gate_in "${WORK}/e2" "${WORK}/e2" ci --ignore-scripts
status=$?
if (( status == 104 )) && grep -q 'known-malware record on debug@4.1.1' "${WORK}/e2.err" && [[ ! -e "${WORK}/e2/node_modules" ]]; then
  pass "E3 (ci): a malware record anywhere in the graph refuses 104 and nothing is installed"
else
  fail "E3 (ci): exit ${status}; $(tail -n 2 "${WORK}/e2.err")"
fi
# the manifest moves, the lockfile does not: npm's own error, recognisable as npm's
jq '.dependencies.ms = "2.1.2"' "${WORK}/e3/package.json" > "${WORK}/e3/package.json.new" && mv "${WORK}/e3/package.json.new" "${WORK}/e3/package.json"
gate_in "${WORK}/e3" "${WORK}/e3" ci --ignore-scripts
status=$?
if (( status == 1 )) && grep -q 'npm: code EUSAGE' "${WORK}/e3.err" && grep -q 'in sync' "${WORK}/e3.err" && ! grep -q 'install-strategy' "${WORK}/e3.err" && grep -q "npm's own frozen check failed" "${WORK}/e3.err" && [[ ! -e "${WORK}/e3/node_modules" ]]; then
  pass "E4 (ci): a manifest out of step with its lockfile is npm's own error, with npm's diagnostic and status, and nothing is installed"
else
  fail "E4 (ci): exit ${status}; $(tail -n 3 "${WORK}/e3.err")"
fi

# F. dedupe: the real npm writes a changed plan on a fixture that needs deduplication
fixture_project "${WORK}/f" '{"debug":"4.1.1","ms":"2.1.3"}' "${DEBUG_411},${MS_211},${MS_213}"
mkdir -p "${WORK}/f-plan" && cp "${WORK}/f/package.json" "${WORK}/f/package-lock.json" "${WORK}/f-plan/"
( cd "${WORK}/f-plan" && real_npm dedupe --package-lock-only --ignore-scripts --no-audit --no-fund >"${WORK}/f-plan.log" 2>&1 )
if jq -e '(.packages | has("node_modules/debug/node_modules/ms")) | not' "${WORK}/f-plan/package-lock.json" >/dev/null 2>&1 \
    && jq -e 'has("node_modules/debug/node_modules/ms")' <<<"$(jq '.packages' "${WORK}/f/package-lock.json")" >/dev/null 2>&1 \
    && ! cmp -s "${WORK}/f/package-lock.json" "${WORK}/f-plan/package-lock.json"; then
  pass "F1: the real npm writes a CHANGED plan for dedupe on a fixture that needs it (the nested ms 2.1.1 is dropped from the lockfile)"
else
  fail "F1: the real npm's dedupe plan: $(tail -n 3 "${WORK}/f-plan.log")"
fi
gate_in "${WORK}/f" "${WORK}/f" dedupe --ignore-scripts
status=$?
sed 's/^/# F gate: /' "${WORK}/f.err" | tail -n 6
if (( status == 0 )) && cmp -s "${WORK}/f/package-lock.json" "${WORK}/f-plan/package-lock.json" && [[ -d "${WORK}/f/node_modules/debug" && ! -e "${WORK}/f/node_modules/debug/node_modules" ]] \
    && grep -q '0 packages added, 1 changed, 0 removed' "${WORK}/f.err"; then
  pass "F2 (dedupe): the lane publishes the plan the real npm made (byte for byte) and builds the tree from it by one frozen installation"
else
  fail "F2 (dedupe): exit ${status}; $(tail -n 3 "${WORK}/f.err")"
fi

# G. prune: (1) a lockfile that holds an entry nothing needs; (2) a tree that holds a package the lockfile lacks
fixture_project "${WORK}/g1" '{"ms":"2.1.3"}' "${ISNUMBER_700},${MS_213}"
mkdir -p "${WORK}/g1-plan" && cp "${WORK}/g1/package.json" "${WORK}/g1/package-lock.json" "${WORK}/g1-plan/"
( cd "${WORK}/g1-plan" && real_npm prune --package-lock-only --ignore-scripts --no-audit --no-fund >"${WORK}/g1-plan.log" 2>&1 )
if jq -e '(.packages | has("node_modules/is-number")) | not' "${WORK}/g1-plan/package-lock.json" >/dev/null 2>&1; then
  pass "G1: the real npm's prune drops from the lockfile an entry nothing needs"
else
  fail "G1: the real npm's prune plan: $(tail -n 3 "${WORK}/g1-plan.log")"
fi
gate_in "${WORK}/g1" "${WORK}/g1" prune --ignore-scripts
status=$?
sed 's/^/# G gate: /' "${WORK}/g1.err" | tail -n 5
if (( status == 0 )) && cmp -s "${WORK}/g1/package-lock.json" "${WORK}/g1-plan/package-lock.json" && [[ -d "${WORK}/g1/node_modules/ms" && ! -e "${WORK}/g1/node_modules/is-number" ]] \
    && grep -q '0 packages added, 0 changed, 1 removed' "${WORK}/g1.err"; then
  pass "G2 (prune, lockfile changed): the lane publishes npm's plan, nothing is introduced, the tree is the frozen installation of it"
else
  fail "G2 (prune): exit ${status}; $(tail -n 3 "${WORK}/g1.err")"
fi
fixture_project "${WORK}/g2" '{"ms":"2.1.3"}' "${MS_213}"
gate_in "${WORK}/g2" "${WORK}/g2-first" ci --ignore-scripts || fail "G3 set-up: ci"
mkdir -p "${WORK}/g2/node_modules/stray" && printf '{"name":"stray","version":"9.9.9"}\n' > "${WORK}/g2/node_modules/stray/package.json"
lock_g2="$(jq -S -c '.packages' "${WORK}/g2/package-lock.json")"
gate_in "${WORK}/g2" "${WORK}/g2" prune --ignore-scripts
status=$?
if (( status == 0 )) && [[ "$(jq -S -c '.packages' "${WORK}/g2/package-lock.json")" == "${lock_g2}" ]] && [[ ! -e "${WORK}/g2/node_modules/stray" && -d "${WORK}/g2/node_modules/ms" ]] \
    && grep -q '0 packages added, 0 changed, 0 removed' "${WORK}/g2.err"; then
  pass "G3 (prune, tree only): the lockfile's packages are unchanged (npm rewrites the file's formatting), nothing is introduced, and the frozen installation of the same lockfile yields the pruned tree"
else
  fail "G3 (prune, tree only): exit ${status}; lock $([[ "$(jq -S -c '.packages' "${WORK}/g2/package-lock.json")" == "${lock_g2}" ]] && echo same || echo changed); stray $([[ -e "${WORK}/g2/node_modules/stray" ]] && echo present || echo gone); $(grep -c '0 packages added, 0 changed, 0 removed' "${WORK}/g2.err") report lines; $(head -n 6 "${WORK}/g2.err" | tr '\n' '|')"
fi

# H. dedupe and prune on the REAL npm, against npm's own plan. Nothing stands in for npm's dedupe: when its
# lockfile-only run writes a lockfile that differs, that is the plan; when it writes none, the plan is the lockfile on
# disk, provided npm's own frozen check accepts it; no lockfile refuses. npm's own plan is computed independently of the
# lane, by `npm dedupe --dry-run --json` in an untouched copy (no tree), and the lane's published lockfile is compared with it.
npm_alone() { # <dir> <verb>: the real npm's lockfile-only run of the verb on a copy; prints entries or ABSENT or UNCHANGED
  local src="$1" verb="$2" tmp="${WORK}/alone-$(basename "$1")-$2"
  rm -rf "${tmp}"; mkdir -p "${tmp}"
  cp "${src}/package.json" "${tmp}/"; [[ ! -f "${src}/package-lock.json" ]] || cp "${src}/package-lock.json" "${tmp}/"
  ( cd "${tmp}" && real_npm "${verb}" --package-lock-only --ignore-scripts --no-audit --no-fund >/dev/null 2>&1 )
  if [[ ! -f "${tmp}/package-lock.json" ]]; then printf 'ABSENT'
  elif [[ -f "${src}/package-lock.json" ]] && cmp -s "${src}/package-lock.json" "${tmp}/package-lock.json"; then printf 'UNCHANGED'
  else printf 'entries=%s' "$(jq '[.packages | keys[] | select(test("node_modules/"))] | length' "${tmp}/package-lock.json")"; fi
}
native_plan() { # <dir>: what npm's own dedupe would install, sorted name@version lines (an untouched copy, no tree)
  local src="$1" tmp="${WORK}/native-$(basename "$1")"
  rm -rf "${tmp}"; mkdir -p "${tmp}"
  cp "${src}/package.json" "${src}/package-lock.json" "${tmp}/"
  ( cd "${tmp}" && real_npm dedupe --dry-run --json --long --ignore-scripts --no-audit --no-fund 2>/dev/null ) | jq -r '[.add[] | "\(.name)@\(.version)"] | sort | .[]' 2>/dev/null
}
published_plan() { # <dir>: the lockfile's entries, sorted name@version lines
  jq -r '[.packages | to_entries[] | select(.key | test("node_modules/")) | "\(.key | sub("^.*node_modules/"; ""))@\(.value.version)"] | sort | .[]' "$1/package-lock.json"
}
DEBUG_NESTED_MS="${DEBUG_411},${MS_211},${MS_213}"
fixture_project "${WORK}/h-dups" '{"debug":"4.1.1","ms":"2.1.3"}' "${DEBUG_411},${MS_211},${MS_213}"
fixture_project "${WORK}/h-overlap" '{"debug":"4.1.1","ms":"^2.1.0"}' "${DEBUG_411},${MS_211},${MS_213}"
fixture_project "${WORK}/h-nothing" '{"ms":"2.1.3"}' "${MS_213}"
fixture_project "${WORK}/h-surplus" '{"ms":"2.1.3"}' "${ISNUMBER_700},${MS_213}"
mkdir -p "${WORK}/h-nolock" && ( cd "${WORK}/h-nolock" && printf '{"name":"live-lane","version":"1.0.0","dependencies":{"ms":"2.1.3"}}\n' > package.json \
  && git init -q -b main && git add package.json && git -c user.name=lane -c user.email=lane@example.invalid commit -q -m base )
alone_dups="$(npm_alone "${WORK}/h-dups" dedupe)"; alone_overlap="$(npm_alone "${WORK}/h-overlap" dedupe)"; alone_surplus="$(npm_alone "${WORK}/h-surplus" dedupe)"
alone_nothing="$(npm_alone "${WORK}/h-nothing" dedupe)"; alone_nolock="$(npm_alone "${WORK}/h-nolock" dedupe)"
printf '# H: the real npm dedupe alone, lockfile-only: duplicates=%s overlap=%s surplus=%s nothing=%s no-lockfile=%s\n' "${alone_dups}" "${alone_overlap}" "${alone_surplus}" "${alone_nothing}" "${alone_nolock}"
if [[ "${alone_dups}" == entries=2 && "${alone_surplus}" == UNCHANGED && "${alone_nothing}" == UNCHANGED && "${alone_nolock}" == ABSENT ]]; then
  pass "H1: the real npm's dedupe writes its plan only when a name is duplicated (surplus entry kept, nothing to do, no lockfile: nothing written)"
else
  fail "H1: the real npm's dedupe alone: duplicates=${alone_dups} surplus=${alone_surplus} nothing=${alone_nothing} no-lockfile=${alone_nolock}"
fi
native_dups="$(native_plan "${WORK}/h-dups")"; native_overlap="$(native_plan "${WORK}/h-overlap")"; native_nothing="$(native_plan "${WORK}/h-nothing")"
for fx in dups overlap nothing; do
  gate_in "${WORK}/h-${fx}" "${WORK}/h-${fx}" dedupe --ignore-scripts
  status=$?
  sed "s/^/# H ${fx} gate: /" "${WORK}/h-${fx}.err" | tail -n 3
  native_var="native_${fx}"; ok=$(( status == 0 ))
  [[ "$(published_plan "${WORK}/h-${fx}")" == "${!native_var}" && -n "${!native_var}" ]] || ok=0
  "${WORK}/safe/bin/safe-core" project-tree "${selection[@]}" "${WORK}/h-${fx}/package-lock.json" "${WORK}/h-${fx}" 2>/dev/null | jq -e '.ok == true' >/dev/null 2>&1 || ok=0
  if (( ok )); then pass "H2 (${fx}): the lane's published lockfile is npm's own dedupe plan ($(tr '\n' ' ' <<<"${!native_var}")), and the tree is its frozen installation"
  else fail "H2 (${fx}): exit ${status}; native: $(tr '\n' ' ' <<<"${!native_var}") lane: $(published_plan "${WORK}/h-${fx}" | tr '\n' ' '); $(tail -n 2 "${WORK}/h-${fx}.err")"; fi
done
# the surplus entry: npm's dedupe leaves the lockfile alone and its frozen check accepts it, `npm ci` builds only what the
# manifest reaches, and the binder's verification refuses BEFORE anything is published, naming the cause and a way out
surplus_before="$(sha256sum < "${WORK}/h-surplus/package-lock.json")"
mkdir -p "${WORK}/h-surplus-ci" && cp "${WORK}/h-surplus/package.json" "${WORK}/h-surplus/package-lock.json" "${WORK}/h-surplus-ci/"
( cd "${WORK}/h-surplus-ci" && real_npm ci --ignore-scripts --no-audit --no-fund >/dev/null 2>&1 )
gate_in "${WORK}/h-surplus" "${WORK}/h-surplus" dedupe --ignore-scripts
status=$?
sed "s/^/# H surplus gate: /" "${WORK}/h-surplus.err" | tail -n 2
if [[ -d "${WORK}/h-surplus-ci/node_modules/ms" && ! -e "${WORK}/h-surplus-ci/node_modules/is-number" ]] && (( status == 100 )) \
    && grep -q 'node_modules/is-number: missing' "${WORK}/h-surplus.err" && grep -q 'run npm install first to refresh it' "${WORK}/h-surplus.err" \
    && grep -q 'nothing was published' "${WORK}/h-surplus.err" && [[ "$(sha256sum < "${WORK}/h-surplus/package-lock.json")" == "${surplus_before}" && ! -e "${WORK}/h-surplus/node_modules" ]]; then
  pass "H3 (surplus entry): the real npm ci builds only ms; the binder refuses before publishing, naming the missing entry and the way out; the project is as it was"
else
  fail "H3 (surplus entry): exit ${status}; $(tail -n 2 "${WORK}/h-surplus.err")"
fi
# no lockfile: dedupe and prune refuse 100 (npm would work from the installed tree, which the lane does not read)
for verb in dedupe prune; do
  rm -rf "${WORK}/h-nolock-${verb}"; mkdir -p "${WORK}/h-nolock-${verb}"; cp -r "${WORK}/h-nolock/." "${WORK}/h-nolock-${verb}/"
  gate_in "${WORK}/h-nolock-${verb}" "${WORK}/h-nolock-${verb}" "${verb}" --ignore-scripts
  status=$?
  if (( status == 100 )) && grep -q "npm ${verb} on a project with no lockfile" "${WORK}/h-nolock-${verb}.err" && grep -q 'run npm install first' "${WORK}/h-nolock-${verb}.err" \
      && [[ ! -e "${WORK}/h-nolock-${verb}/package-lock.json" && ! -e "${WORK}/h-nolock-${verb}/node_modules" ]]; then
    pass "H4 (${verb}, no lockfile): refused 100 with the way out; nothing was resolved or written"
  else
    fail "H4 (${verb}, no lockfile): exit ${status}; $(tail -n 2 "${WORK}/h-nolock-${verb}.err")"
  fi
done
# why: a lockless project with a RESIDENT tree. Native prune/dedupe keep the resident ms; a lockfile-only run in a copy without the tree resolves the latest
mkdir -p "${WORK}/h-resident/node_modules/ms" && printf '{"name":"live-lane","version":"1.0.0","dependencies":{"ms":"^2.0.0"}}\n' > "${WORK}/h-resident/package.json" \
  && printf '{"name":"ms","version":"2.0.0"}\n' > "${WORK}/h-resident/node_modules/ms/package.json"
( cd "${WORK}/h-resident" && git init -q -b main && git add package.json && git -c user.name=lane -c user.email=lane@example.invalid commit -q -m base )
native_resident="$( cd "${WORK}/h-resident" && real_npm prune --dry-run --json --ignore-scripts --no-audit --no-fund 2>/dev/null | jq -c '[.add, .change, .remove] | map(length)' )"
alone_resident="$(npm_alone "${WORK}/h-resident" prune)"
gate_in "${WORK}/h-resident" "${WORK}/h-resident" prune --ignore-scripts
status=$?
if [[ "${native_resident}" == '[0,0,0]' && "${alone_resident}" == entries=1 ]] && (( status == 100 )) && [[ "$(jq -r .version "${WORK}/h-resident/node_modules/ms/package.json")" == 2.0.0 ]]; then
  pass "H5: on a lockless project with a resident ms@2.0.0, the real npm's prune changes nothing while a lockfile-only run would resolve a newer ms: the lane refuses, the resident tree is untouched"
else
  fail "H5: native=${native_resident} lockfile-only=${alone_resident} exit ${status}"
fi
# out of step: npm saves nothing, its own frozen check refuses, and that is what the operator sees
fixture_project "${WORK}/h-step" '{"ms":"2.1.3"}' "${MS_213}"
jq '.dependencies.ms = "2.1.2"' "${WORK}/h-step/package.json" > "${WORK}/h-step/p.new" && mv "${WORK}/h-step/p.new" "${WORK}/h-step/package.json"
gate_in "${WORK}/h-step" "${WORK}/h-step" dedupe --ignore-scripts
status=$?
if (( status == 1 )) && grep -q 'npm: code EUSAGE' "${WORK}/h-step.err" && grep -q 'run npm install first' "${WORK}/h-step.err" && [[ ! -e "${WORK}/h-step/node_modules" ]]; then
  pass "H6 (dedupe, lockfile out of step): npm's own frozen check refuses with npm's diagnostic and status; the way out is npm install first"
else
  fail "H6: exit ${status}; $(tail -n 3 "${WORK}/h-step.err")"
fi
# prune keeps its plan (its lockfile-only run writes in every case where a lockfile exists)
fixture_project "${WORK}/h-prune-surplus" '{"ms":"2.1.3"}' "${ISNUMBER_700},${MS_213}"
p1="$(npm_alone "${WORK}/h-prune-surplus" prune)"
gate_in "${WORK}/h-prune-surplus" "${WORK}/h-prune-surplus" prune --ignore-scripts
status=$?
if [[ "${p1}" == entries=1 ]] && (( status == 0 )) && [[ ! -e "${WORK}/h-prune-surplus/node_modules/is-number" && -d "${WORK}/h-prune-surplus/node_modules/ms" ]]; then
  pass "H7 (prune, surplus entry): the real npm's prune writes the lockfile without it; the lane judges that plan and builds the tree"
else
  fail "H7: prune alone=${p1} exit ${status}; $(tail -n 2 "${WORK}/h-prune-surplus.err")"
fi
# npm does not resolve `clean` (the gate's conservative classifier takes it for ci): the lane does nothing with the
# project, and what happens is what the switch off does
fixture_project "${WORK}/h-clean" '{"ms":"2.1.3"}' "${MS_213}"
gate_in "${WORK}/h-clean" "${WORK}/h-clean-first" ci --ignore-scripts || fail "H8 set-up: ci"
mkdir -p "${WORK}/h-clean/node_modules/marker"; printf '{"name":"marker","version":"1.0.0"}\n' > "${WORK}/h-clean/node_modules/marker/package.json"
lock_h="$(sha256sum < "${WORK}/h-clean/package-lock.json")"
gate_in "${WORK}/h-clean" "${WORK}/h-clean" clean
status=$?
printf '{"install":{"project_lane":false}}\n' > "${HOME}/.config/safe/run/config.json"
gate_in "${WORK}/h-clean" "${WORK}/h-clean-off" clean
status_off=$?
printf '{"install":{"project_lane":true}}\n' > "${HOME}/.config/safe/run/config.json"
if (( status != 0 )) && (( status == status_off )) && cmp -s "${WORK}/h-clean.err" "${WORK}/h-clean-off.err" \
    && [[ -f "${WORK}/h-clean/node_modules/marker/package.json" && -d "${WORK}/h-clean/node_modules/ms" ]] \
    && [[ "$(sha256sum < "${WORK}/h-clean/package-lock.json")" == "${lock_h}" ]] && ! grep -q 'project lane' "${WORK}/h-clean.err"; then
  pass "H8 (npm clean): not the lane's, and not npm's to run (exit ${status}, as with the switch off); the tree and the lockfile are as they were"
else
  fail "H8 (npm clean): exit ${status} (switch off: ${status_off}); $(tail -n 3 "${WORK}/h-clean.err")"
fi
# an option before the verb: the form npm reads differently (`npm --json=prefix de`: npm takes `prefix` for the command) is
# refused by the gate's front door before the lane is reached, and an option whose value npm consumes is refused by the
# lane's own line, before npm is asked about the token; npm runs neither command
gate_in "${WORK}/h-clean" "${WORK}/h-opt" --json=prefix de
status=$?
if (( status == 100 )) && grep -q 'to allow: write the option without the value' "${WORK}/h-opt.err" && ! grep -q 'project lane' "${WORK}/h-opt.err" \
    && ! grep -q "${WORK}/h-clean" "${WORK}/h-opt.out" 2>/dev/null; then
  pass "H9 (option before the verb, npm reads another command): the front door refuses it in one line; npm did not run the command it would have taken (prefix)"
else
  fail "H9: exit ${status}; $(tail -n 2 "${WORK}/h-opt.err")"
fi
gate_in "${WORK}/h-clean" "${WORK}/h-opt2" --loglevel=error de
status=$?
if (( status == 100 )) && grep -q 'an option before the verb' "${WORK}/h-opt2.err" && grep -q '\[lane: project\]' "${WORK}/h-opt2.err"; then
  pass "H9b (option before the verb, its value consumed): the lane refuses it in its own form, before npm is asked about the token"
else
  fail "H9b: exit ${status}; $(tail -n 2 "${WORK}/h-opt2.err")"
fi

# I. npm's own errors, on the real npm, whatever the caller's presentation settings
FSEVENTS_233='"node_modules/fsevents":{"version":"2.3.3","resolved":"https://registry.npmjs.org/fsevents/-/fsevents-2.3.3.tgz","integrity":"sha512-5xoDfX+fL7faATnagmWPpbFtwh/R77WmMMqqHGS65C3vvB0YHrgF+B1YmZ3441tMj5n63k0212XNoJwzlhffQw==","os":["darwin"]}'
fixture_project "${WORK}/i-platform" '{"fsevents":"2.3.3"}' "${FSEVENTS_233}"
gate_in "${WORK}/i-platform" "${WORK}/i-platform" ci --ignore-scripts
status=$?
sed 's/^/# I platform gate: /' "${WORK}/i-platform.err" | tail -n 3
if (( status == 1 )) && grep -q 'npm: code EBADPLATFORM' "${WORK}/i-platform.err" && grep -q 'Unsupported platform for fsevents@2.3.3' "${WORK}/i-platform.err" \
    && grep -q "npm's own frozen check failed with npm exit 1 (code EBADPLATFORM)" "${WORK}/i-platform.err" && [[ ! -e "${WORK}/i-platform/node_modules" ]]; then
  pass "I1 (ci): a platform error on a synchronised project is shown as npm's EBADPLATFORM, with npm's status, and the final line names no other cause"
else
  fail "I1 (ci): exit ${status}; $(tail -n 3 "${WORK}/i-platform.err")"
fi
mkdir -p "${WORK}/i-nolock" && ( cd "${WORK}/i-nolock" && printf '{"name":"live-lane","version":"1.0.0","dependencies":{"ms":"2.1.3"}}\n' > package.json \
  && git init -q -b main && git add package.json && git -c user.name=lane -c user.email=lane@example.invalid commit -q -m base )
for setting in npm_config_loglevel=silly npm_config_heading=review-npm npm_config_color=always npm_config_loglevel=silent; do
  export "${setting?}"
  gate_in "${WORK}/i-nolock" "${WORK}/i-nolock" ci --ignore-scripts
  status=$?
  unset "${setting%%=*}"
  if (( status == 1 )) && grep -q 'npm: code EUSAGE' "${WORK}/i-nolock.err" && grep -q 'can only install with an existing package-lock.json' "${WORK}/i-nolock.err" \
      && ! grep -q 'install-strategy' "${WORK}/i-nolock.err" && grep -q "(code EUSAGE); npm's diagnostic is above" "${WORK}/i-nolock.err" && [[ ! -e "${WORK}/i-nolock/node_modules" ]]; then
    pass "I2 (ci, ${setting}): a missing lockfile still shows npm's code and explanation (usage text left out)"
  else
    fail "I2 (ci, ${setting}): exit ${status}; $(tail -n 3 "${WORK}/i-nolock.err")"
  fi
done

# --- scenario B: a delegate that answers differently per phase -----------------
# B needs the lane's own window to be the one the control resolved with: 3 days, explicit (the earlier scenarios set
# others). Only the dated projection (the recording wrapper below) is given the longer one.
write_cooldown_config 3
# An installation the lane follows the supported way (a launcher, the Node beside
# it, the npm-cli.js of the same installation) whose Node is a recording wrapper:
# the projection (the call that begins with --package-lock-only) is dated as of
# T1, everything else runs against the registry as it is NOW, and every call is
# logged. The projection the gate actually made is kept as it is.
# The launcher form the lane executes as it is (a): forwards to its sibling node on its
# own npm-cli.js. A fake version manager (marked shim + a real-manager stand-in on PATH)
# names it, as `mise which npm` does.
make_delegate() { # <dir> <launcher kind: forward|exit99>
  local d="$1" kind="$2"
  mkdir -p "${d}/bin" "${d}/lib/node_modules"
  if [[ "${kind}" == forward ]]; then
    printf '#!/usr/bin/env bash\nexec "$(dirname "$0")/node" "$(dirname "$0")/../lib/node_modules/npm/bin/npm-cli.js" "$@"\n' > "${d}/bin/npm"
  else
    printf '#!/bin/sh\ntouch "%s/launcher99.ran"\nexit 99\n' "${WORK}" > "${d}/bin/npm"
  fi
  cat > "${d}/bin/node" <<DELEGATE
#!/usr/bin/env bash
if [[ "\${1:-}" == */node_modules/npm/bin/npm-cli.js ]]; then
  printf '%s\\n' "\${*:2}" >> "${WORK}/delegate.log"
  if [[ "\${2:-}" == "--package-lock-only" ]]; then
    "${real_node_bin}" "\$@" "--min-release-age=${WINDOW}"
    status=\$?
    n=\$(ls "${WORK}"/captured-*.json 2>/dev/null | wc -l)
    [[ -f package-lock.json ]] && cp package-lock.json "${WORK}/captured-\$((n + 1)).json"
    exit \$status
  fi
fi
exec "${real_node_bin}" "\$@"
DELEGATE
  chmod +x "${d}/bin/npm" "${d}/bin/node"
  ln -sfn "${npm_dir}" "${d}/lib/node_modules/npm"
}
mkdir -p "${WORK}/shims" "${WORK}/realmise"
printf '#!/usr/bin/env bash\n# safe-gate-wrapper v1 tool=mise\nexit 97\n' > "${WORK}/shims/npm"
chmod +x "${WORK}/shims/npm"
cat > "${WORK}/realmise/mise" <<REALMISE
#!/usr/bin/env bash
if [[ "\${1:-}" == "which" ]]; then
  printf '%s/bin/%s\\n' "${WORK}/delegate" "\${2:-}"
  exit 0
fi
exit 98
REALMISE
chmod +x "${WORK}/realmise/mise"
make_delegate "${WORK}/delegate" forward

run_b() { # <name> <lib dir>
  local name="$1" lib="$2"
  new_project "${WORK}/${name}" || return 99
  : > "${WORK}/delegate.log"
  rm -f "${WORK}"/captured-*.json
  rm -rf "${WORK}/safe/lib"
  ln -s "${lib}" "${WORK}/safe/lib"
  ( cd "${WORK}/${name}" && PATH="${WORK}/shims:${WORK}/realmise:${PATH}" SAFE_AUDIT_PATH="${WORK}/safe/bin/safe-audit" \
      "${WORK}/safe/bin/safe" gate npm install express@5.1.0 --ignore-scripts >"${WORK}/${name}.out" 2>"${WORK}/${name}.err" )
  return $?
}
# The assertions of B, as a function: returns non-zero when any fails.
assert_b() { # <name>
  local name="$1" ok=0 dir="${WORK}/$1" log="${WORK}/delegate.log" captured calls
  # the ordered npm calls, configuration probes aside: exactly one resolution, then exactly one frozen install
  calls="$(grep -v '^config ' "${log}" | awk '/^--package-lock-only /{print "resolve"; next} /^ci --ignore-scripts --no-audit --no-fund /{print "ci"; next} {print "OTHER: " $0}' | tr '\n' ' ')"
  if [[ "${calls}" != "resolve ci " ]]; then echo "# the ordered npm calls are not exactly one resolution then exactly one frozen install: ${calls}"; ok=1; fi
  # the projection the gate actually made is what was published, byte for byte, and it is the independent one
  captured="${WORK}/captured-1.json"
  if [[ ! -f "${captured}" ]]; then echo "# no projection was captured"; ok=1
  else
    cmp -s "${dir}/package-lock.json" "${captured}" || { echo "# the published lockfile is not the projection the gate made"; ok=1; }
    cmp -s "${captured}" "${judged}" || { echo "# the projection the gate made is not the independently captured one"; ok=1; }
  fi
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

# --- the negative controls ------------------------------------------------------
# 1. a lane that resolves again at materialisation (its frozen install is `update`)
# 2. a lane that makes a SECOND resolution that gives the very same graph: every byte
#    published agrees, and only the ordered calls tell it
mkdir -p "${WORK}/broken-lib" "${WORK}/twice-lib"
cp -r "${ROOT}/lib/." "${WORK}/broken-lib/"
cp -r "${ROOT}/lib/." "${WORK}/twice-lib/"
ORDERED_MSG='not exactly one resolution then exactly one frozen install'
if grep -q 'frozen_args=(ci ' "${WORK}/broken-lib/gate-lib.sh"; then
  sed -i 's/frozen_args=(ci /frozen_args=(update /' "${WORK}/broken-lib/gate-lib.sh"
  run_b broken "${WORK}/broken-lib"
  status=$?
  problems="$(assert_b broken 2>&1)"
  # the set-up must have worked (npm ran to its end: the gate's own verifier then
  # refused the tree, publishing nothing) and the ordered-calls assertion must be
  # among those that failed
  if (( status == 100 )) && grep -q 'the installed tree differs from the judged lockfile' "${WORK}/broken.err" \
      && [[ "${problems}" == *"${ORDERED_MSG}: resolve OTHER: update"* ]]; then
    pass "the assertions of B fail, on the ordered calls, for a lane that resolves again at materialisation (and the gate's verifier refused its tree)"
  else
    fail "the resolving-materialisation control: gate exit ${status}, assertions said: ${problems:-nothing}"
  fi
else
  fail "the negative control cannot be built: frozen_args is not where it was"
fi
python3 -I - "${WORK}/twice-lib/gate-lib.sh" <<'PY' || fail "the second-resolution control cannot be built"
import sys
p = sys.argv[1]
s = open(p).read()
start = s.index('  safe_gate_lane_npm_in "${proj}" --package-lock-only')
end = s.index('|| rc=$?', start) + len('|| rc=$?')
block = s[start:end]
open(p, 'w').write(s[:start] + block + '\n' + block + s[end:])
PY
run_b twice "${WORK}/twice-lib"
status=$?
problems="$(assert_b twice 2>&1)"
if (( status == 0 )) && [[ "${problems}" == *"not exactly one resolution then exactly one frozen install: resolve resolve ci"* ]] \
    && ! grep -q 'published lockfile\|tree is not\|IS today' <<<"${problems}"; then
  pass "a second resolution that gives the same graph fails on the ordered-calls assertion alone"
else
  fail "the second-resolution control: gate exit ${status}, assertions said: ${problems}"
fi

# 3. the launcher the manager names is the one that runs: a launcher that exits 99 ends
#    the command and leaves its mark, and no assertion of B can pass on what it left
make_delegate "${WORK}/delegate99" exit99
rm -f "${WORK}/launcher99.ran"
sed -i "s|${WORK}/delegate|${WORK}/delegate99|" "${WORK}/realmise/mise"
run_b launcher99 "${ROOT}/lib"
status=$?
problems="$(assert_b launcher99 2>&1)"
if (( status != 0 )) && [[ -f "${WORK}/launcher99.ran" ]] && [[ "${problems}" == *"no projection was captured"* ]]; then
  pass "the launcher the manager names is the one the lane runs (an exit-99 launcher ran and ended the command, exit ${status})"
else
  fail "the exit-99 launcher control: gate exit ${status}, launcher ran: $([[ -f "${WORK}/launcher99.ran" ]] && echo yes || echo no), assertions said: ${problems:-nothing}"
fi

# --- scenario K: the scripts report on a real tree, through the real gate (ticket 1638) -----------------------------------------
# husky@4.3.8 (published 2021-01-15, far older than the cooldown window, so its graph is judged as of T1 like the others): a registry
# package that declares an `install` script (`node husky install`, which writes git hooks into the project's repository) and a
# `postinstall`. The lane runs neither; the section names the package, the script events and the command that runs them, and the
# project's repository holds no husky hook.
# There is NO control that runs the package's scripts, and there must never be one: this suite does not execute a registry package's
# lifecycle scripts (that would be an unaudited install running a stranger's code, outside the gate and against the operator's script
# policy). That scripts DO run when they are on, and that the absence of their effect can therefore fail, is held with safe's own
# loopback fixtures in tests/live/project_lane_no_scripts.sh; here the absence of hooks is asserted on what the package declares.
new_project "${WORK}/k" || { fail "scenario K project"; exit 1; }
# the project defines install-time scripts of its own (the lane never runs them; for an install that names a package it does not name them)
( cd "${WORK}/k" && jq -c '.scripts = {preinstall: "echo own-preinstall", postinstall: "echo own-postinstall"}' package.json > package.json.new && mv package.json.new package.json \
    && git add package.json && git -c user.name=lane -c user.email=lane@example.invalid commit -q -m scripts ) || { fail "scenario K: the project's own scripts are written"; exit 1; }
hooks_written() { # <repository>: the number of git hooks husky wrote
  local hook count=0
  for hook in "$1"/.git/hooks/*; do [[ -f "${hook}" ]] && grep -q husky "${hook}" 2>/dev/null && count=$((count + 1)); done
  printf '%s' "${count}"
}
gate_in "${WORK}/k" "${WORK}/k" install husky@4.3.8
status=$?
sed 's/^/# K gate: /' "${WORK}/k.err" | tail -n 5
if (( status == 0 )) && [[ -d "${WORK}/k/node_modules/husky" ]] \
    && grep -q 'install scripts did not run (the lane installs with scripts off): 1 introduced package(s) have install-time scripts or a binding.gyp on disk: husky@4.3.8 (install, postinstall)' "${WORK}/k.err" \
    && grep -q "scripts: to run them: npm rebuild ./node_modules/husky; npm decides what it runs: its own script policy applies, and it can skip a script that a lockfile entry does not declare" "${WORK}/k.err" \
    && ! grep -q "this project's own install-time scripts" "${WORK}/k.err"; then
  pass "K1: a lane install of husky@4.3.8 through the real gate names the package, its events and the command that runs them (and not the project's own scripts, which the project defines: the install names a package)"
else
  fail "K1: exit ${status}; $(tail -n 4 "${WORK}/k.err")"
fi
if (( status == 0 )) && jq -e '.scripts.install == "node husky install"' "${WORK}/k/node_modules/husky/package.json" >/dev/null 2>&1 \
    && [[ -d "${WORK}/k/.git/hooks" || -d "${WORK}/k/.git" ]] && [[ "$(hooks_written "${WORK}/k")" == 0 ]]; then
  pass "K2: the installed husky declares the install script that writes git hooks, and the project's repository holds none (no control runs a registry package's scripts; the loopback suite holds that scripts run when they are on)"
else
  fail "K2: husky hooks in the repository: $(hooks_written "${WORK}/k"); or the installed package no longer declares the script this scenario reads"
fi

# --- scenario L: the project scan as a report, through the real gate (ticket 1639) -----------------------------------------------
# The stand-in auditor beside the dispatcher implements `repo-audit`: it writes a result document with a critical finding in ANOTHER
# ecosystem and scanners that are not ok. The lane prints the scan's lines after the install and the status is the install's.
# (An earlier stand-in exited 0 for `repo-audit` and wrote nothing, which the lane read, correctly, as "left no readable result".)
new_project "${WORK}/l" || { fail "scenario L project"; exit 1; }
LIVE_SCAN_PYTHON_CRITICAL=2 LIVE_SCAN_PARTIAL=1 gate_in "${WORK}/l" "${WORK}/l" install semver@7.7.1
status=$?
sed 's/^/# L gate: /' "${WORK}/l.err" | tail -n 4
if (( status == 0 )) && [[ -d "${WORK}/l/node_modules/semver" ]] \
    && grep -qF 'safe: project lane: project scan: critical findings: python 2; detail: safe audit repo-audit .' "${WORK}/l.err" \
    && grep -qF 'safe: project lane: project scan: scanner coverage: osv-scanner partial, syft skipped; that coverage is missing' "${WORK}/l.err" \
    && ! grep -qF 'the lockfile it read is not the one this command published' "${WORK}/l.err" \
    && ! grep -qF 'did not complete' "${WORK}/l.err"; then
  pass "L1: a lane install of semver@7.7.1 through the real gate exits 0 and prints the scan's two lines (a critical finding in python, two scanners that are not ok)"
else
  fail "L1: exit ${status}; $(tail -n 4 "${WORK}/l.err")"
fi
# the document of THIS command: in the directory of its own project (the digest of the project's physical path), not the newest of any
report_key="$(cd -P -- "${WORK}/l" && printf %s "${PWD}" | sha256sum | cut -d' ' -f1)"
report_file="$(find "${SAFE_DATA_DIR}/project-lane/reports/${report_key}" -type f -name '*.json' 2>/dev/null | sort | tail -n 1)"
if [[ -n "${report_file}" ]] && "${WORK}/safe/bin/safe-core" project-report check "${report_file}" \
    && jq -e '.end == "published" and .passed == true and .status == 0 and .scan.status == "completed" and .scan.lockfile_published == true and .scan.summary.critical.python == 2
              and (.scan.summary.coverage_gaps | map(.scanner + ":" + .status) | sort) == ["osv-scanner:partial", "syft:skipped"]' "${report_file}" >/dev/null; then
  pass "L2: the document the real gate wrote checks, says published with status 0, and holds the scan's summary as typed values"
else
  fail "L2: the report document: ${report_file:-none}"
fi
new_project "${WORK}/l2" || { fail "scenario L project 2"; exit 1; }
LIVE_SCAN_EXIT=3 gate_in "${WORK}/l2" "${WORK}/l2" install semver@7.7.1
status=$?
if (( status == 0 )) && grep -qF 'safe: project lane: project scan: did not complete (it failed); the project'"'"'s other ecosystems were not reported' "${WORK}/l2.err"; then
  pass "L3: a scan that fails leaves the install's own status (0) and says so in one line"
else
  fail "L3: exit ${status}; $(tail -n 3 "${WORK}/l2.err")"
fi

# --- scenario J: the cooldown, on the real npm (ticket 1635) ---------------------------------------
# The window is WINDOW days (the cutoff is T1). npm's release-age filter is on every command line of the lane, so a bare
# install resolves nothing younger than the window and the report lists nothing young; a version the caller names exactly
# is excluded from the filter BY NAME (npm would refuse it with ETARGET and hide the wait), so safe's own reading is what
# refuses it, with the date; and a young version of the same name that nobody named, which npm's filter no longer sees
# either, is caught by the same reading. `semver` is the fixture: 7.7.1 is older than the window, 7.8.6 younger.
write_cooldown_config "${WINDOW}"
epoch() { date -u -d "$1" +%s; }
gate_e() { # <dir> <npm args...>: the gate with the real advisory-reader stand-in
  local dir="$1"
  shift
  ( cd "${dir}" && SAFE_AUDIT_PATH="${WORK}/safe/bin/safe-audit" "${WORK}/safe/bin/safe" gate npm "$@" >"${dir}.out" 2>"${dir}.err" )
}
sem_times="${WORK}/semver-packument.json"
if curl -fsS --max-time 60 https://registry.npmjs.org/semver -o "${sem_times}" \
    && jq -e '.time["7.7.1"] != null and .time["7.8.6"] != null and .time["5.7.2"] != null' "${sem_times}" >/dev/null 2>&1 \
    && (( $(epoch "$(jq -r '.time["7.7.1"]' "${sem_times}")") < $(date +%s) - WINDOW * 86400 )) \
    && (( $(epoch "$(jq -r '.time["7.8.6"]' "${sem_times}")") > $(date +%s) - WINDOW * 86400 )); then
  mkdir -p "${WORK}/j1" && ( cd "${WORK}/j1" && printf '{"name":"live-cooldown","version":"1.0.0","dependencies":{"semver":"^7.0.0"}}\n' > package.json \
    && git init -q -b main && git add package.json && git -c user.name=lane -c user.email=lane@example.invalid commit -q -m base )
  gate_e "${WORK}/j1" install --ignore-scripts
  status=$?
  got="$(jq -r '.packages["node_modules/semver"].version' "${WORK}/j1/package-lock.json" 2>/dev/null)"
  published="$(jq -r --arg v "${got}" '.time[$v] // empty' "${sem_times}")"
  latest7="$(jq -r '[.versions | keys[] | select(test("^7\\.[0-9]+\\.[0-9]+$"))] | map(split(".") | map(tonumber)) | sort | last | map(tostring) | join(".")' "${sem_times}")"
  if (( status == 0 )) && [[ -n "${published}" ]] && (( $(epoch "${published}") <= $(date +%s) - WINDOW * 86400 )) && [[ "${got}" != "${latest7}" ]] \
      && grep -q 'cooldown: .* introduced version(s) judged against the '"${WINDOW}"'-day window' "${WORK}/j1.err" && ! grep -q 'was published' "${WORK}/j1.err"; then
    pass "J1 (the filter): a bare install resolves semver ${got}, older than the ${WINDOW}-day window (not ${latest7}), and the report lists nothing young"
  else
    fail "J1 (the filter): exit ${status}, semver ${got:-none} (latest 7.x ${latest7}); $(tail -n 4 "${WORK}/j1.err")"
  fi

  new_project "${WORK}/j2" || { fail "scenario J2 project"; exit 1; }
  j2_before="$(sha256sum "${WORK}/j2/package.json" "${WORK}/j2/package-lock.json" | cut -d' ' -f1 | tr '\n' ' ')"
  gate_e "${WORK}/j2" install semver@7.8.6 --ignore-scripts
  status=$?
  if (( status == 100 )) && tail -n 1 "${WORK}/j2.err" | grep -qE '^safe: BLOCKED npm install \[lane: project\] — semver@7\.8\.6 was published 2026-11-02T17:05:43\.359Z and is inside the '"${WINDOW}"'-day cooldown; it becomes installable on 20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9:]{8}Z' \
      && ! grep -qiE 'notarget|ETARGET' "${WORK}/j2.err" \
      && [[ "$(sha256sum "${WORK}/j2/package.json" "${WORK}/j2/package-lock.json" | cut -d' ' -f1 | tr '\n' ' ')" == "${j2_before}" && ! -e "${WORK}/j2/node_modules" ]]; then
    pass "J2 (a named young version): excluded from npm's filter by name, so safe's own reading refuses it with the date it becomes installable (not npm's ETARGET); nothing was written"
  else
    fail "J2 (a named young version): exit ${status}; $(tail -n 3 "${WORK}/j2.err")"
  fi

  new_project "${WORK}/j3" || { fail "scenario J3 project"; exit 1; }
  gate_e "${WORK}/j3" install semver@5.7.2 npm-package-arg@12.0.0 --ignore-scripts
  status=$?
  if (( status == 100 )) && tail -n 1 "${WORK}/j3.err" | grep -qE '^safe: BLOCKED npm install \[lane: project\] — semver@7\.[0-9]+\.[0-9]+ was published .* and is inside the '"${WINDOW}"'-day cooldown' \
      && ! grep -q 'semver@5.7.2 was published' "${WORK}/j3.err"; then
    pass "J3 (another young version of an excluded name): semver is excluded by name for the named 5.7.2, and the young 7.x that npm-package-arg's dependency resolves to is caught by safe's own reading"
  else
    fail "J3 (another young version of an excluded name): exit ${status}; $(tail -n 3 "${WORK}/j3.err")"
  fi

  new_project "${WORK}/j4" || { fail "scenario J4 project"; exit 1; }
  ( cd "${WORK}/j4" && npm_config_before=2030-01-01 SAFE_AUDIT_PATH="${WORK}/safe/bin/safe-audit" "${WORK}/safe/bin/safe" gate npm install ms@2.1.3 --ignore-scripts >"${WORK}/j4.out" 2>"${WORK}/j4.err" )
  status=$?
  if (( status == 100 )) && grep -q 'a before date' "${WORK}/j4.err" && [[ ! -e "${WORK}/j4/node_modules" ]]; then
    pass "J4 (a configuration cannot widen the cooldown): a before date from the environment is read back from npm and refused"
  else
    fail "J4: exit ${status}; $(tail -n 2 "${WORK}/j4.err")"
  fi
else
  fail "J (the cooldown): the registry's semver packument is not what the scenario needs (7.7.1 older and 7.8.6 younger than the ${WINDOW}-day window)"
fi

# --- scenario R: the REAL auditor, end to end (ticket 1884) ---------------------------------------------------------------------------
# A to J give the gate a stand-in for the auditor. K gives it the auditor of this checkout, installed beside the dispatcher the way install.sh
# lays it out: the real advisory reading (OSV, over the network), the real Socket reader in a home where Socket is not set up (no tool, no
# credential), the real operator-store doors, the real project scan after a publication (the scanners are what this machine has; one that is
# missing is coverage the lane reports, never a refusal). Nothing here needs a Socket credential, and the lane installs with scripts off.
REAL="${WORK}/real"
mkdir -p "${REAL}/bin"
cp "${ROOT}/bin/safe" "${REAL}/bin/safe"
cp "${ROOT}/bin/safe-audit" "${REAL}/bin/safe-audit"
cp "${WORK}/safe/bin/safe-core" "${REAL}/bin/safe-core"
ln -s "${ROOT}/bin/safe-run" "${REAL}/bin/safe-run"
ln -s "${ROOT}/lib" "${REAL}/lib"
printf '{"install":{"project_lane":true}}\n' > "${HOME}/.config/safe/run/config.json"
gate_real() { # <dir> <args...>: the checkout's gate with the real auditor beside it, in <dir>
  local dir="$1"
  shift
  ( cd "${dir}" && env -u SOCKET_SECURITY_API_TOKEN -u SAFE_AUDIT_PATH -u SAFE_AUDIT_BIN -u SAFE_CONFIG_DIR -u SAFE_DATA_DIR -u SAFE_RUN_CONFIG_DIR -u SAFE_RUN_DATA_DIR -u SAFE_AUDIT_CONFIG_DIR -u SAFE_AUDIT_DATA_DIR "${REAL}/bin/safe" gate npm "$@" >"${dir}.out" 2>"${dir}.err" )
}
R_DEPS='{"ms":"2.1.3","is-number":"7.0.0"}'
R_ENTRIES="${MS_213},${ISNUMBER_700}"

fixture_project "${WORK}/r1" "${R_DEPS}" "${R_ENTRIES}"
gate_real "${WORK}/r1" ci --ignore-scripts
status=$?
sed 's/^/# R1 gate: /' "${WORK}/r1.err" | tail -n 6
if (( status == 0 )) && [[ -d "${WORK}/r1/node_modules/ms" && -d "${WORK}/r1/node_modules/is-number" ]] \
    && grep -qE 'evidence: [0-9]+ of [0-9]+ identities read completely' "${WORK}/r1.err" \
    && ! grep -q 'could not be read' "${WORK}/r1.err"; then
  pass "R1 (real auditor, npm ci): the lane completes, the advisory reading and the Socket cache are read, the tree is installed"
else
  fail "R1 (real auditor, npm ci): exit ${status}; $(tail -n 3 "${WORK}/r1.err")"
fi

fixture_project "${WORK}/r2" "${R_DEPS}" "${R_ENTRIES}"
gate_real "${WORK}/r2" install --ignore-scripts
status=$?
sed 's/^/# R2 gate: /' "${WORK}/r2.err" | tail -n 6
if (( status == 0 )) && [[ -d "${WORK}/r2/node_modules/ms" ]] && ! grep -q 'could not be read' "${WORK}/r2.err"; then
  pass "R2 (real auditor, an install that names no root): the lane completes and installs the tree"
else
  fail "R2 (real auditor, an install that names no root): exit ${status}; $(tail -n 3 "${WORK}/r2.err")"
fi

# A named root asks Socket, and this home has no Socket tool: the refusal and its way out are asserted as they are (the scenario does not make it pass).
fixture_project "${WORK}/r3" "${R_DEPS}" "${R_ENTRIES}"
k3_before="$(sha256sum "${WORK}/r3/package.json" "${WORK}/r3/package-lock.json" | cut -d' ' -f1 | tr '\n' ' ')"
gate_real "${WORK}/r3" install semver@7.5.4 --ignore-scripts
status=$?
sed 's/^/# R3 gate: /' "${WORK}/r3.err" | tail -n 4
if (( status == 0 )) && [[ -d "${WORK}/r3/node_modules/semver" ]] && grep -q 'semver@7.5.4: clear' "${WORK}/r3.err"; then
  pass "R3 (real auditor, a named root, Socket's mode auto): a version older than Socket's window is installed, its Socket reading is clear without a Socket call"
else
  fail "R3 (real auditor, a named root, Socket's mode auto): exit ${status}; $(tail -n 3 "${WORK}/r3.err")"
fi

# A named root with Socket asked for every named root (mode always) in a home where Socket is not set up: the refusal and its way out, as they are.
printf '{"install":{"project_lane":true,"socket":{"mode":"always"}}}\n' > "${HOME}/.config/safe/run/config.json"
fixture_project "${WORK}/r4" "${R_DEPS}" "${R_ENTRIES}"
r4_before="$(sha256sum "${WORK}/r4/package.json" "${WORK}/r4/package-lock.json" | cut -d' ' -f1 | tr '\n' ' ')"
gate_real "${WORK}/r4" install semver@7.5.4 --ignore-scripts
status=$?
sed 's/^/# R4 gate: /' "${WORK}/r4.err" | tail -n 2
if (( status == 102 )) && tail -n 1 "${WORK}/r4.err" | grep -qE '^safe: BLOCKED npm install \[lane: project\] — semver@7\.5\.4: audit infrastructure is unavailable \(not a package finding\); fix the infra \(socket login / wait / safe doctor\), then retry' \
    && [[ ! -e "${WORK}/r4/node_modules" ]] \
    && [[ "$(sha256sum "${WORK}/r4/package.json" "${WORK}/r4/package-lock.json" | cut -d' ' -f1 | tr '\n' ' ')" == "${r4_before}" ]]; then
  pass "R4 (real auditor, a named root, no Socket set up): refused 102 as audit-infrastructure breakage with its way out (socket login / wait / safe doctor); nothing installed, nothing written"
else
  fail "R4 (real auditor, a named root, no Socket set up): exit ${status}; $(tail -n 2 "${WORK}/r4.err")"
fi

printf '%s passed, %s failed\n' "${PASS}" "${FAIL}"
(( FAIL == 0 ))
