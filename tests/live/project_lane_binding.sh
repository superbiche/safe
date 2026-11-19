#!/usr/bin/env bash
# LIVE suite (opt-in, network) — the project lane installs exactly what it
# judged, with the REAL npm reached the way the fleet reaches it, when the
# registry answers differently between the projection and a resolving command.
#
# Why this exists: the hermetic install suite stubs npm. The claim of spec 1625
# ("the tree on disk after the command is the graph that was judged") is a claim
# about npm: that the frozen install of the judged lockfile cannot resolve
# again, and that safe's strict verifier accepts the tree npm really produces
# (staged in a directory of the project, published once verified). Only the
# real npm can attest both.
#
# The npm is the one the gate's delegate would run. On a fleet machine `npm` on
# PATH is a gate wrapper and the next candidate is a version manager's shim that
# routes back into the gate: the suite puts neither of them out of the way. The
# checkout's gate resolves the real mise under argv0 npm itself (the lane's one
# npm); this suite reaches the same binary the same way for its independent
# runs. If no such chain exists the suite names a genuine npm in SAFE_LIVE_NPM.
#
# How the registry is made to answer differently, as in the binding prototype:
# npm's `--before=<date>` resolves against the registry as it was on that date.
# `npm_config_before` dates the whole gate run, so the projection resolves the
# T1 graph; the frozen install resolves nothing. A control resolution without
# the date, from the same starting project, is what a resolving command would
# have installed NOW, and it must differ.
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

# The command that runs the genuine npm: the gate's own way (a real binary, or
# the real mise under argv0 npm when the delegate is a version manager's shim).
real_npm=""
while IFS= read -r candidate; do
  [[ -x "${candidate}" ]] || continue
  head=$(LC_ALL=C head -n 2 -- "${candidate}" 2>/dev/null)
  if grep -q '^# safe-gate-wrapper' <<<"${head}"; then
    if grep -q 'tool=mise' <<<"${head}" && [[ -z "${real_npm}" ]]; then
      real_mise=""
      while IFS= read -r m; do
        [[ -x "${m}" ]] || continue
        LC_ALL=C head -n 2 -- "${m}" 2>/dev/null | grep -q '^# safe-gate-wrapper' && continue
        real_mise="${m}"
        break
      done < <(type -a -p mise 2>/dev/null)
      [[ -n "${real_mise}" ]] && { real_npm="mise:${real_mise}"; break; }
    fi
    continue
  fi
  real_npm="${candidate}"
  break
done < <(type -a -p npm 2>/dev/null)
if [[ -z "${real_npm}" && -n "${SAFE_LIVE_NPM:-}" && -x "${SAFE_LIVE_NPM}" ]]; then
  real_npm="${SAFE_LIVE_NPM}"
fi
if [[ -z "${real_npm}" ]]; then
  printf 'SKIP: no real npm available (set SAFE_LIVE_NPM to name one)\n'
  exit 0
fi
npm_run() {
  if [[ "${real_npm}" == mise:* ]]; then
    ( exec -a npm "${real_npm#mise:}" "$@" )
  else
    "${real_npm}" "$@"
  fi
}
printf '# npm: %s (%s)\n' "${real_npm}" "$(npm_run --version 2>/dev/null || printf 'version unknown')"
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

# Installed layout: a copied dispatcher with its sibling safe-core, the library
# of the checkout, and a stand-in advisory reader.
mkdir -p "${WORK}/safe/bin" "${WORK}/control" "${WORK}/independent" "${WORK}/project"
cp "${ROOT}/bin/safe" "${WORK}/safe/bin/safe"
ln -s "${ROOT}/lib" "${WORK}/safe/lib"
ln -s "${ROOT}/bin/safe-run" "${WORK}/safe/bin/safe-run"
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

run_config_dir="${SAFE_RUN_CONFIG_DIR:-${SAFE_CONFIG_DIR:-${HOME}/.config/safe}/run}"
mkdir -p "${run_config_dir}"
printf '{"install":{"project_lane":true}}\n' > "${run_config_dir}/config.json"

T1="2025-04-02"
ARGS=(install express@5.1.0 --ignore-scripts)

# The starting project: no dependency, the lockfile npm writes for it, committed.
cd "${WORK}/project" || exit 1
printf '{"name":"live-lane","version":"1.0.0"}\n' > package.json
if ! npm_run install --package-lock-only --ignore-scripts --no-audit --no-fund >/dev/null 2>&1; then
  fail "the starting lockfile is written"
  exit 1
fi
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
git init -q -b main
git add package.json package-lock.json
git -c user.name=lane -c user.email=lane@example.invalid commit -q -m base
cp package.json package-lock.json "${WORK}/control/"
cp package.json package-lock.json "${WORK}/independent/"

# Both resolutions must succeed and carry the requested root; a control that
# failed would make "the registry answers differently" vacuously true.
resolve() { # <dir> [--before=<date>]
  local dir="$1"
  shift
  ( cd "${dir}" && npm_run install express@5.1.0 --package-lock-only --ignore-scripts --no-audit --no-fund "$@" >"${dir}/resolve.log" 2>&1 ) || return 1
  jq -e '.packages["node_modules/express"].version == "5.1.0"' "${dir}/package-lock.json" >/dev/null
}
if resolve "${WORK}/control"; then
  pass "the control resolution (now) succeeds and holds express@5.1.0"
else
  fail "the control resolution (now) succeeds and holds express@5.1.0: $(tail -n 3 "${WORK}/control/resolve.log")"
  exit 1
fi
if resolve "${WORK}/independent" "--before=${T1}"; then
  pass "the independent projection (as of ${T1}) succeeds and holds express@5.1.0"
else
  fail "the independent projection (as of ${T1}) succeeds and holds express@5.1.0: $(tail -n 3 "${WORK}/independent/resolve.log")"
  exit 1
fi
judged="${WORK}/independent/package-lock.json"
entries() { jq -r '.packages | to_entries[] | select(.key | test("node_modules/")) | "\(.key)@\(.value.version)"' "$1" | LC_ALL=C sort; }
entries "${judged}" > "${WORK}/judged.txt"
entries "${WORK}/control/package-lock.json" > "${WORK}/now.txt"
differing="$(LC_ALL=C comm -3 "${WORK}/judged.txt" "${WORK}/now.txt" | wc -l)"
if (( differing > 0 )); then
  pass "the registry answers differently now: ${differing} lockfile lines differ between the judged graph and what a resolving command gives today"
else
  fail "the fixture is vacuous: the registry answers today as it did at ${T1}"
fi

# The lane, through the checkout's gate. npm is whatever the gate resolves.
npm_config_before="${T1}" SAFE_AUDIT_PATH="${WORK}/safe/bin/safe-audit" \
  "${WORK}/safe/bin/safe" gate npm "${ARGS[@]}" >"${WORK}/gate.out" 2>"${WORK}/gate.err"
status=$?
sed 's/^/# gate: /' "${WORK}/gate.err" | tail -n 25
if (( status == 0 )); then
  pass "the lane installs express@5.1.0 (gate exit 0)"
else
  fail "the lane installs express@5.1.0 (gate exit ${status})"
  printf '# the lane did not publish; the project is: %s\n' "$(ls -A "${WORK}/project" | tr '\n' ' ')"
  exit 1
fi

# The lockfile on disk is the independently captured projection, byte for byte.
if cmp -s package-lock.json "${judged}"; then
  pass "the final lockfile is byte-identical to the independently captured projection"
else
  fail "the final lockfile differs from the independently captured projection"
  diff <(entries package-lock.json) "${WORK}/judged.txt" | head -5
fi
if [[ "$(jq -r '.dependencies.express' package.json)" == "^5.1.0" ]]; then
  pass "the judged manifest was written"
else
  fail "the judged manifest was not written"
fi

# The tree is the judged lockfile: by safe's strict verifier, and independently.
selection=(--os "$(uname -s | tr '[:upper:]' '[:lower:]')" --cpu "$(case "$(uname -m)" in x86_64) echo x64;; aarch64) echo arm64;; *) uname -m;; esac)" --libc "$(ldd --version 2>&1 | grep -qi musl && echo musl || echo glibc)")
tree_json="$("${WORK}/safe/bin/safe-core" project-tree "${selection[@]}" "${judged}" . 2>/dev/null)"
tree_status=$?
if (( tree_status == 0 )) && jq -e '.ok == true and .checked > 10' <<<"${tree_json}" >/dev/null 2>&1; then
  pass "the installed tree is the independently captured lockfile (project-tree: $(jq -r '.checked' <<<"${tree_json}") entries checked)"
else
  fail "the installed tree is the independently captured lockfile (exit ${tree_status}): $(jq -c '.problems[:3]' <<<"${tree_json}" 2>/dev/null)"
fi
mismatch=0
while IFS=$'\t' read -r key version; do
  have="$(jq -r '.version' "${key}/package.json" 2>/dev/null)"
  [[ "${have}" == "${version}" ]] || { mismatch=$((mismatch + 1)); printf '# %s: lockfile %s, tree %s\n' "${key}" "${version}" "${have:-absent}"; }
done < <(jq -r '.packages | to_entries[] | select(.key | test("node_modules/")) | select(.value.optional | not) | [.key, .value.version] | @tsv' "${judged}")
if (( mismatch == 0 )); then
  pass "every non-optional entry of the judged lockfile is installed at its locked version"
else
  fail "${mismatch} entries differ between the judged lockfile and the tree"
fi
# What npm recorded as installed (its hidden lockfile) is the judged graph, and
# not the one a resolving command gives today.
entries node_modules/.package-lock.json > "${WORK}/installed.txt"
if cmp -s "${WORK}/installed.txt" "${WORK}/judged.txt" && ! cmp -s "${WORK}/installed.txt" "${WORK}/now.txt"; then
  pass "npm's own record of the installed tree is the judged graph and not today's resolution"
else
  fail "npm's own record of the installed tree differs from the judged graph: $(LC_ALL=C comm -3 "${WORK}/installed.txt" "${WORK}/judged.txt" | head -3 | tr '\n' ' ')"
fi

# Nothing is left behind, and the lock is released.
if compgen -G '.safe-bind-*' >/dev/null; then
  fail "a staging directory is left in the project"
else
  pass "no staging directory is left in the project"
fi
flock -n -x "${WORK}/project" true && pass "the project lock was released" || fail "the project lock was not released"

printf '%s passed, %s failed\n' "${PASS}" "${FAIL}"
(( FAIL == 0 ))
