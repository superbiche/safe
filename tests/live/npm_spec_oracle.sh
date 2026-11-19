#!/usr/bin/env bash
# LIVE suite — the admission classifier of safe-core (project-admit) against
# the classifier of the npm that is installed (npm-package-arg and semver).
#
# The project lane admits only registry packages, "the way npm classifies
# them". The Go port is deliberately conservative: it must never take as a
# registry spec a spelling npm reads as a file, a git source, a URL or an alias,
# and an exact `name@version` must be a version for npm too. This suite feeds
# the table tests/fixtures/admit-spellings.txt (plus generated variants:
# every spelling upper-cased, quoted with a version prefix and suffixed with an
# archive suffix) to both and fails on any spelling safe admits that npm does not.
# Spellings safe refuses and npm takes (loose semver, non-ASCII) are reported,
# not failed: refusing more than npm is the safe direction.
#
# Offline. It reads npm's own modules; no registry is contacted.
set -uo pipefail

# SAFE_TEST_ISOLATION_MARKER: every suite owns a scratch HOME and safe state.
# shellcheck source=tests/lib/test-isolation.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/test-isolation.sh"
export SAFE_TEST_ISOLATION_KEEP_TOOLS=1
safe_test_setup_isolation || exit 1

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
# shellcheck source=tests/lib/safe-core.sh
source "${ROOT}/tests/lib/safe-core.sh"

pass() { printf 'ok - %s\n' "$1"; }
fail() { printf 'FAIL - %s\n' "$1"; FAILED=1; }
FAILED=0

# npm's modules: from a genuine npm on PATH, or the real mise's npm (a mise shim
# on PATH is a gate wrapper), or SAFE_LIVE_NPM.
npm_bin=""
while IFS= read -r candidate; do
  [[ -x "${candidate}" ]] || continue
  head=$(LC_ALL=C head -n 2 -- "${candidate}" 2>/dev/null)
  if grep -q '^# safe-gate-wrapper' <<<"${head}"; then
    if grep -q 'tool=mise' <<<"${head}" && [[ -z "${npm_bin}" ]]; then
      while IFS= read -r m; do
        [[ -x "${m}" ]] || continue
        LC_ALL=C head -n 2 -- "${m}" 2>/dev/null | grep -q '^# safe-gate-wrapper' && continue
        npm_bin="$("${m}" which npm 2>/dev/null)" && break
        npm_bin=""
      done < <(type -a -p mise 2>/dev/null)
    fi
    [[ -n "${npm_bin}" ]] && break
    continue
  fi
  npm_bin="${candidate}"
  break
done < <(type -a -p npm 2>/dev/null)
[[ -n "${npm_bin}" || -z "${SAFE_LIVE_NPM:-}" ]] || npm_bin="${SAFE_LIVE_NPM}"
if [[ -z "${npm_bin}" ]]; then
  printf 'SKIP: no real npm available\n'
  exit 0
fi
npm_real="$(realpath -- "${npm_bin}")"
npm_dir="$(cd -- "$(dirname -- "${npm_bin}")/../lib/node_modules/npm" 2>/dev/null && pwd)" \
  || npm_dir="$(cd -- "$(dirname -- "${npm_real}")/.." && pwd)"
node_bin="$(dirname -- "${npm_bin}")/node"
[[ -x "${node_bin}" ]] || node_bin="$(command -v node 2>/dev/null)"
if [[ ! -d "${npm_dir}/node_modules/npm-package-arg" || -z "${node_bin}" ]]; then
  printf 'SKIP: npm-package-arg or node not found next to %s\n' "${npm_bin}"
  exit 0
fi
printf '# npm: %s (npm-package-arg beside it)\n' "${npm_real}"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/safe-spec-oracle.XXXXXX")" || exit 1
safe_test_compose_exit_trap "rm -rf -- \"\${WORK}\""
safe_core_test_prepare "${ROOT}" "${WORK}/safe-core" || { printf 'SKIP: safe-core cannot be built\n'; exit 0; }

# The spellings: the table, and variants of each.
python3 -I - "${ROOT}/tests/fixtures/admit-spellings.txt" > "${WORK}/spellings.bin" <<'PY' || { printf 'SKIP: python3 unavailable\n'; exit 0; }
import sys
rows = [l.rstrip("\n") for l in open(sys.argv[1], encoding="utf-8")]
out = []
for r in rows:
    out += [r, r.upper(), "x@" + r, "@s/x@" + r, "1.2.3-" + r, r + ".tgz", r + ".TAR.GZ", "v" + r]
seen = []
for r in out:
    if r not in seen and "\0" not in r:
        seen.append(r)
sys.stdout.buffer.write(b"\0".join(s.encode("utf-8") for s in seen))
PY

"${WORK}/safe-core" project-admit --classify < "${WORK}/spellings.bin" > "${WORK}/ours.json" || { fail "project-admit --classify runs"; exit 1; }

cat > "${WORK}/oracle.cjs" <<'JS'
const fs = require('fs')
const npa = require(process.argv[2] + '/node_modules/npm-package-arg')
const rows = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'))
const registry = new Set(['version', 'range', 'tag'])
const out = []
for (const row of rows) {
  const s = row.raw
  let spec, arg
  try { const r = npa.resolve('x', s, '/tmp/w'); spec = r.type } catch { spec = 'error' }
  try { const r = npa(s, '/tmp/w'); arg = r.registry && r.name ? r.type : (r.type || 'other') } catch { arg = 'error' }
  out.push({ raw: s, spec, arg, ours: row.spec, ourArg: row.arg, exact: row.exact })
}
process.stdout.write(JSON.stringify(out))
JS
"${node_bin}" "${WORK}/oracle.cjs" "${npm_dir}" "${WORK}/ours.json" > "${WORK}/both.json" 2>"${WORK}/oracle.err" || { fail "the oracle runs: $(head -c 300 "${WORK}/oracle.err")"; exit 1; }

total="$(jq 'length' "${WORK}/both.json")"
# Never admit what npm does not take for the registry.
wrong="$(jq -c '[.[] | select((.ours == "version" or .ours == "range" or .ours == "tag") and (.spec | IN("version","range","tag") | not))]' "${WORK}/both.json")"
if [[ "${wrong}" == "[]" ]]; then
  pass "none of ${total} spellings is admitted as a registry spec that npm reads otherwise"
else
  fail "spellings admitted as registry specs that npm does not: $(jq -c '.[0:8] | map({raw, spec, ours})' <<<"${wrong}")"
fi
# A source safe names (file, git, remote, alias) is a non-registry source for npm too.
wrong="$(jq -c '[.[] | select((.ours | IN("file","git","remote","alias")) and (.spec | IN("version","range","tag")))]' "${WORK}/both.json")"
if [[ "${wrong}" == "[]" ]]; then
  pass "every spelling safe reads as a source npm reads as a registry spec is absent"
else
  printf '# note: safe refuses more than npm on: %s\n' "$(jq -c '.[0:8] | map({raw, spec, ours})' <<<"${wrong}")"
fi
# An exact argument is a version for npm.
wrong="$(jq -c '[.[] | select(.exact == true and .arg != "version")]' "${WORK}/both.json")"
if [[ "${wrong}" == "[]" ]]; then
  pass "every exact argument is a version for npm"
else
  fail "exact arguments that npm does not read as a version: $(jq -c '.[0:8] | map({raw, arg})' <<<"${wrong}")"
fi
refused="$(jq '[.[] | select(.ours == "invalid" and (.spec | IN("version","range","tag")))] | length' "${WORK}/both.json")"
printf '# safe refuses %s of %s spellings that npm takes for the registry (loose or non-ASCII forms)\n' "${refused}" "${total}"
exit "${FAILED}"
