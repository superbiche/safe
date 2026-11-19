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
# \s is a space and \t a tab: written out so that the fixture carries no trailing
# whitespace (git diff --check) while the spellings do.
rows = [l.rstrip("\n").replace("\\s", " ").replace("\\t", "\t") for l in open(sys.argv[1], encoding="utf-8")]
out = []
names = ["a", "A", "a-b", "a.b", "a_b", ".a", "_a", "a b", " a", "a ", "@s/a", "@s/.a", "@s/_a", "@s/-a", "-a", "@-s/a", "@s/", "@/a", "@s/a/b", "a/b", "node_modules", "favicon.ico",
         "a~b", "a'b", "a(b)", "a*b", "a!b", "a%b", "a@b", "é", "x" * 214, "x" * 215, "@" + "s" * 100 + "/" + "a" * 100,
         "a@^1", "a@1.x", "@s/a@1.2.3", "a@npm:b@1", "a@file:../x", "a@git+https://x/y.git", "x.tgz", "x.TGZ@1", "a@1.2.3-x.tgz",
         "^9007199254740991.0.0", "^9007199254740990.0.0", "~9007199254740991.0.0", ">=9007199254740991.0.0", "9007199254740991.0.0"]
for r in rows + names:
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
const validate = require(process.argv[2] + '/node_modules/validate-npm-package-name')
const rows = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'))
const registry = new Set(['version', 'range', 'tag'])
const out = []
for (const row of rows) {
  const s = row.raw
  let spec, arg
  try { const r = npa.resolve('x', s, '/tmp/w'); spec = r.type } catch { spec = 'error' }
  try { const r = npa(s, '/tmp/w'); arg = r.registry && r.name ? r.type : (r.type || 'other') } catch { arg = 'error' }
  // names: the old-package rule npm applies to the name part of a dependency
  let name = false
  try { name = !!validate(s).validForOldPackages } catch { name = false }
  // override selectors: Arborist parses the whole key with npa and needs a name
  let key = false
  try { const r = npa(s, '/tmp/w'); key = !!(r.name && r.registry && registry.has(r.type)) } catch { key = false }
  out.push({ raw: s, spec, arg, ours: row.spec, ourArg: row.arg, exact: row.exact, name, ourName: row.name, key, ourKey: row.override_key })
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
# Names and override selectors: never admitted when npm does not take them.
wrong="$(jq -c '[.[] | select(.ourName == true and .name == false)]' "${WORK}/both.json")"
if [[ "${wrong}" == "[]" ]]; then
  pass "no package name is admitted that npm's validate-npm-package-name refuses"
else
  fail "names admitted that npm refuses: $(jq -c '.[0:8] | map(.raw)' <<<"${wrong}")"
fi
wrong="$(jq -c '[.[] | select(.ourKey == true and .key == false)]' "${WORK}/both.json")"
if [[ "${wrong}" == "[]" ]]; then
  pass "no override selector is admitted that npm's parser does not read as a named registry package"
else
  fail "override selectors admitted that npm does not read so: $(jq -c '.[0:8] | map(.raw)' <<<"${wrong}")"
fi
refused="$(jq '[.[] | select(.ours == "invalid" and (.spec | IN("version","range","tag")))] | length' "${WORK}/both.json")"
printf '# safe refuses %s of %s spellings that npm takes for the registry (loose or non-ASCII forms)\n' "${refused}" "${total}"
# --- the probe script the gate runs with the selected node (capability, selection,
# agreement), against this npm's own modules ---------------------------------------
probe="${WORK}/lane-probe.cjs"
GATE_LIB="${ROOT}/lib/gate-lib.sh" bash -c 'source "$GATE_LIB"; safe_gate_lane_write_probe_script "$1"' _ "${probe}" || { fail "the probe script is written"; exit 1; }
run_probe() { # <npm dir> <mode> <json>
  printf '%s' "$3" | "${node_bin}" "${probe}" "$1" "$2"
}
opts='["allow-git","git","replace-registry-host","cache","logs-dir","logs-max"]'
out="$(run_probe "${npm_dir}" capability "{\"floor\":\"11.12.1\",\"options\":${opts}}")"
if jq -e '.atFloor == true and (.missing | length) == 0' <<<"${out}" >/dev/null 2>&1; then
  pass "capability: this npm ($(jq -r .version <<<"${out}")) is at the floor and defines every option the lane passes"
else
  fail "capability on this npm: ${out}"
fi
old_npm=""
for d in "$(cd "${npm_dir}/../../../.." 2>/dev/null && pwd)"/*/lib/node_modules/npm; do
  [[ -f "${d}/package.json" ]] && grep -q '"version": "10\.' "${d}/package.json" && { old_npm="${d}"; break; }
done
if [[ -n "${old_npm}" && -d "${old_npm}" ]]; then
  out="$(run_probe "${old_npm}" capability "{\"floor\":\"11.12.1\",\"options\":${opts}}")"
  if jq -e '.atFloor == false and (.missing | index("allow-git"))' <<<"${out}" >/dev/null 2>&1; then
    pass "capability: npm $(jq -r .version <<<"${out}") is refused: below the floor and it does not define allow-git (though it echoes it)"
  else
    fail "capability on the older npm: ${out}"
  fi
else
  printf '# note: no older npm installed to show the refusal on\n'
fi
out="$(run_probe "${npm_dir}" selection '{"config":{"os":"darwin","cpu":null,"libc":null,"omit":["dev","optional"],"include":["optional"]}}')"
if jq -e '.os == "darwin" and .libc == null and .omit == ["dev"]' <<<"${out}" >/dev/null 2>&1; then
  pass "selection: libc is judged against the effective os (none for darwin), include removes an omission"
else
  fail "selection with os=darwin: ${out}"
fi
out="$(run_probe "${npm_dir}" selection '{"config":{"os":null,"cpu":null,"libc":null,"omit":[],"include":[]}}')"
if jq -e --arg os "$("${node_bin}" -p 'process.platform')" --arg cpu "$("${node_bin}" -p 'process.arch')" '.os == $os and .cpu == $cpu' <<<"${out}" >/dev/null 2>&1; then
  pass "selection: without settings, the selected node's own platform"
else
  fail "selection without settings: ${out}"
fi
# agreement: what project-admit admits, npm's own parsers read the same way
cat > "${WORK}/m.json" <<'JSON'
{"name":"p","dependencies":{"a":"^1.0.0","b":"latest","@s/c":"1.2.3 - 2"},"devDependencies":{"d":"~1.2.3"},
 "overrides":{"a":"1.2.3","b@^2":{".":"2.0.0","e":{"f":"$a"}}}}
JSON
"${WORK}/safe-core" project-admit --arg foo@1.2.3 --manifest "${WORK}/m.json" > "${WORK}/admit.json"
out="$(run_probe "${npm_dir}" agreement "$(jq -c '{checked}' "${WORK}/admit.json")")"
if jq -e '.disagreements == [] and (.disagreements | type == "array")' <<<"${out}" >/dev/null 2>&1 && jq -e '[.checked[].kind] | unique | length >= 4' "${WORK}/admit.json" >/dev/null; then
  pass "agreement: npm's parsers read every admitted string ($(jq '.checked | length' "${WORK}/admit.json")) as a registry request"
else
  fail "agreement on an admitted manifest: ${out}"
fi
out="$(run_probe "${npm_dir}" agreement '{"checked":[{"kind":"dep","name":"a","spec":"git+https://example.invalid/x.git"},{"kind":"arg","name":"","spec":"foo@^1"},{"kind":"override-key","name":"","spec":"x.tgz"},{"kind":"name","name":".a","spec":""}]}')"
if [[ "$(jq '.disagreements | length' <<<"${out}")" == "4" ]]; then
  pass "agreement: npm's parsers refuse a git dependency, a range as an exact argument, an unnamed selector and a bad name"
else
  fail "agreement on refused strings: ${out}"
fi

exit "${FAILED}"
