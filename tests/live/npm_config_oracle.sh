#!/usr/bin/env bash
# LIVE suite — runs the lock-diff npm oracles against the REAL npm binary.
#
# Why this exists: the install suite is hermetic (stubbed npm), and a stub
# that answered `config get --json` with a JSON object — a shape npm never
# emits — kept the suite green while the live gate refused every dedupe and
# prune (PR#70 delta-3 F2/F4). A probe that asks a real tool for a real
# format must be verified against that tool. Offline: `npm config list`
# reads configuration only, never the network.
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
PASS=0
FAIL=0

pass() { printf 'ok - %s\n' "$1"; PASS=$((PASS + 1)); }
fail() { printf 'FAIL - %s\n' "$1"; FAIL=$((FAIL + 1)); }

# The gate resolves the delegate by skipping safe's own wrappers; here we want
# the genuine npm, so locate it the same way and refuse to run against a
# wrapper.
real_npm=""
while IFS= read -r candidate; do
  [[ -x "${candidate}" ]] || continue
  LC_ALL=C head -n 2 -- "${candidate}" 2>/dev/null | grep -q '^# safe-gate-wrapper' && continue
  real_npm="${candidate}"
  break
done < <(type -a -p npm 2>/dev/null)

if [[ -z "${real_npm}" ]]; then
  printf 'SKIP: no real (non-wrapper) npm available; live npm oracle checks skipped\n'
  exit 0
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/safe-live-npm.XXXXXX")" || exit 1
trap 'rm -rf -- "${WORK}"' EXIT
: > "${WORK}/isolated-npmrc"
printf '{"name":"live-oracle","version":"1.0.0"}\n' > "${WORK}/package.json"

# Isolate from the operator's own user config so the suite measures npm's
# stock defaults, not this machine's hardening.
npm_probe() {
  (
    cd "${WORK}" || exit 125
    "${real_npm}" config list --json --userconfig "${WORK}/isolated-npmrc" \
      --package-lock-only --ignore-scripts --no-audit --no-fund "$@" 2>/dev/null
  )
}

json="$(npm_probe dedupe)"
if [[ -n "${json}" ]] && jq -e 'type == "object"' <<<"${json}" >/dev/null 2>&1; then
  pass "npm config list --json emits a JSON object (the format the gate parses)"
else
  fail "npm config list --json did not emit a JSON object: ${json:0:120}"
fi

# Stock npm defaults ignore-scripts to false; the projection asserts it via
# its own flags, so an ordinary dedupe must still resolve healthy. Reading
# the ambient value instead refused every command on a stock machine.
if jq -e '.["package-lock"] == true and .["ignore-scripts"] == true' <<<"${json}" >/dev/null 2>&1; then
  pass "ordinary dedupe resolves healthy invariants on a stock npm config"
else
  fail "ordinary dedupe did not resolve healthy invariants: $(jq -c '{"package-lock","ignore-scripts"}' <<<"${json}" 2>/dev/null)"
fi

json="$(npm_probe dedupe --no-ignore-scripts)"
if jq -e '.["ignore-scripts"] == false' <<<"${json}" >/dev/null 2>&1; then
  pass "user --no-ignore-scripts still resolves to a weakened invariant (gate refuses)"
else
  fail "user --no-ignore-scripts was not detected as weakening"
fi

printf 'package-lock=false\n' > "${WORK}/.npmrc"
json="$(npm_probe dedupe)"
if jq -e '.["package-lock"] == false' <<<"${json}" >/dev/null 2>&1; then
  pass "project .npmrc package-lock=false resolves weakened (gate refuses)"
else
  fail "project .npmrc package-lock=false was not detected"
fi

# Real scoped registry keys must be enumerable: querying the literal
# "@scope:registry" returned a placeholder and over-refused scoped private
# artifacts as remote.
printf 'registry=https://registry.npmjs.org/\n@corp:registry=https://npm.corp.invalid/\n' > "${WORK}/.npmrc"
json="$(npm_probe dedupe)"
if jq -e '(.registry | type == "string")
  and ([to_entries[] | select((.key | endswith(":registry")) and (.key != "registry")) | .value]
       | index("https://npm.corp.invalid/") != null)' <<<"${json}" >/dev/null 2>&1; then
  pass "scoped registry keys are enumerable from the effective config"
else
  fail "scoped registry enumeration failed: $(jq -c 'with_entries(select(.key | endswith(":registry")))' <<<"${json}" 2>/dev/null)"
fi

# The retired call shape, pinned so nobody reintroduces it: `config get`
# emits key=value text and is NOT parseable as JSON.
get_out="$(cd "${WORK}" && "${real_npm}" config get package-lock ignore-scripts --json --userconfig "${WORK}/isolated-npmrc" 2>/dev/null)"
if jq -e 'type == "object"' <<<"${get_out}" >/dev/null 2>&1; then
  fail "npm config get --json now emits JSON; revisit the oracle choice"
else
  pass "npm config get --json is NOT JSON (why the oracle uses config list)"
fi

printf '%s passed, %s failed\n' "${PASS}" "${FAIL}"
(( FAIL == 0 ))
