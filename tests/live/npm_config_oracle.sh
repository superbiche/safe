#!/usr/bin/env bash
# LIVE suite — exercises the CHECKED-IN lock-diff npm oracles against the REAL
# npm binary.
#
# Why this exists: the install suite is hermetic (stubbed npm), and a stub that
# answered `config get --json` with a JSON object — a shape npm never emits —
# kept the suite green while the live gate refused every dedupe and prune
# (PR#70 delta-3). A probe that asks a real tool for a real format must be
# verified against that tool, and it must call the shipped helper rather than a
# convenient re-implementation of it (delta-4 N1): a duplicated raw npm call
# passes while lib/gate-lib.sh regresses.
#
# Offline: `npm config list` reads configuration only, never the network.
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
PASS=0
FAIL=0

pass() { printf 'ok - %s\n' "$1"; PASS=$((PASS + 1)); }
fail() { printf 'FAIL - %s\n' "$1"; FAIL=$((FAIL + 1)); }

# The gate resolves its delegate by skipping safe's own wrappers; this suite
# needs the genuine npm, so locate it the same way.
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
printf '{"name":"live-oracle","version":"1.0.0"}\n' > "${WORK}/package.json"

# shellcheck source=/dev/null
source "${ROOT}/lib/gate-lib.sh" >/dev/null 2>&1 || {
  printf 'FAIL - cannot source lib/gate-lib.sh\n'
  exit 1
}

# Pin the delegate the helpers resolve to the real npm found above, so the
# suite measures the shipped code paths and not PATH accidents. The variable
# name must be one gate-lib never declares `local`: bash is dynamically
# scoped, so an override reading `real_npm` would see the CALLER's empty local
# and report npm as unresolvable.
SAFE_LIVE_REAL_NPM="${real_npm}"
safe_gate_resolve_real() { printf '%s\n' "${SAFE_LIVE_REAL_NPM}"; }

npmrc() { printf '%s' "$1" > "${WORK}/.npmrc"; }

config_rc() {
  ( safe_gate_npm_lockdiff_effective_config "${WORK}" dedupe "$@" ) >/dev/null 2>&1
  printf '%s' "$?"
}

hosts_out() {
  ( safe_gate_npm_lockdiff_registry_hosts "${WORK}" dedupe "$@" ) 2>/dev/null
}

# --- effective-config oracle -------------------------------------------------

npmrc ''
[[ "$(config_rc dedupe)" == "0" ]] \
  && pass "ordinary dedupe passes the shipped config oracle on a stock npm config" \
  || fail "ordinary dedupe was refused by the shipped config oracle"

# npm's own default is ignore-scripts=false; the projection asserts it via its
# own flags, so reading the ambient value refused every command on a stock
# machine. The probe must mirror the projection instead.
[[ "$(config_rc prune)" == "0" ]] \
  && pass "ordinary prune passes the shipped config oracle" \
  || fail "ordinary prune was refused by the shipped config oracle"

# The probe's own transport must not be overridable by an ordinary output flag.
[[ "$(config_rc dedupe --json=false)" == "0" ]] \
  && pass "--json=false does not disable the probe transport (no over-refusal)" \
  || fail "--json=false over-refused an ordinary command"
[[ "$(config_rc dedupe --no-json)" == "0" ]] \
  && pass "--no-json does not disable the probe transport (no over-refusal)" \
  || fail "--no-json over-refused an ordinary command"

[[ "$(config_rc dedupe --no-ignore-scripts)" == "100" ]] \
  && pass "--no-ignore-scripts is detected as weakening and refused" \
  || fail "--no-ignore-scripts was not refused"
[[ "$(config_rc dedupe --package-lock=false)" == "100" ]] \
  && pass "--package-lock=false is detected as weakening and refused" \
  || fail "--package-lock=false was not refused"

npmrc 'package-lock = "false"'
[[ "$(config_rc dedupe)" == "100" ]] \
  && pass "quoted .npmrc package-lock=false is refused (npm parses the quotes)" \
  || fail "quoted .npmrc package-lock=false was not refused"

npmrc $'package-lock=false\npackage-lock=true\n'
[[ "$(config_rc dedupe)" == "0" ]] \
  && pass "last-key-wins .npmrc resolving to true is not over-refused" \
  || fail "last-key-wins .npmrc resolving to true was over-refused"

npmrc ''
[[ "$(NPM_CONFIG_PACKAGE_LOCK=' false ' config_rc dedupe)" == "100" ]] \
  && pass "whitespace-padded environment false is refused (npm trims it)" \
  || fail "whitespace-padded environment false was not refused"

# --- registry-provenance oracle ---------------------------------------------

npmrc $'registry=https://registry.npmjs.org/\n@corp:registry=https://npm.corp.invalid/\n'
out="$(hosts_out dedupe)"
if grep -qx 'npm.corp.invalid' <<<"${out}" && grep -qx 'registry.npmjs.org' <<<"${out}"; then
  pass "real scoped registry keys are enumerated as trusted hosts"
else
  fail "scoped registry enumeration missing: ${out//$'\n'/,}"
fi

# npm STORES any `<x>:registry` line but only SELECTS a scope its package-name
# validator accepts. Trusting a stored-but-unselectable key let a project's own
# .npmrc grant an arbitrary host registry provenance, so a remote tarball looked
# registry-authoritative — first via `not-a-scope:` (delta-4 F4), then via
# `@<junk>:` spellings npm keeps but can never resolve (delta-5 F4).
for bad_key in 'not-a-scope' '@a b' '@a#b' '@a%20b' '@a/b' '@a:b' '@'; do
  npmrc "registry=https://registry.npmjs.org/"$'\n'"${bad_key}:registry=https://attacker.invalid/"$'\n'
  if grep -qx 'attacker.invalid' <<<"$(hosts_out dedupe)"; then
    fail "unselectable key '${bad_key}:registry' granted registry provenance to attacker.invalid"
  else
    pass "unselectable key '${bad_key}:registry' cannot grant registry provenance"
  fi
done

# ...while every scope npm CAN select keeps working, including uppercase.
npmrc $'registry=https://registry.npmjs.org/\n@Corp:registry=https://npm.up.invalid/\n'
grep -qx 'npm.up.invalid' <<<"$(hosts_out dedupe)" \
  && pass "an uppercase scope npm selects is still trusted" \
  || fail "an uppercase scope npm selects was over-refused"

# The host must equal what Go's url.Host holds on the safe-core side.
npmrc 'registry=http://[::1]:4873/'
[[ "$(hosts_out dedupe)" == '[::1]:4873' ]] \
  && pass "a bracketed IPv6 registry is preserved verbatim as a host" \
  || fail "IPv6 registry host was mangled or refused: $(hosts_out dedupe)"

npmrc 'registry=https://example.com:99999/'
[[ -z "$(hosts_out dedupe)" ]] \
  && pass "a port outside 1..65535 is refused, not passed as a host" \
  || fail "invalid port accepted: $(hosts_out dedupe)"

# Bash character ranges are locale-collated: under en_US.UTF-8 `[a-z]` matched
# accented letters and a Unicode host was emitted raw, while npm resolves such
# a registry to punycode (delta-5 F4).
npmrc 'registry=https://bücher.example/'
[[ -z "$(LC_ALL=en_US.UTF-8 hosts_out dedupe)" ]] \
  && pass "a non-ASCII registry host is refused under a UTF-8 locale" \
  || fail "non-ASCII host leaked under en_US.UTF-8: $(LC_ALL=en_US.UTF-8 hosts_out dedupe)"

npmrc 'registry=https://:'
if [[ -z "$(hosts_out dedupe)" ]]; then
  pass "a malformed registry authority is refused, not passed as a host"
else
  fail "malformed registry authority produced a host: $(hosts_out dedupe)"
fi

# --- retired call shape ------------------------------------------------------

npmrc ''
if get_out="$(cd "${WORK}" && "${real_npm}" config get package-lock ignore-scripts --json 2>/dev/null)" \
   && [[ -n "${get_out}" ]]; then
  if jq -e 'type == "object"' <<<"${get_out}" >/dev/null 2>&1; then
    fail "npm config get --json now emits JSON; revisit the oracle choice"
  else
    pass "npm config get --json is NOT JSON (why the oracle uses config list)"
  fi
else
  # Not vacuous: a failed or empty command must not be scored as a pass.
  fail "npm config get probe produced no output; cannot assert the retired shape"
fi

printf '%s passed, %s failed\n' "${PASS}" "${FAIL}"
(( FAIL == 0 ))
