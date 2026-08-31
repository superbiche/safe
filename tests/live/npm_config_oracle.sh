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

# Which npm answered matters when a result is version-dependent: this suite
# takes whatever the gate's own resolution takes, which is not necessarily the
# npm a probe was originally measured on.
printf '# npm oracle target: %s (%s)\n' "${real_npm}" "$("${real_npm}" --version 2>/dev/null || printf 'version unknown')"

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

# The target platform the shipped oracle extracted, read from the global the
# preflight hands safe-core.
target_os() {
  SAFE_GATE_LOCKDIFF_TARGET_OS=""
  safe_gate_npm_lockdiff_effective_config "${WORK}" dedupe "$@" >/dev/null 2>&1
  printf '%s' "${SAFE_GATE_LOCKDIFF_TARGET_OS}"
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

# --- target-platform oracle --------------------------------------------------

# The reify-candidate exemption speaks for the platform npm installs FOR, and
# npm resolves that from every config source. The argv scanner this replaced
# saw only the command line, so an environment or .npmrc target moved the real
# install while the audit stayed on the host platform (#244).

npmrc ''
[[ -z "$(target_os dedupe)" ]] \
  && pass "no configured target platform leaves the host platform standing" \
  || fail "an unset os produced a target: $(target_os dedupe)"

[[ "$(target_os dedupe --os=aix)" == "aix" ]] \
  && pass "an argv target platform is read from the effective config" \
  || fail "argv --os=aix did not reach the target: $(target_os dedupe --os=aix)"

[[ "$(target_os dedupe --os aix)" == "aix" ]] \
  && pass "the space-separated argv spelling reaches the target too" \
  || fail "argv --os aix did not reach the target"

# npm treats a target as an opaque string: a dash-led value is a platform it
# will resolve os constraints against, so it must survive verbatim.
[[ "$(target_os dedupe --os=-weird)" == "-weird" ]] \
  && pass "a dash-led target platform survives the probe verbatim" \
  || fail "dash-led target was mangled: $(target_os dedupe --os=-weird)"

[[ "$(npm_config_os=aix target_os dedupe)" == "aix" ]] \
  && pass "an environment target platform is read from the effective config" \
  || fail "npm_config_os=aix did not reach the target"

[[ "$(NPM_CONFIG_OS=aix target_os dedupe)" == "aix" ]] \
  && pass "npm reads its environment target case-insensitively" \
  || fail "NPM_CONFIG_OS=aix did not reach the target"

npmrc 'os=aix'
[[ "$(target_os dedupe)" == "aix" ]] \
  && pass "a project .npmrc target platform is read from the effective config" \
  || fail "an .npmrc os=aix did not reach the target"

# npm reports an empty argv target as "", which leaves the host platform
# standing in safe-core — the same fallback npm-install-checks makes with
# `environment.os || currentEnv.os()` (r1 review F5).
npmrc ''
[[ -z "$(target_os dedupe --os=)" ]] \
  && pass "an empty argv target leaves the host platform standing" \
  || fail "an empty --os= produced a target: $(target_os dedupe --os=)"

# --- relative userconfig resolution -----------------------------------------

# The refusal for a relative userconfig/globalconfig rests on this: npm
# resolves such a path against the CWD, which is the project for the delegate
# and the scratch directory for the projection, so one spelling names two
# different config files.
printf 'os=fromrelative\n' > "${WORK}/relative-npmrc"
mkdir -p "${WORK}/elsewhere"
from_project="$(cd "${WORK}" && "${real_npm}" config list --json --userconfig ./relative-npmrc 2>/dev/null | jq -r '.os // "unset"')"
from_elsewhere="$(cd "${WORK}/elsewhere" && "${real_npm}" config list --json --userconfig ./relative-npmrc 2>/dev/null | jq -r '.os // "unset"')"
if [[ "${from_project}" == "fromrelative" && "${from_elsewhere}" == "unset" ]]; then
  pass "a relative --userconfig resolves against the cwd (why the projection refuses it)"
else
  fail "relative --userconfig resolution changed: project=${from_project} elsewhere=${from_elsewhere}"
fi

# --- effective-config parity across cwds -------------------------------------

# Copying config files into the projection does not copy what they RESOLVE to:
# npm expands values against the cwd of the process reading them, so the same
# files can hand the projection different settings than the delegate gets (r1
# review F3). The parity check compares the same probe run from the project
# and from the prepared scratch; these assertions pin the npm behaviors that
# check depends on.

PARITY_SCRATCH="${WORK}/parity-scratch"
mkdir -p "${PARITY_SCRATCH}"
printf '{"name":"live-oracle","version":"1.0.0"}\n' > "${PARITY_SCRATCH}/package.json"

# The probe layout the gate uses, verbatim, from an arbitrary cwd.
parity_probe() {
  ( cd -- "$1" && "${real_npm}" config list \
      --package-lock-only --ignore-scripts --no-audit --no-fund dedupe "${@:2}" --json 2>/dev/null )
}

npmrc ''
: > "${PARITY_SCRATCH}/.npmrc"
project_config="$(parity_probe "${WORK}")"
scratch_config="$(parity_probe "${PARITY_SCRATCH}")"
if [[ -n "${project_config}" ]] \
  && jq -en --argjson a "${project_config}" --argjson b "${scratch_config}" '$a == $b' >/dev/null 2>&1; then
  pass "a stock project's effective config is identical from either cwd (empty allowlist is earned)"
else
  fail "stock config differs across cwds: $(jq -rn --argjson a "${project_config:-null}" --argjson b "${scratch_config:-null}" '[((($a|keys)+($b|keys))|unique)[]|select($a[.] != $b[.])] | join(", ")' 2>/dev/null)"
fi

# The F3 reproduction shape: one absolute userconfig, two cwds, two values.
printf 'registry=https://npm.example.test/${PWD}/\n' > "${WORK}/pwd-user.npmrc"
from_project="$(parity_probe "${WORK}" --userconfig "${WORK}/pwd-user.npmrc" | jq -r '.registry')"
from_scratch="$(parity_probe "${PARITY_SCRATCH}" --userconfig "${WORK}/pwd-user.npmrc" | jq -r '.registry')"
if [[ -n "${from_project}" && "${from_project}" != "${from_scratch}" ]]; then
  pass "a userconfig \${PWD} value resolves per-cwd (the divergence parity catches)"
else
  fail "userconfig \${PWD} did not diverge: project=${from_project} scratch=${from_scratch}"
fi

# Reported values come back RESOLVED, so cwd-dependent settings are visible to
# the comparison rather than hidden from it — including the target platform
# itself, whose divergence would re-aim the reify exemption.
npmrc 'os=${PWD}'
cp -- "${WORK}/.npmrc" "${PARITY_SCRATCH}/.npmrc"
from_project="$(parity_probe "${WORK}" | jq -r '.os')"
from_scratch="$(parity_probe "${PARITY_SCRATCH}" | jq -r '.os')"
if [[ "${from_project}" == "${WORK}" && "${from_scratch}" == "${PARITY_SCRATCH}" ]]; then
  pass "a project-rc os=\${PWD} expands per-cwd and is visible to the parity check"
else
  fail "project-rc os=\${PWD} did not expand per-cwd: project=${from_project} scratch=${from_scratch}"
fi

npmrc 'cache=./cache'
cp -- "${WORK}/.npmrc" "${PARITY_SCRATCH}/.npmrc"
from_project="$(parity_probe "${WORK}" | jq -r '.cache')"
from_scratch="$(parity_probe "${PARITY_SCRATCH}" | jq -r '.cache')"
if [[ "${from_project}" == "${WORK}/cache" && "${from_scratch}" == "${PARITY_SCRATCH}/cache" ]]; then
  pass "a relative cache is reported resolved per-cwd, so parity catches it too"
else
  fail "relative cache was not reported per-cwd: project=${from_project} scratch=${from_scratch}"
fi

# --- lane-divergent ${VAR} expansion -----------------------------------------

# npm expands ${VAR} in config VALUES against the reading process's own
# environment, which is why the expansion guard refuses the references whose
# variable differs between the projection lane and the delegate lane. These
# assertions pin the boundary that guard is drawn on.

# Only the exact braced spelling expands: the unbraced and default-value forms
# stay literal, so scanning for ${PWD} alone is not under-reaching.
npmrc $'os=${PWD}\ncpu=$PWD\nsearchlimit=${PWD:-fallback}\n'
expansion_shapes="$(parity_probe "${WORK}" | jq -c '{os, cpu, searchlimit}')"
if [[ "${expansion_shapes}" == "{\"os\":\"${WORK}\",\"cpu\":\"\$PWD\",\"searchlimit\":\"\${PWD:-fallback}\"}" ]]; then
  pass "npm expands only the exact braced \${VAR} form (\$PWD and \${PWD:-x} stay literal)"
else
  fail "braced-only expansion changed: ${expansion_shapes}"
fi

# Whether a pinned PWD steers the expansion is npm-version-dependent, and this
# suite runs against whichever npm the GATE would resolve: npm 12.0.2 ignores
# the pin and uses the process's real cwd, while the older npm bundled with
# Node 22 honors it. Both shapes are recorded rather than asserted away — the
# guard refuses such a reference instead of rewriting it, so neither shape
# changes the outcome, and only a third, unknown shape is a failure.
npmrc 'os=${PWD}'
pinned_os="$( cd -- "${WORK}" && env PWD=/pinned/elsewhere "${real_npm}" config list \
  --package-lock-only --ignore-scripts --no-audit --no-fund dedupe --json 2>/dev/null | jq -r '.os' )"
if [[ "${pinned_os}" == "${WORK}" ]]; then
  pass "a pinned PWD does not steer \${PWD} here (npm uses the real cwd; matching the lanes' expansion is unavailable)"
elif [[ "${pinned_os}" == "/pinned/elsewhere" ]]; then
  pass "a pinned PWD steers \${PWD} here (older npm shape; the guard refuses rather than rewrites either way)"
else
  fail "\${PWD} resolved to neither the cwd nor the pinned value: ${pinned_os}"
fi

# Environment-sourced npm_config_* values are expanded the same way, which is
# why the guard scans them as well as the config files.
npmrc ''
env_expanded="$(npm_config_os='${PWD}' parity_probe "${WORK}" | jq -r '.os')"
if [[ "${env_expanded}" == "${WORK}" ]]; then
  pass "an npm_config_* environment value is expanded per-cwd too"
else
  fail "npm_config_os=\${PWD} did not expand per-cwd: ${env_expanded}"
fi

# The guard learns which files npm will read from the probe's own report.
config_files="$(parity_probe "${WORK}" | jq -r '[(.userconfig | type), (.globalconfig | type)] | join(",")')"
if [[ "${config_files}" == "string,string" ]]; then
  pass "the probe reports the effective userconfig and globalconfig paths (the guard's file list)"
else
  fail "config file paths are not both reported as strings: ${config_files}"
fi

# The one class npm keeps OUT of this output: secret-bearing keys. npm applies
# the expansion above to them BEFORE omitting them, so a ${PWD}-built token
# diverges invisibly to parity (r2 review F3) — the expansion guard is what
# refuses that class, upstream of this comparison.
printf '//registry.npmjs.org/:_authToken=live-oracle-not-a-real-token\n_auth=bGl2ZS1vcmFjbGU=\n' > "${WORK}/auth.npmrc"
auth_keys="$(parity_probe "${WORK}" --userconfig "${WORK}/auth.npmrc" | jq -r '[keys[] | select(startswith("_") or startswith("//"))] | join(", ")')"
if [[ -z "${auth_keys}" ]]; then
  pass "secret-bearing config keys are omitted from config list --json (documented parity blind spot)"
else
  fail "secret-bearing keys appear in config list --json: ${auth_keys}"
fi
rm -f -- "${PARITY_SCRATCH}/.npmrc"

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
