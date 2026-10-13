#!/usr/bin/env bash
# Private-registry trust (trusted origins, ruling a37): the install-gate
# lane, its gate termini and the operator commands. Registries, clients and
# network are fixtures: fake npm, go and curl binaries on PATH stand in for
# the ecosystem clients the lane asks, so no request leaves the machine and
# no credential exists.

set -uo pipefail

# SAFE_TEST_ISOLATION_MARKER: every suite owns a scratch HOME and safe state.
# shellcheck source=tests/lib/test-isolation.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/test-isolation.sh"
safe_test_setup_isolation || exit 1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
pass() { printf 'ok - %s\n' "$*"; }
fail() { printf 'not ok - %s\n' "$*" >&2; exit 1; }
for tool in jq python3; do
  command -v "$tool" >/dev/null 2>&1 || fail "missing required command: $tool"
done

tmp="$(mktemp -d)"
safe_test_compose_exit_trap "rm -rf \"\$tmp\""
export tmp ROOT

# shellcheck source=tests/lib/safe-core.sh
source "$ROOT/tests/lib/safe-core.sh"
if ! safe_core_test_prepare "$ROOT" "$tmp/safe-core"; then
  [[ "${SAFE_TEST_STRICT:-}" == "1" ]] && fail "safe-core could not be built under SAFE_TEST_STRICT=1"
  printf 'SKIP: safe-core unavailable\n'
  exit 0
fi

export HOME="$tmp/home"
export SAFE_RUN_CONFIG_DIR="$HOME/.config/safe/run" SAFE_RUN_DATA_DIR="$tmp/data"
export SAFE_AUDIT_DATA_DIR="$tmp/audit" SAFE_RUN_TRUST_OVERRIDE=0 SAFE_RUN_NO_INIT=0
export SAFE_AUDIT_AUDIT_LOG="$tmp/audit/audit-log.jsonl"
mkdir -p "$SAFE_RUN_CONFIG_DIR" "$tmp/bin" "$tmp/fix"
export PATH="$tmp/bin:$PATH"
AUDIT="$ROOT/bin/safe-audit"
RUN="$ROOT/bin/safe-run"
CORE="$SAFE_CORE_BIN"

NPM_ORIGIN="https://git.example.test:8443/api/packages/owner/npm"
GO_ORIGIN="https://git.example.test:8443/api/packages/owner/go"
PY_ORIGIN="https://git.example.test:8443/api/packages/owner/pypi"
EVIL="https://evil.example.test"
SRI_A="sha512-$(printf 'A%.0s' {1..86})=="
SECRET="fixture-secret-token-must-never-appear"
export NPM_ORIGIN GO_ORIGIN PY_ORIGIN EVIL SRI_A SECRET

# --- fake clients ----------------------------------------------------------
# npm answers `config get <scope>:registry` from an argv --<scope>:registry,
# else FAKE_NPM_SCOPE_REG, else the private origin; it never views metadata.
cat > "$tmp/bin/npm" <<'NPM'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$tmp/npm.argv"
if [[ "$1 $2" == "config get" ]]; then
  key="$3"
  for a in "$@"; do
    [[ "$a" == "--${key}="* ]] && { printf '%s\n' "${a#*=}"; exit 0; }
  done
  [[ "${FAKE_NPM_MODE:-ok}" == fail ]] && exit 1
  printf '%s\n' "${FAKE_NPM_SCOPE_REG-$NPM_ORIGIN/}"
  exit 0
fi
exit 0
NPM
# go answers `env -json` from FAKE_GOPROXY/FAKE_GONOPROXY/FAKE_GOPRIVATE and
# `mod edit -json <file>` from <file>.fakejson (or FAKE_GO_MODJSON).
cat > "$tmp/bin/go" <<'GO'
#!/usr/bin/env bash
printf '%s cwd=%s\n' "$*" "$PWD" >> "$tmp/go.argv"
if [[ "$1 $2" == "env -json" ]]; then
  jq -cn --arg p "${FAKE_GOPROXY-$GO_ORIGIN,https://proxy.golang.org,direct}" --arg n "${FAKE_GONOPROXY-}" --arg v "${FAKE_GOPRIVATE-}" \
    --arg f "${FAKE_GOFLAGS-}" --arg w "${FAKE_GOWORK-}" '{GOPROXY: $p, GONOPROXY: $n, GOPRIVATE: $v, GOFLAGS: $f, GOWORK: $w}'
  exit 0
fi
if [[ "$1 $2 $3" == "work edit -json" ]]; then
  cat "${FAKE_GOWORK_JSON:?}"
  exit 0
fi
if [[ "$1 $2 $3" == "mod edit -json" ]]; then
  if [[ -f "${4:-}.fakejson" ]]; then cat "$4.fakejson"; exit 0; fi
  [[ -n "${FAKE_GO_MODJSON:-}" ]] || exit 1
  cat "$FAKE_GO_MODJSON"
  exit 0
fi
exit 0
GO
# curl answers the Python namesake probes: other indexes FAKE_OTHER_CODE,
# PyPI FAKE_PYPI_CODE (404 = absent).
cat > "$tmp/bin/curl" <<'CURL'
#!/usr/bin/env bash
w="" url="${!#}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -w) w="$2"; shift 2 ;;
    -o|-D|-H|--max-time) shift 2 ;;
    *) shift ;;
  esac
done
printf '%s\n' "$url" >> "$tmp/curl.urls"
case "$(sed -E 's#://[^@/]+@#://#' <<<"$url")" in
  https://pypi.org/simple/*) code="${FAKE_PYPI_CODE:-404}" ;;
  "$PY_ORIGIN"/*) code=200 ;;
  *) code="${FAKE_OTHER_CODE:-404}" ;;
esac
[[ -z "$w" ]] || printf '%s' "$code"
exit 0
CURL
chmod +x "$tmp/bin/npm" "$tmp/bin/go" "$tmp/bin/curl"
printf '@p:registry=%s/\n//git.example.test:8443/api/packages/owner/npm/:_authToken=%s\n' "$NPM_ORIGIN" "$SECRET" > "$HOME/.npmrc"

policy="$SAFE_RUN_CONFIG_DIR/private-registries.json"
add_registry() { # id eco origin namespace
  "$CORE" private-trust registry-add --policy "$policy" --id "$1" --ecosystem "$2" --origin "$3" \
    --namespace "$4" >/dev/null || fail "registry-add $1"
}
reset_state() { rm -f "$policy" "$tmp/npm.argv" "$tmp/go.argv" "$tmp/curl.urls" "$SAFE_AUDIT_AUDIT_LOG"; }
# audit <spec> <eco> [env...] [-- package-audit flags...]: gate-mode audit
audit() {
  local spec="$1" eco="$2"
  shift 2
  local -a envs=() flags=()
  while [[ $# -gt 0 && "$1" != "--" ]]; do envs+=("$1"); shift; done
  [[ "${1:-}" == "--" ]] && { shift; flags=("$@"); }
  rm -f "$tmp/result.json"
  rc=0
  env "${envs[@]}" SAFE_AUDIT_RESULT_OUT="$tmp/result.json" "$AUDIT" package-audit "$spec" --ecosystem "$eco" --gate install "${flags[@]}" \
    > "$tmp/out" 2>&1 || rc=$?
}
decision() { jq -r '.private_registry.decision // empty' "$tmp/result.json" 2>/dev/null; }
no_secret() {
  ! grep -rqs "$SECRET" "$tmp/out" "$tmp/result.json" "$SAFE_AUDIT_AUDIT_LOG" "$policy" "$tmp/data" \
    || fail "the registry credential leaked: $1"
}

# --- not configured: nothing changes -----------------------------------------
reset_state
mkdir -p "$tmp/fix/plain"; printf '{"name":"a","version":"1.0.0","dependencies":{"@p/x":"1.0.0"}}\n' > "$tmp/fix/plain/package.json"
rc=0; "$AUDIT" private-npm-project --tool npm --class install --project-dir "$tmp/fix/plain" --gate install -- install > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" == 0 && ! -e "$tmp/npm.argv" ]] || fail "unconfigured npm project lane: rc=$rc"
rc=0; "$AUDIT" private-go --project-dir "$tmp/fix/plain" --gate install -- build ./... > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" == 0 && ! -e "$tmp/go.argv" ]] || fail "unconfigured go lane: rc=$rc"
pass "no private-registry policy: the lanes do nothing and ask no client"

# --- npm explicit specs -------------------------------------------------------
reset_state
add_registry p-npm npm "$NPM_ORIGIN" '@p/*'
audit @p/x@1.0.0 npm
[[ "$rc" == 18 ]] || fail "npm private spec: rc=$rc $(cat "$tmp/out")"
jq -e --arg o "$NPM_ORIGIN" '.private_registry.audit_extra == ("registry=p-npm origin=" + $o + " name=@p/x version=1.0.0")' "$tmp/result.json" >/dev/null \
  || fail "npm audit line: $(cat "$tmp/result.json")"
grep -q 'config get @p:registry' "$tmp/npm.argv" || fail "the scope mapping was not asked of npm"
grep -q 'view' "$tmp/npm.argv" && fail "the lane fetched metadata"
[[ ! -e "$tmp/curl.urls" ]] || fail "the npm lane made a network request"
no_secret "npm allow"
pass "npm: a private spec npm maps to its origin installs unattended (18) with one audit line naming registry, origin, name and version; no metadata fetch"

# A host whose npm is reachable only through mise shims bound to the mise
# wrapper (install.sh re-points them): the lane resolves the real npm through
# the real mise and never runs the shim, which would re-enter the gate.
mkdir -p "$tmp/mise-host/wrap" "$tmp/mise-host/shims" "$tmp/mise-host/mise"
for w in "wrap/npm tool=npm" "shims/npm tool=mise"; do
  printf '#!/usr/bin/env bash\n# safe-gate-wrapper v1 %s\nprintf reentered >> "$tmp/reentered"; exit 99\n' "${w#* }" > "$tmp/mise-host/${w%% *}"
done
printf '#!/usr/bin/env bash\nprintf "%%s cwd=%%s\\n" "$*" "$PWD" >> "$tmp/mise.argv"\n[[ "$1" == which && "$2" == npm ]] && { printf "%%s\\n" "$tmp/bin/npm"; exit 0; }\nexit 1\n' > "$tmp/mise-host/mise/mise"
chmod +x "$tmp/mise-host/wrap/npm" "$tmp/mise-host/shims/npm" "$tmp/mise-host/mise/mise"
rm -f "$tmp/npm.argv" "$tmp/reentered" "$tmp/mise.argv"
audit @p/x@1.0.0 npm PATH="$tmp/mise-host/wrap:$tmp/mise-host/shims:$tmp/mise-host/mise:/usr/bin:/bin"
[[ "$rc" == 18 ]] || fail "npm behind a mise-bound shim: rc=$rc $(cat "$tmp/out")"
[[ ! -e "$tmp/reentered" ]] || fail "the lane ran a gate wrapper or the mise-bound shim"
grep -q '^which npm ' "$tmp/mise.argv" && grep -q 'config get @p:registry' "$tmp/npm.argv" \
  || fail "the real npm was not resolved through the real mise"
pass "npm behind a mise shim bound to the mise wrapper: the lane resolves the real npm through the real mise (18), never re-entering the gate"
audit '@p/x@^1.0.0' npm
[[ "$rc" == 19 && "$(decision)" == private_version_not_exact ]] || fail "npm range: rc=$rc"
audit @p/x@1.0.0 npm FAKE_NPM_SCOPE_REG=undefined
[[ "$rc" == 20 && "$(decision)" == private_cross_registry ]] && grep -q 'default registry' "$tmp/out" || fail "unmapped scope: rc=$rc"
audit @p/x@1.0.0 npm FAKE_NPM_SCOPE_REG=https://registry.npmjs.org/
[[ "$rc" == 20 ]] || fail "scope mapped to npmjs: rc=$rc"
audit @p/x@1.0.0 npm -- --registry "@p:registry=$EVIL/npm/"
[[ "$rc" == 20 ]] || fail "argv scope selector elsewhere: rc=$rc"
audit @p/x@1.0.0 npm -- --registry "@p:registry=$NPM_ORIGIN/"
[[ "$rc" == 18 ]] || fail "argv scope selector at the origin: rc=$rc"
rm -f "$tmp/npm.argv"
printf '@p:registry=%s/\n' "$NPM_ORIGIN" > "$tmp/fix/alt.npmrc"
audit @p/x@1.0.0 npm -- --npm-userconfig "$tmp/fix/alt.npmrc"
grep -q -- "--userconfig=$tmp/fix/alt.npmrc" "$tmp/npm.argv" || fail "the selected npm userconfig did not reach npm"
audit @p/x@1.0.0 npm -- --installer bun
[[ "$rc" == 19 && "$(decision)" == private_route_unmodelled ]] || fail "bun: rc=$rc"
audit @p/x@1.0.0 npm FAKE_NPM_MODE=fail
[[ "$rc" == 19 && "$(decision)" == private_registry_unreachable ]] || fail "npm config failure: rc=$rc"
pass "npm: ranges ask (19); a scope npm maps elsewhere or not at all is cross-registry substitution (20); argv and config selectors are npm's own answer; bun and npm failures ask"
cat > "$tmp/fix/lock.json" <<JSON
{"lockfileVersion":3,"packages":{"":{},"node_modules/@p/x":{"version":"1.0.0","resolved":"$NPM_ORIGIN/@p%2fx/-/1.0.0/x-1.0.0.tgz","integrity":"$SRI_A"},
 "node_modules/alias":{"name":"@p/x","version":"1.0.0","resolved":"$NPM_ORIGIN/@p%2fx/-/1.0.0/x-1.0.0.tgz","integrity":"$SRI_A"}}}
JSON
audit @p/x@1.0.0 npm SAFE_AUDIT_ARTIFACT_LOCKFILE="$tmp/fix/lock.json"
[[ "$rc" == 18 ]] && jq -e '.resolved_versions[0] == "1.0.0"' "$tmp/result.json" >/dev/null || fail "lock-diff at the origin: rc=$rc $(cat "$tmp/out")"
jq '.packages["node_modules/alias"].resolved = "https://registry.npmjs.org/@p/x/-/x-1.0.0.tgz"' "$tmp/fix/lock.json" > "$tmp/fix/lock-evil.json"
audit @p/x@1.0.0 npm SAFE_AUDIT_ARTIFACT_LOCKFILE="$tmp/fix/lock-evil.json"
[[ "$rc" == 20 ]] || fail "lock-diff alias resolved elsewhere: rc=$rc"
pass "npm lock-diff: every lockfile entry of the name (aliases included) must resolve under the origin"
rc=0; "$AUDIT" package-audit @p/x@1.0.0 --ecosystem npm > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" == 0 ]] && grep -q 'VERDICT: PRIVATE' "$tmp/out" || fail "direct check: rc=$rc $(cat "$tmp/out")"
rc=0; "$AUDIT" package-audit @p/x@1.0.0 --ecosystem npm --json > "$tmp/out" 2>/dev/null || rc=$?
jq -e '.verdict == "PRIVATE"' "$tmp/out" >/dev/null || fail "direct json verdict"
pass "a direct package-audit reports PRIVATE, never GO"

# --- npm projects ---------------------------------------------------------------
mkdir -p "$tmp/fix/npmproj"
proj() { # class [env...] -- argv
  local class="$1"; shift
  local -a envs=()
  while [[ $# -gt 0 && "$1" != "--" ]]; do envs+=("$1"); shift; done
  shift
  rm -f "$tmp/result.json"
  rc=0
  env "${envs[@]}" SAFE_AUDIT_RESULT_OUT="$tmp/result.json" "$AUDIT" private-npm-project --tool "${PROJ_TOOL:-npm}" --class "$class" \
    --project-dir "$tmp/fix/npmproj" --gate install -- "$@" > "$tmp/out" 2>&1 || rc=$?
}
manifest() { printf '%s\n' "$1" > "$tmp/fix/npmproj/package.json"; }
lock() { printf '%s\n' "$1" > "$tmp/fix/npmproj/package-lock.json"; }
manifest '{"name":"app","version":"1.0.0","dependencies":{"@p/x":"1.0.0","left-pad":"1.3.0"}}'
cp "$tmp/fix/lock.json" "$tmp/fix/npmproj/package-lock.json"
proj ci -- ci
[[ "$rc" == 18 ]] && jq -e --arg o "$NPM_ORIGIN" '.private_registry_lines | length == 1 and .[0].package == "@p/x@1.0.0" and (.[0].extra == ("registry=p-npm origin=" + $o + " name=@p/x version=1.0.0"))' "$tmp/result.json" >/dev/null \
  || fail "npm ci private entries: rc=$rc $(cat "$tmp/out") $(cat "$tmp/result.json" 2>/dev/null)"
lock "$(jq '.packages["node_modules/@p/x"].resolved = "https://registry.npmjs.org/@p/x/-/x-1.0.0.tgz"' "$tmp/fix/lock.json")"
proj ci -- ci
[[ "$rc" == 20 && "$(decision)" == private_cross_registry ]] || fail "lockfile entry resolved elsewhere: rc=$rc"
manifest '{"name":"app","version":"1.0.0","dependencies":{"@p/x":"1.0.0"}}'
lock "$(jq -n --arg r "$EVIL/x.tgz" '{lockfileVersion: 3, packages: {"": {}, "node_modules/@p/x": {name: "fixture-public", version: "1.0.0", resolved: $r}}}')"
proj ci -- ci
[[ "$rc" == 20 ]] || fail "a private install path hidden by an untrusted name field: rc=$rc"
manifest '{"name":"app","version":"1.0.0","dependencies":{"private-alias":"npm:@p/x@1.0.0"}}'
lock "$(jq -n --arg r "$EVIL/x.tgz" '{lockfileVersion: 1, dependencies: {"private-alias": {version: "npm:@p/x@1.0.0", resolved: $r}}}')"
proj ci -- ci
[[ "$rc" == 20 ]] || fail "a v1 alias resolved elsewhere: rc=$rc $(cat "$tmp/out")"
lock "$(jq -n --arg r "$NPM_ORIGIN/@p%2fx/-/1.0.0/x-1.0.0.tgz" '{lockfileVersion: 1, dependencies: {"pub": {version: "2.0.0", resolved: "https://registry.npmjs.org/pub/-/pub-2.0.0.tgz", dependencies: {"private-alias": {version: "npm:@p/x@1.0.0", resolved: $r}}}}}')"
proj ci -- ci
[[ "$rc" == 18 ]] && jq -e '.private_registry_lines[0].package == "@p/x@1.0.0"' "$tmp/result.json" >/dev/null || fail "a nested v1 alias at the origin: rc=$rc $(cat "$tmp/out")"
lock "$(jq -n '{lockfileVersion: 3, packages: {"": {}, "node_modules/@p/x": {version: "1.0.0"}}}')"
proj ci -- ci
[[ "$rc" == 19 && "$(decision)" == private_project_unmodelled ]] || fail "a private entry without a resolved URL: rc=$rc"
lock "$(jq -n '{lockfileVersion: 3, packages: {"": {}, "node_modules/pub/node_modules/@p/x": {version: "1.0.0", inBundle: true}}}')"
proj ci -- ci
[[ "$rc" == 19 ]] || fail "a bundled private entry: rc=$rc"
lock "$(jq -n '{lockfileVersion: 3, packages: {"": {}, "node_modules/@p/x": {resolved: "packages/x", link: true}}}')"
proj ci -- ci
[[ "$rc" == 0 ]] || fail "a linked workspace entry is local: rc=$rc"
lock 'not json'
proj ci -- ci
[[ "$rc" == 19 ]] || fail "an unreadable lockfile with a private name: rc=$rc $(cat "$tmp/out")"
pass "npm project lane: every lockfile entry whose path, name or alias target (v1 and v3) is private must resolve under its origin (20 otherwise); entries without a resolved URL, bundled or unreadable ask (19); links are local"
manifest '{"name":"app","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}'
lock '{"lockfileVersion":3,"packages":{"":{}}}'
proj install -- install
[[ "$rc" == 0 ]] || fail "a public project on a configured host: rc=$rc"
proj install FAKE_NPM_SCOPE_REG=https://registry.npmjs.org/ -- install
[[ "$rc" == 20 ]] || fail "a registered scope npm maps elsewhere BLOCKs even before a private name is visible: rc=$rc"
proj install FAKE_NPM_SCOPE_REG=undefined -- install
[[ "$rc" == 20 && "$(decision)" == private_cross_registry ]] || fail "a43: an unmapped registered scope BLOCKs every npm project operation: rc=$rc"
proj ci FAKE_NPM_SCOPE_REG=undefined -- ci
[[ "$rc" == 20 ]] || fail "a43: an unmapped registered scope BLOCKs npm ci too: rc=$rc"
proj install FAKE_NPM_MODE=fail -- install
[[ "$rc" == 19 && "$(decision)" == private_registry_unreachable ]] || fail "a43: an unanswered scope mapping asks: rc=$rc"
proj install FAKE_NPM_SCOPE_REG=undefined -- install @p/x@1.0.0
[[ "$rc" == 20 ]] || fail "an unmapped scope when the operation names a private package: rc=$rc"
PROJ_TOOL=pnpm proj install -- add @p/x@1.0.0
[[ "$rc" == 19 && "$(decision)" == private_project_unmodelled ]] || fail "pnpm naming a private package: rc=$rc"
PROJ_TOOL=pnpm proj install -- install
[[ "$rc" == 0 ]] || fail "pnpm public project: rc=$rc"
proj install -- install --prefix /elsewhere @p/x@1.0.0
[[ "$rc" == 19 ]] || fail "--prefix with a private name: rc=$rc"
pass "npm project lane: registered scopes must map to their origin (mapped elsewhere or, ruling a43, not at all BLOCKs every npm install/ci); pnpm/yarn/bun and lockfile-redirecting flags ask on a private name"

# the shipped npm ci route reaches the project lane before delegation
cat > "$tmp/route.sh" <<'ROUTE'
#!/usr/bin/env bash
set -uo pipefail
export SAFE_RUN_DATA_DIR="$tmp/rdata" TMPDIR="$tmp/tmpdir"
mkdir -p "$SAFE_RUN_DATA_DIR" "$TMPDIR"
source "$ROOT/lib/gate-lib.sh"
SAFE_GATE_AUDIT_BIN="$ROOT/bin/safe-audit"
safe_gate_audit_available() { return 0; }
safe_gate_operator_terminal() { return 1; }
safe_gate_scan_project() { printf 'SCAN\n' >> "$tmp/scanned"; return 0; }
[[ "${ROUTE_REAL_CHECK:-0}" == 1 ]] || safe_gate_check_many() { printf 'SPEC %s\n' "$*" > "$tmp/spec"; return 0; }
safe_gate_exec_real() { printf 'DELEGATED %s PIP_CONFIG_FILE=%s PIP_INDEX_URL=%s UV_NO_CONFIG=%s UV_INDEX=%s UV_INDEX_P_PASSWORD=%s\n' "$*" "${PIP_CONFIG_FILE:-}" "${PIP_INDEX_URL:-}" "${UV_NO_CONFIG:-}" "${UV_INDEX:-}" "${UV_INDEX_P_PASSWORD:+set}" > "$tmp/delegated"; exit 0; }
cd "${ROUTE_DIR:-$tmp/fix/npmproj}"
"$@"
ROUTE
chmod +x "$tmp/route.sh"
manifest '{"name":"app","version":"1.0.0","dependencies":{"@p/x":"1.0.0"}}'
lock "$(jq '.packages["node_modules/@p/x"].resolved = "https://registry.npmjs.org/@p/x/-/x-1.0.0.tgz"' "$tmp/fix/lock.json")"
rm -f "$tmp/delegated"
rc=0; bash "$tmp/route.sh" safe_gate_npm_like npm ci > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" == 104 && ! -e "$tmp/delegated" ]] || fail "npm ci route delegated a substituted private entry: rc=$rc $(cat "$tmp/out")"
cp "$tmp/fix/lock.json" "$tmp/fix/npmproj/package-lock.json"
rc=0; bash "$tmp/route.sh" safe_gate_npm_like npm ci > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" == 0 && -e "$tmp/delegated" ]] && grep -q 'ALLOWED_VIA_PRIVATE_REGISTRY.*name=@p/x version=1.0.0' "$tmp/rdata/audit.log" \
  || fail "npm ci route with entries at the origin: rc=$rc $(cat "$tmp/out")"
pass "the shipped npm ci route decides private lockfile entries before delegating (104 substituted, 0 + audit line otherwise)"

# --- trust root and store integrity ------------------------------------------
rc=0; SAFE_RUN_CONFIG_DIR="$tmp/elsewhere" "$AUDIT" private-npm-project --tool npm --class ci --project-dir "$tmp/fix/npmproj" --gate install -- ci > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" == 0 ]] || fail "redirected root honored the private policy: rc=$rc"
cp "$policy" "$tmp/policy.bak"
printf '{"schema":"safe-private-registries/2","registries":{"x":{"ecosystem":"npm","origin":"http://evil.example.test/","namespace":["@p/*"]}}}\n' > "$policy"
audit @p/x@1.0.0 npm
[[ "$rc" == 30 ]] && grep -q 'malformed' "$tmp/out" || fail "malformed policy: rc=$rc $(cat "$tmp/out")"
cp "$tmp/policy.bak" "$policy"
pass "an unblessed redirected trust root declines the policy; a malformed store decides nothing (30)"

# --- python -------------------------------------------------------------------
reset_state
add_registry p-py python "$PY_ORIGIN" caviar-redact
PYI=(--python-isolated --registry "$PY_ORIGIN/simple")
audit caviar-redact@0.2.0 python -- "${PYI[@]}"
[[ "$rc" == 18 ]] && jq -e --arg o "$PY_ORIGIN" '.private_registry.audit_extra == ("registry=p-py origin=" + $o + " name=caviar-redact version=0.2.0")' "$tmp/result.json" >/dev/null \
  || fail "python private spec: rc=$rc $(cat "$tmp/out")"
grep -q 'https://pypi.org/simple/caviar-redact/' "$tmp/curl.urls" || fail "the PyPI namesake probe did not run"
audit caviar-redact@0.2.0 python PIP_INDEX_URL="$EVIL/simple" PIP_EXTRA_INDEX_URL="$EVIL/simple" -- "${PYI[@]}"
[[ "$rc" == 18 ]] || fail "source environment the isolated delegate drops still decided: rc=$rc"
pass "python: an isolated pip/uv pip install whose argv index is the origin installs unattended (18) with the audit line; configuration and source env do not count (the delegate drops them)"
audit caviar-redact@0.2.0 python -- --registry "$PY_ORIGIN/simple"
[[ "$rc" == 19 && "$(decision)" == private_route_unmodelled ]] || fail "a route the gate does not isolate: rc=$rc"
audit caviar-redact@0.2.0 python -- --python-isolated
[[ "$rc" == 20 && "$(decision)" == private_cross_registry ]] || fail "no argv index at the origin: rc=$rc"
audit caviar-redact@0.2.0 python -- "${PYI[@]}" --find-links-selected
[[ "$rc" == 20 ]] || fail "argv find-links: rc=$rc"
audit caviar-redact@0.2.0 python -- --python-isolated --registry "$PY_ORIGIN/simple local:no-index"
[[ "$rc" == 20 ]] || fail "argv --no-index: rc=$rc"
audit caviar-redact@0.2.0 python FAKE_OTHER_CODE=200 -- --python-isolated --registry "$PY_ORIGIN/simple $EVIL/simple"
[[ "$rc" == 20 ]] && grep -q 'dependency confusion' "$tmp/out" || fail "another argv index serves the name: rc=$rc"
audit caviar-redact@0.2.0 python -- --python-isolated --registry "$PY_ORIGIN/simple $EVIL/simple"
[[ "$rc" == 18 ]] || fail "another argv index without the name: rc=$rc"
audit caviar-redact@0.2.0 python FAKE_PYPI_CODE=200 -- "${PYI[@]}"
[[ "$rc" == 20 ]] || fail "a PyPI namesake: rc=$rc"
audit caviar-redact@0.2.0 python FAKE_PYPI_CODE=503 -- "${PYI[@]}"
[[ "$rc" == 19 && "$(decision)" == private_registry_unreachable ]] || fail "probe outage: rc=$rc"
audit caviar-redact@0.2.0 python -- "${PYI[@]}" --uv-config-file-selected
[[ "$rc" == 19 ]] || fail "uv --config-file: rc=$rc"
audit 'caviar-redact@>=0.2' python -- "${PYI[@]}"
[[ "$rc" == 19 ]] || fail "python range: rc=$rc"
audit caviar-redact@0.2.0 python -- --python-isolated --registry "https://user:$SECRET@git.example.test:8443/api/packages/owner/pypi/simple"
[[ "$rc" == 18 ]] || fail "inline-credential origin index: rc=$rc"
no_secret "python inline credential"
pass "python: an unisolated route asks; no origin index, argv find-links/--no-index, another index or PyPI serving the name BLOCK; a probe outage, uv --config-file and ranges ask; an inline-credential index is never printed"
printf 'caviar-redact==0.2.0\nrequests==2.32.0\n' > "$tmp/fix/req.txt"
printf 'requests==2.32.0\n' > "$tmp/fix/req-public.txt"
rc=0; SAFE_AUDIT_RESULT_OUT="$tmp/result.json" "$AUDIT" private-python-project --gate install -- "$tmp/fix/req.txt" > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" == 19 && "$(decision)" == private_route_unmodelled ]] || fail "a requirements file naming a private package: rc=$rc"
rc=0; "$AUDIT" private-python-project --gate install -- "$tmp/fix/req-public.txt" > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" == 0 ]] || fail "a public requirements file: rc=$rc"
pass "python: a requirements file naming a private package asks (19)"
( source "$ROOT/lib/gate-lib.sh"
  export PIP_INDEX_URL=x PIP_EXTRA_INDEX_URL=y UV_INDEX=z UV_CONFIG_FILE=c
  SAFE_GATE_PRIVATE_PY_ALLOWED=0; safe_gate_python_isolate pip
  [[ "$PIP_INDEX_URL" == x && -z "${PIP_CONFIG_FILE:-}" ]] || exit 1
  SAFE_GATE_PRIVATE_PY_ALLOWED=1; safe_gate_python_isolate pip
  [[ "$PIP_CONFIG_FILE" == /dev/null && -z "${PIP_INDEX_URL:-}" && -z "${PIP_EXTRA_INDEX_URL:-}" ]] || exit 2
  safe_gate_python_isolate uv
  [[ "$UV_NO_CONFIG" == 1 && -z "${UV_INDEX:-}" && -z "${UV_CONFIG_FILE:-}" ]] || exit 3
  [[ "$(safe_gate_python_requirement_files install -r a.txt --constraint=b.txt -rc.txt x==1 | paste -sd,)" == "a.txt,b.txt,c.txt" ]] || exit 4
) || fail "python delegate isolation helpers: $?"
mkdir -p "$tmp/fix/pyproj"
rm -f "$tmp/delegated"
rc=0; ROUTE_REAL_CHECK=1 ROUTE_DIR="$tmp/fix/pyproj" PIP_INDEX_URL="$EVIL/simple" bash "$tmp/route.sh" safe_gate_pip_like pip install --index-url "$PY_ORIGIN/simple" caviar-redact==0.2.0 > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" == 0 ]] && grep -q 'PIP_CONFIG_FILE=/dev/null PIP_INDEX_URL= ' "$tmp/delegated" \
  || fail "the shipped pip route did not isolate the delegate: rc=$rc $(cat "$tmp/out") $(cat "$tmp/delegated" 2>/dev/null)"
pass "the shipped pip route delegates a private allow with its configuration switched off and the source env dropped"
# uv names an index as <name>=<url>: the URL is the source, and the name
# selects its UV_INDEX_<NAME>_* credentials, which the delegate keeps.
for flag in --index --default-index; do
  rm -f "$tmp/delegated"
  rc=0; ROUTE_REAL_CHECK=1 ROUTE_DIR="$tmp/fix/pyproj" UV_INDEX_P_PASSWORD=fixture UV_INDEX="q=$EVIL/simple" bash "$tmp/route.sh" safe_gate_uv pip install "$flag" "p=$PY_ORIGIN/simple" caviar-redact==0.2.0 > "$tmp/out" 2>&1 || rc=$?
  [[ "$rc" == 0 ]] && grep -q 'UV_NO_CONFIG=1 UV_INDEX= UV_INDEX_P_PASSWORD=set' "$tmp/delegated" \
    || fail "uv pip install $flag <name>=<origin>: rc=$rc $(cat "$tmp/out") $(cat "$tmp/delegated" 2>/dev/null)"
  rm -f "$tmp/delegated"
  rc=0; ROUTE_REAL_CHECK=1 ROUTE_DIR="$tmp/fix/pyproj" bash "$tmp/route.sh" safe_gate_uv pip install "$flag=p=$EVIL/simple" caviar-redact==0.2.0 > "$tmp/out" 2>&1 || rc=$?
  [[ "$rc" == 104 && ! -e "$tmp/delegated" ]] || fail "uv pip install $flag=<name>=<elsewhere>: rc=$rc $(cat "$tmp/out")"
done
pass "uv named indexes: --index/--default-index <name>=<origin> install unattended with the index credentials kept; a named index elsewhere BLOCKs (104)"
( source "$ROOT/lib/gate-lib.sh"
  SAFE_GATE_REGISTRY=""; safe_gate_scan_target_flags python pip install --index p=https://pypi.org/simple requests==2.32.0
  [[ "$SAFE_GATE_REGISTRY" == "p=https://pypi.org/simple" ]] ) || fail "the general source set rewrote a uv named index"
[[ "$(UV_INDEX=p=https://pypi.org/simple bash -c 'source <(sed -n "/^python_env_sources() {/,/^}/p" "$ROOT/bin/safe-audit"); python_bool_truthy() { return 1; }; python_env_sources' 2>/dev/null | head -n 1)" == p=https://pypi.org/simple* ]] \
  || fail "the environment source set rewrote a uv named index"
pass "public audits keep a uv named index selector verbatim; only the private lane reads its URL"

# --- go -----------------------------------------------------------------------
reset_state
add_registry p-go go "$GO_ORIGIN" superbiche.me
audit superbiche.me/caviar@v0.2.0 go
[[ "$rc" == 18 ]] && jq -e --arg o "$GO_ORIGIN" '.private_registry.audit_extra == ("registry=p-go origin=" + $o + " name=superbiche.me/caviar version=v0.2.0 route=" + $o)' "$tmp/result.json" >/dev/null \
  || fail "go private spec: rc=$rc $(cat "$tmp/out") $(cat "$tmp/result.json" 2>/dev/null)"
grep -q 'mod download' "$tmp/go.argv" && fail "the go lane downloaded"
audit superbiche.me/caviar@v0.2.0 go FAKE_GOPROXY="file:///repo/third_party/goproxy,$GO_ORIGIN,https://proxy.golang.org,direct"
[[ "$rc" == 18 ]] && jq -e '.private_registry.audit_extra | contains("route=file:///repo/third_party/goproxy,")' "$tmp/result.json" >/dev/null \
  || fail "a local file:// GOPROXY ahead of the origin: rc=$rc"
pass "go: a namespace module routed to its origin installs unattended (18) with the route in the audit line; local file:// GOPROXY entries ahead of the origin are local artifacts"
for proxy in "https://proxy.golang.org,$GO_ORIGIN" "direct" "file:///repo/goproxy,https://proxy.golang.org,$GO_ORIGIN" "$EVIL/go,$GO_ORIGIN"; do
  audit superbiche.me/caviar@v0.2.0 go FAKE_GOPROXY="$proxy"
  [[ "$rc" == 20 && "$(decision)" == private_cross_registry ]] || fail "GOPROXY=$proxy: rc=$rc"
done
audit superbiche.me/caviar@v0.2.0 go FAKE_GOPRIVATE=superbiche.me
[[ "$rc" == 20 ]] || fail "GOPRIVATE: rc=$rc"
audit superbiche.me/caviar@latest go
[[ "$rc" == 19 ]] || fail "go query: rc=$rc"
pass "go: another proxy, direct or GOPRIVATE ahead of the origin BLOCK (20); queries ask"
mkdir -p "$tmp/fix/gomod/sub"
printf 'module example.com/app\n' > "$tmp/fix/gomod/go.mod"
jq -n '{Module: {Path: "example.com/app"}, Go: "1.22", Require: [{Path: "superbiche.me/caviar", Version: "v0.2.0"}, {Path: "example.com/public", Version: "v1.0.0"}]}' > "$tmp/fix/gomod/go.mod.fakejson"
gol() { local dir="$1"; shift; local -a envs=(); while [[ $# -gt 0 && "$1" != "--" ]]; do envs+=("$1"); shift; done; shift
  rm -f "$tmp/result.json"; rc=0
  env "${envs[@]}" SAFE_AUDIT_RESULT_OUT="$tmp/result.json" "$AUDIT" private-go --project-dir "$dir" --gate install -- "$@" > "$tmp/out" 2>&1 || rc=$?; }
gol "$tmp/fix/gomod/sub" -- build ./...
[[ "$rc" == 18 ]] && jq -e '.private_registry_lines | length == 1 and .[0].package == "superbiche.me/caviar@v0.2.0"' "$tmp/result.json" >/dev/null \
  || fail "go project audit lines: rc=$rc $(cat "$tmp/out")"
gol "$tmp/fix/gomod" FAKE_GOPROXY="https://proxy.golang.org,direct" -- build ./...
[[ "$rc" == 20 ]] || fail "a misrouted namespace BLOCKs every module command: rc=$rc"
gol "$tmp/fix/plain" FAKE_GOPROXY="https://proxy.golang.org,direct" -- build ./...
[[ "$rc" == 20 ]] || fail "a misrouted namespace BLOCKs outside a module too: rc=$rc"
gol "$tmp/fix/gomod" FAKE_GOPROXY="file:///repo/third_party/goproxy,$GO_ORIGIN" -- test ./...
[[ "$rc" == 18 ]] || fail "Memoire-style file:// then origin: rc=$rc"
gol "$tmp/fix/gomod" FAKE_GOPROXY="file:///repo/third_party/goproxy,off" -- build ./...
[[ "$rc" == 18 ]] && jq -e '.private_registry_lines[0].extra | contains("route=file:///repo/third_party/goproxy,off")' "$tmp/result.json" >/dev/null || fail "local-only routing: rc=$rc"
gol "$tmp/fix/nonexistent" -- -C "$tmp/fix/plain" mod download superbiche.me/other@v1.2.3
[[ "$rc" == 18 ]] && grep -q "cwd=$tmp/fix/plain" "$tmp/go.argv" && jq -e '.private_registry_lines[0].package == "superbiche.me/other@v1.2.3"' "$tmp/result.json" >/dev/null \
  || fail "go -C and explicit download targets: rc=$rc"
gol "$tmp/fix/gomod" -- build -modfile=missing.mod ./...
[[ "$rc" == 18 ]] && jq -e '.private_registry_lines[0].extra | contains("version=unknown")' "$tmp/result.json" >/dev/null || fail "an unreadable module file still logs the route: rc=$rc"
jq -n '{Module: {Path: "example.com/app"}, Go: "1.22", Require: [{Path: "example.com/public", Version: "v1.0.0"}]}' > "$tmp/fix/gomod/go.mod.fakejson"
gol "$tmp/fix/gomod" -- build ./...
[[ "$rc" == 18 ]] && jq -e --arg o "$GO_ORIGIN" '.private_registry_lines | length == 1 and .[0].package == "superbiche.me@go-build" and (.[0].extra == ("registry=p-go origin=" + $o + " name=superbiche.me version=unknown route=" + $o + " command=go-build"))' "$tmp/result.json" >/dev/null \
  || fail "a module requiring nothing private still logs the namespace fallback line: rc=$rc $(cat "$tmp/result.json" 2>/dev/null)"
pass "go lane: every module command checks the namespace routing in its own context (go -C followed; file:// sources local; misrouting BLOCKs); audit lines name the namespace requirements and explicit download targets"
cp "$tmp/fix/gomod/go.mod.fakejson" "$tmp/fix/gomod/go.mod.public"
jq -n '{Module: {Path: "example.com/app"}, Go: "1.22", Require: [{Path: "superbiche.me/caviar", Version: "v0.2.0"}]}' > "$tmp/fix/gomod/go.mod.fakejson"
for cmd in "run ." "install" "install ./cmd/app" "vet ./..." "list -m all" "mod vendor" "mod tidy" "build ./..."; do
  rm -f "$tmp/delegated"
  rc=0; ROUTE_DIR="$tmp/fix/gomod" FAKE_GOPROXY="https://proxy.golang.org,direct" bash "$tmp/route.sh" safe_gate_go $cmd > "$tmp/out" 2>&1 || rc=$?
  [[ "$rc" == 104 && ! -e "$tmp/delegated" ]] || fail "go $cmd delegated with the namespace misrouted: rc=$rc $(cat "$tmp/out")"
done
rm -f "$tmp/delegated"
rc=0; ROUTE_DIR="$tmp/fix/gomod" bash "$tmp/route.sh" safe_gate_go run . > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" == 0 && -e "$tmp/delegated" ]] && grep -q 'ALLOWED_VIA_PRIVATE_REGISTRY.*name=superbiche.me/caviar version=v0.2.0' "$tmp/rdata/audit.log" \
  || fail "go run with the namespace routed: rc=$rc $(cat "$tmp/out")"
rm -f "$tmp/delegated" "$tmp/spec"
rc=0; ROUTE_DIR="$tmp/fix/gomod" bash "$tmp/route.sh" safe_gate_go install superbiche.me/tool@v1.0.0 > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" == 0 && -e "$tmp/spec" ]] || fail "go install <mod>@<ver> stays on the spec lane: rc=$rc"
pass "the shipped go routes (run, install, vet, list, go mod *, build) check the routing before delegating"
# The repo-audit scanner's Go cataloger runs `go list` through the gate: a
# project scan on list or vet re-entered the gate without end (1.69.0, live).
for cmd in "vet ./..." "list -e -f {{context.ReleaseTags}} -- unsafe" "list -m all"; do
  rm -f "$tmp/delegated" "$tmp/scanned"
  rc=0; ROUTE_DIR="$tmp/fix/gomod" bash "$tmp/route.sh" safe_gate_go $cmd > "$tmp/out" 2>&1 || rc=$?
  [[ "$rc" == 0 && -e "$tmp/delegated" && ! -e "$tmp/scanned" ]] || fail "go $cmd ran the project scan or did not delegate: rc=$rc $(cat "$tmp/out")"
done
rm -f "$tmp/delegated" "$tmp/scanned"
rc=0; ROUTE_DIR="$tmp/fix/gomod" bash "$tmp/route.sh" safe_gate_go build ./... > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" == 0 && -e "$tmp/scanned" ]] || fail "go build no longer scans the project: rc=$rc"
pass "go list and go vet check the private routing without a project scan (the scanner runs go list itself); go build still scans"

# --- review round 4 correctives --------------------------------------------------
reset_state
add_registry p-npm npm "$NPM_ORIGIN" '@p/*'
add_registry p-py python "$PY_ORIGIN" caviar-redact
add_registry p-go go "$GO_ORIGIN" superbiche.me
blocklist="$SAFE_RUN_CONFIG_DIR/blocked.json"

# P1: a v3 alias whose installed key and declared name look public, bound to
# its private target by the manifest or a lock entry's dependency map
manifest '{"name":"app","version":"1.0.0","dependencies":{"alias":"npm:@p/x@1.0.0"}}'
lock "$(jq -n --arg r "$EVIL/x.tgz" '{lockfileVersion: 3, packages: {"": {dependencies: {"alias": "npm:@p/x@1.0.0"}}, "node_modules/alias": {name: "fixture-public", version: "1.0.0", resolved: $r}}}')"
proj ci -- ci
[[ "$rc" == 20 && "$(decision)" == private_cross_registry ]] || fail "P1: v3 alias bound by the manifest, resolved elsewhere: rc=$rc $(cat "$tmp/out")"
manifest '{"name":"app","version":"1.0.0","dependencies":{"pub":"1.0.0"}}'
lock "$(jq -n --arg r "$EVIL/x.tgz" '{lockfileVersion: 3, packages: {"": {dependencies: {"pub": "1.0.0"}}, "node_modules/pub": {version: "1.0.0", resolved: "https://registry.npmjs.org/pub/-/pub-1.0.0.tgz", dependencies: {"alias": "npm:@p/x@1.0.0"}}, "node_modules/alias": {name: "fixture-public", version: "1.0.0", resolved: $r}}}')"
proj ci -- ci
[[ "$rc" == 20 ]] || fail "P1: v3 alias bound by a lock entry's dependency map, resolved elsewhere: rc=$rc"
manifest '{"name":"app","version":"1.0.0","dependencies":{"alias":"npm:@p/x@1.0.0"}}'
lock "$(jq -n --arg r "$NPM_ORIGIN/@p%2fx/-/1.0.0/x-1.0.0.tgz" '{lockfileVersion: 3, packages: {"": {dependencies: {"alias": "npm:@p/x@1.0.0"}}, "node_modules/alias": {name: "fixture-public", version: "1.0.0", resolved: $r}}}')"
proj ci -- ci
[[ "$rc" == 18 ]] && jq -e '[.private_registry_lines[].package] | index("@p/x@1.0.0") != null' "$tmp/result.json" >/dev/null || fail "P1: v3 alias at the origin: rc=$rc $(cat "$tmp/out")"
pass "round-4 P1: a v3 alias entry is bound to its private target (manifest or any lock entry's dependency map) whatever its key and declared name"

# P11: a synthetic query token in a source never reaches a sink
TOK="SYNTHQUERYTOKEN"
leak() { ! grep -rqs "$TOK" "$tmp/out" "$tmp/result.json" "$SAFE_AUDIT_AUDIT_LOG" || fail "P11: the query token leaked: $1"; }
audit @p/x@1.0.0 npm FAKE_NPM_SCOPE_REG="$EVIL/npm/?token=$TOK#frag"
[[ "$rc" == 20 ]] || fail "P11: npm spec scope elsewhere: rc=$rc"
grep -q "$EVIL/npm" "$tmp/out" || fail "P11: the sanitized source is not named: $(cat "$tmp/out")"
leak "npm spec refusal"
manifest '{"name":"app","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}'
lock '{"lockfileVersion":3,"packages":{"":{}}}'
proj install FAKE_NPM_SCOPE_REG="https://u:$TOK@registry.npmjs.org/?t=$TOK" -- install
[[ "$rc" == 20 ]] || fail "P11: npm project scope elsewhere: rc=$rc"
leak "npm project refusal"
manifest '{"name":"app","version":"1.0.0","dependencies":{"@p/x":"1.0.0"}}'
lock "$(jq -n --arg r "$EVIL/x.tgz?token=$TOK" '{lockfileVersion: 3, packages: {"": {}, "node_modules/@p/x": {version: "1.0.0", resolved: $r}}}')"
proj ci -- ci
[[ "$rc" == 20 ]] || fail "P11: lockfile entry elsewhere: rc=$rc"
leak "npm lockfile refusal"
audit caviar-redact@0.2.0 python FAKE_OTHER_CODE=200 -- --python-isolated --registry "$PY_ORIGIN/simple https://u:$TOK@evil.example.test/simple?token=$TOK"
[[ "$rc" == 20 ]] || fail "P11: python namesake index: rc=$rc"
leak "python namesake refusal"
audit superbiche.me/caviar@v0.2.0 go FAKE_GOPROXY="$EVIL/go?token=$TOK,$GO_ORIGIN"
[[ "$rc" == 20 ]] || fail "P11: go route elsewhere: rc=$rc"
leak "go route refusal"
pass "round-4 P11: npm, lockfile, Python and Go refusals name a source without userinfo, query or fragment in every sink"

# P12: every Go bypass logs a line, first use and workspace roots included;
# npm first installs log theirs
mkdir -p "$tmp/fix/ws/app" "$tmp/fix/ws/lib"
printf 'module example.com/workapp\n' > "$tmp/fix/ws/app/go.mod"
jq -n '{Module: {Path: "example.com/workapp"}, Require: [{Path: "superbiche.me/caviar", Version: "v0.2.0"}]}' > "$tmp/fix/ws/app/go.mod.fakejson"
printf '{"Use":[{"DiskPath":"./app"},{"DiskPath":"./lib"}]}\n' > "$tmp/fix/ws/work.json"
gol "$tmp/fix/ws" FAKE_GOWORK="$tmp/fix/ws/go.work" FAKE_GOWORK_JSON="$tmp/fix/ws/work.json" -- run ./app
[[ "$rc" == 18 ]] && jq -e '.private_registry_lines | map(.package) == ["superbiche.me/caviar@v0.2.0"]' "$tmp/result.json" >/dev/null \
  || fail "P12: a workspace root without go.mod logs its members' requirements: rc=$rc $(cat "$tmp/result.json" 2>/dev/null)"
cp "$tmp/fix/ws/app/go.mod.fakejson" "$tmp/fix/gomod/alt.mod.fakejson"
cp "$tmp/fix/gomod/go.mod.public" "$tmp/fix/gomod/go.mod.fakejson"
gol "$tmp/fix/gomod" FAKE_GOFLAGS="-modfile=alt.mod" -- build ./...
[[ "$rc" == 18 ]] && jq -e '.private_registry_lines[0].package == "superbiche.me/caviar@v0.2.0"' "$tmp/result.json" >/dev/null || fail "P12: a GOFLAGS -modfile logs its requirements: rc=$rc"
mkdir -p "$tmp/fix/tidy"; printf 'module example.com/tidy\n' > "$tmp/fix/tidy/go.mod"
jq -n '{Module: {Path: "example.com/tidy"}, Require: []}' > "$tmp/fix/tidy/go.mod.fakejson"
gol "$tmp/fix/tidy" -- mod tidy
[[ "$rc" == 18 ]] && jq -e '.private_registry_lines[0].extra | contains("name=superbiche.me version=unknown") and contains("command=go-mod")' "$tmp/result.json" >/dev/null \
  || fail "P12: a first tidy logs the namespace fallback line: rc=$rc"
mkdir -p "$tmp/fix/npmnew"; printf '{"name":"app","version":"1.0.0","dependencies":{"@p/x":"1.0.0"}}\n' > "$tmp/fix/npmnew/package.json"
rc=0; SAFE_AUDIT_RESULT_OUT="$tmp/result.json" "$AUDIT" private-npm-project --tool npm --class install --project-dir "$tmp/fix/npmnew" --gate install -- install > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" == 18 ]] && jq -e '.private_registry_lines[0].package == "@p/x@npm-install" and (.private_registry_lines[0].extra | contains("command=npm-install"))' "$tmp/result.json" >/dev/null \
  || fail "P12: an npm first install logs its private name: rc=$rc $(cat "$tmp/out")"
cat > "$tmp/fake-audit" <<'FA'
#!/usr/bin/env bash
[[ -z "${SAFE_AUDIT_RESULT_OUT:-}" ]] || printf '%s\n' "${FAKE_RESULT:-{\"gate_exit\":18}}" > "$SAFE_AUDIT_RESULT_OUT"
exit 18
FA
chmod +x "$tmp/fake-audit"
for result in '{"gate_exit":18}' '{"gate_exit":18,"private_registry_lines":[{"package":"x@1"}]}' 'not json'; do
  rc=0; FAKE_RESULT="$result" bash -c 'source "$ROOT/lib/gate-lib.sh"; SAFE_GATE_AUDIT_BIN="$tmp/fake-audit"; safe_gate_audit_available() { return 0; }; export SAFE_RUN_DATA_DIR="$tmp/fdata"; safe_gate_private_project go go "go build" -- build' > "$tmp/out" 2>&1 || rc=$?
  [[ "$rc" == 100 ]] || fail "P12: the project helper accepted an allow without a complete audit line ($result): rc=$rc"
done
pass "round-4 P12: Go bypasses log the selected context's requirements (go.work members, GOFLAGS -modfile) or the namespace fallback line; npm first installs log theirs; an allow without a complete line refuses"

# P13: requirement includes are walked (bounded, cycle-safe); what cannot be
# inventoried asks
mkdir -p "$tmp/fix/req/sub"
printf -- '-r sub/child.txt\nrequests==2.32.0\n' > "$tmp/fix/req/parent.txt"
printf 'caviar-redact==0.2.0\n' > "$tmp/fix/req/sub/child.txt"
pyproj() { rc=0; SAFE_AUDIT_RESULT_OUT="$tmp/result.json" "$AUDIT" private-python-project --gate install -- "$@" > "$tmp/out" 2>&1 || rc=$?; }
pyproj "$tmp/fix/req/parent.txt"
[[ "$rc" == 19 && "$(decision)" == private_route_unmodelled ]] || fail "P13: a private name behind an include: rc=$rc $(cat "$tmp/out")"
printf -- '--requirement=../b.txt\nrequests==2.32.0\n' > "$tmp/fix/req/sub/a.txt"
printf -- '-csub/a.txt\nidna==3.7\n' > "$tmp/fix/req/b.txt"
pyproj "$tmp/fix/req/sub/a.txt"
[[ "$rc" == 0 ]] || fail "P13: a public include cycle terminates clean: rc=$rc $(cat "$tmp/out")"
printf -- '-r missing.txt\n' > "$tmp/fix/req/broken.txt"
pyproj "$tmp/fix/req/broken.txt"
[[ "$rc" == 19 ]] && grep -q 'could not be fully inventoried' "$tmp/out" || fail "P13: a missing include asks: rc=$rc"
printf -- '-r https://u:%s@example.test/req.txt\n' "$TOK" > "$tmp/fix/req/remote.txt"
pyproj "$tmp/fix/req/remote.txt"
[[ "$rc" == 19 ]] || fail "P13: a remote include asks: rc=$rc"
leak "remote include"
for i in $(seq 0 70); do printf -- '-r f%s.txt\n' "$((i + 1))" > "$tmp/fix/req/f$i.txt"; done
printf 'idna==3.7\n' > "$tmp/fix/req/f71.txt"
pyproj "$tmp/fix/req/f0.txt"
[[ "$rc" == 19 ]] || fail "P13: an include chain past the bounds asks: rc=$rc"
for tool_cmd in "safe_gate_pip_like pip install -r parent.txt" "safe_gate_uv pip install -r parent.txt"; do
  rm -f "$tmp/delegated"
  rc=0; ROUTE_DIR="$tmp/fix/req" bash "$tmp/route.sh" $tool_cmd > "$tmp/out" 2>&1 || rc=$?
  [[ "$rc" == 102 && ! -e "$tmp/delegated" ]] || fail "P13: $tool_cmd delegated a nested private requirement: rc=$rc $(cat "$tmp/out")"
done
pass "round-4 P13: pip and uv requirement files are walked through their -r/-c includes (bounded, cycle-safe); a private name, an unreadable or remote include, or a set past the bounds asks"

# P14: the local blocklist still decides named private Go modules (and npm
# lockfile entries)
printf '{"packages":{"superbiche.me/caviar":{"reason":"operator-blocked"},"@p/x":{"reason":"operator-blocked"}}}\n' > "$blocklist"
audit superbiche.me/caviar@v0.2.0 go
[[ "$rc" == 20 && "$(decision)" == blocklist ]] || fail "P14: explicit audit of a blocked private module: rc=$rc"
gol "$tmp/fix/plain" -- mod download superbiche.me/caviar@v0.2.0
[[ "$rc" == 20 && "$(decision)" == blocklist ]] || fail "P14: a blocked private module named for download: rc=$rc $(cat "$tmp/out")"
gol "$tmp/fix/ws" FAKE_GOWORK="$tmp/fix/ws/go.work" FAKE_GOWORK_JSON="$tmp/fix/ws/work.json" -- run ./app
[[ "$rc" == 20 ]] || fail "P14: a blocked private requirement: rc=$rc"
manifest '{"name":"app","version":"1.0.0","dependencies":{"@p/x":"1.0.0"}}'
cp "$tmp/fix/lock.json" "$tmp/fix/npmproj/package-lock.json"
proj ci -- ci
[[ "$rc" == 20 && "$(decision)" == blocklist ]] || fail "P14 sibling: a blocked private npm lockfile entry: rc=$rc"
rc=0; "$AUDIT" private-npm-project --tool npm --class install --project-dir "$tmp/fix/npmnew" --gate install -- install > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" == 20 ]] || fail "P14 sibling: a blocked private npm name on a first install: rc=$rc"
rm -f "$blocklist"
pass "round-4 P14: the local blocklist decides named private Go modules (download targets, selected requirements) and npm private entries before delegation"

# --- review round 5 correctives --------------------------------------------------
reset_state
add_registry p-npm npm "$NPM_ORIGIN" '@p/*'
add_registry p-py python "$PY_ORIGIN" caviar-redact
add_registry p-go go "$GO_ORIGIN" superbiche.me

# P13: requirement syntax the inventory does not model is incomplete, not absent
mkdir -p "$tmp/fix/req5"
printf 'caviar-redact==0.2.0\n' > "$tmp/fix/req5/child.txt"
printf -- '--requirement\tchild.txt\n' > "$tmp/fix/req5/tab.txt"
pyproj "$tmp/fix/req5/tab.txt"
[[ "$rc" == 19 && "$(decision)" == private_route_unmodelled ]] || fail "P13: --requirement<TAB>file reaches the child: rc=$rc $(cat "$tmp/out")"
printf -- '-r   child.txt\n' > "$tmp/fix/req5/spaces.txt"
pyproj "$tmp/fix/req5/spaces.txt"
[[ "$rc" == 19 ]] || fail "P13: -r with several spaces: rc=$rc"
# a44: lines that name no readable package are skipped (baseline public
# handling), never an ask — a ${VAR} public name must not prompt.
for line in '${PUBLIC_PACKAGE}==2.32.0' 'https://example.test/x-0.1-py3-none-any.whl' '-e git+https://example.test/x.git#egg=x' '--some-future-option x' '@weird'; do
  printf '%s\n' "$line" > "$tmp/fix/req5/one.txt"
  rc=0; PUBLIC_PACKAGE=requests SAFE_AUDIT_RESULT_OUT="$tmp/result.json" "$AUDIT" private-python-project --gate install -- "$tmp/fix/req5/one.txt" > "$tmp/out" 2>&1 || rc=$?
  [[ "$rc" == 0 ]] || fail "a44: '$line' names no readable private package and must not ask: rc=$rc $(cat "$tmp/out")"
done
printf -- '-e .\n./dist/local-0.1-py3-none-any.whl\n--index-url https://pypi.org/simple\n--extra-index-url=https://pypi.org/simple\nrequests==2.32.0  # comment\nidna; python_version >= "3.8"\n' > "$tmp/fix/req5/ok.txt"
pyproj "$tmp/fix/req5/ok.txt"
[[ "$rc" == 0 ]] || fail "P13: local editable, local wheel, source options and public names stay clean: rc=$rc $(cat "$tmp/out")"
pass "round-5 P13 (a44): include whitespace is parsed and reaches private names; unreadable lines are skipped, not asked"

# P14: a remote replacement destination is a named private module
mkdir -p "$tmp/fix/repl"; printf 'module example.com/app\n' > "$tmp/fix/repl/go.mod"
jq -n '{Module: {Path: "example.com/app"}, Require: [{Path: "example.com/public", Version: "v0.1.0"}], Replace: [{Old: {Path: "example.com/public", Version: "v0.1.0"}, New: {Path: "superbiche.me/caviar", Version: "v0.2.0"}}, {Old: {Path: "example.com/other"}, New: {Path: "../local"}}]}' > "$tmp/fix/repl/go.mod.fakejson"
gol "$tmp/fix/repl" -- mod download
[[ "$rc" == 18 ]] && jq -e '[.private_registry_lines[].package] == ["superbiche.me/caviar@v0.2.0"]' "$tmp/result.json" >/dev/null || fail "P14: the replacement destination is logged: rc=$rc $(cat "$tmp/result.json" 2>/dev/null)"
printf '{"packages":{"superbiche.me/caviar":{"reason":"operator-blocked"}}}\n' > "$SAFE_RUN_CONFIG_DIR/blocked.json"
gol "$tmp/fix/repl" -- mod download
[[ "$rc" == 20 && "$(decision)" == blocklist ]] || fail "P14: a blocked private replacement destination: rc=$rc $(cat "$tmp/out")"
printf '{"Use":[{"DiskPath":"./app"}],"Replace":[{"Old":{"Path":"example.com/public"},"New":{"Path":"superbiche.me/caviar","Version":"v0.2.0"}}]}\n' > "$tmp/fix/ws/work-repl.json"
jq -n '{Module: {Path: "example.com/workapp"}, Require: []}' > "$tmp/fix/ws/app/go.mod.fakejson"
gol "$tmp/fix/ws" FAKE_GOWORK="$tmp/fix/ws/go.work" FAKE_GOWORK_JSON="$tmp/fix/ws/work-repl.json" -- build ./app
[[ "$rc" == 20 ]] || fail "P14: a blocked private replacement in go.work: rc=$rc"
rm -f "$SAFE_RUN_CONFIG_DIR/blocked.json"
pass "round-5 P14: remote replacement destinations (go.mod and go.work) are named private modules for the blocklist and the audit line; local replacements stay local"

# P15: a path that escapes the origin by dot segments is not under it
manifest '{"name":"app","version":"1.0.0","dependencies":{"@p/x":"1.0.0"}}'
for r in "$NPM_ORIGIN/../other/x.tgz" "$NPM_ORIGIN/%2e%2e/other/x.tgz" "$NPM_ORIGIN/%2E%2e/other/x.tgz" "$NPM_ORIGIN/sub/..%2f..%2fother/x.tgz"; do
  lock "$(jq -n --arg r "$r" '{lockfileVersion: 3, packages: {"": {}, "node_modules/@p/x": {version: "1.0.0", resolved: $r}}}')"
  proj ci -- ci
  [[ "$rc" == 20 && "$(decision)" == private_cross_registry ]] || fail "P15: lockfile resolved $r is not under the origin: rc=$rc"
done
audit @p/x@1.0.0 npm FAKE_NPM_SCOPE_REG="$NPM_ORIGIN/../other/"
[[ "$rc" == 20 ]] || fail "P15: a scope mapped through dot segments: rc=$rc"
audit caviar-redact@0.2.0 python -- --python-isolated --registry "$PY_ORIGIN/../other/simple"
[[ "$rc" == 20 ]] || fail "P15: a Python argv index escaping the origin: rc=$rc"
audit superbiche.me/caviar@v0.2.0 go FAKE_GOPROXY="$GO_ORIGIN/../other"
[[ "$rc" == 20 ]] || fail "P15: a GOPROXY entry escaping the origin: rc=$rc"
pass "round-5 P15: observed sources with dot segments (literal or percent-encoded) never compare as under the origin (npm lockfile and scope, Python index, Go proxy)"

# --- gate termini ---------------------------------------------------------------
cat > "$tmp/scenario.sh" <<'SCENARIO'
#!/usr/bin/env bash
set -uo pipefail
export SAFE_RUN_DATA_DIR="$tmp/gdata" TMPDIR="$tmp/tmpdir"
mkdir -p "$SAFE_RUN_DATA_DIR" "$TMPDIR"
source "$ROOT/lib/gate-lib.sh"
safe_gate_audit_available() { return 0; }
safe_gate_audit_op() { printf 'install'; }
safe_gate_operator_terminal() { [[ "$TEST_TERMINAL" == 1 ]]; }
safe_gate_run_audit() {
  [[ -z "${SAFE_AUDIT_RESULT_OUT:-}" || -z "${TEST_RESULT:-}" ]] || printf '%s\n' "$TEST_RESULT" > "$SAFE_AUDIT_RESULT_OUT"
  return "$TEST_AUDIT_RC"
}
rc=0
safe_gate_check "@p/x@1.0.0" npm || rc=$?
printf '%s' "$rc" > "$tmp/grc"
SCENARIO
chmod +x "$tmp/scenario.sh"
gate_case() { # audit-rc terminal result answer
  rm -f "$tmp/grc" "$tmp/gdata/audit.log"
  printf '%s\n' "$4" | TEST_AUDIT_RC="$1" TEST_TERMINAL="$2" TEST_RESULT="$3" \
    python3 -c 'import pty,sys,os; sys.exit(os.waitstatus_to_exitcode(pty.spawn(sys.argv[1:])))' \
    bash "$tmp/scenario.sh" > "$tmp/gout" 2>&1
  cat "$tmp/grc" 2>/dev/null || printf none
}
last_line() { tail -n 1 "$tmp/gdata/audit.log" 2>/dev/null; }
ALLOW='{"package":"@p/x","resolved_versions":["1.0.0"],"private_registry":{"decision":"ALLOWED_VIA_PRIVATE_REGISTRY","audit_extra":"registry=p-npm origin=https://o name=@p/x version=1.0.0"},"gate_exit":18}'
ASK='{"package":"@p/x","resolved_versions":["1.0.0"],"private_registry":{"decision":"private_route_unmodelled","detail":"this install route reads package sources safe does not control","hint":"install it with npm"},"gate_exit":19}'
BLOCK='{"package":"@p/x","resolved_versions":["1.0.0"],"block":{"class":"private","detail":"npm would fetch it elsewhere"},"private_registry":{"decision":"private_cross_registry"},"gate_exit":20}'
r="$(gate_case 18 0 "$ALLOW" '')"
[[ "$r" == 0 ]] && last_line | grep -q '| ALLOWED_VIA_PRIVATE_REGISTRY | registry=p-npm origin=https://o name=@p/x version=1.0.0' \
  || fail "18 unattended: rc=$r $(last_line)"
r="$(gate_case 18 0 '{"package":"@p/x","resolved_versions":["1.0.0"],"gate_exit":18}' '')"
[[ "$r" == 100 ]] || fail "18 without evidence: rc=$r"
pass "gate 18 installs unattended with the audit line (registry, origin, name, version); an allow without it refuses"
r="$(gate_case 19 0 "$ASK" '')"
[[ "$r" == 102 ]] && last_line | grep -q 'REFUSED_PRIVATE_NONTTY' && grep -q 'reads package sources safe does not control' "$tmp/gout" || fail "19 non-tty: rc=$r"
grep -q 'host-allow' "$tmp/gout" && fail "19 refusal suggests host-allow"
r="$(gate_case 19 1 "$ASK" 'y')"
[[ "$r" == 0 ]] && last_line | grep -q 'PRIVATE_TTY_OVERRIDE' || fail "19 tty y: rc=$r"
r="$(gate_case 19 1 "$ASK" 'n')"
[[ "$r" == 100 ]] || fail "19 tty n: rc=$r"
pass "gate 19: 102 unattended (no host-allow hint), a deliberate confirm at an operator terminal"
r="$(gate_case 20 0 "$BLOCK" '')"
[[ "$r" == 104 ]] || fail "20 private non-tty: rc=$r"
r="$(gate_case 20 1 "$BLOCK" '@p/x@1.0.0')"
[[ "$r" == 0 ]] && last_line | grep -q 'BLOCK_TTY_OVERRIDE' || fail "20 private typed: rc=$r"
r="$(gate_case 20 1 "$BLOCK" 'record @p/x@1.0.0')"
[[ "$r" == 100 ]] || fail "a private BLOCK was recordable: rc=$r"
pass "gate 20 class private: 104 unattended, typed install-once at a terminal, never recordable"

# --- operator commands ----------------------------------------------------------
reset_state
pty_run() { python3 -c 'import pty,sys,os; sys.exit(os.waitstatus_to_exitcode(pty.spawn(sys.argv[1:])))' "$@"; }
rc=0; "$RUN" private-registry add p-npm --ecosystem npm --origin "$NPM_ORIGIN" --namespace '@p/*' > "$tmp/out" 2>&1 </dev/null || rc=$?
[[ "$rc" == 102 && ! -e "$policy" ]] || fail "add without a terminal: rc=$rc"
pty_run "$RUN" private-registry add p-npm --ecosystem npm --origin "$NPM_ORIGIN/" --namespace '@p/*' > "$tmp/out" 2>&1 || fail "add: $(cat "$tmp/out")"
jq -e --arg o "$NPM_ORIGIN" '.registries["p-npm"].origin == $o and (.registries["p-npm"] | has("pin_mode") | not)' "$policy" >/dev/null || fail "add wrote no canonical origin"
grep -q 'PRIVATE_REGISTRY_ADDED' "$SAFE_RUN_DATA_DIR/audit.log" || fail "add not logged"
rc=0; pty_run "$RUN" private-registry add bad --ecosystem npm --origin "$EVIL/npm" --namespace '@p/x' > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" != 0 ]] && grep -q 'overlapping' "$tmp/out" || fail "overlapping registry accepted: $(cat "$tmp/out")"
pty_run "$RUN" private-registry add bad --ecosystem npm --origin "$EVIL/npm" --namespace '@q/*' > "$tmp/out" 2>&1 || fail "add without a reason refused (grants carry none): $(cat "$tmp/out")"
jq -e '.registries["bad"] | has("reason") | not' "$policy" >/dev/null || fail "registry entry stored a reason"
pty_run "$RUN" private-registry remove bad > "$tmp/out" 2>&1 || fail "remove cleanup: $(cat "$tmp/out")"
rc=0; pty_run "$RUN" private-registry add bad --ecosystem npm --origin "$EVIL/npm" --namespace '@q/*' --reason x > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" != 0 ]] || fail "the removed --reason option was accepted"
rc=0; pty_run "$RUN" private-registry add bad --ecosystem npm --origin "$EVIL/npm" --namespace '@q/*' --pin-mode operator > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" != 0 ]] || fail "the removed --pin-mode option was accepted"
"$RUN" private-registry list > "$tmp/out" 2>&1 || fail "list: $(cat "$tmp/out")"
grep -q "p-npm" "$tmp/out" && ! grep -q 'pin' "$tmp/out" || fail "list: $(cat "$tmp/out")"
rc=0; "$RUN" private-registry pin add @p/x@1.0.0 --ecosystem npm > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" != 0 ]] && grep -q 'unknown private-registry subcommand' "$tmp/out" || fail "the removed pin command still exists: rc=$rc"
no_secret "operator commands"
pass "private-registry add: operator terminal only, canonical origin, overlap refused, logged; list is read-only; there are no pin commands"

rm -f "$tmp/npm.argv"
rc=0; SAFE_AUDIT_BIN="$AUDIT" pty_run "$RUN" host-allow add @p/x@2.0.0 > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" != 0 ]] && grep -q 'trusted already' "$tmp/out" && ! jq -e '.packages["@p/x"]' "$SAFE_RUN_CONFIG_DIR/host-allow.json" >/dev/null 2>&1 \
  || fail "host-allow add of a private name: rc=$rc $(cat "$tmp/out")"
pass "host-allow add of a private name is refused (its origin is trusted already) and never takes public integrity"

pty_run "$RUN" private-registry remove p-npm > "$tmp/out" 2>&1 || fail "remove"
[[ "$("$CORE" private-trust match --policy "$policy" --ecosystem npm --name @p/x | jq -r .lane)" == none ]] || fail "removed registry still private"
pass "removing the registry withdraws the private lane"

printf 'all private-registry tests passed\n'
