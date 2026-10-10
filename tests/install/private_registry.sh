#!/usr/bin/env bash
# Private-registry trust: the install-gate lane, its gate termini and the
# operator commands. Registries, clients and network are fixtures: fake npm,
# go and curl binaries on PATH stand in for the ecosystem clients the lane
# runs, so no request leaves the machine and no credential exists.

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
SRI_A="sha512-$(printf 'A%.0s' {1..86})=="
SRI_B="sha512-$(printf 'B%.0s' {1..86})=="
H1_A="h1:$(printf 'a%.0s' {1..43})="
H1_B="h1:$(printf 'b%.0s' {1..43})="
SHA_A="$(printf 'a%.0s' {1..64})"
SHA_B="$(printf 'b%.0s' {1..64})"
SECRET="fixture-secret-token-must-never-appear"
export NPM_ORIGIN GO_ORIGIN PY_ORIGIN SRI_A SRI_B H1_A H1_B SHA_A SHA_B SECRET

# --- fake clients ----------------------------------------------------------
cat > "$tmp/bin/npm" <<'NPM'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$tmp/npm.argv"
case "${FAKE_NPM_MODE:-ok}" in
  e401) printf 'npm error code E401\nnpm error Unable to authenticate, token %s\n' "$SECRET" >&2; exit 1 ;;
  e404) printf 'npm error code E404\n' >&2; exit 1 ;;
esac
if [[ " $* " == *" --package-lock-only "* ]]; then
  # Projection: the lockfile npm would write for this operation.
  [[ -n "${FAKE_PROJECTION_LOCK:-}" ]] || exit 1
  cp "$FAKE_PROJECTION_LOCK" package-lock.json
  exit 0
fi
spec="$2"; version="${spec##*@}"
# npm >= 12 answers a multi-field `view --json` with a one-element array.
body=$(cat <<JSON
{"version":"$version","dist":{"tarball":"${FAKE_TARBALL_BASE:-$NPM_ORIGIN}/@p%2fx/-/$version/x-$version.tgz","integrity":"${FAKE_SRI:-$SRI_A}"},"time":{"$version":"${FAKE_PUBLISHED:-2026-01-01T00:00:00Z}"}}
JSON
)
case "${FAKE_NPM_SHAPE:-array}" in
  array) printf '[%s]\n' "$body" ;;
  object) printf '%s\n' "$body" ;;
  multi) printf '[%s,%s]\n' "$body" "$body" ;;
esac
NPM
cat > "$tmp/bin/go" <<'GO'
#!/usr/bin/env bash
printf '%s GOPROXY=%s\n' "$*" "${GOPROXY:-}" >> "$tmp/go.argv"
if [[ "$1 $2" == "env GOWORK" ]]; then
  printf '%s\n' "${FAKE_GOWORK:-}"
  exit 0
fi
if [[ "$1 $2 $3" == "mod edit -json" ]]; then
  cat "${FAKE_GO_MODJSON:?}"
  exit 0
fi
if [[ "$1" == env ]]; then
  jq -cn --arg p "${GOPROXY-}" --arg n "${GONOPROXY-}" --arg v "${GOPRIVATE-}" '{GOPROXY: $p, GONOPROXY: $n, GOPRIVATE: $v}'
  exit 0
fi
if [[ "$1 $2" == "mod download" ]]; then
  mv="${!#}"
  if [[ "${FAKE_GO_MODE:-ok}" == e401 ]]; then
    jq -cn --arg e "reading $GOPROXY: 401 Unauthorized" '{Error: $e}'; exit 1
  fi
  mkdir -p "$GOMODCACHE"; printf '{"Version":"%s","Time":"2026-01-01T00:00:00Z"}' "${mv##*@}" > "$GOMODCACHE/info.json"
  jq -cn --arg p "${mv%@*}" --arg v "${mv##*@}" --arg s "${FAKE_GO_H1:-$H1_A}" --arg m "${FAKE_GO_MOD:-$H1_B}" --arg i "$GOMODCACHE/info.json" \
    '{Path: $p, Version: $v, Sum: $s, GoModSum: $m, Info: $i}'
  exit 0
fi
exit 0
GO
cat > "$tmp/bin/curl" <<'CURL'
#!/usr/bin/env bash
out="" hdr="" w="" url="${!#}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -D) hdr="$2"; shift 2 ;;
    -w) w="$2"; shift 2 ;;
    -H|--max-time) shift 2 ;;
    *) shift ;;
  esac
done
printf '%s\n' "$url" >> "$tmp/curl.urls"
code=404 body="" ctype="text/html"
case "$(sed -E 's#://[^@/]+@#://#' <<<"$url")" in
  "$PY_ORIGIN"/simple/caviar-redact/)
    code="${FAKE_PY_CODE:-200}"; ctype="application/vnd.pypi.simple.v1+json"
    body=$(jq -cn --arg o "${FAKE_PY_FILE_BASE:-$PY_ORIGIN}" --arg a "${FAKE_PY_SHA:-$SHA_A}" --arg b "$SHA_B" \
      '{files: [{filename: "caviar_redact-0.2.0-py3-none-any.whl", url: ($o + "/files/caviar-redact/0.2.0/caviar_redact-0.2.0-py3-none-any.whl"), hashes: {sha256: $a}, "upload-time": "2026-01-01T00:00:00Z"},
                {filename: "caviar_redact-0.2.0.tar.gz", url: ($o + "/files/caviar-redact/0.2.0/caviar_redact-0.2.0.tar.gz"), hashes: {sha256: $b}},
                {filename: "caviar_redact-0.1.0.tar.gz", url: ($o + "/files/x"), hashes: {sha256: $b}}]}') ;;
  https://pypi.org/simple/caviar-redact/) code="${FAKE_PYPI_CODE:-404}" ;;
esac
[[ -z "$out" ]] || printf '%s' "$body" > "$out"
[[ -z "$hdr" ]] || printf 'HTTP/1.1 %s\r\ncontent-type: %s\r\n\r\n' "$code" "$ctype" > "$hdr"
[[ -z "$w" ]] || printf '%s' "$code"
exit 0
CURL
chmod +x "$tmp/bin/npm" "$tmp/bin/go" "$tmp/bin/curl"
printf '@p:registry=%s/\n//git.example.test:8443/api/packages/owner/npm/:_authToken=%s\n' "$NPM_ORIGIN" "$SECRET" > "$HOME/.npmrc"

policy="$SAFE_RUN_CONFIG_DIR/private-registries.json"
pins="$SAFE_RUN_CONFIG_DIR/private-pins.json"
add_registry() { # id eco origin namespace [pin_mode]
  "$CORE" private-trust registry-add --policy "$policy" --id "$1" --ecosystem "$2" --origin "$3" \
    --namespace "$4" --pin-mode "${5:-tofu}" --reason test >/dev/null || fail "registry-add $1"
}
reset_state() { rm -f "$policy" "$pins" "$tmp/npm.argv" "$tmp/go.argv" "$tmp/curl.urls" "$SAFE_AUDIT_AUDIT_LOG"; }
# audit <spec> <eco> [extra env...]: gate-mode package audit; sets rc and result
audit() {
  local spec="$1" eco="$2"
  shift 2
  rm -f "$tmp/result.json"
  rc=0
  env "$@" SAFE_AUDIT_RESULT_OUT="$tmp/result.json" "$AUDIT" package-audit "$spec" --ecosystem "$eco" --gate install \
    > "$tmp/out" 2>&1 || rc=$?
}
no_secret() {
  ! grep -rqs "$SECRET" "$tmp/out" "$tmp/result.json" "$SAFE_AUDIT_AUDIT_LOG" "$pins" "$policy" "$tmp/data" \
    || fail "the registry credential leaked: $1"
}

# --- not configured: nothing changes -----------------------------------------
reset_state
rc=0; "$AUDIT" private-fetch @p/x@1.0.0 --ecosystem npm > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" == 3 ]] || fail "private-fetch without a policy: rc=$rc $(cat "$tmp/out")"
pass "no private-registry policy: the public path is untouched (private-fetch reports not-private)"

# --- npm ----------------------------------------------------------------------
add_registry p-npm npm "$NPM_ORIGIN/" '@p/*'
audit @p/x@1.0.0 npm
[[ "$rc" == 18 ]] || fail "npm first install: rc=$rc $(cat "$tmp/out")"
jq -e --arg o "$NPM_ORIGIN" --arg s "$SRI_A" '.gate_exit == 18 and .private_registry.pin == "tofu-new"
  and (.private_registry.audit_extra | contains("origin=" + $o) and contains("integrity=" + $s) and contains("artifact=" + $o + "/@p%2fx/-/1.0.0/x-1.0.0.tgz"))' \
  "$tmp/result.json" >/dev/null || fail "npm allow evidence: $(cat "$tmp/result.json")"
jq -e --arg s "$SRI_A" '.pins | to_entries | length == 1 and .[0].value.integrity.sri == $s and .[0].value.pinned_by == "tofu"' "$pins" >/dev/null \
  || fail "TOFU pin not recorded"
grep -q -- "--@p:registry=$NPM_ORIGIN/" "$tmp/npm.argv" || fail "npm view was not bound to the private origin: $(cat "$tmp/npm.argv")"
jq -se 'map(select(.event == "private_registry")) | length == 1' "$SAFE_AUDIT_AUDIT_LOG" >/dev/null || fail "no verdict-log event"
no_secret "npm allow"
pass "npm: an exact private pin installs unattended (18), records the TOFU pin and names artifact and integrity"

audit @p/x@1.0.0 npm
[[ "$rc" == 18 && "$(jq -r '.private_registry.pin' "$tmp/result.json")" == "matched:tofu" ]] || fail "npm second install: rc=$rc"
audit @p/x@1.0.0 npm FAKE_SRI="$SRI_B"
[[ "$rc" == 20 && "$(jq -r '.block.class + ":" + .private_registry.decision' "$tmp/result.json")" == "private:private_artifact_changed" ]] \
  || fail "changed bytes: rc=$rc $(cat "$tmp/result.json")"
pass "npm: a matching reinstall passes; changed bytes for the pinned version BLOCK (20, class private)"

audit '@p/x@^1.0.0' npm
[[ "$rc" == 19 && "$(jq -r '.private_registry.decision' "$tmp/result.json")" == private_version_not_exact ]] || fail "range: rc=$rc"
audit @p/x@latest npm
[[ "$rc" == 19 ]] || fail "latest: rc=$rc"
pass "npm: ranges and tags never reach the private lane's allow (19)"

rm -f "$tmp/npm.argv"
audit @p/x@2.0.0 npm FAKE_NPM_MODE=e401
[[ "$rc" == 19 && "$(jq -r '.private_registry.decision' "$tmp/result.json")" == private_registry_auth_missing ]] || fail "auth: rc=$rc $(cat "$tmp/out")"
grep -q 'not a package finding' "$tmp/out" || fail "auth failure reads as a finding"
no_secret "npm auth failure"
audit @p/x@2.0.0 npm FAKE_NPM_MODE=e404
[[ "$rc" == 19 && "$(jq -r '.private_registry.decision' "$tmp/result.json")" == private_version_missing ]] || fail "404: rc=$rc"
pass "npm: missing credentials and missing versions stay visible (19) and never print the credential"

audit @p/x@3.0.0 npm FAKE_TARBALL_BASE=https://evil.example.test/npm
[[ "$rc" == 20 && "$(jq -r '.private_registry.decision' "$tmp/result.json")" == private_cross_registry ]] || fail "tarball elsewhere: rc=$rc"
printf '@p:registry=https://registry.npmjs.org/\n' > "$tmp/fix/project.npmrc"
mkdir -p "$tmp/fix/proj"; cp "$tmp/fix/project.npmrc" "$tmp/fix/proj/.npmrc"
rc=0; ( cd "$tmp/fix/proj" && SAFE_AUDIT_RESULT_OUT="$tmp/result.json" "$AUDIT" package-audit @p/x@1.0.0 --ecosystem npm --gate install ) > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" == 20 ]] && grep -q 'registry.npmjs.org' "$tmp/out" || fail "scope remapped to npmjs: rc=$rc $(cat "$tmp/out")"
pass "npm: a tarball or scope mapping outside the private origin is cross-registry substitution (20)"

# lock-diff lane: the projected lockfile is the observed artifact
cat > "$tmp/fix/lock.json" <<JSON
{"lockfileVersion":3,"packages":{"":{},"node_modules/@p/x":{"version":"1.0.0","resolved":"$NPM_ORIGIN/@p%2fx/-/1.0.0/x-1.0.0.tgz","integrity":"$SRI_A"},
 "node_modules/alias":{"name":"@p/x","version":"1.0.0","resolved":"$NPM_ORIGIN/@p%2fx/-/1.0.0/x-1.0.0.tgz","integrity":"$SRI_A"}}}
JSON
rm -f "$tmp/npm.argv"
audit @p/x@1.0.0 npm SAFE_AUDIT_ARTIFACT_LOCKFILE="$tmp/fix/lock.json"
[[ "$rc" == 18 && ! -e "$tmp/npm.argv" ]] || fail "lockfile matched pin: rc=$rc npm called: $(cat "$tmp/npm.argv" 2>/dev/null)"
jq '.packages["node_modules/alias"].resolved = "https://registry.npmjs.org/@p/x/-/x-1.0.0.tgz"' "$tmp/fix/lock.json" > "$tmp/fix/lock-evil.json"
audit @p/x@1.0.0 npm SAFE_AUDIT_ARTIFACT_LOCKFILE="$tmp/fix/lock-evil.json"
[[ "$rc" == 20 ]] || fail "lockfile occurrence outside origin: rc=$rc"
jq --arg s "$SRI_B" '.packages["node_modules/@p/x"].integrity = $s | .packages["node_modules/alias"].integrity = $s' "$tmp/fix/lock.json" > "$tmp/fix/lock-changed.json"
audit @p/x@1.0.0 npm SAFE_AUDIT_ARTIFACT_LOCKFILE="$tmp/fix/lock-changed.json"
[[ "$rc" == 20 ]] || fail "lockfile integrity differs from the origin: rc=$rc"
pass "npm lock-diff: a pinned lockfile artifact passes without a fetch; any occurrence elsewhere or with other bytes BLOCKs"

# round-1 P3: an SRI with two different sha512 digests admits either artifact
jq --arg s "$SRI_A $SRI_B" '.packages["node_modules/@p/x"].integrity = $s | .packages["node_modules/alias"].integrity = $s' "$tmp/fix/lock.json" > "$tmp/fix/lock-two.json"
audit @p/x@1.0.0 npm SAFE_AUDIT_ARTIFACT_LOCKFILE="$tmp/fix/lock-two.json"
[[ "$rc" == 20 && "$(jq -r '.private_registry.decision' "$tmp/result.json")" == private_integrity_ambiguous ]] || fail "two sha512 digests: rc=$rc $(cat "$tmp/out")"
audit @p/x@4.0.0 npm FAKE_SRI="$SRI_A $SRI_B"
[[ "$rc" == 20 ]] || fail "registry metadata with two sha512 digests: rc=$rc"
jq 'del(.packages["node_modules/@p/x"].integrity, .packages["node_modules/alias"].integrity)' "$tmp/fix/lock.json" > "$tmp/fix/lock-noint.json"
audit @p/x@1.0.0 npm SAFE_AUDIT_ARTIFACT_LOCKFILE="$tmp/fix/lock-noint.json"
[[ "$rc" == 19 ]] || fail "lockfile entry without integrity: rc=$rc"
pass "npm: two sha512 digests BLOCK (lockfile or registry); a lockfile entry without integrity asks"

# round-1 P6: npm's real view shapes
audit @p/x@5.0.0 npm FAKE_NPM_SHAPE=object
[[ "$rc" == 18 ]] || fail "object-shaped npm view: rc=$rc"
audit @p/x@5.0.1 npm FAKE_NPM_SHAPE=array
[[ "$rc" == 18 ]] || fail "array-shaped npm view (npm >= 12): rc=$rc"
audit @p/x@5.0.2 npm FAKE_NPM_SHAPE=multi
[[ "$rc" == 19 && "$(jq -r '.private_registry.decision' "$tmp/result.json")" == private_version_missing ]] || fail "ambiguous npm view answer: rc=$rc"
rm -f "$tmp/npm.argv"
printf '@p:registry=%s/\n' "$NPM_ORIGIN" > "$tmp/fix/alt.npmrc"
rc=0; "$AUDIT" package-audit @p/x@5.0.3 --ecosystem npm --gate install --npm-userconfig "$tmp/fix/alt.npmrc" > "$tmp/out" 2>&1 || rc=$?
grep -q -- "--userconfig=$tmp/fix/alt.npmrc" "$tmp/npm.argv" || fail "the selected npm userconfig did not reach the private fetch: rc=$rc $(cat "$tmp/out")"
pass "npm: the private fetch reads npm's object and one-element-array answers, refuses several versions, and keeps the selected npm config"

# round-1 P1: every private identity an npm project operation materializes
mkdir -p "$tmp/fix/npmproj"
printf '{"name":"app","version":"1.0.0","dependencies":{"@p/x":"1.0.0","left-pad":"1.3.0"}}\n' > "$tmp/fix/npmproj/package.json"
cp "$tmp/fix/lock.json" "$tmp/fix/npmproj/package-lock.json"
proj() { # class [env...] -- argv
  local class="$1"; shift
  local -a envs=()
  while [[ $# -gt 0 && "$1" != "--" ]]; do envs+=("$1"); shift; done
  shift
  rc=0
  env "${envs[@]}" SAFE_AUDIT_RESULT_OUT="$tmp/result.json" "$AUDIT" private-npm-project --tool "${PROJ_TOOL:-npm}" --class "$class" \
    --project-dir "$tmp/fix/npmproj" --gate install -- "$@" > "$tmp/out" 2>&1 || rc=$?
}
rm -f "$pins"
proj ci -- ci
[[ "$rc" == 18 ]] && jq -e '.private_registry_lines | length == 1 and .[0].package == "@p/x@1.0.0"' "$tmp/result.json" >/dev/null || fail "npm ci private sweep: rc=$rc $(cat "$tmp/out")"
"$CORE" private-trust record --pins "$pins" --ecosystem npm --origin "$NPM_ORIGIN" --name @p/x --version 1.0.0 --mode revoke >/dev/null
proj ci -- ci
[[ "$rc" == 20 ]] && jq -e '.private_registry.decision == "private_pin_revoked"' "$tmp/result.json" >/dev/null || fail "npm ci of a revoked lockfile entry: rc=$rc"
rm -f "$pins"
jq --arg s "$SRI_B" '.packages["node_modules/@p/x"].integrity = $s | .packages["node_modules/alias"].integrity = $s' "$tmp/fix/lock.json" > "$tmp/fix/projected-changed.json"
proj install FAKE_PROJECTION_LOCK="$tmp/fix/projected-changed.json" -- install
[[ "$rc" == 20 ]] || fail "npm install whose projection resolves other bytes than the origin: rc=$rc $(cat "$tmp/out")"
proj install FAKE_PROJECTION_LOCK="$tmp/fix/lock.json" -- install
[[ "$rc" == 18 ]] || fail "npm install projection sweep: rc=$rc $(cat "$tmp/out")"
proj install -- install --prefix /elsewhere
[[ "$rc" == 19 ]] || fail "--prefix redirects the projection: rc=$rc"
PROJ_TOOL=pnpm proj install -- install
[[ "$rc" == 19 && "$(jq -r '.private_registry.decision' "$tmp/result.json")" == private_project_unmodelled ]] || fail "pnpm project with a private name: rc=$rc"
printf '{"name":"pub","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}\n' > "$tmp/fix/npmproj/package.json"
jq 'del(.packages["node_modules/@p/x"], .packages["node_modules/alias"])' "$tmp/fix/lock.json" > "$tmp/fix/npmproj/package-lock.json"
PROJ_TOOL=pnpm proj install -- install
[[ "$rc" == 0 ]] || fail "a project naming nothing private is untouched: rc=$rc"
printf '{"name":"app","version":"1.0.0","dependencies":{"@p/x":"1.0.0"}}\n' > "$tmp/fix/npmproj/package.json"
cp "$tmp/fix/lock.json" "$tmp/fix/npmproj/package-lock.json"
pass "npm project lane: ci sweeps the lockfile, install sweeps its projection, unmodelled managers/flags ask, projects without private names are untouched"

# the shipped npm route reaches the project lane before delegation
cat > "$tmp/route.sh" <<'ROUTE'
#!/usr/bin/env bash
set -uo pipefail
export SAFE_RUN_DATA_DIR="$tmp/rdata" TMPDIR="$tmp/tmpdir"
mkdir -p "$SAFE_RUN_DATA_DIR" "$TMPDIR"
source "$ROOT/lib/gate-lib.sh"
SAFE_GATE_AUDIT_BIN="$ROOT/bin/safe-audit"
safe_gate_audit_available() { return 0; }
safe_gate_operator_terminal() { return 1; }
safe_gate_scan_project() { return 0; }
safe_gate_exec_real() { printf 'DELEGATED %s\n' "$*" > "$tmp/delegated"; exit 0; }
cd "$tmp/fix/npmproj"
safe_gate_npm_like npm "$@"
ROUTE
chmod +x "$tmp/route.sh"
"$CORE" private-trust record --pins "$pins" --ecosystem npm --origin "$NPM_ORIGIN" --name @p/x --version 1.0.0 --mode revoke >/dev/null
rm -f "$tmp/delegated"
rc=0; bash "$tmp/route.sh" ci > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" == 104 && ! -e "$tmp/delegated" ]] || fail "npm ci route delegated a revoked private identity: rc=$rc $(cat "$tmp/out")"
grep -q 'REFUSED_BLOCK' "$tmp/rdata/audit.log" || fail "the route refusal was not logged"
rm -f "$pins" "$tmp/delegated"
rc=0; bash "$tmp/route.sh" ci > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" == 0 && -e "$tmp/delegated" ]] && grep -q 'ALLOWED_VIA_PRIVATE_REGISTRY' "$tmp/rdata/audit.log" || fail "npm ci route with a valid private entry: rc=$rc $(cat "$tmp/out")"
pass "the shipped npm ci route decides private lockfile entries before delegating (104 revoked, 0 + audit line otherwise)"

# revocation and operator pin mode
"$CORE" private-trust record --pins "$pins" --ecosystem npm --origin "$NPM_ORIGIN" --name @p/x --version 1.0.0 --mode revoke >/dev/null || fail "revoke"
audit @p/x@1.0.0 npm
[[ "$rc" == 20 && "$(jq -r '.private_registry.decision' "$tmp/result.json")" == private_pin_revoked ]] || fail "revoked: rc=$rc"
reset_state
add_registry p-npm npm "$NPM_ORIGIN" '@p/*' operator
audit @p/x@1.0.0 npm
[[ "$rc" == 19 && "$(jq -r '.private_registry.decision' "$tmp/result.json")" == private_pin_missing ]] || fail "operator mode: rc=$rc"
grep -q 'safe run private-registry pin add @p/x@1.0.0 --ecosystem npm' "$tmp/out" || fail "operator mode hint"
pass "npm: a revoked version BLOCKs; a registry in operator pin mode asks for the operator pin (19)"

# direct (non-gate) check never reads as GO
reset_state
add_registry p-npm npm "$NPM_ORIGIN" '@p/*'
rc=0; "$AUDIT" package-audit @p/x@1.0.0 --ecosystem npm > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" == 0 ]] && grep -q 'VERDICT: PRIVATE' "$tmp/out" || fail "direct check: rc=$rc $(cat "$tmp/out")"
rc=0; "$AUDIT" package-audit @p/x@1.0.0 --ecosystem npm --json > "$tmp/out" 2>/dev/null || rc=$?
jq -e '.verdict == "PRIVATE"' "$tmp/out" >/dev/null || fail "direct json verdict"
pass "a direct package-audit reports PRIVATE, never GO"

# --- trust root and store integrity ------------------------------------------
rc=0; SAFE_RUN_CONFIG_DIR="$tmp/elsewhere" "$AUDIT" private-fetch @p/x@1.0.0 --ecosystem npm > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" == 3 ]] || fail "redirected root honored the private policy: rc=$rc"
printf '{"schema":"safe-private-registries/1","registries":{"x":{"ecosystem":"npm","origin":"http://evil.example.test/","namespace":["@p/*"],"pin_mode":"tofu","cooldown_days":0}}}\n' > "$policy"
audit @p/x@1.0.0 npm
[[ "$rc" == 30 ]] && grep -q 'malformed' "$tmp/out" || fail "malformed policy: rc=$rc $(cat "$tmp/out")"
pass "an unblessed redirected trust root declines the policy; a malformed store decides nothing (30)"

# --- python -------------------------------------------------------------------
reset_state
add_registry p-py python "$PY_ORIGIN" caviar-redact
audit caviar-redact@0.2.0 python PIP_INDEX_URL="$PY_ORIGIN/simple"
[[ "$rc" == 18 ]] || fail "python: rc=$rc $(cat "$tmp/out")"
jq -e --arg a "$SHA_A" --arg b "$SHA_B" '.pins | to_entries[0].value.integrity.files
  == {"caviar_redact-0.2.0-py3-none-any.whl": $a, "caviar_redact-0.2.0.tar.gz": $b}' "$pins" >/dev/null || fail "python pin file set: $(cat "$pins")"
grep -qx 'https://pypi.org/simple/caviar-redact/' "$tmp/curl.urls" || fail "public namesake probe missing"
pass "python: an exact pin from the private index installs (18) and pins every distribution file of the version"
audit caviar-redact@0.2.0 python PIP_INDEX_URL="$PY_ORIGIN/simple" FAKE_PY_SHA="$SHA_B"
[[ "$rc" == 20 ]] || fail "python changed: rc=$rc"
audit caviar-redact@0.2.0 python PIP_INDEX_URL="$PY_ORIGIN/simple" FAKE_PYPI_CODE=200
[[ "$rc" == 20 ]] && grep -q 'dependency confusion' "$tmp/out" || fail "python namesake on PyPI: rc=$rc"
audit caviar-redact@0.2.0 python FAKE_PYPI_CODE=404
[[ "$rc" == 20 && "$(jq -r '.private_registry.decision' "$tmp/result.json")" == private_cross_registry ]] || fail "python without the private index: rc=$rc"
audit caviar-redact@0.2.0 python PIP_INDEX_URL="$PY_ORIGIN/simple" FAKE_PYPI_CODE=503
[[ "$rc" == 19 ]] || fail "python probe outage: rc=$rc"
audit caviar-redact@0.2.0 python PIP_INDEX_URL="$PY_ORIGIN/simple" FAKE_PY_FILE_BASE=https://cdn.example.test
[[ "$rc" == 20 ]] || fail "python file outside origin: rc=$rc"
pass "python: changed files, a public namesake, a missing private index and files hosted elsewhere BLOCK; a probe outage asks (19)"
rc=0; PIP_INDEX_URL="$PY_ORIGIN/simple" SAFE_AUDIT_RESULT_OUT="$tmp/result.json" "$AUDIT" package-audit caviar-redact@0.2.0 --ecosystem python --gate install --find-links-selected > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" == 20 ]] && grep -q 'find-links' "$tmp/out" || fail "argv find-links: rc=$rc"
audit caviar-redact@0.2.0 python PIP_INDEX_URL="$PY_ORIGIN/simple" PIP_FIND_LINKS=https://flat.example.test/
[[ "$rc" == 20 ]] || fail "PIP_FIND_LINKS: rc=$rc"
mkdir -p "$HOME/.config/pip"; printf '[global]\nfind-links = https://flat.example.test/\n' > "$HOME/.config/pip/pip.conf"
audit caviar-redact@0.2.0 python PIP_INDEX_URL="$PY_ORIGIN/simple"
[[ "$rc" == 20 ]] || fail "pip config find-links: rc=$rc"
rm -f "$HOME/.config/pip/pip.conf"
audit caviar-redact@0.2.0 python PIP_INDEX_URL="$PY_ORIGIN/simple" PIP_NO_INDEX=1
[[ "$rc" == 20 ]] || fail "no-index: rc=$rc"
( source "$ROOT/lib/gate-lib.sh"; safe_gate_scan_target_flags python install -f https://flat.example.test/ caviar-redact==0.2.0; [[ "$SAFE_GATE_FIND_LINKS" == 1 ]] ) || fail "the gate does not flag -f"
( source "$ROOT/lib/gate-lib.sh"; safe_gate_scan_target_flags python install --find-links=https://f/ x; [[ "$SAFE_GATE_FIND_LINKS" == 1 ]] ) || fail "the gate does not flag --find-links="
audit caviar-redact@0.2.0 python PIP_INDEX_URL="https://user:$SECRET@git.example.test:8443/api/packages/owner/pypi/simple"
[[ "$rc" == 18 ]] || fail "inline-credential index: rc=$rc"
grep -q "user:$SECRET@git.example.test" "$tmp/curl.urls" || fail "the operator's inline-credential index URL did not reach the fetch"
grep -q "$SECRET" "$tmp/out" "$tmp/result.json" "$SAFE_AUDIT_AUDIT_LOG" "$pins" && fail "the inline index credential leaked into an output or store"
pass "python: find-links (argv, env, pip config) and --no-index BLOCK on the private lane; an inline-credential index URL is used for the fetch and never printed"

# --- go -----------------------------------------------------------------------
reset_state
add_registry p-go go "$GO_ORIGIN" superbiche.me
audit superbiche.me/caviar@v0.2.0 go GOPROXY="$GO_ORIGIN,https://proxy.golang.org,direct" GONOSUMDB=superbiche.me
[[ "$rc" == 18 ]] || fail "go: rc=$rc $(cat "$tmp/out")"
grep -q "mod download -json superbiche.me/caviar@v0.2.0 GOPROXY=$GO_ORIGIN\$" "$tmp/go.argv" || fail "go fetch not pinned to the origin: $(cat "$tmp/go.argv")"
audit superbiche.me/caviar@v0.2.0 go GOPROXY="$GO_ORIGIN" GOPRIVATE=superbiche.me
[[ "$rc" == 20 ]] && grep -q 'VCS directly' "$tmp/out" || fail "GOPRIVATE route: rc=$rc"
audit superbiche.me/caviar@v0.2.0 go GOPROXY="https://proxy.golang.org,$GO_ORIGIN"
[[ "$rc" == 20 ]] || fail "origin not first: rc=$rc"
audit superbiche.me/caviar@v0.2.0 go GOPROXY="$GO_ORIGIN" FAKE_GO_H1="$H1_B"
[[ "$rc" == 20 ]] || fail "go changed: rc=$rc"
audit superbiche.me/caviar@v0.3.0 go GOPROXY="$GO_ORIGIN" FAKE_GO_MODE=e401
[[ "$rc" == 19 && "$(jq -r '.private_registry.decision' "$tmp/result.json")" == private_registry_auth_missing ]] || fail "go auth: rc=$rc"
pass "go: install through the private proxy pins h1 (18); GOPRIVATE/other-first routing and changed hashes BLOCK; auth asks"

# go.sum project lane
mkdir -p "$tmp/fix/gomod"
printf 'module example.com/app\n' > "$tmp/fix/gomod/go.mod"
printf '{"Module":{"Path":"example.com/app"},"Go":"1.22","Require":null,"Replace":null}\n' > "$tmp/fix/modjson-none.json"
export FAKE_GO_MODJSON="$tmp/fix/modjson-none.json"
printf 'superbiche.me/caviar v0.2.0 %s\nsuperbiche.me/caviar v0.2.0/go.mod %s\nexample.com/public v1.0.0/go.mod %s\n' "$H1_A" "$H1_B" "$H1_A" > "$tmp/fix/gomod/go.sum"
rm -f "$tmp/go.argv"
rc=0; GOPROXY="$GO_ORIGIN" SAFE_AUDIT_RESULT_OUT="$tmp/result.json" "$AUDIT" private-gosum --project-dir "$tmp/fix/gomod" --gate install > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" == 18 ]] || fail "gosum matched: rc=$rc $(cat "$tmp/out")"
jq -e '.private_registry_lines | length == 1 and (.[0].package == "superbiche.me/caviar@v0.2.0") and (.[0].extra | contains("pin=matched"))' "$tmp/result.json" >/dev/null \
  || fail "gosum lines: $(cat "$tmp/result.json")"
grep -q 'mod download' "$tmp/go.argv" 2>/dev/null && fail "a pinned go.sum entry fetched again"
printf 'superbiche.me/caviar v0.2.0 %s\nsuperbiche.me/caviar v0.2.0/go.mod %s\n' "$H1_B" "$H1_B" > "$tmp/fix/gomod/go.sum"
rc=0; GOPROXY="$GO_ORIGIN" SAFE_AUDIT_RESULT_OUT="$tmp/result.json" "$AUDIT" private-gosum --project-dir "$tmp/fix/gomod" --gate install > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" == 20 ]] || fail "gosum changed: rc=$rc"
rm -f "$pins"
printf 'superbiche.me/caviar v0.2.0/go.mod %s\n' "$H1_B" > "$tmp/fix/gomod/go.sum"
rc=0; GOPROXY="$GO_ORIGIN" SAFE_AUDIT_RESULT_OUT="$tmp/result.json" "$AUDIT" private-gosum --project-dir "$tmp/fix/gomod" --gate install > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" == 18 ]] && jq -e '.pins | to_entries[0].value.integrity.h1 != null' "$pins" >/dev/null || fail "gosum TOFU from a go.mod-only line: rc=$rc"
printf 'example.com/public v1.0.0/go.mod %s\n' "$H1_A" > "$tmp/fix/gomod/go.sum"
rc=0; "$AUDIT" private-gosum --project-dir "$tmp/fix/gomod" --gate install > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" == 0 ]] || fail "public-only go.sum: rc=$rc"
pass "go.sum lane: pinned private modules pass without a fetch, changed hashes BLOCK, first use pins from the origin, public modules are untouched"

# go.mod requirements without go.sum lines (round-1 P4): no sum is not authorization
rm -f "$tmp/fix/gomod/go.sum" "$pins"
jq -n '{Module: {Path: "example.com/app"}, Go: "1.22", Require: [{Path: "superbiche.me/caviar", Version: "v0.2.0"}, {Path: "example.com/public", Version: "v1.0.0"}], Replace: null}' > "$tmp/fix/modjson-req.json"
gosum() { rc=0; FAKE_GO_MODJSON="$tmp/fix/modjson-req.json" GOPROXY="$GO_ORIGIN" SAFE_AUDIT_RESULT_OUT="$tmp/result.json" "$AUDIT" private-gosum --project-dir "$tmp/fix/gomod" --gate install "$@" > "$tmp/out" 2>&1 || rc=$?; }
"$CORE" private-trust record --pins "$pins" --ecosystem go --origin "$GO_ORIGIN" --name superbiche.me/caviar --version v0.2.0 --mode revoke >/dev/null || fail "go revoke"
gosum
[[ "$rc" == 20 ]] && jq -e '.private_registry.decision == "private_pin_revoked"' "$tmp/result.json" >/dev/null || fail "revoked module required by go.mod, no go.sum: rc=$rc $(cat "$tmp/out")"
rm -f "$pins"
gosum
[[ "$rc" == 18 ]] && jq -e '.pins | to_entries[0].value.pinned_by == "tofu"' "$pins" >/dev/null || fail "first ingress without go.sum must verify from the origin and pin: rc=$rc"
grep -q 'mod download -json superbiche.me/caviar@v0.2.0' "$tmp/go.argv" || fail "first ingress was not confirmed against the origin"
gosum -- -modfile=alt.mod build ./...
[[ "$rc" == 19 ]] || fail "-modfile: rc=$rc"
rc=0; FAKE_GOWORK="$tmp/fix/go.work" FAKE_GO_MODJSON="$tmp/fix/modjson-req.json" GOPROXY="$GO_ORIGIN" SAFE_AUDIT_RESULT_OUT="$tmp/result.json" "$AUDIT" private-gosum --project-dir "$tmp/fix/gomod" --gate install > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" == 19 ]] || fail "workspace mode: rc=$rc"
jq '.Go = "1.16"' "$tmp/fix/modjson-req.json" > "$tmp/fix/modjson-old.json"
rc=0; FAKE_GO_MODJSON="$tmp/fix/modjson-old.json" GOPROXY="$GO_ORIGIN" "$AUDIT" private-gosum --project-dir "$tmp/fix/gomod" --gate install > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" == 19 ]] || fail "pre-1.17 graph: rc=$rc"
jq '.Replace = [{Old: {Path: "superbiche.me/caviar"}, New: {Path: "../caviar"}}]' "$tmp/fix/modjson-req.json" > "$tmp/fix/modjson-local.json"
"$CORE" private-trust record --pins "$pins" --ecosystem go --origin "$GO_ORIGIN" --name superbiche.me/caviar --version v0.2.0 --mode revoke >/dev/null
rc=0; FAKE_GO_MODJSON="$tmp/fix/modjson-local.json" GOPROXY="$GO_ORIGIN" "$AUDIT" private-gosum --project-dir "$tmp/fix/gomod" --gate install > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" == 0 ]] || fail "a local-directory replace downloads nothing: rc=$rc"
mkdir -p "$tmp/fix/other"; cp "$tmp/fix/gomod/go.mod" "$tmp/fix/other/go.mod"
rc=0; FAKE_GO_MODJSON="$tmp/fix/modjson-req.json" GOPROXY="$GO_ORIGIN" SAFE_AUDIT_RESULT_OUT="$tmp/result.json" "$AUDIT" private-gosum --project-dir "$tmp/fix/nonexistent" --gate install -- -C "$tmp/fix/other" mod download > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" == 20 ]] || fail "go -C must be followed: rc=$rc"
rm -f "$pins"
pass "go project lane: go.mod requirements are decided without go.sum (revoked BLOCKs, first use pins from the origin); -modfile, go.work and pre-1.17 graphs ask; local replaces skip; -C is followed"

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
ALLOW='{"package":"@p/x","resolved_versions":["1.0.0"],"private_registry":{"decision":"ALLOWED_VIA_PRIVATE_REGISTRY","audit_extra":"registry=p-npm origin=https://o artifact=a integrity=sha512-X pin=matched cooldown=0"},"gate_exit":18}'
ASK='{"package":"@p/x","resolved_versions":["1.0.0"],"private_registry":{"decision":"private_pin_missing","detail":"the registry requires an operator pin","hint":"ask the operator"},"gate_exit":19}'
BLOCK='{"package":"@p/x","resolved_versions":["1.0.0"],"block":{"class":"private","detail":"the artifact differs"},"private_registry":{"decision":"private_artifact_changed"},"gate_exit":20}'
r="$(gate_case 18 0 "$ALLOW" '')"
[[ "$r" == 0 ]] && last_line | grep -q '| ALLOWED_VIA_PRIVATE_REGISTRY | registry=p-npm origin=https://o artifact=a integrity=sha512-X' \
  || fail "18 unattended: rc=$r $(last_line)"
r="$(gate_case 18 0 '{"package":"@p/x","resolved_versions":["1.0.0"],"gate_exit":18}' '')"
[[ "$r" == 100 ]] || fail "18 without evidence: rc=$r"
pass "gate 18 installs unattended with the evidence line; an allow without evidence refuses"
r="$(gate_case 19 0 "$ASK" '')"
[[ "$r" == 102 ]] && last_line | grep -q 'REFUSED_PRIVATE_NONTTY' && grep -q 'requires an operator pin' "$tmp/gout" || fail "19 non-tty: rc=$r"
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
rc=0; "$RUN" private-registry add p-npm --ecosystem npm --origin "$NPM_ORIGIN" --namespace '@p/*' --reason r > "$tmp/out" 2>&1 </dev/null || rc=$?
[[ "$rc" == 102 && ! -e "$policy" ]] || fail "add without a terminal: rc=$rc"
pty_run "$RUN" private-registry add p-npm --ecosystem npm --origin "$NPM_ORIGIN/" --namespace '@p/*' --reason "my registry" > "$tmp/out" 2>&1 || fail "add: $(cat "$tmp/out")"
jq -e --arg o "$NPM_ORIGIN" '.registries["p-npm"].origin == $o' "$policy" >/dev/null || fail "add wrote no canonical origin"
grep -q 'PRIVATE_REGISTRY_ADDED' "$SAFE_RUN_DATA_DIR/audit.log" || fail "add not logged"
rc=0; pty_run "$RUN" private-registry add bad --ecosystem npm --origin "https://evil.example.test/npm" --namespace '@p/x' --reason r > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" != 0 ]] && grep -q 'overlapping' "$tmp/out" || fail "overlapping registry accepted: $(cat "$tmp/out")"
rc=0; pty_run "$RUN" private-registry add bad --ecosystem npm --origin "https://evil.example.test/npm" --namespace '@q/*' > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" != 0 ]] || fail "add without a reason accepted"
"$RUN" private-registry list > "$tmp/out" 2>&1 || fail "list: $(cat "$tmp/out")"
grep -q "p-npm" "$tmp/out" || fail "list"
pass "private-registry add: operator terminal only, canonical origin, overlap refused, logged; list is read-only"

rc=0; "$RUN" private-registry pin add @p/x@1.0.0 --ecosystem npm > "$tmp/out" 2>&1 </dev/null || rc=$?
[[ "$rc" == 102 ]] || fail "pin add without a terminal: rc=$rc"
SAFE_AUDIT_BIN="$AUDIT" pty_run "$RUN" private-registry pin add @p/x@1.0.0 --ecosystem npm > "$tmp/out" 2>&1 || fail "pin add: $(cat "$tmp/out")"
jq -e '.pins | to_entries[0].value.pinned_by == "operator"' "$pins" >/dev/null || fail "operator pin"
printf 'nope\n' | SAFE_AUDIT_BIN="$AUDIT" pty_run "$RUN" private-registry pin revoke @p/x@1.0.0 --ecosystem npm > "$tmp/out" 2>&1
jq -e '.pins | to_entries[0].value.revoked != true' "$pins" >/dev/null || fail "revoke without the typed identity"
printf '@p/x@1.0.0\n' | SAFE_AUDIT_BIN="$AUDIT" pty_run "$RUN" private-registry pin revoke @p/x@1.0.0 --ecosystem npm > "$tmp/out" 2>&1 || fail "revoke: $(cat "$tmp/out")"
jq -e '.pins | to_entries[0].value.revoked == true' "$pins" >/dev/null || fail "revoke not recorded"
no_secret "operator commands"
pass "pin add fetches through the private origin; revoke needs the typed identity"

rc=0; SAFE_AUDIT_BIN="$AUDIT" pty_run "$RUN" host-allow add @p/x@2.0.0 --reason "private grant" > "$tmp/out" 2>&1 || rc=$?
jq -e --arg s "$SRI_A" '.packages["@p/x"].sha == $s' "$SAFE_RUN_CONFIG_DIR/host-allow.json" >/dev/null \
  || fail "host-allow add of a private name did not use the private origin: rc=$rc $(cat "$tmp/out")"
grep -q -- "--registry=$NPM_ORIGIN/" "$tmp/npm.argv" || fail "host-allow integrity not fetched from the private origin"
pass "host-allow add of a private npm name takes its integrity from the private registry, not npmjs"

pty_run "$RUN" private-registry remove p-npm > "$tmp/out" 2>&1 || fail "remove"
rc=0; "$AUDIT" private-fetch @p/x@1.0.0 --ecosystem npm > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" == 3 ]] || fail "removed registry still private: rc=$rc"
pass "removing the registry withdraws the private lane"

printf 'all private-registry tests passed\n'
