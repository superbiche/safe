#!/usr/bin/env bash
# Version-aware `safe audit check` suite: target-version resolution, OSV
# server-authoritative classification, pagination, install-gate mode,
# install-known recording/revocation, and the pinned (never @latest) refusal
# hints. Fully offline: curl and socket are mocked on PATH.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SAFE_AUDIT="$ROOT/bin/safe-audit"

PASS_COUNT=0
FAIL_COUNT=0

pass() { printf 'ok - %s\n' "$*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { printf 'not ok - %s\n' "$*" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }

TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT

MOCKBIN="$TEST_ROOT/mockbin"
mkdir -p "$MOCKBIN"

# --- mock curl ---------------------------------------------------------------
# Registry requests serve MOCK_REGISTRY_FIXTURE (fail with MOCK_REGISTRY_STATUS).
# OSV requests are version-aware: when the posted body carries a version equal
# to MOCK_OSV_MATCH_VERSION the fixture is served, otherwise an empty vulns
# page — mirroring the real server-side matching of /v1/query. Package-only
# queries (no version in body) always get the fixture. MOCK_OSV_PAGES=<dir>
# serves <dir>/page1.json, page2.json… per call instead (pagination tests).
cat > "$MOCKBIN/curl" <<'MOCK'
#!/usr/bin/env bash
url=""
outfile=""
data=""
args=("$@")
i=0
while (( i < ${#args[@]} )); do
  a="${args[$i]}"
  case "$a" in
    -H|--max-time) i=$((i + 2)); continue ;;
    -d) data="${args[$((i + 1))]}"; i=$((i + 2)); continue ;;
    -o) outfile="${args[$((i + 1))]}"; i=$((i + 2)); continue ;;
    http*://*) url="$a" ;;
  esac
  i=$((i + 1))
done
emit() {
  if [[ -n "$outfile" ]]; then cat > "$outfile"; else cat; fi
}
case "$url" in
  *api.osv.dev*)
    [[ "${MOCK_OSV_STATUS:-0}" == "0" ]] || exit 22
    if [[ -n "${MOCK_OSV_PAGES:-}" ]]; then
      count_file="${MOCK_OSV_PAGES}/.count"
      count=$(( $(cat "$count_file" 2>/dev/null || echo 0) + 1 ))
      printf '%s' "$count" > "$count_file"
      cat "${MOCK_OSV_PAGES}/page${count}.json" | emit
      exit 0
    fi
    body_version=$(printf '%s' "$data" | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')
    if [[ -z "$body_version" || "$body_version" == "${MOCK_OSV_MATCH_VERSION:-}" ]]; then
      cat "${MOCK_OSV_FIXTURE:?}" | emit
    else
      printf '{"vulns": []}' | emit
    fi
    ;;
  *)
    [[ "${MOCK_REGISTRY_STATUS:-0}" == "0" ]] || exit 22
    printf '%s\n' "$url" >> "${MOCK_REGISTRY_URL_LOG:-/dev/null}"
    cat "${MOCK_REGISTRY_FIXTURE:?}" | emit
    ;;
esac
exit 0
MOCK
chmod +x "$MOCKBIN/curl"

# --- mock socket CLI ---------------------------------------------------------
cat > "$MOCKBIN/socket" <<'MOCK'
#!/usr/bin/env bash
case "${MOCK_SOCKET_MODE:-ok}" in
  ok) printf '{"score": 95}\n'; exit 0 ;;
  auth) printf '{"message":"Unauthorized","cause":"401 Unauthorized"}\n'; exit 1 ;;
  rate) printf '{"message":"Too Many Requests","cause":"429"}\n'; exit 1 ;;
  *) exit 1 ;;
esac
MOCK
chmod +x "$MOCKBIN/socket"

FIXTURES="$TEST_ROOT/fixtures"
mkdir -p "$FIXTURES"

# brace-expansion-like packument: 1.x line, 2.x line (tip 2.1.4), latest 5.0.1
cat > "$FIXTURES/packument.json" <<'JSON'
{
  "dist-tags": {"latest": "5.0.1", "beta": "2.1.3", "next": "6.0.0-rc.1"},
  "versions": {
    "1.1.11": {}, "1.1.12": {},
    "2.0.0": {}, "2.0.1": {}, "2.1.3": {}, "2.1.4": {},
    "3.0.0-rc.1": {},
    "4.0.0": {}, "5.0.0": {}, "5.0.1": {}
  }
}
JSON

# npm latest-tag preference: latest=1.2.0 satisfies ^1.0.0 although 1.3.0 exists
cat > "$FIXTURES/packument-latestpref.json" <<'JSON'
{
  "dist-tags": {"latest": "1.2.0"},
  "versions": {"1.1.0": {}, "1.2.0": {}, "1.3.0": {}}
}
JSON

cat > "$FIXTURES/crates.json" <<'JSON'
{"crate": {"max_stable_version": "14.1.1", "newest_version": "14.1.1"}}
JSON

cat > "$FIXTURES/packagist.json" <<'JSON'
{"packages": {"vendor/pkg": [{"version": "2.5.0"}, {"version": "2.4.0"}]}}
JSON

osv_fixture_empty() {
  printf '{"vulns": []}' > "$FIXTURES/osv-empty.json"
  printf '%s' "$FIXTURES/osv-empty.json"
}

#  - GHSA-AFFECTS-MOD: moderate, matched by the server for the queried version
osv_fixture_affecting_moderate() {
  cat > "$FIXTURES/osv-affect-mod.json" <<'JSON'
{"vulns": [
  {"id": "GHSA-AFFECTS-MOD", "database_specific": {"severity": "MODERATE"},
   "affected": [{"package": {"ecosystem": "npm", "name": "brace-expansion"},
     "ranges": [{"type": "SEMVER", "events": [{"introduced": "2.0.0"}, {"fixed": "2.9.9"}]}]}]}
]}
JSON
  printf '%s' "$FIXTURES/osv-affect-mod.json"
}

osv_fixture_affecting_critical() {
  cat > "$FIXTURES/osv-affect-crit.json" <<'JSON'
{"vulns": [
  {"id": "GHSA-AFFECTS-CRIT", "database_specific": {"severity": "critical"},
   "affected": [{"package": {"ecosystem": "npm", "name": "brace-expansion"},
     "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]}
]}
JSON
  printf '%s' "$FIXTURES/osv-affect-crit.json"
}

# Server-matched advisory whose LOCAL range data claims the version is fixed —
# the exact-query server hit must win (review finding 1: the local comparator
# must never downgrade a version-scoped result to GO).
osv_fixture_server_hit_local_miss() {
  cat > "$FIXTURES/osv-server-hit.json" <<'JSON'
{"vulns": [
  {"id": "GHSA-SERVER-HIT", "database_specific": {"severity": "HIGH"},
   "affected": [{"package": {"ecosystem": "npm", "name": "brace-expansion"},
     "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0-alpha.2"}, {"fixed": "1.0.0"}]}]}]}
]}
JSON
  printf '%s' "$FIXTURES/osv-server-hit.json"
}

osv_fixture_git_only() {
  cat > "$FIXTURES/osv-git-only.json" <<'JSON'
{"vulns": [
  {"id": "GHSA-GIT-ONLY", "database_specific": {"severity": "LOW"},
   "affected": [{"package": {"ecosystem": "npm", "name": "brace-expansion"},
     "ranges": [{"type": "GIT", "repo": "https://example.invalid/r", "events": [{"introduced": "abc123"}]}]}]}
]}
JSON
  printf '%s' "$FIXTURES/osv-git-only.json"
}

# No database_specific.severity; only a standard CVSS v3 vector (9.8 critical).
osv_fixture_cvss_critical() {
  cat > "$FIXTURES/osv-cvss-crit.json" <<'JSON'
{"vulns": [
  {"id": "GHSA-CVSS-ONLY",
   "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
   "affected": [{"package": {"ecosystem": "npm", "name": "brace-expansion"},
     "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]}
]}
JSON
  printf '%s' "$FIXTURES/osv-cvss-crit.json"
}

CASE_DIR=""
CASE_RUN_CONFIG=""
CASE_HOME=""
CASE_PROJECT=""
CASE_CHECKS_DIR=""

prepare_case() {
  local name="$1"
  CASE_DIR="$TEST_ROOT/case-$name"
  CASE_RUN_CONFIG="$CASE_DIR/run-config"
  CASE_HOME="$CASE_DIR/home"
  CASE_PROJECT="$CASE_DIR/project"
  CASE_CHECKS_DIR="$CASE_DIR/audit-data/checks"
  mkdir -p "$CASE_RUN_CONFIG" "$CASE_HOME" "$CASE_PROJECT" "$CASE_DIR/audit-config" "$CASE_DIR/audit-data"
}

# run_check <mock env assignments...> -- <check args...>
run_check() {
  local -a envs=()
  while [[ "$1" != "--" ]]; do
    envs+=("$1")
    shift
  done
  shift
  OUT_FILE="$CASE_DIR/stdout.log"
  ERR_FILE="$CASE_DIR/stderr.log"
  set +e
  (
    cd "$CASE_PROJECT" || exit 99
    env \
      HOME="$CASE_HOME" \
      PATH="$MOCKBIN:/usr/bin:/bin" \
      SAFE_RUN_CONFIG_DIR="$CASE_RUN_CONFIG" \
      SAFE_AUDIT_CONFIG_DIR="$CASE_DIR/audit-config" \
      SAFE_AUDIT_DATA_DIR="$CASE_DIR/audit-data" \
      "${envs[@]}" \
      "$SAFE_AUDIT" check "$@"
  ) > "$OUT_FILE" 2> "$ERR_FILE"
  STATUS=$?
  set -e
}

expect_status() {
  local expected="$1" label="$2"
  if [[ "$STATUS" -ne "$expected" ]]; then
    printf 'expected exit %s, got %s\nstdout:\n%s\nstderr:\n%s\n' \
      "$expected" "$STATUS" "$(cat "$OUT_FILE")" "$(cat "$ERR_FILE")" >&2
    fail "$label"
    return 1
  fi
  return 0
}

expect_grep() {
  local file="$1" pattern="$2" label="$3"
  if ! grep -qE "$pattern" "$file"; then
    printf 'pattern not found: %s\nin:\n%s\n' "$pattern" "$(cat "$file")" >&2
    fail "$label"
    return 1
  fi
  return 0
}

expect_no_grep() {
  local file="$1" pattern="$2" label="$3"
  if grep -qE "$pattern" "$file"; then
    printf 'forbidden pattern found: %s\nin:\n%s\n' "$pattern" "$(cat "$file")" >&2
    fail "$label"
    return 1
  fi
  return 0
}

# ---------------------------------------------------------------------------
# 1. Exact clean version (server returns nothing), socket ok -> GO + record
# ---------------------------------------------------------------------------
prepare_case exact-clean
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion@2.1.4 --ecosystem npm --gate install
if expect_status 0 "exact clean version gates GO"; then
  pass "exact clean version gates GO"
fi
if jq -e '.packages["npm:brace-expansion"] | .version == "2.1.4" and .verdict == "GO"' \
  "$CASE_RUN_CONFIG/install-known.json" >/dev/null 2>&1; then
  pass "install-known entry recorded with pinned version"
else
  cat "$CASE_RUN_CONFIG/install-known.json" 2>/dev/null >&2 || true
  fail "install-known entry recorded with pinned version"
fi

# ---------------------------------------------------------------------------
# 2. npm update shape: unversioned + --op update resolves in-range (2.1.4)
# ---------------------------------------------------------------------------
prepare_case update-in-range
printf '{"dependencies": {"brace-expansion": "^2.0.0"}}\n' > "$CASE_PROJECT/package.json"
cat > "$CASE_PROJECT/package-lock.json" <<'JSON'
{"packages": {"node_modules/minimatch": {"dependencies": {"brace-expansion": "^2.0.1"}}}}
JSON
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion --ecosystem npm --op update --gate install
if expect_status 0 "update op resolves in-range and gates GO"; then
  pass "update op resolves in-range and gates GO"
fi
if expect_grep "$OUT_FILE" 'Resolved:.*2\.1\.4' "resolved line shows the in-range target"; then
  pass "resolved line shows the in-range target"
fi
if expect_no_grep "$OUT_FILE" '5\.0\.1' "dist-tag latest is not the audited version on update"; then
  pass "dist-tag latest is not the audited version on update"
fi
receipt="$CASE_CHECKS_DIR/$(date +%F)-brace-expansion-2.1.4.json"
if [[ -f "$receipt" ]] && jq -e '.resolution.method == "project-range" and .resolved_versions == ["2.1.4"]' "$receipt" >/dev/null; then
  pass "receipt records resolution evidence"
else
  ls "$CASE_CHECKS_DIR" >&2 || true
  fail "receipt records resolution evidence"
fi

# ---------------------------------------------------------------------------
# 3. Server hit whose local ranges disagree must stay affecting (finding 1)
# ---------------------------------------------------------------------------
prepare_case server-hit-wins
fixture="$(osv_fixture_server_hit_local_miss)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_OSV_MATCH_VERSION=2.1.4 \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion@2.1.4 --ecosystem npm --gate install
if expect_status 10 "version-scoped server hit is authoritative over local ranges"; then
  pass "version-scoped server hit is authoritative over local ranges"
fi

# ---------------------------------------------------------------------------
# 4. Critical advisory affecting the resolved version -> BLOCK (gate exit 20)
# ---------------------------------------------------------------------------
prepare_case affect-critical
fixture="$(osv_fixture_affecting_critical)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_OSV_MATCH_VERSION=2.1.4 \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion@2.1.4 --ecosystem npm --gate install
if expect_status 20 "critical advisory on resolved version blocks"; then
  pass "critical advisory on resolved version blocks"
fi

# ---------------------------------------------------------------------------
# 5. Standard CVSS v3 critical with no database_specific -> still BLOCK
# ---------------------------------------------------------------------------
prepare_case cvss-critical
fixture="$(osv_fixture_cvss_critical)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_OSV_MATCH_VERSION=2.1.4 \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion@2.1.4 --ecosystem npm --gate install
if expect_status 20 "standard CVSS v3 critical blocks without database_specific"; then
  pass "standard CVSS v3 critical blocks without database_specific"
fi

# ---------------------------------------------------------------------------
# 6a. Affecting moderate -> WARN refusal with pinned host-allow hint
# ---------------------------------------------------------------------------
prepare_case affect-moderate
fixture="$(osv_fixture_affecting_moderate)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_OSV_MATCH_VERSION=2.1.4 \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion@2.1.4 --ecosystem npm --gate install
if expect_status 10 "moderate affecting advisory refuses at the gate"; then
  pass "moderate affecting advisory refuses at the gate"
fi
if expect_grep "$ERR_FILE" 'host-allow add brace-expansion@2\.1\.4' "refusal hint is pinned to the resolved version"; then
  pass "refusal hint is pinned to the resolved version"
fi
if expect_no_grep "$ERR_FILE" '@latest' "refusal hint never suggests @latest"; then
  pass "refusal hint never suggests @latest"
fi

# ---------------------------------------------------------------------------
# 6b. Same, but a pinned host-allow entry matching the resolved version allows
# ---------------------------------------------------------------------------
prepare_case host-allow-resolved
printf '{"dependencies": {"brace-expansion": "^2.0.0"}}\n' > "$CASE_PROJECT/package.json"
printf '{"packages": {"brace-expansion": {"version": "2.1.4", "ecosystem": "npm", "added": "2026-07-31", "reason": "test"}}}\n' \
  > "$CASE_RUN_CONFIG/host-allow.json"
fixture="$(osv_fixture_affecting_moderate)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_OSV_MATCH_VERSION=2.1.4 \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion --ecosystem npm --op update --gate install
if expect_status 0 "pinned host-allow entry matches the RESOLVED version of an unversioned spec"; then
  pass "pinned host-allow entry matches the RESOLVED version of an unversioned spec"
fi
if expect_grep "$ERR_FILE" 'host-allow entry brace-expansion@2\.1\.4 matches' "override notice names the pin"; then
  pass "override notice names the pin"
fi

# ---------------------------------------------------------------------------
# 7. Gate WARN/BLOCK revokes a stale install-known entry for the same version
# ---------------------------------------------------------------------------
prepare_case revoke-on-adverse
printf '{"packages": {"npm:brace-expansion": {"version": "2.1.4", "verdict": "GO", "reasons": [], "evidence": "x", "first_allowed": "2026-07-31T10:00:00+02:00", "last_used": "2026-07-31", "times_used": 1}}}\n' \
  > "$CASE_RUN_CONFIG/install-known.json"
fixture="$(osv_fixture_affecting_moderate)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_OSV_MATCH_VERSION=2.1.4 \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion@2.1.4 --ecosystem npm --gate install
if expect_status 10 "adverse check still refuses"; then
  pass "adverse check still refuses"
fi
if jq -e '.packages["npm:brace-expansion"] == null' "$CASE_RUN_CONFIG/install-known.json" >/dev/null 2>&1; then
  pass "adverse check revokes the stale install-known entry"
else
  cat "$CASE_RUN_CONFIG/install-known.json" >&2
  fail "adverse check revokes the stale install-known entry"
fi

# ---------------------------------------------------------------------------
# 8a. Socket unavailable, OSV clean -> refusal legible as infrastructure
# ---------------------------------------------------------------------------
prepare_case socket-down
mv "$MOCKBIN/socket" "$MOCKBIN/socket.hidden"
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  -- brace-expansion@2.1.4 --ecosystem npm --gate install
mv "$MOCKBIN/socket.hidden" "$MOCKBIN/socket"
if expect_status 10 "socket outage still refuses (never tolerated silently)"; then
  pass "socket outage still refuses (never tolerated silently)"
fi
if expect_grep "$ERR_FILE" 'infrastructure failure, NOT a package finding' "socket refusal reads as breakage, not a CVE"; then
  pass "socket refusal reads as breakage, not a CVE"
fi
if expect_grep "$ERR_FILE" 'fix now:' "socket refusal carries a recovery path"; then
  pass "socket refusal carries a recovery path"
fi

# ---------------------------------------------------------------------------
# 8b. Operator opt-in tolerate knob allows socket-outage WARN when OSV clean
# ---------------------------------------------------------------------------
prepare_case socket-tolerated
printf '{"install": {"auto_allow_tolerate": ["socket_unavailable"]}}\n' > "$CASE_RUN_CONFIG/config.json"
mv "$MOCKBIN/socket" "$MOCKBIN/socket.hidden"
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  -- brace-expansion@2.1.4 --ecosystem npm --gate install
mv "$MOCKBIN/socket.hidden" "$MOCKBIN/socket"
if expect_status 0 "auto_allow_tolerate opt-in allows the tolerated cause"; then
  pass "auto_allow_tolerate opt-in allows the tolerated cause"
fi
if jq -e '.packages["npm:brace-expansion"].verdict == "WARN_TOLERATED"' \
  "$CASE_RUN_CONFIG/install-known.json" >/dev/null 2>&1; then
  pass "tolerated allow recorded with its reasons"
else
  fail "tolerated allow recorded with its reasons"
fi
# A tolerated record must be distinguishable from clean GO evidence: the
# offline timeout fallback readers require verdict == "GO".
if jq -e '.packages["npm:brace-expansion"].verdict != "GO"' \
  "$CASE_RUN_CONFIG/install-known.json" >/dev/null 2>&1; then
  pass "tolerated record is not disguised as clean GO evidence"
else
  fail "tolerated record is not disguised as clean GO evidence"
fi

# ---------------------------------------------------------------------------
# 9. Unresolvable range (||) -> degraded WARN with pin guidance
# ---------------------------------------------------------------------------
prepare_case unresolved-range
printf '{"dependencies": {"brace-expansion": "^1.0.0 || ^2.0.0"}}\n' > "$CASE_PROJECT/package.json"
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion --ecosystem npm --op update --gate install
if expect_status 10 "unresolvable range degrades to WARN refusal"; then
  pass "unresolvable range degrades to WARN refusal"
fi
if expect_grep "$ERR_FILE" 'pin an exact version' "unresolved refusal tells the caller to pin"; then
  pass "unresolved refusal tells the caller to pin"
fi

# ---------------------------------------------------------------------------
# 10. overrides mentioning the package -> unresolved (npm may force a version)
# ---------------------------------------------------------------------------
prepare_case overrides-degrade
printf '{"dependencies": {"brace-expansion": "^2.0.0"}, "overrides": {"brace-expansion": "1.1.11"}}\n' > "$CASE_PROJECT/package.json"
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion --ecosystem npm --op update --gate install
if expect_status 10 "root overrides degrade resolution instead of guessing"; then
  pass "root overrides degrade resolution instead of guessing"
fi
if expect_grep "$OUT_FILE" 'version unresolved' "overrides path is explicit"; then
  pass "overrides path is explicit"
fi

# ---------------------------------------------------------------------------
# 11. Glob regression: a file matching the range must not alter parsing
# ---------------------------------------------------------------------------
prepare_case glob-range
printf '{"dependencies": {"brace-expansion": "1.*"}}\n' > "$CASE_PROJECT/package.json"
touch "$CASE_PROJECT/1.0.0"
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion --ecosystem npm --op update --gate install
if expect_status 0 "1.* range resolves despite a matching filename in cwd"; then
  pass "1.* range resolves despite a matching filename in cwd"
fi
if expect_grep "$OUT_FILE" 'Resolved:.*1\.1\.12' "1.* resolves to the 1.x tip, not the filename"; then
  pass "1.* resolves to the 1.x tip, not the filename"
fi

# ---------------------------------------------------------------------------
# 12. npm latest-tag preference: latest wins when it satisfies the range
# ---------------------------------------------------------------------------
prepare_case latest-pref
printf '{"dependencies": {"demo-pkg": "^1.0.0"}}\n' > "$CASE_PROJECT/package.json"
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument-latestpref.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- demo-pkg --ecosystem npm --op update --gate install
if expect_status 0 "latest-tag preference case gates GO"; then
  pass "latest-tag preference case gates GO"
fi
if expect_grep "$OUT_FILE" 'Resolved:.*1\.2\.0' "npm picks the satisfying latest tag, not plain max"; then
  pass "npm picks the satisfying latest tag, not plain max"
fi

# ---------------------------------------------------------------------------
# 13. --dist-tag changes what an unversioned install audits
# ---------------------------------------------------------------------------
prepare_case dist-tag-flag
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion --ecosystem npm --dist-tag beta --gate install
if expect_status 0 "--dist-tag resolves through the named tag"; then
  pass "--dist-tag resolves through the named tag"
fi
if expect_grep "$OUT_FILE" 'Resolved:.*2\.1\.3' "--dist-tag beta audits the beta target"; then
  pass "--dist-tag beta audits the beta target"
fi

# ---------------------------------------------------------------------------
# 14. --registry is used as the npm resolution source
# ---------------------------------------------------------------------------
prepare_case registry-flag
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_REGISTRY_URL_LOG="$CASE_DIR/urls.log" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion --ecosystem npm --registry https://registry.example --gate install
if expect_status 0 "--registry resolution gates GO"; then
  pass "--registry resolution gates GO"
fi
if expect_grep "$CASE_DIR/urls.log" '^https://registry\.example/brace-expansion$' "packument fetched from the command-line registry"; then
  pass "packument fetched from the command-line registry"
fi

# ---------------------------------------------------------------------------
# 15. A custom python index makes the default-registry lookup unresolvable
# ---------------------------------------------------------------------------
prepare_case python-index
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- requests --ecosystem python --registry https://index.example --gate install
if expect_status 10 "custom python index degrades instead of auditing PyPI"; then
  pass "custom python index degrades instead of auditing PyPI"
fi

# ---------------------------------------------------------------------------
# 16. cargo/composer ecosystem labels reach their resolvers (finding 7)
# ---------------------------------------------------------------------------
prepare_case cargo-eco
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/crates.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- ripgrep --ecosystem cargo --gate install
if expect_status 0 "cargo ecosystem resolves via crates.io"; then
  pass "cargo ecosystem resolves via crates.io"
fi
if expect_grep "$OUT_FILE" 'Resolved:.*14\.1\.1' "cargo unpinned resolves to the stable tip"; then
  pass "cargo unpinned resolves to the stable tip"
fi

prepare_case composer-eco
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packagist.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- vendor/pkg --ecosystem composer --gate install
if expect_status 0 "composer ecosystem resolves via packagist"; then
  pass "composer ecosystem resolves via packagist"
fi
if expect_grep "$OUT_FILE" 'Resolved:.*2\.5\.0' "composer unpinned resolves to the newest release"; then
  pass "composer unpinned resolves to the newest release"
fi

# ---------------------------------------------------------------------------
# 17. OSV pagination: token-only first page, findings on page 2 (finding 2)
# ---------------------------------------------------------------------------
prepare_case pagination
PAGES="$CASE_DIR/pages"
mkdir -p "$PAGES"
printf '{"next_page_token": "opaque-token-1"}' > "$PAGES/page1.json"
cp "$(osv_fixture_affecting_critical)" "$PAGES/page2.json"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_PAGES="$PAGES" \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion@2.1.4 --ecosystem npm --gate install
if expect_status 20 "advisories on a later OSV page still block"; then
  pass "advisories on a later OSV page still block"
fi

prepare_case pagination-loop
PAGES="$CASE_DIR/pages"
mkdir -p "$PAGES"
printf '{"next_page_token": "same-token"}' > "$PAGES/page1.json"
printf '{"next_page_token": "same-token"}' > "$PAGES/page2.json"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_PAGES="$PAGES" \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion@2.1.4 --ecosystem npm --gate install
if expect_status 10 "a repeated pagination token fails closed"; then
  pass "a repeated pagination token fails closed"
fi
if expect_grep "$OUT_FILE" 'OSV query failed|OSV pagination|OSV response' "pagination anomaly is explicit"; then
  pass "pagination anomaly is explicit"
fi

# ---------------------------------------------------------------------------
# 18. Registry failure -> degraded WARN, never GO
# ---------------------------------------------------------------------------
prepare_case registry-down
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_REGISTRY_STATUS=22 \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion --ecosystem npm --gate install
if expect_status 10 "registry outage degrades to WARN refusal"; then
  pass "registry outage degrades to WARN refusal"
fi

# ---------------------------------------------------------------------------
# 19. OSV outage with a resolved version -> WARN (fail closed, was fail-open)
# ---------------------------------------------------------------------------
prepare_case osv-down
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_OSV_STATUS=22 \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion@2.1.4 --ecosystem npm --gate install
if expect_status 10 "OSV outage fails closed instead of counting zero CVEs"; then
  pass "OSV outage fails closed instead of counting zero CVEs"
fi
if expect_grep "$OUT_FILE" 'OSV query failed' "OSV outage is explicit in the check output"; then
  pass "OSV outage is explicit in the check output"
fi

# ---------------------------------------------------------------------------
# 20. GIT-only advisory on the exact path is trusted as affecting (WARN)
# ---------------------------------------------------------------------------
prepare_case git-only
fixture="$(osv_fixture_git_only)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_OSV_MATCH_VERSION=2.1.4 \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion@2.1.4 --ecosystem npm --gate install
if expect_status 10 "unparseable advisory ranges stay WARN on the exact path"; then
  pass "unparseable advisory ranges stay WARN on the exact path"
fi

# ---------------------------------------------------------------------------
# 21. Non-gate mode is unchanged for consumers: WARN -> 10, GO -> 0
# ---------------------------------------------------------------------------
prepare_case plain-warn
fixture="$(osv_fixture_affecting_moderate)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_OSV_MATCH_VERSION=2.1.4 \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion@2.1.4 --ecosystem npm
if expect_status 10 "plain check keeps WARN=10 for existing consumers"; then
  pass "plain check keeps WARN=10 for existing consumers"
fi
if [[ ! -f "$CASE_RUN_CONFIG/install-known.json" ]]; then
  pass "plain check never writes install-known"
else
  fail "plain check never writes install-known"
fi

prepare_case plain-go
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion@2.1.4 --ecosystem npm --json
if expect_status 0 "plain check keeps GO=0"; then
  pass "plain check keeps GO=0"
fi
if jq -e '.verdict == "GO" and .resolution.status == "ok" and (.osv.classification.affecting | length) == 0' "$OUT_FILE" >/dev/null 2>&1; then
  pass "check --json exposes resolution and classification"
else
  cat "$OUT_FILE" >&2
  fail "check --json exposes resolution and classification"
fi

# ---------------------------------------------------------------------------
printf '\n%d passed, %d failed\n' "$PASS_COUNT" "$FAIL_COUNT"
[[ "$FAIL_COUNT" -eq 0 ]]
