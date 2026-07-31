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
  low) printf '{"score": 40}\n'; exit 0 ;;
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
# 14. --registry is used as the npm resolution source, and an UNTRUSTED
#     custom source floors at WARN even though resolution succeeded
# ---------------------------------------------------------------------------
prepare_case registry-flag
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_REGISTRY_URL_LOG="$CASE_DIR/urls.log" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion --ecosystem npm --registry https://registry.example --gate install
if expect_status 10 "untrusted custom registry floors at WARN"; then
  pass "untrusted custom registry floors at WARN"
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
# 22. Malformed pagination token shape must not read as zero advisories
# ---------------------------------------------------------------------------
prepare_case pagination-bad-token
PAGES="$CASE_DIR/pages"
mkdir -p "$PAGES"
printf '{"next_page_token": false}' > "$PAGES/page1.json"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_PAGES="$PAGES" \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion@2.1.4 --ecosystem npm --gate install
if expect_status 10 "non-string pagination token fails closed"; then
  pass "non-string pagination token fails closed"
fi

# ---------------------------------------------------------------------------
# 23. vparse orders SemVer prerelease identifiers per spec (unit-level)
# ---------------------------------------------------------------------------
sed '$d' "$SAFE_AUDIT" > "$TEST_ROOT/audit-lib.sh"
if (
  SAFE_AUDIT_NO_INIT=1
  # shellcheck source=/dev/null
  source "$TEST_ROOT/audit-lib.sh" >/dev/null 2>&1
  jq -n "$JQ_VSEMVER"'
    vlt("1.0.0-alpha.2"; "1.0.0-alpha.10")
    and vlt("1.0.0-alpha.10"; "1.0.0")
    and vlt("1.0.0-alpha"; "1.0.0-alpha.1")
    and vlt("1.0.0-alpha.beta"; "1.0.0-beta")
    and vlt("0e0.0.0"; "0.0.1")
    and vlt("1e2.0.0"; "1.0.0")
  ' | grep -q '^true$'
); then
  pass "prerelease identifiers compare per SemVer, not lexically"
else
  fail "prerelease identifiers compare per SemVer, not lexically"
fi

# ---------------------------------------------------------------------------
# 24. Version-qualified override keys degrade resolution too
# ---------------------------------------------------------------------------
prepare_case overrides-qualified
printf '{"dependencies": {"brace-expansion": "^2.0.0"}, "overrides": {"brace-expansion@^2.0.0": "1.1.11"}}\n' > "$CASE_PROJECT/package.json"
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion --ecosystem npm --op update --gate install
if expect_status 10 "version-qualified override key degrades resolution"; then
  pass "version-qualified override key degrades resolution"
fi

# ---------------------------------------------------------------------------
# 25. Custom source floors at WARN even for exact versions (delta finding 3)
# ---------------------------------------------------------------------------
prepare_case custom-source-exact
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- requests@2.32.0 --ecosystem python --registry https://private.example --gate install
if expect_status 10 "exact version from a custom source still floors at WARN"; then
  pass "exact version from a custom source still floors at WARN"
fi
if expect_grep "$ERR_FILE" 'trusted_registries' "custom-source refusal names the trust knob"; then
  pass "custom-source refusal names the trust knob"
fi

# ---------------------------------------------------------------------------
# 26. install.trusted_registries lifts the custom-source floor
# ---------------------------------------------------------------------------
prepare_case trusted-registry
printf '{"install": {"trusted_registries": ["https://registry.example"]}}\n' > "$CASE_RUN_CONFIG/config.json"
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion --ecosystem npm --registry https://registry.example --gate install
if expect_status 0 "an operator-trusted registry audits like the default source"; then
  pass "an operator-trusted registry audits like the default source"
fi

# ---------------------------------------------------------------------------
# 27. Host-allow override still revokes stale clean evidence (delta finding 5)
# ---------------------------------------------------------------------------
prepare_case override-still-revokes
printf '{"dependencies": {"brace-expansion": "^2.0.0"}}\n' > "$CASE_PROJECT/package.json"
printf '{"packages": {"brace-expansion": {"version": "2.1.4", "ecosystem": "npm", "added": "2026-07-31", "reason": "test"}}}\n' \
  > "$CASE_RUN_CONFIG/host-allow.json"
printf '{"packages": {"npm:brace-expansion": {"version": "2.1.4", "verdict": "GO", "reasons": [], "evidence": "x", "first_allowed": "2026-07-31T10:00:00+02:00", "last_used": "2026-07-31", "times_used": 1}}}\n' \
  > "$CASE_RUN_CONFIG/install-known.json"
fixture="$(osv_fixture_affecting_moderate)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_OSV_MATCH_VERSION=2.1.4 \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion@2.1.4 --ecosystem npm --gate install
if expect_status 0 "pinned host-allow still permits this invocation"; then
  pass "pinned host-allow still permits this invocation"
fi
if jq -e '.packages["npm:brace-expansion"] == null' "$CASE_RUN_CONFIG/install-known.json" >/dev/null 2>&1; then
  pass "stale clean evidence is revoked even when host-allow overrides"
else
  cat "$CASE_RUN_CONFIG/install-known.json" >&2
  fail "stale clean evidence is revoked even when host-allow overrides"
fi


# ---------------------------------------------------------------------------
# 28. A whitespace-only pagination token is rejected, not read as completion
# ---------------------------------------------------------------------------
prepare_case pagination-ws-token
PAGES="$CASE_DIR/pages"
mkdir -p "$PAGES"
# printf '%s' so the file is VALID JSON whose decoded token is a real
# newline — a format-string \n would break the JSON itself and exercise the
# generic malformed-JSON path instead (delta-3 F2 test nit).
printf '%s' '{"vulns": [], "next_page_token": "\n"}' > "$PAGES/page1.json"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_PAGES="$PAGES" \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion@2.1.4 --ecosystem npm --gate install
if expect_status 10 "whitespace pagination token fails closed"; then
  pass "whitespace pagination token fails closed"
fi

# ---------------------------------------------------------------------------
# 29. jq-numeric-but-SemVer-alphanumeric prerelease ids ("1e-2") never let
#     the resolver pick a version npm would reject
# ---------------------------------------------------------------------------
prepare_case semver-numeric-grammar
cat > "$FIXTURES/packument-1e2.json" <<'JSON'
{
  "dist-tags": {"latest": "1.0.0-1e-2"},
  "versions": {"1.0.0-1e-2": {}, "1.0.0-1": {}}
}
JSON
printf '{"dependencies": {"demo-pkg": "<=1.0.0-1"}}\n' > "$CASE_PROJECT/package.json"
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument-1e2.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- demo-pkg --ecosystem npm --op update --gate install
if expect_status 10 "alphanumeric 1e-2 prerelease cannot satisfy a numeric bound"; then
  pass "alphanumeric 1e-2 prerelease cannot satisfy a numeric bound"
fi
if expect_no_grep "$OUT_FILE" 'Resolved:.*1e-2' "the wrong tagged version is never audited as the target"; then
  pass "the wrong tagged version is never audited as the target"
fi

# ---------------------------------------------------------------------------
# 30. Trust matching is origin-bounded: pypi.org.evil.example is NOT PyPI
# ---------------------------------------------------------------------------
prepare_case evil-hostname
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- requests@2.32.0 --ecosystem python --registry https://pypi.org.evil.example/simple --gate install
if expect_status 10 "a pypi.org-prefixed attacker hostname is not trusted"; then
  pass "a pypi.org-prefixed attacker hostname is not trusted"
fi

prepare_case real-pypi-trusted
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- requests@2.32.0 --ecosystem python --registry https://pypi.org/simple --gate install
if expect_status 0 "the real PyPI origin stays trusted"; then
  pass "the real PyPI origin stays trusted"
fi

# ---------------------------------------------------------------------------
# 31. Cumulative sources: one untrusted source floors even beside a trusted one
# ---------------------------------------------------------------------------
prepare_case multi-source
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- requests@2.32.0 --ecosystem python --registry 'local:find-links https://pypi.org/simple' --gate install
if expect_status 10 "an untrusted source in a cumulative set floors at WARN"; then
  pass "an untrusted source in a cumulative set floors at WARN"
fi

# ---------------------------------------------------------------------------
# 32. A low Socket score is adverse evidence: it revokes stale clean receipts
# ---------------------------------------------------------------------------
prepare_case low-score-revokes
printf '{"packages": {"npm:brace-expansion": {"version": "2.1.4", "verdict": "GO", "reasons": [], "evidence": "x", "source": "default", "first_allowed": "2026-07-31T10:00:00+02:00", "last_used": "2026-07-31", "times_used": 1}}}\n' \
  > "$CASE_RUN_CONFIG/install-known.json"
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=low \
  -- brace-expansion@2.1.4 --ecosystem npm --gate install
if expect_status 10 "low socket score refuses"; then
  pass "low socket score refuses"
fi
if jq -e '.packages["npm:brace-expansion"] == null' "$CASE_RUN_CONFIG/install-known.json" >/dev/null 2>&1; then
  pass "low socket score revokes stale clean evidence"
else
  cat "$CASE_RUN_CONFIG/install-known.json" >&2
  fail "low socket score revokes stale clean evidence"
fi

# ---------------------------------------------------------------------------
# 33. Receipts are source-scoped on write
# ---------------------------------------------------------------------------
prepare_case receipt-source-scope
printf '{"install": {"trusted_registries": ["https://mirror.example"]}}\n' > "$CASE_RUN_CONFIG/config.json"
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion --ecosystem npm --registry https://mirror.example --gate install
if expect_status 0 "trusted mirror gates GO"; then
  pass "trusted mirror gates GO"
fi
if jq -e '.packages["npm:brace-expansion"].source == "explicit:https://mirror.example"' \
  "$CASE_RUN_CONFIG/install-known.json" >/dev/null 2>&1; then
  pass "receipt records the source it was gathered against"
else
  cat "$CASE_RUN_CONFIG/install-known.json" >&2
  fail "receipt records the source it was gathered against"
fi

# ---------------------------------------------------------------------------
# 34. npm repeated --registry: resolution follows npm's LAST-wins semantics
#     (delta-3 finding 3.1) while the floor still sees every selector
# ---------------------------------------------------------------------------
prepare_case npm-registry-last-wins
printf '{"install": {"trusted_registries": ["https://first.example", "https://second.example"]}}\n' \
  > "$CASE_RUN_CONFIG/config.json"
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_REGISTRY_URL_LOG="$CASE_DIR/registry-urls.log" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion --ecosystem npm --registry 'https://first.example https://second.example' --gate install
if expect_status 0 "two operator-trusted registries still gate GO"; then
  pass "two operator-trusted registries still gate GO"
fi
if grep -q '^https://second\.example/' "$CASE_DIR/registry-urls.log" \
  && ! grep -q '^https://first\.example/' "$CASE_DIR/registry-urls.log"; then
  pass "npm resolution fetches from the LAST registry (npm last-wins)"
else
  cat "$CASE_DIR/registry-urls.log" >&2
  fail "npm resolution fetches from the LAST registry (npm last-wins)"
fi

# ---------------------------------------------------------------------------
# 35. NPM_CONFIG_REGISTRY reaches the trust floor even on an exact pin
#     (delta-3 finding 3.2: effective sources outside argv)
# ---------------------------------------------------------------------------
prepare_case env-registry-floor
fixture="$(osv_fixture_empty)"
run_check \
  NPM_CONFIG_REGISTRY=https://evil.example \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion@2.1.4 --ecosystem npm --gate install
if expect_status 10 "env-configured registry floors an exact pin at WARN"; then
  pass "env-configured registry floors an exact pin at WARN"
fi
if expect_grep "$ERR_FILE" 'custom package source' "env-registry refusal names the custom source"; then
  pass "env-registry refusal names the custom source"
fi

# ---------------------------------------------------------------------------
# 36. A project .npmrc registry line reaches the trust floor too
# ---------------------------------------------------------------------------
prepare_case npmrc-registry-floor
printf 'registry=https://corp.example/npm/\n' > "$CASE_PROJECT/.npmrc"
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion@2.1.4 --ecosystem npm --gate install
if expect_status 10 "project .npmrc registry floors an exact pin at WARN"; then
  pass "project .npmrc registry floors an exact pin at WARN"
fi

# ---------------------------------------------------------------------------
# 37. A trusted env-configured mirror stays frictionless and the receipt is
#     scoped to it (UX-preserving mitigation for finding 3.2)
# ---------------------------------------------------------------------------
prepare_case env-registry-trusted
printf '{"install": {"trusted_registries": ["https://mirror.example"]}}\n' > "$CASE_RUN_CONFIG/config.json"
fixture="$(osv_fixture_empty)"
run_check \
  NPM_CONFIG_REGISTRY=https://mirror.example \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion@2.1.4 --ecosystem npm --gate install
if expect_status 0 "a trusted env-configured mirror gates GO"; then
  pass "a trusted env-configured mirror gates GO"
fi
if jq -e '.packages["npm:brace-expansion"].source == "explicit:https://mirror.example"' \
  "$CASE_RUN_CONFIG/install-known.json" >/dev/null 2>&1; then
  pass "receipt identity carries the env-configured source"
else
  cat "$CASE_RUN_CONFIG/install-known.json" >&2
  fail "receipt identity carries the env-configured source"
fi

# ---------------------------------------------------------------------------
# 38. Malformed packument core versions never win selection: npm's selector
#     rejects "0e0.0.0"; ours must pick what npm actually installs
#     (delta-3 finding 4)
# ---------------------------------------------------------------------------
prepare_case malformed-core
cat > "$FIXTURES/packument-malformed.json" <<'JSON'
{
  "dist-tags": {"latest": "0e0.0.0"},
  "versions": {"0e0.0.0": {}, "1.0.0": {}}
}
JSON
printf '{"dependencies": {"demo-pkg": "<=1.0.0"}}\n' > "$CASE_PROJECT/package.json"
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument-malformed.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- demo-pkg --ecosystem npm --op update --gate install
if expect_status 0 "malformed candidates are excluded from selection"; then
  pass "malformed candidates are excluded from selection"
fi
if expect_grep "$OUT_FILE" 'Resolved:.*1\.0\.0' "the well-formed in-range version is audited"; then
  pass "the well-formed in-range version is audited"
fi
if expect_no_grep "$OUT_FILE" '0e0' "the malformed version is never the audited target"; then
  pass "the malformed version is never the audited target"
fi

# ---------------------------------------------------------------------------
# 39. A malformed dist-tag TARGET degrades instead of being audited
# ---------------------------------------------------------------------------
prepare_case malformed-dist-tag
cat > "$FIXTURES/packument-malformed-only.json" <<'JSON'
{
  "dist-tags": {"latest": "0e0.0.0"},
  "versions": {"0e0.0.0": {}}
}
JSON
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument-malformed-only.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- demo-pkg --ecosystem npm --gate install
if expect_status 10 "a malformed dist-tag target degrades to unresolved"; then
  pass "a malformed dist-tag target degrades to unresolved"
fi
if expect_grep "$ERR_FILE" 'pin an exact version' "degraded refusal keeps the pin guidance"; then
  pass "degraded refusal keeps the pin guidance"
fi

# ---------------------------------------------------------------------------
# 40. Default-source receipts carry the implicit-default sentinel; a literal
#     "--registry default" floors (untrusted) and never writes a colliding
#     receipt (delta-3 finding 5)
# ---------------------------------------------------------------------------
prepare_case implicit-default-sentinel
printf '{"dependencies": {"brace-expansion": "^2.0.0"}}\n' > "$CASE_PROJECT/package.json"
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion@2.1.4 --ecosystem npm --gate install
if expect_status 0 "default-source exact pin gates GO"; then
  pass "default-source exact pin gates GO"
fi
if jq -e '.packages["npm:brace-expansion"].source == "implicit-default"' \
  "$CASE_RUN_CONFIG/install-known.json" >/dev/null 2>&1; then
  pass "default-source receipt carries the implicit-default sentinel"
else
  cat "$CASE_RUN_CONFIG/install-known.json" >&2
  fail "default-source receipt carries the implicit-default sentinel"
fi
run_check \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- ripgrep@14.1.1 --ecosystem cargo --registry default --gate install
if expect_status 10 "a literal 'default' selector is an untrusted explicit source"; then
  pass "a literal 'default' selector is an untrusted explicit source"
fi

# ---------------------------------------------------------------------------
# 41. Lowercase npm_config_registry is as effective as the uppercase form
#     (delta-4 finding 3.2)
# ---------------------------------------------------------------------------
prepare_case env-registry-lowercase
fixture="$(osv_fixture_empty)"
run_check \
  npm_config_registry=https://evil.example \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion@2.1.4 --ecosystem npm --gate install
if expect_status 10 "lowercase npm_config_registry floors an exact pin at WARN"; then
  pass "lowercase npm_config_registry floors an exact pin at WARN"
fi

# ---------------------------------------------------------------------------
# 42. A scoped @scope:registry .npmrc key routes the scoped package to a
#     custom registry — it must reach the floor even beside argv selectors
#     (delta-4 finding 3.2)
# ---------------------------------------------------------------------------
prepare_case scoped-registry-floor
printf '@demo:registry=https://scoped.example\n' > "$CASE_PROJECT/.npmrc"
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- @demo/pkg@1.2.3 --ecosystem npm --gate install
if expect_status 10 "a scoped .npmrc registry floors the scoped package"; then
  pass "a scoped .npmrc registry floors the scoped package"
fi
: > "$CASE_DIR/stderr.log"
run_check \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- @demo/pkg@1.2.3 --ecosystem npm --registry https://registry.npmjs.org --gate install
if expect_status 10 "the scoped key floors even beside a trusted argv selector"; then
  pass "the scoped key floors even beside a trusted argv selector"
fi

# ---------------------------------------------------------------------------
# 43. Malformed PRERELEASE identifiers never win selection either: npm
#     rejects leading-zero numeric identifiers like 1.0.0-01
#     (delta-4 finding 4)
# ---------------------------------------------------------------------------
prepare_case malformed-prerelease
cat > "$FIXTURES/packument-pre01.json" <<'JSON'
{
  "dist-tags": {"latest": "1.0.0-01"},
  "versions": {"1.0.0-01": {}, "1.0.0": {}}
}
JSON
printf '{"dependencies": {"demo-pkg": "<=1.0.0"}}\n' > "$CASE_PROJECT/package.json"
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument-pre01.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- demo-pkg --ecosystem npm --op update --gate install
if expect_status 0 "a leading-zero prerelease candidate is excluded"; then
  pass "a leading-zero prerelease candidate is excluded"
fi
if expect_grep "$OUT_FILE" 'Resolved:.*1\.0\.0' "npm-oracle: the valid version npm installs is audited"; then
  pass "npm-oracle: the valid version npm installs is audited"
fi
if expect_no_grep "$OUT_FILE" '1\.0\.0-01' "the malformed prerelease is never the target"; then
  pass "the malformed prerelease is never the target"
fi
prepare_case malformed-prerelease-tag
cat > "$FIXTURES/packument-pre01-only.json" <<'JSON'
{
  "dist-tags": {"latest": "1.0.0-01"},
  "versions": {"1.0.0-01": {}}
}
JSON
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument-pre01-only.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- demo-pkg --ecosystem npm --gate install
if expect_status 10 "a malformed prerelease dist-tag target degrades"; then
  pass "a malformed prerelease dist-tag target degrades"
fi

# ---------------------------------------------------------------------------
# 44. version_is_exact enforces full SemVer grammar (unit-level)
# ---------------------------------------------------------------------------
if (
  SAFE_AUDIT_NO_INIT=1
  # shellcheck source=/dev/null
  source "$TEST_ROOT/audit-lib.sh" >/dev/null 2>&1
  for bad in 1.0.0-01 01.0.0 1.0.0-alpha..1 1.0.0-.alpha 1.0.0-alpha. 0e0.0.0; do
    ! version_is_exact npm "$bad" || exit 1
  done
  for good in 1.0.0 1.0.0-alpha.1 1.0.0-0 1.0.0+build.1 v1.0.0-rc.1+meta.2; do
    version_is_exact npm "$good" || exit 1
  done
  version_is_exact go v1.2.3 || exit 1
  ! version_is_exact go 1.2.3 || exit 1
); then
  pass "version_is_exact enforces full SemVer grammar"
else
  fail "version_is_exact enforces full SemVer grammar"
fi

# ---------------------------------------------------------------------------
# 45. effective-sources plumbing: single derivation for readers
#     (delta-4 findings 3.2 and N1)
# ---------------------------------------------------------------------------
prepare_case effective-sources-plumbing
run_es() {
  (
    cd "$CASE_PROJECT" || exit 99
    env \
      HOME="$CASE_HOME" \
      PATH="$MOCKBIN:/usr/bin:/bin" \
      SAFE_RUN_CONFIG_DIR="$CASE_RUN_CONFIG" \
      SAFE_AUDIT_CONFIG_DIR="$CASE_DIR/audit-config" \
      SAFE_AUDIT_DATA_DIR="$CASE_DIR/audit-data" \
      "$@" \
      "$SAFE_AUDIT" effective-sources "${ES_ARGS[@]}"
  )
}
ES_ARGS=(okpkg --ecosystem npm)
if [[ "$(run_es)" == "implicit-default" ]]; then
  pass "plumbing: no sources -> implicit-default"
else
  fail "plumbing: no sources -> implicit-default"
fi
ES_ARGS=(okpkg --ecosystem npm --registry 'https://a.example/ https://a.example')
if [[ "$(run_es)" == "explicit:https://a.example" ]]; then
  pass "plumbing: trailing slashes and repeats canonicalize (N1)"
else
  fail "plumbing: trailing slashes and repeats canonicalize (N1)"
fi
ES_ARGS=(okpkg --ecosystem npm --registry 'https://a.example https://b.example https://a.example')
if [[ "$(run_es)" == "explicit:https://b.example https://a.example" ]]; then
  pass "plumbing: a repeated selector keeps its LAST position (3.1)"
else
  fail "plumbing: a repeated selector keeps its LAST position (3.1)"
fi
ES_ARGS=(okpkg --ecosystem npm)
if [[ "$(run_es NPM_CONFIG_REGISTRY=https://mirror.example/)" == "explicit:https://mirror.example" ]]; then
  pass "plumbing: env registry becomes an explicit identity"
else
  fail "plumbing: env registry becomes an explicit identity"
fi
ES_ARGS=(okpkg --ecosystem cargo --registry default)
if [[ "$(run_es)" == "explicit:default" ]]; then
  pass "plumbing: a literal default selector stays explicit"
else
  fail "plumbing: a literal default selector stays explicit"
fi

# ---------------------------------------------------------------------------
# 46. Receipt identity is canonicalized: a trailing-slash argv selector and
#     its slashless twin are the same source (delta-4 finding N1)
# ---------------------------------------------------------------------------
prepare_case receipt-canonical
printf '{"install": {"trusted_registries": ["https://mirror.example"]}}\n' > "$CASE_RUN_CONFIG/config.json"
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion@2.1.4 --ecosystem npm --registry https://mirror.example/ --gate install
if expect_status 0 "trailing-slash trusted mirror gates GO"; then
  pass "trailing-slash trusted mirror gates GO"
fi
if jq -e '.packages["npm:brace-expansion"].source == "explicit:https://mirror.example"' \
  "$CASE_RUN_CONFIG/install-known.json" >/dev/null 2>&1; then
  pass "receipt identity is slash-canonical"
else
  cat "$CASE_RUN_CONFIG/install-known.json" >&2
  fail "receipt identity is slash-canonical"
fi

# ---------------------------------------------------------------------------
# 47. Sibling manager env sources reach the floor: PIP_INDEX_URL and GOPROXY
#     (delta-4 finding 3.2)
# ---------------------------------------------------------------------------
prepare_case pip-env-floor
fixture="$(osv_fixture_empty)"
run_check \
  PIP_INDEX_URL=https://evil.example/simple \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- requests@2.32.0 --ecosystem python --gate install
if expect_status 10 "PIP_INDEX_URL floors an exact python pin at WARN"; then
  pass "PIP_INDEX_URL floors an exact python pin at WARN"
fi
prepare_case goproxy-floor
run_check \
  GOPROXY='https://corp.example,direct' \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- golang.org/x/tools@v0.1.0 --ecosystem go --gate install
if expect_status 10 "a custom GOPROXY floors a go pin at WARN"; then
  pass "a custom GOPROXY floors a go pin at WARN"
fi

# ---------------------------------------------------------------------------
# 48. A trusted pip mirror stays frictionless (UX preservation for 3.2)
# ---------------------------------------------------------------------------
prepare_case pip-env-trusted
printf '{"install": {"trusted_registries": ["https://mirror.example"]}}\n' > "$CASE_RUN_CONFIG/config.json"
fixture="$(osv_fixture_empty)"
run_check \
  PIP_INDEX_URL=https://mirror.example/simple \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- requests@2.32.0 --ecosystem python --gate install
if expect_status 0 "a trusted pip mirror gates GO without friction"; then
  pass "a trusted pip mirror gates GO without friction"
fi

# ---------------------------------------------------------------------------
# 49. When both env case forms are set, the LOWERCASE one wins — npm's own
#     precedence (delta-5 finding 3.2)
# ---------------------------------------------------------------------------
prepare_case env-registry-case-precedence
printf '{"install": {"trusted_registries": ["https://mirror.example"]}}\n' > "$CASE_RUN_CONFIG/config.json"
fixture="$(osv_fixture_empty)"
run_check \
  NPM_CONFIG_REGISTRY=https://mirror.example \
  npm_config_registry=https://evil.example \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion@2.1.4 --ecosystem npm --gate install
if expect_status 10 "lowercase env wins over a trusted uppercase mirror"; then
  pass "lowercase env wins over a trusted uppercase mirror"
fi

# ---------------------------------------------------------------------------
# 50. node-semver limits: a numeric core beyond MAX_SAFE_INTEGER is a TAG to
#     npm, never a version (delta-5 finding 4)
# ---------------------------------------------------------------------------
if (
  SAFE_AUDIT_NO_INIT=1
  # shellcheck source=/dev/null
  source "$TEST_ROOT/audit-lib.sh" >/dev/null 2>&1
  version_is_exact npm 9007199254740991.0.0 || exit 1
  ! version_is_exact npm 9007199254740992.0.0 || exit 1
  long_pre=$(printf 'a%.0s' {1..260})
  ! version_is_exact npm "1.0.0-${long_pre}" || exit 1
); then
  pass "npm version grammar enforces node-semver limits"
else
  fail "npm version grammar enforces node-semver limits"
fi
prepare_case huge-core-tag
cat > "$FIXTURES/packument-hugetag.json" <<'JSON'
{
  "dist-tags": {"latest": "1.0.0", "9007199254740992.0.0": "1.0.0"},
  "versions": {"1.0.0": {}}
}
JSON
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument-hugetag.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- demo-pkg@9007199254740992.0.0 --ecosystem npm --gate install
if expect_status 0 "an over-limit numeric spec resolves as the dist-tag npm sees"; then
  pass "an over-limit numeric spec resolves as the dist-tag npm sees"
fi
if expect_grep "$OUT_FILE" 'Resolved:.*1\.0\.0 \(dist-tag' "npm-oracle: the tag's target version is audited"; then
  pass "npm-oracle: the tag's target version is audited"
fi
prepare_case huge-core-range
cat > "$FIXTURES/packument-hugelatest.json" <<'JSON'
{
  "dist-tags": {"latest": "9007199254740992.0.0"},
  "versions": {"9007199254740992.0.0": {}, "1.0.0": {}}
}
JSON
printf '{"dependencies": {"demo-pkg": ">=1.0.0"}}\n' > "$CASE_PROJECT/package.json"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument-hugelatest.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- demo-pkg --ecosystem npm --op update --gate install
if expect_status 0 "an over-limit candidate is excluded from range selection"; then
  pass "an over-limit candidate is excluded from range selection"
fi
if expect_grep "$OUT_FILE" 'Resolved:.*1\.0\.0' "npm-oracle: the valid candidate wins the range"; then
  pass "npm-oracle: the valid candidate wins the range"
fi
if expect_no_grep "$OUT_FILE" '9007199254740992' "the over-limit value is never the audited target"; then
  pass "the over-limit value is never the audited target"
fi

# ---------------------------------------------------------------------------
# 51. Python find-links / extra-index env selectors reach the floor
#     (delta-5 finding 3.2)
# ---------------------------------------------------------------------------
prepare_case pip-findlinks-floor
fixture="$(osv_fixture_empty)"
run_check \
  PIP_FIND_LINKS=https://evil.example/wheels \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- requests@2.32.0 --ecosystem python --gate install
if expect_status 10 "PIP_FIND_LINKS floors an exact python pin at WARN"; then
  pass "PIP_FIND_LINKS floors an exact python pin at WARN"
fi
prepare_case uv-extra-index-floor
run_check \
  UV_EXTRA_INDEX_URL=https://evil.example/simple \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- requests@2.32.0 --ecosystem python --gate install
if expect_status 10 "UV_EXTRA_INDEX_URL floors an exact python pin at WARN"; then
  pass "UV_EXTRA_INDEX_URL floors an exact python pin at WARN"
fi
prepare_case pip-noindex-floor
run_check \
  PIP_NO_INDEX=1 \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- requests@2.32.0 --ecosystem python --gate install
if expect_status 10 "PIP_NO_INDEX floors at WARN (local resolution)"; then
  pass "PIP_NO_INDEX floors at WARN (local resolution)"
fi

# ---------------------------------------------------------------------------
# 52. Inline credentials never reach output, receipts, or identities
#     (delta-5 finding N2)
# ---------------------------------------------------------------------------
prepare_case creds-redacted-refusal
fixture="$(osv_fixture_empty)"
run_check \
  PIP_INDEX_URL=https://alice:sekret@evil.example/simple \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- requests@2.32.0 --ecosystem python --gate install
if expect_status 10 "a credentialed custom index still floors"; then
  pass "a credentialed custom index still floors"
fi
if expect_no_grep "$OUT_FILE" 'sekret' "credentials never reach stdout"; then
  pass "credentials never reach stdout"
fi
if expect_no_grep "$ERR_FILE" 'sekret' "credentials never reach stderr"; then
  pass "credentials never reach stderr"
fi
prepare_case creds-redacted-receipt
printf '{"install": {"trusted_registries": ["https://mirror.example"]}}\n' > "$CASE_RUN_CONFIG/config.json"
run_check \
  PIP_INDEX_URL=https://alice:sekret@mirror.example/simple \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- requests@2.32.0 --ecosystem python --gate install
if expect_status 0 "trust matches the credential-free canonical endpoint"; then
  pass "trust matches the credential-free canonical endpoint"
fi
if jq -e '.packages["python:requests"].source == "explicit:https://mirror.example/simple"' \
  "$CASE_RUN_CONFIG/install-known.json" >/dev/null 2>&1 \
  && ! grep -q 'sekret' "$CASE_RUN_CONFIG/install-known.json"; then
  pass "receipt identity is credential-free"
else
  cat "$CASE_RUN_CONFIG/install-known.json" >&2
  fail "receipt identity is credential-free"
fi

# ---------------------------------------------------------------------------
printf '\n%d passed, %d failed\n' "$PASS_COUNT" "$FAIL_COUNT"
[[ "$FAIL_COUNT" -eq 0 ]]
