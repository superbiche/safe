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
[[ -n "${MOCK_SOCKET_ARGS_LOG:-}" ]] && printf '%s\n' "$*" >> "$MOCK_SOCKET_ARGS_LOG"
case "${MOCK_SOCKET_MODE:-ok}" in
  ok) printf '{"score": 95}\n'; exit 0 ;;
  low) printf '{"score": 40}\n'; exit 0 ;;
  auth) printf '{"message":"Unauthorized","cause":"401 Unauthorized"}\n'; exit 1 ;;
  rate) printf '{"message":"Too Many Requests","cause":"429"}\n'; exit 1 ;;
  hang) sleep 300; exit 0 ;;
  # First call: auth failure (triggers the vault-injected retry); the
  # retry then hangs. State lives in a per-case file.
  auth-then-hang)
    if [[ -e "${MOCK_SOCKET_STATE:?}" ]]; then
      sleep 300
      exit 0
    fi
    : > "${MOCK_SOCKET_STATE}"
    printf '{"message":"Unauthorized","cause":"401 Unauthorized"}\n'
    exit 1 ;;
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

osv_fixture_cvss4_critical() {
  cat > "$FIXTURES/osv-cvss4-crit.json" <<'JSON'
{"vulns": [
  {"id": "GHSA-CVSS4-CRITICAL",
   "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"}],
   "affected": [{"package": {"ecosystem": "npm", "name": "brace-expansion"},
     "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]}
]}
JSON
  printf '%s' "$FIXTURES/osv-cvss4-crit.json"
}

osv_fixture_cvss4_moderate() {
  cat > "$FIXTURES/osv-cvss4-moderate.json" <<'JSON'
{"vulns": [
  {"id": "GHSA-CVSS4-MODERATE",
   "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N"}],
   "affected": [{"package": {"ecosystem": "npm", "name": "brace-expansion"},
     "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]}
]}
JSON
  printf '%s' "$FIXTURES/osv-cvss4-moderate.json"
}

osv_fixture_cvss4_malformed() {
  cat > "$FIXTURES/osv-cvss4-malformed.json" <<'JSON'
{"vulns": [
  {"id": "GHSA-CVSS4-MALFORMED",
   "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H"}],
   "affected": [{"package": {"ecosystem": "npm", "name": "brace-expansion"},
     "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]}
]}
JSON
  printf '%s' "$FIXTURES/osv-cvss4-malformed.json"
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
# 5a. Standard CVSS v4 critical with no qualitative label -> BLOCK
# ---------------------------------------------------------------------------
prepare_case cvss4-critical
fixture="$(osv_fixture_cvss4_critical)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_OSV_MATCH_VERSION=2.1.4 \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion@2.1.4 --ecosystem npm --gate install
if expect_status 20 "standard CVSS v4 critical blocks without a qualitative label"; then
  pass "standard CVSS v4 critical blocks without a qualitative label"
fi

# ---------------------------------------------------------------------------
# 5b. Standard CVSS v4 moderate with no qualitative label -> WARN
# ---------------------------------------------------------------------------
prepare_case cvss4-moderate
fixture="$(osv_fixture_cvss4_moderate)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_OSV_MATCH_VERSION=2.1.4 \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion@2.1.4 --ecosystem npm --gate install
if expect_status 10 "standard CVSS v4 moderate warns without a qualitative label"; then
  pass "standard CVSS v4 moderate warns without a qualitative label"
fi

# ---------------------------------------------------------------------------
# 5c. A malformed CVSS v4 vector retains the high WARN floor
# ---------------------------------------------------------------------------
prepare_case cvss4-malformed
fixture="$(osv_fixture_cvss4_malformed)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_OSV_MATCH_VERSION=2.1.4 \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion@2.1.4 --ecosystem npm --gate install
if expect_status 10 "malformed CVSS v4 vector retains the high floor"; then
  pass "malformed CVSS v4 vector retains the high floor"
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
# A cargo --registry value is a NAME; one that happens to be the literal
# string "default" maps to the opaque cargo-registry:<name> identity — still
# explicit, never conflated with the implicit default source.
ES_ARGS=(okpkg --ecosystem cargo --registry default)
if [[ "$(run_es)" == "explicit:cargo-registry:default" ]]; then
  pass "plumbing: a literal default selector stays explicit"
else
  printf 'got: %s\n' "$(run_es)" >&2
  fail "plumbing: a literal default selector stays explicit"
fi
ES_ARGS=(@demo/pkg --ecosystem npm --registry '@demo:registry=https://alice:pw@scoped.example/')
if [[ "$(run_es)" == "explicit:@demo:registry=https://scoped.example" ]]; then
  pass "plumbing: scoped tokens keep their key, redacted and canonical"
else
  printf 'got: %s\n' "$(run_es)" >&2
  fail "plumbing: scoped tokens keep their key, redacted and canonical"
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
  # node-semver measures the 256-char ceiling on the RAW input, v included
  # (delta-6 finding 4): v1.0.0- plus 249 chars = 256 raw (ok), 250 = 257.
  pre_249=$(printf 'a%.0s' {1..249})
  pre_250=$(printf 'a%.0s' {1..250})
  version_is_exact npm "v1.0.0-${pre_249}" || exit 1
  ! version_is_exact npm "v1.0.0-${pre_250}" || exit 1
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
# 53. Scoped selectors keep their KEY end-to-end: resolution uses the
#     matching scope's registry, CLI beats env for the same key
#     (delta-6 finding 3.2b)
# ---------------------------------------------------------------------------
prepare_case scoped-key-resolution
printf '{"install": {"trusted_registries": ["https://foo.example", "https://bar.example"]}}\n' \
  > "$CASE_RUN_CONFIG/config.json"
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_REGISTRY_URL_LOG="$CASE_DIR/registry-urls.log" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- @foo/pkg --ecosystem npm --registry '@foo:registry=https://foo.example @bar:registry=https://bar.example' --gate install
if expect_status 0 "two trusted scoped registries still gate GO"; then
  pass "two trusted scoped registries still gate GO"
fi
if grep -q '^https://foo\.example/' "$CASE_DIR/registry-urls.log" \
  && ! grep -q '^https://bar\.example/' "$CASE_DIR/registry-urls.log"; then
  pass "npm-oracle: the MATCHING scope's registry resolves the package"
else
  cat "$CASE_DIR/registry-urls.log" >&2
  fail "npm-oracle: the MATCHING scope's registry resolves the package"
fi
prepare_case scoped-cli-over-env
printf '{"install": {"trusted_registries": ["https://cli.example", "https://env.example"]}}\n' \
  > "$CASE_RUN_CONFIG/config.json"
run_check \
  'npm_config_@demo:registry=https://env.example' \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_REGISTRY_URL_LOG="$CASE_DIR/registry-urls.log" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- @demo/pkg --ecosystem npm --registry '@demo:registry=https://cli.example' --gate install
if expect_status 0 "trusted scoped CLI + env gate GO"; then
  pass "trusted scoped CLI + env gate GO"
fi
if grep -q '^https://cli\.example/' "$CASE_DIR/registry-urls.log"; then
  pass "npm-oracle: a CLI scoped selector beats the env one"
else
  cat "$CASE_DIR/registry-urls.log" >&2
  fail "npm-oracle: a CLI scoped selector beats the env one"
fi

# ---------------------------------------------------------------------------
# 54. An env-selected alternate userconfig file reaches the floor
#     (delta-6 finding 3.2b)
# ---------------------------------------------------------------------------
prepare_case env-userconfig-floor
printf 'registry=https://evil.example\n' > "$CASE_DIR/alt-npmrc"
fixture="$(osv_fixture_empty)"
run_check \
  npm_config_userconfig="$CASE_DIR/alt-npmrc" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion@2.1.4 --ecosystem npm --gate install
if expect_status 10 "npm_config_userconfig registry floors an exact pin"; then
  pass "npm_config_userconfig registry floors an exact pin"
fi

# ---------------------------------------------------------------------------
# 55. Query-string credentials are redacted like userinfo; operational
#     fetches keep their credentials (delta-6 finding N2)
# ---------------------------------------------------------------------------
prepare_case query-token-redacted
fixture="$(osv_fixture_empty)"
run_check \
  PIP_INDEX_URL='https://evil.example/simple?token=sekret2' \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- requests@2.32.0 --ecosystem python --gate install
if expect_status 10 "a query-credentialed custom index still floors"; then
  pass "a query-credentialed custom index still floors"
fi
if expect_no_grep "$OUT_FILE" 'sekret2' "query tokens never reach stdout" \
  && expect_no_grep "$ERR_FILE" 'sekret2' "query tokens never reach stderr"; then
  pass "query tokens never reach output"
fi
prepare_case authed-registry-operational
printf '{"install": {"trusted_registries": ["https://mirror.example"]}}\n' > "$CASE_RUN_CONFIG/config.json"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_REGISTRY_URL_LOG="$CASE_DIR/registry-urls.log" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion --ecosystem npm --registry https://alice:pw@mirror.example --gate install
if expect_status 0 "an authenticated trusted registry gates GO"; then
  pass "an authenticated trusted registry gates GO"
fi
if grep -q '^https://alice:pw@mirror\.example/' "$CASE_DIR/registry-urls.log"; then
  pass "the packument fetch keeps its credentials (operational URL)"
else
  cat "$CASE_DIR/registry-urls.log" >&2
  fail "the packument fetch keeps its credentials (operational URL)"
fi
if jq -e '.packages["npm:brace-expansion"].source == "explicit:https://mirror.example"' \
  "$CASE_RUN_CONFIG/install-known.json" >/dev/null 2>&1 \
  && ! grep -q 'alice' "$CASE_RUN_CONFIG/install-known.json"; then
  pass "the receipt identity is credential-free while the fetch was authed"
else
  cat "$CASE_RUN_CONFIG/install-known.json" >&2
  fail "the receipt identity is credential-free while the fetch was authed"
fi

# ---------------------------------------------------------------------------
# 56. pip config syntax: colon delimiters, continuations, and pip's boolean
#     vocabulary (delta-6 findings 3.2c and N3)
# ---------------------------------------------------------------------------
prepare_case pip-colon-config
cat > "$CASE_DIR/pip.conf" <<'CONF'
[global]
find-links: https://evil.example/wheels
CONF
fixture="$(osv_fixture_empty)"
run_check \
  PIP_CONFIG_FILE="$CASE_DIR/pip.conf" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- requests@2.32.0 --ecosystem python --gate install
if expect_status 10 "a colon-delimited find-links floors"; then
  pass "a colon-delimited find-links floors"
fi
prepare_case pip-continuation-config
cat > "$CASE_DIR/pip.conf" <<'CONF'
[global]
find-links =
    https://evil.example/wheels
CONF
run_check \
  PIP_CONFIG_FILE="$CASE_DIR/pip.conf" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- requests@2.32.0 --ecosystem python --gate install
if expect_status 10 "a continuation-line find-links floors"; then
  pass "a continuation-line find-links floors"
fi
prepare_case pip-noindex-colon
cat > "$CASE_DIR/pip.conf" <<'CONF'
[install]
no-index: yes
CONF
run_check \
  PIP_CONFIG_FILE="$CASE_DIR/pip.conf" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- requests@2.32.0 --ecosystem python --gate install
if expect_status 10 "no-index: yes floors"; then
  pass "no-index: yes floors"
fi
prepare_case pip-noindex-false
run_check \
  PIP_NO_INDEX=False \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- requests@2.32.0 --ecosystem python --gate install
if expect_status 0 "PIP_NO_INDEX=False preserves the default-source GO"; then
  pass "PIP_NO_INDEX=False preserves the default-source GO"
fi
prepare_case pip-noindex-zero-pair
run_check \
  PIP_NO_INDEX=0 \
  UV_NO_INDEX=0 \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- requests@2.32.0 --ecosystem python --gate install
if expect_status 0 "a 0/0 no-index pair never floors"; then
  pass "a 0/0 no-index pair never floors"
fi

# ---------------------------------------------------------------------------
# 57. Alternate npm config files are threaded as PATHS with npm's config
#     tiers — scoped keys resolve per package, generic keys reach the floor
#     (delta-7 finding 3.2b)
# ---------------------------------------------------------------------------
prepare_case userconfig-scoped-resolution
printf '@foo:registry=https://foo.example\n@bar:registry=https://bar.example\n' > "$CASE_DIR/alt-npmrc"
printf '{"install": {"trusted_registries": ["https://foo.example"]}}\n' > "$CASE_RUN_CONFIG/config.json"
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_REGISTRY_URL_LOG="$CASE_DIR/registry-urls.log" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- @foo/pkg --ecosystem npm --npm-userconfig "$CASE_DIR/alt-npmrc" --gate install
if expect_status 0 "userconfig scoped key resolves the matching scope only"; then
  pass "userconfig scoped key resolves the matching scope only"
fi
if grep -q '^https://foo\.example/' "$CASE_DIR/registry-urls.log" \
  && ! grep -q 'bar\.example' "$CASE_DIR/registry-urls.log"; then
  pass "npm-oracle: the matching scope's key wins from an alternate file"
else
  cat "$CASE_DIR/registry-urls.log" >&2
  fail "npm-oracle: the matching scope's key wins from an alternate file"
fi
prepare_case userconfig-generic-floor
printf 'registry=https://evil.example\n' > "$CASE_DIR/alt-npmrc"
run_check \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion@2.1.4 --ecosystem npm --npm-userconfig "$CASE_DIR/alt-npmrc" --gate install
if expect_status 10 "a generic registry in an argv userconfig floors"; then
  pass "a generic registry in an argv userconfig floors"
fi

# ---------------------------------------------------------------------------
# 58. pip config semantics: [install] overrides [global] regardless of file
#     order, keys normalize (case, underscores), spaced paths survive
#     (delta-7 finding 3.2c)
# ---------------------------------------------------------------------------
prepare_case pip-section-precedence
cat > "$CASE_DIR/pip.conf" <<'CONF'
[install]
index-url = https://evil.example/simple

[global]
index-url = https://pypi.org/simple
CONF
run_check \
  PIP_CONFIG_FILE="$CASE_DIR/pip.conf" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- requests@2.32.0 --ecosystem python --gate install
if expect_status 10 "the install section overrides a trailing global section"; then
  pass "the install section overrides a trailing global section"
fi
prepare_case pip-key-normalization
cat > "$CASE_DIR/pip.conf" <<'CONF'
[global]
INDEX_URL: https://evil.example/simple
CONF
run_check \
  PIP_CONFIG_FILE="$CASE_DIR/pip.conf" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- requests@2.32.0 --ecosystem python --gate install
if expect_status 10 "pip-style key normalization (case + underscores) applies"; then
  pass "pip-style key normalization (case + underscores) applies"
fi
prepare_case pip-spaced-path
mkdir -p "$CASE_DIR/conf dir"
cat > "$CASE_DIR/conf dir/pip.conf" <<'CONF'
[global]
index-url = https://evil.example/simple
CONF
run_check \
  PIP_CONFIG_FILE="$CASE_DIR/conf dir/pip.conf" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- requests@2.32.0 --ecosystem python --gate install
if expect_status 10 "a config path containing spaces is still swept"; then
  pass "a config path containing spaces is still swept"
fi

# ---------------------------------------------------------------------------
# 59. pip's full boolean vocabulary: y and t are true too (delta-7 N3)
# ---------------------------------------------------------------------------
prepare_case pip-noindex-y
run_check \
  PIP_NO_INDEX=y \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- requests@2.32.0 --ecosystem python --gate install
if expect_status 10 "PIP_NO_INDEX=y floors"; then
  pass "PIP_NO_INDEX=y floors"
fi
prepare_case pip-noindex-t-config
cat > "$CASE_DIR/pip.conf" <<'CONF'
[global]
no-index: t
CONF
run_check \
  PIP_CONFIG_FILE="$CASE_DIR/pip.conf" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- requests@2.32.0 --ecosystem python --gate install
if expect_status 10 "a config-file no-index: t floors"; then
  pass "a config-file no-index: t floors"
fi

# ---------------------------------------------------------------------------
# 60. Option-like config paths cannot fail the sweep open: a file literally
#     named "-q" is a valid config target to the managers (delta-8 3.2b/c)
# ---------------------------------------------------------------------------
prepare_case dash-userconfig
printf 'registry=https://evil.example\n' > "$CASE_PROJECT/-q"
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion@2.1.4 --ecosystem npm --npm-userconfig -q --gate install
if expect_status 10 "an argv userconfig named -q still floors"; then
  pass "an argv userconfig named -q still floors"
fi
: > "$CASE_DIR/stderr.log"
run_check \
  NPM_CONFIG_USERCONFIG=-q \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion@2.1.4 --ecosystem npm --gate install
if expect_status 10 "an env userconfig named -q still floors"; then
  pass "an env userconfig named -q still floors"
fi
prepare_case dash-pip-config
cat > "$CASE_PROJECT/-q" <<'CONF'
[global]
index-url = https://evil.example/simple
CONF
run_check \
  PIP_CONFIG_FILE=-q \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- requests@2.32.0 --ecosystem python --gate install
if expect_status 10 "a PIP_CONFIG_FILE named -q still floors"; then
  pass "a PIP_CONFIG_FILE named -q still floors"
fi

# ---------------------------------------------------------------------------
# 61. ConfigParser layouts pip accepts: indented base options and a --key
#     spelling (delta-8 finding 3.2c)
# ---------------------------------------------------------------------------
prepare_case pip-indented-option
cat > "$CASE_DIR/pip.conf" <<'CONF'
[global]
  index-url = https://indent.example/simple
CONF
run_check \
  PIP_CONFIG_FILE="$CASE_DIR/pip.conf" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- requests@2.32.0 --ecosystem python --gate install
if expect_status 10 "an indented base option is still an option, not a continuation"; then
  pass "an indented base option is still an option, not a continuation"
fi
prepare_case pip-dashdash-key
cat > "$CASE_DIR/pip.conf" <<'CONF'
[global]
--index-url = https://dashkey.example/simple
CONF
run_check \
  PIP_CONFIG_FILE="$CASE_DIR/pip.conf" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- requests@2.32.0 --ecosystem python --gate install
if expect_status 10 "a --index-url key spelling is normalized like pip does"; then
  pass "a --index-url key spelling is normalized like pip does"
fi
prepare_case pip-continuation-still-works
cat > "$CASE_DIR/pip.conf" <<'CONF'
[global]
find-links =
    https://evil.example/wheels
CONF
run_check \
  PIP_CONFIG_FILE="$CASE_DIR/pip.conf" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- requests@2.32.0 --ecosystem python --gate install
if expect_status 10 "deeper-indent continuations still attach to their option"; then
  pass "deeper-indent continuations still attach to their option"
fi

# ---------------------------------------------------------------------------
# 62. Writer/reader loop: the gate's stale-evidence reader honors the exact
#     source identity safe-audit stamped on the receipt.
#
# The receipt producer and the offline-fallback consumer live in different
# files (bin/safe-audit mark_install_known, lib/gate-lib.sh
# safe_gate_known_matches). Testing them apart let provenance be lost at the
# boundary: an unscoped receipt read as "default" let a custom-index receipt
# vouch for a default-index install (PR#30 delta finding 1). These cases run
# the REAL writer and then the REAL reader over the receipt it wrote.
# ---------------------------------------------------------------------------

# gate_known_rc <spec> <ecosystem> [VAR=value ...] -> prints the reader's rc.
# PROBE_SOURCE_SET stands in for the argv-derived source set the gate
# accumulates from --registry/--index-url/... selectors.
gate_known_rc() {
  local spec="$1" eco="$2"
  shift 2
  local rc=0
  (
    cd "$CASE_PROJECT" || exit 99
    env HOME="$CASE_HOME" SAFE_RUN_CONFIG_DIR="$CASE_RUN_CONFIG" \
      SAFE_AUDIT_PATH="$SAFE_AUDIT" "$@" \
      bash -c '
        set -u
        . "$0"
        SAFE_GATE_REGISTRY="${PROBE_SOURCE_SET:-}"
        safe_gate_known_matches "$1" "$2"
      ' "$ROOT/lib/gate-lib.sh" "$spec" "$eco"
  ) >/dev/null 2>&1 || rc=$?
  printf '%s' "$rc"
}

prepare_case gate-reader-default-source
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion@2.1.4 --ecosystem npm --gate install
if jq -e '.packages["npm:brace-expansion"].source == "implicit-default"' \
  "$CASE_RUN_CONFIG/install-known.json" >/dev/null 2>&1; then
  pass "default-source receipt is stamped implicit-default"
else
  cat "$CASE_RUN_CONFIG/install-known.json" >&2
  fail "default-source receipt is stamped implicit-default"
fi

if [[ "$(gate_known_rc brace-expansion@2.1.4 npm)" == "0" ]]; then
  pass "gate reuses a same-source receipt on timeout"
else
  fail "gate reuses a same-source receipt on timeout"
fi

# An env-configured registry the argv never mentions still changes identity.
if [[ "$(gate_known_rc brace-expansion@2.1.4 npm NPM_CONFIG_REGISTRY=https://evil.example)" != "0" ]]; then
  pass "NPM_CONFIG_REGISTRY invalidates a default-source receipt"
else
  fail "NPM_CONFIG_REGISTRY invalidates a default-source receipt"
fi

# A .npmrc registry the argv never mentions does too (project file wins).
printf 'registry = https://evil.example/\n' > "$CASE_PROJECT/.npmrc"
if [[ "$(gate_known_rc brace-expansion@2.1.4 npm)" != "0" ]]; then
  pass ".npmrc registry invalidates a default-source receipt"
else
  fail ".npmrc registry invalidates a default-source receipt"
fi
rm -f "$CASE_PROJECT/.npmrc"

# An explicit selector (what --registry would accumulate) invalidates it.
if [[ "$(gate_known_rc brace-expansion@2.1.4 npm PROBE_SOURCE_SET=https://evil.example)" != "0" ]]; then
  pass "an explicit source selector invalidates a default-source receipt"
else
  fail "an explicit source selector invalidates a default-source receipt"
fi

# The default registry spelled out explicitly is still the default identity.
if [[ "$(gate_known_rc brace-expansion@2.1.4 npm NPM_CONFIG_REGISTRY=https://registry.npmjs.org/)" == "0" ]]; then
  pass "an explicit npmjs.org registry normalizes to implicit-default"
else
  fail "an explicit npmjs.org registry normalizes to implicit-default"
fi

# ---------------------------------------------------------------------------
# 63. A literal selector spelled "default" is NOT the implicit-default sentinel
# ---------------------------------------------------------------------------
# A cargo --registry value is a NAME: a literal "default" maps to the
# opaque cargo-registry:default identity (PR6), which is what gets trusted,
# stamped, and re-derived by the reader — never conflated with the implicit
# default source.
prepare_case gate-reader-literal-default
printf '{"install": {"trusted_registries": ["cargo-registry:default"]}}\n' > "$CASE_RUN_CONFIG/config.json"
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- ripgrep@14.1.1 --ecosystem cargo --registry default --gate install
if jq -e '.packages["rust:ripgrep"].source == "explicit:cargo-registry:default"' \
  "$CASE_RUN_CONFIG/install-known.json" >/dev/null 2>&1; then
  pass "a literal 'default' selector is stamped explicit:cargo-registry:default"
else
  cat "$CASE_RUN_CONFIG/install-known.json" >&2 || true
  fail "a literal 'default' selector is stamped explicit:cargo-registry:default"
fi
if [[ "$(gate_known_rc ripgrep@14.1.1 cargo)" != "0" ]]; then
  pass "explicit:cargo-registry:default never satisfies an implicit-default request"
else
  fail "explicit:cargo-registry:default never satisfies an implicit-default request"
fi
if [[ "$(gate_known_rc ripgrep@14.1.1 cargo PROBE_SOURCE_SET=default)" == "0" ]]; then
  pass "the reader derives the same opaque identity from the same selector"
else
  fail "the reader derives the same opaque identity from the same selector"
fi

# ---------------------------------------------------------------------------
# 64. A custom-source receipt is reusable only from that same custom source
# ---------------------------------------------------------------------------
prepare_case gate-reader-custom-source
printf '{"install": {"trusted_registries": ["https://mirror.example"]}}\n' > "$CASE_RUN_CONFIG/config.json"
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion@2.1.4 --ecosystem npm --registry https://mirror.example --gate install
if [[ "$(gate_known_rc brace-expansion@2.1.4 npm PROBE_SOURCE_SET=https://mirror.example)" == "0" ]]; then
  pass "a custom-source receipt is reusable from the same source"
else
  cat "$CASE_RUN_CONFIG/install-known.json" >&2
  fail "a custom-source receipt is reusable from the same source"
fi
if [[ "$(gate_known_rc brace-expansion@2.1.4 npm)" != "0" ]]; then
  pass "a custom-source receipt never vouches for a default install"
else
  cat "$CASE_RUN_CONFIG/install-known.json" >&2
  fail "a custom-source receipt never vouches for a default install"
fi

# Round 5 canonicalizes each source element (trailing slashes stripped). Writer
# and reader must canonicalize identically or a trailing slash silently splits
# the identity — the exact boundary that broke before centralization.
prepare_case gate-reader-canonicalized-source
printf '{"install": {"trusted_registries": ["https://mirror.example"]}}\n' > "$CASE_RUN_CONFIG/config.json"
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion@2.1.4 --ecosystem npm --registry https://mirror.example/ --gate install
if jq -e '.packages["npm:brace-expansion"].source == "explicit:https://mirror.example"' \
  "$CASE_RUN_CONFIG/install-known.json" >/dev/null 2>&1; then
  pass "a trailing-slash selector is canonicalized on the receipt"
else
  cat "$CASE_RUN_CONFIG/install-known.json" >&2
  fail "a trailing-slash selector is canonicalized on the receipt"
fi
if [[ "$(gate_known_rc brace-expansion@2.1.4 npm PROBE_SOURCE_SET=https://mirror.example/)" == "0" ]]; then
  pass "the reader canonicalizes a trailing-slash selector the same way"
else
  fail "the reader canonicalizes a trailing-slash selector the same way"
fi

# ---------------------------------------------------------------------------
# PR6: cargo / composer / bun source derivation (installer-keyed selectors)
# ---------------------------------------------------------------------------

# 48. Cargo env pair (registry.default + registries.<name>.index) selects a
#     custom source: floors WARN, degrades resolution, records the URL.
prepare_case cargo-env-pair
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  CARGO_REGISTRY_DEFAULT=private \
  CARGO_REGISTRIES_PRIVATE_INDEX=https://private.example/index/ \
  -- okpkg@1.0.0 --ecosystem cargo
if expect_status 10 "cargo env pair floors WARN"; then
  pass "cargo env pair floors WARN"
fi
if grep -q 'custom source: https://private.example/index' "$OUT_FILE"; then
  pass "cargo env pair resolves the name to its index URL"
else
  cat "$OUT_FILE" >&2
  fail "cargo env pair resolves the name to its index URL"
fi

# An UNPINNED spec under the same selection must not resolve from crates.io:
# the default-registry lookup degrades to the package-level path.
prepare_case cargo-env-degrades-resolution
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/crates.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  CARGO_REGISTRY_DEFAULT=private \
  CARGO_REGISTRIES_PRIVATE_INDEX=https://private.example/index/ \
  -- okpkg --ecosystem cargo
if expect_status 10 "cargo env selection degrades resolution"; then
  pass "cargo env selection degrades resolution"
fi
if grep -q 'unresolved — auditing at package level' "$OUT_FILE"; then
  pass "cargo env selection audits at package level"
else
  cat "$OUT_FILE" >&2
  fail "cargo env selection audits at package level"
fi

# 49. A selected name with no env-defined index is the opaque identity
#     cargo-registry:<name>; trusting that exact token lifts the floor.
prepare_case cargo-opaque-name
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  CARGO_REGISTRY_DEFAULT=private \
  -- okpkg@1.0.0 --ecosystem cargo
if expect_status 10 "cargo name without index floors as opaque identity"; then
  pass "cargo name without index floors as opaque identity"
fi
if grep -q 'custom source: cargo-registry:private' "$OUT_FILE"; then
  pass "cargo opaque identity is cargo-registry:<name>"
else
  cat "$OUT_FILE" >&2
  fail "cargo opaque identity is cargo-registry:<name>"
fi
prepare_case cargo-opaque-trusted
printf '{"install": {"trusted_registries": ["cargo-registry:private"]}}\n' > "$CASE_RUN_CONFIG/config.json"
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  CARGO_REGISTRY_DEFAULT=private \
  -- okpkg@1.0.0 --ecosystem cargo
if expect_status 0 "a trusted cargo-registry token lifts the floor"; then
  pass "a trusted cargo-registry token lifts the floor"
fi

# 50. Defining is not selecting: an index variable alone is inert, and so
#     are the crates-io protocol/name forms (cargo hardcodes that source).
prepare_case cargo-defined-not-selected
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  CARGO_REGISTRIES_PRIVATE_INDEX=https://private.example/index/ \
  CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse \
  -- okpkg@1.0.0 --ecosystem cargo
if expect_status 0 "a defined-but-unselected cargo registry is inert"; then
  pass "a defined-but-unselected cargo registry is inert"
fi
prepare_case cargo-crates-io-selected
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  CARGO_REGISTRY_DEFAULT=crates-io \
  -- okpkg@1.0.0 --ecosystem cargo
if expect_status 0 "selecting crates-io by name is the default source"; then
  pass "selecting crates-io by name is the default source"
fi

# 51. Env-name mapping uppercases and maps dashes/dots to underscores
#     (cargo context/key.rs) — my-reg reads CARGO_REGISTRIES_MY_REG_INDEX.
prepare_case cargo-dashed-name
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  CARGO_REGISTRIES_MY_REG_INDEX=https://dashed.example/index \
  -- okpkg@1.0.0 --ecosystem cargo --registry my-reg
if grep -q 'custom source: https://dashed.example/index' "$OUT_FILE"; then
  pass "a dashed registry name maps to its underscore env index"
else
  cat "$OUT_FILE" >&2
  fail "a dashed registry name maps to its underscore env index"
fi

# 52. Composer: repositories in $COMPOSER_HOME/config.json floor the
#     verdict (array shape), a disabled packagist emits its sentinel
#     (object-map shape), and COMPOSER_AUTH alone floors nothing.
prepare_case composer-home-repos
mkdir -p "$CASE_DIR/composer-home"
printf '{"repositories": [{"type": "composer", "url": "https://repo.private.example/"}]}\n' \
  > "$CASE_DIR/composer-home/config.json"
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  COMPOSER_HOME="$CASE_DIR/composer-home" \
  -- vendor/pkg@2.5.0 --ecosystem composer
if expect_status 10 "composer global config repositories floor WARN"; then
  pass "composer global config repositories floor WARN"
fi
if grep -q 'custom source: https://repo.private.example' "$OUT_FILE"; then
  pass "composer repo URL is the recorded source"
else
  cat "$OUT_FILE" >&2
  fail "composer repo URL is the recorded source"
fi
prepare_case composer-packagist-disabled
mkdir -p "$CASE_DIR/composer-home"
printf '{"repositories": {"packagist.org": false}}\n' > "$CASE_DIR/composer-home/config.json"
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  COMPOSER_HOME="$CASE_DIR/composer-home" \
  -- vendor/pkg@2.5.0 --ecosystem composer
if expect_status 10 "a disabled packagist floors WARN"; then
  pass "a disabled packagist floors WARN"
fi
if grep -q 'custom source: local:packagist-disabled' "$OUT_FILE"; then
  pass "packagist disable emits its sentinel"
else
  cat "$OUT_FILE" >&2
  fail "packagist disable emits its sentinel"
fi
prepare_case composer-auth-only
mkdir -p "$CASE_DIR/composer-home"
printf '{}\n' > "$CASE_DIR/composer-home/config.json"
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packagist.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  COMPOSER_HOME="$CASE_DIR/composer-home" \
  COMPOSER_AUTH='{"http-basic": {"repo.example": {"username": "u", "password": "p"}}}' \
  -- vendor/pkg@2.5.0 --ecosystem composer
if expect_status 0 "COMPOSER_AUTH alone floors nothing"; then
  pass "COMPOSER_AUTH alone floors nothing"
fi

# A packagist-URL composer repo is composer's own auto-disable-and-replace
# shape: same endpoint, default source.
prepare_case composer-packagist-redefined
mkdir -p "$CASE_DIR/composer-home"
printf '{"repositories": [{"type": "composer", "url": "https://repo.packagist.org"}]}\n' \
  > "$CASE_DIR/composer-home/config.json"
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  COMPOSER_HOME="$CASE_DIR/composer-home" \
  -- vendor/pkg@2.5.0 --ecosystem composer
if expect_status 0 "a packagist-URL composer repo is the default source"; then
  pass "a packagist-URL composer repo is the default source"
fi

# 53. Bun: --installer bun makes BUN_CONFIG_REGISTRY the effective source —
#     floor + packument fetched FROM it; without the installer flag the
#     same variable is ignored (selectors key off the installer, delta-4
#     finding F4).
prepare_case bun-registry-selected
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_REGISTRY_URL_LOG="$CASE_DIR/urls.log" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  BUN_CONFIG_REGISTRY=https://bunreg.example \
  -- brace-expansion --ecosystem npm --installer bun
if expect_status 10 "bun registry floors WARN under --installer bun"; then
  pass "bun registry floors WARN under --installer bun"
fi
if grep -q '^https://bunreg.example/brace-expansion$' "$CASE_DIR/urls.log"; then
  pass "bun resolution fetches the packument from bun's registry"
else
  cat "$CASE_DIR/urls.log" >&2
  fail "bun resolution fetches the packument from bun's registry"
fi
prepare_case bun-var-ignored-for-npm
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_REGISTRY_URL_LOG="$CASE_DIR/urls.log" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  BUN_CONFIG_REGISTRY=https://bunreg.example \
  -- brace-expansion --ecosystem npm
if expect_status 0 "an npm install ignores bun's registry variable"; then
  pass "an npm install ignores bun's registry variable"
fi
if grep -q '^https://registry.npmjs.org/brace-expansion$' "$CASE_DIR/urls.log"; then
  pass "npm resolution stays on the npm registry"
else
  cat "$CASE_DIR/urls.log" >&2
  fail "npm resolution stays on the npm registry"
fi

# 54. Bun env precedence is upper-before-lower (the reverse of npm), and a
#     non-http(s) value is silently ignored, falling through the chain.
prepare_case bun-env-precedence
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  BUN_CONFIG_REGISTRY=https://bunreg.example \
  npm_config_registry=https://lower.example \
  -- brace-expansion@2.1.4 --ecosystem npm --installer bun
if grep -q 'custom source: https://bunreg.example' "$OUT_FILE"; then
  pass "BUN_CONFIG_REGISTRY beats the lowercase npm env form"
else
  cat "$OUT_FILE" >&2
  fail "BUN_CONFIG_REGISTRY beats the lowercase npm env form"
fi
prepare_case bun-nonhttp-ignored
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  BUN_CONFIG_REGISTRY=file:///srv/registry \
  npm_config_registry=https://lower.example \
  -- brace-expansion@2.1.4 --ecosystem npm --installer bun
if grep -q 'custom source: https://lower.example' "$OUT_FILE"; then
  pass "a non-http bun value is ignored and the chain falls through"
else
  cat "$OUT_FILE" >&2
  fail "a non-http bun value is ignored and the chain falls through"
fi

# 55. Bun's user npmrc lives under XDG_CONFIG_HOME when set (bun diverges
#     from npm here); npm keeps reading ~/.npmrc.
prepare_case bun-xdg-npmrc
mkdir -p "$CASE_HOME/xdg"
printf 'registry=https://xdgreg.example\n' > "$CASE_HOME/xdg/.npmrc"
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  XDG_CONFIG_HOME="$CASE_HOME/xdg" \
  -- brace-expansion@2.1.4 --ecosystem npm --installer bun
if grep -q 'custom source: https://xdgreg.example' "$OUT_FILE"; then
  pass "bun reads its user npmrc from XDG_CONFIG_HOME"
else
  cat "$OUT_FILE" >&2
  fail "bun reads its user npmrc from XDG_CONFIG_HOME"
fi
prepare_case npm-ignores-xdg-npmrc
fixture="$(osv_fixture_empty)"
mkdir -p "$CASE_HOME/xdg"
printf 'registry=https://xdgreg.example\n' > "$CASE_HOME/xdg/.npmrc"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  XDG_CONFIG_HOME="$CASE_HOME/xdg" \
  -- brace-expansion@2.1.4 --ecosystem npm
if expect_status 0 "npm does not read the XDG npmrc"; then
  pass "npm does not read the XDG npmrc"
fi

# 56. --installer is validated; the receipt records the resolved installer.
prepare_case installer-validated
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- okpkg@1.0.0 --ecosystem npm --installer frobnicator
if [[ "$STATUS" -ne 0 && -z "$(ls "$CASE_CHECKS_DIR" 2>/dev/null)" ]]; then
  pass "an unknown --installer dies before any receipt"
else
  printf 'status=%s checks=%s\n' "$STATUS" "$(ls "$CASE_CHECKS_DIR" 2>/dev/null)" >&2
  fail "an unknown --installer dies before any receipt"
fi
prepare_case installer-on-receipt
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  BUN_CONFIG_REGISTRY=https://bunreg.example \
  -- brace-expansion@2.1.4 --ecosystem npm --installer bun --json
if jq -e '.installer == "bun"' "$OUT_FILE" >/dev/null 2>&1; then
  pass "the receipt records the installer"
else
  cat "$OUT_FILE" >&2
  fail "the receipt records the installer"
fi
prepare_case installer-default-on-receipt
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/crates.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- okpkg@1.0.0 --ecosystem cargo --json
if jq -e '.installer == "cargo"' "$OUT_FILE" >/dev/null 2>&1; then
  pass "the ecosystem default installer lands on the receipt"
else
  cat "$OUT_FILE" >&2
  fail "the ecosystem default installer lands on the receipt"
fi

# 57a. Review round 1 regressions (findings 1, 2, 4) + the verified bun
#      scoped-vs-CLI semantics that survived challenge (finding 3 refuted).

# F1: a package repository whose `package` is an ARRAY of definitions must
# contribute every endpoint — never implicit-default.
prepare_case composer-package-array
mkdir -p "$CASE_DIR/composer-home"
printf '{"repositories":[{"type":"package","package":[{"name":"vendor/pkg","version":"1.0.0","dist":{"url":"https://evil.example/pkg.zip","type":"zip"}}]}]}\n' \
  > "$CASE_DIR/composer-home/config.json"
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  COMPOSER_HOME="$CASE_DIR/composer-home" \
  -- vendor/pkg@1.0.0 --ecosystem composer
if expect_status 10 "an array-form package repository floors WARN"; then
  pass "an array-form package repository floors WARN"
fi
if grep -q 'custom source: https://evil.example/pkg.zip' "$OUT_FILE"; then
  pass "the array-form package endpoint reaches the floor"
else
  cat "$OUT_FILE" >&2
  fail "the array-form package endpoint reaches the floor"
fi

# F2: an inline package with BOTH dist and source metadata contributes both
# endpoints (composer can fetch either: --prefer-source, dist fallback).
prepare_case composer-dist-and-source
mkdir -p "$CASE_DIR/composer-home"
printf '{"repositories":[{"type":"package","package":{"name":"vendor/pkg","version":"1.0.0","dist":{"url":"https://trusted.example/pkg.zip","type":"zip"},"source":{"url":"https://evil.example/repo.git","type":"git","reference":"main"}}}]}\n' \
  > "$CASE_DIR/composer-home/config.json"
printf '{"install": {"trusted_registries": ["https://trusted.example"]}}\n' > "$CASE_RUN_CONFIG/config.json"
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  COMPOSER_HOME="$CASE_DIR/composer-home" \
  -- vendor/pkg@1.0.0 --ecosystem composer
if expect_status 10 "an untrusted source URL floors WARN despite a trusted dist"; then
  pass "an untrusted source URL floors WARN despite a trusted dist"
fi
if grep -q 'https://evil.example/repo.git' "$OUT_FILE"; then
  pass "both dist and source endpoints reach the floor"
else
  cat "$OUT_FILE" >&2
  fail "both dist and source endpoints reach the floor"
fi

# F4: an explicit crates-io selection overrides an ambient registry.default
# — cargo ignores the env key whenever argv selected, even the default.
ES_ARGS=(okpkg --ecosystem cargo --registry crates-io)
if [[ "$(run_es CARGO_REGISTRY_DEFAULT=private)" == "implicit-default" ]]; then
  pass "explicit crates-io overrides an ambient registry.default"
else
  printf 'got: %s\n' "$(run_es CARGO_REGISTRY_DEFAULT=private)" >&2
  fail "explicit crates-io overrides an ambient registry.default"
fi
prepare_case cargo-argv-beats-env-default
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/crates.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  CARGO_REGISTRY_DEFAULT=private \
  -- okpkg@1.0.0 --ecosystem cargo --registry crates-io
if expect_status 0 "explicit crates-io under an ambient default gates GO"; then
  pass "explicit crates-io under an ambient default gates GO"
fi

# F3 (refuted — semantics pinned): bun's scoped npmrc registry beats the
# generic CLI --registry, exactly as in npm: bun's CLI flag rewrites only
# the default scope (pmopt.rs `cli.registry` -> `self.scope`) and the
# scoped map is consulted first. The packument for a scoped package must
# come from the scoped registry even with a CLI selector present.
prepare_case bun-scoped-beats-cli
printf '@demo:registry=https://scoped.example\n' > "$CASE_PROJECT/.npmrc"
cat > "$FIXTURES/scoped-packument.json" <<'JSON'
{"dist-tags": {"latest": "1.0.0"}, "versions": {"1.0.0": {}}}
JSON
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/scoped-packument.json" \
  MOCK_REGISTRY_URL_LOG="$CASE_DIR/urls.log" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- @demo/pkg --ecosystem npm --installer bun --registry https://cli.example
if grep -q '^https://scoped.example/@demo%2Fpkg$' "$CASE_DIR/urls.log"; then
  pass "bun scoped npmrc registry beats the CLI selector"
else
  cat "$CASE_DIR/urls.log" >&2
  fail "bun scoped npmrc registry beats the CLI selector"
fi
rm -f "$CASE_PROJECT/.npmrc"

# 58. Contract-drift fixes (contract-test findings): the socket call is
#     wall-clock bounded on a DIRECT check; a direct WARN/BLOCK check emits
#     the same next-step hints the gate does; a long affecting list says
#     how many IDs it withheld.
prepare_case socket-hang-bounded
fixture="$(osv_fixture_empty)"
hang_start=$SECONDS
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=hang \
  SAFE_AUDIT_SOCKET_TIMEOUT=2 \
  -- brace-expansion@2.1.4 --ecosystem npm
hang_elapsed=$((SECONDS - hang_start))
if expect_status 10 "a wedged socket CLI degrades to WARN"; then
  pass "a wedged socket CLI degrades to WARN"
fi
if (( hang_elapsed < 30 )); then
  pass "the socket call is wall-clock bounded ($hang_elapsed s)"
else
  fail "the socket call is wall-clock bounded ($hang_elapsed s)"
fi
if grep -q 'WARN (socket score timed out)' "$OUT_FILE" \
   && grep -q 'socket score timed out after 2s' "$ERR_FILE"; then
  pass "the timeout reads as legible infrastructure breakage"
else
  cat "$OUT_FILE" "$ERR_FILE" >&2
  fail "the timeout reads as legible infrastructure breakage"
fi
if grep -q 'infrastructure failure, NOT a package finding' "$ERR_FILE"; then
  pass "a direct check carries the infra hint lines"
else
  cat "$ERR_FILE" >&2
  fail "a direct check carries the infra hint lines"
fi

# F1 (PR7 review): a vault-injected RETRY that hits the leash keeps the
# timeout diagnosis instead of degrading to "socket command failed".
prepare_case socket-retry-hang
mkdir -p "$CASE_HOME/.local/bin" "$CASE_HOME/.config/setup-new-machines/bw-env.d"
cat > "$CASE_HOME/.local/bin/bw-env-run" <<'BWMOCK'
#!/usr/bin/env bash
while [[ $# -gt 0 && "$1" != "--" ]]; do shift; done
shift
exec "$@"
BWMOCK
chmod +x "$CASE_HOME/.local/bin/bw-env-run"
: > "$CASE_HOME/.config/setup-new-machines/bw-env.d/socket.env"
fixture="$(osv_fixture_empty)"
retry_start=$SECONDS
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=auth-then-hang \
  MOCK_SOCKET_STATE="$CASE_DIR/socket-called-once" \
  SOCKET_SECURITY_API_TOKEN=stale-ambient-token \
  SAFE_AUDIT_SOCKET_TIMEOUT=2 \
  -- brace-expansion@2.1.4 --ecosystem npm
retry_elapsed=$((SECONDS - retry_start))
if expect_status 10 "a hanging vault retry degrades to WARN"; then
  pass "a hanging vault retry degrades to WARN"
fi
if (( retry_elapsed < 30 )); then
  pass "the vault retry is wall-clock bounded ($retry_elapsed s)"
else
  fail "the vault retry is wall-clock bounded ($retry_elapsed s)"
fi
if grep -q 'WARN (socket score timed out)' "$OUT_FILE"; then
  pass "the retry timeout keeps its diagnosis"
else
  cat "$OUT_FILE" >&2
  fail "the retry timeout keeps its diagnosis"
fi

# F2 (PR7 review): with no timeout binary on PATH the socket call is not
# started at all — a legible skipped-coverage WARN, never a hang.
NOTIMEOUT_BIN="$TEST_ROOT/no-timeout-bin"
mkdir -p "$NOTIMEOUT_BIN"
for _b in /usr/bin/* /bin/*; do
  [[ -e "$NOTIMEOUT_BIN/$(basename "$_b")" ]] && continue
  ln -s "$_b" "$NOTIMEOUT_BIN/$(basename "$_b")" 2>/dev/null || true
done
rm -f "$NOTIMEOUT_BIN/timeout"
prepare_case socket-no-timeout-binary
fixture="$(osv_fixture_empty)"
nt_start=$SECONDS
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=hang \
  PATH="$MOCKBIN:$NOTIMEOUT_BIN" \
  -- brace-expansion@2.1.4 --ecosystem npm
nt_elapsed=$((SECONDS - nt_start))
if expect_status 10 "no timeout binary degrades to WARN"; then
  pass "no timeout binary degrades to WARN"
fi
if (( nt_elapsed < 30 )); then
  pass "the unboundable call is never started ($nt_elapsed s)"
else
  fail "the unboundable call is never started ($nt_elapsed s)"
fi
if grep -q 'WARN (socket score skipped: cannot be bounded)' "$OUT_FILE" \
   && jq -e '.socket.note | test("no timeout binary")' "$(ls "$CASE_CHECKS_DIR"/*.json | head -1)" >/dev/null 2>&1; then
  pass "the skipped score names its cause"
else
  cat "$OUT_FILE" >&2
  fail "the skipped score names its cause"
fi

prepare_case direct-warn-hints
fixture="$(osv_fixture_affecting_moderate)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_OSV_MATCH_VERSION=2.1.4 \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion@2.1.4 --ecosystem npm
if expect_status 10 "direct advisory WARN exits 10"; then
  pass "direct advisory WARN exits 10"
fi
if grep -q 'to allow this exact version: safe run host-allow add brace-expansion@2.1.4' "$ERR_FILE"; then
  pass "a direct WARN check emits the pinned allow hint"
else
  cat "$ERR_FILE" >&2
  fail "a direct WARN check emits the pinned allow hint"
fi

prepare_case affecting-list-count
cat > "$FIXTURES/osv-affect-many.json" <<'JSON'
{"vulns": [
  {"id": "GHSA-MANY-0001", "database_specific": {"severity": "MODERATE"},
   "affected": [{"package": {"ecosystem": "npm", "name": "brace-expansion"},
     "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]},
  {"id": "GHSA-MANY-0002", "database_specific": {"severity": "MODERATE"},
   "affected": [{"package": {"ecosystem": "npm", "name": "brace-expansion"},
     "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]},
  {"id": "GHSA-MANY-0003", "database_specific": {"severity": "MODERATE"},
   "affected": [{"package": {"ecosystem": "npm", "name": "brace-expansion"},
     "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]},
  {"id": "GHSA-MANY-0004", "database_specific": {"severity": "MODERATE"},
   "affected": [{"package": {"ecosystem": "npm", "name": "brace-expansion"},
     "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]},
  {"id": "GHSA-MANY-0005", "database_specific": {"severity": "MODERATE"},
   "affected": [{"package": {"ecosystem": "npm", "name": "brace-expansion"},
     "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]}
]}
JSON
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$FIXTURES/osv-affect-many.json" \
  MOCK_OSV_MATCH_VERSION=2.1.4 \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion@2.1.4 --ecosystem npm
if grep -q '+2 more' "$OUT_FILE"; then
  pass "a truncated affecting list names the withheld count"
else
  cat "$OUT_FILE" >&2
  fail "a truncated affecting list names the withheld count"
fi

# 57. Plumbing parity: the identity readers derive the same PR6 sources.
ES_ARGS=(okpkg --ecosystem cargo)
if [[ "$(run_es CARGO_REGISTRY_DEFAULT=private)" == "explicit:cargo-registry:private" ]]; then
  pass "plumbing: cargo env selection becomes the opaque identity"
else
  printf 'got: %s\n' "$(run_es CARGO_REGISTRY_DEFAULT=private)" >&2
  fail "plumbing: cargo env selection becomes the opaque identity"
fi
ES_ARGS=(brace-expansion --ecosystem npm --installer bun)
if [[ "$(run_es BUN_CONFIG_REGISTRY=https://bunreg.example)" == "explicit:https://bunreg.example" ]]; then
  pass "plumbing: bun installer identity follows bun's registry"
else
  printf 'got: %s\n' "$(run_es BUN_CONFIG_REGISTRY=https://bunreg.example)" >&2
  fail "plumbing: bun installer identity follows bun's registry"
fi
ES_ARGS=(brace-expansion --ecosystem npm)
if [[ "$(run_es BUN_CONFIG_REGISTRY=https://bunreg.example)" == "implicit-default" ]]; then
  pass "plumbing: without the installer, bun's variable is invisible"
else
  printf 'got: %s\n' "$(run_es BUN_CONFIG_REGISTRY=https://bunreg.example)" >&2
  fail "plumbing: without the installer, bun's variable is invisible"
fi

# ---------------------------------------------------------------------------
# 58. Predictable override subset: a single top-level exact-version override
#     with no conflicting direct dep resolves without a fetch (the cdk8s
#     transitive-pin shape from the CVE catch-22 note).
# ---------------------------------------------------------------------------
prepare_case override-pin-resolves
printf '{"devDependencies": {"tsx": "^4.19.0"}, "overrides": {"brace-expansion": "2.1.3"}}\n' > "$CASE_PROJECT/package.json"
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion --ecosystem npm --op update --gate install
if expect_status 0 "a lone top-level exact override resolves instead of degrading"; then
  pass "a lone top-level exact override resolves instead of degrading"
fi
if expect_grep "$OUT_FILE" 'override-pin' "override resolution names its method"; then
  pass "override resolution names its method"
fi
if expect_grep "$OUT_FILE" '2\.1\.3' "override resolution audits the pinned version"; then
  pass "override resolution audits the pinned version"
fi

# ---------------------------------------------------------------------------
# 59. An override RANGE is not the predictable subset: still degrades.
# ---------------------------------------------------------------------------
prepare_case override-range-degrades
printf '{"overrides": {"brace-expansion": "^2.0.0"}}\n' > "$CASE_PROJECT/package.json"
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion --ecosystem npm --op update --gate install
if expect_status 10 "an override range still degrades resolution"; then
  pass "an override range still degrades resolution"
fi
if expect_grep "$OUT_FILE" 'version unresolved' "override-range degrade is explicit"; then
  pass "override-range degrade is explicit"
fi

# ---------------------------------------------------------------------------
# 60. An explicit requested range beside an override pin still degrades:
#     the range/override interplay is back in unpredictable territory.
# ---------------------------------------------------------------------------
prepare_case override-pin-requested-range
printf '{"overrides": {"brace-expansion": "2.1.3"}}\n' > "$CASE_PROJECT/package.json"
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- 'brace-expansion@^2.0.0' --ecosystem npm --gate install
if expect_status 10 "a requested range beside an override pin degrades"; then
  pass "a requested range beside an override pin degrades"
fi

# ---------------------------------------------------------------------------
# 61. Resolved version declares install scripts, no scripts grant: GO with
#     the operator hint (scripts are skipped, name the grant command) and
#     has_install_script recorded in the receipt.
# ---------------------------------------------------------------------------
cat > "$FIXTURES/packument-installscript.json" <<'JSON'
{
  "dist-tags": {"latest": "0.5.0"},
  "versions": {"0.4.0": {"hasInstallScript": true}, "0.5.0": {"hasInstallScript": true}}
}
JSON
prepare_case install-script-hint
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument-installscript.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- opencode-ai --ecosystem npm --gate install
if expect_status 0 "install-script package still passes on GO"; then
  pass "install-script package still passes on GO"
fi
if expect_grep "$ERR_FILE" 'declares install scripts.*SKIPPED' "hint names the skip"; then
  pass "hint names the skip"
fi
if expect_grep "$ERR_FILE" 'safe run scripts-allow add opencode-ai@0\.5\.0' "hint carries the exact grant command"; then
  pass "hint carries the exact grant command"
fi
if [[ "$(jq -r '.has_install_script' "$CASE_CHECKS_DIR"/*.json 2>/dev/null | head -1)" == "true" ]]; then
  pass "receipt records has_install_script"
else
  fail "receipt records has_install_script"
fi

# ---------------------------------------------------------------------------
# 62. Same package with a matching scripts grant: no hint (the gate will
#     inject the reviewed policy; nagging a granted identity is noise).
# ---------------------------------------------------------------------------
prepare_case install-script-granted
printf '{"packages":{"opencode-ai":{"version":"0.5.0","ecosystem":"npm"}}}\n' \
  > "$CASE_RUN_CONFIG/scripts-allow.json"
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument-installscript.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- opencode-ai --ecosystem npm --gate install
if expect_status 0 "granted install-script package passes"; then
  pass "granted install-script package passes"
fi
if expect_no_grep "$ERR_FILE" 'scripts-allow add' "no hint when the grant matches"; then
  pass "no hint when the grant matches"
fi

# ---------------------------------------------------------------------------
# 63. No install scripts declared: no hint, receipt false.
# ---------------------------------------------------------------------------
prepare_case no-install-script
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion@beta --ecosystem npm --gate install
if expect_status 0 "scriptless package passes" ; then
  pass "scriptless package passes"
fi
if expect_no_grep "$ERR_FILE" 'declares install scripts' "no hint without scripts"; then
  pass "no hint without scripts"
fi

# ---------------------------------------------------------------------------
# 64. Socket receives purl types, not safe ecosystem names: "python" must be
#     scored as pkg:pypi (the API 400s on pkg:python), npm stays npm.
# ---------------------------------------------------------------------------
prepare_case socket-purl-type
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  MOCK_SOCKET_ARGS_LOG="$CASE_DIR/socket-args.log" \
  -- requests@2.32.0 --ecosystem python --registry https://pypi.org/simple --gate install
if expect_status 0 "python check with socket ok gates GO"; then
  pass "python check with socket ok gates GO"
fi
if expect_grep "$CASE_DIR/socket-args.log" '^package score pypi requests@2\.32\.0' "socket is invoked with purl type pypi"; then
  pass "socket is invoked with purl type pypi"
fi

prepare_case socket-purl-npm
fixture="$(osv_fixture_empty)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  MOCK_SOCKET_ARGS_LOG="$CASE_DIR/socket-args.log" \
  -- brace-expansion@2.1.4 --ecosystem npm --gate install
if expect_grep "$CASE_DIR/socket-args.log" '^package score npm brace-expansion@2\.1\.4' "npm purl type is unchanged"; then
  pass "npm purl type is unchanged"
fi

# ---------------------------------------------------------------------------
printf '\n%d passed, %d failed\n' "$PASS_COUNT" "$FAIL_COUNT"
[[ "$FAIL_COUNT" -eq 0 ]]
