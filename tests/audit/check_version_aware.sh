#!/usr/bin/env bash
# Version-aware `safe audit check` suite: target-version resolution, per-version
# OSV advisory matching, install-gate mode, install-known recording, and the
# pinned (never @latest) refusal hints. Fully offline: curl and socket are
# mocked on PATH.

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

# --- mock curl: serves the registry packument and OSV query from fixtures ----
cat > "$MOCKBIN/curl" <<'MOCK'
#!/usr/bin/env bash
url=""
outfile=""
args=("$@")
i=0
while (( i < ${#args[@]} )); do
  a="${args[$i]}"
  case "$a" in
    -H|-d|--max-time) i=$((i + 2)); continue ;;
    -o) outfile="${args[$((i + 1))]}"; i=$((i + 2)); continue ;;
    http*://*) url="$a" ;;
  esac
  i=$((i + 1))
done
case "$url" in
  *api.osv.dev*)
    [[ "${MOCK_OSV_STATUS:-0}" == "0" ]] || exit 22
    cat "${MOCK_OSV_FIXTURE:?}"
    ;;
  *)
    [[ "${MOCK_REGISTRY_STATUS:-0}" == "0" ]] || exit 22
    if [[ -n "$outfile" ]]; then
      cat "${MOCK_REGISTRY_FIXTURE:?}" > "$outfile"
    else
      cat "${MOCK_REGISTRY_FIXTURE:?}"
    fi
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
  "dist-tags": {"latest": "5.0.1", "next": "6.0.0-rc.1"},
  "versions": {
    "1.1.11": {}, "1.1.12": {},
    "2.0.0": {}, "2.0.1": {}, "2.1.3": {}, "2.1.4": {},
    "3.0.0-rc.1": {},
    "4.0.0": {}, "5.0.0": {}, "5.0.1": {}
  }
}
JSON

# Advisory set:
#  - GHSA-REMEDIATED: moderate, affects [2.0.0, 2.0.2)  -> fixed below 2.1.4
#  - GHSA-OLDLINE:    high, affects [1.0.0, 1.9.9)      -> hits the 1.x line only
osv_fixture_clean_for_214() {
  cat > "$FIXTURES/osv-clean-214.json" <<'JSON'
{"vulns": [
  {"id": "GHSA-REMEDIATED", "database_specific": {"severity": "MODERATE"},
   "affected": [{"package": {"ecosystem": "npm", "name": "brace-expansion"},
     "ranges": [{"type": "SEMVER", "events": [{"introduced": "2.0.0"}, {"fixed": "2.0.2"}]}]}]},
  {"id": "GHSA-OLDLINE", "database_specific": {"severity": "HIGH"},
   "affected": [{"package": {"ecosystem": "npm", "name": "brace-expansion"},
     "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.9.9"}]}]}]}
]}
JSON
  printf '%s' "$FIXTURES/osv-clean-214.json"
}

#  - GHSA-AFFECTS-MOD: moderate, affects [2.0.0, 2.9.9) -> hits 2.1.4
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

#  - GHSA-AFFECTS-CRIT: critical, open range from 0 -> hits everything
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

#  - GHSA-GIT-ONLY: low, only a GIT range -> unparseable, trusted on exact path
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

osv_fixture_empty() {
  printf '{"vulns": []}' > "$FIXTURES/osv-empty.json"
  printf '%s' "$FIXTURES/osv-empty.json"
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
# 1. Exact clean version, socket ok -> GO, install-known recorded (gate mode)
# ---------------------------------------------------------------------------
prepare_case exact-clean
fixture="$(osv_fixture_clean_for_214)"
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
if expect_grep "$OUT_FILE" 'this version fixes: .*GHSA-REMEDIATED \(fixed 2\.0\.2\)' "remediation notice names the fixed advisory"; then
  pass "remediation notice names the fixed advisory"
fi

# ---------------------------------------------------------------------------
# 2. npm update shape: unversioned + --op update resolves in-range (2.1.4, not 5.x)
# ---------------------------------------------------------------------------
prepare_case update-in-range
printf '{"dependencies": {"brace-expansion": "^2.0.0"}}\n' > "$CASE_PROJECT/package.json"
cat > "$CASE_PROJECT/package-lock.json" <<'JSON'
{"packages": {"node_modules/minimatch": {"dependencies": {"brace-expansion": "^2.0.1"}}}}
JSON
fixture="$(osv_fixture_clean_for_214)"
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
# 3. Advisory affecting the resolved version: critical -> BLOCK (gate exit 20)
# ---------------------------------------------------------------------------
prepare_case affect-critical
fixture="$(osv_fixture_affecting_critical)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion@2.1.4 --ecosystem npm --gate install
if expect_status 20 "critical advisory on resolved version blocks"; then
  pass "critical advisory on resolved version blocks"
fi

# ---------------------------------------------------------------------------
# 4a. Affecting moderate -> WARN refusal with pinned host-allow hint
# ---------------------------------------------------------------------------
prepare_case affect-moderate
fixture="$(osv_fixture_affecting_moderate)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
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
# 4b. Same, but a pinned host-allow entry matching the resolved version allows
# ---------------------------------------------------------------------------
prepare_case host-allow-resolved
printf '{"dependencies": {"brace-expansion": "^2.0.0"}}\n' > "$CASE_PROJECT/package.json"
printf '{"packages": {"brace-expansion": {"version": "2.1.4", "ecosystem": "npm", "added": "2026-07-31", "reason": "test"}}}\n' \
  > "$CASE_RUN_CONFIG/host-allow.json"
fixture="$(osv_fixture_affecting_moderate)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion --ecosystem npm --op update --gate install
if expect_status 0 "pinned host-allow entry matches the RESOLVED version of an unversioned spec"; then
  pass "pinned host-allow entry matches the RESOLVED version of an unversioned spec"
fi
if expect_grep "$ERR_FILE" 'host-allow entry brace-expansion@2\.1\.4 matches' "override notice names the pin"; then
  pass "override notice names the pin"
fi

# ---------------------------------------------------------------------------
# 5a. Socket unavailable, OSV clean -> refusal is legible as infrastructure
# ---------------------------------------------------------------------------
prepare_case socket-down
rm -f "$MOCKBIN/socket.hidden"
mv "$MOCKBIN/socket" "$MOCKBIN/socket.hidden"
fixture="$(osv_fixture_clean_for_214)"
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
# 5b. Operator opt-in tolerate knob allows socket-outage WARN when OSV is clean
# ---------------------------------------------------------------------------
prepare_case socket-tolerated
printf '{"install": {"auto_allow_tolerate": ["socket_unavailable"]}}\n' > "$CASE_RUN_CONFIG/config.json"
mv "$MOCKBIN/socket" "$MOCKBIN/socket.hidden"
fixture="$(osv_fixture_clean_for_214)"
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

# ---------------------------------------------------------------------------
# 6. Unresolvable range (||) -> degraded WARN with pin guidance
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
if expect_grep "$OUT_FILE" 'version unresolved' "unresolved path is explicit in the check output"; then
  pass "unresolved path is explicit in the check output"
fi

# ---------------------------------------------------------------------------
# 7. Registry failure -> degraded WARN, never GO
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
# 8. OSV outage with a resolved version -> WARN (fail closed, was fail-open)
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
# 9. GIT-only advisory on the exact path is trusted as affecting (WARN)
# ---------------------------------------------------------------------------
prepare_case git-only
fixture="$(osv_fixture_git_only)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion@2.1.4 --ecosystem npm --gate install
if expect_status 10 "unparseable advisory ranges stay WARN on the exact path"; then
  pass "unparseable advisory ranges stay WARN on the exact path"
fi

# ---------------------------------------------------------------------------
# 10. Non-gate mode is unchanged for consumers: WARN -> exit 10, GO -> 0
# ---------------------------------------------------------------------------
prepare_case plain-warn
fixture="$(osv_fixture_affecting_moderate)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
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
fixture="$(osv_fixture_clean_for_214)"
run_check \
  MOCK_REGISTRY_FIXTURE="$FIXTURES/packument.json" \
  MOCK_OSV_FIXTURE="$fixture" \
  MOCK_SOCKET_MODE=ok \
  -- brace-expansion@2.1.4 --ecosystem npm --json
if expect_status 0 "plain check keeps GO=0"; then
  pass "plain check keeps GO=0"
fi
if jq -e '.verdict == "GO" and .resolution.status == "ok" and (.osv.classification.remediated | length) == 2' "$OUT_FILE" >/dev/null 2>&1; then
  pass "check --json exposes resolution and classification"
else
  cat "$OUT_FILE" >&2
  fail "check --json exposes resolution and classification"
fi

# ---------------------------------------------------------------------------
printf '\n%d passed, %d failed\n' "$PASS_COUNT" "$FAIL_COUNT"
[[ "$FAIL_COUNT" -eq 0 ]]
