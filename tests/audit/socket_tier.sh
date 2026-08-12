#!/usr/bin/env bash
# Socket primary behavioral-tier and bounded-cache regression suite. Fully
# offline: the Socket CLI and OSV are mocked on PATH. No live account state or
# token value is read.

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

cat > "$MOCKBIN/curl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
outfile="" url="" data=""
args=("$@")
for ((i = 0; i < ${#args[@]}; i++)); do
  case "${args[$i]}" in
    -o) outfile="${args[$((i + 1))]}"; i=$((i + 1)) ;;
    -d) data="${args[$((i + 1))]}"; i=$((i + 1)) ;;
    http*://*) url="${args[$i]}" ;;
  esac
done
emit() { if [[ -n "$outfile" ]]; then cat > "$outfile"; else cat; fi; }
case "$url" in
  *api.osv.dev*)
    if [[ "${MOCK_COOLDOWN_FIX:-0}" == "1" && "$data" != *'"version"'* ]]; then
      printf '%s\n' '{"vulns":[{"id":"GHSA-FIXED","database_specific":{"severity":"HIGH"},"affected":[{"package":{"ecosystem":"npm","name":"fixture"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.0"}]}]}]}]}' | emit
    else
      printf '{"vulns":[]}\n' | emit
    fi
    ;;
  *)
    if [[ "${MOCK_RELEASE_FRESH:-0}" == "1" ]]; then
      printf '{"versions":{"1.0.0":{}},"time":{"1.0.0":"%s"}}\n' "$(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)" | emit
    elif [[ "${MOCK_MULTI_VERSION:-0}" == "1" ]]; then
      # Two majors so two distinct project constraints resolve to two
      # distinct installable versions (RESOLVED_VERSIONS length 2).
      printf '{"versions":{"1.0.0":{},"2.0.0":{}},"dist-tags":{"latest":"2.0.0"},"time":{"1.0.0":"2020-01-01T00:00:00Z","2.0.0":"2020-06-01T00:00:00Z"}}\n' | emit
    else
      printf '{"versions":{"1.0.0":{}},"time":{"1.0.0":"2020-01-01T00:00:00Z"}}\n' | emit
    fi
    ;;
esac
MOCK
chmod +x "$MOCKBIN/curl"

cat > "$MOCKBIN/socket" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
[[ -n "${MOCK_SOCKET_LOG:-}" ]] && printf 'call\n' >> "$MOCK_SOCKET_LOG"
# Mirrors the real package-score envelope: `transitively` is an OBJECT
# describing the dependency tree (dependencyCount/alerts/score/...), not an
# array. Pinned live in tests/live/socket_envelope.sh — a fixture that invents
# a shape tests a fiction, which is exactly how an every-response-invalid bug
# passed 50 green cases once already.
envelope() {
  local score="$1" alerts="$2"
  printf '{"ok":true,"data":{"self":{"score":{"overall":%s},"alerts":%s},"transitively":{"dependencyCount":0,"alerts":[],"score":{"overall":100}}}}\n' "$score" "$alerts"
}
# The scored purl is the last non-flag argument: `... score npm name@version --json`.
scored_version=""
for arg in "$@"; do
  case "$arg" in *@*) scored_version="${arg##*@}" ;; esac
done
case "${MOCK_SOCKET_MODE:-clean}" in
  clean) envelope 95 '[]' ;;
  # Primary (1.0.0) is clean, the sibling major (2.0.0) is malicious: the exact
  # shape of the coverage gap review F1 found after GuardDog's multi-version
  # scan was removed.
  sibling-malware)
    if [[ "$scored_version" == "2.0.0" ]]; then
      envelope 95 '[{"name":"malware","severity":"critical","category":"supplyChainRisk","example":"npm/fixture@2.0.0"}]'
    else
      envelope 95 '[]'
    fi
    ;;
  sibling-error)
    if [[ "$scored_version" == "2.0.0" ]]; then
      printf '{"message":"mock failure"}\n'; exit 1
    else
      envelope 95 '[]'
    fi
    ;;
  # A critical alert in a category safe does not map: must never reach PASS.
  unknown-category) envelope 95 '[{"name":"future-risk","severity":"critical","category":"newCategory","example":"npm/fixture@1.0.0"}]' ;;
  malware) envelope 95 '[{"name":"malware","severity":"critical","category":"supplyChainRisk","example":"npm/fixture@1.0.0"}]' ;;
  critical-cve) envelope 95 '[{"name":"cve","severity":"critical","category":"vulnerability","example":"npm/fixture@1.0.0"}]' ;;
  high) envelope 95 '[{"name":"risky","severity":"high","category":"supplyChainRisk","example":"npm/fixture@1.0.0"}]' ;;
  low) envelope 40 '[]' ;;
  bad-severity) envelope 95 '[{"name":"odd","severity":"unknown","category":"supplyChainRisk","example":"npm/fixture@1.0.0"}]' ;;
  missing-name) envelope 95 '[{"severity":"critical","category":"supplyChainRisk"}]' ;;
  missing-category) envelope 95 '[{"name":"incomplete","severity":"critical"}]' ;;
  bad-score) printf '{"ok":true,"data":{"self":{"score":{"overall":"95"},"alerts":[]}}}\n' ;;
  missing-self) printf '{"ok":true,"data":{"transitively":{"dependencyCount":0}}}\n' ;;
  non-object-alert) envelope 95 '[true]' ;;
  rate) printf '{"message":"Too Many Requests","cause":"429"}\n'; exit 1 ;;
  # Carries account context the way a real provider error body can. The
  # sentinel must reach no receipt, cache, stdout, or stderr (review F5).
  auth-leaky) printf '{"message":"Unauthorized for operator@example.com","cause":"account SENTINELACCT9137"}\n'; exit 1 ;;
  pending) sleep 5 ;;
  *) printf '{"message":"mock failure"}\n'; exit 1 ;;
esac
MOCK
chmod +x "$MOCKBIN/socket"

prepare_case() {
  CASE="$TEST_ROOT/$1"
  CASE_RUN_CONFIG="$CASE/run"
  CASE_AUDIT_CONFIG="$CASE/audit"
  CASE_DATA="$CASE/data"
  CASE_CACHE="$CASE/cache"
  CASE_HOME="$CASE/home"
  CASE_OUT="$CASE/out.json"
  CASE_ERR="$CASE/err.txt"
  CASE_LOG="$CASE/socket.log"
  mkdir -p "$CASE_RUN_CONFIG" "$CASE_AUDIT_CONFIG" "$CASE_DATA" "$CASE_HOME"
  printf '{"install":{"cooldown_days":0,"socket":{"mode":"auto","cache_ttl_days":7}}}\n' > "$CASE_RUN_CONFIG/config.json"
  printf '{"packages":{}}\n' > "$CASE_RUN_CONFIG/blocked.json"
  : > "$CASE_LOG"
}

run_check() {
  local mode="$1"
  shift
  local -a extra_env=()
  while (( $# > 0 )) && [[ "$1" == *=* ]]; do
    extra_env+=("$1")
    shift
  done
  set +e
  env -u SOCKET_SECURITY_API_TOKEN \
    HOME="$CASE_HOME" \
    PATH="$MOCKBIN:/usr/bin:/bin" \
    SAFE_AUDIT_CONFIG_DIR="$CASE_AUDIT_CONFIG" \
    SAFE_AUDIT_DATA_DIR="$CASE_DATA/audit" \
    SAFE_RUN_CONFIG_DIR="$CASE_RUN_CONFIG" \
    SAFE_AUDIT_SOCKET_CACHE_DIR="$CASE_CACHE" \
    MOCK_SOCKET_LOG="$CASE_LOG" \
    MOCK_SOCKET_MODE="$mode" \
    "${extra_env[@]}" \
    "$SAFE_AUDIT" check fixture@1.0.0 --ecosystem npm --json "$@" > "$CASE_OUT" 2> "$CASE_ERR"
  CHECK_RC=$?
  set -e
}

expect_rc() {
  local expected="$1" label="$2"
  if [[ "$CHECK_RC" == "$expected" ]]; then pass "$label"; else fail "$label (got $CHECK_RC, expected $expected)"; fi
}

expect_json() {
  local filter="$1" label="$2"
  if jq -e "$filter" "$CASE_OUT" >/dev/null 2>&1; then pass "$label"; else fail "$label"; fi
}

socket_calls() { wc -l < "$CASE_LOG" | tr -d '[:space:]'; }
cache_entries() { find "$CASE_CACHE" -type f -name '*.json' 2>/dev/null | wc -l | tr -d '[:space:]'; }

# A primary clean scan is called on auto, and its second exact request replays
# a validated cache result instead of consuming another service request.
prepare_case cache-hit
run_check clean
expect_rc 0 'clean Socket score permits GO'
expect_json '.socket.status == "ok" and .socket.cached == false' 'fresh result is marked uncached'
run_check clean
expect_rc 0 'cached clean Socket score permits GO'
expect_json '.socket.status == "ok" and .socket.cached == true' 'second exact result is marked cached'
[[ "$(socket_calls)" == "1" ]] && pass 'cache avoids the second Socket request' || fail 'cache avoids the second Socket request'
[[ "$(cache_entries)" == "1" ]] && pass 'successful result creates one cache entry' || fail 'successful result creates one cache entry'
[[ "$(stat -c %a "$CASE_CACHE")" == "700" ]] && pass 'cache directory is private' || fail 'cache directory is private'
cache_file="$(find "$CASE_CACHE" -type f -name '*.json' -print -quit)"
[[ "$(stat -c %a "$cache_file")" == "600" ]] && pass 'cache entry is private' || fail 'cache entry is private'

# Cache identity includes the exact resolved version.
set +e
env -u SOCKET_SECURITY_API_TOKEN HOME="$CASE_HOME" PATH="$MOCKBIN:/usr/bin:/bin" \
  SAFE_AUDIT_CONFIG_DIR="$CASE_AUDIT_CONFIG" SAFE_AUDIT_DATA_DIR="$CASE_DATA/audit" \
  SAFE_RUN_CONFIG_DIR="$CASE_RUN_CONFIG" SAFE_AUDIT_SOCKET_CACHE_DIR="$CASE_CACHE" \
  MOCK_SOCKET_LOG="$CASE_LOG" MOCK_SOCKET_MODE=clean \
  "$SAFE_AUDIT" check fixture@1.0.1 --ecosystem npm --json > "$CASE_OUT" 2> "$CASE_ERR"
CHECK_RC=$?
set -e
expect_rc 0 'different exact version is independently scored'
[[ "$(socket_calls)" == "2" ]] && pass 'cache never crosses exact versions' || fail 'cache never crosses exact versions'

# Cache success never changes the narrow verdict mapping.
prepare_case verdict-malware
run_check malware
expect_rc 20 'critical supply-chain-risk alert blocks'
expect_json '.warn_causes | index("socket_malware") != null' 'supply-chain-risk block has a specific cause'
prepare_case verdict-critical-cve
run_check critical-cve
expect_rc 10 'critical vulnerability alert warns rather than blocks'
expect_json '.warn_causes | index("socket_critical_cve") != null' 'critical vulnerability has a specific cause'
prepare_case verdict-high
run_check high
expect_rc 10 'high Socket alert warns'
expect_json '.warn_causes | index("socket_high_alert") != null' 'high alert has a specific cause'
prepare_case verdict-low
run_check low
expect_rc 10 'low Socket score warns'
expect_json '.warn_causes | index("socket_low_score") != null' 'low score has a specific cause'

# The envelope is a contract boundary: malformed success data must become a
# live infrastructure WARN, never a clean score or a cache entry.
for malformed in bad-severity missing-name missing-category bad-score missing-self non-object-alert; do
  prepare_case "malformed-$malformed"
  run_check "$malformed"
  expect_rc 10 "$malformed Socket envelope warns"
  expect_json '.socket.status == "error" and (.warn_causes | index("socket_error") != null)' "$malformed envelope is not trusted"
  [[ "$(cache_entries)" == "0" ]] && pass "$malformed envelope is never cached" || fail "$malformed envelope is never cached"
done

# Errors are never cached. An expired valid result is context only: refresh
# failure remains a live WARN while its last complete score is disclosed.
prepare_case expired
run_check clean
expect_rc 0 'seed cache for expiry path'
cache_file="$(find "$CASE_CACHE" -type f -name '*.json' -print -quit)"
tmp_file="$CASE/expired.json"
jq '.fetched_at = 1' "$cache_file" > "$tmp_file"
mv "$tmp_file" "$cache_file"
chmod 600 "$cache_file"
run_check rate
expect_rc 10 'expired cache refresh failure warns'
expect_json '.socket.status == "error" and (.checks.socket | contains("last complete score was 95"))' 'expired score is disclosure only'
[[ "$(socket_calls)" == "2" ]] && pass 'expired entry forces a fresh Socket request' || fail 'expired entry forces a fresh Socket request'

prepare_case no-error-cache
run_check rate
expect_rc 10 'rate limit warns as infrastructure breakage'
[[ "$(cache_entries)" == "0" ]] && pass 'rate-limit result is never cached' || fail 'rate-limit result is never cached'

# TTL zero disables both read and write caching.
prepare_case ttl-zero
printf '{"install":{"cooldown_days":0,"socket":{"mode":"auto","cache_ttl_days":0}}}\n' > "$CASE_RUN_CONFIG/config.json"
run_check clean
run_check clean
[[ "$(socket_calls)" == "2" ]] && pass 'zero TTL calls Socket every time' || fail 'zero TTL calls Socket every time'
[[ "$(cache_entries)" == "0" ]] && pass 'zero TTL writes no cache entry' || fail 'zero TTL writes no cache entry'

# `never` is the sole policy skip; auto is always consulted. Since Socket
# became the only behavioral tier, a skip carries no evidence and so cannot
# certify on its own — but it stays free (no API call, no timeout).
prepare_case disabled
printf '{"install":{"cooldown_days":0,"socket":{"mode":"never","cache_ttl_days":7}}}\n' > "$CASE_RUN_CONFIG/config.json"
run_check clean --gate install
expect_rc 10 'never mode discloses that no behavioral evidence was gathered'
expect_json '.warn_causes | index("socket_disabled") != null' 'the policy skip has its own cause, distinct from an outage'
expect_json '.socket.status == "skipped" and .socket.note == "disabled by install.socket.mode=never"' 'disabled mode is an honest policy skip'
[[ "$(socket_calls)" == "0" ]] && pass 'never mode does not invoke Socket' || fail 'never mode does not invoke Socket'
grep -q 'auto_allow_tolerate' "$CASE_ERR" && pass 'the skip names the way to run this posture routinely' || fail 'the skip names the way to run this posture routinely'

# An operator who declares the posture gets a clean gate again — recorded as
# WARN_TOLERATED, never GO, so a tolerated skip cannot later read as a real
# clean check.
prepare_case disabled-tolerated
printf '{"install":{"cooldown_days":0,"auto_allow_tolerate":["socket_disabled"],"socket":{"mode":"never","cache_ttl_days":7}}}\n' > "$CASE_RUN_CONFIG/config.json"
run_check clean --gate install
expect_rc 0 'a declared skip posture passes the install gate'
[[ "$(socket_calls)" == "0" ]] && pass 'tolerated skip still makes no Socket request' || fail 'tolerated skip still makes no Socket request'

# A fresh release whose bounded retries have no completed score remains a
# disclosed PENDING GO only while OSV and the blocklist are clean.
prepare_case pending
printf '{"install":{"cooldown_days":3,"socket":{"mode":"auto","cache_ttl_days":7}}}\n' > "$CASE_RUN_CONFIG/config.json"
run_check pending MOCK_RELEASE_FRESH=1 MOCK_COOLDOWN_FIX=1 SAFE_AUDIT_SOCKET_TIMEOUT=1 SAFE_AUDIT_SOCKET_FRESH_SCAN_TIMEOUT=1
expect_rc 0 'clean fresh release with incomplete Socket score stays GO'
expect_json '.socket.status == "pending" and .verdict == "GO"' 'pending Socket score is disclosed in the receipt'
[[ "$(cache_entries)" == "0" ]] && pass 'pending Socket score is never cached' || fail 'pending Socket score is never cached'

# A critical alert whose category safe cannot map must degrade to an
# infrastructure WARN, never fall through to PASS (review F3). Socket can add
# a category at any time; an unknown class is unresolved, not clean.
prepare_case unknown-category
run_check unknown-category
expect_rc 10 'unclassifiable critical alert warns instead of passing'
expect_json '.warn_causes | index("socket_error") != null' 'unclassifiable critical alert is an unresolved result'
expect_json '.verdict == "WARN"' 'unclassifiable critical alert never reaches GO'

# --- every resolved version is scored, not just the primary (review F1) -----
# Two project constraints resolve to two installable versions. The primary is
# clean and the sibling major carries the malice alert; the operation installs
# both, so a primary-only scan would let the malicious one through at GO.
multi_project() {
  MULTI_DIR="$CASE/project"
  mkdir -p "$MULTI_DIR"
  printf '{"dependencies":{"fixture":"^1.0.0"},"devDependencies":{"fixture":"^2.0.0"}}\n' \
    > "$MULTI_DIR/package.json"
}

run_multi() {
  local mode="$1"
  set +e
  env -u SOCKET_SECURITY_API_TOKEN HOME="$CASE_HOME" PATH="$MOCKBIN:/usr/bin:/bin" \
    SAFE_AUDIT_CONFIG_DIR="$CASE_AUDIT_CONFIG" SAFE_AUDIT_DATA_DIR="$CASE_DATA/audit" \
    SAFE_RUN_CONFIG_DIR="$CASE_RUN_CONFIG" SAFE_AUDIT_SOCKET_CACHE_DIR="$CASE_CACHE" \
    MOCK_SOCKET_LOG="$CASE_LOG" MOCK_SOCKET_MODE="$mode" MOCK_MULTI_VERSION=1 \
    "$SAFE_AUDIT" check fixture --ecosystem npm --op update --project-dir "$MULTI_DIR" \
    --json > "$CASE_OUT" 2> "$CASE_ERR"
  CHECK_RC=$?
  set -e
}

prepare_case multi-version-sanity
multi_project
run_multi clean
expect_rc 0 'multi-constraint resolve with all versions clean permits GO'
expect_json '.resolution.method == "project-range" and (.resolved_versions | sort) == ["1.0.0","2.0.0"]' 'both project constraints resolve to distinct installable versions'
[[ "$(socket_calls)" == "2" ]] && pass 'every resolved version is scored' || fail 'every resolved version is scored'

prepare_case multi-version-sibling-malware
multi_project
run_multi sibling-malware
expect_rc 20 'malicious non-primary resolved version blocks'
expect_json '.warn_causes | index("socket_malware") != null' 'sibling malice raises the malware cause'
expect_json '.verdict == "BLOCK"' 'a clean primary cannot carry a malicious sibling to GO'

prepare_case multi-version-sibling-error
multi_project
run_multi sibling-error
expect_rc 10 'unscored non-primary version warns rather than passing'
expect_json '.warn_causes | index("socket_error") != null' 'an unproven sibling is never assumed clean'

# Provider error bodies can name the operator or the org, and could in
# principle reflect credential material. safe classifies the failure into a
# fixed reason code and discards the text (review F5).
prepare_case error-body-sentinel
run_check auth-leaky
expect_rc 10 'auth failure warns as infrastructure breakage'
expect_json '.warn_causes | index("socket_auth_failed") != null' 'auth failure is classified from a fixed reason code'
if grep -rq 'SENTINELACCT9137' "$CASE" 2>/dev/null; then
  fail 'provider error-body text never reaches receipt, cache, stdout, or stderr'
else
  pass 'provider error-body text never reaches receipt, cache, stdout, or stderr'
fi
if grep -rq 'operator@example.com' "$CASE" 2>/dev/null; then
  fail 'provider error-body identity never reaches receipt, cache, stdout, or stderr'
else
  pass 'provider error-body identity never reaches receipt, cache, stdout, or stderr'
fi

printf '\n%d passed, %d failed\n' "$PASS_COUNT" "$FAIL_COUNT"
[[ "$FAIL_COUNT" -eq 0 ]]
