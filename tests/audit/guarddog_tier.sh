#!/usr/bin/env bash
# GuardDog behavioral tier: verdict mapping, permanent identity cache,
# configuration, doctor visibility, and per-resolved-version invocation.
# Fully offline: curl, Socket, and GuardDog are mocked on PATH.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SAFE_AUDIT="$ROOT/bin/safe-audit"
SAFE="$ROOT/bin/safe"
PASS_COUNT=0
FAIL_COUNT=0

pass() { printf 'ok - %s\n' "$*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { printf 'not ok - %s\n' "$*" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }

TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT
COMMONBIN="$TEST_ROOT/common-bin"
GUARDDOGBIN="$TEST_ROOT/guarddog-bin"
mkdir -p "$COMMONBIN" "$GUARDDOGBIN"
SRI_A="sha512-$(printf 'A%.0s' {1..86})=="
SRI_B="sha512-B$(printf 'A%.0s' {1..85})=="

cat > "$COMMONBIN/curl" <<'MOCK'
#!/usr/bin/env bash
url=""
outfile=""
args=("$@")
i=0
while (( i < ${#args[@]} )); do
  case "${args[$i]}" in
    -H|--max-time|-d) i=$((i + 2)); continue ;;
    -o) outfile="${args[$((i + 1))]}"; i=$((i + 2)); continue ;;
    http*://*) url="${args[$i]}" ;;
  esac
  i=$((i + 1))
done
emit() {
  if [[ -n "$outfile" ]]; then
    printf '%s\n' "$1" > "$outfile"
  else
    printf '%s\n' "$1"
  fi
}
case "$url" in
  *api.osv.dev*)
    emit '{"vulns":[]}'
    ;;
  *registry.npmjs.org*)
    sri_a="sha512-$(printf 'A%.0s' {1..86})=="
    sri_b="sha512-B$(printf 'A%.0s' {1..85})=="
    case "$url" in
      */1.5.0) emit "{\"name\":\"multi\",\"version\":\"1.5.0\",\"dist\":{\"integrity\":\"$sri_a\"}}" ;;
      */2.5.0) emit "{\"name\":\"multi\",\"version\":\"2.5.0\",\"dist\":{\"integrity\":\"$sri_b\"}}" ;;
      */1.0.0)
        if [[ "${MOCK_NPM_INTEGRITY_MISSING:-0}" == "1" ]]; then
          emit '{"name":"demo","version":"1.0.0","dist":{}}'
        else
          integrity="${MOCK_NPM_INTEGRITY:-$sri_a}"
          emit "{\"name\":\"demo\",\"version\":\"1.0.0\",\"dist\":{\"integrity\":\"$integrity\"}}"
        fi
        ;;
      *)
        if [[ "${MOCK_PACKUMENT_MODE:-single}" == "multi" ]]; then
          emit '{"dist-tags":{"latest":"2.5.0"},"versions":{"1.0.0":{},"1.5.0":{},"2.0.0":{},"2.5.0":{}}}'
        elif [[ -n "${MOCK_NPM_TIME:-}" ]]; then
          emit "{\"dist-tags\":{\"latest\":\"1.0.0\"},\"versions\":{\"1.0.0\":{}},\"time\":{\"1.0.0\":\"${MOCK_NPM_TIME}\"}}"
        else
          emit '{"dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{}}}'
        fi
        ;;
    esac
    ;;
  *pypi.org/pypi/*)
    digest="${MOCK_PYPI_DIGEST:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}"
    emit "{\"info\":{\"version\":\"1.0.0\"},\"releases\":{\"1.0.0\":[{\"filename\":\"demo-1.0.0.metadata\",\"digests\":{\"sha256\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"}},{\"filename\":\"demo-1.0.0-py3-none-any.whl\",\"digests\":{\"sha256\":\"$digest\"},\"url\":\"https://files.pythonhosted.org/demo.whl\"}]}}"
    ;;
  *) exit 22 ;;
esac
MOCK
chmod +x "$COMMONBIN/curl"

cat > "$COMMONBIN/socket" <<'MOCK'
#!/usr/bin/env bash
[[ -n "${MOCK_SOCKET_ARGS_LOG:-}" ]] && printf '%s\n' "$*" >> "$MOCK_SOCKET_ARGS_LOG"
if [[ "${MOCK_SOCKET_MODE:-ok}" == "error" ]]; then
  printf 'socket backend failed\n' >&2
  exit 1
fi
printf '{"score":95}\n'
MOCK
chmod +x "$COMMONBIN/socket"

cat > "$GUARDDOGBIN/guarddog" <<'MOCK'
#!/usr/bin/env bash
guarddog_env_present=0
for config_var in \
  GUARDDOG_PARALLELISM \
  GUARDDOG_VERIFY_EXHAUSTIVE_DEPENDENCIES \
  GUARDDOG_NEW_DEPENDENCY_RISK_THRESHOLD \
  GUARDDOG_TOP_PACKAGES_CACHE_LOCATION \
  GUARDDOG_YARA_EXT_EXCLUDE \
  GUARDDOG_MAX_UNCOMPRESSED_SIZE \
  GUARDDOG_MAX_COMPRESSION_RATIO \
  GUARDDOG_MAX_FILE_COUNT \
  GUARDDOG_SUBSCAN_SANDBOX
do
  [[ -v "$config_var" ]] && guarddog_env_present=1
done
if [[ "${1:-}" == "--version" ]]; then
  if [[ "${MOCK_GUARDDOG_VERSION_REQUIRE_CLEAN_ENV:-0}" == "1" && "$guarddog_env_present" == "1" ]]; then
    printf 'caller GuardDog environment leaked into version probe\n' >&2
    exit 3
  fi
  case "${MOCK_GUARDDOG_VERSION_MODE:-normal}" in
    stubborn) trap '' TERM; while :; do :; done ;;
    flood) while :; do printf '0123456789abcdef'; done ;;
    valid-error) printf 'guarddog, version 3.1.0\n'; exit 7 ;;
    valid-stubborn)
      printf 'guarddog, version 3.1.0\n'
      trap '' TERM
      while :; do :; done
      ;;
    valid-flood)
      printf 'guarddog, version 3.1.0 '
      while :; do printf '0123456789abcdef'; done
      ;;
  esac
  printf 'guarddog, version %s\n' "${MOCK_GUARDDOG_VERSION:-3.1.0}"
  exit 0
fi
[[ -n "${MOCK_GUARDDOG_LOG:-}" ]] && printf '%s\n' "$*" >> "$MOCK_GUARDDOG_LOG"
scan_version=""
args=("$@")
for ((i = 0; i < ${#args[@]}; i++)); do
  if [[ "${args[$i]}" == "--version" ]]; then
    scan_version="${args[$((i + 1))]:-}"
    break
  fi
done
case "${MOCK_GUARDDOG_MODE:-clean}" in
  clean)
    printf '{"issues":0,"errors":{},"results":{},"risk_score":{"score":0.0,"label":"no_risks_detected","findings_count":0,"score_breakdown":{}},"risks":[]}\n'
    ;;
  raw-only)
    printf '{"issues":1,"errors":{},"results":{"capability-network-outbound":[{"location":"x.js:1"}]},"risk_score":{"score":0.0,"label":"no_risks_detected","findings_count":0,"score_breakdown":{}},"risks":[]}\n'
    ;;
  warn)
    printf '{"issues":1,"errors":{},"results":{"typosquatting":[{"package":"demo"}]},"risk_score":{"score":6.4,"label":"suspicious","findings_count":1,"score_breakdown":{}},"risks":[{"threat_rule":"typosquatting","capability_rule":null}]}\n'
    ;;
  block)
    printf '{"issues":4,"errors":{},"results":{"threat-network-exfiltration":[{}],"threat-runtime-obfuscation-general":[{}]},"risk_score":{"score":9.1,"label":"high_risk","findings_count":4,"score_breakdown":{}},"risks":[{"threat_rule":"threat-network-exfiltration","capability_rule":"capability-network-outbound"},{"threat_rule":"threat-runtime-obfuscation-general","capability_rule":null}]}\n'
    ;;
  partial-block)
    printf '{"issues":2,"errors":{"metadata_mismatch":"detector failed"},"results":{"threat-network-exfiltration":[{}]},"risk_score":{"score":8.2,"label":"high_risk","findings_count":2,"score_breakdown":{}},"risks":[{"threat_rule":"threat-network-exfiltration","capability_rule":"capability-network-outbound"}]}\n'
    ;;
  inconsistent)
    printf '{"issues":1,"errors":{},"results":{"threat-network-exfiltration":[{}]},"risk_score":{"score":9.1,"label":"suspicious","findings_count":1,"score_breakdown":{}},"risks":[{"threat_rule":"threat-network-exfiltration","capability_rule":"capability-network-outbound"}]}\n'
    ;;
  env-sensitive)
    if (( guarddog_env_present )); then
      printf '{"issues":0,"errors":{},"results":{},"risk_score":{"score":0.0,"label":"no_risks_detected","findings_count":0,"score_breakdown":{}},"risks":[]}\n'
    else
      printf '{"issues":4,"errors":{},"results":{"threat-network-exfiltration":[{}]},"risk_score":{"score":9.1,"label":"high_risk","findings_count":4,"score_breakdown":{}},"risks":[{"threat_rule":"threat-network-exfiltration","capability_rule":"capability-network-outbound"}]}\n'
    fi
    ;;
  mixed)
    if [[ "$scan_version" == "2.5.0" ]]; then
      printf '{"issues":4,"errors":{},"results":{"threat-network-exfiltration":[{}]},"risk_score":{"score":9.1,"label":"high_risk","findings_count":4,"score_breakdown":{}},"risks":[{"threat_rule":"threat-network-exfiltration","capability_rule":"capability-network-outbound"}]}\n'
    else
      printf '{"issues":0,"errors":{},"results":{},"risk_score":{"score":0.0,"label":"no_risks_detected","findings_count":0,"score_breakdown":{}},"risks":[]}\n'
    fi
    ;;
  mixed-warn)
    if [[ "$scan_version" == "2.5.0" ]]; then
      printf '{"issues":1,"errors":{},"results":{"typosquatting":[{"package":"multi"}]},"risk_score":{"score":6.4,"label":"suspicious","findings_count":1,"score_breakdown":{}},"risks":[{"threat_rule":"typosquatting","capability_rule":null}]}\n'
    else
      printf '{"issues":0,"errors":{},"results":{},"risk_score":{"score":0.0,"label":"no_risks_detected","findings_count":0,"score_breakdown":{}},"risks":[]}\n'
    fi
    ;;
  mixed-error-block)
    if [[ "$scan_version" == "1.5.0" ]]; then
      printf 'registry request failed\n' >&2
      exit 1
    else
      printf '{"issues":4,"errors":{},"results":{"threat-network-exfiltration":[{}]},"risk_score":{"score":9.1,"label":"high_risk","findings_count":4,"score_breakdown":{}},"risks":[{"threat_rule":"threat-network-exfiltration","capability_rule":"capability-network-outbound"}]}\n'
    fi
    ;;
  mixed-error-warn)
    if [[ "$scan_version" == "1.5.0" ]]; then
      printf 'registry request failed\n' >&2
      exit 1
    else
      printf '{"issues":1,"errors":{},"results":{"typosquatting":[{"package":"multi"}]},"risk_score":{"score":6.4,"label":"suspicious","findings_count":1,"score_breakdown":{}},"risks":[{"threat_rule":"typosquatting","capability_rule":null}]}\n'
    fi
    ;;
  malformed) printf '{not-json\n' ;;
  error) printf 'registry request failed\n' >&2; exit 1 ;;
  hang) sleep 30 ;;
  stubborn) trap '' TERM; while :; do :; done ;;
  flood) while :; do printf '0123456789abcdef'; done ;;
  *) exit 2 ;;
esac
MOCK
chmod +x "$GUARDDOGBIN/guarddog"

CASE_DIR=""
CASE_HOME=""
CASE_RUN_CONFIG=""
CASE_CACHE=""
CASE_LOG=""
OUT_FILE=""
ERR_FILE=""
STATUS=0

prepare_case() {
  local name="$1"
  CASE_DIR="$TEST_ROOT/case-$name"
  CASE_HOME="$CASE_DIR/home"
  CASE_RUN_CONFIG="$CASE_DIR/run-config"
  CASE_CACHE="$CASE_DIR/cache"
  CASE_LOG="$CASE_DIR/guarddog.log"
  mkdir -p "$CASE_HOME" "$CASE_RUN_CONFIG" "$CASE_DIR/audit-config" "$CASE_DIR/audit-data" "$CASE_DIR/project"
}

# run_check <present:0|1> <env assignments...> -- <check args...>
run_check() {
  local present="$1"
  shift
  local -a envs=()
  while [[ "$1" != "--" ]]; do
    envs+=("$1")
    shift
  done
  shift
  local path="$COMMONBIN:/usr/bin:/bin"
  [[ "$present" == "1" ]] && path="$GUARDDOGBIN:$path"
  OUT_FILE="$CASE_DIR/stdout.log"
  ERR_FILE="$CASE_DIR/stderr.log"
  set +e
  (
    cd "$CASE_DIR/project" || exit 99
    env HOME="$CASE_HOME" PATH="$path" \
      SAFE_RUN_CONFIG_DIR="$CASE_RUN_CONFIG" \
      SAFE_AUDIT_CONFIG_DIR="$CASE_DIR/audit-config" \
      SAFE_AUDIT_DATA_DIR="$CASE_DIR/audit-data" \
      SAFE_AUDIT_GUARDDOG_CACHE_DIR="$CASE_CACHE" \
      MOCK_GUARDDOG_LOG="$CASE_LOG" \
      "${envs[@]}" "$SAFE_AUDIT" check "$@"
  ) > "$OUT_FILE" 2> "$ERR_FILE"
  STATUS=$?
  set -e
}

expect_status() {
  local expected="$1" label="$2"
  if [[ "$STATUS" -eq "$expected" ]]; then
    pass "$label"
  else
    printf 'expected %s, got %s\nstdout:\n%s\nstderr:\n%s\n' \
      "$expected" "$STATUS" "$(cat "$OUT_FILE")" "$(cat "$ERR_FILE")" >&2
    fail "$label"
  fi
}

expect_json() {
  local filter="$1" label="$2"
  if jq -e "$filter" "$OUT_FILE" >/dev/null 2>&1; then
    pass "$label"
  else
    cat "$OUT_FILE" >&2
    fail "$label"
  fi
}

expect_grep() {
  local file="$1" pattern="$2" label="$3"
  if grep -qE "$pattern" "$file"; then
    pass "$label"
  else
    cat "$file" >&2
    fail "$label"
  fi
}

# Missing GuardDog is an affirmative, non-adverse skip and GO evidence names it.
prepare_case missing
run_check 0 -- demo@1.0.0 --ecosystem npm --gate install --json
expect_status 0 "missing guarddog does not degrade the current Socket-backed verdict"
expect_json '.verdict == "GO" and .guarddog.status == "skipped" and .guarddog.available == false and .warn_causes == [] and (.guarddog.note | contains("guarddog not installed — behavioral tier skipped; install: uv tool install guarddog"))' \
  "missing guarddog receipt is explicit and non-adverse"
if jq -e '.packages["npm:demo"].reasons | index("guarddog_skipped_not_installed") != null' \
  "$CASE_RUN_CONFIG/install-known.json" >/dev/null 2>&1; then
  pass "install-known GO reason records missing behavioral tier honestly"
else
  fail "install-known GO reason records missing behavioral tier honestly"
fi

# Disabled tier is not invoked and is distinct from a missing binary.
prepare_case disabled
printf '{"install":{"guarddog":{"enabled":false}}}\n' > "$CASE_RUN_CONFIG/config.json"
run_check 1 -- demo@1.0.0 --ecosystem npm --json
expect_status 0 "disabled guarddog contributes no verdict"
expect_json '.guarddog.status == "disabled" and .guarddog.enabled == false' \
  "disabled guarddog has a distinct receipt state"
[[ ! -e "$CASE_LOG" ]] && pass "disabled guarddog is not invoked" || fail "disabled guarddog is not invoked"

# Capability-only raw matches do not override GuardDog's correlated risk model.
prepare_case raw-only
run_check 1 MOCK_GUARDDOG_MODE=raw-only -- demo@1.0.0 --ecosystem npm --json
expect_status 0 "capability-only raw matches remain GO"
expect_json '.guarddog.contribution == "GO" and .guarddog.rules == [] and .guarddog.versions[0].raw.issues == 1' \
  "capability-only evidence remains visible without becoming a package finding"

# Caller GuardDog configuration must never weaken or poison safe's profile.
prepare_case env-scrub
run_check 1 \
  MOCK_GUARDDOG_MODE=env-sensitive \
  MOCK_GUARDDOG_VERSION_REQUIRE_CLEAN_ENV=1 \
  GUARDDOG_PARALLELISM=1 \
  GUARDDOG_VERIFY_EXHAUSTIVE_DEPENDENCIES=true \
  GUARDDOG_NEW_DEPENDENCY_RISK_THRESHOLD=10 \
  GUARDDOG_TOP_PACKAGES_CACHE_LOCATION=/tmp/weakened \
  GUARDDOG_YARA_EXT_EXCLUDE=js \
  GUARDDOG_MAX_UNCOMPRESSED_SIZE=1 \
  GUARDDOG_MAX_COMPRESSION_RATIO=1 \
  GUARDDOG_MAX_FILE_COUNT=1 \
  GUARDDOG_SUBSCAN_SANDBOX=0 \
  -- demo@1.0.0 --ecosystem npm --json
expect_status 20 "caller GuardDog environment cannot suppress high-risk behavior"
expect_json '.guarddog.contribution == "BLOCK" and (.guarddog.rules | index("threat-network-exfiltration") != null) and .guarddog.cache.misses == 1' \
  "safe-owned GuardDog profile is applied before scanning and caching"

# Complete scans cache permanently; the same immutable identity replays.
prepare_case cache
run_check 1 MOCK_GUARDDOG_MODE=clean -- demo@1.0.0 --ecosystem npm --gate install --json
expect_status 0 "clean guarddog scan passes"
expect_json '.guarddog.cache.misses == 1 and .guarddog.cache.hits == 0 and .guarddog.versions[0].artifact_identity.artifact.algorithm == "sha512" and .guarddog.versions[0].cache.eligible == true' \
  "first scan binds a valid npm SRI and records a cache miss"
cache_entries=("$CASE_CACHE"/*.json)
if [[ "${#cache_entries[@]}" -eq 1 ]] \
  && jq -e '.scanner.profile == "safe-default-v1"' "${cache_entries[0]}" >/dev/null 2>&1; then
  pass "cache identity records the safe-owned scanner profile"
else
  fail "cache identity records the safe-owned scanner profile"
fi
scan_calls_before=$(wc -l < "$CASE_LOG")
run_check 1 MOCK_GUARDDOG_MODE=block -- demo@1.0.0 --ecosystem npm --json
expect_status 0 "same immutable identity replays the clean cached result"
expect_json '.guarddog.cache.hits == 1 and .guarddog.versions[0].cache.cached == true' \
  "cache replay is explicit in the receipt"
scan_calls_after=$(wc -l < "$CASE_LOG")
[[ "$scan_calls_before" -eq "$scan_calls_after" ]] && pass "cache hit does not rescan" || fail "cache hit does not rescan"

# Integrity changes invalidate the key; high-risk correlated rules BLOCK and
# revoke stale clean evidence even in gate mode.
run_check 1 MOCK_GUARDDOG_MODE=block MOCK_NPM_INTEGRITY="$SRI_B" -- \
  demo@1.0.0 --ecosystem npm --gate install --json
expect_status 20 "changed artifact identity rescans and high-risk behavior BLOCKs"
expect_json '.verdict == "BLOCK" and (.warn_causes | index("guarddog_high_risk") != null) and (.guarddog.rules | index("threat-network-exfiltration") != null) and .guarddog.cache.misses == 1' \
  "high-risk receipt names rules and the cache miss"
expect_grep "$ERR_FILE" 'guarddog high-risk behavioral findings.*threat-network-exfiltration' \
  "BLOCK hint names the triggered GuardDog rule"
if jq -e '.packages["npm:demo"] == null' "$CASE_RUN_CONFIG/install-known.json" >/dev/null 2>&1; then
  pass "GuardDog BLOCK revokes stale install-known evidence"
else
  fail "GuardDog BLOCK revokes stale install-known evidence"
fi

# Corrupt entries are misses and are replaced only by a fresh valid scan.
prepare_case corrupt-cache
run_check 1 MOCK_GUARDDOG_MODE=clean -- demo@1.0.0 --ecosystem npm --json
expect_status 0 "corrupt-cache fixture seeds a clean entry"
corrupt_entries=("$CASE_CACHE"/*.json)
printf '{broken\n' > "${corrupt_entries[0]}"
run_check 1 MOCK_GUARDDOG_MODE=block -- demo@1.0.0 --ecosystem npm --json
expect_status 20 "corrupt cache entry cannot replay clean evidence"
expect_json '.guarddog.cache.misses == 1 and .guarddog.cache.hits == 0 and .guarddog.contribution == "BLOCK"' \
  "corrupt cache entry forces a fresh scan and atomic replacement"
[[ "$(wc -l < "$CASE_LOG")" -eq 2 ]] && pass "corrupt cache entry rescans" || fail "corrupt cache entry rescans"

# Lower-confidence risks WARN, name rules, and remain overridable only through
# existing exact/operator policy paths.
prepare_case warn
run_check 1 MOCK_GUARDDOG_MODE=warn -- demo@1.0.0 --ecosystem npm --gate install --json
expect_status 10 "suspicious GuardDog risk WARN-refuses by default"
expect_json '.verdict == "WARN" and .warn_causes == ["guarddog_findings"] and .guarddog.rules == ["typosquatting"]' \
  "GuardDog WARN cause and rule are additive receipt fields"
expect_grep "$ERR_FILE" 'guarddog behavioral findings \(typosquatting\)' \
  "WARN hint names the triggered metadata rule"
printf '{"install":{"auto_allow_tolerate":["guarddog_findings"]}}\n' > "$CASE_RUN_CONFIG/config.json"
run_check 1 MOCK_GUARDDOG_MODE=block -- demo@1.0.0 --ecosystem npm --gate install --json
expect_status 0 "operator tolerate knob allows the cached GuardDog WARN"
if jq -e '.packages["npm:demo"].verdict == "WARN_TOLERATED" and (.packages["npm:demo"].reasons | index("guarddog_findings") != null)' \
  "$CASE_RUN_CONFIG/install-known.json" >/dev/null 2>&1; then
  pass "tolerated GuardDog WARN records its cause"
else
  fail "tolerated GuardDog WARN records its cause"
fi

# Present scanner failures and timeouts are infrastructure WARNs, never cached.
prepare_case error
run_check 1 MOCK_GUARDDOG_MODE=error -- demo@1.0.0 --ecosystem npm --gate install --json
expect_status 10 "present GuardDog command failure WARN-refuses"
expect_json '.guarddog.status == "error" and .guarddog.infra_error == true and .warn_causes == ["guarddog_error"] and .guarddog.cache.misses == 0' \
  "GuardDog command failure is infrastructure, not package evidence"
expect_grep "$ERR_FILE" 'guarddog unavailable.*infrastructure failure, NOT a package finding' \
  "GuardDog failure hint uses infrastructure wording"
[[ ! -d "$CASE_CACHE" ]] && pass "failed scan is not cached" || fail "failed scan is not cached"

prepare_case timeout
printf '{"install":{"guarddog":{"timeout_seconds":1}}}\n' > "$CASE_RUN_CONFIG/config.json"
run_check 1 MOCK_GUARDDOG_MODE=hang -- demo@1.0.0 --ecosystem npm --json
expect_status 10 "GuardDog scan obeys configured wall-clock timeout"
expect_json '.guarddog.infra_error == true and (.guarddog.note | contains("timed out after 1s")) and (.warn_causes | index("guarddog_error") != null)' \
  "timeout is an explicit infrastructure receipt state"

prepare_case stubborn-timeout
printf '{"install":{"guarddog":{"timeout_seconds":1}}}\n' > "$CASE_RUN_CONFIG/config.json"
SECONDS=0
run_check 1 MOCK_GUARDDOG_MODE=stubborn -- demo@1.0.0 --ecosystem npm --json
stubborn_elapsed=$SECONDS
expect_status 10 "GuardDog timeout force-kills a TERM-resistant child"
expect_json '.guarddog.infra_error == true and (.guarddog.note | contains("timed out after 1s"))' \
  "forced timeout remains an infrastructure receipt state"
(( stubborn_elapsed < 8 )) && pass "TERM-resistant GuardDog remains wall-clock bounded" || fail "TERM-resistant GuardDog remains wall-clock bounded"

prepare_case output-bound
run_check 1 MOCK_GUARDDOG_MODE=flood -- demo@1.0.0 --ecosystem npm --json
expect_status 10 "unbounded GuardDog stdout is refused"
expect_json '.guarddog.infra_error == true and (.guarddog.note | contains("output exceeded the 16384 KiB per-stream limit")) and .guarddog.cache.misses == 0' \
  "GuardDog output bound becomes uncached infrastructure evidence"

prepare_case malformed
run_check 1 MOCK_GUARDDOG_MODE=malformed -- demo@1.0.0 --ecosystem npm --json
expect_status 10 "malformed GuardDog JSON WARN-refuses"
expect_json '.guarddog.status == "error" and .guarddog.infra_error == true and (.guarddog.note | contains("malformed or inconsistent JSON")) and .warn_causes == ["guarddog_error"]' \
  "malformed GuardDog output is infrastructure, not clean evidence"
[[ ! -d "$CASE_CACHE" ]] && pass "malformed GuardDog output is not cached" || fail "malformed GuardDog output is not cached"

prepare_case inconsistent
run_check 1 MOCK_GUARDDOG_MODE=inconsistent -- demo@1.0.0 --ecosystem npm --json
expect_status 10 "score/label-inconsistent GuardDog JSON WARN-refuses"
expect_json '.guarddog.status == "error" and (.guarddog.note | contains("malformed or inconsistent JSON")) and .guarddog.cache.misses == 0' \
  "v3.1 semantic inconsistency cannot enter the tolerant findings lane or cache"

prepare_case unsupported-version
run_check 1 MOCK_GUARDDOG_VERSION=4.0.0 MOCK_GUARDDOG_MODE=clean -- \
  demo@1.0.0 --ecosystem npm --json
expect_status 10 "uncharacterized GuardDog version WARN-refuses"
expect_json '.guarddog.status == "error" and .guarddog.scanner_version == "4.0.0" and (.guarddog.note | contains("safe supports 3.1.0")) and .guarddog.versions == []' \
  "unsupported GuardDog semantics never scan or cache"
[[ ! -e "$CASE_LOG" ]] && pass "unsupported GuardDog version is not used" || fail "unsupported GuardDog version is not used"

# Partial valid high-risk evidence outranks a simultaneous rule failure.
prepare_case partial
run_check 1 MOCK_GUARDDOG_MODE=partial-block -- demo@1.0.0 --ecosystem npm --json
expect_status 20 "partial high-risk evidence remains BLOCK"
expect_json '.guarddog.status == "partial" and .guarddog.infra_error == true and (.warn_causes | index("guarddog_high_risk") != null) and (.warn_causes | index("guarddog_error") != null)' \
  "partial scanner failure cannot erase retained high-risk rules"

# Missing integrity scans normally but never creates a guessable cache entry.
prepare_case no-integrity
run_check 1 MOCK_GUARDDOG_MODE=clean MOCK_NPM_INTEGRITY_MISSING=1 -- \
  demo@1.0.0 --ecosystem npm --json
expect_status 0 "missing artifact integrity does not skip the GuardDog scan"
expect_json '.guarddog.cache.uncacheable == 1 and .guarddog.versions[0].cache.eligible == false and .guarddog.versions[0].artifact_identity == null' \
  "missing integrity is explicit and uncacheable"
[[ ! -d "$CASE_CACHE" ]] && pass "missing integrity does not create a cache" || fail "missing integrity does not create a cache"

prepare_case invalid-integrity
run_check 1 MOCK_GUARDDOG_MODE=clean MOCK_NPM_INTEGRITY=sha512-AAAA -- \
  demo@1.0.0 --ecosystem npm --json
expect_status 0 "invalid registry SRI does not skip the GuardDog scan"
expect_json '.guarddog.cache.uncacheable == 1 and .guarddog.versions[0].artifact_identity == null' \
  "invalid registry SRI cannot become a permanent cache identity"
[[ ! -d "$CASE_CACHE" ]] && pass "invalid registry SRI does not create a cache" || fail "invalid registry SRI does not create a cache"

# PyPI cache binding follows GuardDog's first supported archive, not urls[0].
prepare_case pypi
run_check 1 MOCK_GUARDDOG_MODE=clean -- demo@1.0.0 --ecosystem python --json
expect_status 0 "exact PyPI version receives a GuardDog scan"
expect_json '.guarddog.versions[0].artifact_identity.artifact.filename == "demo-1.0.0-py3-none-any.whl" and .guarddog.versions[0].artifact_identity.artifact.algorithm == "sha256"' \
  "PyPI cache key selects the first GuardDog-supported archive"
expect_grep "$CASE_LOG" '^pypi scan demo --version 1\.0\.0 --output-format=json$' \
  "PyPI invocation uses the pinned v3.1.0 CLI shape"

# Every exact version resolved for an npm update is scanned independently.
prepare_case multi
printf '{"dependencies":{"multi":"^1.0.0"}}\n' > "$CASE_DIR/project/package.json"
printf '{"packages":{"node_modules/consumer":{"dependencies":{"multi":"^2.0.0"}}}}\n' > "$CASE_DIR/project/package-lock.json"
run_check 1 MOCK_GUARDDOG_MODE=clean MOCK_PACKUMENT_MODE=multi -- \
  multi --ecosystem npm --op update --project-dir "$CASE_DIR/project" --json
expect_status 0 "multi-target npm resolution remains clean"
expect_json '.resolved_versions == ["1.5.0","2.5.0"] and (.guarddog.versions | map(.version)) == ["1.5.0","2.5.0"]' \
  "GuardDog scans every exact resolved version"
[[ "$(wc -l < "$CASE_LOG")" -eq 2 ]] && pass "multi-target resolution invokes GuardDog twice" || fail "multi-target resolution invokes GuardDog twice"

prepare_case mixed-multi
printf '{"dependencies":{"multi":"^1.0.0"}}\n' > "$CASE_DIR/project/package.json"
printf '{"packages":{"node_modules/consumer":{"dependencies":{"multi":"^2.0.0"}}}}\n' > "$CASE_DIR/project/package-lock.json"
run_check 1 MOCK_GUARDDOG_MODE=mixed MOCK_PACKUMENT_MODE=multi -- \
  multi --ecosystem npm --op update --project-dir "$CASE_DIR/project" --json
expect_status 20 "one high-risk member BLOCKs a multi-version resolution"
expect_json '.guarddog.contribution == "BLOCK" and (.guarddog.versions | map(.contribution)) == ["GO","BLOCK"] and (.guarddog.rules | index("threat-network-exfiltration") != null)' \
  "multi-version aggregation retains the strongest behavioral evidence"

# A host-allow pin covers the exact adverse member, never any clean sibling.
prepare_case multi-warn-clean-pin
printf '{"dependencies":{"multi":"^1.0.0"}}\n' > "$CASE_DIR/project/package.json"
printf '{"packages":{"node_modules/consumer":{"dependencies":{"multi":"^2.0.0"}}}}\n' > "$CASE_DIR/project/package-lock.json"
printf '{"packages":{"multi":{"version":"1.5.0","ecosystem":"npm"}}}\n' \
  > "$CASE_RUN_CONFIG/host-allow.json"
run_check 1 MOCK_GUARDDOG_MODE=mixed-warn MOCK_PACKUMENT_MODE=multi -- \
  multi --ecosystem npm --op update --project-dir "$CASE_DIR/project" --gate install --json
expect_status 10 "clean sibling host-allow cannot authorize a warned version"
expect_json '.guarddog.contribution == "WARN" and (.guarddog.versions | map(.contribution)) == ["GO","WARN"]' \
  "clean-plus-WARN aggregation retains the adverse member"
expect_grep "$ERR_FILE" 'host-allow add multi@2\.5\.0' \
  "GuardDog WARN hint names the adverse version rather than the primary version"

prepare_case multi-warn-adverse-pin
printf '{"dependencies":{"multi":"^1.0.0"}}\n' > "$CASE_DIR/project/package.json"
printf '{"packages":{"node_modules/consumer":{"dependencies":{"multi":"^2.0.0"}}}}\n' > "$CASE_DIR/project/package-lock.json"
printf '{"packages":{"multi":{"version":"2.5.0","ecosystem":"npm"}}}\n' \
  > "$CASE_RUN_CONFIG/host-allow.json"
run_check 1 MOCK_GUARDDOG_MODE=mixed-warn MOCK_PACKUMENT_MODE=multi -- \
  multi --ecosystem npm --op update --project-dir "$CASE_DIR/project" --gate install --json
expect_status 0 "host-allow for the sole warned version authorizes the aggregate operation"
expect_grep "$ERR_FILE" 'host-allow entry multi@2\.5\.0 matches every warned resolved version; allowing' \
  "override notice names the covered adverse pin"

prepare_case multi-warn-no-pin
printf '{"dependencies":{"multi":"^1.0.0"}}\n' > "$CASE_DIR/project/package.json"
printf '{"packages":{"node_modules/consumer":{"dependencies":{"multi":"^2.0.0"}}}}\n' > "$CASE_DIR/project/package-lock.json"
run_check 1 MOCK_GUARDDOG_MODE=mixed-warn MOCK_PACKUMENT_MODE=multi -- \
  multi --ecosystem npm --op update --project-dir "$CASE_DIR/project" --gate install --json
expect_status 10 "multi-version GuardDog WARN refuses without an adverse-version pin"

prepare_case multi-global-guarddog-error
printf '{"dependencies":{"multi":"^1.0.0"}}\n' > "$CASE_DIR/project/package.json"
printf '{"packages":{"node_modules/consumer":{"dependencies":{"multi":"^2.0.0"}}}}\n' > "$CASE_DIR/project/package-lock.json"
printf '{"packages":{"multi":{"version":"1.5.0","ecosystem":"npm"}}}\n' \
  > "$CASE_RUN_CONFIG/host-allow.json"
run_check 1 MOCK_GUARDDOG_VERSION=4.0.0 MOCK_SOCKET_MODE=error MOCK_PACKUMENT_MODE=multi -- \
  multi --ecosystem npm --op update --project-dir "$CASE_DIR/project" --gate install --json
expect_status 10 "primary pin cannot clear a global GuardDog failure for an unscanned sibling"
expect_json '.resolved_versions == ["1.5.0","2.5.0"]
  and .guarddog.status == "error" and .guarddog.versions == []
  and (.warn_causes | index("guarddog_error") != null)
  and (.warn_causes | index("socket_error") != null)' \
  "tier-wide GuardDog error and primary Socket error remain explicit"

# Strong retained evidence remains legible when a sibling scan also fails.
prepare_case mixed-error-block
printf '{"dependencies":{"multi":"^1.0.0"}}\n' > "$CASE_DIR/project/package.json"
printf '{"packages":{"node_modules/consumer":{"dependencies":{"multi":"^2.0.0"}}}}\n' > "$CASE_DIR/project/package-lock.json"
run_check 1 MOCK_GUARDDOG_MODE=mixed-error-block MOCK_PACKUMENT_MODE=multi -- \
  multi --ecosystem npm --op update --project-dir "$CASE_DIR/project" --json
expect_status 20 "scan error cannot visually demote a sibling GuardDog BLOCK"
expect_json '.guarddog.status == "error" and .guarddog.contribution == "BLOCK" and (.checks.guarddog | startswith("BLOCK")) and (.checks.guarddog | contains("scan incomplete"))' \
  "receipt line preserves BLOCK and discloses incomplete coverage"
run_check 1 MOCK_GUARDDOG_MODE=mixed-error-block MOCK_PACKUMENT_MODE=multi -- \
  multi --ecosystem npm --op update --project-dir "$CASE_DIR/project"
expect_status 20 "human mixed error-plus-BLOCK verdict remains BLOCK"
expect_grep "$OUT_FILE" '^GuardDog:    BLOCK .*scan incomplete' \
  "human scanner line preserves BLOCK and incomplete-scan context"

prepare_case mixed-error-warn
printf '{"dependencies":{"multi":"^1.0.0"}}\n' > "$CASE_DIR/project/package.json"
printf '{"packages":{"node_modules/consumer":{"dependencies":{"multi":"^2.0.0"}}}}\n' > "$CASE_DIR/project/package-lock.json"
run_check 1 MOCK_GUARDDOG_MODE=mixed-error-warn MOCK_PACKUMENT_MODE=multi -- \
  multi --ecosystem npm --op update --project-dir "$CASE_DIR/project" --json
expect_status 10 "scan error plus behavioral WARN remains a findings WARN"
expect_json '.guarddog.status == "error" and .guarddog.contribution == "WARN" and (.checks.guarddog | contains("typosquatting")) and (.checks.guarddog | contains("scan incomplete"))' \
  "mixed error-plus-WARN line retains rules and incomplete-scan context"

prepare_case npm-v-prefix
run_check 1 MOCK_GUARDDOG_MODE=clean -- demo@v1.0.0 --ecosystem npm --json
expect_status 0 "npm leading-v exact spelling scans successfully"
expect_json '.spec == "demo@v1.0.0" and .resolved_versions == ["1.0.0"] and .guarddog.versions[0].version == "1.0.0"' \
  "npm leading-v spelling canonicalizes before exact scanner lookup"
expect_grep "$CASE_LOG" '^npm scan demo --version 1\.0\.0 --output-format=json$' \
  "GuardDog receives npm's canonical exact version"

# Doctor exposes path and version without creating config/data state.
prepare_case doctor
doctor_json="$(HOME="$CASE_HOME" PATH="$GUARDDOGBIN:$COMMONBIN:/usr/bin:/bin" \
  SAFE_CONFIG_DIR="$CASE_DIR/doctor-config" SAFE_DATA_DIR="$CASE_DIR/doctor-data" \
  SAFE_ZSH_COMPLETION_DIR="$CASE_DIR/site-functions" "$SAFE" doctor --json)"
if jq -e '.environment.guarddog.cli_present == true and (.environment.guarddog.cli_path | endswith("/guarddog")) and (.environment.guarddog.version | contains("3.1.0"))' \
  <<<"$doctor_json" >/dev/null 2>&1; then
  pass "safe doctor reports GuardDog presence and version"
else
  printf '%s\n' "$doctor_json" >&2
  fail "safe doctor reports GuardDog presence and version"
fi

prepare_case doctor-tool-cache
printf '{"machines":{"local":{"type":"local"}}}\n' > "$CASE_DIR/audit-config/machines.json"
jq -n --arg path "$GUARDDOGBIN/guarddog" '{local:{guarddog:$path}}' \
  > "$CASE_DIR/audit-config/tools.json"
doctor_json="$(HOME="$CASE_HOME" PATH="$COMMONBIN:/usr/bin:/bin" \
  SAFE_CONFIG_DIR="$CASE_DIR/doctor-config" \
  SAFE_AUDIT_CONFIG_DIR="$CASE_DIR/audit-config" \
  SAFE_DATA_DIR="$CASE_DIR/doctor-data" \
  SAFE_ZSH_COMPLETION_DIR="$CASE_DIR/site-functions" \
  GUARDDOG_YARA_EXT_EXCLUDE=js \
  MOCK_GUARDDOG_VERSION_REQUIRE_CLEAN_ENV=1 \
  "$SAFE" doctor --json)"
if jq -e --arg path "$GUARDDOGBIN/guarddog" \
  '.environment.guarddog.cli_present == true
   and .environment.guarddog.cli_path == $path
   and (.environment.guarddog.version | contains("3.1.0"))' \
  <<<"$doctor_json" >/dev/null 2>&1; then
  pass "safe doctor matches audit tools.json resolution under a clean GuardDog environment"
else
  printf '%s\n' "$doctor_json" >&2
  fail "safe doctor matches audit tools.json resolution under a clean GuardDog environment"
fi

prepare_case doctor-machine-override
printf '{"machines":{}}\n' > "$CASE_DIR/audit-config/machines.json"
jq -n --arg path "$GUARDDOGBIN/guarddog" '{workstation:{guarddog:$path}}' \
  > "$CASE_DIR/audit-config/tools.json"
doctor_json="$(HOME="$CASE_HOME" PATH="$COMMONBIN:/usr/bin:/bin" \
  SAFE_CONFIG_DIR="$CASE_DIR/doctor-config" \
  SAFE_AUDIT_CONFIG_DIR="$CASE_DIR/audit-config" \
  SAFE_AUDIT_LOCAL_MACHINE=workstation \
  SAFE_DATA_DIR="$CASE_DIR/doctor-data" \
  SAFE_ZSH_COMPLETION_DIR="$CASE_DIR/site-functions" \
  "$SAFE" doctor --json)"
if jq -e --arg path "$GUARDDOGBIN/guarddog" \
  '.environment.guarddog.cli_present == true
   and .environment.guarddog.cli_path == $path
   and (.environment.guarddog.version | contains("3.1.0"))' \
  <<<"$doctor_json" >/dev/null 2>&1; then
  pass "safe doctor honors audit's local-machine override fallback"
else
  printf '%s\n' "$doctor_json" >&2
  fail "safe doctor honors audit's local-machine override fallback"
fi

prepare_case doctor-stubborn-version
doctor_started=$SECONDS
doctor_json="$(HOME="$CASE_HOME" PATH="$GUARDDOGBIN:$COMMONBIN:/usr/bin:/bin" \
  SAFE_CONFIG_DIR="$CASE_DIR/doctor-config" SAFE_DATA_DIR="$CASE_DIR/doctor-data" \
  SAFE_ZSH_COMPLETION_DIR="$CASE_DIR/site-functions" \
  MOCK_GUARDDOG_VERSION_MODE=stubborn "$SAFE" doctor --json)"
doctor_elapsed=$((SECONDS - doctor_started))
if jq -e '.environment.guarddog.cli_present == true and .environment.guarddog.version == null' \
  <<<"$doctor_json" >/dev/null 2>&1 && (( doctor_elapsed < 8 )); then
  pass "safe doctor force-terminates a TERM-resistant GuardDog version probe"
else
  printf 'elapsed=%s\n%s\n' "$doctor_elapsed" "$doctor_json" >&2
  fail "safe doctor force-terminates a TERM-resistant GuardDog version probe"
fi

prepare_case doctor-version-flood
doctor_json="$(HOME="$CASE_HOME" PATH="$GUARDDOGBIN:$COMMONBIN:/usr/bin:/bin" \
  SAFE_CONFIG_DIR="$CASE_DIR/doctor-config" SAFE_DATA_DIR="$CASE_DIR/doctor-data" \
  SAFE_ZSH_COMPLETION_DIR="$CASE_DIR/site-functions" \
  MOCK_GUARDDOG_VERSION_MODE=flood "$SAFE" doctor --json)"
if jq -e '.environment.guarddog.cli_present == true and .environment.guarddog.version == null' \
  <<<"$doctor_json" >/dev/null 2>&1; then
  pass "safe doctor bounds and rejects an unrecognized flooding version probe"
else
  printf '%s\n' "$doctor_json" >&2
  fail "safe doctor bounds and rejects an unrecognized flooding version probe"
fi

prepare_case doctor-valid-prefix-error
doctor_json="$(HOME="$CASE_HOME" PATH="$GUARDDOGBIN:$COMMONBIN:/usr/bin:/bin" \
  SAFE_CONFIG_DIR="$CASE_DIR/doctor-config" SAFE_DATA_DIR="$CASE_DIR/doctor-data" \
  SAFE_ZSH_COMPLETION_DIR="$CASE_DIR/site-functions" \
  MOCK_GUARDDOG_VERSION_MODE=valid-error "$SAFE" doctor --json)"
if jq -e '.environment.guarddog.cli_present == true and .environment.guarddog.version == null' \
  <<<"$doctor_json" >/dev/null 2>&1; then
  pass "safe doctor rejects a valid-looking version from a failed probe"
else
  printf '%s\n' "$doctor_json" >&2
  fail "safe doctor rejects a valid-looking version from a failed probe"
fi

prepare_case doctor-valid-prefix-stubborn
doctor_json="$(HOME="$CASE_HOME" PATH="$GUARDDOGBIN:$COMMONBIN:/usr/bin:/bin" \
  SAFE_CONFIG_DIR="$CASE_DIR/doctor-config" SAFE_DATA_DIR="$CASE_DIR/doctor-data" \
  SAFE_ZSH_COMPLETION_DIR="$CASE_DIR/site-functions" \
  MOCK_GUARDDOG_VERSION_MODE=valid-stubborn "$SAFE" doctor --json)"
if jq -e '.environment.guarddog.cli_present == true and .environment.guarddog.version == null' \
  <<<"$doctor_json" >/dev/null 2>&1; then
  pass "safe doctor rejects a valid-looking version from a force-killed probe"
else
  printf '%s\n' "$doctor_json" >&2
  fail "safe doctor rejects a valid-looking version from a force-killed probe"
fi

prepare_case doctor-valid-prefix-flood
doctor_json="$(HOME="$CASE_HOME" PATH="$GUARDDOGBIN:$COMMONBIN:/usr/bin:/bin" \
  SAFE_CONFIG_DIR="$CASE_DIR/doctor-config" SAFE_DATA_DIR="$CASE_DIR/doctor-data" \
  SAFE_ZSH_COMPLETION_DIR="$CASE_DIR/site-functions" \
  MOCK_GUARDDOG_VERSION_MODE=valid-flood "$SAFE" doctor --json)"
if jq -e '.environment.guarddog.cli_present == true and .environment.guarddog.version == null' \
  <<<"$doctor_json" >/dev/null 2>&1; then
  pass "safe doctor rejects a valid-prefix flooding probe that does not exit cleanly"
else
  printf '%s\n' "$doctor_json" >&2
  fail "safe doctor rejects a valid-prefix flooding probe that does not exit cleanly"
fi

# --- tier-3 socket decision --------------------------------------------------

# A clean GuardDog verdict makes Socket unnecessary: it is not consulted at
# all, so a Socket outage cannot degrade the check (the tiered-scoring
# headline). The recorded evidence says skipped, never ok.
prepare_case tier3-skip-on-clean
run_check 1 MOCK_SOCKET_MODE=error MOCK_SOCKET_ARGS_LOG="$CASE_DIR/socket-args.log" -- \
  demo@1.0.0 --ecosystem npm --gate install
expect_status 0 "clean GuardDog verdict gates GO with Socket broken"
expect_grep "$OUT_FILE" '^Socket:      SKIP \(tier 3' "socket line reads as a deliberate tier-3 skip"
if [[ ! -s "$CASE_DIR/socket-args.log" ]]; then
  pass "socket is not invoked when the behavioral tier concluded"
else
  cat "$CASE_DIR/socket-args.log" >&2
  fail "socket is not invoked when the behavioral tier concluded"
fi
if jq -e '.packages["npm:demo"].reasons | index("socket_skipped_tier3") != null and index("socket_ok") == null' \
  "$CASE_RUN_CONFIG/install-known.json" >/dev/null 2>&1; then
  pass "install-known reasons record the tier-3 skip honestly"
else
  cat "$CASE_RUN_CONFIG/install-known.json" >&2 || true
  fail "install-known reasons record the tier-3 skip honestly"
fi

# Behavioral tier unavailable -> Socket is consulted (guarddog absent).
prepare_case tier3-consult-when-missing
run_check 0 MOCK_SOCKET_ARGS_LOG="$CASE_DIR/socket-args.log" -- \
  demo@1.0.0 --ecosystem npm --gate install
expect_status 0 "guarddog-missing check with Socket ok gates GO"
expect_grep "$CASE_DIR/socket-args.log" '^package score npm demo@1\.0\.0' \
  "socket is consulted when the behavioral tier did not run"

# install.socket.mode=always restores always-on Socket beside a clean scan.
prepare_case tier3-mode-always
printf '{"install": {"socket": {"mode": "always"}}}\n' > "$CASE_RUN_CONFIG/config.json"
run_check 1 MOCK_SOCKET_ARGS_LOG="$CASE_DIR/socket-args.log" -- \
  demo@1.0.0 --ecosystem npm --gate install
expect_status 0 "mode=always with socket ok gates GO"
expect_grep "$CASE_DIR/socket-args.log" '^package score npm demo@1\.0\.0' \
  "mode=always consults socket despite a clean behavioral verdict"
if jq -e '.packages["npm:demo"].reasons | index("socket_ok") != null' \
  "$CASE_RUN_CONFIG/install-known.json" >/dev/null 2>&1; then
  pass "mode=always records socket_ok"
else
  cat "$CASE_RUN_CONFIG/install-known.json" >&2 || true
  fail "mode=always records socket_ok"
fi

# install.socket.mode=never disables Socket entirely, honestly recorded.
prepare_case tier3-mode-never
printf '{"install": {"socket": {"mode": "never"}}}\n' > "$CASE_RUN_CONFIG/config.json"
run_check 0 MOCK_SOCKET_ARGS_LOG="$CASE_DIR/socket-args.log" -- \
  demo@1.0.0 --ecosystem npm --gate install
expect_status 0 "mode=never with no behavioral tier still gates GO by operator choice"
expect_grep "$OUT_FILE" '^Socket:      SKIP \(disabled by install.socket.mode=never' \
  "mode=never skip names the knob"
if [[ ! -s "$CASE_DIR/socket-args.log" ]]; then
  pass "mode=never never invokes socket"
else
  fail "mode=never never invokes socket"
fi
if jq -e '.packages["npm:demo"].reasons | index("socket_disabled") != null' \
  "$CASE_RUN_CONFIG/install-known.json" >/dev/null 2>&1; then
  pass "mode=never records socket_disabled"
else
  cat "$CASE_RUN_CONFIG/install-known.json" >&2 || true
  fail "mode=never records socket_disabled"
fi

# --- release-age cooldown ----------------------------------------------------

# Fresh release inside the cooldown -> WARN with the named override paths.
prepare_case cooldown-too-new
run_check 1 MOCK_NPM_TIME="$(date -d '1 day ago' -Is)" -- \
  demo@1.0.0 --ecosystem npm --gate install
expect_status 10 "release younger than the cooldown refuses at the gate"
expect_grep "$OUT_FILE" '^Release age: WARN \(1\.0\.0 published [01]d ago' \
  "release line names the version and age"
expect_grep "$ERR_FILE" 'younger than the release cooldown' "cooldown hint printed"
expect_grep "$ERR_FILE" 'release_too_new to install.auto_allow_tolerate' \
  "cooldown hint names the tolerate override"
if jq -e '.packages["npm:demo"]' "$CASE_RUN_CONFIG/install-known.json" >/dev/null 2>&1; then
  fail "cooldown WARN never records clean evidence"
else
  pass "cooldown WARN never records clean evidence"
fi

# Tolerating release_too_new allows the same check.
prepare_case cooldown-tolerated
printf '{"install": {"auto_allow_tolerate": ["release_too_new"]}}\n' > "$CASE_RUN_CONFIG/config.json"
run_check 1 MOCK_NPM_TIME="$(date -d '1 day ago' -Is)" -- \
  demo@1.0.0 --ecosystem npm --gate install
expect_status 0 "tolerated cooldown WARN allows the exact version"

# Old release passes; lookup failure skips with disclosure, never a WARN.
prepare_case cooldown-old-release
run_check 1 MOCK_NPM_TIME="$(date -d '30 days ago' -Is)" -- \
  demo@1.0.0 --ecosystem npm --gate install
expect_status 0 "release older than the cooldown gates GO"
expect_grep "$OUT_FILE" '^Release age: PASS \(published 30d ago\)' "age is reported"

prepare_case cooldown-lookup-fails
run_check 1 -- demo@1.0.0 --ecosystem npm --gate install
expect_status 0 "missing publish date skips the cooldown without refusing"
expect_grep "$OUT_FILE" '^Release age: SKIP \(publish date unavailable' \
  "cooldown skip is disclosed"

# cooldown_days=0 disables the check entirely (no line, no fetch dependency).
prepare_case cooldown-disabled
printf '{"install": {"cooldown_days": 0}}\n' > "$CASE_RUN_CONFIG/config.json"
run_check 1 MOCK_NPM_TIME="$(date -d '1 hour ago' -Is)" -- \
  demo@1.0.0 --ecosystem npm --gate install
expect_status 0 "cooldown disabled ignores a brand-new release"
if grep -q '^Release age:' "$OUT_FILE"; then
  fail "no release-age line when the cooldown is disabled"
else
  pass "no release-age line when the cooldown is disabled"
fi

if (( FAIL_COUNT > 0 )); then
  printf 'guarddog tier: %d passed, %d failed\n' "$PASS_COUNT" "$FAIL_COUNT" >&2
  exit 1
fi
printf 'guarddog tier: all %d cases passed\n' "$PASS_COUNT"
