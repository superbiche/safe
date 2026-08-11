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
data=""
args=("$@")
i=0
while (( i < ${#args[@]} )); do
  case "${args[$i]}" in
    -H|--max-time) i=$((i + 2)); continue ;;
    -d) data="${args[$((i + 1))]}"; i=$((i + 2)); continue ;;
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
    body_version=$(printf '%s' "$data" | tr -d ' \n' | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')
    if [[ "${MOCK_OSV_AFFECTING:-0}" == "1" ]]; then
      # An open-range advisory affecting every version: the behavioral-ack
      # OSV condition must void the acknowledgement.
      emit '{"vulns":[{"id":"GHSA-affects-all","database_specific":{"severity":"MODERATE"},"affected":[{"package":{"ecosystem":"npm","name":"demo"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}]}'
    elif [[ "${MOCK_OSV_REMEDIATED_AT:-}" != "" && -z "$body_version" ]]; then
      # Advisory introduced earlier and FIXED exactly at the resolved
      # version: the version under audit IS the security fix. BARE drops the
      # introduced event (malformed range with only a fixed token).
      events="{\"introduced\":\"0\"},{\"fixed\":\"${MOCK_OSV_REMEDIATED_AT}\"}"
      [[ "${MOCK_OSV_REMEDIATED_BARE:-0}" == "1" ]] && events="{\"fixed\":\"${MOCK_OSV_REMEDIATED_AT}\"}"
      emit "{\"vulns\":[{\"id\":\"GHSA-fix-here\",\"database_specific\":{\"severity\":\"HIGH\"},\"affected\":[{\"package\":{\"ecosystem\":\"npm\",\"name\":\"${MOCK_OSV_REMEDIATED_NAME:-demo}\"},\"ranges\":[{\"type\":\"SEMVER\",\"events\":[${events}]}]}]}]}"
    else
      emit '{"vulns":[]}'
    fi
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
          if [[ -n "${MOCK_NPM_TIME_MULTI:-}" ]]; then
            emit "{\"dist-tags\":{\"latest\":\"2.5.0\"},\"versions\":{\"1.0.0\":{},\"1.5.0\":{},\"2.0.0\":{},\"2.5.0\":{}},\"time\":{\"1.5.0\":\"${MOCK_NPM_TIME_MULTI%%|*}\",\"2.5.0\":\"${MOCK_NPM_TIME_MULTI##*|}\"}}"
          else
            emit '{"dist-tags":{"latest":"2.5.0"},"versions":{"1.0.0":{},"1.5.0":{},"2.0.0":{},"2.5.0":{}}}'
          fi
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
    case "$url" in
      */1.0.0/json)
        # Per-version endpoint (release-age lookup): .urls carries one entry
        # per distribution file, each with its own upload time.
        old_up="${MOCK_PYPI_UPLOAD_OLD:-}"
        new_up="${MOCK_PYPI_UPLOAD_NEW:-}"
        if [[ -z "$old_up" && -z "$new_up" ]]; then
          emit '{"info":{"version":"1.0.0"},"urls":[]}'
        else
          emit "{\"info\":{\"version\":\"1.0.0\"},\"urls\":[{\"filename\":\"demo-1.0.0.tar.gz\",\"upload_time_iso_8601\":\"${old_up:-$new_up}\"},{\"filename\":\"demo-1.0.0-py3-none-any.whl\",\"upload_time_iso_8601\":\"${new_up:-$old_up}\"}]}"
        fi
        ;;
      *)
        emit "{\"info\":{\"version\":\"1.0.0\"},\"releases\":{\"1.0.0\":[{\"filename\":\"demo-1.0.0.metadata\",\"digests\":{\"sha256\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"}},{\"filename\":\"demo-1.0.0-py3-none-any.whl\",\"digests\":{\"sha256\":\"$digest\"},\"url\":\"https://files.pythonhosted.org/demo.whl\"}]}}"
        ;;
    esac
    ;;
  *) exit 22 ;;
esac
MOCK
chmod +x "$COMMONBIN/curl"

cat > "$COMMONBIN/socket" <<'MOCK'
#!/usr/bin/env bash
[[ -n "${MOCK_SOCKET_ARGS_LOG:-}" ]] && printf '%s\n' "$*" >> "$MOCK_SOCKET_ARGS_LOG"
socket_envelope() {
  local score="$1" alerts="$2"
  printf '{"ok":true,"data":{"purl":"pkg:npm/demo@1.0.0","self":{"alerts":%s,"capabilities":[],"purl":"pkg:npm/demo@1.0.0","score":{"overall":%s,"supplyChain":80,"quality":80,"maintenance":80,"vulnerability":80,"license":80}},"transitively":[]}}\n' "$alerts" "$score"
}
if [[ "${MOCK_SOCKET_MODE:-ok}" == "error" ]]; then
  printf 'socket backend failed\n' >&2
  exit 1
fi
if [[ "${MOCK_SOCKET_MODE:-ok}" == "high-alert" ]]; then
  socket_envelope 20 '[{"name":"didYouMean","severity":"high","category":"supplyChainRisk"}]'
  exit 0
fi
if [[ "${MOCK_SOCKET_MODE:-ok}" == "unknown-severity" ]]; then
  # ok:true envelope whose alert severity is outside Socket's enum: an
  # alert safe cannot classify must veto, never count as not-high
  # (PR#67 F1 delta residual — "HIGH", "urgent", Unicode lookalikes).
  socket_envelope 40 '[{"name":"didYouMean","severity":"HIGH","category":"supplyChainRisk"}]'
  exit 0
fi
if [[ "${MOCK_SOCKET_MODE:-ok}" == "bare" ]]; then
  # Schema-less exit-0 body: says nothing about the package and must never
  # count as the clean second opinion (PR#67 F1).
  printf '{}\n'
  exit 0
fi
case "${MOCK_SOCKET_MODE:-ok}" in
  fresh-timeout-then-ok)
    if [[ -e "${MOCK_SOCKET_STATE:?}" ]]; then
      socket_envelope 82 '[]'
      exit 0
    fi
    : > "${MOCK_SOCKET_STATE}"
    sleep 30
    ;;
  fresh-timeout|hang) sleep 30 ;;
  not-found)
    printf '{"ok":false,"message":"Socket API error","cause":"Not Found (404)","data":{"code":404}}\n'
    exit 1
    ;;
esac
socket_envelope 80 '[]'
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
  if [[ "${MOCK_GUARDDOG_VERSION_SPELLING:-click}" == "bare" ]]; then
    printf '%s\n' "${MOCK_GUARDDOG_VERSION:-3.1.0}"
  else
    printf 'guarddog, version %s\n' "${MOCK_GUARDDOG_VERSION:-3.1.0}"
  fi
  exit 0
fi
[[ -n "${MOCK_GUARDDOG_LOG:-}" ]] && printf '%s\n' "$*" >> "$MOCK_GUARDDOG_LOG"
no_sandbox=0
for a in "$@"; do [[ "$a" == "--no-sandbox" ]] && no_sandbox=1; done
broken_for_version=0
[[ "${MOCK_GUARDDOG_SANDBOX_BROKEN:-0}" == "1" ]] && broken_for_version=1
if [[ -n "${MOCK_GUARDDOG_SANDBOX_BROKEN_VERSION:-}" ]]; then
  broken_for_version=0
  for a in "$@"; do
    [[ "$a" == "${MOCK_GUARDDOG_SANDBOX_BROKEN_VERSION}" ]] && broken_for_version=1
  done
fi
if [[ "$broken_for_version" == "1" && "$no_sandbox" == "0" ]]; then
  printf '{"package": "demo", "issues": 0, "errors": {"download-package": "Sandboxed extraction failed: no entropy"}}\n'
  exit 0
fi
scan_version=""
args=("$@")
for ((i = 0; i < ${#args[@]}; i++)); do
  if [[ "${args[$i]}" == "--version" ]]; then
    scan_version="${args[$((i + 1))]:-}"
    break
  fi
done
case "${MOCK_GUARDDOG_MODE:-clean}" in
  valid-block-with-sandbox-text)
    # Shape-valid, retains a high_risk finding, AND carries an error value
    # containing a fallback marker. The sandboxed attempt must stand.
    if [[ "$no_sandbox" == "1" ]]; then
      printf '{"package":"demo","issues":0,"errors":{},"results":{},"risk_score":{"score":0,"label":"no_risks_detected","findings_count":0,"score_breakdown":{}},"risks":[]}\n'
    else
      printf '{"package":"demo","issues":1,"errors":{"metadata_mismatch":"--no-sandbox"},"results":{},"risk_score":{"score":9,"label":"high_risk","findings_count":1,"score_breakdown":{}},"risks":[{"threat_rule":"threat-exfiltrate-secrets","capability_rule":null}]}\n'
    fi
    exit 0
    ;;
  slow-then-sandbox-fail)
    # Consumes most of the budget, THEN reports a sandbox failure.
    if [[ "$no_sandbox" == "1" ]]; then
      sleep 30
      exit 0
    fi
    sleep 2
    printf '{"package": "demo", "issues": 0, "errors": {"download-package": "Sandboxed extraction failed: no entropy"}}\n'
    exit 0
    ;;
  scan-error-shape)
    # GuardDog's real failure shape: no risk fields, cause in .errors.
    printf '{"package": "demo", "issues": 0, "errors": {"download-package": "Sandboxed extraction failed: no entropy"}}\n'
    exit 0
    ;;
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
  big-internal-write)
    # Simulates the package-tarball download: a >16MiB write to guarddog's
    # own scratch. The retired RLIMIT_FSIZE wrapper killed this as
    # `download-package: [Errno 27] File too large` before any scan ran
    # (qwen-code 0.21.5, 2026-08-04); the pipe-cap bounding must not.
    bigfile="${TMPDIR:-/tmp}/guarddog-mock-big.$$"
    if ! dd if=/dev/zero of="$bigfile" bs=1048576 count=20 2>/dev/null; then
      rm -f "$bigfile"
      printf 'download-package: [Errno 27] File too large\n' >&2
      exit 1
    fi
    rm -f "$bigfile"
    printf '{"issues":0,"errors":{},"results":{},"risk_score":{"score":0.0,"label":"no_risks_detected","findings_count":0,"score_breakdown":{}},"risks":[]}\n'
    ;;
  malformed) printf '{not-json\n' ;;
  error) printf 'registry request failed\n' >&2; exit 1 ;;
  hang) sleep 30 ;;
  stubborn) trap '' TERM; while :; do :; done ;;
  flood)
    # 8 KiB chunks: the flood must cross the 16 MiB cap well inside the
    # case's 1s budget so the size branch (not the timeout branch) is the
    # note under test.
    flood_chunk=$(printf 'x%.0s' {1..8192})
    while :; do printf '%s' "$flood_chunk"; done
    ;;
  flood-stderr)
    # Same flood aimed at stderr: the live cap must stop scratch growth at
    # the per-stream limit instead of letting the flood run its budget
    # against the filesystem (PR#66 F1 delta).
    flood_chunk=$(printf 'x%.0s' {1..8192})
    while :; do printf '%s' "$flood_chunk" >&2; done
    ;;
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
# 1s budget + elapsed bound: the stub's flood loop survives SIGPIPE (bash
# builtin printf), so without the short budget this case burned the full
# 120s production default proving only the wall-clock leash (PR#66 F3).
printf '{"install":{"guarddog":{"timeout_seconds":1}}}\n' > "$CASE_RUN_CONFIG/config.json"
SECONDS=0
run_check 1 MOCK_GUARDDOG_MODE=flood -- demo@1.0.0 --ecosystem npm --json
flood_elapsed=$SECONDS
expect_status 10 "unbounded GuardDog stdout is refused"
# Size-or-timeout: under parallel suite load the 1s budget can expire
# before the flood crosses 16 MiB — which note wins is a race. The exact
# live-cap byte count is pinned by the bounded-capture oracle below.
expect_json '.guarddog.infra_error == true and ((.guarddog.note | contains("output exceeded the 16384 KiB per-stream limit")) or (.guarddog.note | contains("timed out"))) and .guarddog.cache.misses == 0' \
  "GuardDog output bound becomes uncached infrastructure evidence"
(( flood_elapsed < 10 )) && pass "flood refusal stays wall-clock bounded" || fail "flood refusal stays wall-clock bounded"

prepare_case stderr-output-bound
printf '{"install":{"guarddog":{"timeout_seconds":1}}}\n' > "$CASE_RUN_CONFIG/config.json"
SECONDS=0
run_check 1 MOCK_GUARDDOG_MODE=flood-stderr -- demo@1.0.0 --ecosystem npm --json
stderr_flood_elapsed=$SECONDS
expect_status 10 "unbounded GuardDog stderr is refused"
expect_json '.guarddog.infra_error == true and ((.guarddog.note | contains("per-stream limit")) or (.guarddog.note | contains("timed out")))' \
  "stderr flood lands on a legible size or timeout note"
(( stderr_flood_elapsed < 10 )) && pass "stderr flood refusal stays wall-clock bounded" || fail "stderr flood refusal stays wall-clock bounded"

# --- behavioral acknowledgement (operator FP lane, ruled 2026-08-04) ---------
# A GuardDog BLOCK downgrades to a host-allowable WARN only via an operator
# behavioral_ack pinned to exactly this version, with the live rule set a
# subset of the acknowledged one, a clean forced Socket second opinion, and
# zero affecting OSV advisories.
ack_full_rules='["capability-network-outbound","threat-network-exfiltration","threat-runtime-obfuscation-general"]'
write_ack_entry() {
  printf '{"packages":{"demo":{"version":"%s","sha":"","ecosystem":"npm","added":"2026-08-04","reason":"fp","behavioral_ack":{"rules":%s,"added":"2026-08-04"}}}}\n' \
    "$1" "$2" > "$CASE_RUN_CONFIG/host-allow.json"
}

prepare_case ack-engages
write_ack_entry 1.0.0 "$ack_full_rules"
run_check 1 MOCK_GUARDDOG_MODE=block MOCK_SOCKET_ARGS_LOG="$CASE_DIR/socket-args.log" -- \
  demo@1.0.0 --ecosystem npm --json
expect_status 10 "acknowledged high-risk findings downgrade BLOCK to WARN"
expect_json '.verdict == "WARN" and (.warn_causes | index("guarddog_high_risk_acknowledged") != null) and ((.warn_causes | index("guarddog_high_risk")) == null)' \
  "the downgrade is explicit in warn_causes, never an erased finding"
expect_grep "$OUT_FILE" 'acknowledged by operator' "guarddog line names the acknowledgement"
[[ -s "$CASE_DIR/socket-args.log" ]] && pass "the ack forces the Socket second opinion (no tier-3 skip)" \
  || fail "the ack forces the Socket second opinion (no tier-3 skip)"

prepare_case ack-gate-allows
write_ack_entry 1.0.0 "$ack_full_rules"
run_check 1 MOCK_GUARDDOG_MODE=block -- demo@1.0.0 --ecosystem npm --gate install --json
expect_status 0 "gate allows the acknowledged version through the same host-allow entry"
expect_grep "$ERR_FILE" 'host-allow entry demo@1.0.0' "gate names the authorizing entry"

prepare_case ack-new-rule-veto
write_ack_entry 1.0.0 '["threat-network-exfiltration"]'
run_check 1 MOCK_GUARDDOG_MODE=block -- demo@1.0.0 --ecosystem npm --json
expect_status 20 "rules outside the acknowledged set keep the BLOCK"
expect_grep "$OUT_FILE" 'behavioral acknowledgement NOT applied — rules not covered' \
  "the veto names the uncovered rules"

prepare_case ack-socket-unavailable-veto
write_ack_entry 1.0.0 "$ack_full_rules"
run_check 1 MOCK_GUARDDOG_MODE=block MOCK_SOCKET_MODE=error -- demo@1.0.0 --ecosystem npm --json
expect_status 20 "no Socket second opinion, no downgrade"
expect_grep "$OUT_FILE" 'requires a Socket second opinion' "the veto names the missing second opinion"

prepare_case ack-socket-pending-veto
write_ack_entry 1.0.0 "$ack_full_rules"
printf '{"install":{"socket":{"fresh_scan_budget_seconds":1}}}\n' > "$CASE_RUN_CONFIG/config.json"
run_check 1 \
  MOCK_GUARDDOG_MODE=block \
  MOCK_NPM_TIME="$(date -d '1 hour ago' -Is)" \
  MOCK_OSV_REMEDIATED_AT=1.0.0 \
  MOCK_SOCKET_MODE=fresh-timeout \
  SAFE_AUDIT_SOCKET_TIMEOUT=1 -- \
  demo@1.0.0 --ecosystem npm --gate install --json
expect_status 20 "pending Socket score vetoes a behavioral acknowledgement"
expect_json '.verdict == "BLOCK" and .socket.status == "pending"
  and (.warn_causes | index("socket_score_pending") != null)
  and (.warn_causes | index("guarddog_high_risk") != null)' \
  "pending receipt retains the missing second-opinion cause and BLOCK"
expect_grep "$OUT_FILE" 'requires a Socket second opinion' \
  "pending Socket state is not accepted as acknowledgement evidence"

prepare_case ack-socket-high-alert-veto
write_ack_entry 1.0.0 "$ack_full_rules"
run_check 1 MOCK_GUARDDOG_MODE=block MOCK_SOCKET_MODE=high-alert -- demo@1.0.0 --ecosystem npm --json
expect_status 20 "a high-severity Socket alert vetoes the downgrade"
expect_grep "$OUT_FILE" 'Socket reports high-severity alerts' "the veto names the Socket alerts"

prepare_case ack-osv-void
write_ack_entry 1.0.0 "$ack_full_rules"
run_check 1 MOCK_GUARDDOG_MODE=block MOCK_OSV_AFFECTING=1 -- demo@1.0.0 --ecosystem npm --json
expect_status 20 "an affecting OSV advisory voids the acknowledgement"
expect_grep "$OUT_FILE" 'behavioral acknowledgement void' "the void names the OSV condition"
expect_json '((.warn_causes | index("guarddog_high_risk_acknowledged")) == null) and ((.warn_causes | index("guarddog_high_risk")) != null)' \
  "the voided receipt carries no acknowledged cause (PR#67 F4)"

prepare_case ack-socket-bare-veto
write_ack_entry 1.0.0 "$ack_full_rules"
run_check 1 MOCK_GUARDDOG_MODE=block MOCK_SOCKET_MODE=bare -- demo@1.0.0 --ecosystem npm --json
expect_status 20 "a schema-less Socket success is a vacuous second opinion, not a clean one"
expect_grep "$OUT_FILE" 'unrecognized result' "the veto names the unrecognized Socket envelope (PR#67 F1)"

prepare_case ack-unknown-severity-veto
write_ack_entry 1.0.0 "$ack_full_rules"
run_check 1 MOCK_GUARDDOG_MODE=block MOCK_SOCKET_MODE=unknown-severity -- demo@1.0.0 --ecosystem npm --json
expect_status 20 "an out-of-enum Socket severity is unclassifiable, not clean"
expect_grep "$OUT_FILE" 'unrecognized result' "the veto treats unknown severities as an unrecognized envelope"
expect_json '.checks.socket | startswith("WARN (socket returned an unrecognized result")' \
  "the Socket line matches the veto instead of claiming PASS"

prepare_case ack-vetoed-entry-suppresses-hint
write_ack_entry 1.0.0 "$ack_full_rules"
run_check 1 MOCK_GUARDDOG_MODE=block MOCK_SOCKET_MODE=high-alert -- demo@1.0.0 --ecosystem npm --gate install --json
expect_status 20 "a Socket-vetoed acknowledgement still refuses at the gate"
if grep -q 'acknowledge-behavioral' "$ERR_FILE"; then
  printf 'stderr:\n%s\n' "$(cat "$ERR_FILE")" >&2
  fail "no add-suggestion while a vetoed entry already exists (PR#67 F5 delta)"
else
  pass "no add-suggestion while a vetoed entry already exists (PR#67 F5 delta)"
fi

prepare_case ack-partial-scan-veto
write_ack_entry 1.0.0 "$ack_full_rules"
run_check 1 MOCK_GUARDDOG_MODE=partial-block -- demo@1.0.0 --ecosystem npm --json
expect_status 20 "an incomplete GuardDog scan is never ack-eligible (PR#67 F2)"
expect_json '((.warn_causes | index("guarddog_high_risk_acknowledged")) == null) and ((.warn_causes | index("guarddog_high_risk")) != null)' \
  "the partial scan keeps the plain BLOCK cause"

prepare_case ack-partial-scan-suppresses-hint
run_check 1 MOCK_GUARDDOG_MODE=partial-block -- demo@1.0.0 --ecosystem npm --gate install --json
expect_status 20 "a partial high-risk scan still refuses at the gate"
if grep -q 'acknowledge-behavioral' "$ERR_FILE"; then
  printf 'stderr:\n%s\n' "$(cat "$ERR_FILE")" >&2
  fail "no add-suggestion for a scan an ack can never engage on (PR#67 F5 delta-2)"
else
  pass "no add-suggestion for a scan an ack can never engage on (PR#67 F5 delta-2)"
fi

prepare_case ack-uncovered-rules-refresh-hint
write_ack_entry 1.0.0 '["threat-network-exfiltration"]'
run_check 1 MOCK_GUARDDOG_MODE=block -- demo@1.0.0 --ecosystem npm --gate install --json
expect_status 20 "uncovered rules refuse at the gate"
expect_grep "$ERR_FILE" 'acknowledge-behavioral' \
  "the uncovered-rules veto keeps the refresh command — re-adding IS its recovery (PR#67 delta-2 N1)"

prepare_case ack-uncovered-plus-socket-veto-suppresses-hint
write_ack_entry 1.0.0 '["threat-network-exfiltration"]'
run_check 1 MOCK_GUARDDOG_MODE=block MOCK_SOCKET_MODE=high-alert -- demo@1.0.0 --ecosystem npm --gate install --json
expect_status 20 "coexisting rule and Socket vetoes still refuse"
if grep -q 'acknowledge-behavioral' "$ERR_FILE"; then
  printf 'stderr:\n%s\n' "$(cat "$ERR_FILE")" >&2
  fail "re-add cannot repair the Socket veto — no refresh hint beside it (PR#67 delta-3 N2)"
else
  pass "re-add cannot repair the Socket veto — no refresh hint beside it (PR#67 delta-3 N2)"
fi
run_check 1 MOCK_GUARDDOG_MODE=block MOCK_SOCKET_MODE=high-alert -- demo@1.0.0 --ecosystem npm --json
expect_grep "$OUT_FILE" 'rules not covered by the acknowledgement.*Socket reports high-severity alerts' \
  "the veto text names BOTH standing reasons"

prepare_case ack-hint-suppressed-beside-independent-block
run_check 1 MOCK_GUARDDOG_MODE=block MOCK_OSV_AFFECTING=1 -- demo@1.0.0 --ecosystem npm --gate install --json
expect_status 20 "combined guarddog + affecting-advisory BLOCK still refuses"
if grep -q 'acknowledge-behavioral' "$ERR_FILE"; then
  printf 'stderr:\n%s\n' "$(cat "$ERR_FILE")" >&2
  fail "no FP-lane hint beside a BLOCK the acknowledgement cannot clear (PR#67 F5)"
else
  pass "no FP-lane hint beside a BLOCK the acknowledgement cannot clear (PR#67 F5)"
fi

prepare_case ack-version-mismatch
write_ack_entry 2.0.0 "$ack_full_rules"
run_check 1 MOCK_GUARDDOG_MODE=block -- demo@1.0.0 --ecosystem npm --json
expect_status 20 "an ack pinned to another version never matches"
expect_json '(.warn_causes | index("guarddog_high_risk")) != null' \
  "the mismatched ack leaves the plain BLOCK cause"

prepare_case ack-hint
run_check 1 MOCK_GUARDDOG_MODE=block -- demo@1.0.0 --ecosystem npm --gate install --json
expect_status 20 "unacknowledged high-risk findings still BLOCK at the gate"
expect_grep "$ERR_FILE" 'acknowledge-behavioral' \
  "the gate refusal names the operator FP lane recipe"

# Direct oracle for guarddog_bounded_capture (PR#66 N1): the downstream
# receipt cannot distinguish a live cap from an unbounded write a later
# consumer shrank, and an inner (stderr-head) capture failure must be
# visible in the three-status contract, not silently discarded.
prepare_case bounded-capture-oracle
cap_out="$CASE_DIR/cap.out"
cap_err="$CASE_DIR/cap.err"
cap_st="$CASE_DIR/cap.status"
probe_capture() {
  # Hermetic source: SAFE_AUDIT_NO_INIT=1 keeps `main help` from seeding
  # config/data trees, and the scratch HOME + dir overrides keep any stray
  # write inside the case (PR#66 delta-3 N3 — the probe touched the real
  # ~/.config/safe on an uninitialized host).
  SA="$SAFE_AUDIT" OUT="$cap_out" ERR="${2:-$cap_err}" ST="$cap_st" MODE="$1" \
    SAFE_AUDIT_NO_INIT=1 HOME="$CASE_HOME" \
    SAFE_RUN_CONFIG_DIR="$CASE_RUN_CONFIG" \
    SAFE_AUDIT_CONFIG_DIR="$CASE_DIR/audit-config" \
    SAFE_AUDIT_DATA_DIR="$CASE_DIR/audit-data" \
    bash -c '
    set -euo pipefail
    source "$SA" help >/dev/null 2>&1
    case "$MODE" in
      clean)
        producer() { printf "hello\n" >&2; printf "{}"; }
        ;;
      stderr-flood)
        producer() {
          chunk=$(printf "x%.0s" {1..8192})
          for ((i = 0; i < 3000; i++)); do
            printf "%s" "$chunk" >&2 || exit 141
          done
          printf "{}"
        }
        ;;
    esac
    guarddog_bounded_capture "$OUT" "$ERR" "$ST" producer
    printf "%s|%s|%s\n" "${GUARDDOG_CAPTURE[0]:-x}" "${GUARDDOG_CAPTURE[1]:-x}" "${GUARDDOG_CAPTURE[2]:-x}"
  ' 2>/dev/null
}

got="$(probe_capture clean)"
[[ "$got" == "0|0|0" ]] && pass "bounded capture reports a clean three-status contract" || { printf 'got %s\n' "$got" >&2; fail "bounded capture reports a clean three-status contract"; }
grep -q hello "$cap_err" && grep -q '{}' "$cap_out" \
  && pass "bounded capture keeps the streams separated" || fail "bounded capture keeps the streams separated"

got="$(probe_capture stderr-flood)"
[[ "$got" == "141|0|0" ]] && pass "a stderr flood dies on the closed cap, statuses intact" || { printf 'got %s\n' "$got" >&2; fail "a stderr flood dies on the closed cap, statuses intact"; }
cap_err_size=$(stat -c %s "$cap_err")
[[ "$cap_err_size" == "16777216" ]] && pass "stderr capture is live-capped at exactly the per-stream limit" || { printf 'stderr size %s\n' "$cap_err_size" >&2; fail "stderr capture is live-capped at exactly the per-stream limit"; }

got="$(probe_capture clean /dev/full)"
[[ "$got" == "0|0|1" ]] && pass "an inner stderr-head failure is visible in the contract" || { printf 'got %s\n' "$got" >&2; fail "an inner stderr-head failure is visible in the contract"; }

# Direct safe-audit coverage of the version-probe pipeline's failure paths:
# the doctor cases exercising these mock modes run bin/safe's SEPARATE
# implementation, so the changed check-side probe had none (PR#66 F4).
prepare_case version-probe-error
run_check 1 MOCK_GUARDDOG_VERSION_MODE=valid-error -- demo@1.0.0 --ecosystem npm --json
expect_status 10 "a version probe that exits nonzero after a valid banner is infra failure"
expect_json '.guarddog.infra_error == true and (.guarddog.note | contains("guarddog version check failed (exit 7)"))' \
  "probe exit status is captured through the pipe, not read off the banner"

prepare_case version-probe-flood
printf '{"install":{"guarddog":{"timeout_seconds":1}}}\n' > "$CASE_RUN_CONFIG/config.json"
SECONDS=0
run_check 1 MOCK_GUARDDOG_VERSION_MODE=valid-flood -- demo@1.0.0 --ecosystem npm --json
version_flood_elapsed=$SECONDS
expect_status 10 "a flooding version probe is refused"
expect_json '.guarddog.infra_error == true and ((.guarddog.note | contains("per-stream limit")) or (.guarddog.note | contains("timed out")))' \
  "flooding probe lands on a legible size or timeout note"
(( version_flood_elapsed < 10 )) && pass "flooding version probe stays wall-clock bounded" || fail "flooding version probe stays wall-clock bounded"

prepare_case version-probe-stubborn
printf '{"install":{"guarddog":{"timeout_seconds":1}}}\n' > "$CASE_RUN_CONFIG/config.json"
SECONDS=0
run_check 1 MOCK_GUARDDOG_VERSION_MODE=valid-stubborn -- demo@1.0.0 --ecosystem npm --json
version_stubborn_elapsed=$SECONDS
expect_status 10 "a TERM-resistant version probe is force-killed and refused"
expect_json '.guarddog.infra_error == true and (.guarddog.note | contains("timed out after 1s"))' \
  "forced probe kill keeps the timeout diagnosis"
(( version_stubborn_elapsed < 10 )) && pass "TERM-resistant version probe stays wall-clock bounded" || fail "TERM-resistant version probe stays wall-clock bounded"

prepare_case big-internal-write
run_check 1 MOCK_GUARDDOG_MODE=big-internal-write -- demo@1.0.0 --ecosystem npm --json
expect_status 0 "a >16MiB internal write (tarball download) no longer kills the scan"
expect_json '.verdict == "GO" and .guarddog.status == "ok" and (.guarddog.infra_error // false) == false' \
  "large-package behavioral coverage is real, not an EFBIG infra WARN"

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

# A first Socket timeout for a young security-fix release gets one extended,
# still-bounded score attempt. A real envelope from that retry is evidence,
# not a pending waiver.
prepare_case socket-fresh-retry-success
printf '{"install":{"socket":{"mode":"always","fresh_scan_budget_seconds":1}}}\n' > "$CASE_RUN_CONFIG/config.json"
run_check 1 \
  MOCK_NPM_TIME="$(date -d '1 hour ago' -Is)" \
  MOCK_OSV_REMEDIATED_AT=1.0.0 \
  MOCK_SOCKET_MODE=fresh-timeout-then-ok \
  MOCK_SOCKET_STATE="$CASE_DIR/socket-state" \
  MOCK_SOCKET_ARGS_LOG="$CASE_DIR/socket-args.log" \
  SAFE_AUDIT_SOCKET_TIMEOUT=1 -- \
  demo@1.0.0 --ecosystem npm --gate install --json
expect_status 0 "young Socket timeout retries into a scored GO"
expect_json '.verdict == "GO" and .socket.status == "ok"
  and .socket.raw.data.self.score.overall == 82 and .warn_causes == []' \
  "retry receipt preserves the real Socket score"
if [[ "$(wc -l < "$CASE_DIR/socket-args.log")" == "2" ]]; then
  pass "fresh score path makes exactly one retry"
else
  fail "fresh score path makes exactly one retry"
fi

# When that extended retry also times out, clean GuardDog, OSV, and blocklist
# evidence permit a disclosed GO. Install-known must retain PENDING, never
# misstate that a clean Socket score was obtained.
prepare_case socket-fresh-pending-clean
printf '{"install":{"socket":{"mode":"always","fresh_scan_budget_seconds":1}}}\n' > "$CASE_RUN_CONFIG/config.json"
run_check 1 \
  MOCK_NPM_TIME="$(date -d '1 hour ago' -Is)" \
  MOCK_OSV_REMEDIATED_AT=1.0.0 \
  MOCK_SOCKET_MODE=fresh-timeout \
  SAFE_AUDIT_SOCKET_TIMEOUT=1 -- \
  demo@1.0.0 --ecosystem npm --gate install --json
expect_status 0 "clean fresh score pending still gates GO"
expect_json '.verdict == "GO" and .socket.status == "pending"
  and (.checks.socket | startswith("PENDING (fresh release 1.0.0"))
  and .warn_causes == []' \
  "pending score is disclosed without an infrastructure WARN"
if jq -e '.packages["npm:demo"].reasons | index("socket_score_pending") != null' \
  "$CASE_RUN_CONFIG/install-known.json" >/dev/null 2>&1; then
  pass "GO evidence records the pending Socket state honestly"
else
  fail "GO evidence records the pending Socket state honestly"
fi
# Pending-score evidence is not fully clean: the offline stale-evidence
# fallback in gate-lib selects verdict == "GO" only, so the record must
# carry the distinct verdict (same exclusion principle as WARN_TOLERATED).
if jq -e '.packages["npm:demo"].verdict == "GO_PENDING_SOCKET"' \
  "$CASE_RUN_CONFIG/install-known.json" >/dev/null 2>&1; then
  pass "pending GO records a distinct verdict excluded from the offline fallback"
else
  fail "pending GO records a distinct verdict excluded from the offline fallback"
fi

prepare_case socket-fresh-pending-guarddog-error
printf '{"install":{"socket":{"fresh_scan_budget_seconds":1}}}\n' > "$CASE_RUN_CONFIG/config.json"
run_check 1 \
  MOCK_NPM_TIME="$(date -d '1 hour ago' -Is)" \
  MOCK_OSV_REMEDIATED_AT=1.0.0 \
  MOCK_GUARDDOG_MODE=error \
  MOCK_SOCKET_MODE=fresh-timeout \
  SAFE_AUDIT_SOCKET_TIMEOUT=1 -- \
  demo@1.0.0 --ecosystem npm --json
expect_status 10 "pending score beside GuardDog failure remains WARN"
expect_json '.verdict == "WARN" and .socket.status == "pending"
  and (.warn_causes | index("guarddog_error") != null)
  and (.warn_causes | index("socket_score_pending") != null)' \
  "pending cause is explicit when companion evidence is incomplete"

prepare_case socket-old-timeout
printf '{"install":{"socket":{"mode":"always","fresh_scan_budget_seconds":1}}}\n' > "$CASE_RUN_CONFIG/config.json"
run_check 1 \
  MOCK_NPM_TIME="$(date -d '30 days ago' -Is)" \
  MOCK_SOCKET_MODE=fresh-timeout \
  MOCK_SOCKET_ARGS_LOG="$CASE_DIR/socket-args.log" \
  SAFE_AUDIT_SOCKET_TIMEOUT=1 -- \
  demo@1.0.0 --ecosystem npm --json
expect_status 10 "old Socket timeout keeps the infrastructure WARN"
expect_json '.socket.status == "error" and (.warn_causes | index("socket_error") != null)
  and ((.warn_causes | index("socket_score_pending")) == null)' \
  "old timeout remains socket_error, not pending"
if [[ "$(wc -l < "$CASE_DIR/socket-args.log")" == "1" ]]; then
  pass "old score timeout does not use the fresh retry"
else
  fail "old score timeout does not use the fresh retry"
fi

prepare_case socket-fresh-404
printf '{"install":{"socket":{"mode":"always","fresh_scan_budget_seconds":1}}}\n' > "$CASE_RUN_CONFIG/config.json"
run_check 1 \
  MOCK_NPM_TIME="$(date -d '1 hour ago' -Is)" \
  MOCK_OSV_REMEDIATED_AT=1.0.0 \
  MOCK_SOCKET_MODE=not-found \
  MOCK_SOCKET_ARGS_LOG="$CASE_DIR/socket-args.log" -- \
  demo@1.0.0 --ecosystem npm --json
expect_status 10 "Socket 404 remains an infrastructure error"
expect_json '.socket.status == "error" and (.socket.note | contains("404"))
  and (.warn_causes | index("socket_error") != null)
  and ((.warn_causes | index("socket_score_pending")) == null)' \
  "404 never masquerades as a fresh-score pending state"
if [[ "$(wc -l < "$CASE_DIR/socket-args.log")" == "1" ]]; then
  pass "404 does not use the fresh retry"
else
  fail "404 does not use the fresh retry"
fi

# --- review closures (PR#60 round 1) ----------------------------------------

# F1: a PyPI release that gained a fresh wheel is as new as that wheel — an
# old sdist in the same release must not lend it age.
prepare_case cooldown-pypi-newest-file
run_check 1 MOCK_PYPI_UPLOAD_OLD="$(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%S.%6NZ)" \
  MOCK_PYPI_UPLOAD_NEW="$(date -u -d '1 day ago' +%Y-%m-%dT%H:%M:%S.%6NZ)" -- \
  demo@1.0.0 --ecosystem python --gate install
expect_status 10 "newest PyPI distribution upload anchors the release age"
expect_grep "$OUT_FILE" '^Release age: WARN' "fresh wheel beside an old sdist warns"

prepare_case cooldown-pypi-all-old
run_check 1 MOCK_PYPI_UPLOAD_OLD="$(date -u -d '40 days ago' +%Y-%m-%dT%H:%M:%S.%6NZ)" \
  MOCK_PYPI_UPLOAD_NEW="$(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%S.%6NZ)" -- \
  demo@1.0.0 --ecosystem python --gate install
expect_status 0 "a wholly old PyPI release passes the cooldown"

# F2: learning that a pin is too new must revoke stale clean evidence, or the
# timeout fallback would reuse the superseded GO.
prepare_case cooldown-revokes-stale-go
mkdir -p "$CASE_RUN_CONFIG"
cat > "$CASE_RUN_CONFIG/install-known.json" <<'JSON'
{"packages":{"npm:demo":{"version":"1.0.0","verdict":"GO","reasons":["osv_clean_for_version"],"evidence":"seeded","source":"implicit-default","first_allowed":"2026-08-01T00:00:00+02:00","last_used":"2026-08-01","times_used":1}}}
JSON
run_check 1 MOCK_NPM_TIME="$(date -d '1 day ago' -Is)" -- \
  demo@1.0.0 --ecosystem npm --gate install
expect_status 10 "cooldown WARN refuses despite a seeded clean entry"
if jq -e '.packages["npm:demo"]' "$CASE_RUN_CONFIG/install-known.json" >/dev/null 2>&1; then
  cat "$CASE_RUN_CONFIG/install-known.json" >&2
  fail "cooldown WARN revokes the stale install-known GO"
else
  pass "cooldown WARN revokes the stale install-known GO"
fi

# Tolerating the cause must record WHAT was tolerated (not merely exit 0).
prepare_case cooldown-tolerated-records-cause
printf '{"install": {"auto_allow_tolerate": ["release_too_new"]}}\n' > "$CASE_RUN_CONFIG/config.json"
run_check 1 MOCK_NPM_TIME="$(date -d '1 day ago' -Is)" -- \
  demo@1.0.0 --ecosystem npm --gate install --json
expect_status 0 "tolerated cooldown allows the exact version"
expect_json '(.warn_causes | index("release_too_new") != null) and .verdict == "WARN"' \
  "receipt still records the tolerated cooldown cause"
if jq -e '.packages["npm:demo"] | .verdict == "WARN_TOLERATED"
  and (.reasons | index("release_too_new") != null)' \
  "$CASE_RUN_CONFIG/install-known.json" >/dev/null 2>&1; then
  pass "tolerated record is not disguised as clean evidence"
else
  cat "$CASE_RUN_CONFIG/install-known.json" >&2 || true
  fail "tolerated record is not disguised as clean evidence"
fi

# F3: a deliberate skip must never render as an outage on either surface.
prepare_case tier3-skip-not-an-outage
run_check 1 -- demo@1.0.0 --ecosystem npm
expect_status 0 "clean tier-3 check succeeds"
if grep -q 'socket CLI not available' "$OUT_FILE"; then
  cat "$OUT_FILE" >&2
  fail "tier-3 skip does not print the CLI-unavailable outage warning"
else
  pass "tier-3 skip does not print the CLI-unavailable outage warning"
fi

prepare_case tier3-never-not-an-outage
printf '{"install": {"socket": {"mode": "never"}}}\n' > "$CASE_RUN_CONFIG/config.json"
run_check 1 -- demo@1.0.0 --ecosystem npm
if grep -q 'socket CLI not available' "$OUT_FILE"; then
  fail "mode=never does not print the CLI-unavailable outage warning"
else
  pass "mode=never does not print the CLI-unavailable outage warning"
fi

# A genuinely absent CLI must still warn (the discriminator must not silence it).
prepare_case socket-absent-still-warns
printf '{"install": {"guarddog": {"enabled": false}}}\n' > "$CASE_RUN_CONFIG/config.json"
(
  cd "$CASE_DIR/project" || exit 99
  env HOME="$CASE_HOME" PATH="/usr/bin:/bin" \
    SAFE_RUN_CONFIG_DIR="$CASE_RUN_CONFIG" \
    SAFE_AUDIT_CONFIG_DIR="$CASE_DIR/audit-config" \
    SAFE_AUDIT_DATA_DIR="$CASE_DIR/audit-data" \
    "$SAFE_AUDIT" check demo@1.0.0 --ecosystem npm
) > "$CASE_DIR/stdout.log" 2>&1 || true
if grep -q 'socket CLI not available' "$CASE_DIR/stdout.log"; then
  pass "a truly missing socket CLI still reports the outage"
else
  cat "$CASE_DIR/stdout.log" >&2
  fail "a truly missing socket CLI still reports the outage"
fi

# F4: socket-consultation matrix across every GuardDog conclusiveness state.
# ok -> skip; every other status -> consult.
for gd_case in \
  "clean:ok:skip" \
  "error:error:consult" \
  "partial-block:partial:consult"
do
  gd_mode="${gd_case%%:*}"
  rest="${gd_case#*:}"
  gd_status="${rest%%:*}"
  expectation="${rest##*:}"
  prepare_case "tier3-matrix-$gd_mode"
  run_check 1 MOCK_GUARDDOG_MODE="$gd_mode" MOCK_SOCKET_ARGS_LOG="$CASE_DIR/socket-args.log" -- \
    demo@1.0.0 --ecosystem npm --json
  if jq -e --arg s "$gd_status" '.guarddog.status == $s' "$OUT_FILE" >/dev/null 2>&1; then
    pass "matrix $gd_mode yields guarddog status $gd_status"
  else
    jq -r '.guarddog.status' "$OUT_FILE" >&2 || true
    fail "matrix $gd_mode yields guarddog status $gd_status"
  fi
  if [[ "$expectation" == "consult" ]]; then
    if [[ -s "$CASE_DIR/socket-args.log" ]]; then
      pass "matrix $gd_mode (status $gd_status) consults socket"
    else
      fail "matrix $gd_mode (status $gd_status) consults socket"
    fi
  else
    if [[ -s "$CASE_DIR/socket-args.log" ]]; then
      fail "matrix $gd_mode (status $gd_status) skips socket"
    else
      pass "matrix $gd_mode (status $gd_status) skips socket"
    fi
  fi
done

# not_applicable (non-npm/PyPI ecosystem) and disabled must both consult.
prepare_case tier3-matrix-not-applicable
run_check 1 MOCK_SOCKET_ARGS_LOG="$CASE_DIR/socket-args.log" -- \
  libc@0.2.150 --ecosystem rust --json
if jq -e '.guarddog.status == "not_applicable"' "$OUT_FILE" >/dev/null 2>&1 \
  && [[ -s "$CASE_DIR/socket-args.log" ]]; then
  pass "not_applicable ecosystem keeps socket coverage"
else
  jq -r '.guarddog.status' "$OUT_FILE" >&2 || true
  fail "not_applicable ecosystem keeps socket coverage"
fi

prepare_case tier3-matrix-disabled
printf '{"install": {"guarddog": {"enabled": false}}}\n' > "$CASE_RUN_CONFIG/config.json"
run_check 1 MOCK_SOCKET_ARGS_LOG="$CASE_DIR/socket-args.log" -- \
  demo@1.0.0 --ecosystem npm --json
if jq -e '.guarddog.status == "disabled"' "$OUT_FILE" >/dev/null 2>&1 \
  && [[ -s "$CASE_DIR/socket-args.log" ]]; then
  pass "disabled behavioral tier keeps socket coverage"
else
  fail "disabled behavioral tier keeps socket coverage"
fi

# Cooldown edges: boundary day, future timestamp, offset timezone, and the
# multi-version minimum age driving the all-versions host-allow scope.
# Exactly 3*86400s old: derived from one captured epoch so neither the local
# time of day nor a DST transition decides which side of the boundary is
# tested (review F5). A few seconds past the boundary keeps age == 3.
prepare_case cooldown-boundary
BOUNDARY_EPOCH=$(( $(date +%s) - 3 * 86400 - 60 ))
run_check 1 MOCK_NPM_TIME="$(date -u -d "@$BOUNDARY_EPOCH" +%Y-%m-%dT%H:%M:%SZ)" -- \
  demo@1.0.0 --ecosystem npm --gate install
expect_status 0 "a release exactly at the cooldown boundary passes"
expect_grep "$OUT_FILE" '^Release age: PASS \(published 3d ago\)' \
  "the boundary case really sits at the boundary"

# One minute inside the boundary must warn — the pair pins the comparison.
prepare_case cooldown-just-inside-boundary
INSIDE_EPOCH=$(( $(date +%s) - 3 * 86400 + 60 ))
run_check 1 MOCK_NPM_TIME="$(date -u -d "@$INSIDE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)" -- \
  demo@1.0.0 --ecosystem npm --gate install
expect_status 10 "one minute short of the cooldown still warns"
expect_grep "$OUT_FILE" 'published 2d ago' "just-inside case reports age 2"

prepare_case cooldown-future-timestamp
run_check 1 MOCK_NPM_TIME="$(date -d '2 days' -Is)" -- \
  demo@1.0.0 --ecosystem npm --gate install
expect_status 10 "a future publish timestamp clamps to age 0 and warns"
expect_grep "$OUT_FILE" 'published 0d ago' "future timestamp is clamped, not negative"

prepare_case cooldown-offset-timezone
run_check 1 MOCK_NPM_TIME="$(date -u -d '1 day ago' +%Y-%m-%dT%H:%M:%S+05:30)" -- \
  demo@1.0.0 --ecosystem npm --gate install
expect_status 10 "an offset-bearing publish timestamp is parsed, not ignored"

prepare_case cooldown-multiversion-min-age
printf '{"dependencies":{"multi":"^1.0.0"}}\n' > "$CASE_DIR/project/package.json"
printf '{"packages":{"node_modules/consumer":{"dependencies":{"multi":"^2.0.0"}}}}\n' > "$CASE_DIR/project/package-lock.json"
printf '{"packages":{"multi":{"version":"2.5.0","ecosystem":"npm"}}}\n' \
  > "$CASE_RUN_CONFIG/host-allow.json"
run_check 1 MOCK_PACKUMENT_MODE=multi \
  MOCK_NPM_TIME_MULTI="$(date -d '40 days ago' -Is)|$(date -d '1 day ago' -Is)" -- \
  multi --ecosystem npm --op update --project-dir "$CASE_DIR/project" --gate install
expect_status 10 "the youngest resolved version drives the cooldown and one pin cannot cover all versions"
expect_grep "$OUT_FILE" '^Release age: WARN \(2\.5\.0 published' \
  "the release line names the youngest resolved version"

# The real guarddog 3.1.0 prints a BARE version; parsing only Click's
# "prog, version x" form made a correct install read as unsupported, which
# silently disabled the tier (live adoption 2026-08-03).
prepare_case version-bare-spelling
run_check 1 MOCK_GUARDDOG_VERSION_SPELLING=bare MOCK_SOCKET_ARGS_LOG="$CASE_DIR/socket-args.log" -- \
  demo@1.0.0 --ecosystem npm --gate install --json
expect_status 0 "a bare-version guarddog is accepted"
expect_json '.guarddog.status == "ok" and .guarddog.scanner_version == "3.1.0"' \
  "bare version parses into the supported scanner version"
if [[ -s "$CASE_DIR/socket-args.log" ]]; then
  fail "bare-version guarddog still drives the tier-3 socket skip"
else
  pass "bare-version guarddog still drives the tier-3 socket skip"
fi

prepare_case version-bare-unsupported
run_check 1 MOCK_GUARDDOG_VERSION_SPELLING=bare MOCK_GUARDDOG_VERSION=4.0.0 -- \
  demo@1.0.0 --ecosystem npm --json
expect_json '.guarddog.status == "error" and (.guarddog.note | contains("unsupported guarddog version 4.0.0"))' \
  "an unsupported bare version is still refused by version"

# GuardDog's own error envelope must surface its cause, not read as a parser
# complaint (live: sandboxed extraction failure returns {package,issues,errors}).
prepare_case scan-error-shape-names-cause
run_check 1 MOCK_GUARDDOG_MODE=scan-error-shape MOCK_SOCKET_ARGS_LOG="$CASE_DIR/socket-args.log" -- \
  demo@1.0.0 --ecosystem npm --json
expect_json '.guarddog.status == "error"
  and (.guarddog.note | contains("Sandboxed extraction failed"))
  and (.guarddog.note | contains("download-package"))' \
  "guarddog error envelope names the underlying cause"
if [[ -s "$CASE_DIR/socket-args.log" ]]; then
  pass "an errored behavioral scan falls back to socket (tier-3 contract)"
else
  fail "an errored behavioral scan falls back to socket (tier-3 contract)"
fi

# --- sandbox fallback (operator ruling 2026-08-03) ---------------------------

# auto: a broken kernel sandbox retries once with --no-sandbox, discloses the
# weaker isolation everywhere, and still concludes (so Socket stays skipped).
prepare_case sandbox-auto-fallback
run_check 1 MOCK_GUARDDOG_SANDBOX_BROKEN=1 MOCK_SOCKET_ARGS_LOG="$CASE_DIR/socket-args.log" -- \
  demo@1.0.0 --ecosystem npm --gate install --json
expect_status 0 "auto mode recovers behavioral coverage on a sandbox-broken host"
expect_json '.guarddog.status == "ok" and .guarddog.sandbox.mode == "auto"
  and .guarddog.sandbox.fell_back == true
  and (.guarddog.note | contains("weaker isolation"))' \
  "the fallback is disclosed in the receipt"
if grep -q -- '--no-sandbox' "$CASE_LOG"; then
  pass "the retry passes --no-sandbox"
else
  cat "$CASE_LOG" >&2 || true
  fail "the retry passes --no-sandbox"
fi
if [[ -s "$CASE_DIR/socket-args.log" ]]; then
  fail "a fallback-but-conclusive scan still skips socket"
else
  pass "a fallback-but-conclusive scan still skips socket"
fi

# Human output must show the weaker isolation even on a clean PASS.
prepare_case sandbox-auto-fallback-human
run_check 1 MOCK_GUARDDOG_SANDBOX_BROKEN=1 -- demo@1.0.0 --ecosystem npm
expect_grep "$OUT_FILE" 'weaker isolation' "human output discloses the fallback on a PASS"

# required: no fallback — the tier reports breakage and Socket is consulted.
prepare_case sandbox-required-no-fallback
printf '{"install": {"guarddog": {"sandbox": "required"}}}\n' > "$CASE_RUN_CONFIG/config.json"
run_check 1 MOCK_GUARDDOG_SANDBOX_BROKEN=1 MOCK_SOCKET_ARGS_LOG="$CASE_DIR/socket-args.log" -- \
  demo@1.0.0 --ecosystem npm --json
expect_json '.guarddog.status == "error" and .guarddog.sandbox.fell_back == false' \
  "required mode keeps the hard failure"
if grep -q -- '--no-sandbox' "$CASE_LOG"; then
  fail "required mode never retries unsandboxed"
else
  pass "required mode never retries unsandboxed"
fi
if [[ -s "$CASE_DIR/socket-args.log" ]]; then
  pass "required-mode breakage falls back to socket"
else
  fail "required-mode breakage falls back to socket"
fi

# off: always unsandboxed, and its results live under a SEPARATE cache
# profile — a sandboxed cache entry must never satisfy an unsandboxed run.
prepare_case sandbox-off-separate-cache
run_check 1 -- demo@1.0.0 --ecosystem npm --json
expect_json '.guarddog.cache.misses == 1' "sandboxed run populates the sandboxed profile"
printf '{"install": {"guarddog": {"sandbox": "off"}}}\n' > "$CASE_RUN_CONFIG/config.json"
run_check 1 -- demo@1.0.0 --ecosystem npm --json
expect_json '.guarddog.cache.hits == 0 and .guarddog.cache.misses == 1' \
  "an unsandboxed run does not replay the sandboxed cache entry"
run_check 1 -- demo@1.0.0 --ecosystem npm --json
expect_json '.guarddog.cache.hits == 1' "the unsandboxed profile caches on its own key"

# F6: a shape-valid result — even a partial one whose error text mentions the
# sandbox — must never be discarded by the fallback retry.
prepare_case sandbox-no-retry-over-valid-block
run_check 1 MOCK_GUARDDOG_MODE=valid-block-with-sandbox-text -- \
  demo@1.0.0 --ecosystem npm --gate install --json
expect_status 20 "a valid partial BLOCK survives a sandbox-marker error value"
expect_json '.guarddog.contribution == "BLOCK"
  and .guarddog.sandbox.fell_back == false
  and (.guarddog.rules | index("threat-exfiltrate-secrets") != null)' \
  "the sandboxed findings are retained, not replaced by a retry"
if grep -q -- '--no-sandbox' "$CASE_LOG"; then
  cat "$CASE_LOG" >&2
  fail "no unsandboxed retry happens over a valid result"
else
  pass "no unsandboxed retry happens over a valid result"
fi

# F7: the retry shares the version's wall-clock budget instead of doubling it.
prepare_case sandbox-retry-shares-budget
printf '{"install": {"guarddog": {"timeout_seconds": 3}}}\n' > "$CASE_RUN_CONFIG/config.json"
SECONDS_BEFORE=$(date +%s)
run_check 1 MOCK_GUARDDOG_SANDBOX_BROKEN=1 MOCK_GUARDDOG_MODE=hang -- \
  demo@1.0.0 --ecosystem npm --json
SECONDS_AFTER=$(date +%s)
if (( SECONDS_AFTER - SECONDS_BEFORE <= 8 )); then
  pass "an auto retry stays inside one scan budget (plus grace)"
else
  printf 'elapsed %ss for a 3s budget\n' "$(( SECONDS_AFTER - SECONDS_BEFORE ))" >&2
  fail "an auto retry stays inside one scan budget (plus grace)"
fi

# F8: provenance is per attempt — a sibling version that scanned sandboxed
# must not inherit the run's no-sandbox profile, and a repeated auto fallback
# must consume its own cache instead of rescanning.
prepare_case sandbox-repeat-fallback-hits-cache
run_check 1 MOCK_GUARDDOG_SANDBOX_BROKEN=1 -- demo@1.0.0 --ecosystem npm --json
expect_json '.guarddog.sandbox.fell_back == true and .guarddog.cache.misses == 1' \
  "first auto fallback populates the no-sandbox profile"
run_check 1 MOCK_GUARDDOG_SANDBOX_BROKEN=1 -- demo@1.0.0 --ecosystem npm --json
expect_json '.guarddog.cache.hits == 1' "a repeated auto fallback replays its own cache entry"

# A sandboxed sibling in the same run keeps the sandboxed profile: after
# falling back for one version, a later sandbox-clean version's entry must
# still be rejected by a sandbox=off read.
prepare_case sandbox-mixed-version-provenance
printf '{"dependencies":{"multi":"^1.0.0"}}\n' > "$CASE_DIR/project/package.json"
printf '{"packages":{"node_modules/consumer":{"dependencies":{"multi":"^2.0.0"}}}}\n' > "$CASE_DIR/project/package-lock.json"
run_check 1 MOCK_PACKUMENT_MODE=multi MOCK_GUARDDOG_SANDBOX_BROKEN_VERSION=1.5.0 -- \
  multi --ecosystem npm --op update --project-dir "$CASE_DIR/project" --json
printf '{"install": {"guarddog": {"sandbox": "off"}}}\n' > "$CASE_RUN_CONFIG/config.json"
run_check 1 MOCK_PACKUMENT_MODE=multi -- \
  multi --ecosystem npm --op update --project-dir "$CASE_DIR/project" --json
expect_json '.guarddog.cache.hits < 2' \
  "a sandbox-off run cannot consume a sibling scanned under the sandbox"

# F9: provenance reaches recorded evidence.
prepare_case sandbox-fallback-install-known-reason
run_check 1 MOCK_GUARDDOG_SANDBOX_BROKEN=1 -- demo@1.0.0 --ecosystem npm --gate install
expect_status 0 "auto fallback still gates GO"
if jq -e '.packages["npm:demo"].reasons | index("guarddog_clean_for_versions_nosandbox") != null' \
  "$CASE_RUN_CONFIG/install-known.json" >/dev/null 2>&1; then
  pass "install-known records the unsandboxed provenance"
else
  cat "$CASE_RUN_CONFIG/install-known.json" >&2 || true
  fail "install-known records the unsandboxed provenance"
fi

# F11: the budget is shared, and it starts at the FIRST LAUNCH (cache
# preparation must not consume it). First attempt burns ~2s of a 3s budget,
# then the retry hangs: shared-budget code finishes near 3s; per-attempt
# budgets would take ~5s. The scanner must actually have been invoked.
prepare_case sandbox-budget-is-shared-not-doubled
printf '{"install": {"guarddog": {"timeout_seconds": 3}}}\n' > "$CASE_RUN_CONFIG/config.json"
BUDGET_BEFORE=$(date +%s)
run_check 1 MOCK_GUARDDOG_MODE=slow-then-sandbox-fail -- demo@1.0.0 --ecosystem npm --json
BUDGET_ELAPSED=$(( $(date +%s) - BUDGET_BEFORE ))
if (( BUDGET_ELAPSED <= 4 )); then
  pass "both attempts share one budget (elapsed ${BUDGET_ELAPSED}s for a 3s budget)"
else
  printf 'elapsed %ss — per-attempt budgets would show ~5s\n' "$BUDGET_ELAPSED" >&2
  fail "both attempts share one budget"
fi
if grep -q 'scan demo' "$CASE_LOG" 2>/dev/null; then
  pass "the first attempt actually invoked the scanner"
else
  cat "$CASE_LOG" >&2 || true
  fail "the first attempt actually invoked the scanner"
fi

# A tiny budget must still reach the scanner: the deadline may not be spent
# by cache-key derivation before the first launch.
prepare_case sandbox-tiny-budget-still-scans
printf '{"install": {"guarddog": {"timeout_seconds": 1}}}\n' > "$CASE_RUN_CONFIG/config.json"
run_check 1 -- demo@1.0.0 --ecosystem npm --json
if grep -q 'scan demo' "$CASE_LOG" 2>/dev/null; then
  pass "a 1s budget still launches the scanner after cache preparation"
else
  cat "$CASE_LOG" >&2 || true
  fail "a 1s budget still launches the scanner after cache preparation"
fi

# F9 residual: reuse of recorded evidence discloses unsandboxed provenance.
prepare_case sandbox-stale-reuse-discloses
run_check 1 MOCK_GUARDDOG_SANDBOX_BROKEN=1 -- demo@1.0.0 --ecosystem npm --gate install
expect_status 0 "auto fallback records evidence"
STALE_OUT="$CASE_DIR/stale.log"
(
  cd "$CASE_DIR/project" || exit 99
  env HOME="$CASE_HOME" PATH="$GUARDDOGBIN:$COMMONBIN:/usr/bin:/bin" \
    SAFE_RUN_CONFIG_DIR="$CASE_RUN_CONFIG" \
    SAFE_AUDIT_CHECK_STATUS=124 \
    bash -c 'source "$0"; safe_gate_known_provenance demo@1.0.0 npm' \
    "$ROOT/lib/gate-lib.sh"
) > "$STALE_OUT" 2>&1 || true
if grep -q 'WITHOUT the kernel sandbox' "$STALE_OUT"; then
  pass "stale-evidence reuse discloses unsandboxed provenance"
else
  cat "$STALE_OUT" >&2
  fail "stale-evidence reuse discloses unsandboxed provenance"
fi

# --- cooldown vs security fixes (operator ruling 2026-08-03) -----------------
#
# A cooldown that blocks the release fixing a published CVE is the same
# catch-22 the gate exists to end. Default `exempt` lets the fix through and
# names the advisory; `enforce` keeps the wait and says why.

prepare_case cooldown-waives-the-security-fix
run_check 1 MOCK_NPM_TIME="$(date -d '1 day ago' -Is)" MOCK_OSV_REMEDIATED_AT=1.0.0 -- \
  demo@1.0.0 --ecosystem npm --gate install --json
expect_status 0 "a day-old release that IS the fix installs by default"
expect_json '.release.cooldown_waived == true
  and (.release.remediates | index("GHSA-fix-here") != null)
  and ((.warn_causes // []) | index("release_too_new") == null)' \
  "the receipt records the waiver and the advisory it remediates"

prepare_case cooldown-waiver-is-visible
run_check 1 MOCK_NPM_TIME="$(date -d '1 day ago' -Is)" MOCK_OSV_REMEDIATED_AT=1.0.0 -- \
  demo@1.0.0 --ecosystem npm
expect_grep "$OUT_FILE" 'waived: it remediates GHSA-fix-here' \
  "the verdict line explains why the cooldown did not apply"

prepare_case cooldown-enforce-keeps-the-wait
printf '{"install": {"cooldown_security_fix": "enforce"}}\n' > "$CASE_RUN_CONFIG/config.json"
run_check 1 MOCK_NPM_TIME="$(date -d '1 day ago' -Is)" MOCK_OSV_REMEDIATED_AT=1.0.0 -- \
  demo@1.0.0 --ecosystem npm --gate install
expect_status 10 "enforce keeps the cooldown even for a security fix"
expect_grep "$OUT_FILE" 'but install.cooldown_security_fix=enforce' \
  "the verdict line names the setting that caused the refusal"
expect_grep "$ERR_FILE" 'this version remediates GHSA-fix-here' \
  "the refusal discloses that the blocked version is a fix"

# The exemption must NOT cover an ordinary young release with no remediation.
prepare_case cooldown-no-waiver-without-a-fix
run_check 1 MOCK_NPM_TIME="$(date -d '1 day ago' -Is)" -- \
  demo@1.0.0 --ecosystem npm --gate install
expect_status 10 "a plain young release still waits out the cooldown"

# ...nor an advisory fixed at a DIFFERENT version than the one resolved.
prepare_case cooldown-no-waiver-for-other-version-fix
run_check 1 MOCK_NPM_TIME="$(date -d '1 day ago' -Is)" MOCK_OSV_REMEDIATED_AT=0.9.0 -- \
  demo@1.0.0 --ecosystem npm --gate install
expect_status 10 "an advisory fixed at another version does not waive the cooldown"

# An OLD fix in the resolved set must not launder a YOUNG unrelated sibling
# (review PR#61 F1): every version inside the window must be a fix target.
prepare_case cooldown-old-fix-cannot-launder-young-sibling
printf '{"dependencies":{"multi":"^1.0.0"}}\n' > "$CASE_DIR/project/package.json"
printf '{"packages":{"node_modules/consumer":{"dependencies":{"multi":"^2.0.0"}}}}\n' > "$CASE_DIR/project/package-lock.json"
run_check 1 MOCK_GUARDDOG_MODE=clean MOCK_PACKUMENT_MODE=multi \
  MOCK_NPM_TIME_MULTI="$(date -d '40 days ago' -Is)|$(date -d '1 day ago' -Is)" \
  MOCK_OSV_REMEDIATED_AT=1.5.0 MOCK_OSV_REMEDIATED_NAME=multi -- \
  multi --ecosystem npm --op update --project-dir "$CASE_DIR/project" --gate install
expect_status 10 "an old fix cannot waive the cooldown for a young sibling release"

# ...nor may a young fix cover a second young NON-fix sibling.
prepare_case cooldown-young-fix-cannot-cover-young-sibling
printf '{"dependencies":{"multi":"^1.0.0"}}\n' > "$CASE_DIR/project/package.json"
printf '{"packages":{"node_modules/consumer":{"dependencies":{"multi":"^2.0.0"}}}}\n' > "$CASE_DIR/project/package-lock.json"
run_check 1 MOCK_GUARDDOG_MODE=clean MOCK_PACKUMENT_MODE=multi \
  MOCK_NPM_TIME_MULTI="$(date -d '1 day ago' -Is)|$(date -d '2 days ago' -Is)" \
  MOCK_OSV_REMEDIATED_AT=1.5.0 MOCK_OSV_REMEDIATED_NAME=multi -- \
  multi --ecosystem npm --op update --project-dir "$CASE_DIR/project" --gate install
expect_status 10 "a young fix cannot cover a young non-fix sibling"

# A fixed event whose range never opened an affected interval is not
# remediation evidence (review PR#61 F2).
prepare_case cooldown-bare-fixed-token-no-waiver
run_check 1 MOCK_NPM_TIME="$(date -d '1 day ago' -Is)" MOCK_OSV_REMEDIATED_AT=1.0.0 \
  MOCK_OSV_REMEDIATED_BARE=1 -- \
  demo@1.0.0 --ecosystem npm --gate install
expect_status 10 "a fixed event without an affected interval does not waive the cooldown"

# --- host-allow works outside npm (graphifyy regression, 2026-08-03) --------
#
# The gate's matcher was npm-only while `host-allow add --ecosystem python`
# happily recorded grants: the operator pin existed but was never consulted.
# An exact pin must waive WARN-tier causes in every supported ecosystem.

prepare_case python-warn-hints-host-allow
run_check 1 MOCK_GUARDDOG_MODE=warn -- demo@1.0.0 --ecosystem python --gate install
expect_status 10 "python GuardDog WARN refuses without a pin"
expect_grep "$ERR_FILE" 'host-allow add demo@1\.0\.0 --ecosystem python' \
  "python refusal hint offers the ecosystem-qualified host-allow command"

prepare_case python-host-allow-waives-warn
printf '{"packages":{"demo":{"version":"1.0.0","ecosystem":"python"}}}\n' \
  > "$CASE_RUN_CONFIG/host-allow.json"
run_check 1 MOCK_GUARDDOG_MODE=warn -- demo@1.0.0 --ecosystem python --gate install
expect_status 0 "python host-allow pin waives a WARN-tier refusal"
expect_grep "$ERR_FILE" 'host-allow entry demo@1\.0\.0 matches every warned resolved version; allowing' \
  "override notice names the python pin"

# Grant-time spelling (uv/py/pipx) must match audit-time spelling (python).
prepare_case python-host-allow-uv-spelling
printf '{"packages":{"demo":{"version":"1.0.0","ecosystem":"uv"}}}\n' \
  > "$CASE_RUN_CONFIG/host-allow.json"
run_check 1 MOCK_GUARDDOG_MODE=warn -- demo@1.0.0 --ecosystem python --gate install
expect_status 0 "a uv-spelled grant matches a python-ecosystem audit"

# An npm-scoped pin must NOT leak into another ecosystem's package of the
# same name.
prepare_case python-host-allow-npm-entry-no-crossover
printf '{"packages":{"demo":{"version":"1.0.0","ecosystem":"npm"}}}\n' \
  > "$CASE_RUN_CONFIG/host-allow.json"
run_check 1 MOCK_GUARDDOG_MODE=warn -- demo@1.0.0 --ecosystem python --gate install
expect_status 10 "an npm pin cannot authorize the same-named python package"

# A hand-edited entry for an ecosystem `host-allow add` cannot grant carries
# no authority, even on exact string match (review PR#61 F3).
prepare_case rust-host-allow-entry-carries-no-authority
printf '{"packages":{"demo":{"version":"1.0.0","ecosystem":"rust"}}}\n' \
  > "$CASE_RUN_CONFIG/host-allow.json"
run_check 1 MOCK_SOCKET_MODE=error -- demo@1.0.0 --ecosystem rust --gate install
expect_status 10 "an unsupported-ecosystem entry cannot clear a WARN"

if (( FAIL_COUNT > 0 )); then
  printf 'guarddog tier: %d passed, %d failed\n' "$PASS_COUNT" "$FAIL_COUNT" >&2
  exit 1
fi
printf 'guarddog tier: all %d cases passed\n' "$PASS_COUNT"
