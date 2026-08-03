#!/usr/bin/env bash
# scanner-batch suite: the Bun Security Scanner API backend (`safe audit
# scanner-batch`) and its share/scanner.mjs adapter. Hermetic — curl is a
# mock serving querybatch / per-vuln / paginated-query fixtures, and the
# adapter cases drive a stub safe-audit. The contract under test: advisories
# out on clean exit, NOTHING but a nonzero exit on infrastructure failure
# (the host fail-closes), and infra stderr that never reads as a CVE signal.

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
FIXDIR="$TEST_ROOT/fixtures"
mkdir -p "$MOCKBIN" "$FIXDIR"

# --- mock curl ---------------------------------------------------------------
# querybatch → MOCK_BATCH_FIXTURE (fail when MOCK_BATCH_STATUS != 0);
# /v1/vulns/<id> → $FIXDIR/vuln-<id>.json (fail when MOCK_VULN_STATUS != 0);
# /v1/query (pagination fallback) → MOCK_QUERY_FIXTURE.
cat > "$MOCKBIN/curl" <<'MOCK'
#!/usr/bin/env bash
url=""
args=("$@")
i=0
while (( i < ${#args[@]} )); do
  a="${args[$i]}"
  case "$a" in
    -H|--max-time|-d) i=$((i + 2)); continue ;;
    http*://*) url="$a" ;;
  esac
  i=$((i + 1))
done
case "$url" in
  *api.osv.dev/v1/querybatch*)
    [[ "${MOCK_BATCH_STATUS:-0}" == "0" ]] || exit 22
    cat "${MOCK_BATCH_FIXTURE:?}"
    ;;
  *api.osv.dev/v1/vulns/*)
    [[ "${MOCK_VULN_STATUS:-0}" == "0" ]] || exit 22
    id="${url##*/}"
    cat "${MOCK_FIXDIR:?}/vuln-${id}.json"
    ;;
  *api.osv.dev/v1/query*)
    [[ "${MOCK_QUERY_STATUS:-0}" == "0" ]] || exit 22
    cat "${MOCK_QUERY_FIXTURE:?}"
    ;;
  *)
    exit 22
    ;;
esac
exit 0
MOCK
chmod +x "$MOCKBIN/curl"

# --- per-case environment ----------------------------------------------------
# Fresh HOME + run-config dir per case so blocklist/config are case-local.
setup_case() {
  CASE_HOME="$TEST_ROOT/home-$1"
  RUN_DIR="$CASE_HOME/.config/safe/run"
  mkdir -p "$RUN_DIR"
  printf '{"packages": {}}\n' > "$RUN_DIR/blocked.json"
  printf '{}\n' > "$RUN_DIR/config.json"
}

run_batch() {
  env -i \
    PATH="$MOCKBIN:/usr/bin:/bin" \
    HOME="$CASE_HOME" \
    SAFE_RUN_CONFIG_DIR="$RUN_DIR" \
    MOCK_FIXDIR="$FIXDIR" \
    MOCK_BATCH_FIXTURE="${MOCK_BATCH_FIXTURE:-}" \
    MOCK_BATCH_STATUS="${MOCK_BATCH_STATUS:-0}" \
    MOCK_VULN_STATUS="${MOCK_VULN_STATUS:-0}" \
    MOCK_QUERY_FIXTURE="${MOCK_QUERY_FIXTURE:-}" \
    MOCK_QUERY_STATUS="${MOCK_QUERY_STATUS:-0}" \
    bash "$SAFE_AUDIT" scanner-batch
}

# --- cases: scanner-batch ----------------------------------------------------

case_clean_tree_returns_empty_array() {
  setup_case clean
  MOCK_BATCH_FIXTURE="$FIXDIR/batch-clean.json"
  printf '{"results": [{}, {}]}\n' > "$MOCK_BATCH_FIXTURE"
  local out rc=0
  out=$(printf '{"packages":[{"name":"left-pad","version":"1.3.0"},{"name":"lodash","version":"4.17.21"}]}' | run_batch) || rc=$?
  if [[ "$rc" == "0" && "$(jq -c . <<<"$out")" == "[]" ]]; then
    pass "clean tree returns [] with exit 0"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "clean tree returns [] with exit 0"
  fi
}

case_malformed_stdin_refuses() {
  setup_case malformed
  local rc=0 err
  err=$(printf 'not json' | run_batch 2>&1 >/dev/null) || rc=$?
  if [[ "$rc" == "2" && "$err" == *"malformed input"* ]]; then
    pass "malformed stdin exits 2 with a single legible line"
  else
    printf 'rc=%s err=%s\n' "$rc" "$err" >&2
    fail "malformed stdin exits 2 with a single legible line"
  fi
}

case_blocklisted_package_is_fatal() {
  setup_case blocklist
  printf '{"packages": {"evil-pkg": {"reason": "operator blocklist test"}}}\n' > "$RUN_DIR/blocked.json"
  MOCK_BATCH_FIXTURE="$FIXDIR/batch-clean1.json"
  printf '{"results": [{}]}\n' > "$MOCK_BATCH_FIXTURE"
  local out rc=0
  out=$(printf '{"packages":[{"name":"evil-pkg","version":"1.0.0"}]}' | run_batch) || rc=$?
  if [[ "$rc" == "0" ]] \
    && jq -e '.[0].level == "fatal" and .[0].package == "evil-pkg" and (.[0].description | contains("blocklisted"))' <<<"$out" >/dev/null; then
    pass "blocklisted package yields a fatal advisory"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "blocklisted package yields a fatal advisory"
  fi
}

case_mal_record_is_fatal_without_fetch() {
  setup_case mal
  MOCK_BATCH_FIXTURE="$FIXDIR/batch-mal.json"
  printf '{"results": [{"vulns": [{"id": "MAL-2026-9999", "modified": "2026-01-01T00:00:00Z"}]}]}\n' > "$MOCK_BATCH_FIXTURE"
  # No vuln-MAL-2026-9999.json fixture exists: a fetch attempt would fail the
  # case, proving MAL ids classify without a network round-trip.
  local out rc=0
  out=$(printf '{"packages":[{"name":"trojan","version":"2.0.0"}]}' | run_batch) || rc=$?
  if [[ "$rc" == "0" ]] \
    && jq -e '.[0].level == "fatal" and (.[0].description | contains("known-malware record MAL-2026-9999"))' <<<"$out" >/dev/null; then
    pass "MAL-* record is fatal with no per-vuln fetch"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "MAL-* record is fatal with no per-vuln fetch"
  fi
}

case_critical_advisory_is_fatal_medium_is_warn() {
  setup_case sev
  MOCK_BATCH_FIXTURE="$FIXDIR/batch-sev.json"
  printf '{"results": [{"vulns": [{"id": "GHSA-crit-0001"}]}, {"vulns": [{"id": "GHSA-med-0002"}]}]}\n' > "$MOCK_BATCH_FIXTURE"
  printf '{"id": "GHSA-crit-0001", "database_specific": {"severity": "CRITICAL"}}\n' > "$FIXDIR/vuln-GHSA-crit-0001.json"
  printf '{"id": "GHSA-med-0002", "database_specific": {"severity": "MODERATE"}}\n' > "$FIXDIR/vuln-GHSA-med-0002.json"
  local out rc=0
  out=$(printf '{"packages":[{"name":"aaa","version":"1.0.0"},{"name":"bbb","version":"2.0.0"}]}' | run_batch) || rc=$?
  if [[ "$rc" == "0" ]] \
    && jq -e '[.[] | select(.package == "aaa")][0].level == "fatal"' <<<"$out" >/dev/null \
    && jq -e '[.[] | select(.package == "bbb")][0].level == "warn"' <<<"$out" >/dev/null \
    && jq -e '[.[] | select(.package == "bbb")][0].description | contains("GHSA-med-0002 (medium)")' <<<"$out" >/dev/null; then
    pass "critical is fatal, medium is warn (default block_severities)"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "critical is fatal, medium is warn (default block_severities)"
  fi
}

case_block_severities_knob_promotes_high() {
  setup_case knob
  printf '{"install": {"block_severities": ["critical", "high"]}}\n' > "$RUN_DIR/config.json"
  MOCK_BATCH_FIXTURE="$FIXDIR/batch-high.json"
  printf '{"results": [{"vulns": [{"id": "GHSA-high-0003"}]}]}\n' > "$MOCK_BATCH_FIXTURE"
  printf '{"id": "GHSA-high-0003", "database_specific": {"severity": "HIGH"}}\n' > "$FIXDIR/vuln-GHSA-high-0003.json"
  local out rc=0
  out=$(printf '{"packages":[{"name":"ccc","version":"3.0.0"}]}' | run_batch) || rc=$?
  if [[ "$rc" == "0" ]] && jq -e '.[0].level == "fatal"' <<<"$out" >/dev/null; then
    pass "install.block_severities promotes high to fatal"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "install.block_severities promotes high to fatal"
  fi
}

case_batch_failure_is_infra_breakage_not_cve() {
  setup_case infra
  MOCK_BATCH_FIXTURE="$FIXDIR/unused.json"
  local out err rc=0
  out=$(printf '{"packages":[{"name":"ddd","version":"1.0.0"}]}' | MOCK_BATCH_STATUS=22 run_batch 2>"$TEST_ROOT/infra.err") || rc=$?
  err=$(cat "$TEST_ROOT/infra.err")
  if [[ "$rc" == "4" && -z "$out" ]] \
    && [[ "$err" == *"audit-infrastructure breakage"* ]] \
    && [[ "$err" == *"not a package finding"* ]] \
    && [[ "$err" != *"CVE"* && "$err" != *"vulnerab"* ]]; then
    pass "OSV batch failure exits 4, no advisories, infra-legible stderr"
  else
    printf 'rc=%s out=%s err=%s\n' "$rc" "$out" "$err" >&2
    fail "OSV batch failure exits 4, no advisories, infra-legible stderr"
  fi
}

case_vuln_fetch_failure_fails_closed() {
  setup_case vfail
  MOCK_BATCH_FIXTURE="$FIXDIR/batch-vfail.json"
  printf '{"results": [{"vulns": [{"id": "GHSA-miss-0004"}]}]}\n' > "$MOCK_BATCH_FIXTURE"
  local out rc=0 err
  out=$(printf '{"packages":[{"name":"eee","version":"1.0.0"}]}' | MOCK_VULN_STATUS=22 run_batch 2>"$TEST_ROOT/vfail.err") || rc=$?
  err=$(cat "$TEST_ROOT/vfail.err")
  if [[ "$rc" == "4" && -z "$out" && "$err" == *"audit-infrastructure breakage"* ]]; then
    pass "per-advisory fetch failure exits 4 with infra-legible stderr"
  else
    printf 'rc=%s out=%s err=%s\n' "$rc" "$out" "$err" >&2
    fail "per-advisory fetch failure exits 4 with infra-legible stderr"
  fi
}

case_pagination_token_triggers_complete_requery() {
  setup_case paged
  MOCK_BATCH_FIXTURE="$FIXDIR/batch-paged.json"
  printf '{"results": [{"vulns": [{"id": "GHSA-page-0005"}], "next_page_token": "tok"}]}\n' > "$MOCK_BATCH_FIXTURE"
  MOCK_QUERY_FIXTURE="$FIXDIR/query-paged.json"
  printf '{"vulns": [{"id": "GHSA-page-0005"}, {"id": "GHSA-page-0006"}]}\n' > "$MOCK_QUERY_FIXTURE"
  printf '{"id": "GHSA-page-0005", "database_specific": {"severity": "LOW"}}\n' > "$FIXDIR/vuln-GHSA-page-0005.json"
  printf '{"id": "GHSA-page-0006", "database_specific": {"severity": "CRITICAL"}}\n' > "$FIXDIR/vuln-GHSA-page-0006.json"
  local out rc=0
  out=$(printf '{"packages":[{"name":"fff","version":"1.0.0"}]}' | run_batch) || rc=$?
  # The advisory only present on the second page must classify — the truncated
  # first page alone would have missed the critical.
  if [[ "$rc" == "0" ]] \
    && jq -e '[.[] | select(.description | contains("GHSA-page-0006"))][0].level == "fatal"' <<<"$out" >/dev/null; then
    pass "next_page_token result is re-queried to completeness"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "next_page_token result is re-queried to completeness"
  fi
}

# --- cases: scanner.mjs adapter ----------------------------------------------

node_bin() { command -v node 2>/dev/null; }

adapter_driver() {
  # Drives scanner.scan() with a fixed package list against a stub safe-audit.
  cat > "$TEST_ROOT/driver.mjs" <<DRIVER
import { scanner } from "$ROOT/share/scanner.mjs";
const advisories = await scanner.scan({
  packages: [{ name: "left-pad", version: "1.3.0", requestedRange: "^1.0.0" }],
});
console.log(JSON.stringify(advisories));
DRIVER
}

case_adapter_maps_advisories() {
  local node; node=$(node_bin) || { pass "adapter mapping (SKIPPED: node not available)"; return; }
  adapter_driver
  cat > "$MOCKBIN/safe-audit-stub" <<'STUB'
#!/usr/bin/env bash
input=$(cat)
grep -q '"left-pad"' <<<"$input" || { echo "missing package" >&2; exit 2; }
printf '[{"level":"warn","package":"left-pad","url":"https://osv.dev/vulnerability/GHSA-x","description":"GHSA-x (medium) affects left-pad@1.3.0"}]\n'
STUB
  chmod +x "$MOCKBIN/safe-audit-stub"
  local out rc=0
  out=$(SAFE_AUDIT_BIN="$MOCKBIN/safe-audit-stub" "$node" "$TEST_ROOT/driver.mjs") || rc=$?
  if [[ "$rc" == "0" ]] && jq -e '.[0].level == "warn" and .[0].package == "left-pad"' <<<"$out" >/dev/null; then
    pass "adapter passes the package list in and advisories out"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "adapter passes the package list in and advisories out"
  fi
}

case_adapter_throws_on_nonzero_exit() {
  local node; node=$(node_bin) || { pass "adapter fail-closed (SKIPPED: node not available)"; return; }
  adapter_driver
  cat > "$MOCKBIN/safe-audit-stub" <<'STUB'
#!/usr/bin/env bash
cat >/dev/null
printf 'safe audit: scanner-batch: OSV batch query failed — audit-infrastructure breakage\n' >&2
exit 4
STUB
  chmod +x "$MOCKBIN/safe-audit-stub"
  local out rc=0
  out=$(SAFE_AUDIT_BIN="$MOCKBIN/safe-audit-stub" "$node" "$TEST_ROOT/driver.mjs" 2>&1) || rc=$?
  if [[ "$rc" != "0" && "$out" == *"exited 4"* && "$out" == *"audit-infrastructure breakage"* ]]; then
    pass "adapter throws (fail-closed) on nonzero safe-audit exit, cause preserved"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "adapter throws (fail-closed) on nonzero safe-audit exit, cause preserved"
  fi
}

case_adapter_throws_on_malformed_payload() {
  local node; node=$(node_bin) || { pass "adapter malformed payload (SKIPPED: node not available)"; return; }
  adapter_driver
  cat > "$MOCKBIN/safe-audit-stub" <<'STUB'
#!/usr/bin/env bash
cat >/dev/null
printf 'this is not json\n'
STUB
  chmod +x "$MOCKBIN/safe-audit-stub"
  local out rc=0
  out=$(SAFE_AUDIT_BIN="$MOCKBIN/safe-audit-stub" "$node" "$TEST_ROOT/driver.mjs" 2>&1) || rc=$?
  if [[ "$rc" != "0" && "$out" == *"malformed JSON"* ]]; then
    pass "adapter throws on malformed advisories payload"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "adapter throws on malformed advisories payload"
  fi
}

# --- run ---------------------------------------------------------------------

case_clean_tree_returns_empty_array
case_malformed_stdin_refuses
case_blocklisted_package_is_fatal
case_mal_record_is_fatal_without_fetch
case_critical_advisory_is_fatal_medium_is_warn
case_block_severities_knob_promotes_high
case_batch_failure_is_infra_breakage_not_cve
case_vuln_fetch_failure_fails_closed
case_pagination_token_triggers_complete_requery
case_adapter_maps_advisories
case_adapter_throws_on_nonzero_exit
case_adapter_throws_on_malformed_payload

printf '%d passed, %d failed\n' "$PASS_COUNT" "$FAIL_COUNT"
(( FAIL_COUNT == 0 ))
