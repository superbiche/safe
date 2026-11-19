#!/usr/bin/env bash
# scanner-batch suite: the Bun Security Scanner API backend (`safe audit
# scanner-batch`) and its share/scanner.mjs adapter. Hermetic — curl is a
# mock serving querybatch / per-vuln / paginated-query fixtures, and the
# adapter cases drive a stub safe-audit. The contract under test: advisories
# out on clean exit, NOTHING but a nonzero exit on infrastructure failure
# (the host fail-closes), and infra stderr that never reads as a CVE signal.

set -euo pipefail

# SAFE_TEST_ISOLATION_MARKER: every suite owns a scratch HOME and safe state.
# shellcheck source=tests/lib/test-isolation.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/test-isolation.sh"
safe_test_setup_isolation || exit 1
unset AUBE_SECURITY_SCANNER

# #87: seeds blocklist fixtures (incl. malformed) in a relocated
# SAFE_RUN_CONFIG_DIR; bless it as authoritative so the blocklist-readability
# check judges the redirected fixture rather than the canonical store. The
# trust-redirect guard itself is covered by tests/run/trust_store_redirect.sh.
export SAFE_RUN_TRUST_OVERRIDE=1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SAFE_AUDIT="$ROOT/bin/safe-audit"

PASS_COUNT=0
FAIL_COUNT=0

pass() { printf 'ok - %s\n' "$*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { printf 'not ok - %s\n' "$*" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }

TEST_ROOT="$(mktemp -d)"
safe_test_compose_exit_trap "rm -rf \"\$TEST_ROOT\""

# The evidence mode asks safe-core (built from the working tree, at this tree's
# version) whether an OSV answer repeats a member; without a Go toolchain those
# cases are skipped, as the contract case below always was.
# shellcheck source=tests/lib/safe-core.sh
. "$ROOT/tests/lib/safe-core.sh"
SC_OK=0
if safe_core_test_prepare "$ROOT" "$TEST_ROOT/safe-core-ev" 2>/dev/null; then SC_OK=1; fi

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
    if [[ -n "${MOCK_BATCH_DIR:-}" ]]; then
      count_file="${MOCK_BATCH_DIR}/.count"
      count=$(( $(cat "$count_file" 2>/dev/null || echo 0) + 1 ))
      printf '%s' "$count" > "$count_file"
      # A batchN.fail marker makes the Nth call a transport failure.
      [[ ! -e "${MOCK_BATCH_DIR}/batch${count}.fail" ]] || exit 22
      cat "${MOCK_BATCH_DIR}/batch${count}.json"
    else
      cat "${MOCK_BATCH_FIXTURE:?}"
    fi
    ;;
  *api.osv.dev/v1/vulns/*)
    [[ "${MOCK_VULN_STATUS:-0}" == "0" ]] || exit 22
    id="${url##*/}"
    # A vuln-<id>.fail marker makes that one advisory fetch a transport failure.
    [[ ! -e "${MOCK_FIXDIR:?}/vuln-${id}.fail" ]] || exit 22
    cat "${MOCK_FIXDIR:?}/vuln-${id}.json"
    ;;
  *api.osv.dev/v1/query*)
    [[ "${MOCK_QUERY_STATUS:-0}" == "0" ]] || exit 22
    if [[ -n "${MOCK_QUERY_DIR:-}" ]]; then
      # Page N of a paginated query: queryN.json, or a transport failure when
      # queryN.fail exists.
      qcount_file="${MOCK_QUERY_DIR}/.count"
      qcount=$(( $(cat "$qcount_file" 2>/dev/null || echo 0) + 1 ))
      printf '%s' "$qcount" > "$qcount_file"
      [[ ! -e "${MOCK_QUERY_DIR}/query${qcount}.fail" ]] || exit 22
      cat "${MOCK_QUERY_DIR}/query${qcount}.json"
    else
      cat "${MOCK_QUERY_FIXTURE:?}"
    fi
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
    MOCK_BATCH_DIR="${MOCK_BATCH_DIR:-}" \
    MOCK_BATCH_STATUS="${MOCK_BATCH_STATUS:-0}" \
    MOCK_VULN_STATUS="${MOCK_VULN_STATUS:-0}" \
    MOCK_QUERY_FIXTURE="${MOCK_QUERY_FIXTURE:-}" \
    MOCK_QUERY_STATUS="${MOCK_QUERY_STATUS:-0}" \
    MOCK_QUERY_DIR="${MOCK_QUERY_DIR:-}" \
    SAFE_CORE_BIN="${SAFE_CORE_BIN:-}" \
    FAKE_COUNT="${FAKE_COUNT:-}" FAKE_MODE="${FAKE_MODE:-}" FAKE_OK="${FAKE_OK:-}" \
    bash "$SAFE_AUDIT" scanner-batch "$@"
}

run_evidence() { run_batch --evidence "$@"; }

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
    && jq -e '[.[] | select(.package == "bbb")][0].description | contains("GHSA-med-0002 (moderate)")' <<<"$out" >/dev/null; then
    pass "critical is fatal, moderate is warn (default block_severities)"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "critical is fatal, moderate is warn (default block_severities)"
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

case_cvss_vector_critical_is_fatal() {
  # PR#64 review F1: the legacy substring matcher read "CVSS:3.1/..." as
  # "low". The classifier must band the vector itself, matching check's
  # policy for the identical record.
  setup_case cvssvec
  MOCK_BATCH_FIXTURE="$FIXDIR/batch-cvssvec.json"
  printf '{"results": [{"vulns": [{"id": "GHSA-vect-0007"}]}]}\n' > "$MOCK_BATCH_FIXTURE"
  printf '{"id": "GHSA-vect-0007", "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}\n' > "$FIXDIR/vuln-GHSA-vect-0007.json"
  local out rc=0
  out=$(printf '{"packages":[{"name":"ggg","version":"1.0.0"}]}' | run_batch) || rc=$?
  if [[ "$rc" == "0" ]] \
    && jq -e '.[0].level == "fatal" and (.[0].description | contains("(critical)"))' <<<"$out" >/dev/null; then
    pass "CVSS v3 vector-only critical is fatal"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "CVSS v3 vector-only critical is fatal"
  fi
}

case_conflicting_severity_candidates_max_wins() {
  setup_case sevmax
  MOCK_BATCH_FIXTURE="$FIXDIR/batch-sevmax.json"
  printf '{"results": [{"vulns": [{"id": "GHSA-mixd-0008"}]}]}\n' > "$MOCK_BATCH_FIXTURE"
  printf '{"id": "GHSA-mixd-0008", "database_specific": {"severity": "LOW"}, "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}\n' > "$FIXDIR/vuln-GHSA-mixd-0008.json"
  local out rc=0
  out=$(printf '{"packages":[{"name":"hhh","version":"1.0.0"}]}' | run_batch) || rc=$?
  if [[ "$rc" == "0" ]] && jq -e '.[0].level == "fatal"' <<<"$out" >/dev/null; then
    pass "conflicting severity candidates: the maximum wins"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "conflicting severity candidates: the maximum wins"
  fi
}

case_unknown_severity_respects_knob() {
  # A record with no severity candidates is legitimately "unknown" — warn by
  # default, fatal only when the operator lists unknown in the knob.
  setup_case unk
  MOCK_BATCH_FIXTURE="$FIXDIR/batch-unk.json"
  printf '{"results": [{"vulns": [{"id": "GHSA-nosev-0009"}]}]}\n' > "$MOCK_BATCH_FIXTURE"
  printf '{"id": "GHSA-nosev-0009"}\n' > "$FIXDIR/vuln-GHSA-nosev-0009.json"
  local out rc=0
  out=$(printf '{"packages":[{"name":"iii","version":"1.0.0"}]}' | run_batch) || rc=$?
  local first_ok=0
  [[ "$rc" == "0" ]] && jq -e '.[0].level == "warn" and (.[0].description | contains("(unknown)"))' <<<"$out" >/dev/null && first_ok=1
  printf '{"install": {"block_severities": ["critical", "unknown"]}}\n' > "$RUN_DIR/config.json"
  rc=0
  out=$(printf '{"packages":[{"name":"iii","version":"1.0.0"}]}' | run_batch) || rc=$?
  if [[ "$first_ok" == "1" && "$rc" == "0" ]] && jq -e '.[0].level == "fatal"' <<<"$out" >/dev/null; then
    pass "no-candidate severity is unknown: warn by default, knob can promote"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "no-candidate severity is unknown: warn by default, knob can promote"
  fi
}

case_malformed_batch_entries_fail_closed() {
  # PR#64 review F2: null entries, non-array vulns, and wrong-shape tokens
  # must exit 4 — optional iterators would read each as "no advisories".
  setup_case entries
  local shape rc out ok=1
  for shape in '{"results":[null]}' '{"results":[{"vulns":null}]}' '{"results":[{"next_page_token":7}]}' '{"results":[{"vulns":[{"id":42}]}]}'; do
    MOCK_BATCH_FIXTURE="$FIXDIR/batch-entry.json"
    printf '%s\n' "$shape" > "$MOCK_BATCH_FIXTURE"
    rc=0
    out=$(printf '{"packages":[{"name":"jjj","version":"1.0.0"}]}' | run_batch 2>"$TEST_ROOT/entry.err") || rc=$?
    if [[ "$rc" != "4" || -n "$out" ]] || ! grep -q "audit-infrastructure breakage" "$TEST_ROOT/entry.err"; then
      printf 'shape=%s rc=%s out=%s\n' "$shape" "$rc" "$out" >&2
      ok=0
    fi
  done
  if [[ "$ok" == "1" ]]; then
    pass "malformed batch entries fail closed (null result, null vulns, bad token, non-string id)"
  else
    fail "malformed batch entries fail closed (null result, null vulns, bad token, non-string id)"
  fi
}

case_malformed_advisory_record_fails_closed() {
  # PR#64 review F3: an unparseable or mismatched detail record is
  # infrastructure breakage, never an unknown-severity warn.
  setup_case badrec
  MOCK_BATCH_FIXTURE="$FIXDIR/batch-badrec.json"
  printf '{"results": [{"vulns": [{"id": "GHSA-bad-0010"}]}]}\n' > "$MOCK_BATCH_FIXTURE"
  printf 'not-json\n' > "$FIXDIR/vuln-GHSA-bad-0010.json"
  local rc=0 out ok=1
  out=$(printf '{"packages":[{"name":"kkk","version":"1.0.0"}]}' | run_batch 2>"$TEST_ROOT/badrec.err") || rc=$?
  { [[ "$rc" == "4" && -z "$out" ]] && grep -q "audit-infrastructure breakage" "$TEST_ROOT/badrec.err"; } || ok=0
  # Parseable but claiming a different id.
  printf '{"id": "GHSA-other-9999"}\n' > "$FIXDIR/vuln-GHSA-bad-0010.json"
  rc=0
  out=$(printf '{"packages":[{"name":"kkk","version":"1.0.0"}]}' | run_batch 2>"$TEST_ROOT/badrec2.err") || rc=$?
  { [[ "$rc" == "4" && -z "$out" ]] && grep -q "audit-infrastructure breakage" "$TEST_ROOT/badrec2.err"; } || ok=0
  if [[ "$ok" == "1" ]]; then
    pass "malformed or mismatched advisory record fails closed"
  else
    fail "malformed or mismatched advisory record fails closed"
  fi
}

case_unreadable_blocklist_fails_closed() {
  # PR#64 review F4: a blocklist that exists but cannot parse must never
  # read as "not blocked".
  setup_case badblock
  printf 'not-json{' > "$RUN_DIR/blocked.json"
  MOCK_BATCH_FIXTURE="$FIXDIR/batch-clean-bb.json"
  printf '{"results": [{}]}\n' > "$MOCK_BATCH_FIXTURE"
  local rc=0 out
  out=$(printf '{"packages":[{"name":"lll","version":"1.0.0"}]}' | run_batch 2>"$TEST_ROOT/bb.err") || rc=$?
  if [[ "$rc" == "4" && -z "$out" ]] && grep -q "blocklist file unreadable" "$TEST_ROOT/bb.err"; then
    pass "unreadable blocklist fails closed as local infrastructure breakage"
  else
    printf 'rc=%s out=%s err=%s\n' "$rc" "$out" "$(cat "$TEST_ROOT/bb.err")" >&2
    fail "unreadable blocklist fails closed as local infrastructure breakage"
  fi
}

case_hostile_advisory_ids_fail_closed() {
  # PR#64 review F7: dot-only sentinels and malformed MAL ids must be
  # rejected before URL or output construction.
  setup_case hostile
  local shape rc out ok=1
  # Embedded-newline ids included (delta-2 F14): the id shape is enforced
  # inside the schema validator, never by a line-oriented loop that would
  # validate fragments separately.
  for shape in '{"results":[{"vulns":[{"id":".."}]}]}' '{"results":[{"vulns":[{"id":"MAL-../bad"}]}]}' '{"results":[{"vulns":[{"id":"MAL-good\nMAL-bad"}]}]}'; do
    MOCK_BATCH_FIXTURE="$FIXDIR/batch-hostile.json"
    printf '%s\n' "$shape" > "$MOCK_BATCH_FIXTURE"
    rc=0
    out=$(printf '{"packages":[{"name":"mmm","version":"1.0.0"}]}' | run_batch 2>"$TEST_ROOT/hostile.err") || rc=$?
    if [[ "$rc" != "4" || -n "$out" ]] || ! grep -q "audit-infrastructure breakage" "$TEST_ROOT/hostile.err"; then
      printf 'shape=%s rc=%s out=%s\n' "$shape" "$rc" "$out" >&2
      ok=0
    fi
  done
  if [[ "$ok" == "1" ]]; then
    pass "hostile advisory ids (dot sentinels, malformed MAL, embedded newline) fail closed"
  else
    fail "hostile advisory ids (dot sentinels, malformed MAL, embedded newline) fail closed"
  fi
}

case_multidoc_raw_page_fails_closed() {
  # PR#64 delta-2 F13: the shared paginated /v1/query helper must reject a
  # JSON stream page — plain jq validated the tail while the merge slurped
  # only the first document, silently dropping the later advisory.
  setup_case rawmultidoc
  MOCK_BATCH_FIXTURE="$FIXDIR/batch-rawmd.json"
  printf '{"results": [{"next_page_token": "tok"}]}\n' > "$MOCK_BATCH_FIXTURE"
  MOCK_QUERY_FIXTURE="$FIXDIR/query-rawmd.json"
  printf '{"vulns": []}\n{"vulns": [{"id": "GHSA-paged-drop-0016"}]}\n' > "$MOCK_QUERY_FIXTURE"
  local rc=0 out
  out=$(printf '{"packages":[{"name":"uuu","version":"1.0.0"}]}' | run_batch 2>"$TEST_ROOT/rawmd.err") || rc=$?
  if [[ "$rc" == "4" && -z "$out" ]] && grep -q "OSV pagination re-query failed" "$TEST_ROOT/rawmd.err"; then
    pass "multi-document raw /v1/query page fails closed through the shared helper"
  else
    printf 'rc=%s out=%s err=%s\n' "$rc" "$out" "$(cat "$TEST_ROOT/rawmd.err")" >&2
    fail "multi-document raw /v1/query page fails closed through the shared helper"
  fi
}

case_shared_advisory_scopes_per_package() {
  # One advisory affecting two queried packages classifies each by its own
  # affected entry (delta-2 verified this manually; pin it).
  setup_case sharedid
  MOCK_BATCH_FIXTURE="$FIXDIR/batch-sharedid.json"
  printf '{"results": [{"vulns": [{"id": "GHSA-shared-0017"}]}, {"vulns": [{"id": "GHSA-shared-0017"}]}]}\n' > "$MOCK_BATCH_FIXTURE"
  cat > "$FIXDIR/vuln-GHSA-shared-0017.json" <<'JSON'
{"id": "GHSA-shared-0017",
 "affected": [
   {"package": {"ecosystem": "npm", "name": "vvv"},
    "ecosystem_specific": {"severity": "LOW"}},
   {"package": {"ecosystem": "npm", "name": "www"},
    "ecosystem_specific": {"severity": "CRITICAL"}}
 ]}
JSON
  local rc=0 out
  out=$(printf '{"packages":[{"name":"vvv","version":"1.0.0"},{"name":"www","version":"2.0.0"}]}' | run_batch) || rc=$?
  if [[ "$rc" == "0" ]] \
    && jq -e '[.[] | select(.package == "vvv")][0].level == "warn"' <<<"$out" >/dev/null \
    && jq -e '[.[] | select(.package == "www")][0].level == "fatal"' <<<"$out" >/dev/null; then
    pass "one advisory shared by two packages scopes severity per package"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "one advisory shared by two packages scopes severity per package"
  fi
}

case_whitespace_package_names_refused() {
  setup_case wsnames
  local rc=0 err
  err=$(printf '{"packages":[{"name":"evil\\ngood","version":"1.0.0"}]}' | run_batch 2>&1 >/dev/null) || rc=$?
  if [[ "$rc" == "2" && "$err" == *"malformed input"* ]]; then
    pass "whitespace/control characters in package names are refused at the door"
  else
    printf 'rc=%s err=%s\n' "$rc" "$err" >&2
    fail "whitespace/control characters in package names are refused at the door"
  fi
}

case_chunk_alignment_across_batches() {
  # 150 packages → two querybatch calls; the only advisory sits on the
  # LAST package of the second chunk. Misalignment anywhere in the
  # chunk/transpose/accumulate pipeline would attribute it elsewhere or
  # lose it.
  setup_case chunks
  local batchdir="$FIXDIR/chunks"
  mkdir -p "$batchdir"; rm -f "$batchdir/.count"
  jq -n '{results: [range(100) | {}]}' > "$batchdir/batch1.json"
  jq -n '{results: ([range(49) | {}] + [{vulns: [{id: "GHSA-last-0011"}]}])}' > "$batchdir/batch2.json"
  printf '{"id": "GHSA-last-0011", "database_specific": {"severity": "CRITICAL"}}\n' > "$FIXDIR/vuln-GHSA-last-0011.json"
  local input out rc=0 expected
  input=$(jq -n '{packages: [range(150) | {name: ("pkg-" + (. | tostring)), version: "1.0.0"}]}')
  # scanner-batch queries in dedupe order (jq unique SORTS); the advisory
  # sits on the last entry of the second batch call, i.e. sorted position
  # 149 — compute it the same way rather than assuming input order.
  expected=$(jq -r '[.packages[] | {name, version}] | unique | .[149].name' <<<"$input")
  out=$(printf '%s' "$input" | MOCK_BATCH_DIR="$batchdir" MOCK_BATCH_FIXTURE= run_batch) || rc=$?
  if [[ "$rc" == "0" ]] \
    && jq -e --arg exp "$expected" 'length == 1 and .[0].package == $exp and .[0].level == "fatal"' <<<"$out" >/dev/null; then
    pass "chunk alignment holds across 150 packages / two batch calls"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "chunk alignment holds across 150 packages / two batch calls"
  fi
}

case_multidoc_responses_fail_closed() {
  # PR#64 delta F10: a JSON stream validates on its last document while
  # consumption reads the first — both response paths must enforce exactly
  # one document.
  setup_case multidoc
  MOCK_BATCH_FIXTURE="$FIXDIR/batch-multidoc.json"
  printf '{"results": [{}]}\n{"results": [{"vulns": [{"id": "GHSA-dropped-0012"}]}]}\n' > "$MOCK_BATCH_FIXTURE"
  local rc=0 out ok=1
  out=$(printf '{"packages":[{"name":"nnn","version":"1.0.0"}]}' | run_batch 2>"$TEST_ROOT/md.err") || rc=$?
  { [[ "$rc" == "4" && -z "$out" ]] && grep -q "not a single JSON document" "$TEST_ROOT/md.err"; } || ok=0
  # Detail path: two matching documents (critical then low) must not
  # concatenate into an unrecognized label warn.
  MOCK_BATCH_FIXTURE="$FIXDIR/batch-multidoc2.json"
  printf '{"results": [{"vulns": [{"id": "GHSA-multi-0013"}]}]}\n' > "$MOCK_BATCH_FIXTURE"
  printf '{"id": "GHSA-multi-0013", "database_specific": {"severity": "CRITICAL"}}\n{"id": "GHSA-multi-0013", "database_specific": {"severity": "LOW"}}\n' > "$FIXDIR/vuln-GHSA-multi-0013.json"
  rc=0
  out=$(printf '{"packages":[{"name":"ooo","version":"1.0.0"}]}' | run_batch 2>"$TEST_ROOT/md2.err") || rc=$?
  { [[ "$rc" == "4" && -z "$out" ]] && grep -q "advisory record malformed" "$TEST_ROOT/md2.err"; } || ok=0
  if [[ "$ok" == "1" ]]; then
    pass "multi-document batch and detail responses fail closed"
  else
    fail "multi-document batch and detail responses fail closed"
  fi
}

case_paginated_requery_enforces_id_schema() {
  # PR#64 delta F11: the pagination fallback replaces validated results, so
  # its entries must satisfy the same string-id schema — a numeric id was
  # stringified by jq -r and rode past the upfront guard.
  setup_case pagschema
  MOCK_BATCH_FIXTURE="$FIXDIR/batch-pagschema.json"
  printf '{"results": [{"next_page_token": "tok"}]}\n' > "$MOCK_BATCH_FIXTURE"
  MOCK_QUERY_FIXTURE="$FIXDIR/query-pagschema.json"
  printf '{"vulns": [{"id": 42}]}\n' > "$MOCK_QUERY_FIXTURE"
  local rc=0 out
  out=$(printf '{"packages":[{"name":"ppp","version":"1.0.0"}]}' | run_batch 2>"$TEST_ROOT/ps.err") || rc=$?
  if [[ "$rc" == "4" && -z "$out" ]] && grep -q "malformed paginated OSV response" "$TEST_ROOT/ps.err"; then
    pass "paginated re-query entries must satisfy the id schema"
  else
    printf 'rc=%s out=%s err=%s\n' "$rc" "$out" "$(cat "$TEST_ROOT/ps.err")" >&2
    fail "paginated re-query entries must satisfy the id schema"
  fi
}

case_severity_scoped_to_queried_package() {
  # PR#64 delta F12: another affected package's critical must not classify
  # the queried package — package_audit_command scopes to matching_affected, and
  # the scanner must agree.
  setup_case sevscope
  MOCK_BATCH_FIXTURE="$FIXDIR/batch-sevscope.json"
  printf '{"results": [{"vulns": [{"id": "GHSA-scope-0014"}]}]}\n' > "$MOCK_BATCH_FIXTURE"
  cat > "$FIXDIR/vuln-GHSA-scope-0014.json" <<'JSON'
{"id": "GHSA-scope-0014",
 "affected": [
   {"package": {"ecosystem": "npm", "name": "qqq"},
    "ecosystem_specific": {"severity": "LOW"}},
   {"package": {"ecosystem": "npm", "name": "other-pkg"},
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "ecosystem_specific": {"severity": "CRITICAL"}}
 ]}
JSON
  local rc=0 out
  out=$(printf '{"packages":[{"name":"qqq","version":"1.0.0"}]}' | run_batch) || rc=$?
  if [[ "$rc" == "0" ]] \
    && jq -e '.[0].level == "warn" and (.[0].description | contains("(low)"))' <<<"$out" >/dev/null; then
    pass "severity is scoped to the queried package, not the whole record"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "severity is scoped to the queried package, not the whole record"
  fi
}

case_numeric_detail_id_fails_closed() {
  # Delta re-check F3 residual: a numeric detail id must not impersonate
  # its string form through tostring.
  setup_case numid
  MOCK_BATCH_FIXTURE="$FIXDIR/batch-numid.json"
  printf '{"results": [{"vulns": [{"id": "42"}]}]}\n' > "$MOCK_BATCH_FIXTURE"
  printf '{"id": 42}\n' > "$FIXDIR/vuln-42.json"
  local rc=0 out
  out=$(printf '{"packages":[{"name":"rrr","version":"1.0.0"}]}' | run_batch 2>"$TEST_ROOT/numid.err") || rc=$?
  if [[ "$rc" == "4" && -z "$out" ]] && grep -q "advisory record malformed" "$TEST_ROOT/numid.err"; then
    pass "numeric detail id does not impersonate its string form"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "numeric detail id does not impersonate its string form"
  fi
}

case_blocklist_entry_schema_fails_closed() {
  # Delta re-check F4 residual: a parseable blocklist whose ENTRY is not an
  # object silently reads as "not blocked" through `// empty`.
  setup_case entrycorrupt
  printf '{"packages": {"sss": ""}}\n' > "$RUN_DIR/blocked.json"
  MOCK_BATCH_FIXTURE="$FIXDIR/batch-entrycorrupt.json"
  printf '{"results": [{}]}\n' > "$MOCK_BATCH_FIXTURE"
  local rc=0 out
  out=$(printf '{"packages":[{"name":"sss","version":"1.0.0"}]}' | run_batch 2>"$TEST_ROOT/ec.err") || rc=$?
  if [[ "$rc" == "4" && -z "$out" ]] && grep -q "blocklist file unreadable" "$TEST_ROOT/ec.err"; then
    pass "non-object blocklist entry fails closed"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "non-object blocklist entry fails closed"
  fi
}

case_same_name_different_versions_stay_distinct() {
  setup_case twovers
  MOCK_BATCH_FIXTURE="$FIXDIR/batch-twovers.json"
  # Dedupe keys on {name, version}: two versions of one package are two
  # queries; the duplicate pair collapses to one.
  printf '{"results": [{"vulns": [{"id": "GHSA-v1-0015"}]}, {}]}\n' > "$MOCK_BATCH_FIXTURE"
  printf '{"id": "GHSA-v1-0015", "database_specific": {"severity": "CRITICAL"}}\n' > "$FIXDIR/vuln-GHSA-v1-0015.json"
  local rc=0 out
  out=$(printf '{"packages":[{"name":"ttt","version":"1.0.0"},{"name":"ttt","version":"2.0.0"},{"name":"ttt","version":"1.0.0"}]}' | run_batch) || rc=$?
  if [[ "$rc" == "0" ]] \
    && jq -e 'length == 1 and (.[0].description | contains("ttt@1.0.0"))' <<<"$out" >/dev/null; then
    pass "same-name different-version stay distinct; exact duplicates collapse"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "same-name different-version stay distinct; exact duplicates collapse"
  fi
}

# --- cases: gate env injection -----------------------------------------------

case_gate_injects_scanner_env() {
  # PR#64 review F6: the probe must honor SAFE_CONFIG_DIR, not hardcode
  # ~/.config/safe; a caller-set value is preserved; no file → no export.
  setup_case gateinj
  local confdir="$TEST_ROOT/gateconf" tooldir="$TEST_ROOT/gatetools"
  mkdir -p "$confdir" "$tooldir"
  printf '// adapter placeholder\n' > "$confdir/scanner.mjs"
  cat > "$tooldir/faketool" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "${AUBE_SECURITY_SCANNER:-UNSET}"
STUB
  chmod +x "$tooldir/faketool"
  local lib="$ROOT/lib/gate-lib.sh" out ok=1
  out=$(PATH="$tooldir:/usr/bin:/bin" SAFE_CONFIG_DIR="$confdir" \
    bash -c "source '$lib'; safe_gate_exec_real faketool")
  [[ "$out" == "$confdir/scanner.mjs" ]] || { printf 'custom dir: %s\n' "$out" >&2; ok=0; }
  out=$(PATH="$tooldir:/usr/bin:/bin" SAFE_CONFIG_DIR="$confdir" AUBE_SECURITY_SCANNER=/caller/own.mjs \
    bash -c "source '$lib'; safe_gate_exec_real faketool")
  [[ "$out" == "/caller/own.mjs" ]] || { printf 'caller-set: %s\n' "$out" >&2; ok=0; }
  out=$(PATH="$tooldir:/usr/bin:/bin" SAFE_CONFIG_DIR="$TEST_ROOT/gate-empty" \
    bash -c "source '$lib'; safe_gate_exec_real faketool")
  [[ "$out" == "UNSET" ]] || { printf 'no file: %s\n' "$out" >&2; ok=0; }
  if [[ "$ok" == "1" ]]; then
    pass "gate injects AUBE_SECURITY_SCANNER (SAFE_CONFIG_DIR honored, caller wins, no file no export)"
  else
    fail "gate injects AUBE_SECURITY_SCANNER (SAFE_CONFIG_DIR honored, caller wins, no file no export)"
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

case_adapter_rejects_malformed_advisory_elements() {
  local node; node=$(node_bin) || { pass "adapter element shape (SKIPPED: node not available)"; return; }
  adapter_driver
  local shape out rc ok=1
  for shape in '{}' '[42]' '[{"level":"fatal"}]'; do
    cat > "$MOCKBIN/safe-audit-stub" <<STUB
#!/usr/bin/env bash
cat >/dev/null
printf '%s\n' '$shape'
STUB
    chmod +x "$MOCKBIN/safe-audit-stub"
    rc=0
    out=$(SAFE_AUDIT_BIN="$MOCKBIN/safe-audit-stub" "$node" "$TEST_ROOT/driver.mjs" 2>&1) || rc=$?
    if [[ "$rc" == "0" ]] || [[ "$out" != *"non-array payload"* && "$out" != *"malformed advisory element"* ]]; then
      printf 'shape=%s rc=%s out=%s\n' "$shape" "$rc" "$out" >&2
      ok=0
    fi
  done
  if [[ "$ok" == "1" ]]; then
    pass "adapter rejects non-array payloads and malformed advisory elements"
  else
    fail "adapter rejects non-array payloads and malformed advisory elements"
  fi
}

case_adapter_throws_on_missing_binary() {
  local node; node=$(node_bin) || { pass "adapter ENOENT (SKIPPED: node not available)"; return; }
  adapter_driver
  local out rc=0
  out=$(SAFE_AUDIT_BIN="$TEST_ROOT/does-not-exist" "$node" "$TEST_ROOT/driver.mjs" 2>&1) || rc=$?
  if [[ "$rc" != "0" && "$out" == *"could not start"* ]]; then
    pass "adapter throws when safe-audit is missing (ENOENT)"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "adapter throws when safe-audit is missing (ENOENT)"
  fi
}

case_adapter_times_out_hung_child() {
  local node; node=$(node_bin) || { pass "adapter timeout (SKIPPED: node not available)"; return; }
  adapter_driver
  cat > "$MOCKBIN/safe-audit-stub" <<'STUB'
#!/usr/bin/env bash
cat >/dev/null
sleep 60
STUB
  chmod +x "$MOCKBIN/safe-audit-stub"
  local out rc=0
  out=$(SAFE_SCANNER_TIMEOUT_MS=1500 SAFE_AUDIT_BIN="$MOCKBIN/safe-audit-stub" "$node" "$TEST_ROOT/driver.mjs" 2>&1) || rc=$?
  if [[ "$rc" != "0" && "$out" == *"timed out"* ]]; then
    pass "adapter kills and rejects a hung safe-audit"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "adapter kills and rejects a hung safe-audit"
  fi
}

case_adapter_rejects_partial_request_channel() {
  # PR#64 review F5: a child that stops reading stdin (EPIPE) and still
  # exits 0 with valid output must REJECT — the package list may not have
  # arrived in full, so its "clean" answer covers an unknown subset.
  local node; node=$(node_bin) || { pass "adapter EPIPE (SKIPPED: node not available)"; return; }
  cat > "$TEST_ROOT/driver-big.mjs" <<DRIVER
import { scanner } from "$ROOT/share/scanner.mjs";
const packages = Array.from({ length: 4000 }, (_, i) => ({
  name: "pkg-" + i, version: "1.0.0",
}));
const advisories = await scanner.scan({ packages });
console.log(JSON.stringify(advisories));
DRIVER
  cat > "$MOCKBIN/safe-audit-stub" <<'STUB'
#!/usr/bin/env bash
exec 0<&-
printf '[]\n'
exit 0
STUB
  chmod +x "$MOCKBIN/safe-audit-stub"
  local out rc=0
  out=$(SAFE_AUDIT_BIN="$MOCKBIN/safe-audit-stub" "$node" "$TEST_ROOT/driver-big.mjs" 2>&1) || rc=$?
  if [[ "$rc" != "0" && "$out" == *"did not receive the full package list"* ]]; then
    pass "adapter rejects when the request channel breaks (EPIPE, zero-exit child)"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "adapter rejects when the request channel breaks (EPIPE, zero-exit child)"
  fi
}

# --- cases: scanner-batch --evidence -----------------------------------------
# The structured twin of the batch: one document, each identity's validated
# answer and coverage kept apart, so a later failure never erases a validated
# hit and a malformed answer is never read as empty.

evidence_identity() { # <doc> <name> <version> <jq filter on the identity>
  jq -e --arg n "$2" --arg v "$3" ".identities[] | select(.name == \$n and .version == \$v) | $4" <<<"$1" >/dev/null
}

case_evidence_clean_tree_is_complete_and_empty() {
  setup_case ev-clean
  MOCK_BATCH_FIXTURE="$FIXDIR/batch-ev-clean.json"
  printf '{"results": [{}, {}]}\n' > "$MOCK_BATCH_FIXTURE"
  local out rc=0
  out=$(printf '{"packages":[{"name":"left-pad","version":"1.3.0"},{"name":"lodash","version":"4.17.21"}]}' | run_evidence) || rc=$?
  if [[ "$rc" == "0" ]] \
    && jq -e '.schema_version == 1 and .policy.block_severities == ["critical"] and .blocklist == []
        and (.identities | length == 2)
        and ([.identities[] | .coverage == "complete" and .gap == "" and .advisories == []] | all)' <<<"$out" >/dev/null; then
    pass "evidence: clean tree is complete with empty advisories"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "evidence: clean tree is complete with empty advisories"
  fi
}

case_evidence_malformed_stdin_refuses() {
  setup_case ev-malformed
  local rc=0 out
  out=$(printf 'not json' | run_evidence 2>/dev/null) || rc=$?
  if [[ "$rc" == "2" && -z "$out" ]]; then
    pass "evidence: malformed stdin exits 2 with no document"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "evidence: malformed stdin exits 2 with no document"
  fi
}

case_evidence_keeps_severity_ladder_and_malware_identity() {
  setup_case ev-ladder
  printf '{"install": {"block_severities": ["critical", "Medium"]}}\n' > "$RUN_DIR/config.json"
  MOCK_BATCH_FIXTURE="$FIXDIR/batch-ev-ladder.json"
  printf '%s\n' '{"results": [
    {"vulns": [{"id": "GHSA-evc-0001"}]},
    {"vulns": [{"id": "MAL-2026-4242"}]},
    {"vulns": [{"id": "GHSA-evv-0002"}, {"id": "GHSA-evu-0003"}]}]}' > "$MOCK_BATCH_FIXTURE"
  # aaa: a CVSS vector must band through the existing ladder (critical), not
  # read as "low". ccc: one record without any severity reads "unknown".
  # No vuln-MAL-* fixture exists: a fetch attempt would fail the case.
  printf '{"id": "GHSA-evc-0001", "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}\n' > "$FIXDIR/vuln-GHSA-evc-0001.json"
  printf '{"id": "GHSA-evv-0002", "database_specific": {"severity": "MODERATE"}}\n' > "$FIXDIR/vuln-GHSA-evv-0002.json"
  printf '{"id": "GHSA-evu-0003"}\n' > "$FIXDIR/vuln-GHSA-evu-0003.json"
  local out rc=0
  out=$(printf '{"packages":[{"name":"aaa","version":"1.0.0"},{"name":"bbb","version":"2.0.0"},{"name":"ccc","version":"3.0.0"}]}' | run_evidence) || rc=$?
  if [[ "$rc" == "0" ]] \
    && jq -e '.policy.block_severities == ["critical","moderate"]' <<<"$out" >/dev/null \
    && evidence_identity "$out" aaa 1.0.0 '.coverage == "complete" and .advisories == [{id:"GHSA-evc-0001",severity:"critical",malware:false}]' \
    && evidence_identity "$out" bbb 2.0.0 '.coverage == "complete" and .advisories == [{id:"MAL-2026-4242",severity:"critical",malware:true}]' \
    && evidence_identity "$out" ccc 3.0.0 '.advisories == [{id:"GHSA-evu-0003",severity:"unknown",malware:false},{id:"GHSA-evv-0002",severity:"moderate",malware:false}]'; then
    pass "evidence: ladder severities, block_severities, and MAL keeps its affected version"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "evidence: ladder severities, block_severities, and MAL keeps its affected version"
  fi
}

case_evidence_same_name_versions_stay_apart() {
  setup_case ev-versions
  MOCK_BATCH_FIXTURE="$FIXDIR/batch-ev-versions.json"
  printf '{"results": [{"vulns": [{"id": "GHSA-evs-0004"}]}, {}]}\n' > "$MOCK_BATCH_FIXTURE"
  printf '{"id": "GHSA-evs-0004", "database_specific": {"severity": "HIGH"}}\n' > "$FIXDIR/vuln-GHSA-evs-0004.json"
  local out rc=0
  out=$(printf '{"packages":[{"name":"multi","version":"1.0.0"},{"name":"multi","version":"2.0.0"},{"name":"multi","version":"1.0.0"}]}' | run_evidence) || rc=$?
  if [[ "$rc" == "0" ]] \
    && jq -e '.identities | length == 2' <<<"$out" >/dev/null \
    && evidence_identity "$out" multi 1.0.0 '.advisories | length == 1' \
    && evidence_identity "$out" multi 2.0.0 '.advisories == [] and .coverage == "complete"'; then
    pass "evidence: one package at several versions keeps each answer on its own identity"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "evidence: one package at several versions keeps each answer on its own identity"
  fi
}

case_evidence_later_chunk_failure_keeps_earlier_hits() {
  # 150 identities → two querybatch calls. The first answers with a validated
  # critical on its first identity; the second fails in transport. The batch
  # aborts with nothing; the evidence keeps the hit and marks only the second
  # chunk's identities missing.
  setup_case ev-chunk-fail
  local batchdir="$FIXDIR/ev-chunk-fail"
  mkdir -p "$batchdir"; rm -f "$batchdir/.count" "$batchdir"/batch2.*
  jq -n '{results: ([{vulns: [{id: "GHSA-evk-0005"}]}] + [range(99) | {}])}' > "$batchdir/batch1.json"
  : > "$batchdir/batch2.fail"
  printf '{"id": "GHSA-evk-0005", "database_specific": {"severity": "CRITICAL"}}\n' > "$FIXDIR/vuln-GHSA-evk-0005.json"
  local input out rc=0 first last
  input=$(jq -n '{packages: [range(150) | {name: ("pkg-" + (. + 1000 | tostring)), version: "1.0.0"}]}')
  first=$(jq -r '[.packages[].name] | sort | .[0]' <<<"$input")
  last=$(jq -r '[.packages[].name] | sort | .[149]' <<<"$input")
  out=$(printf '%s' "$input" | MOCK_BATCH_DIR="$batchdir" MOCK_BATCH_FIXTURE= run_evidence 2>/dev/null) || rc=$?
  if [[ "$rc" == "0" ]] \
    && jq -e '[.identities[] | select(.coverage == "complete")] | length == 100' <<<"$out" >/dev/null \
    && jq -e '[.identities[] | select(.coverage == "missing")] | length == 50' <<<"$out" >/dev/null \
    && evidence_identity "$out" "$first" 1.0.0 '.advisories[0].id == "GHSA-evk-0005" and .advisories[0].severity == "critical"' \
    && evidence_identity "$out" "$last" 1.0.0 '.coverage == "missing" and (.gap | contains("OSV batch query failed")) and .advisories == []'; then
    pass "evidence: a later chunk's failure keeps the earlier validated hit and marks only its own identities"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "evidence: a later chunk's failure keeps the earlier validated hit and marks only its own identities"
  fi
  # The batch over the same fixtures still aborts on that failure.
  rm -f "$batchdir/.count"
  rc=0
  out=$(printf '%s' "$input" | MOCK_BATCH_DIR="$batchdir" MOCK_BATCH_FIXTURE= run_batch 2>/dev/null) || rc=$?
  if [[ "$rc" == "4" && -z "$out" ]]; then
    pass "evidence: the batch itself still fails closed on the same chunk failure"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "evidence: the batch itself still fails closed on the same chunk failure"
  fi
}

case_evidence_malformed_result_loses_only_itself() {
  # Positional pairing holds (one result per query), so each result stands or
  # falls alone: a sound hit beside a bare string and a null keeps the hit; a
  # chunk whose length does not match loses all of its identities.
  setup_case ev-chunk-malformed
  local batchdir="$FIXDIR/ev-chunk-malformed"
  mkdir -p "$batchdir"; rm -f "$batchdir/.count" "$batchdir"/batch2.*
  jq -n '{results: [range(100) | {}]}' > "$batchdir/batch1.json"
  printf '{"results": [{"vulns": [{"id": "GHSA-evm-0013"}]}, "oops", null]}\n' > "$batchdir/batch2.json"
  printf '{"id": "GHSA-evm-0013", "database_specific": {"severity": "CRITICAL"}}\n' > "$FIXDIR/vuln-GHSA-evm-0013.json"
  local input out rc=0 first second third
  input=$(jq -n '{packages: [range(103) | {name: ("pkg-" + (. + 1000 | tostring)), version: "1.0.0"}]}')
  first=$(jq -r '[.packages[].name] | sort | .[100]' <<<"$input")
  second=$(jq -r '[.packages[].name] | sort | .[101]' <<<"$input")
  third=$(jq -r '[.packages[].name] | sort | .[102]' <<<"$input")
  out=$(printf '%s' "$input" | MOCK_BATCH_DIR="$batchdir" MOCK_BATCH_FIXTURE= run_evidence 2>/dev/null) || rc=$?
  if [[ "$rc" == "0" ]] \
    && jq -e '[.identities[] | select(.coverage == "missing")] | length == 2' <<<"$out" >/dev/null \
    && evidence_identity "$out" "$first" 1.0.0 '.coverage == "complete" and .advisories[0].severity == "critical"' \
    && evidence_identity "$out" "$second" 1.0.0 '.coverage == "missing" and (.gap | contains("malformed OSV batch response")) and .advisories == []' \
    && evidence_identity "$out" "$third" 1.0.0 '.coverage == "missing"'; then
    pass "evidence: a malformed result loses only itself, its sound neighbour keeps its hit"
  else
    printf 'rc=%s out=%s\n' "$rc" "$(jq -c '[.identities[] | select(.coverage == "missing" or (.advisories | length > 0))]' <<<"$out" 2>/dev/null)" >&2
    fail "evidence: a malformed result loses only itself, its sound neighbour keeps its hit"
  fi
  # A chunk answered with the wrong number of results has no positional
  # pairing: every identity in it is a gap, never an empty reading.
  rm -f "$batchdir/.count"
  printf '{"results": [{}, {}]}\n' > "$batchdir/batch2.json"
  rc=0
  out=$(printf '%s' "$input" | MOCK_BATCH_DIR="$batchdir" MOCK_BATCH_FIXTURE= run_evidence 2>/dev/null) || rc=$?
  if [[ "$rc" == "0" ]] && jq -e '[.identities[] | select(.coverage == "missing")] | length == 3' <<<"$out" >/dev/null; then
    pass "evidence: a chunk answered with the wrong number of results is a gap on all its identities"
  else
    fail "evidence: a chunk answered with the wrong number of results is a gap on all its identities"
  fi
}

case_evidence_repeated_member_is_a_gap() {
  # jq keeps the last of two same-named members: {"vulns":[critical],"vulns":[]}
  # would read as an empty answer. A repeated member is refused as malformed.
  setup_case ev-repeated
  MOCK_BATCH_FIXTURE="$FIXDIR/batch-ev-repeated.json"
  printf '{"results": [{"vulns": [{"id": "GHSA-evr-0014"}], "vulns": []}]}\n' > "$MOCK_BATCH_FIXTURE"
  local out rc=0
  out=$(printf '{"packages":[{"name":"rep","version":"1.0.0"}]}' | run_evidence 2>/dev/null) || rc=$?
  if [[ "$rc" == "0" ]] && evidence_identity "$out" rep 1.0.0 '.coverage == "missing" and (.gap | contains("repeated member"))'; then
    pass "evidence: a repeated member in the batch answer is a gap, not the last value"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "evidence: a repeated member in the batch answer is a gap, not the last value"
  fi
  # And in an advisory record: the identity keeps its other hits and is missing.
  MOCK_BATCH_FIXTURE="$FIXDIR/batch-ev-repeated2.json"
  printf '{"results": [{"vulns": [{"id": "GHSA-evr-0015"}]}]}\n' > "$MOCK_BATCH_FIXTURE"
  printf '{"id": "GHSA-evr-0015", "database_specific": {"severity": "CRITICAL", "severity": "LOW"}}\n' > "$FIXDIR/vuln-GHSA-evr-0015.json"
  rc=0
  out=$(printf '{"packages":[{"name":"rep","version":"2.0.0"}]}' | run_evidence 2>/dev/null) || rc=$?
  if [[ "$rc" == "0" ]] && evidence_identity "$out" rep 2.0.0 '.coverage == "missing" and .advisories == [] and (.gap | contains("GHSA-evr-0015: OSV advisory record malformed"))'; then
    pass "evidence: a repeated member in an advisory record is a gap, not the last value"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "evidence: a repeated member in an advisory record is a gap, not the last value"
  fi
}

case_evidence_pagination_failure_keeps_first_page() {
  setup_case ev-page-fail
  MOCK_BATCH_FIXTURE="$FIXDIR/batch-ev-page.json"
  printf '{"results": [{"vulns": [{"id": "GHSA-evp-0006"}], "next_page_token": "tok"}, {"vulns": [{"id": "GHSA-evp-0007"}]}]}\n' > "$MOCK_BATCH_FIXTURE"
  printf '{"id": "GHSA-evp-0006", "database_specific": {"severity": "CRITICAL"}}\n' > "$FIXDIR/vuln-GHSA-evp-0006.json"
  printf '{"id": "GHSA-evp-0007", "database_specific": {"severity": "LOW"}}\n' > "$FIXDIR/vuln-GHSA-evp-0007.json"
  local out rc=0
  out=$(printf '{"packages":[{"name":"paged","version":"1.0.0"},{"name":"plain","version":"1.0.0"}]}' | MOCK_QUERY_STATUS=1 run_evidence 2>/dev/null) || rc=$?
  if [[ "$rc" == "0" ]] \
    && evidence_identity "$out" paged 1.0.0 '.coverage == "missing" and (.gap | contains("pagination")) and .advisories == [{id:"GHSA-evp-0006",severity:"critical",malware:false}]' \
    && evidence_identity "$out" plain 1.0.0 '.coverage == "complete" and .advisories[0].severity == "low"'; then
    pass "evidence: a failed pagination re-query keeps the validated first page and marks the identity missing"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "evidence: a failed pagination re-query keeps the validated first page and marks the identity missing"
  fi
  # The validated hit of page ONE survives a failure on page two, with the
  # batch answer carrying nothing but a token (the shape a truncated page has).
  local qdir="$FIXDIR/ev-pages"
  mkdir -p "$qdir"; rm -f "$qdir/.count" "$qdir"/query2.*
  MOCK_BATCH_FIXTURE="$FIXDIR/batch-ev-tokenonly.json"
  printf '{"results": [{"next_page_token": "tok"}]}\n' > "$MOCK_BATCH_FIXTURE"
  printf '{"vulns": [{"id": "GHSA-evp-0016"}], "next_page_token": "tok2"}\n' > "$qdir/query1.json"
  : > "$qdir/query2.fail"
  printf '{"id": "GHSA-evp-0016", "database_specific": {"severity": "CRITICAL"}}\n' > "$FIXDIR/vuln-GHSA-evp-0016.json"
  rc=0
  out=$(printf '{"packages":[{"name":"twopage","version":"1.0.0"}]}' | MOCK_QUERY_DIR="$qdir" run_evidence 2>/dev/null) || rc=$?
  if [[ "$rc" == "0" ]] \
    && evidence_identity "$out" twopage 1.0.0 '.coverage == "missing" and (.gap | contains("pagination")) and .advisories == [{id:"GHSA-evp-0016",severity:"critical",malware:false}]'; then
    pass "evidence: a hit read on page one survives a failure on page two"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "evidence: a hit read on page one survives a failure on page two"
  fi
  # A successful re-query keeps the batch answer's validated hits too, even
  # when the re-query's own pages do not repeat them.
  rm -f "$qdir/.count" "$qdir"/query2.*
  MOCK_BATCH_FIXTURE="$FIXDIR/batch-ev-keep.json"
  printf '{"results": [{"vulns": [{"id": "GHSA-evp-0017"}], "next_page_token": "tok"}]}\n' > "$MOCK_BATCH_FIXTURE"
  printf '{"vulns": [{"id": "GHSA-evp-0016"}]}\n' > "$qdir/query1.json"
  printf '{"id": "GHSA-evp-0017", "database_specific": {"severity": "LOW"}}\n' > "$FIXDIR/vuln-GHSA-evp-0017.json"
  rc=0
  out=$(printf '{"packages":[{"name":"twopage","version":"1.0.0"}]}' | MOCK_QUERY_DIR="$qdir" run_evidence 2>/dev/null) || rc=$?
  if [[ "$rc" == "0" ]] \
    && evidence_identity "$out" twopage 1.0.0 '.coverage == "complete" and ([.advisories[].id] == ["GHSA-evp-0016","GHSA-evp-0017"])'; then
    pass "evidence: a successful re-query is the union with the batch answer's validated hits"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "evidence: a successful re-query is the union with the batch answer's validated hits"
  fi
  # And a complete re-query still merges to completeness.
  MOCK_QUERY_FIXTURE="$FIXDIR/query-ev-page.json"
  printf '{"vulns": [{"id": "GHSA-evp-0006"}, {"id": "GHSA-evp-0008"}]}\n' > "$MOCK_QUERY_FIXTURE"
  printf '{"id": "GHSA-evp-0008", "database_specific": {"severity": "HIGH"}}\n' > "$FIXDIR/vuln-GHSA-evp-0008.json"
  rc=0
  MOCK_BATCH_FIXTURE="$FIXDIR/batch-ev-page1.json"
  printf '{"results": [{"vulns": [{"id": "GHSA-evp-0006"}], "next_page_token": "tok"}]}\n' > "$MOCK_BATCH_FIXTURE"
  out=$(printf '{"packages":[{"name":"paged","version":"1.0.0"}]}' | run_evidence 2>/dev/null) || rc=$?
  if [[ "$rc" == "0" ]] \
    && evidence_identity "$out" paged 1.0.0 '.coverage == "complete" and ([.advisories[].id] == ["GHSA-evp-0006","GHSA-evp-0008"])'; then
    pass "evidence: a complete pagination re-query is read to completeness"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "evidence: a complete pagination re-query is read to completeness"
  fi
}

case_evidence_detail_failure_keeps_other_hits() {
  setup_case ev-detail
  MOCK_BATCH_FIXTURE="$FIXDIR/batch-ev-detail.json"
  printf '{"results": [{"vulns": [{"id": "GHSA-evd-0009"}, {"id": "GHSA-evd-0010"}, {"id": "MAL-2026-777"}]}, {"vulns": [{"id": "GHSA-evd-0011"}]}]}\n' > "$MOCK_BATCH_FIXTURE"
  printf '{"id": "GHSA-evd-0009", "database_specific": {"severity": "CRITICAL"}}\n' > "$FIXDIR/vuln-GHSA-evd-0009.json"
  # 0010: an advisory record that is not the advisory asked for; 0011: no
  # fixture at all (the fetch fails).
  printf '{"id": "GHSA-someone-else"}\n' > "$FIXDIR/vuln-GHSA-evd-0010.json"
  : > "$FIXDIR/vuln-GHSA-evd-0011.fail"
  local out rc=0
  out=$(printf '{"packages":[{"name":"dd1","version":"1.0.0"},{"name":"dd2","version":"1.0.0"}]}' | run_evidence 2>/dev/null) || rc=$?
  if [[ "$rc" == "0" ]] \
    && evidence_identity "$out" dd1 1.0.0 '.coverage == "missing" and (.gap | contains("GHSA-evd-0010: OSV advisory record malformed"))
        and ([.advisories[] | .id] == ["GHSA-evd-0009","MAL-2026-777"])' \
    && evidence_identity "$out" dd2 1.0.0 '.coverage == "missing" and (.gap | contains("GHSA-evd-0011: OSV advisory fetch failed")) and .advisories == []'; then
    pass "evidence: a failed or malformed detail drops only that advisory and names it in the gap"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "evidence: a failed or malformed detail drops only that advisory and names it in the gap"
  fi
}

case_evidence_blocklist_is_independent_of_osv() {
  setup_case ev-blocklist
  printf '{"packages": {"evil-pkg": {"reason": "operator blocklist test"}, "@scope/*": {"reason": "scope blocked"}}}\n' > "$RUN_DIR/blocked.json"
  local out rc=0
  out=$(printf '{"packages":[{"name":"evil-pkg","version":"1.0.0"},{"name":"@scope/x","version":"2.0.0"},{"name":"fine","version":"1.0.0"}]}' \
    | MOCK_BATCH_STATUS=1 run_evidence 2>/dev/null) || rc=$?
  if [[ "$rc" == "0" ]] \
    && jq -e '.blocklist == [{name:"@scope/x",reason:"scope blocked"},{name:"evil-pkg",reason:"operator blocklist test"}]
        and ([.identities[] | .coverage == "missing"] | all)' <<<"$out" >/dev/null; then
    pass "evidence: blocklist hits are reported by name whatever the OSV reading did"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "evidence: blocklist hits are reported by name whatever the OSV reading did"
  fi
}

case_evidence_unreadable_blocklist_fails_closed() {
  setup_case ev-blocklist-bad
  printf '{"packages": [1]}\n' > "$RUN_DIR/blocked.json"
  MOCK_BATCH_FIXTURE="$FIXDIR/batch-ev-bl.json"
  printf '{"results": [{}]}\n' > "$MOCK_BATCH_FIXTURE"
  local out rc=0
  out=$(printf '{"packages":[{"name":"x","version":"1.0.0"}]}' | run_evidence 2>"$TEST_ROOT/ev-bl.err") || rc=$?
  if [[ "$rc" == "4" && -z "$out" ]] && grep -q "blocklist file unreadable" "$TEST_ROOT/ev-bl.err"; then
    pass "evidence: an unreadable blocklist yields no document"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "evidence: an unreadable blocklist yields no document"
  fi
}

case_evidence_document_is_read_by_the_decision() {
  # The two sides of the contract in one run: the evidence this mode writes,
  # plus the acceptances the gate adds, is a document safe-core's decision
  # reads; a malformed answer on the target side is Missing evidence there.
  setup_case ev-contract
  MOCK_BATCH_FIXTURE="$FIXDIR/batch-ev-contract.json"
  printf '%s\n' '{"results": [{"vulns": [{"id": "GHSA-evx-0012"}]}, {}, {"vulns": [{"id": "MAL-2026-1"}]}]}' > "$MOCK_BATCH_FIXTURE"
  printf '{"id": "GHSA-evx-0012", "database_specific": {"severity": "CRITICAL"}}\n' > "$FIXDIR/vuln-GHSA-evx-0012.json"
  local evidence="$TEST_ROOT/ev-contract.json" lock="$TEST_ROOT/ev-contract-lock.json" out rc=0 sri
  sri="sha512-$(head -c 64 /dev/zero | base64 -w0)"
  printf '{"packages":[{"name":"crit","version":"1.0.0"},{"name":"mal","version":"1.0.0"},{"name":"fine","version":"1.0.0"}]}' \
    | run_evidence 2>/dev/null | jq -c '. + {acceptances: []}' > "$evidence"
  jq -n --arg sri "$sri" '{lockfileVersion: 3, packages: ({"": {name: "root"}} + ([["crit","1.0.0"],["mal","1.0.0"],["fine","1.0.0"]] | map({key: ("node_modules/" + .[0]),
    value: {version: .[1], resolved: ("https://registry.npmjs.org/" + .[0] + "/-/" + .[0] + "-" + .[1] + ".tgz"),
            integrity: $sri}}) | from_entries))}' > "$lock"
  out=$("$SAFE_CORE_BIN" project-decide --no-baseline --evidence "$evidence" "$lock") || rc=$?
  if [[ "$rc" == "0" ]] \
    && jq -e '.outcome == {status:"stopped",class:"malice",exit:104}
        and (.malice | length == 1 and .[0].name == "mal" and .[0].versions == ["1.0.0"] and .[0].id == "MAL-2026-1")
        and (.advisories.introduced | length == 1 and .[0].name == "crit" and .[0].class == "blocking")' <<<"$out" >/dev/null; then
    pass "evidence: the document the mode writes is the one safe-core project-decide reads"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "evidence: the document the mode writes is the one safe-core project-decide reads"
  fi
}

# A stand-in for safe-core that reports the tree's version and answers the
# repeated-member check as told: the real answer for the first FAKE_OK calls,
# then FAKE_MODE ("exit2": status 2, "garbage": status 0 with a non-array on
# stdout).
make_fake_core() { # <path>
  cat > "$1" <<FAKE
#!/usr/bin/env bash
if [[ "\${1:-}" == "--version" ]]; then printf '%s\n' "$(tr -d '[:space:]' < "$ROOT/VERSION")"; exit 0; fi
count_file="\${FAKE_COUNT:?}"
count=\$(( \$(cat "\$count_file" 2>/dev/null || echo 0) + 1 ))
printf '%s' "\$count" > "\$count_file"
if (( count > \${FAKE_OK:-0} )); then
  case "\${FAKE_MODE:-exit2}" in
    exit2) exit 2 ;;
    garbage) printf 'not an array\n'; exit 0 ;;
  esac
fi
exec "$SAFE_CORE_BIN" "\$@"
FAKE
  chmod +x "$1"
}

case_evidence_duplicate_in_one_result_keeps_its_neighbour() {
  # Pairing is sound (one results array of the right length); the duplicate is
  # confined to the second result, so only that result is lost.
  setup_case ev-dup-one
  MOCK_BATCH_FIXTURE="$FIXDIR/batch-ev-dup-one.json"
  printf '{"results":[{"vulns":[{"id":"TEST-A"}]},{"vulns":[],"vulns":[]}]}\n' > "$MOCK_BATCH_FIXTURE"
  printf '{"id": "TEST-A", "database_specific": {"severity": "CRITICAL"}}\n' > "$FIXDIR/vuln-TEST-A.json"
  local out rc=0
  out=$(printf '{"packages":[{"name":"aaa","version":"1.0.0"},{"name":"bbb","version":"1.0.0"}]}' | run_evidence 2>/dev/null) || rc=$?
  if [[ "$rc" == "0" ]] \
    && evidence_identity "$out" aaa 1.0.0 '.coverage == "complete" and .advisories == [{id:"TEST-A",severity:"critical",malware:false}]' \
    && evidence_identity "$out" bbb 1.0.0 '.coverage == "missing" and (.gap | contains("repeated member")) and .advisories == []'; then
    pass "evidence: a repeated member inside one result costs that result only"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "evidence: a repeated member inside one result costs that result only"
  fi
  # A repeated member in the envelope cannot be trusted per result.
  printf '{"results":[{"vulns":[{"id":"TEST-A"}]},{}],"results":[{},{}]}\n' > "$MOCK_BATCH_FIXTURE"
  rc=0
  out=$(printf '{"packages":[{"name":"aaa","version":"1.0.0"},{"name":"bbb","version":"1.0.0"}]}' | run_evidence 2>/dev/null) || rc=$?
  if [[ "$rc" == "0" ]] && jq -e '[.identities[] | .coverage == "missing"] | all' <<<"$out" >/dev/null; then
    pass "evidence: a repeated envelope member leaves the whole chunk missing"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "evidence: a repeated envelope member leaves the whole chunk missing"
  fi
  # Member names are compared exactly: case and Case are two names.
  printf '{"results":[{"vulns":[{"id":"TEST-A","case":1,"Case":2}]},{}]}\n' > "$MOCK_BATCH_FIXTURE"
  rc=0
  out=$(printf '{"packages":[{"name":"aaa","version":"1.0.0"},{"name":"bbb","version":"1.0.0"}]}' | run_evidence 2>/dev/null) || rc=$?
  if [[ "$rc" == "0" ]] && jq -e '[.identities[] | .coverage == "complete"] | all' <<<"$out" >/dev/null; then
    pass "evidence: names differing only by case are not a repeated member"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "evidence: names differing only by case are not a repeated member"
  fi
}

case_evidence_checker_does_not_fail_open() {
  setup_case ev-checker
  local input='{"packages":[{"name":"aaa","version":"1.0.0"},{"name":"bbb","version":"1.0.0"}]}' out rc=0
  # 1e400 is a number no float64 holds; the walk must go on to the duplicate.
  MOCK_BATCH_FIXTURE="$FIXDIR/batch-ev-big.json"
  printf '{"extra":1e400,"results":[{"vulns":[{"id":"TEST-A"}],"vulns":[]},{}]}\n' > "$MOCK_BATCH_FIXTURE"
  out=$(printf '%s' "$input" | run_evidence 2>/dev/null) || rc=$?
  if [[ "$rc" == "0" ]] \
    && evidence_identity "$out" aaa 1.0.0 '.coverage == "missing" and (.gap | contains("repeated member"))' \
    && evidence_identity "$out" bbb 1.0.0 '.coverage == "complete"'; then
    pass "evidence: 1e400 does not end the repeated-member walk"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "evidence: 1e400 does not end the repeated-member walk"
  fi
  # jq accepts NaN; it is not JSON.
  printf '{"extra":NaN,"results":[{},{}]}\n' > "$MOCK_BATCH_FIXTURE"
  rc=0
  out=$(printf '%s' "$input" | run_evidence 2>/dev/null) || rc=$?
  if [[ "$rc" == "0" ]] && jq -e '[.identities[] | .coverage == "missing" and (.gap | contains("not valid JSON"))] | all' <<<"$out" >/dev/null; then
    pass "evidence: a NaN in the batch answer is a malformed answer, not a clean reading"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "evidence: a NaN in the batch answer is a malformed answer, not a clean reading"
  fi
  # A checker that cannot answer is breakage (exit 4), never "no duplicate".
  local fake="$TEST_ROOT/fake-core"
  make_fake_core "$fake"
  printf '{"results":[{},{}]}\n' > "$MOCK_BATCH_FIXTURE"
  local mode
  for mode in exit2 garbage; do
    rc=0
    : > "$TEST_ROOT/fake-count"
    out=$(printf '%s' "$input" | SAFE_CORE_BIN="$fake" FAKE_COUNT="$TEST_ROOT/fake-count" FAKE_MODE="$mode" FAKE_OK=0 run_evidence 2>"$TEST_ROOT/fake.err") || rc=$?
    if [[ "$rc" == "4" && -z "$out" ]] && grep -q "unusable" "$TEST_ROOT/fake.err"; then
      pass "evidence: a checker that answers '$mode' is audit-infrastructure breakage (exit 4)"
    else
      printf 'rc=%s out=%s\n' "$rc" "$out" >&2
      fail "evidence: a checker that answers '$mode' is audit-infrastructure breakage (exit 4)"
    fi
  done
  # The same at the page boundary (second call) and the detail boundary (third).
  printf '{"results":[{"vulns":[{"id":"TEST-A"}],"next_page_token":"tok"},{}]}\n' > "$MOCK_BATCH_FIXTURE"
  printf '{"vulns":[{"id":"TEST-A"}]}\n' > "$FIXDIR/query-ev-fake.json"
  printf '{"id": "TEST-A", "database_specific": {"severity": "CRITICAL"}}\n' > "$FIXDIR/vuln-TEST-A.json"
  local ok
  for ok in 1 2; do
    rc=0
    : > "$TEST_ROOT/fake-count"
    out=$(printf '%s' "$input" | SAFE_CORE_BIN="$fake" FAKE_COUNT="$TEST_ROOT/fake-count" FAKE_MODE=exit2 FAKE_OK="$ok" \
      MOCK_QUERY_FIXTURE="$FIXDIR/query-ev-fake.json" run_evidence 2>"$TEST_ROOT/fake.err") || rc=$?
    if [[ "$rc" == "4" && -z "$out" ]] && grep -q "unusable" "$TEST_ROOT/fake.err"; then
      pass "evidence: an unusable checker after $ok good call(s) is exit 4 (page/detail boundary)"
    else
      printf 'rc=%s out=%s\n' "$rc" "$out" >&2
      fail "evidence: an unusable checker after $ok good call(s) is exit 4 (page/detail boundary)"
    fi
  done
}

case_evidence_page_and_detail_answers_are_checked_too() {
  setup_case ev-page-detail
  local input='{"packages":[{"name":"pg","version":"1.0.0"}]}' out rc=0
  MOCK_BATCH_FIXTURE="$FIXDIR/batch-ev-pd.json"
  printf '{"results":[{"vulns":[{"id":"TEST-B"}],"next_page_token":"tok"}]}\n' > "$MOCK_BATCH_FIXTURE"
  printf '{"id": "TEST-B", "database_specific": {"severity": "CRITICAL"}}\n' > "$FIXDIR/vuln-TEST-B.json"
  local body
  for body in '{"vulns":[{"id":"TEST-B"}],"extra":NaN}' '{"vulns":[{"id":"TEST-B"}],"vulns":[]}'; do
    printf '%s\n' "$body" > "$FIXDIR/query-ev-pd.json"
    rc=0
    out=$(printf '%s' "$input" | MOCK_QUERY_FIXTURE="$FIXDIR/query-ev-pd.json" run_evidence 2>/dev/null) || rc=$?
    if [[ "$rc" == "0" ]] \
      && evidence_identity "$out" pg 1.0.0 '.coverage == "missing" and (.gap | contains("pagination")) and ([.advisories[].id] == ["TEST-B"])'; then
      pass "evidence: a page that is not valid JSON or repeats a member is a gap that keeps the batch hit"
    else
      printf 'rc=%s out=%s\n' "$rc" "$out" >&2
      fail "evidence: a page that is not valid JSON or repeats a member is a gap that keeps the batch hit"
    fi
  done
  # A detail record with a NaN is malformed; the other hits stay.
  printf '{"results":[{"vulns":[{"id":"TEST-C"},{"id":"MAL-2026-5"}]}]}\n' > "$MOCK_BATCH_FIXTURE"
  printf '{"id": "TEST-C", "database_specific": {"severity": NaN}}\n' > "$FIXDIR/vuln-TEST-C.json"
  rc=0
  out=$(printf '%s' "$input" | run_evidence 2>/dev/null) || rc=$?
  if [[ "$rc" == "0" ]] \
    && evidence_identity "$out" pg 1.0.0 '.coverage == "missing" and (.gap | contains("TEST-C: OSV advisory record malformed")) and ([.advisories[].id] == ["MAL-2026-5"])'; then
    pass "evidence: a detail record that is not valid JSON is a gap, the other hits stay"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "evidence: a detail record that is not valid JSON is a gap, the other hits stay"
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
case_cvss_vector_critical_is_fatal
case_conflicting_severity_candidates_max_wins
case_unknown_severity_respects_knob
case_malformed_batch_entries_fail_closed
case_malformed_advisory_record_fails_closed
case_unreadable_blocklist_fails_closed
case_hostile_advisory_ids_fail_closed
case_chunk_alignment_across_batches
case_multidoc_responses_fail_closed
case_paginated_requery_enforces_id_schema
case_severity_scoped_to_queried_package
case_numeric_detail_id_fails_closed
case_blocklist_entry_schema_fails_closed
case_same_name_different_versions_stay_distinct
case_multidoc_raw_page_fails_closed
case_shared_advisory_scopes_per_package
case_whitespace_package_names_refused
case_gate_injects_scanner_env
case_adapter_maps_advisories
case_adapter_throws_on_nonzero_exit
case_adapter_throws_on_malformed_payload
case_adapter_rejects_malformed_advisory_elements
case_adapter_throws_on_missing_binary
case_adapter_times_out_hung_child
case_adapter_rejects_partial_request_channel
if (( SC_OK )); then
  case_evidence_clean_tree_is_complete_and_empty
  case_evidence_malformed_stdin_refuses
  case_evidence_keeps_severity_ladder_and_malware_identity
  case_evidence_same_name_versions_stay_apart
  case_evidence_later_chunk_failure_keeps_earlier_hits
  case_evidence_malformed_result_loses_only_itself
  case_evidence_repeated_member_is_a_gap
  case_evidence_pagination_failure_keeps_first_page
  case_evidence_detail_failure_keeps_other_hits
  case_evidence_blocklist_is_independent_of_osv
  case_evidence_unreadable_blocklist_fails_closed
  case_evidence_document_is_read_by_the_decision
  case_evidence_duplicate_in_one_result_keeps_its_neighbour
  case_evidence_checker_does_not_fail_open
  case_evidence_page_and_detail_answers_are_checked_too
else
  pass "evidence cases (SKIPPED: safe-core not buildable here)"
fi

printf '%d passed, %d failed\n' "$PASS_COUNT" "$FAIL_COUNT"
(( FAIL_COUNT == 0 ))
