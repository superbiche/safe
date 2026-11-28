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

# blocklist_names belongs to the evidence mode: the plain batch accepts what it
# always accepted, an unrelated member of that name included.
case_plain_batch_ignores_an_unrelated_blocklist_names_member() {
  setup_case plain-extension
  MOCK_BATCH_FIXTURE="$FIXDIR/batch-plain-ext.json"
  printf '{"results": [{}]}\n' > "$MOCK_BATCH_FIXTURE"
  local out rc=0 value
  for value in '"x"' '{"a":1}' '7'; do
    rc=0
    out=$(printf '{"packages":[{"name":"left-pad","version":"1.3.0"}],"blocklist_names":%s}' "$value" | run_batch) || rc=$?
    if [[ "$rc" == "0" && "$(jq -c . <<<"$out")" == "[]" ]]; then
      pass "plain batch: an unrelated blocklist_names member (${value}) is accepted as before"
    else
      printf 'rc=%s out=%s\n' "$rc" "$out" >&2
      fail "plain batch: an unrelated blocklist_names member (${value}) is accepted as before"
    fi
  done
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

# A withdrawn advisory (its record carries a withdrawal date) is removed before it can count: no hit, no gap. The one that
# is not withdrawn stays. (The lane's security-fix waiver rests on this evidence.)
case_evidence_a_withdrawn_advisory_is_removed() {
  setup_case ev-withdrawn
  MOCK_BATCH_FIXTURE="$FIXDIR/batch-ev-withdrawn.json"
  printf '%s\n' '{"results": [{"vulns": [{"id": "GHSA-wd-0001"}, {"id": "GHSA-wd-0002"}]}]}' > "$MOCK_BATCH_FIXTURE"
  printf '{"id": "GHSA-wd-0001", "withdrawn": "2026-10-01T00:00:00Z", "database_specific": {"severity": "HIGH"}}\n' > "$FIXDIR/vuln-GHSA-wd-0001.json"
  printf '{"id": "GHSA-wd-0002", "withdrawn": "", "database_specific": {"severity": "HIGH"}}\n' > "$FIXDIR/vuln-GHSA-wd-0002.json"
  local out rc=0
  out=$(printf '{"packages":[{"name":"wdp","version":"1.0.0"}]}' | run_evidence) || rc=$?
  if [[ "$rc" == "0" ]] && evidence_identity "$out" wdp 1.0.0 '.coverage == "complete" and .advisories == [{id:"GHSA-wd-0002",severity:"high",malware:false}]'; then
    pass "evidence: a withdrawn advisory is removed, the live one stays, and nothing is a gap"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "evidence: a withdrawn advisory is removed, the live one stays, and nothing is a gap"
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
  # 1,050 identities → two querybatch calls (the evidence mode asks 1,000 at a
  # time). The first answers with a validated critical on its first identity;
  # the second fails in transport. The evidence keeps the hit and marks only the
  # second chunk's identities missing; the batch (chunks of 100) over 150
  # identities aborts with nothing on the same kind of failure.
  setup_case ev-chunk-fail
  local batchdir="$FIXDIR/ev-chunk-fail"
  mkdir -p "$batchdir"; rm -f "$batchdir/.count" "$batchdir"/batch2.*
  jq -n '{results: ([{vulns: [{id: "GHSA-evk-0005"}]}] + [range(999) | {}])}' > "$batchdir/batch1.json"
  : > "$batchdir/batch2.fail"
  printf '{"id": "GHSA-evk-0005", "database_specific": {"severity": "CRITICAL"}}\n' > "$FIXDIR/vuln-GHSA-evk-0005.json"
  local input out rc=0 first last
  input=$(jq -n '{packages: [range(1050) | {name: ("pkg-" + (. + 1000 | tostring)), version: "1.0.0"}]}')
  first=$(jq -r '[.packages[].name] | sort | .[0]' <<<"$input")
  last=$(jq -r '[.packages[].name] | sort | .[1049]' <<<"$input")
  out=$(printf '%s' "$input" | MOCK_BATCH_DIR="$batchdir" MOCK_BATCH_FIXTURE= run_evidence 2>/dev/null) || rc=$?
  if [[ "$rc" == "0" ]] \
    && jq -e '[.identities[] | select(.coverage == "complete")] | length == 1000' <<<"$out" >/dev/null \
    && jq -e '[.identities[] | select(.coverage == "missing")] | length == 50' <<<"$out" >/dev/null \
    && evidence_identity "$out" "$first" 1.0.0 '.advisories[0].id == "GHSA-evk-0005" and .advisories[0].severity == "critical"' \
    && evidence_identity "$out" "$last" 1.0.0 '.coverage == "missing" and (.gap | contains("OSV batch query failed")) and .advisories == []'; then
    pass "evidence: a later chunk's failure keeps the earlier validated hit and marks only its own identities"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "evidence: a later chunk's failure keeps the earlier validated hit and marks only its own identities"
  fi
  # The batch (chunks of 100, 150 identities) still aborts on a chunk's failure.
  local batchdir2="$FIXDIR/ev-chunk-fail-batch"
  mkdir -p "$batchdir2"; rm -f "$batchdir2/.count" "$batchdir2"/batch2.*
  jq -n '{results: [range(100) | {}]}' > "$batchdir2/batch1.json"
  : > "$batchdir2/batch2.fail"
  input=$(jq -n '{packages: [range(150) | {name: ("pkg-" + (. + 1000 | tostring)), version: "1.0.0"}]}')
  rc=0
  out=$(printf '%s' "$input" | MOCK_BATCH_DIR="$batchdir2" MOCK_BATCH_FIXTURE= run_batch 2>/dev/null) || rc=$?
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
  jq -n '{results: [range(1000) | {}]}' > "$batchdir/batch1.json"
  printf '{"results": [{"vulns": [{"id": "GHSA-evm-0013"}]}, "oops", null]}\n' > "$batchdir/batch2.json"
  printf '{"id": "GHSA-evm-0013", "database_specific": {"severity": "CRITICAL"}}\n' > "$FIXDIR/vuln-GHSA-evm-0013.json"
  local input out rc=0 first second third
  input=$(jq -n '{packages: [range(1003) | {name: ("pkg-" + (. + 1000 | tostring)), version: "1.0.0"}]}')
  first=$(jq -r '[.packages[].name] | sort | .[1000]' <<<"$input")
  second=$(jq -r '[.packages[].name] | sort | .[1001]' <<<"$input")
  third=$(jq -r '[.packages[].name] | sort | .[1002]' <<<"$input")
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

case_evidence_blocklist_names_and_empty_requests() {
  setup_case ev-blocklist-names
  printf '{"packages": {"private-thing": {"reason": "operator blocklist test"}}}\n' > "$RUN_DIR/blocked.json"
  local out rc=0
  # A name that is not an advisory identity (a link, a private artifact) is
  # still checked against the blocklist, and is never sent to OSV.
  out=$(printf '{"packages":[],"blocklist_names":["private-thing","other"]}' | MOCK_BATCH_STATUS=1 run_evidence 2>/dev/null) || rc=$?
  if [[ "$rc" == "0" ]] \
    && jq -e '.blocklist == [{name:"private-thing",reason:"operator blocklist test"}] and .identities == []' <<<"$out" >/dev/null; then
    pass "evidence: blocklist_names are checked by name and never queried; an empty request is allowed"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "evidence: blocklist_names are checked by name and never queried; an empty request is allowed"
  fi
  # An empty request still reads the blocklist: an unreadable one fails closed.
  printf '{"packages": [1]}\n' > "$RUN_DIR/blocked.json"
  rc=0
  out=$(printf '{"packages":[]}' | run_evidence 2>/dev/null) || rc=$?
  if [[ "$rc" == "4" && -z "$out" ]]; then
    pass "evidence: an empty request over an unreadable blocklist yields no document"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "evidence: an empty request over an unreadable blocklist yields no document"
  fi
  # The plain batch still refuses an empty request.
  rc=0
  printf '{"packages":[]}' | run_batch >/dev/null 2>&1 || rc=$?
  if [[ "$rc" == "2" ]]; then
    pass "evidence: the plain batch still refuses an empty request"
  else
    fail "evidence: the plain batch still refuses an empty request (rc=$rc)"
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
  # untouched (the standing acceptances are a separate input of the decision),
  # is a document safe-core's decision reads; its exit status is the
  # outcome's; a malformed answer on the target side is Missing evidence there.
  setup_case ev-contract
  MOCK_BATCH_FIXTURE="$FIXDIR/batch-ev-contract.json"
  printf '%s\n' '{"results": [{"vulns": [{"id": "GHSA-evx-0012"}]}, {}, {"vulns": [{"id": "MAL-2026-1"}]}]}' > "$MOCK_BATCH_FIXTURE"
  printf '{"id": "GHSA-evx-0012", "database_specific": {"severity": "CRITICAL"}}\n' > "$FIXDIR/vuln-GHSA-evx-0012.json"
  local evidence="$TEST_ROOT/ev-contract.json" lock="$TEST_ROOT/ev-contract-lock.json" out rc=0 sri
  sri="sha512-$(head -c 64 /dev/zero | base64 -w0)"
  printf '{"packages":[{"name":"crit","version":"1.0.0"},{"name":"mal","version":"1.0.0"},{"name":"fine","version":"1.0.0"}]}' \
    | run_evidence 2>/dev/null > "$evidence"
  jq -n --arg sri "$sri" '{lockfileVersion: 3, packages: ({"": {name: "root"}} + ([["crit","1.0.0"],["mal","1.0.0"],["fine","1.0.0"]] | map({key: ("node_modules/" + .[0]),
    value: {version: .[1], resolved: ("https://registry.npmjs.org/" + .[0] + "/-/" + .[0] + "-" + .[1] + ".tgz"),
            integrity: $sri}}) | from_entries))}' > "$lock"
  out=$("$SAFE_CORE_BIN" project-decide --no-baseline --evidence "$evidence" "$lock") || rc=$?
  if [[ "$rc" == "104" ]] \
    && jq -e '.outcome == {status:"stopped",class:"malice",exit:104}
        and (.malice | length == 1 and .[0].name == "mal" and .[0].versions == ["1.0.0"] and .[0].id == "MAL-2026-1")
        and (.advisories.introduced | length == 1 and .[0].name == "crit" and .[0].class == "blocking")' <<<"$out" >/dev/null; then
    pass "evidence: the document the mode writes is the one safe-core project-decide reads, unmodified, and the exit is the outcome's"
  else
    printf 'rc=%s out=%s\n' "$rc" "$out" >&2
    fail "evidence: the document the mode writes is the one safe-core project-decide reads, unmodified, and the exit is the outcome's"
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

# --- cases: the advisory-record cache, the chunks of 1,000 and the blocklist read once (ticket 1671) --------------------------------------
# The mock below answers by what it is asked (the identities of the querybatch body, the id of a record) from one database file, enforces the
# service's limit (1,000 queries per call, a refusal above), and logs every call: the cases count calls and compare documents, never a duration.
#   OSV_DB   {"adv": {"name@version": [{"id","modified"}]}, "records": {"<id>": <record>}, "fail": ["<id>"], "raw": {"<id>": "<text>"}}
#   OSV_LOG  one line per call: "batch <queries> <max-time>", "detail <id>", "query"
MOCK2BIN="$TEST_ROOT/mockbin2"
mkdir -p "$MOCK2BIN"
cat > "$MOCK2BIN/curl" <<'MOCK'
#!/usr/bin/env bash
url="" body="" maxtime=""
args=("$@")
i=0
while (( i < ${#args[@]} )); do
  a="${args[$i]}"
  case "$a" in
    --max-time) maxtime="${args[$((i + 1))]}"; i=$((i + 2)); continue ;;
    -H) i=$((i + 2)); continue ;;
    -d) body="${args[$((i + 1))]}"; i=$((i + 2)); continue ;;
    http*://*) url="$a" ;;
  esac
  i=$((i + 1))
done
case "$url" in
  *api.osv.dev/v1/querybatch*)
    n=$(jq '.queries | length' <<<"$body")
    printf 'batch %s %s\n' "$n" "$maxtime" >> "${OSV_LOG:?}"
    (( n <= 1000 )) || exit 22
    jq -c --slurpfile db "${OSV_DB:?}" '{results: [.queries[] | ($db[0].adv[.package.name + "@" + .version] // null) | if . then {vulns: .} else {} end]}' <<<"$body"
    ;;
  *api.osv.dev/v1/vulns/*)
    id="${url##*/}"
    printf 'detail %s\n' "$id" >> "${OSV_LOG:?}"
    jq -e --arg id "$id" '(.fail // []) | index($id) | not' "${OSV_DB:?}" >/dev/null || exit 22
    if jq -e --arg id "$id" '(.raw // {}) | has($id)' "${OSV_DB:?}" >/dev/null; then
      jq -r --arg id "$id" '.raw[$id]' "${OSV_DB:?}"
    else
      jq -c --arg id "$id" '.records[$id]' "${OSV_DB:?}"
    fi
    ;;
  *) printf 'other %s\n' "$url" >> "${OSV_LOG:?}"; exit 22 ;;
esac
exit 0
MOCK
chmod +x "$MOCK2BIN/curl"

# A database: GHSA-c-1 (critical) on a@1, GHSA-m-2 (moderate) and GHSA-c-1 on b@1, c@1 clean, d@1 withdrawn advisory.
cache_db() {
  jq -n '{adv: {"a@1.0.0": [{id: "GHSA-c-1", modified: "2026-01-01T00:00:00.000001Z"}],
             "b@1.0.0": [{id: "GHSA-c-1", modified: "2026-01-01T00:00:00.000001Z"}, {id: "GHSA-m-2", modified: "2026-02-02T00:00:00.000002Z"}],
             "d@1.0.0": [{id: "GHSA-w-3", modified: "2026-03-03T00:00:00.000003Z"}]},
          records: {"GHSA-c-1": {id: "GHSA-c-1", database_specific: {severity: "CRITICAL"}, affected: [{package: {ecosystem: "npm", name: "a"}}, {package: {ecosystem: "npm", name: "b"}}]},
                    "GHSA-m-2": {id: "GHSA-m-2", database_specific: {severity: "MODERATE"}, affected: [{package: {ecosystem: "npm", name: "b"}}]},
                    "GHSA-w-3": {id: "GHSA-w-3", withdrawn: "2026-03-04T00:00:00Z", database_specific: {severity: "HIGH"}}},
          fail: [], raw: {}}'
}
CACHE_REQUEST='{"packages":[{"name":"a","version":"1.0.0"},{"name":"b","version":"1.0.0"},{"name":"c","version":"1.0.0"},{"name":"d","version":"1.0.0"}]}'

# <state-args...> -- runs the evidence reader against the mock database of the case (OSV_DB), the call log in OSV_LOG
run_ev2() {
  env -i PATH="$MOCK2BIN:/usr/bin:/bin" HOME="$CASE_HOME" SAFE_RUN_CONFIG_DIR="$RUN_DIR" SAFE_CORE_BIN="${SAFE_CORE_BIN:-}" \
    OSV_DB="$OSV_DB" OSV_LOG="$OSV_LOG" bash "$SAFE_AUDIT" scanner-batch --evidence "$@"
}
setup_cache_case() { # <name>: sets CASE_HOME RUN_DIR OSV_DB OSV_LOG STATE
  setup_case "$1"
  OSV_DB="$CASE_HOME/osv-db.json"; OSV_LOG="$CASE_HOME/osv.log"; STATE="$CASE_HOME/state"
  cache_db > "$OSV_DB"; : > "$OSV_LOG"
  mkdir -p "$STATE"; chmod 700 "$STATE"
}
log_count() { grep -c "^$1" "$OSV_LOG" 2>/dev/null || true; }
store_count() { find "$STATE/advisory-records" -maxdepth 1 -type f 2>/dev/null | wc -l; }
cache_doc() { printf '%s' "${2:-$CACHE_REQUEST}" | run_ev2 --state-dir "$STATE" 2>/dev/null; }

case_cache_second_run_fetches_no_record() {
  setup_cache_case cache-second
  local out1 out2 d1 b1 d2 b2
  out1=$(cache_doc) || { fail "cache: the first run failed"; return; }
  d1=$(log_count detail); b1=$(log_count batch)
  # three distinct advisories, one of them fetched once for its two packages; the withdrawn record is read too
  if [[ "$d1" == 3 && "$b1" == 1 && "$(store_count)" == 4 ]] \
    && jq -e '[.identities[] | select(.name == "a") | .advisories[0] | .id == "GHSA-c-1" and .severity == "critical"] | all' <<<"$out1" >/dev/null; then
    pass "cache: a first run fetches each advisory record once and stores what it classified (4 readings: 3 classified, 1 withdrawn)"
  else
    printf 'details=%s batches=%s stored=%s\n' "$d1" "$b1" "$(store_count)" >&2
    fail "cache: a first run fetches each advisory record once and stores what it classified"
  fi
  : > "$OSV_LOG"
  out2=$(cache_doc) || { fail "cache: the second run failed"; return; }
  d2=$(log_count detail); b2=$(log_count batch)
  if [[ "$d2" == 0 && "$b2" == 1 ]] && [[ "$(jq -S . <<<"$out1")" == "$(jq -S . <<<"$out2")" ]]; then
    pass "cache: a second run fetches no record, asks the service which advisories each identity carries, and the document is identical"
  else
    printf 'details=%s batches=%s\n' "$d2" "$b2" >&2
    fail "cache: a second run fetches no record, asks the service which advisories each identity carries, and the document is identical"
  fi
}

case_cache_a_changed_stamp_is_fetched_again() {
  setup_cache_case cache-stamp
  local out
  cache_doc >/dev/null
  # the service now says GHSA-c-1 changed (new stamp) and the record now reads LOW; GHSA-m-2 is untouched
  jq '.adv["a@1.0.0"][0].modified = "2026-06-06T00:00:00.000009Z" | .adv["b@1.0.0"][0].modified = "2026-06-06T00:00:00.000009Z"
      | .records["GHSA-c-1"].database_specific.severity = "LOW"' "$OSV_DB" > "$OSV_DB.new" && mv "$OSV_DB.new" "$OSV_DB"
  : > "$OSV_LOG"
  out=$(cache_doc)
  if [[ "$(log_count detail)" == 1 ]] && grep -qx 'detail GHSA-c-1' "$OSV_LOG" \
    && jq -e '[.identities[] | select(.name == "a" or .name == "b") | .advisories[] | select(.id == "GHSA-c-1") | .severity] == ["low", "low"]' <<<"$out" >/dev/null; then
    pass "cache: an advisory whose stamp changed is fetched again and read as it now is; the others stay cached"
  else
    cat "$OSV_LOG" >&2
    fail "cache: an advisory whose stamp changed is fetched again and read as it now is; the others stay cached"
  fi
  # the earlier reading under the old stamp is still stored, and never answers for the new one
  : > "$OSV_LOG"
  cache_doc >/dev/null
  if [[ "$(log_count detail)" == 0 ]]; then pass "cache: the new stamp's reading is stored"; else fail "cache: the new stamp's reading is stored"; fi
}

case_cache_ignores_a_corrupt_foreign_or_other_mode_entry() {
  setup_cache_case cache-corrupt
  local out ref mutation ok=1 first
  ref=$(cache_doc)
  for mutation in corrupt mode link foreign unknown-member directory-owned; do
    rm -rf "$STATE/advisory-records"; : > "$OSV_LOG"
    cache_doc >/dev/null
    first=$(find "$STATE/advisory-records" -maxdepth 1 -type f | sort | head -1)
    case "$mutation" in
      corrupt) for f in "$STATE/advisory-records"/*; do printf '{not json' > "$f"; done ;;
      mode) chmod 644 "$STATE/advisory-records"/* ;;
      link) for f in "$STATE/advisory-records"/*; do cp "$f" "$f.real"; rm "$f"; ln -s "$(basename "$f").real" "$f"; done ;;
      foreign) # every entry holds the content of one other entry
        for f in "$STATE/advisory-records"/*; do [[ "$f" == "$first" ]] || cp "$first" "$f"; done ;;
      unknown-member) for f in "$STATE/advisory-records"/*; do jq -c '. + {extra: 1}' "$f" > "$f.n" && mv "$f.n" "$f" && chmod 600 "$f"; done ;;
      directory-owned) chmod 770 "$STATE/advisory-records" ;;
    esac
    : > "$OSV_LOG"
    out=$(cache_doc)
    # a foreign entry for ONE key still answers for that one: the case is that nothing it holds answers for another key
    if [[ "$mutation" == foreign ]]; then
      (( $(log_count detail) >= 2 )) || { printf 'foreign: %s details\n' "$(log_count detail)" >&2; ok=0; }
    else
      [[ "$(log_count detail)" == 3 ]] || { printf '%s: %s details, want 3\n' "$mutation" "$(log_count detail)" >&2; ok=0; }
    fi
    [[ "$(jq -S . <<<"$out")" == "$(jq -S . <<<"$ref")" ]] || { printf '%s: the document differs\n' "$mutation" >&2; ok=0; }
  done
  if (( ok )); then pass "cache: a corrupt, linked, wrong-mode, foreign or extended entry, or an open directory, is ignored and the record fetched again (same document)"; else fail "cache: a corrupt, linked, wrong-mode, foreign or extended entry, or an open directory, is ignored"; fi
}

case_cache_stores_nothing_for_a_failed_malformed_or_unclassifiable_record() {
  setup_cache_case cache-failed
  local out ok=1
  # GHSA-c-1: transport failure; GHSA-m-2: not a record; GHSA-w-3 (d): a record that cannot be classified (no severity) is "unknown"
  jq '.fail = ["GHSA-c-1"] | .raw["GHSA-m-2"] = "{not json" | .records["GHSA-w-3"] = {id: "GHSA-w-3", affected: [{package: {ecosystem: "npm", name: "d"}}]}' "$OSV_DB" > "$OSV_DB.new" && mv "$OSV_DB.new" "$OSV_DB"
  out=$(cache_doc)
  [[ "$(store_count)" == 0 ]] || { printf 'stored %s entries\n' "$(store_count)" >&2; ok=0; }
  jq -e '(.identities | map(select(.coverage == "missing") | .name) | sort) == ["a", "b"]' <<<"$out" >/dev/null || { printf 'coverage: %s\n' "$(jq -c '[.identities[] | {name, coverage}]' <<<"$out")" >&2; ok=0; }
  jq -e '.identities[] | select(.name == "d") | .advisories[0].severity == "unknown"' <<<"$out" >/dev/null || ok=0
  # nothing was stored, so the next run fetches all three again; once the service answers, only then are they stored
  : > "$OSV_LOG"
  out=$(cache_doc)
  [[ "$(log_count detail)" == 3 ]] || { printf 'second run fetched %s\n' "$(log_count detail)" >&2; ok=0; }
  jq '.fail = [] | del(.raw["GHSA-m-2"])' "$OSV_DB" > "$OSV_DB.new" && mv "$OSV_DB.new" "$OSV_DB"
  : > "$OSV_LOG"
  out=$(cache_doc)
  jq -e '[.identities[] | .coverage] | all(. == "complete")' <<<"$out" >/dev/null || ok=0
  [[ "$(store_count)" == 3 ]] || { printf 'stored %s after recovery, want 3 (GHSA-c-1 for two packages, GHSA-m-2; the unclassifiable one is never stored)\n' "$(store_count)" >&2; ok=0; }
  if (( ok )); then pass "cache: a failed, malformed or unclassifiable record stores nothing, and a gap stays a gap"; else fail "cache: a failed, malformed or unclassifiable record stores nothing, and a gap stays a gap"; fi
}

case_cache_never_delays_a_malware_record_or_a_new_advisory() {
  setup_cache_case cache-malware
  local out ok=1
  cache_doc >/dev/null
  # between two commands the service adds a known-malware record and a new advisory to versions already read
  jq '.adv["a@1.0.0"] += [{id: "MAL-2026-1", modified: "2026-07-07T00:00:00.000001Z"}]
      | .adv["c@1.0.0"] = [{id: "GHSA-n-9", modified: "2026-07-07T00:00:00.000002Z"}]
      | .records["GHSA-n-9"] = {id: "GHSA-n-9", database_specific: {severity: "HIGH"}, affected: [{package: {ecosystem: "npm", name: "c"}}]}' "$OSV_DB" > "$OSV_DB.new" && mv "$OSV_DB.new" "$OSV_DB"
  : > "$OSV_LOG"
  out=$(cache_doc)
  jq -e '.identities[] | select(.name == "a") | [.advisories[] | select(.malware == true) | .id] == ["MAL-2026-1"]' <<<"$out" >/dev/null || ok=0
  jq -e '.identities[] | select(.name == "c") | .advisories | map({id, severity}) == [{id: "GHSA-n-9", severity: "high"}]' <<<"$out" >/dev/null || ok=0
  [[ "$(log_count batch)" == 1 && "$(log_count detail)" == 1 ]] || { printf 'calls: %s\n' "$(tr '\n' ';' < "$OSV_LOG")" >&2; ok=0; }
  # and a malware record is never read from, nor written to, the store
  grep -q 'MAL-' "$STATE"/advisory-records/* 2>/dev/null && ok=0
  if (( ok )); then pass "cache: a malware record or a new advisory on a version already read is seen by the next command"; else fail "cache: a malware record or a new advisory on a version already read is seen by the next command"; fi
}

case_cache_a_reading_is_trusted_for_a_day_at_most() {
  setup_cache_case cache-day
  local out ok=1 now f
  cache_doc >/dev/null
  now=$(date +%s)
  age_entries() { # <seconds of age>: every entry's fetch time is moved
    for f in "$STATE/advisory-records"/*; do jq -c --argjson t "$(( now - $1 ))" '.fetched = $t' "$f" > "$f.n" && mv "$f.n" "$f" && chmod 600 "$f"; done
  }
  age_entries 86300; : > "$OSV_LOG"; cache_doc >/dev/null
  [[ "$(log_count detail)" == 0 ]] || { printf 'inside the day: %s details\n' "$(log_count detail)" >&2; ok=0; }
  age_entries 86401; : > "$OSV_LOG"; cache_doc >/dev/null
  [[ "$(log_count detail)" == 3 ]] || { printf 'older than a day: %s details\n' "$(log_count detail)" >&2; ok=0; }
  [[ "$(store_count)" == 4 ]] || { printf 'stored %s\n' "$(store_count)" >&2; ok=0; }
  : > "$OSV_LOG"; cache_doc >/dev/null
  [[ "$(log_count detail)" == 0 ]] || { printf 'after the refetch: %s details\n' "$(log_count detail)" >&2; ok=0; }
  age_entries -3600; : > "$OSV_LOG"; cache_doc >/dev/null
  [[ "$(log_count detail)" == 3 ]] || { printf 'dated in the future: %s details\n' "$(log_count detail)" >&2; ok=0; }
  if (( ok )); then pass "cache: a reading is trusted for a day at most, and never when it is dated in the future"; else fail "cache: a reading is trusted for a day at most, and never when it is dated in the future"; fi
}

case_cache_the_reader_checks_what_the_core_answers() {
  setup_cache_case cache-liar
  local liar="$CASE_HOME/liar-core" ref out ok=1 mode
  ref=$(cache_doc); rm -rf "$STATE/advisory-records"
  # A core that answers the question wrongly, one way at a time, with every other hit honest and fresh: a hit nobody asked for (another stamp, another
  # package), a band that is not one of the four, a reading dated in the future or older than a day, a withdrawn record that carries a band, a hit with a
  # member too many, an envelope of another schema. None may be taken: all three records are fetched and the document is the honest one.
  cat > "$liar" <<'LIAR'
#!/usr/bin/env bash
if [[ "${1:-}" == "project-advisory-get" ]]; then
  cat >/dev/null
  jq -cn --argjson now "$(date +%s)" --arg mode "${LIAR_MODE:?}" '
    def hit($id; $m; $p; $sev): {id: $id, modified: $m, package: $p, severity: $sev, withdrawn: false, fetched: $now};
    def honest: [hit("GHSA-c-1"; "2026-01-01T00:00:00.000001Z"; "a"; "critical"), hit("GHSA-c-1"; "2026-01-01T00:00:00.000001Z"; "b"; "critical"),
                 hit("GHSA-m-2"; "2026-02-02T00:00:00.000002Z"; "b"; "moderate")];
    {schema_version: 1, hits: (honest + (
      if $mode == "unasked-stamp" then [hit("GHSA-c-1"; "WRONG"; "a"; "low")]
      elif $mode == "unasked-package" then [hit("GHSA-c-1"; "2026-01-01T00:00:00.000001Z"; "zzz"; "low")]
      elif $mode == "unknown-band" then [hit("GHSA-m-2"; "2026-02-02T00:00:00.000002Z"; "b"; "bogus")]
      elif $mode == "future" then [(hit("GHSA-m-2"; "2026-02-02T00:00:00.000002Z"; "b"; "low") | .fetched = $now + 3600)]
      elif $mode == "stale" then [(hit("GHSA-m-2"; "2026-02-02T00:00:00.000002Z"; "b"; "low") | .fetched = $now - 90000)]
      elif $mode == "withdrawn-with-band" then [(hit("GHSA-w-3"; "2026-03-03T00:00:00.000003Z"; "d"; "high") | .withdrawn = true)]
      elif $mode == "extra-member" then [(hit("GHSA-m-2"; "2026-02-02T00:00:00.000002Z"; "b"; "low") | .extra = 1)]
      else [] end)) }
    | if $mode == "schema" then .schema_version = 2 else . end'
  exit 0
fi
exec "${REAL_CORE:?}" "$@"
LIAR
  chmod +x "$liar"
  # the honest hits alone are taken (control): nothing is fetched for them
  for mode in honest unasked-stamp unasked-package unknown-band future stale withdrawn-with-band extra-member schema; do
    : > "$OSV_LOG"
    out=$(printf '%s' "$CACHE_REQUEST" | env -i PATH="$MOCK2BIN:/usr/bin:/bin" HOME="$CASE_HOME" SAFE_RUN_CONFIG_DIR="$RUN_DIR" SAFE_CORE_BIN="$liar" REAL_CORE="$SAFE_CORE_BIN" LIAR_MODE="$mode" \
      OSV_DB="$OSV_DB" OSV_LOG="$OSV_LOG" bash "$SAFE_AUDIT" scanner-batch --evidence --state-dir "$STATE" 2>/dev/null) || ok=0
    if [[ "$mode" == honest ]]; then
      # GHSA-c-1 (both packages) and GHSA-m-2 come from the answer; only the withdrawn GHSA-w-3 is fetched
      [[ "$(log_count detail)" == 1 ]] || { printf 'honest: details fetched %s, want 1\n' "$(log_count detail)" >&2; ok=0; }
    else
      [[ "$(log_count detail)" == 3 ]] || { printf '%s: details fetched %s, want 3\n' "$mode" "$(log_count detail)" >&2; ok=0; }
    fi
    [[ "$(jq -S . <<<"$out")" == "$(jq -S . <<<"$ref")" ]] || { printf '%s: the document differs from the honest one\n' "$mode" >&2; ok=0; }
  done
  if (( ok )); then pass "cache: the reader takes nothing the core answers that it did not ask for or cannot check (unasked, unknown band, future, stale, withdrawn with a band, extra member, other schema)"; else fail "cache: the reader takes nothing the core answers that it did not ask for or cannot check"; fi
}

case_cache_without_the_argument_there_is_no_cache() {
  setup_cache_case cache-noarg
  local out ok=1 other
  # a store planted where an environment variable could point the reader (SAFE_DATA_DIR, XDG_STATE_HOME, the state directory of the case)
  cache_doc >/dev/null
  : > "$OSV_LOG"
  out=$(printf '%s' "$CACHE_REQUEST" | env -i PATH="$MOCK2BIN:/usr/bin:/bin" HOME="$CASE_HOME" SAFE_RUN_CONFIG_DIR="$RUN_DIR" SAFE_CORE_BIN="${SAFE_CORE_BIN:-}" \
    SAFE_DATA_DIR="$STATE" XDG_STATE_HOME="$STATE" XDG_DATA_HOME="$STATE" SAFE_STATE_DIR="$STATE" OSV_DB="$OSV_DB" OSV_LOG="$OSV_LOG" bash "$SAFE_AUDIT" scanner-batch --evidence 2>/dev/null)
  [[ "$(log_count detail)" == 3 ]] || { printf 'no argument: %s details\n' "$(log_count detail)" >&2; ok=0; }
  for other in "--state-dir" "--state-dir relative/dir" "--state-dirs $STATE"; do
    : > "$OSV_LOG"
    # shellcheck disable=SC2086
    out=$(printf '%s' "$CACHE_REQUEST" | run_ev2 $other 2>/dev/null) || true
    [[ "$(log_count detail)" == 3 ]] || { printf '%s: %s details\n' "$other" "$(log_count detail)" >&2; ok=0; }
  done
  # an empty database state directory is not created by a run without the argument
  rm -rf "$STATE/advisory-records"
  printf '%s' "$CACHE_REQUEST" | run_ev2 >/dev/null 2>&1 || true
  [[ ! -e "$STATE/advisory-records" ]] || ok=0
  if (( ok )); then pass "cache: without the state-directory argument (or with one that is not an absolute path) there is no cache, whatever the environment holds"; else fail "cache: without the state-directory argument there is no cache"; fi
}

case_cache_is_bounded_at_ten_thousand_entries() {
  setup_cache_case cache-cap
  local f readings now
  now=$(date +%s)
  jq -cn --argjson now "$now" '{classifier: "c", readings: [range(10000) | {id: ("GHSA-" + tostring), modified: "s", package: "p", severity: "low", withdrawn: false, fetched: $now}]}' \
    | "$SAFE_CORE_BIN" project-advisory-put --state-dir "$STATE"
  [[ "$(store_count)" == 10000 ]] || { fail "cache: 10,000 readings were not all stored ($(store_count))"; return; }
  jq -cn --argjson now "$now" '{classifier: "c", readings: [{id: "GHSA-extra", modified: "s", package: "p", severity: "low", withdrawn: false, fetched: $now}]}' \
    | "$SAFE_CORE_BIN" project-advisory-put --state-dir "$STATE"
  if [[ "$(store_count)" == 10000 ]]; then pass "cache: the 10,001st entry does not grow the store beyond its bound"; else fail "cache: the 10,001st entry does not grow the store beyond its bound ($(store_count))"; fi
}

case_chunks_of_a_thousand_read_what_chunks_of_a_hundred_read() {
  setup_cache_case chunks-1000
  # 1,001 identities; an advisory on every 37th, a malware record on every 211th. The batch (chunks of 100, the verdict mode) and the evidence
  # (chunks of 1,000) must report the same advisories for the same identities.
  jq -n '{adv: ([range(0; 1001; 37)] | map({key: ("p\(.)@1.0.0"), value: [{id: ("GHSA-x-\(.)"), modified: "2026-01-01T00:00:00.000001Z"}]}) | from_entries)
              + ([range(0; 1001; 211)] | map({key: ("p\(.)@1.0.0"), value: [{id: ("MAL-2026-\(.)"), modified: "2026-01-01T00:00:00.000001Z"}]}) | from_entries),
         records: ([range(0; 1001; 37)] | map({key: ("GHSA-x-\(.)"), value: {id: ("GHSA-x-\(.)"), database_specific: {severity: "HIGH"}, affected: [{package: {ecosystem: "npm", name: "p\(.)"}}]}}) | from_entries), fail: [], raw: {}}' > "$OSV_DB"
  local input ev bt ok=1
  input=$(jq -cn '{packages: [range(1001) | {name: ("p\(.)"), version: "1.0.0"}]}')
  ev=$(printf '%s' "$input" | run_ev2 2>/dev/null) || ok=0
  [[ "$(grep -c '^batch' "$OSV_LOG")" == 2 ]] && grep -qx 'batch 1000 30' "$OSV_LOG" && grep -qx 'batch 1 30' "$OSV_LOG" || { printf 'evidence calls: %s\n' "$(grep '^batch' "$OSV_LOG" | tr '\n' ';')" >&2; ok=0; }
  : > "$OSV_LOG"
  bt=$(printf '%s' "$input" | env -i PATH="$MOCK2BIN:/usr/bin:/bin" HOME="$CASE_HOME" SAFE_RUN_CONFIG_DIR="$RUN_DIR" OSV_DB="$OSV_DB" OSV_LOG="$OSV_LOG" bash "$SAFE_AUDIT" scanner-batch 2>/dev/null) || ok=0
  [[ "$(grep -c '^batch' "$OSV_LOG")" == 11 ]] || { printf 'batch calls: %s\n' "$(grep -c '^batch' "$OSV_LOG")" >&2; ok=0; }
  # the same (package, advisory) pairs, severities as the verdict mode levels them (critical → fatal) are not compared: the ids are
  if [[ "$(jq -r '[.identities[] | .name as $n | .advisories[] | "\($n) \(.id)"] | sort | .[]' <<<"$ev")" == "$(jq -r '[.[] | "\(.package) \(.url | sub("^.*/"; ""))"] | sort | .[]' <<<"$bt")" ]] \
    && [[ "$(jq '[.identities[] | .advisories[]] | length' <<<"$ev")" -gt 25 ]]; then
    :
  else
    printf 'evidence: %s pairs, batch: %s\n' "$(jq '[.identities[] | .advisories[]] | length' <<<"$ev")" "$(jq length <<<"$bt")" >&2; ok=0
  fi
  if (( ok )); then pass "chunks: 1,001 identities are asked in two calls of 1,000 and 1 (30 s cap), and report the same advisories as chunks of 100"; else fail "chunks: 1,001 identities are asked in two calls of 1,000 and 1, and report the same advisories as chunks of 100"; fi
}

# The blocklist, once or name by name. Both stores the per-name reading opens (the canonical one and a redirected, blessed one), scoped names,
# scope wildcards, case variants, entries of every shape the validator accepts, names that are in no store.
BLOCK_NAMES='["evil","Evil","EVIL","evil2","@scope/a","@scope/b","@Scope/a","@other/x","@other","@","@/x","@@/y","scope/a","left-pad","@wild/anything","@wild/","@wild//x","a/b","x@y"]'
blocklist_corpus() { # <canonical blocked.json> <redirected blocked.json>
  cat > "$1" <<'JSON'
{"packages": {"evil": {"reason": "canonical evil"}, "@scope/a": {"reason": "canonical scoped"}, "@wild/*": {"reason": "canonical wildcard"}, "Evil": {}, "@/*": {"reason": "odd wildcard"}}}
JSON
  cat > "$2" <<'JSON'
{"packages": {"evil": {"reason": "redirected evil"}, "EVIL": {"reason": 5}, "@scope/*": {"reason": "redirected scope"}, "@other/x": {"reason": {"a": "b"}}, "@@/y": {"reason": null}, "evil2": {"reason": ["x"]}, "x@y": {"note": "no reason"}}}
JSON
}
blocklist_both() { # <names json> → "verdict|evidence" normalised block lists on two lines
  local names="$1" half
  half=$(jq -c '.[:10]' <<<"$names")
  local rest
  rest=$(jq -c '.[10:]' <<<"$names")
  local bt ev
  bt=$(jq -cn --argjson n "$names" '{packages: [$n[] | {name: ., version: "1.0.0"}]}' \
    | env -i PATH="$MOCK2BIN:/usr/bin:/bin" HOME="$CASE_HOME" SAFE_RUN_CONFIG_DIR="$RUN_DIR" SAFE_RUN_TRUST_OVERRIDE=1 OSV_DB="$OSV_DB" OSV_LOG="$OSV_LOG" bash "$SAFE_AUDIT" scanner-batch 2>/dev/null) || { printf 'BATCH-EXIT-%s' "$?"; return 0; }
  ev=$(jq -cn --argjson a "$half" --argjson b "$rest" '{packages: [$a[] | {name: ., version: "1.0.0"}], blocklist_names: $b}' \
    | env -i PATH="$MOCK2BIN:/usr/bin:/bin" HOME="$CASE_HOME" SAFE_RUN_CONFIG_DIR="$RUN_DIR" SAFE_RUN_TRUST_OVERRIDE=1 SAFE_CORE_BIN="${SAFE_CORE_BIN:-}" OSV_DB="$OSV_DB" OSV_LOG="$OSV_LOG" bash "$SAFE_AUDIT" scanner-batch --evidence 2>/dev/null) || { printf 'EVIDENCE-EXIT-%s' "$?"; return 0; }
  printf '%s\n' "$(jq -c '[.[] | select((.description // "") | startswith("blocklisted on this host: ")) | {name: .package, reason: (.description | ltrimstr("blocklisted on this host: "))}] | sort_by(.name)' <<<"$bt")"
  printf '%s\n' "$(jq -c '.blocklist | sort_by(.name)' <<<"$ev")"
}

case_blocklist_read_once_agrees_with_the_per_name_reading() {
  setup_cache_case blocklist-diff
  local got ok=1 redirect="$CASE_HOME/redirected" expected_order ev_order out
  mkdir -p "$redirect"
  # 1. both stores, the redirected one blessed (the suite exports the token): every name agrees, reasons included
  blocklist_corpus "$RUN_DIR/blocked.json" "$redirect/blocked.json"
  RUN_DIR="$redirect"
  got=$(blocklist_both "$BLOCK_NAMES")
  if [[ "$(sed -n 1p <<<"$got")" == "$(sed -n 2p <<<"$got")" ]] && [[ "$(sed -n 2p <<<"$got" | jq 'length')" -ge 9 ]]; then
    pass "blocklist: read once, it agrees with the per-name reading on every name of the corpus (both stores, scopes, wildcards, case variants)"
  else
    printf 'verdict:  %s\nevidence: %s\n' "$(sed -n 1p <<<"$got")" "$(sed -n 2p <<<"$got")" >&2
    fail "blocklist: read once, it agrees with the per-name reading on every name of the corpus"
  fi
  # the document keeps the order the per-name reading produced: the names sorted as `sort -u` sorts them
  out=$(jq -cn --argjson n "$BLOCK_NAMES" '{packages: [$n[] | {name: ., version: "1.0.0"}]}' \
    | env -i PATH="$MOCK2BIN:/usr/bin:/bin" HOME="$CASE_HOME" SAFE_RUN_CONFIG_DIR="$RUN_DIR" SAFE_RUN_TRUST_OVERRIDE=1 SAFE_CORE_BIN="${SAFE_CORE_BIN:-}" OSV_DB="$OSV_DB" OSV_LOG="$OSV_LOG" bash "$SAFE_AUDIT" scanner-batch --evidence 2>/dev/null)
  ev_order=$(jq -r '.blocklist[].name' <<<"$out")
  expected_order=$(printf '%s\n' "$ev_order" | LC_ALL=C sort -u)
  [[ "$ev_order" == "$expected_order" ]] || { printf 'order: %s\n' "$ev_order" >&2; ok=0; }
  # 2. an unreadable store, whichever of the two: both readings end as they did (the batch 4, the evidence 4), with nothing on stdout
  local which
  for which in redirected canonical; do
    blocklist_corpus "$CASE_HOME/.config/safe/run/blocked.json" "$redirect/blocked.json"
    if [[ "$which" == redirected ]]; then printf 'not-json{' > "$redirect/blocked.json"; else printf 'not-json{' > "$CASE_HOME/.config/safe/run/blocked.json"; fi
    got=$(blocklist_both "$BLOCK_NAMES")
    [[ "$got" == BATCH-EXIT-4 ]] || { printf 'unreadable %s store: %s\n' "$which" "$got" >&2; ok=0; }
  done
  # the evidence mode alone (the batch stops first above): also 4, no document
  local rc=0
  out=$(jq -cn --argjson n "$BLOCK_NAMES" '{packages: [$n[] | {name: ., version: "1.0.0"}]}' \
    | env -i PATH="$MOCK2BIN:/usr/bin:/bin" HOME="$CASE_HOME" SAFE_RUN_CONFIG_DIR="$RUN_DIR" SAFE_RUN_TRUST_OVERRIDE=1 SAFE_CORE_BIN="${SAFE_CORE_BIN:-}" OSV_DB="$OSV_DB" OSV_LOG="$OSV_LOG" bash "$SAFE_AUDIT" scanner-batch --evidence 2>/dev/null) || rc=$?
  [[ "$rc" == 4 && -z "$out" ]] || { printf 'evidence with an unreadable store: rc=%s out=%s\n' "$rc" "$out" >&2; ok=0; }
  # an entry that is not an object is an unreadable store too, for both
  blocklist_corpus "$CASE_HOME/.config/safe/run/blocked.json" "$redirect/blocked.json"
  printf '{"packages": {"evil": null}}' > "$redirect/blocked.json"
  got=$(blocklist_both "$BLOCK_NAMES")
  [[ "$got" == BATCH-EXIT-4 ]] || { printf 'null entry: %s\n' "$got" >&2; ok=0; }
  if (( ok )); then pass "blocklist: an unreadable store ends the evidence mode as it ends the batch (exit 4, no document), and the order of the hits is the per-name reading's"; else fail "blocklist: an unreadable store ends the evidence mode as it ends the batch, and the order of the hits is the per-name reading's"; fi
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
case_plain_batch_ignores_an_unrelated_blocklist_names_member
if (( SC_OK )); then
  case_evidence_clean_tree_is_complete_and_empty
  case_evidence_malformed_stdin_refuses
  case_evidence_keeps_severity_ladder_and_malware_identity
  case_evidence_a_withdrawn_advisory_is_removed
  case_evidence_same_name_versions_stay_apart
  case_evidence_later_chunk_failure_keeps_earlier_hits
  case_evidence_malformed_result_loses_only_itself
  case_evidence_repeated_member_is_a_gap
  case_evidence_pagination_failure_keeps_first_page
  case_evidence_detail_failure_keeps_other_hits
  case_evidence_blocklist_is_independent_of_osv
  case_evidence_blocklist_names_and_empty_requests
  case_evidence_unreadable_blocklist_fails_closed
  case_evidence_document_is_read_by_the_decision
  case_evidence_duplicate_in_one_result_keeps_its_neighbour
  case_evidence_checker_does_not_fail_open
  case_evidence_page_and_detail_answers_are_checked_too
  case_cache_second_run_fetches_no_record
  case_cache_a_changed_stamp_is_fetched_again
  case_cache_ignores_a_corrupt_foreign_or_other_mode_entry
  case_cache_stores_nothing_for_a_failed_malformed_or_unclassifiable_record
  case_cache_never_delays_a_malware_record_or_a_new_advisory
  case_cache_a_reading_is_trusted_for_a_day_at_most
  case_cache_the_reader_checks_what_the_core_answers
  case_cache_without_the_argument_there_is_no_cache
  case_cache_is_bounded_at_ten_thousand_entries
  case_chunks_of_a_thousand_read_what_chunks_of_a_hundred_read
  case_blocklist_read_once_agrees_with_the_per_name_reading
else
  pass "evidence cases (SKIPPED: safe-core not buildable here)"
fi

printf '%d passed, %d failed\n' "$PASS_COUNT" "$FAIL_COUNT"
(( FAIL_COUNT == 0 ))
