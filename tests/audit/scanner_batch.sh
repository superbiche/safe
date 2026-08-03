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
    if [[ -n "${MOCK_BATCH_DIR:-}" ]]; then
      count_file="${MOCK_BATCH_DIR}/.count"
      count=$(( $(cat "$count_file" 2>/dev/null || echo 0) + 1 ))
      printf '%s' "$count" > "$count_file"
      cat "${MOCK_BATCH_DIR}/batch${count}.json"
    else
      cat "${MOCK_BATCH_FIXTURE:?}"
    fi
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
    MOCK_BATCH_DIR="${MOCK_BATCH_DIR:-}" \
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
  for shape in '{"results":[{"vulns":[{"id":".."}]}]}' '{"results":[{"vulns":[{"id":"MAL-../bad"}]}]}'; do
    MOCK_BATCH_FIXTURE="$FIXDIR/batch-hostile.json"
    printf '%s\n' "$shape" > "$MOCK_BATCH_FIXTURE"
    rc=0
    out=$(printf '{"packages":[{"name":"mmm","version":"1.0.0"}]}' | run_batch 2>"$TEST_ROOT/hostile.err") || rc=$?
    if [[ "$rc" != "4" || -n "$out" ]] || ! grep -q "malformed advisory id" "$TEST_ROOT/hostile.err"; then
      printf 'shape=%s rc=%s out=%s\n' "$shape" "$rc" "$out" >&2
      ok=0
    fi
  done
  if [[ "$ok" == "1" ]]; then
    pass "hostile advisory ids (dot sentinels, malformed MAL) fail closed"
  else
    fail "hostile advisory ids (dot sentinels, malformed MAL) fail closed"
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
  # the queried package — check_command scopes to matching_affected, and
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
case_gate_injects_scanner_env
case_adapter_maps_advisories
case_adapter_throws_on_nonzero_exit
case_adapter_throws_on_malformed_payload
case_adapter_throws_on_missing_binary
case_adapter_times_out_hung_child
case_adapter_rejects_partial_request_channel

printf '%d passed, %d failed\n' "$PASS_COUNT" "$FAIL_COUNT"
(( FAIL_COUNT == 0 ))
