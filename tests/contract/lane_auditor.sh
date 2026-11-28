#!/usr/bin/env bash
# The joint contract of the project lane and the REAL auditor (ticket 1884).
#
# Every case of the lane suites drives the lane with a stand-in for the auditor, and the auditor's own suites test an entry alone:
# nothing gave the real auditor's answer to the gate's own reader, and the lane could not finish one command with the real auditor
# (the gate required a member of the Socket cache reader's answer that the reader never writes). Here, for every entry of the auditor the
# lane calls (docs/architecture.md, "The lane and the auditor"), the REAL entry of this tree runs in an isolated home with stubs only
# BELOW it (the network's `curl`, a Socket tool, scanners) and its real answer is given to the gate's own consumer; the answer is also
# held to the one definition of its members and types (tests/lib/lane_auditor_shapes.json), which the stand-ins of the other suites are held
# to as well (tests/lib/lane_shape.sh).
#
# Entries (the gate's call, the consumer, what the case shows):
#   scanner-batch --evidence                          safe-core project-decide --evidence
#   package-audit --evidence-only (cache, no roots)   safe_gate_project_lane_socket_cache_doc
#   package-audit --evidence-only (named roots)       safe_gate_project_lane_socket_roots_doc
#   lane-acceptances                                  safe-core project-decide --acceptances
#   lane-revoke                                       the gate's revoke reading (`.revoked`)
#   package-audit <spec> --gate install --op install  the receipt the gate compares (safe_gate_project_lane_receipt) and the exit it reads
#   repo-audit . --deps-only --result-out             safe-core project-scan-summary
#   record-installed, safe-run host-allow             operator terminal only: refuse in an agent session; not driven (no terminal is made)

set -euo pipefail

# SAFE_TEST_ISOLATION_MARKER: every suite owns a scratch HOME and safe state.
# shellcheck source=tests/lib/test-isolation.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/test-isolation.sh"
safe_test_setup_isolation || exit 1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SAFE_AUDIT="$ROOT/bin/safe-audit"
PASS_COUNT=0
FAIL_COUNT=0
pass() { printf 'ok - %s\n' "$*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { printf 'not ok - %s\n' "$*" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }

TEST_ROOT="$(mktemp -d)"
safe_test_compose_exit_trap "rm -rf \"\$TEST_ROOT\""
# shellcheck source=tests/lib/safe-core.sh
. "$ROOT/tests/lib/safe-core.sh"
safe_core_test_prepare "$ROOT" "$TEST_ROOT/safe-core" || exit 1
# shellcheck source=tests/lib/lane_shape.sh
. "$ROOT/tests/lib/lane_shape.sh"

SOCKET_MOCKBIN="$ROOT/tests/lib/socket-mockbin"
OSVBIN="$TEST_ROOT/osvbin"
mkdir -p "$OSVBIN"
# The network below the auditor: OSV's batch and record endpoints answer from the case's database (OSV_DB), anything else (Socket's
# registry reads) is the shared mock's.
cat > "$OSVBIN/curl" <<'MOCK'
#!/usr/bin/env bash
url="" body=""
args=("$@")
for ((i = 0; i < ${#args[@]}; i++)); do
  case "${args[$i]}" in
    -d) body="${args[$((i + 1))]}"; i=$((i + 1)) ;;
    http*://*) url="${args[$i]}" ;;
  esac
done
case "$url" in
  *api.osv.dev/v1/querybatch*)
    jq -c --slurpfile db "${OSV_DB:?}" '{results: [.queries[] | ($db[0].adv[.package.name + "@" + .version] // null) | if . then {vulns: .} else {} end]}' <<<"$body" ;;
  *api.osv.dev/v1/vulns/*)
    jq -c --arg id "${url##*/}" '.records[$id]' "${OSV_DB:?}" ;;
  *) exec "${SOCKET_MOCKBIN:?}/curl" "$@" ;;
esac
MOCK
chmod +x "$OSVBIN/curl"

prepare_case() { # <name>
  CASE="$TEST_ROOT/$1"
  CASE_HOME="$CASE/home"; CASE_RUN_CONFIG="$CASE_HOME/.config/safe/run"; CASE_AUDIT_CONFIG="$CASE/audit-config"; CASE_DATA="$CASE/data"
  CASE_CACHE="$CASE/socket-cache"; CASE_LOG="$CASE/socket.log"; CASE_SCRATCH="$CASE/lane-scratch"; CASE_TMP="$CASE/tmp"
  mkdir -p "$CASE_RUN_CONFIG" "$CASE_AUDIT_CONFIG" "$CASE_DATA" "$CASE_SCRATCH" "$CASE_TMP"
  printf '{"install":{"cooldown_days":0,"socket":{"mode":"always","cache_ttl_days":7}}}\n' > "$CASE_RUN_CONFIG/config.json"
  printf '{"packages":{}}\n' > "$CASE_RUN_CONFIG/blocked.json"
  printf '{"local":{"socket":"%s/socket"}}\n' "$SOCKET_MOCKBIN" > "$CASE_AUDIT_CONFIG/tools.json"
  : > "$CASE_LOG"
  OSV_DB="$CASE/osv-db.json"
  jq -n '{adv: {"fixture@1.0.0": [{id: "GHSA-aaaa-0001", modified: "2026-01-01T00:00:00.000001Z"}], "evil@1.0.0": [{id: "MAL-2026-1", modified: "2026-01-01T00:00:00.000001Z"}]},
          records: {"GHSA-aaaa-0001": {id: "GHSA-aaaa-0001", database_specific: {severity: "HIGH"}, affected: [{package: {ecosystem: "npm", name: "fixture"}}]}}}' > "$OSV_DB"
}

# lane_env <command...>: the command with the environment the lane gives an auditor entry, in the case's isolated home
lane_env() {
  env -u SOCKET_SECURITY_API_TOKEN -u CLAUDECODE -u CODEX_THREAD_ID -u CODEX_CI -u OPENCODE \
    HOME="$CASE_HOME" PATH="$OSVBIN:$SOCKET_MOCKBIN:/usr/bin:/bin" SOCKET_MOCKBIN="$SOCKET_MOCKBIN" OSV_DB="$OSV_DB" \
    SAFE_AUDIT_CONFIG_DIR="$CASE_AUDIT_CONFIG" SAFE_AUDIT_DATA_DIR="$CASE_DATA/audit" SAFE_RUN_CONFIG_DIR="$CASE_RUN_CONFIG" SAFE_RUN_TRUST_OVERRIDE=1 \
    SAFE_AUDIT_SOCKET_CACHE_DIR="$CASE_CACHE" SAFE_CORE_BIN="$SAFE_CORE_BIN" MOCK_SOCKET_LOG="$CASE_LOG" MOCK_SOCKET_MODE="${MOCK_SOCKET_MODE:-clean}" \
    SAFE_AUDIT_SOCKET_TIMEOUT=5 TMPDIR="$CASE_TMP" "$@"
}

# a lane function of the gate, run in a subshell that sourced the gate's library, in the case's environment
gate() {
  ( . "$ROOT/lib/gate-lib.sh"; lane_env "$@" ) 2>/dev/null
}
gate_fn() { # <function> <args...>: runs a function of the gate library in the lane's environment
  local fn="$1"; shift
  ( . "$ROOT/lib/gate-lib.sh"
    export HOME="$CASE_HOME" PATH="$OSVBIN:$SOCKET_MOCKBIN:/usr/bin:/bin" SOCKET_MOCKBIN="$SOCKET_MOCKBIN" OSV_DB="$OSV_DB" \
      SAFE_AUDIT_CONFIG_DIR="$CASE_AUDIT_CONFIG" SAFE_AUDIT_DATA_DIR="$CASE_DATA/audit" SAFE_RUN_CONFIG_DIR="$CASE_RUN_CONFIG" SAFE_RUN_TRUST_OVERRIDE=1 \
      SAFE_AUDIT_SOCKET_CACHE_DIR="$CASE_CACHE" MOCK_SOCKET_LOG="$CASE_LOG" MOCK_SOCKET_MODE="${MOCK_SOCKET_MODE:-clean}" SAFE_AUDIT_SOCKET_TIMEOUT=5 TMPDIR="$CASE_TMP"
    unset SOCKET_SECURITY_API_TOKEN CLAUDECODE CODEX_THREAD_ID CODEX_CI OPENCODE
    "$fn" "$@" )
}

# the shape of one answer: every problem, or a pass
shape_case() { # <label> <entry> <file>
  local problems
  if problems="$(lane_shape_check "$2" "$3")"; then pass "$1: the real answer has the members and types of the contract ($2)"; else printf '%s\n' "$problems" >&2; fail "$1: the real answer differs from the contract ($2)"; fi
}

# a lockfile of two public identities for the decision to read
lockfile_of() { # <file> <name@version>...
  local file="$1" integrity spec; shift
  integrity="sha512-$(printf 'x' | sha512sum | cut -d' ' -f1 | xxd -r -p | base64 -w0)"
  { printf '{"name":"p","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"p","version":"1.0.0","dependencies":{'
    local first=1
    for spec in "$@"; do (( first )) || printf ','; first=0; printf '"%s":"%s"' "${spec%@*}" "${spec##*@}"; done
    printf '}}'
    for spec in "$@"; do
      printf ',"node_modules/%s":{"version":"%s","resolved":"https://registry.npmjs.org/%s/-/%s-%s.tgz","integrity":"%s"}' "${spec%@*}" "${spec##*@}" "${spec%@*}" "${spec%@*}" "${spec##*@}" "${integrity}"
    done
    printf '}}\n'; } > "$file"
}

DEBUG="${LANE_AUDITOR_DEBUG:-}"
show() { [[ -z "$DEBUG" ]] || { printf -- '--- %s\n' "$1" >&2; cat "$2" >&2; }; }

# ---- 1. scanner-batch --evidence ---------------------------------------------------------------------------------------------------
case_evidence() {
  prepare_case evidence
  local request='{"packages":[{"name":"fixture","version":"1.0.0"},{"name":"evil","version":"1.0.0"},{"name":"other","version":"2.0.0"}],"blocklist_names":["other"]}'
  local rc=0
  printf '%s' "$request" | lane_env "$SAFE_AUDIT" scanner-batch --evidence >"$CASE/evidence.json" 2>"$CASE/evidence.err" || rc=$?
  show evidence "$CASE/evidence.json"
  [[ "$rc" == 0 ]] || { cat "$CASE/evidence.err" >&2; fail "evidence: the real reader exited $rc"; return; }
  shape_case "evidence" evidence "$CASE/evidence.json"
  # the gate's own consumer: the decision reads it (exit 3 is an evidence document it cannot read)
  lockfile_of "$CASE/lock.json" fixture@1.0.0 evil@1.0.0 other@2.0.0
  rc=0
  "$SAFE_CORE_BIN" project-decide --no-baseline --evidence "$CASE/evidence.json" "$CASE/lock.json" >"$CASE/decision.json" 2>"$CASE/decision.err" || rc=$?
  if [[ "$rc" == 104 || "$rc" == 100 || "$rc" == 102 || "$rc" == 0 ]] && jq -e '.schema_version == 1' "$CASE/decision.json" >/dev/null 2>&1; then
    pass "evidence: the decision reads the real reader's document (exit $rc)"
  else
    cat "$CASE/decision.err" >&2; fail "evidence: the decision could not read the real reader's document (exit $rc)"
  fi
}

# ---- 2. package-audit --evidence-only, the cache ------------------------------------------------------------------------------------
case_socket_cache() {
  prepare_case socket-cache
  local request='{"roots":[],"cached":[{"name":"fixture","version":"1.0.0"},{"name":"other","version":"2.0.0"}]}' rc=0
  printf '%s' "$request" > "$CASE/cache-request.json"
  gate_fn safe_gate_project_lane_socket_call "$SAFE_AUDIT" "$SAFE_CORE_BIN" "$CASE/cache-request.json" "$CASE/cache.raw" 30 "$CASE_SCRATCH" || rc=$?
  show "socket cache (raw)" "$CASE/cache.raw"
  [[ "$rc" == 0 ]] || { fail "socket cache: the real reader exited $rc"; return; }
  shape_case "socket cache" socket_answer "$CASE/cache.raw"
  gate_fn safe_gate_project_lane_socket_cache_doc "$CASE/cache-request.json" "$CASE/cache.raw" "$CASE/cache-doc.json" "" "$SAFE_CORE_BIN" || true
  show "socket cache (the gate's document)" "$CASE/cache-doc.json"
  if jq -e '.schema_version == 1 and .cache_gap == "" and .roots == [] and .cached_blocks == []' "$CASE/cache-doc.json" >/dev/null 2>&1; then
    pass "socket cache: the gate takes the real reader's answer as whole (no gap)"
  else
    fail "socket cache: the gate did not take the real reader's answer as whole: $(cat "$CASE/cache-doc.json" 2>/dev/null)"
  fi
  # a blocking result in the cache: written by today's audit of the same artifact, read by the reader, kept by the gate
  MOCK_SOCKET_MODE=malware lane_env "$SAFE_AUDIT" package-audit fixture@1.0.0 --ecosystem npm --gate install --op install </dev/null >/dev/null 2>&1 || true
  rc=0
  gate_fn safe_gate_project_lane_socket_call "$SAFE_AUDIT" "$SAFE_CORE_BIN" "$CASE/cache-request.json" "$CASE/cache2.raw" 30 "$CASE_SCRATCH" || rc=$?
  show "socket cache with a block (raw)" "$CASE/cache2.raw"
  shape_case "socket cache with a cached block" socket_answer "$CASE/cache2.raw"
  gate_fn safe_gate_project_lane_socket_cache_doc "$CASE/cache-request.json" "$CASE/cache2.raw" "$CASE/cache2-doc.json" "" "$SAFE_CORE_BIN" || true
  if jq -e '.cache_gap == "" and (.cached_blocks | length == 1) and .cached_blocks[0].name == "fixture"' "$CASE/cache2-doc.json" >/dev/null 2>&1; then
    pass "socket cache: the block the real reader found in the cache is kept by the gate"
  else
    fail "socket cache: the real reader's cached block did not reach the gate's document: $(cat "$CASE/cache2-doc.json" 2>/dev/null) / $(cat "$CASE/cache2.raw" 2>/dev/null)"
  fi
}

# ---- 3. package-audit --evidence-only, named roots ----------------------------------------------------------------------------------
case_socket_roots() {
  prepare_case socket-roots
  local request='{"roots":[{"name":"fixture","version":"1.0.0"}],"cached":[]}' rc=0 mode
  printf '%s' "$request" > "$CASE/roots-request.json"
  for mode in clean malware; do
    rc=0
    MOCK_SOCKET_MODE="$mode" gate_fn safe_gate_project_lane_socket_call "$SAFE_AUDIT" "$SAFE_CORE_BIN" "$CASE/roots-request.json" "$CASE/roots-$mode.raw" 30 "$CASE_SCRATCH" "$CASE/progress-$mode" || rc=$?
    show "socket roots $mode (raw)" "$CASE/roots-$mode.raw"
    [[ "$rc" == 0 ]] || { fail "socket roots ($mode): the real reader exited $rc"; continue; }
    shape_case "socket roots ($mode)" socket_answer "$CASE/roots-$mode.raw"
    printf '[]\n' > "$CASE/untied-$mode.json"
    gate_fn safe_gate_project_lane_socket_roots_doc "$CASE/roots-request.json" "$CASE/roots-$mode.raw" "$CASE/roots-$mode-doc.json" "" "$CASE/progress-$mode" "$CASE/untied-$mode.json" "$SAFE_CORE_BIN" || true
    local want=clear; [[ "$mode" == malware ]] && want=blocked
    if jq -e --arg w "$want" '.schema_version == 1 and (.roots | length == 1) and .roots[0].outcome == $w and .untied == []' "$CASE/roots-$mode-doc.json" >/dev/null 2>&1; then
      pass "socket roots ($mode): the gate keeps the real reader's row ($want)"
    else
      fail "socket roots ($mode): the gate did not keep the real reader's row: $(cat "$CASE/roots-$mode-doc.json" 2>/dev/null)"
    fi
    # the rows from the answer alone: the gate keeps the rows the reader appended as it went (the progress file) when the answer is refused, so a
    # refused answer hides behind them unless the progress file is empty
    : > "$CASE/progress-empty-$mode"
    gate_fn safe_gate_project_lane_socket_roots_doc "$CASE/roots-request.json" "$CASE/roots-$mode.raw" "$CASE/roots-$mode-alone.json" "" "$CASE/progress-empty-$mode" "$CASE/untied-$mode.json" "$SAFE_CORE_BIN" || true
    if jq -e --arg w "$want" '(.roots | length == 1) and .roots[0].outcome == $w' "$CASE/roots-$mode-alone.json" >/dev/null 2>&1; then
      pass "socket roots ($mode): the gate takes the real reader's final answer as whole, with no help from the rows it appended"
    else
      fail "socket roots ($mode): the gate refused the real reader's final answer: $(cat "$CASE/roots-$mode-alone.json" 2>/dev/null)"
    fi
  done
}

# ---- 4. lane-acceptances ------------------------------------------------------------------------------------------------------------
case_acceptances() {
  prepare_case acceptances
  # a standing tolerance the operator holds: the reader answers with what the decision may take
  printf '{"install":{"cooldown_days":0,"auto_allow":true,"auto_allow_tolerate":["socket_low_score"],"socket":{"mode":"always","cache_ttl_days":7}}}\n' > "$CASE_RUN_CONFIG/config.json"
  printf '{"candidates":[{"name":"fixture","version":"1.0.0","host":"registry.npmjs.org","blocking_advisories":["GHSA-aaaa-0001"]}]}' > "$CASE/acc-request.json"
  local rc=0
  gate_fn safe_gate_project_lane_store_call "$SAFE_AUDIT" lane-acceptances "$CASE/acc-request.json" "$CASE/acc.json" 30 || rc=$?
  show acceptances "$CASE/acc.json"
  [[ "$rc" == 0 ]] || { fail "acceptances: the real door exited $rc"; return; }
  shape_case "acceptances" lane_acceptances "$CASE/acc.json"
  jq -e '.acceptances | length >= 1' "$CASE/acc.json" >/dev/null 2>&1 && pass "acceptances: the standing tolerance is answered" || fail "acceptances: the standing tolerance was not answered: $(cat "$CASE/acc.json")"
  # the decision reads it (exit 3 is a document it cannot read)
  lockfile_of "$CASE/lock.json" fixture@1.0.0
  printf '{"schema_version":1,"policy":{"block_severities":["critical"]},"identities":[{"name":"fixture","version":"1.0.0","coverage":"complete","gap":"","advisories":[]}],"blocklist":[]}\n' > "$CASE/ev.json"
  rc=0
  "$SAFE_CORE_BIN" project-decide --no-baseline --evidence "$CASE/ev.json" --acceptances "$CASE/acc.json" "$CASE/lock.json" >"$CASE/dec.json" 2>"$CASE/dec.err" || rc=$?
  [[ "$rc" != 3 && "$rc" != 2 ]] && pass "acceptances: the decision reads the real door's document (exit $rc)" || { cat "$CASE/dec.err" >&2; fail "acceptances: the decision could not read the real door's document (exit $rc)"; }
}

# ---- 5. package-audit <spec> --gate install --op install (a named root, after a publication) and lane-revoke ---------------------------
case_root_audit_and_revoke() {
  prepare_case root-audit
  local rc=0
  : > "$CASE/audit.err"
  gate_fn safe_gate_project_lane_audit_identity "$SAFE_AUDIT" "$SAFE_CORE_BIN" "$CASE_SCRATCH" other@2.0.0 "$CASE/audit.err" || rc=$?
  if [[ "$rc" == 0 ]]; then pass "root audit: the real audit of a clean named root exits 0"; else cat "$CASE/audit.err" >&2; fail "root audit: the real audit exited $rc"; return; fi
  gate_fn safe_gate_project_lane_receipt other 2.0.0 > "$CASE/receipt.json" || true
  show receipt "$CASE/receipt.json"
  if jq -e '. != null and .version == "2.0.0"' "$CASE/receipt.json" >/dev/null 2>&1; then pass "root audit: the receipt the real audit wrote is the one the gate compares"; else fail "root audit: the gate reads no receipt of what the real audit wrote: $(cat "$CASE/receipt.json")"; return; fi
  shape_case "root audit" install_receipt "$CASE/receipt.json"
  # lane-revoke removes it, and the gate's reading of the answer
  printf '{"identities":[{"name":"other","version":"2.0.0","host":"registry.npmjs.org"}]}' > "$CASE/revoke-request.json"
  rc=0
  gate_fn safe_gate_project_lane_store_call "$SAFE_AUDIT" lane-revoke "$CASE/revoke-request.json" "$CASE/revoke.json" 30 || rc=$?
  show revoke "$CASE/revoke.json"
  [[ "$rc" == 0 ]] || { fail "revoke: the real door exited $rc"; return; }
  shape_case "revoke" lane_revoke "$CASE/revoke.json"
  jq -e '.revoked | type == "array" and length == 1 and .[0].name == "other"' "$CASE/revoke.json" >/dev/null 2>&1 && pass "revoke: the gate reads the real door's answer (one receipt revoked)" || fail "revoke: $(cat "$CASE/revoke.json")"
  gate_fn safe_gate_project_lane_receipt other 2.0.0 > "$CASE/receipt-after.json" || true
  [[ "$(cat "$CASE/receipt-after.json")" == null ]] && pass "revoke: the gate reads no receipt afterwards" || fail "revoke: the receipt is still there: $(cat "$CASE/receipt-after.json")"
}

# ---- 6. repo-audit . --deps-only --allow-missing-tools --result-out (the project scan after a publication) -----------------------------------
case_scan() {
  prepare_case scan
  local bin="$CASE/scanners" tool
  mkdir -p "$bin" "$CASE/project"
  for tool in osv-scanner grype syft npm; do
    cat > "$bin/$tool" <<'STUB'
#!/usr/bin/env bash
case "$(basename -- "$0")" in
  osv-scanner) printf '{"results":[]}\n' ;;
  grype)       printf '{"matches":[]}\n' ;;
  syft)        printf '{"components":[],"metadata":{"tools":[{"name":"syft"}]}}\n' ;;
  npm)         printf '{"metadata":{"vulnerabilities":{"info":0,"low":0,"moderate":0,"high":0,"critical":0,"total":0}}}\n' ;;
esac
exit 0
STUB
    chmod +x "$bin/$tool"
  done
  printf '{"name":"demo","version":"1.0.0"}\n' > "$CASE/project/package.json"
  lockfile_of "$CASE/project/package-lock.json" fixture@1.0.0
  local rc=0
  ( cd "$CASE/project" && lane_env env PATH="$bin:$OSVBIN:$SOCKET_MOCKBIN:/usr/bin:/bin" "$SAFE_AUDIT" repo-audit . --deps-only --allow-missing-tools --result-out "$CASE/scan.json" </dev/null >/dev/null 2>"$CASE/scan.err" ) || rc=$?
  show scan "$CASE/scan.json"
  [[ -s "$CASE/scan.json" ]] || { cat "$CASE/scan.err" >&2; fail "scan: the real scan (exit $rc) wrote no result document"; return; }
  shape_case "scan" scan_result "$CASE/scan.json"
  rc=0
  "$SAFE_CORE_BIN" project-scan-summary --result "$CASE/scan.json" >"$CASE/scan-summary.txt" 2>"$CASE/scan-summary.err" || rc=$?
  if [[ "$rc" == 0 ]]; then pass "scan: the core's summary reads the real result document"; else cat "$CASE/scan-summary.err" >&2; fail "scan: the core's summary could not read the real result document (exit $rc)"; fi
}

# ---- 7. record-installed and safe-run host-allow: the operator's terminal only -------------------------------------------------------
# These two are the writers behind the lane's prompts. No terminal is made here: what is held is that in an agent session (a recognized
# marker, no terminal) they refuse and write nothing, so the stores the gate's readers look at stay as they were.
case_operator_only() {
  prepare_case operator-only
  local rc=0 before after
  printf '{"ecosystem":"npm","package":"fixture","resolved_versions":["1.0.0"],"gate_exit":13,"source_identity":"implicit-default","warn_causes":[]}\n' > "$CASE/result.json"
  before="$(find "$CASE_RUN_CONFIG" "$CASE_DATA" -type f -exec sha256sum {} + 2>/dev/null | sort)"
  CLAUDECODE=1 lane_env env CLAUDECODE=1 "$SAFE_AUDIT" record-installed fixture@1.0.0 --ecosystem npm --result "$CASE/result.json" --token GO_SOCKET_CONFIRMED </dev/null >/dev/null 2>"$CASE/rec.err" || rc=$?
  after="$(find "$CASE_RUN_CONFIG" "$CASE_DATA" -type f -exec sha256sum {} + 2>/dev/null | sort)"
  if [[ "$rc" != 0 && "$before" == "$after" ]]; then pass "record-installed: in an agent session it refuses (exit $rc) and writes nothing"; else cat "$CASE/rec.err" >&2; fail "record-installed: in an agent session it exited $rc or wrote something"; fi
  gate_fn safe_gate_project_lane_approved fixture 1.0.0 && fail "record-installed: the gate reads an approval that was never given" || pass "record-installed: the gate reads no approval"
}

# ---- 8. the stand-in of the live binding suite is held to the same definition -------------------------------------------------------
# tests/lib/lane_stand_in_auditor.sh is what scenarios A to J give the gate in place of the auditor (a live run has no Socket credential and must
# not depend on OSV). It answers every entry it stands for with the members and types of the real answers, or this case fails.
case_live_stand_in() {
  prepare_case live-stand-in
  local stand_in="$ROOT/tests/lib/lane_stand_in_auditor.sh" ok=1 problems out="$CASE/answer.json"
  chk() { if problems="$(lane_shape_check "$2" "$out")"; then :; else printf '%s: %s\n' "$1" "$problems" >&2; ok=0; fi; }
  printf '{"packages":[{"name":"a","version":"1.0.0"},{"name":"b","version":"1.0.0"},{"name":"c","version":"1.0.0"}]}' \
    | LIVE_ADVISORY_NAME=a LIVE_MALWARE_NAME=b bash "$stand_in" scanner-batch --evidence > "$out"
  chk "advisory evidence" evidence
  printf '{"roots":[{"name":"a","version":"1.0.0"}],"cached":[]}' | bash "$stand_in" package-audit --ecosystem npm --evidence-only > "$out"
  chk "Socket evidence" socket_answer
  printf '{"candidates":[]}' | bash "$stand_in" lane-acceptances > "$out"
  chk "acceptances" lane_acceptances
  printf '{"identities":[]}' | bash "$stand_in" lane-revoke > "$out"
  chk "revoke" lane_revoke
  ( cd "$CASE" && bash "$stand_in" repo-audit . --deps-only --allow-missing-tools --result-out "$out" ) >/dev/null
  chk "scan" scan_result
  ( cd "$CASE" && LIVE_SCAN_PYTHON_CRITICAL=2 LIVE_SCAN_PARTIAL=1 bash "$stand_in" repo-audit . --deps-only --allow-missing-tools --result-out "$out" ) >/dev/null
  chk "scan with findings and partial coverage" scan_result
  if (( ok )); then pass "the live suite's stand-in answers every entry with the members and types of the contract"; else fail "the live suite's stand-in differs from the contract"; fi
}

case_evidence
case_socket_cache
case_socket_roots
case_acceptances
case_root_audit_and_revoke
case_scan
case_operator_only
case_live_stand_in

printf '\n%d passed, %d failed\n' "$PASS_COUNT" "$FAIL_COUNT"
[[ "$FAIL_COUNT" -eq 0 ]]
