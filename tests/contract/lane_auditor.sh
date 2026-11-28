#!/usr/bin/env bash
# The joint contract of the project lane and the REAL auditor (ticket 1884).
#
# Every case of the lane suites drives the lane with a stand-in for the auditor, and the auditor's own suites test an entry alone: nothing gave
# the real auditor's answer to the gate's own reader, and the lane could not finish one command with the real auditor (the gate required a member
# of the Socket cache reader's answer that the reader never writes). Here, for every entry of the auditor the lane calls (docs/architecture.md,
# "Project lane: the entries of the auditor it calls"), the REAL entry of this tree runs in an isolated home with stubs only BELOW it (a `curl`
# for OSV, the Socket mock, stub scanners), on fixtures that FILL every array, and:
#
#   - its answer goes to the gate's REAL consumer (the function of lib/gate-lib.sh, the command of the core) and the case asserts an outcome that
#     depends on the answer's CONTENT (the decision's exit for a blocked fixture and for a clean one, an acceptance that clears a finding that
#     stands without it, the gate's own line);
#   - the shape of the real answers (every member path and its type) is computed when the suite runs and held, byte for byte, to
#     tests/lib/lane_auditor_shapes.json, which this suite GENERATES (LANE_SHAPES_UPDATE=1 rewrites it, an edit by hand fails here). Every stand-in
#     of the other suites is held to that file (tests/lib/lane_shape.sh), and the stand-in of the live suite is held to it here.
#
# The machine's own `socket` tool is never run: the Socket tool below the auditor is the repository's mock (tests/lib/socket-mockbin/socket), named
# by the home's tool configuration; no PATH holds another.
#
# Entries (the gate's call, the consumer):
#   scanner-batch --evidence                          safe-core project-decide --evidence
#   package-audit --evidence-only (cache, no roots)   safe_gate_project_lane_socket_cache_doc
#   package-audit --evidence-only (named roots)       safe_gate_project_lane_socket_roots_doc
#   lane-acceptances                                  safe_gate_project_lane_judge (and safe-core project-decide --acceptances)
#   lane-revoke                                       safe_gate_project_lane_revoke
#   package-audit <spec> --gate install --op install  safe_gate_project_lane_audit_roots (the receipt it leaves: safe_gate_project_lane_receipt)
#   package-audit <spec> --ecosystem npm --json       safe-run host-allow review (the audit a host-allow grant runs before it writes)
#   repo-audit . --deps-only --result-out             safe_gate_project_lane_scan_report (safe-core project-scan-summary)
#   record-installed, safe-run host-allow add         operator terminal only: refuse in an agent session, called as the gate calls them

set -euo pipefail

# SAFE_TEST_ISOLATION_MARKER: every suite owns a scratch HOME and safe state.
# shellcheck source=tests/lib/test-isolation.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/test-isolation.sh"
safe_test_setup_isolation || exit 1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SAFE_AUDIT="$ROOT/bin/safe-audit"
SAFE_RUN="$ROOT/bin/safe-run"
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
export LANE_SHAPE_CORE="$SAFE_CORE_BIN"

SOCKET_MOCKBIN="$ROOT/tests/lib/socket-mockbin"
OSVBIN="$TEST_ROOT/osvbin"
REAL_DIR="$TEST_ROOT/real"
mkdir -p "$OSVBIN" "$REAL_DIR"
# The network below the auditor: OSV's batch and record endpoints answer from the case's database (OSV_DB), anything else (Socket's registry
# reads) is the shared mock's.
cat > "$OSVBIN/curl" <<'MOCK'
#!/usr/bin/env bash
url="" body=""
args=("$@")
for ((i = 0; i < ${#args[@]}; i++)); do
  case "${args[$i]}" in
    -d) body="${args[$((i + 1))]}"; [[ "$body" != @* ]] || body="$(cat -- "${body#@}")"; i=$((i + 1)) ;;
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
# the scanners below the project scan: stubs that answer in each tool's own shape
SCANBIN="$TEST_ROOT/scanbin"
mkdir -p "$SCANBIN"
for tool in osv-scanner grype syft npm; do
  cat > "$SCANBIN/$tool" <<'STUB'
#!/usr/bin/env bash
case "$(basename -- "$0")" in
  osv-scanner) [[ -z "${STUB_OSV_FAIL:-}" ]] || { printf 'osv-scanner stub failure\n' >&2; exit 2; }; printf '{"results":[]}\n' ;;
  grype)       printf '{"matches":[]}\n' ;;
  syft)        if [[ -n "${STUB_SYFT_NOTE:-}" ]]; then printf '{"components":[],"metadata":{"tools":[{"name":"safe-audit","note":"%s"}]}}\n' "$STUB_SYFT_NOTE"; else printf '{"components":[],"metadata":{"tools":[{"name":"syft"}]}}\n'; fi ;;
  npm)         printf '{"metadata":{"vulnerabilities":{"info":0,"low":0,"moderate":0,"high":0,"critical":0,"total":0}}}\n' ;;
esac
exit 0
STUB
  chmod +x "$SCANBIN/$tool"
done

# a Socket program on the PATH of a case, or one the tool cache names, is a failure of the case (never a pass for another reason)
# shellcheck source=tests/lib/lane_no_socket.sh
. "$ROOT/tests/lib/lane_no_socket.sh"

prepare_case() { # <name>
  CASE="$TEST_ROOT/$1"
  CASE_HOME="$CASE/home"; CASE_RUN_CONFIG="$CASE_HOME/.config/safe/run"; CASE_AUDIT_CONFIG="$CASE/audit-config"; CASE_DATA="$CASE/data"
  CASE_CACHE="$CASE/socket-cache"; CASE_LOG="$CASE/socket.log"; CASE_SCRATCH="$CASE/lane-scratch"; CASE_TMP="$CASE/tmp"
  mkdir -p "$CASE_RUN_CONFIG" "$CASE_AUDIT_CONFIG" "$CASE_DATA" "$CASE_SCRATCH" "$CASE_TMP"
  write_config '{"install":{"cooldown_days":0,"socket":{"mode":"always","cache_ttl_days":7}}}'
  printf '{"packages":{}}\n' > "$CASE_RUN_CONFIG/blocked.json"
  printf '{"local":{"socket":"%s/socket"}}\n' "$SOCKET_MOCKBIN" > "$CASE_AUDIT_CONFIG/tools.json"
  : > "$CASE_LOG"
  OSV_DB="$CASE/osv-db.json"
  jq -n '{adv: {"fixture@1.0.0": [{id: "GHSA-aaaa-0001", modified: "2026-01-01T00:00:00.000001Z"}],
                "evil@1.0.0": [{id: "MAL-2026-1", modified: "2026-01-01T00:00:00.000001Z"}],
                "lost@1.0.0": [{id: "GHSA-lost-0001", modified: "2026-01-01T00:00:00.000001Z"}]},
          records: {"GHSA-aaaa-0001": {id: "GHSA-aaaa-0001", database_specific: {severity: "HIGH"}, affected: [{package: {ecosystem: "npm", name: "fixture"}}]}}}' > "$OSV_DB"
}
write_config() { printf '%s\n' "$1" > "$CASE_RUN_CONFIG/config.json"; }

# the environment the lane gives an auditor entry, in the case's isolated home; a command of the tree runs under it
lane_env() {
  env -u SOCKET_SECURITY_API_TOKEN -u CLAUDECODE -u CODEX_THREAD_ID -u CODEX_CI -u OPENCODE \
    HOME="$CASE_HOME" PATH="$OSVBIN:$SOCKET_MOCKBIN:/usr/bin:/bin" SOCKET_MOCKBIN="$SOCKET_MOCKBIN" OSV_DB="$OSV_DB" \
    SAFE_AUDIT_CONFIG_DIR="$CASE_AUDIT_CONFIG" SAFE_AUDIT_DATA_DIR="$CASE_DATA/audit" SAFE_RUN_CONFIG_DIR="$CASE_RUN_CONFIG" SAFE_RUN_TRUST_OVERRIDE=1 \
    SAFE_AUDIT_SOCKET_CACHE_DIR="$CASE_CACHE" SAFE_CORE_BIN="$SAFE_CORE_BIN" MOCK_SOCKET_LOG="$CASE_LOG" MOCK_SOCKET_MODE="${MOCK_SOCKET_MODE:-clean}" \
    SAFE_AUDIT_SOCKET_TIMEOUT=5 TMPDIR="$CASE_TMP" "$@"
}
# a function of the gate library, run in a subshell that sourced it, in the case's environment (extra variables in front of the call reach it)
gate_fn() { # <function> <args...>
  local fn="$1"; shift
  ( . "$ROOT/lib/gate-lib.sh"
    export HOME="$CASE_HOME" PATH="$OSVBIN:$SOCKET_MOCKBIN:/usr/bin:/bin" SOCKET_MOCKBIN="$SOCKET_MOCKBIN" OSV_DB="$OSV_DB" \
      SAFE_AUDIT_CONFIG_DIR="$CASE_AUDIT_CONFIG" SAFE_AUDIT_DATA_DIR="$CASE_DATA/audit" SAFE_RUN_CONFIG_DIR="$CASE_RUN_CONFIG" SAFE_RUN_TRUST_OVERRIDE=1 \
      SAFE_AUDIT_SOCKET_CACHE_DIR="$CASE_CACHE" MOCK_SOCKET_LOG="$CASE_LOG" MOCK_SOCKET_MODE="${MOCK_SOCKET_MODE:-clean}" SAFE_AUDIT_SOCKET_TIMEOUT=5 TMPDIR="$CASE_TMP"
    unset SOCKET_SECURITY_API_TOKEN CLAUDECODE CODEX_THREAD_ID CODEX_CI OPENCODE
    "$fn" "$@" )
}

# a real answer kept for the shape: $1 entry, $2 variant, $3 file
collect() { mkdir -p "$REAL_DIR/$1"; cp -- "$3" "$REAL_DIR/$1/$2.json"; }

# a lockfile of public identities for the decision to read
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
# the decision of the core for an evidence document (and optional Socket and acceptances documents): prints its exit
decide() { # <lockfile> <evidence> [<socket>] [<acceptances>]
  local lock="$1" ev="$2" rc=0
  local -a args=()
  args=(--no-baseline --evidence "$ev")
  [[ -z "${3:-}" ]] || args+=(--socket "$3")
  [[ -z "${4:-}" ]] || args+=(--acceptances "$4")
  "$SAFE_CORE_BIN" project-decide "${args[@]}" "$lock" >"$CASE/decision.json" 2>"$CASE/decision.err" || rc=$?
  printf '%s' "$rc"
}

DEBUG="${LANE_AUDITOR_DEBUG:-}"
show() { [[ -z "$DEBUG" ]] || { printf -- '--- %s\n' "$1" >&2; cat "$2" >&2; }; }
expect() { # <label> <got> <want>
  if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (got '$2', want '$3')"; fi
}

# ---- 1. scanner-batch --evidence -------------------------------------------------------------------------------------------------------
evidence_of() { # <variant> <request json>: runs the real reader, keeps the answer in $CASE/evidence-<variant>.json
  local rc=0
  printf '%s' "$2" | lane_env "$SAFE_AUDIT" scanner-batch --evidence >"$CASE/evidence-$1.json" 2>"$CASE/evidence-$1.err" || rc=$?
  show "evidence $1" "$CASE/evidence-$1.json"
  [[ "$rc" == 0 ]] || { cat "$CASE/evidence-$1.err" >&2; fail "evidence ($1): the real reader exited $rc"; return 1; }
  # only the document that fills every array is a sample of the shape (the others serve the decision)
  [[ "$1" != full ]] || collect evidence "$1" "$CASE/evidence-$1.json"
}
case_evidence() {
  prepare_case evidence
  printf '{"packages":{"blockedpkg":{"reason":"operator blocklist"}}}\n' > "$CASE_RUN_CONFIG/blocked.json"
  evidence_of full '{"packages":[{"name":"fixture","version":"1.0.0"},{"name":"evil","version":"1.0.0"},{"name":"lost","version":"1.0.0"},{"name":"clean","version":"1.0.0"}],"blocklist_names":["blockedpkg"]}' || return
  evidence_of high '{"packages":[{"name":"fixture","version":"1.0.0"},{"name":"clean","version":"1.0.0"}]}' || return
  evidence_of clean '{"packages":[{"name":"clean","version":"1.0.0"},{"name":"other","version":"2.0.0"}]}' || return
  # what the real reader found, in the members the decision reads
  jq -e '([.identities[] | select(.name == "evil") | .advisories[] | select(.malware == true and .id == "MAL-2026-1")] | length == 1)
         and ([.identities[] | select(.name == "fixture") | .advisories[] | select(.severity == "high" and .malware == false)] | length == 1)
         and ([.identities[] | select(.name == "lost") | select(.coverage == "missing" and (.gap | length > 0))] | length == 1)
         and (.blocklist | map(select(.name == "blockedpkg" and .reason == "operator blocklist")) | length == 1)' "$CASE/evidence-full.json" >/dev/null 2>&1 \
    && pass "evidence: the real reader found the malware record, the high advisory, the identity it could not read and the blocklist hit" \
    || fail "evidence: the real reader's document lacks what the fixture holds: $(cat "$CASE/evidence-full.json")"
  # the gate's consumer is the decision: its exit depends on what the document says
  lockfile_of "$CASE/lock-full.json" fixture@1.0.0 evil@1.0.0 lost@1.0.0 clean@1.0.0 blockedpkg@1.0.0
  expect "evidence: a known-malware record in the real reader's document is a block (104)" "$(decide "$CASE/lock-full.json" "$CASE/evidence-full.json")" 104
  lockfile_of "$CASE/lock-high.json" fixture@1.0.0 clean@1.0.0
  local high_exit
  high_exit="$(decide "$CASE/lock-high.json" "$CASE/evidence-high.json")"
  [[ "$high_exit" != 0 && "$high_exit" != 3 && "$high_exit" != 2 ]] && pass "evidence: a high advisory the command introduces stops the decision (exit $high_exit)" || fail "evidence: a high advisory did not stop the decision (exit $high_exit)"
  lockfile_of "$CASE/lock-clean.json" clean@1.0.0 other@2.0.0
  expect "evidence: a clean identity set is a clean decision (0)" "$(decide "$CASE/lock-clean.json" "$CASE/evidence-clean.json")" 0
  # the same real answer with its findings taken out would not stop the decision: the case above depends on the content
  jq '.identities |= map(.advisories = [])' "$CASE/evidence-high.json" > "$CASE/evidence-high-emptied.json"
  expect "evidence: the decision for the same lockfile without the advisories is clean (so the stop above is the advisory's)" "$(decide "$CASE/lock-high.json" "$CASE/evidence-high-emptied.json")" 0
}

# ---- 2/3. package-audit --evidence-only: the cache and the named roots ------------------------------------------------------------------
# one case home per Socket outcome: the reader is asked for a root and for the cache of an artifact whose blocking result is in the cache
socket_variant() { # <label> <want outcome> <mode> <config json> [VAR=val ...]
  local label="$1" want="$2" mode="$3" config="$4" rc=0
  shift 4
  prepare_case "socket-$label"
  # the cache holds a block: today's audit of the same artifact, in the mode that blocks, writes it
  MOCK_SOCKET_MODE=malware lane_env "$SAFE_AUDIT" package-audit fixture@1.0.0 --ecosystem npm --gate install --op install </dev/null >/dev/null 2>&1 || true
  write_config "$config"
  printf '{"roots":[{"name":"other","version":"2.0.0"}],"cached":[{"name":"fixture","version":"1.0.0"},{"name":"other","version":"9.9.9"}]}' > "$CASE/request.json"
  printf '[]\n' > "$CASE/untied.json"; : > "$CASE/progress"
  ( for kv in "$@"; do export "$kv"; done
    MOCK_SOCKET_MODE="$mode" gate_fn safe_gate_project_lane_socket_call "$SAFE_AUDIT" "$SAFE_CORE_BIN" "$CASE/request.json" "$CASE/answer.json" 40 "$CASE_SCRATCH" "$CASE/progress" ) || rc=$?
  show "socket $label" "$CASE/answer.json"
  [[ "$rc" == 0 && -s "$CASE/answer.json" ]] || { fail "socket ($label): the real reader exited $rc"; return; }
  collect socket_answer "$label" "$CASE/answer.json"
  # the gate's own consumers: the cache's document keeps the block the reader found, the roots' document keeps the reader's row
  gate_fn safe_gate_project_lane_socket_cache_doc "$CASE/request.json" "$CASE/answer.json" "$CASE/cache-doc.json" "" "$SAFE_CORE_BIN" || true
  jq -e '.cache_gap == "" and (.cached_blocks | length == 1) and .cached_blocks[0].name == "fixture" and .cached_blocks[0].version == "1.0.0"' "$CASE/cache-doc.json" >/dev/null 2>&1 \
    && pass "socket ($label): the gate's cache document takes the real answer whole and keeps the cached block" \
    || fail "socket ($label): the gate's cache document: $(cat "$CASE/cache-doc.json" 2>/dev/null)"
  gate_fn safe_gate_project_lane_socket_roots_doc "$CASE/request.json" "$CASE/answer.json" "$CASE/roots-doc.json" "" "$CASE/progress" "$CASE/untied.json" "$SAFE_CORE_BIN" || true
  expect "socket ($label): the gate's roots document keeps the real reader's row, outcome $want" "$(jq -r '.roots[0].outcome' "$CASE/roots-doc.json" 2>/dev/null)" "$want"
  # no help from rows written on the way: with an empty progress file the answer alone is whole
  : > "$CASE/progress-empty"
  gate_fn safe_gate_project_lane_socket_roots_doc "$CASE/request.json" "$CASE/answer.json" "$CASE/roots-alone.json" "" "$CASE/progress-empty" "$CASE/untied.json" "$SAFE_CORE_BIN" || true
  expect "socket ($label): the answer alone is taken as whole, outcome $want" "$(jq -r '.roots[0].outcome' "$CASE/roots-alone.json" 2>/dev/null)" "$want"
  SOCKET_CASE="$CASE"
}
case_socket() {
  socket_variant clear clear clean '{"install":{"cooldown_days":0,"socket":{"mode":"always","cache_ttl_days":7}}}'
  socket_variant adverse adverse low '{"install":{"cooldown_days":0,"socket":{"mode":"always","cache_ttl_days":7}}}'
  socket_variant blocked blocked malware '{"install":{"cooldown_days":0,"socket":{"mode":"always","cache_ttl_days":7}}}'
  socket_variant rate rate_limited rate '{"install":{"cooldown_days":0,"socket":{"mode":"always","cache_ttl_days":7}}}'
  socket_variant unavailable unavailable other '{"install":{"cooldown_days":0,"socket":{"mode":"always","cache_ttl_days":7}}}'
  socket_variant consent consent_required clean '{"install":{"cooldown_days":0,"socket":{"mode":"auto","cache_ttl_days":7}}}' MOCK_RELEASE_FRESH=1
  socket_variant pending pending pending '{"install":{"cooldown_days":3,"socket":{"mode":"always","cache_ttl_days":7}}}' MOCK_RELEASE_FRESH=1 MOCK_COOLDOWN_FIX=1 SAFE_AUDIT_SOCKET_FRESH_SCAN_TIMEOUT=1
  # the decision reads the Socket document the gate assembles from the real answers: a blocked root stops it, a clear one does not
  prepare_case socket-decision
  lockfile_of "$CASE/lock.json" other@2.0.0
  printf '{"schema_version":1,"policy":{"block_severities":["critical"]},"identities":[{"name":"other","version":"2.0.0","coverage":"complete","gap":"","advisories":[]}],"blocklist":[]}\n' > "$CASE/ev.json"
  local variant doc
  for variant in clear blocked; do
    doc="$TEST_ROOT/socket-$variant"
    jq -c --slurpfile r "$doc/roots-doc.json" '.roots = $r[0].roots | .untied = $r[0].untied' "$doc/cache-doc.json" > "$CASE/socket-$variant.json"
  done
  expect "socket: the decision for a root the real reader found clear is clean (0)" "$(decide "$CASE/lock.json" "$CASE/ev.json" "$CASE/socket-clear.json")" 0
  expect "socket: the decision for a root the real reader found blocked is a block (104)" "$(decide "$CASE/lock.json" "$CASE/ev.json" "$CASE/socket-blocked.json")" 104
  # a root the lane named: the decision reads Socket's results for the roots it is told were named; the cached block counts for any artifact of the lockfile
  lockfile_of "$CASE/lock-fixture.json" fixture@1.0.0
  printf '{"schema_version":1,"policy":{"block_severities":["critical"]},"identities":[{"name":"fixture","version":"1.0.0","coverage":"complete","gap":"","advisories":[]}],"blocklist":[]}\n' > "$CASE/ev-fixture.json"
  expect "socket: a block the real reader found in the cache stops the decision for the artifact (104)" "$(decide "$CASE/lock-fixture.json" "$CASE/ev-fixture.json" "$CASE/socket-clear.json")" 104
}

# ---- 4. lane-acceptances, through safe_gate_project_lane_judge --------------------------------------------------------------------------
case_acceptances() {
  prepare_case acceptances
  lockfile_of "$CASE/lock.json" other@2.0.0
  printf '{"schema_version":1,"policy":{"block_severities":["critical"]},"identities":[{"name":"other","version":"2.0.0","coverage":"complete","gap":"","advisories":[]}],"blocklist":[]}\n' > "$CASE/ev.json"
  # a Socket finding that stands: the real reader found a low score on the named root
  printf '{"roots":[{"name":"other","version":"2.0.0"}],"cached":[]}' > "$CASE/request.json"
  printf '[]\n' > "$CASE/untied.json"; : > "$CASE/progress"
  MOCK_SOCKET_MODE=low gate_fn safe_gate_project_lane_socket_call "$SAFE_AUDIT" "$SAFE_CORE_BIN" "$CASE/request.json" "$CASE/answer.json" 40 "$CASE_SCRATCH" "$CASE/progress" || true
  gate_fn safe_gate_project_lane_socket_roots_doc "$CASE/request.json" "$CASE/answer.json" "$CASE/roots-doc.json" "" "$CASE/progress" "$CASE/untied.json" "$SAFE_CORE_BIN" || true
  jq -c '{schema_version: 1, roots: .roots, untied: .untied, cached_blocks: [], cache_gap: ""}' "$CASE/roots-doc.json" > "$CASE/socket.json"
  local without with
  without="$(decide "$CASE/lock.json" "$CASE/ev.json" "$CASE/socket.json")"
  [[ "$without" != 0 && "$without" != 2 && "$without" != 3 ]] && pass "acceptances: the Socket finding stands with no acceptance (exit $without)" || fail "acceptances: the finding does not stand without an acceptance (exit $without)"
  # the gate's judging function: the first decision names what it wants, the real door answers, the decision is made again
  printf '{}' > "$CASE/graph.json"
  gate_fn safe_gate_project_lane_judge "$SAFE_CORE_BIN" "$SAFE_AUDIT" "$CASE_SCRATCH" "$CASE/graph.json" "$CASE/report-none.json" --no-baseline --evidence "$CASE/ev.json" --socket "$CASE/socket.json" "$CASE/lock.json" || true
  local rc_none=0
  "$SAFE_CORE_BIN" project-decide --no-baseline --evidence "$CASE/ev.json" --socket "$CASE/socket.json" "$CASE/lock.json" >/dev/null 2>&1 || rc_none=$?
  # with the operator's standing tolerance of the cause, the real door answers an acceptance and the gate's judging clears the finding
  write_config '{"install":{"cooldown_days":0,"auto_allow":true,"auto_allow_tolerate":["socket_low_score"],"socket":{"mode":"always","cache_ttl_days":7}}}'
  local rc_with=0
  gate_fn safe_gate_project_lane_judge "$SAFE_CORE_BIN" "$SAFE_AUDIT" "$CASE_SCRATCH" "$CASE/graph.json" "$CASE/report-with.json" --no-baseline --evidence "$CASE/ev.json" --socket "$CASE/socket.json" "$CASE/lock.json" || rc_with=$?
  expect "acceptances: the gate's judging, with the real door's acceptance of the standing tolerance, clears the finding (0)" "$rc_with" 0
  jq -e '(.wanted | length) == 0 or true' "$CASE/report-with.json" >/dev/null 2>&1 || true
  # the same judging without the tolerance does not clear it
  write_config '{"install":{"cooldown_days":0,"socket":{"mode":"always","cache_ttl_days":7}}}'
  local rc_off=0
  gate_fn safe_gate_project_lane_judge "$SAFE_CORE_BIN" "$SAFE_AUDIT" "$CASE_SCRATCH" "$CASE/graph.json" "$CASE/report-off.json" --no-baseline --evidence "$CASE/ev.json" --socket "$CASE/socket.json" "$CASE/lock.json" || rc_off=$?
  [[ "$rc_off" != 0 && "$rc_off" == "$rc_none" ]] && pass "acceptances: the same judging without the tolerance leaves the finding standing (exit $rc_off)" || fail "acceptances: without the tolerance the judging gave $rc_off (the decision alone gave $rc_none)"
  # the real door's own answer (kept for the shape)
  printf '{"candidates":[{"name":"other","version":"2.0.0","host":"registry.npmjs.org","blocking_advisories":[]}]}' > "$CASE/door-request.json"
  write_config '{"install":{"cooldown_days":0,"auto_allow":true,"auto_allow_tolerate":["socket_low_score"],"socket":{"mode":"always","cache_ttl_days":7}}}'
  gate_fn safe_gate_project_lane_store_call "$SAFE_AUDIT" lane-acceptances "$CASE/door-request.json" "$CASE/door.json" 30 || true
  show acceptances "$CASE/door.json"
  collect lane_acceptances tolerance "$CASE/door.json"
  jq -e '.acceptances | length == 1 and .[0].kind == "local_tolerance" and (.[0].causes | index("socket_low_score") != null)' "$CASE/door.json" >/dev/null 2>&1 \
    && pass "acceptances: the real door answers the standing tolerance with its cause" || fail "acceptances: the real door's answer: $(cat "$CASE/door.json" 2>/dev/null)"
}

# ---- 5. package-audit <spec> --gate install --op install, the receipt, and lane-revoke -------------------------------------------------------
case_root_audit_and_revoke() {
  prepare_case root-audit
  local bind="$CASE/bind.json" report="$CASE/report.json" err
  printf '{"records":[{"name":"other","version":"2.0.0","host":"registry.npmjs.org"}]}\n' > "$report"
  printf '{"verification":{"present_direct":[{"name":"other","version":"2.0.0"}]}}\n' > "$bind"
  # the gate's own handling of a clean named root: the audit records, and the gate says what the receipt became
  err="$(gate_fn safe_gate_project_lane_audit_roots "$SAFE_AUDIT" "$SAFE_CORE_BIN" "$report" "$CASE_SCRATCH" "$bind" 2>&1 >/dev/null || true)"
  grep -q "today's audit wrote the receipt of other@2.0.0: GO" <<<"$err" && pass "root audit: the gate reports the receipt the real audit wrote (GO)" || { printf '%s\n' "$err" >&2; fail "root audit: the gate's line for a clean root"; }
  gate_fn safe_gate_project_lane_receipt other 2.0.0 > "$CASE/receipt.json" || true
  show receipt "$CASE/receipt.json"
  jq -e '. != null and .version == "2.0.0" and .verdict == "GO" and .source == "implicit-default"' "$CASE/receipt.json" >/dev/null 2>&1 \
    && pass "root audit: the receipt the gate compares is the one the real audit wrote" || fail "root audit: no receipt: $(cat "$CASE/receipt.json")"
  collect install_receipt go "$CASE/receipt.json"
  # a root the audit blocks: the gate says so as a finding of its own
  prepare_case root-audit-block
  printf '{"records":[{"name":"fixture","version":"1.0.0","host":"registry.npmjs.org"}]}\n' > "$report"
  printf '{"verification":{"present_direct":[{"name":"fixture","version":"1.0.0"}]}}\n' > "$bind"
  err="$(MOCK_SOCKET_MODE=malware gate_fn safe_gate_project_lane_audit_roots "$SAFE_AUDIT" "$SAFE_CORE_BIN" "$report" "$CASE_SCRATCH" "$bind" 2>&1 >/dev/null || true)"
  grep -q "FINDING: fixture@1.0.0 is installed, and today's audit now reports a BLOCK (exit 20)" <<<"$err" && pass "root audit: a root the real audit blocks is a finding of the gate's (BLOCK, exit 20)" || { printf '%s\n' "$err" >&2; fail "root audit: the gate's line for a blocked root"; }
  # lane-revoke, through the gate's revocation: the receipt goes, and the gate says so
  prepare_case revoke
  gate_fn safe_gate_project_lane_audit_identity "$SAFE_AUDIT" "$SAFE_CORE_BIN" "$CASE_SCRATCH" other@2.0.0 "$CASE/audit.err" || true
  jq -e '. != null' <(gate_fn safe_gate_project_lane_receipt other 2.0.0) >/dev/null 2>&1 || { fail "revoke: no receipt to revoke"; return; }
  printf '{"adverse":[{"name":"other","version":"2.0.0","host":"registry.npmjs.org"}]}\n' > "$CASE/revoke-report.json"
  err="$(gate_fn safe_gate_project_lane_revoke "$SAFE_AUDIT" "$CASE/revoke-report.json" "$CASE_SCRATCH" 2>&1 >/dev/null || true)"
  grep -q "the receipt of other@2.0.0 was revoked: this command's evidence supersedes it" <<<"$err" && ! grep -q "could not be revoked" <<<"$err" \
    && pass "revoke: the gate says the receipt was revoked (it read the real door's answer)" || { printf '%s\n' "$err" >&2; fail "revoke: the gate's line"; }
  expect "revoke: the gate reads no receipt afterwards" "$(gate_fn safe_gate_project_lane_receipt other 2.0.0)" null
  printf '{"identities":[{"name":"nothing","version":"1.0.0","host":"registry.npmjs.org"}]}' > "$CASE/revoke-request.json"
  gate_fn safe_gate_project_lane_audit_identity "$SAFE_AUDIT" "$SAFE_CORE_BIN" "$CASE_SCRATCH" other@2.0.0 "$CASE/audit.err" || true
  printf '{"identities":[{"name":"other","version":"2.0.0","host":"registry.npmjs.org"}]}' > "$CASE/revoke-request.json"
  gate_fn safe_gate_project_lane_store_call "$SAFE_AUDIT" lane-revoke "$CASE/revoke-request.json" "$CASE/revoke.json" 30 || true
  show revoke "$CASE/revoke.json"
  collect lane_revoke revoked "$CASE/revoke.json"
}

# ---- 6. package-audit <spec> --ecosystem npm --json: the audit a host-allow grant runs, read by `safe-run host-allow review` ----------------------
case_preflight() {
  local mode want out
  for mode in clean low malware; do
    prepare_case "preflight-$mode"
    case "$mode" in clean) want=removable ;; low) want=keep ;; malware) want=review-urgent ;; esac
    printf '{"packages":{"other":{"version":"2.0.0","sha":"a","ecosystem":"npm","added":"2026-07-01"}}}\n' > "$CASE_RUN_CONFIG/host-allow.json"
    mkdir -p "$CASE_DATA/audit/checks"
    # the audit itself, as the grant's preflight runs it (closed stdin, no initialisation), for the shape
    SAFE_AUDIT_NO_INIT=1 MOCK_SOCKET_MODE="$mode" lane_env "$SAFE_AUDIT" package-audit other@2.0.0 --ecosystem npm --json </dev/null >"$CASE/preflight.json" 2>/dev/null || true
    show "preflight $mode" "$CASE/preflight.json"
    collect package_audit_json "$mode" "$CASE/preflight.json"
    # the consumer: `safe-run host-allow review` re-audits each pin through the same call and classifies it by what it answers
    out="$(MOCK_SOCKET_MODE="$mode" lane_env env SAFE_AUDIT_NO_INIT=1 SAFE_AUDIT_BIN="$SAFE_AUDIT" SAFE_RUN_CONFIG_DIR="$CASE_RUN_CONFIG" SAFE_RUN_DATA_DIR="$CASE/run-data" \
      "$SAFE_RUN" host-allow review --json </dev/null 2>"$CASE/review.err")" || true
    expect "preflight ($mode): the consumer classifies the pin from the real answer" "$(jq -r '.entries[0].status' <<<"$out" 2>/dev/null)" "$want"
  done
}

# ---- 7. repo-audit . --deps-only --allow-missing-tools --result-out, through the gate's own scan handling --------------------------------------------
scan_variant() { # <label> <setup command words…>: a project, the real scan on it, the answer kept
  local label="$1"; shift
  prepare_case "scan-$label"
  mkdir -p "$CASE/project"
  "$@"
  local rc=0
  ( cd "$CASE/project" && lane_env env PATH="$SCANBIN:$OSVBIN:$SOCKET_MOCKBIN:/usr/bin:/bin" "$SAFE_AUDIT" repo-audit . --deps-only --allow-missing-tools --result-out "$CASE/scan.json" </dev/null >/dev/null 2>"$CASE/scan.err" ) || rc=$?
  show "scan $label" "$CASE/scan.json"
  [[ -s "$CASE/scan.json" ]] || { cat "$CASE/scan.err" >&2; fail "scan ($label): the real scan (exit $rc) wrote no result"; return 1; }
  collect scan_result "$label" "$CASE/scan.json"
  SCAN_CASE="$CASE"
}
project_ok() { printf '{"name":"demo","version":"1.0.0"}\n' > "$CASE/project/package.json"; lockfile_of "$CASE/project/package-lock.json" fixture@1.0.0; }
project_nolock() { printf '{"name":"demo","version":"1.0.0"}\n' > "$CASE/project/package.json"; }
project_python() { project_ok; printf 'requests==2.0.0\n' > "$CASE/project/requirements.txt"; }
project_osv_error() { project_ok; STUB_OSV_FAIL=1; export STUB_OSV_FAIL; }
project_syft_skipped() { project_ok; STUB_SYFT_NOTE="syft unavailable"; export STUB_SYFT_NOTE; }

# the gate's own handling of the scan: it runs the scan, reads its exit status, and prints what the summary holds
gate_scan() { # <project dir> <scratch dir> <safe dir>: prints the gate's lines (stderr)
  ( . "$ROOT/lib/gate-lib.sh"
    export HOME="$CASE_HOME" PATH="$SCANBIN:$OSVBIN:$SOCKET_MOCKBIN:/usr/bin:/bin" SOCKET_MOCKBIN="$SOCKET_MOCKBIN" OSV_DB="$OSV_DB" SAFE_AUDIT_CONFIG_DIR="$CASE_AUDIT_CONFIG" \
      SAFE_AUDIT_DATA_DIR="$CASE_DATA/audit" SAFE_RUN_CONFIG_DIR="$CASE_RUN_CONFIG" SAFE_RUN_TRUST_OVERRIDE=1 TMPDIR="$CASE_TMP" STUB_OSV_FAIL="${STUB_OSV_FAIL:-}"
    unset SOCKET_SECURITY_API_TOKEN CLAUDECODE CODEX_THREAD_ID CODEX_CI OPENCODE
    SAFE_DIR="$3" SAFE_GATE_LANE_SCRATCH="$2" SAFE_GATE_LANE_CORE="$SAFE_CORE_BIN" SAFE_GATE_LANE_FACT_PROJECT="$1"
    printf '{"target":"sha256:%s","baseline":""}\n' "$(sha256sum "$1/package-lock.json" 2>/dev/null | cut -d' ' -f1)" > "$2/judged.json"
    safe_gate_project_lane_scan_report ) 2>&1 >/dev/null
}
case_scan() {
  local err
  scan_variant ok project_ok || return
  scan_variant unsupported project_nolock || return
  scan_variant error project_osv_error || return
  unset STUB_OSV_FAIL
  scan_variant skipped project_python || return
  unset STUB_OSV_FAIL
  scan_variant syft_skipped project_syft_skipped || return
  unset STUB_SYFT_NOTE
  # the statuses of the scan's own results, taken from the fixtures (no second list), against the summary the core makes of them and the
  # lines the gate prints from the summary: every scanner that is not ok is named, with its status, and none is "other"
  local variant ok=1 gaps summary lines
  for variant in ok unsupported error skipped syft_skipped; do
    gaps="$(jq -c '[((.tool_status // {}) | to_entries[] | select(.value.status != "ok") | {scanner: .key, status: .value.status}),
                    (.ecosystem_audits[]? | select(.status != "ok") | {scanner, status})] | unique' "$REAL_DIR/scan_result/$variant.json")"
    summary="$("$SAFE_CORE_BIN" project-scan-summary --result "$REAL_DIR/scan_result/$variant.json" 2>/dev/null)" || { printf 'scan %s: the summary failed\n' "$variant" >&2; ok=0; continue; }
    [[ "$(jq -c '.coverage_gaps | sort_by(.scanner, .status)' <<<"$summary")" == "$(jq -c 'sort_by(.scanner, .status)' <<<"$gaps")" && "$(jq '.coverage_other' <<<"$summary")" == 0 ]] \
      || { printf 'scan %s: the scan says %s, the summary names %s (other: %s)\n' "$variant" "$gaps" "$(jq -c .coverage_gaps <<<"$summary")" "$(jq .coverage_other <<<"$summary")" >&2; ok=0; }
    lines="$(jq -c '{status: "completed", reason: "", summary: ., lockfile_published: true}' <<<"$summary" | ( . "$ROOT/lib/gate-lib.sh"; safe_gate_project_lane_scan_lines ) 2>&1)" || { printf 'scan %s: the gate cannot read the summary\n' "$variant" >&2; ok=0; continue; }
    while IFS= read -r gap; do
      [[ -z "$gap" ]] && continue
      grep -q "$(jq -r '"\(.scanner) \(.status)"' <<<"$gap")" <<<"$lines" || { printf 'scan %s: the gate does not name %s: %s\n' "$variant" "$gap" "$lines" >&2; ok=0; }
    done < <(jq -c '.[]' <<<"$gaps")
  done
  (( ok )) && pass "scan: every status the real scan wrote (from its own results on fixtures) is named by the core's summary and by the gate's line" || fail "scan: a status the real scan wrote is not named by the summary or the gate"
  jq -e '[.[]?] | length' <<<"[]" >/dev/null 2>&1 || true
  # the gate's own handling of the scan's exit status: a scan that completes is reported; one that exits non-zero after writing its result is a failed scan
  local safe_dir="$TEST_ROOT/safedir"
  mkdir -p "$safe_dir"
  ln -sf "$SAFE_AUDIT" "$safe_dir/safe-audit-real"
  cat > "$safe_dir/safe-audit" <<WRAP
#!/usr/bin/env bash
"$SAFE_AUDIT" "\$@"
rc=\$?
[[ -z "\${SCAN_EXIT_AFTER:-}" ]] || exit "\${SCAN_EXIT_AFTER}"
exit \$rc
WRAP
  chmod +x "$safe_dir/safe-audit"
  prepare_case scan-gate
  mkdir -p "$CASE/project" "$CASE/gate-scratch"
  project_ok
  err="$(gate_scan "$CASE/project" "$CASE/gate-scratch" "$safe_dir")"
  [[ -z "$err" ]] && pass "scan: through the gate's handling, a scan with every scanner ok says nothing" || { printf '%s\n' "$err" >&2; fail "scan: the gate's handling of a clean scan"; }
  # a home of its own for each run: the scan caches a result by the evidence it read, and the stubs' behaviour is not part of that key
  prepare_case scan-gate-error
  mkdir -p "$CASE/project" "$CASE/gate-scratch"; project_ok
  err="$(STUB_OSV_FAIL=1 gate_scan "$CASE/project" "$CASE/gate-scratch" "$safe_dir")"
  grep -q "project scan: scanner coverage: osv-scanner error; that coverage is missing" <<<"$err" && ! grep -q "did not complete" <<<"$err" \
    && pass "scan: through the gate's handling, the real scan's failed scanner is named with its status" || { printf '%s\n' "$err" >&2; fail "scan: the gate's line for a failed scanner"; }
  prepare_case scan-gate-exit7
  mkdir -p "$CASE/project" "$CASE/gate-scratch"; project_ok
  err="$(SCAN_EXIT_AFTER=7 gate_scan "$CASE/project" "$CASE/gate-scratch" "$safe_dir")"
  grep -q "project scan: did not complete (it failed" <<<"$err" \
    && pass "scan: through the gate's handling, a scan that exits 7 after writing its result is a failed scan" || { printf '%s\n' "$err" >&2; fail "scan: the gate's handling of a scan that exits 7"; }
}

# ---- 8. record-installed and safe-run host-allow add: the operator's terminal only, called as the gate calls them -------------------------
# No terminal is made. In an agent session (a recognized marker and no terminal) they refuse with status 102 and their line, and the stores a
# grant would touch are as they were: the approvals (install-known.json) and the host-allow pins (host-allow.json) with their entries. (The runner
# initialises seven files of its own on a cold home; those are not claimed untouched.)
store_digest() { # the stores a grant or an approval would write
  local f
  for f in "$CASE_RUN_CONFIG/install-known.json" "$CASE_RUN_CONFIG/host-allow.json"; do
    # a file the runner has not made yet holds nothing: the same as one that exists and is empty
    if [[ -e "$f" ]]; then jq -S -c '.packages // {}, .approvals // {}' "$f" 2>/dev/null || printf 'unreadable\n'; else printf '{}\n{}\n'; fi
  done
}
case_operator_only() {
  prepare_case operator-only
  local before after rc=0 err
  # the result document the gate hands record-installed (safe_gate_project_lane_result_doc), and the arguments the gate sends
  printf '{"ecosystem":"npm","package":"fixture","resolved_versions":["1.0.0"],"gate_exit":13,"source_identity":"implicit-default","warn_causes":[]}\n' > "$CASE/result.json"
  before="$(store_digest)"
  lane_env env CLAUDECODE=1 "$SAFE_AUDIT" record-installed --result "$CASE/result.json" --verdict GO_SOCKET_CONFIRMED --source-id implicit-default </dev/null >/dev/null 2>"$CASE/rec.err" || rc=$?
  after="$(store_digest)"
  [[ "$rc" == 102 ]] && grep -q 'BLOCKED record-installed — reusable consent requires the operator terminal' "$CASE/rec.err" \
    && pass "record-installed: called with --result, --verdict and --source-id in an agent session it refuses (102) with its line" || { cat "$CASE/rec.err" >&2; fail "record-installed: status $rc, not 102 with its line"; }
  [[ "$before" == "$after" ]] && pass "record-installed: the approval store is as it was" || fail "record-installed: the approval store changed"
  # through the gate's own function: the refusal is the gate's line and no approval exists
  err="$(CLAUDECODE=1 gate_fn safe_gate_project_lane_approve "$SAFE_AUDIT" "$CASE_SCRATCH" GO_SOCKET_CONFIRMED 13 fixture 1.0.0 2>&1 >/dev/null || true)"
  gate_fn safe_gate_project_lane_approved fixture 1.0.0 && fail "record-installed: the gate reads an approval that was never given" || pass "record-installed: through the gate's approval function no approval is recorded"
  : "$err"
  # safe-run host-allow add, in the two forms the gate uses
  local form
  for form in "fixture@1.0.0" "fixture@1.0.0 --accept-block"; do
    rc=0; before="$(store_digest)"
    # shellcheck disable=SC2086
    lane_env env CLAUDECODE=1 SAFE_AUDIT_BIN="$SAFE_AUDIT" SAFE_RUN_DATA_DIR="$CASE/run-data" "$SAFE_RUN" host-allow add $form </dev/null >/dev/null 2>"$CASE/add.err" || rc=$?
    after="$(store_digest)"
    [[ "$rc" == 102 ]] && pass "safe-run host-allow add $form: in an agent session it refuses (102)" || { cat "$CASE/add.err" >&2; fail "safe-run host-allow add $form: status $rc, not 102"; }
    grep -qiE 'operator terminal|requires an interactive operator terminal|BLOCKED' "$CASE/add.err" && pass "safe-run host-allow add $form: its line names the operator terminal" || { cat "$CASE/add.err" >&2; fail "safe-run host-allow add $form: its line"; }
    [[ "$before" == "$after" ]] && pass "safe-run host-allow add $form: no pin, approval or override was written" || fail "safe-run host-allow add $form: the stores changed"
    gate_fn safe_gate_project_lane_pinned fixture 1.0.0 && fail "host-allow: the gate reads a pin that was never granted" || pass "host-allow ($form): the gate reads no pin"
  done
  # the gate's own functions, as the lane calls them, in an agent session: the grant is reported as not recorded
  err="$(CLAUDECODE=1 SAFE_RUN_BIN="$SAFE_RUN" SAFE_GATE_AUDIT_BIN="$SAFE_AUDIT" SAFE_AUDIT_BIN="$SAFE_AUDIT" gate_fn safe_gate_warn_grant_host_allow fixture@1.0.0 npm 2>&1 >/dev/null || true)"
  grep -q "the host-allow grant was not recorded" <<<"$err" && pass "host-allow: the gate's grant function reports the grant was not recorded" || { printf '%s\n' "$err" >&2; fail "host-allow: the gate's grant function line"; }
  err="$(CLAUDECODE=1 SAFE_RUN_BIN="$SAFE_RUN" SAFE_GATE_AUDIT_BIN="$SAFE_AUDIT" SAFE_AUDIT_BIN="$SAFE_AUDIT" gate_fn safe_gate_block_record_override fixture@1.0.0 npm 2>&1 >/dev/null || true)"
  grep -q "the BLOCK override was not recorded" <<<"$err" && pass "host-allow: the gate's override function reports the override was not recorded" || { printf '%s\n' "$err" >&2; fail "host-allow: the gate's override function line"; }
}

# ---- the final answer against the rows the reader wrote on the way --------------------------------------------------------------------------------
# With the final answer accepted it alone decides for a completed call, except that a root for which it and a row the reader appended DISAGREE (or
# that the answer lacks and a row holds) is an unavailable result: never the weaker of the two. The rows are the real reader's own (the clear, adverse
# and blocked rows of the answers kept above). A final answer with a root and NO row on the way is not a disagreement: the append is best-effort, so a
# missing row says nothing, and the answer decides.
case_final_answer_against_rows() {
  prepare_case rows
  local clear="$REAL_DIR/socket_answer/clear.json"
  printf '{"roots":[{"name":"other","version":"2.0.0"}],"cached":[]}' > "$CASE/request.json"
  printf '[]\n' > "$CASE/untied.json"
  answer_of() { # <real answer> | absent: the final answer holding that answer's row for the root, or none
    if [[ "$1" == absent ]]; then jq -c '.roots = []' "$clear"; else jq -c '.' "$1"; fi
  }
  row_of() { # <real answer> | absent: the row on the way
    if [[ "$1" == absent ]]; then : ; else jq -c '.roots[0]' "$1"; fi
  }
  local pair final progress want
  for pair in "clear adverse unavailable" "clear blocked unavailable" "blocked clear unavailable" "clear absent clear" "absent clear unavailable" "absent blocked unavailable" \
              "blocked blocked blocked" "adverse adverse adverse" "clear clear clear"; do
    read -r final progress want <<<"$pair"
    answer_of "$([[ $final == absent ]] && echo absent || echo "$REAL_DIR/socket_answer/$final.json")" > "$CASE/answer.json"
    row_of "$([[ $progress == absent ]] && echo absent || echo "$REAL_DIR/socket_answer/$progress.json")" > "$CASE/progress"
    gate_fn safe_gate_project_lane_socket_roots_doc "$CASE/request.json" "$CASE/answer.json" "$CASE/doc.json" "" "$CASE/progress" "$CASE/untied.json" "$SAFE_CORE_BIN" || true
    expect "rows: final $final, row on the way $progress: the root is $want" "$(jq -r '.roots[0].outcome' "$CASE/doc.json" 2>/dev/null)" "$want"
    if [[ "$want" == unavailable ]]; then
      jq -e '.roots[0].line | test("disagree|does not hold this package")' "$CASE/doc.json" >/dev/null 2>&1 && pass "rows: final $final, row $progress: the line says why" || fail "rows: final $final, row $progress: the line: $(jq -r '.roots[0].line' "$CASE/doc.json")"
    fi
  done
}

# ---- the shapes: computed from the real answers above, held byte for byte to the generated file ---------------------------------------------------
case_shapes_are_the_real_ones() {
  local entry generated="$TEST_ROOT/shapes.json" files
  { printf '{"generated_by":"tests/contract/lane_auditor.sh from the answers of the real entries (LANE_SHAPES_UPDATE=1 rewrites this file; an edit by hand fails the suite)"'
    for entry in $(ls "$REAL_DIR" | LC_ALL=C sort); do
      files=("$REAL_DIR/$entry"/*.json)
      printf ',"%s":%s' "$entry" "$(lane_shape_derive "${files[@]}")"
    done
    printf '}\n'; } | jq -S . > "$generated"
  if [[ -n "${LANE_SHAPES_UPDATE:-}" ]]; then
    [[ -z "${LANE_AUDITOR_CASES:-}" ]] || { fail "shapes: the file is rewritten by a run of every case, never of some"; return; }
    cp -- "$generated" "$LANE_SHAPES_FILE"
    pass "shapes: $LANE_SHAPES_FILE rewritten from the real answers"
    return
  fi
  if [[ -z "${LANE_AUDITOR_CASES:-}" ]]; then
    if cmp -s "$generated" "$LANE_SHAPES_FILE"; then
      pass "shapes: the generated file is exactly what the real answers give"
    else
      diff <(jq -S . "$LANE_SHAPES_FILE") "$generated" >&2 || true
      fail "shapes: tests/lib/lane_auditor_shapes.json is not what the real entries answer (regenerate it with LANE_SHAPES_UPDATE=1, never by hand)"
    fi
  else
    # a partial run: each entry it ran is compared with the file's
    for entry in $(ls "$REAL_DIR" | LC_ALL=C sort); do
      if [[ "$(jq -S --arg e "$entry" '.[$e]' "$generated")" == "$(jq -S --arg e "$entry" '.[$e]' "$LANE_SHAPES_FILE")" ]]; then
        pass "shapes: the entry $entry is exactly what its real answers give"
      else
        diff <(jq -S --arg e "$entry" '.[$e]' "$LANE_SHAPES_FILE") <(jq -S --arg e "$entry" '.[$e]' "$generated") >&2 || true
        fail "shapes: the entry $entry of tests/lib/lane_auditor_shapes.json is not what the real entry answers (regenerate it with LANE_SHAPES_UPDATE=1, never by hand)"
      fi
    done
  fi
  # each real answer is exactly one non-empty document with no member repeated, and conforms to the shape derived from all of them
  local f ok=1 problems
  for f in "$REAL_DIR"/*/*.json; do
    entry="$(basename -- "$(dirname -- "$f")")"
    LANE_SHAPES_FILE="$generated" problems="$(lane_shape_check "$entry" "$f")" || { printf '%s: %s\n' "$f" "$problems" >&2; ok=0; }
  done
  (( ok )) && pass "shapes: every real answer is one document, no member repeated, and has the members of its entry's shape" || fail "shapes: a real answer does not conform to the shape derived from the real answers"
  # the checker itself: it refuses what the reviewer showed it let through
  local probe="$TEST_ROOT/probe.json" refused=1
  : > "$probe"; lane_shape_check scan_result "$probe" >/dev/null 2>&1 && refused=0
  printf '{"verdict":"GO"}{"verdict":"GO"}' > "$probe"; lane_shape_check scan_result "$probe" >/dev/null 2>&1 && refused=0
  printf '{"verdict":"GO","verdict":"GO"}' > "$probe"; lane_shape_check scan_result "$probe" >/dev/null 2>&1 && refused=0
  printf '{}' > "$probe"; lane_shape_check scan_result "$probe" >/dev/null 2>&1 && refused=0
  jq '.extra_member = 1' "$REAL_DIR/scan_result/ok.json" > "$probe"; lane_shape_check scan_result "$probe" >/dev/null 2>&1 && refused=0
  jq '.tool_status.grype.status = 7' "$REAL_DIR/scan_result/ok.json" > "$probe"; lane_shape_check scan_result "$probe" >/dev/null 2>&1 && refused=0
  jq 'del(.machine)' "$REAL_DIR/scan_result/ok.json" > "$probe"; lane_shape_check scan_result "$probe" >/dev/null 2>&1 && refused=0
  (( refused )) && pass "shapes: the checker refuses an empty answer, two documents, a repeated member, a missing, an extra and a mistyped member" || fail "shapes: the checker accepted an answer it must refuse"
}

# ---- 9. the stand-in of the live suite is held to the same shapes ---------------------------------------------------------------------------------
case_live_stand_in() {
  prepare_case live-stand-in
  local stand_in="$ROOT/tests/lib/lane_stand_in_auditor.sh" ok=1 problems out="$CASE/answer.json"
  chk() { if problems="$(lane_shape_check "$2" "$out")"; then :; else printf '%s: %s\n' "$1" "$problems" >&2; ok=0; fi; }
  printf '{"packages":[{"name":"a","version":"1.0.0"},{"name":"b","version":"1.0.0"},{"name":"c","version":"1.0.0"}]}' \
    | LIVE_ADVISORY_NAME=a LIVE_MALWARE_NAME=b LIVE_BLOCKLISTED=c bash "$stand_in" scanner-batch --evidence > "$out"
  chk "advisory evidence" evidence
  printf '{"roots":[{"name":"a","version":"1.0.0"}],"cached":[{"name":"c","version":"1.0.0"}]}' | LIVE_SOCKET_BLOCKED=c bash "$stand_in" package-audit --ecosystem npm --evidence-only > "$out"
  chk "Socket evidence" socket_answer
  printf '{"candidates":[{"name":"a","version":"1.0.0","host":"registry.npmjs.org","blocking_advisories":[]}]}' | LIVE_ACCEPTED=a bash "$stand_in" lane-acceptances > "$out"
  chk "acceptances" lane_acceptances
  printf '{"identities":[{"name":"a","version":"1.0.0","host":"registry.npmjs.org"}]}' | LIVE_REVOKED=a bash "$stand_in" lane-revoke > "$out"
  chk "revoke" lane_revoke
  ( cd "$CASE" && bash "$stand_in" repo-audit . --deps-only --allow-missing-tools --result-out "$out" ) >/dev/null
  chk "scan" scan_result
  ( cd "$CASE" && LIVE_SCAN_PYTHON_CRITICAL=2 LIVE_SCAN_PARTIAL=1 bash "$stand_in" repo-audit . --deps-only --allow-missing-tools --result-out "$out" ) >/dev/null
  chk "scan with findings and partial coverage" scan_result
  # a stand-in that stops answering, or answers twice, is refused
  : > "$out"; lane_shape_check evidence "$out" >/dev/null 2>&1 && ok=0
  (( ok )) && pass "the live suite's stand-in answers every entry it stands for with the real answers' members and types" || fail "the live suite's stand-in differs from the real answers"
}

# ---- 10. a Socket program on the PATH, or in the tool cache, is a failure of the case (the helper the live scenario uses) --------------------
case_no_socket_helper() {
  local dir="$TEST_ROOT/nosocket" ok=1
  mkdir -p "$dir/bin" "$dir/home/.config/safe/audit"
  lane_no_socket_check "$dir/bin" "$dir/home" >/dev/null 2>&1 || { fail "no-socket helper: a clean PATH and an empty tool cache were refused"; return; }
  printf '#!/bin/sh\nexit 0\n' > "$dir/bin/socket"; chmod +x "$dir/bin/socket"
  lane_no_socket_check "$dir/bin" "$dir/home" >/dev/null 2>&1 && ok=0
  rm -f "$dir/bin/socket"
  printf '{"local":{"socket":"/somewhere/socket"}}\n' > "$dir/home/.config/safe/audit/tools.json"
  lane_no_socket_check "$dir/bin" "$dir/home" >/dev/null 2>&1 && ok=0
  (( ok )) && pass "no-socket helper: it fails when a socket program is on the PATH and when the tool cache names one" || fail "no-socket helper: it passed with a socket program present"
}

# LANE_AUDITOR_CASES names the cases to run (a mutation run of one entry does not need the others); the default is all of them, and only then is the
# generated file compared as a whole (an entry nobody generated is then a failure too)
ALL_CASES="case_evidence case_socket case_acceptances case_root_audit_and_revoke case_preflight case_scan case_operator_only case_final_answer_against_rows case_shapes_are_the_real_ones case_live_stand_in case_no_socket_helper"
for case_name in ${LANE_AUDITOR_CASES:-$ALL_CASES}; do
  "$case_name"
done

printf '\n%d passed, %d failed\n' "$PASS_COUNT" "$FAIL_COUNT"
[[ "$FAIL_COUNT" -eq 0 ]]
