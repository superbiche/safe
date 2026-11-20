#!/usr/bin/env bash
# `package-audit --evidence-only`: the Socket facts of a named root for the project lane (ticket 1636). Fully offline:
# the Socket CLI and OSV are the mocks of tests/lib/socket-mockbin (the same as socket_tier.sh's). Proves, with the REAL
# auditor: each outcome is the exit today's install gate takes for the same Socket result, the mode asks nothing, decides
# nothing and writes nothing, the batch is one process and the cache is read with no call.

set -euo pipefail

# SAFE_TEST_ISOLATION_MARKER: every suite owns a scratch HOME and safe state.
# shellcheck source=tests/lib/test-isolation.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/test-isolation.sh"
safe_test_setup_isolation || exit 1
export SAFE_RUN_TRUST_OVERRIDE=1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SAFE_AUDIT="$ROOT/bin/safe-audit"
PASS_COUNT=0
FAIL_COUNT=0
pass() { printf 'ok - %s\n' "$*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { printf 'not ok - %s\n' "$*" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }

TEST_ROOT="$(mktemp -d)"
safe_test_compose_exit_trap "rm -rf \"\$TEST_ROOT\""
. "$ROOT/tests/lib/safe-core.sh"
safe_core_test_prepare "$ROOT" "$TEST_ROOT/safe-core" || exit 1
MOCKBIN="$ROOT/tests/lib/socket-mockbin"
SENTINEL_TOKEN="sentinel-socket-token-7f3a91"

prepare_case() {
  CASE="$TEST_ROOT/$1"
  CASE_RUN_CONFIG="$CASE/run"; CASE_AUDIT_CONFIG="$CASE/audit"; CASE_DATA="$CASE/data"; CASE_CACHE="$CASE/cache"; CASE_HOME="$CASE/home"
  CASE_LOG="$CASE/socket.log"
  mkdir -p "$CASE_RUN_CONFIG" "$CASE_AUDIT_CONFIG" "$CASE_DATA" "$CASE_HOME"
  printf '{"install":{"cooldown_days":%s,"socket":{"mode":"%s","cache_ttl_days":7}}}\n' "${CD:-0}" "${SMODE:-always}" > "$CASE_RUN_CONFIG/config.json"
  printf '{"packages":{}}\n' > "$CASE_RUN_CONFIG/blocked.json"
  : > "$CASE_LOG"
}

# audit <mode> <stdin-file|-> <args...> [VAR=val ...]: the auditor, closed stdin unless a file is given; sets OUT, ERRTXT, RC.
audit() {
  local mode="$1" input="$2"; shift 2
  local -a args=() extra=()
  while (( $# > 0 )); do if [[ "$1" == *=* && "$1" =~ ^[A-Z_]+= ]]; then extra+=("$1"); else args+=("$1"); fi; shift; done
  [[ "$input" != - ]] || input=/dev/null
  set +e
  OUT="$(env -u SOCKET_SECURITY_API_TOKEN HOME="$CASE_HOME" PATH="$MOCKBIN:/usr/bin:/bin" SAFE_AUDIT_CONFIG_DIR="$CASE_AUDIT_CONFIG" \
    SAFE_AUDIT_DATA_DIR="$CASE_DATA/audit" SAFE_RUN_CONFIG_DIR="$CASE_RUN_CONFIG" SAFE_AUDIT_SOCKET_CACHE_DIR="$CASE_CACHE" \
    MOCK_SOCKET_LOG="$CASE_LOG" MOCK_SOCKET_MODE="$mode" SAFE_AUDIT_SOCKET_TIMEOUT=1 "${extra[@]}" \
    "$SAFE_AUDIT" package-audit "${args[@]}" <"$input" 2>"$CASE/err.txt")"
  RC=$?
  set -e
  ERRTXT="$(cat "$CASE/err.txt")"
}
calls() { wc -l < "$CASE_LOG" | tr -d '[:space:]'; }
# every file the auditor may leave, outside Socket's own result cache, with its digest
state() { find "$CASE_HOME" "$CASE_DATA" "$CASE_AUDIT_CONFIG" "$CASE_RUN_CONFIG" -type f 2>/dev/null | sort | xargs -r sha256sum; }

# --- 1. every outcome is the exit today's install gate takes for the same Socket result ----------------------------------
row() { # <label> <mock mode> <fresh 0|1> <want outcome> <want exit> [VAR=val ...]
  local label="$1" mode="$2" fresh="$3" want_outcome="$4" want_exit="$5"; shift 5
  prepare_case "row-$label"
  audit "$mode" - fixture@1.0.0 --ecosystem npm --evidence-only MOCK_RELEASE_FRESH="$fresh" "$@"
  local got_outcome got_exit
  got_outcome="$(jq -r '.outcome' <<<"$OUT" 2>/dev/null || true)"; got_exit="$(jq -r '.gate_exit' <<<"$OUT" 2>/dev/null || true)"
  if [[ "$RC" == 0 && "$got_outcome" == "$want_outcome" && "$got_exit" == "$want_exit" ]]; then pass "$label: outcome $want_outcome, gate exit $want_exit"; else fail "$label: got rc=$RC outcome=$got_outcome exit=$got_exit (want $want_outcome/$want_exit)"; fi
  # today's gate, same environment, same Socket result: the exit is the one the evidence reports
  prepare_case "gate-$label"
  audit "$mode" - fixture@1.0.0 --ecosystem npm --gate install --op install MOCK_RELEASE_FRESH="$fresh" "$@"
  if [[ "$RC" == "$want_exit" ]]; then pass "$label: today's gate exits $RC for the same result"; else fail "$label: today's gate exits $RC, the evidence says $want_exit"; fi
}
row clean clean 0 clear 0
row low-score low 0 adverse 10
row high-alert high 0 adverse 10
row critical-cve critical-cve 0 adverse 10
row unmapped-critical unknown-category 0 adverse 10
row not-found not-found 0 adverse 10
row malware malware 0 blocked 20
row rate-limited rate 0 rate_limited 12
row auth-failure auth-leaky 0 unavailable 11
row unreachable other 0 unavailable 11
SMODE=auto row consent-needed clean 1 consent_required 13
SMODE=auto row consent-granted clean 1 clear 0 SAFE_AUDIT_SOCKET_CONSENT=granted
CD=3 row pending pending 1 pending 14 SAFE_AUDIT_SOCKET_FRESH_SCAN_TIMEOUT=1 MOCK_COOLDOWN_FIX=1

# --- 2. it asks nothing: closed stdin, a consent ask is a FACT and no call is spent ----------------------------------------
SMODE=auto prepare_case no-prompt
SMODE=auto audit clean - fixture@1.0.0 --ecosystem npm --evidence-only MOCK_RELEASE_FRESH=1
if [[ "$(jq -r .outcome <<<"$OUT")" == consent_required && "$(calls)" == 0 ]]; then pass 'a consent ask is reported as consent_required, with no Socket call'; else fail "a consent ask: $OUT ($(calls) calls)"; fi

# --- 3. it decides and writes nothing -----------------------------------------------------------------------------------
# the startup-only set: what any run of the auditor leaves (its machine and tool registries, the host-allow log), taken from a
# run that stops at its input check; an evidence-only run must leave exactly that
for mode in clean low malware rate; do
  prepare_case "writes-nothing-$mode"
  audit "$mode" - --ecosystem npm --evidence-only || true
  before="$(state)"
  audit "$mode" - fixture@1.0.0 --ecosystem npm --evidence-only
  [[ "$(state)" == "$before" ]] && pass "$mode: no check file, receipt, install-known, consent, grant or export was written" || fail "$mode: files changed: $(diff <(printf '%s\n' "$before") <(state))"
done
# the control: the same audit WITHOUT the mode does write (so the comparison above can fail)
prepare_case writes-control; before="$(state)"
audit clean - fixture@1.0.0 --ecosystem npm
[[ "$(state)" != "$before" ]] && pass 'control: the ordinary audit of the same package writes state (the listing is able to see a write)' || fail 'control: the ordinary audit wrote nothing, so the listing proves nothing'
# the return point precedes every write of package_audit_command
emit_line="$(awk '/^package_audit_command\(\) \{/{f=1} f && /package_audit_evidence_emit "\$PKG_NAME"/{print NR; exit}' "$SAFE_AUDIT")"
first_write="$(awk '/^package_audit_command\(\) \{/{f=1} f && /result_json=|mark_install_known|record_local_install_approval|record_followed|write_check|save_receipt/{print NR; exit}' "$SAFE_AUDIT")"
if [[ -n "$emit_line" && -n "$first_write" && "$emit_line" -lt "$first_write" ]]; then pass "the evidence emit (line $emit_line) comes before the first write (line $first_write)"; else fail "the evidence emit ($emit_line) is not before the first write ($first_write)"; fi
# it decides nothing: --gate and the mode do not combine, and the mode never reaches the gate's allow policy
prepare_case no-gate
audit clean - fixture@1.0.0 --ecosystem npm --evidence-only --gate install
[[ "$RC" != 0 ]] && pass '--evidence-only refuses --gate (it decides nothing)' || fail '--evidence-only accepted --gate'

# --- 4. the batch: one process, every root, the cache read with no call --------------------------------------------------
prepare_case batch
printf '{"roots":[{"name":"fixture","version":"1.0.0"},{"name":"other","version":"1.0.0"},{"name":"third","version":"1.0.0"}],"cached":[]}' > "$CASE/in.json"
audit clean "$CASE/in.json" --ecosystem npm --evidence-only
if [[ "$RC" == 0 && "$(jq -r '[.roots[].name] | join(",")' <<<"$OUT")" == "fixture,other,third" && "$(jq -r '[.roots[].outcome] | unique | join(",")' <<<"$OUT")" == clear && "$(calls)" == 3 ]]; then pass 'one invocation scores every root (one Socket call each)'; else fail "batch: rc=$RC calls=$(calls) $OUT"; fi
# the batch runs every root in THIS process: it never starts another safe-audit
body="$(sed -n '/^package_audit_evidence_batch() {/,/^}/p' "$SAFE_AUDIT")"
if grep -qE '"\$0"|BASH_SOURCE|safe-audit|SAFE_AUDIT_BIN|exec ' <<<"$body"; then fail 'the batch starts another process of the auditor'; else pass 'the batch starts no other audit process (it calls package_audit_command in-process)'; fi
# a root whose score cannot be fetched is reported unavailable and does not stop the others
prepare_case batch-one-fails
printf '{"roots":[{"name":"fixture","version":"1.0.0"},{"name":"other","version":"1.0.0"}],"cached":[]}' > "$CASE/in.json"
audit clean "$CASE/in.json" --ecosystem npm --evidence-only MOCK_SOCKET_FAIL_NAME=other
[[ "$(jq -r '[.roots[] | "\(.name)=\(.outcome)"] | join(",")' <<<"$OUT")" == "fixture=clear,other=unavailable" ]] && pass 'a root whose score cannot be fetched is unavailable (never clear) and the others are still read' || fail "batch one fails: $OUT"
# the input must be whole
prepare_case batch-bad-input
printf '{"roots":[{"name":"fixture"}],"cached":[]}' > "$CASE/in.json"
audit clean "$CASE/in.json" --ecosystem npm --evidence-only
[[ "$RC" != 0 ]] && pass 'a malformed request is refused' || fail 'a malformed request was read'

# the cache alone: a blocking result already cached is reported, a clean or absent one is not, and no call is made
prepare_case cache-only
audit malware - fixture@1.0.0 --ecosystem npm --evidence-only
audit clean - other@1.0.0 --ecosystem npm --evidence-only
: > "$CASE_LOG"
printf '{"roots":[],"cached":[{"name":"fixture","version":"1.0.0"},{"name":"other","version":"1.0.0"},{"name":"never-seen","version":"1.0.0"}]}' > "$CASE/in.json"
audit malware "$CASE/in.json" --ecosystem npm --evidence-only
if [[ "$RC" == 0 && "$(jq -c '[.cached_blocks[] | "\(.name)@\(.version)"]' <<<"$OUT")" == '["fixture@1.0.0"]' && "$(jq -r .cache_gap <<<"$OUT")" == "" && "$(calls)" == 0 ]]; then pass 'the cache is read with no call: only the cached blocking result is reported'; else fail "cache only: rc=$RC calls=$(calls) $OUT"; fi
prepare_case cache-empty
printf '{"roots":[],"cached":[{"name":"fixture","version":"1.0.0"}]}' > "$CASE/in.json"
audit malware "$CASE/in.json" --ecosystem npm --evidence-only
[[ "$(jq -c .cached_blocks <<<"$OUT")" == '[]' && "$(calls)" == 0 ]] && pass 'an empty cache is no block and costs no call' || fail "empty cache: $OUT"

# --- 5. the token never appears -----------------------------------------------------------------------------------------
prepare_case token
printf '{"roots":[{"name":"fixture","version":"1.0.0"}],"cached":[{"name":"fixture","version":"1.0.0"}]}' > "$CASE/in.json"
audit auth-leaky "$CASE/in.json" --ecosystem npm --evidence-only SOCKET_SECURITY_API_TOKEN="$SENTINEL_TOKEN"
if grep -rqF "$SENTINEL_TOKEN" "$CASE" 2>/dev/null || grep -qF "$SENTINEL_TOKEN" <<<"$OUT$ERRTXT"; then fail 'the Socket token reached an output, a cache or a file'; else pass 'the Socket token appears in no output, cache or file'; fi

printf '\n%d passed, %d failed\n' "$PASS_COUNT" "$FAIL_COUNT"
[[ "$FAIL_COUNT" -eq 0 ]]
