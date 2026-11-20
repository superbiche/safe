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
LOCAL_MACHINE=local
SENTINEL_TOKEN="sentinel-socket-token-7f3a91"

prepare_case() {
  CASE="$TEST_ROOT/$1"
  CASE_RUN_CONFIG="$CASE/run"; CASE_AUDIT_CONFIG="$CASE/audit"; CASE_DATA="$CASE/data"; CASE_CACHE="$CASE/cache"; CASE_HOME="$CASE/home"
  CASE_LOG="$CASE/socket.log"
  mkdir -p "$CASE_RUN_CONFIG" "$CASE_AUDIT_CONFIG" "$CASE_DATA" "$CASE_HOME"
  printf '{"install":{"cooldown_days":%s,"socket":{"mode":"%s","cache_ttl_days":7}}}\n' "${CD:-0}" "${SMODE:-always}" > "$CASE_RUN_CONFIG/config.json"
  printf '{"packages":{}}\n' > "$CASE_RUN_CONFIG/blocked.json"
  : > "$CASE_LOG"
  # the operator's tool configuration names the Socket tool (the evidence-only reading never consults PATH for it)
  printf '{"%s":{"socket":"%s/socket"}}\n' "$LOCAL_MACHINE" "$MOCKBIN" > "$CASE_AUDIT_CONFIG/tools.json"
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

# --- 3. it decides and writes nothing, from a COLD start --------------------------------------------------------------
# The listing is of every file, directory and link under the home, data, configuration and cache trees, with size, mode
# and the modification time to the nanosecond: a touch, a created directory or a stored cache entry all change it. It is
# taken before the first run of the case (cold state: nothing warmed up) and after.
tree() {
  local d
  for d in "$CASE_HOME" "$CASE_DATA" "$CASE_AUDIT_CONFIG" "$CASE_RUN_CONFIG" "$CASE_CACHE"; do
    [[ -e "$d" || -L "$d" ]] || { printf 'ABSENT %s\n' "$d"; continue; }
    find "$d" -exec stat -c '%n|%F|%s|%a|%y' {} + 2>/dev/null
  done | sort
}
cold_unchanged() { # <label> <mode> <stdin|-> <audit args...>
  local label="$1" mode="$2" input="$3"; shift 3
  local before after
  before="$(tree)"
  audit "$mode" "$input" "$@"
  after="$(tree)"
  if [[ "$before" == "$after" ]]; then pass "cold state, $label: nothing was created, touched or stored"; else fail "cold state, $label: $(diff <(printf '%s\n' "$before") <(printf '%s\n' "$after") | head -8)"; fi
}
for mode in clean low malware rate auth-leaky; do
  prepare_case "cold-$mode"
  cold_unchanged "Socket outcome $mode" "$mode" - fixture@1.0.0 --ecosystem npm --evidence-only
done
SMODE=auto prepare_case cold-consent
cold_unchanged "a consent ask" clean - fixture@1.0.0 --ecosystem npm --evidence-only MOCK_RELEASE_FRESH=1
prepare_case cold-batch
printf '{"roots":[{"name":"fixture","version":"1.0.0"}],"cached":[{"name":"fixture","version":"1.0.0"},{"name":"other","version":"1.0.0"}]}' > "$CASE/in.json"
cold_unchanged "the batch (roots and cache)" clean "$CASE/in.json" --ecosystem npm --evidence-only
# the private branch: a private scope gets a read-only outcome and the private decision (an audit-log event) is not run
prepare_case cold-private
"$SAFE_CORE_BIN" private-trust registry-add --policy "$CASE_RUN_CONFIG/private-registries.json" --id p-npm --ecosystem npm \
  --origin https://git.example.test:8443/api/packages/owner/npm/ --namespace '@p/*' >/dev/null
cold_unchanged "a private identity" clean - @p/fixture@1.0.0 --ecosystem npm --evidence-only
if [[ "$(jq -r '.outcome' <<<"$OUT" 2>/dev/null)" == unavailable && "$(jq -r '.line' <<<"$OUT" 2>/dev/null)" == *"private-origin"* && "$(calls)" == 0 ]]; then pass 'a private identity is reported unavailable (never clear), with no Socket call'; else fail "private identity: $OUT"; fi
# the control: the ordinary audit of the same package DOES write (so the listing is able to see a write)
prepare_case cold-control
before="$(tree)"; audit clean - fixture@1.0.0 --ecosystem npm
[[ "$(tree)" != "$before" ]] && pass 'control: the ordinary audit writes state on the same cold start' || fail 'control: the ordinary audit wrote nothing, so the listing proves nothing'
prepare_case cold-control-private
"$SAFE_CORE_BIN" private-trust registry-add --policy "$CASE_RUN_CONFIG/private-registries.json" --id p-npm --ecosystem npm \
  --origin https://git.example.test:8443/api/packages/owner/npm/ --namespace '@p/*' >/dev/null
before="$(tree)"; audit clean - @p/fixture@1.0.0 --ecosystem npm --gate install
[[ "$(tree)" != "$before" ]] && pass 'control: the private decision of the ordinary audit writes (an audit-log event)' || fail 'control: the private decision wrote nothing'
# the return point precedes every write of package_audit_command
emit_line="$(awk '/^package_audit_command\(\) \{/{f=1} f && /package_audit_evidence_emit "\$PKG_NAME"/{n++; if (n==2) {print NR; exit}}' "$SAFE_AUDIT")"
first_write="$(awk '/^package_audit_command\(\) \{/{f=1} f && /result_json=|mark_install_known|record_local_install_approval|record_followed|write_check|save_receipt/{print NR; exit}' "$SAFE_AUDIT")"
if [[ -n "$emit_line" && -n "$first_write" && "$emit_line" -lt "$first_write" ]]; then pass "the evidence emit (line $emit_line) comes before the first write (line $first_write)"; else fail "the evidence emit ($emit_line) is not before the first write ($first_write)"; fi
prepare_case no-gate
audit clean - fixture@1.0.0 --ecosystem npm --evidence-only --gate install
[[ "$RC" != 0 ]] && pass '--evidence-only refuses --gate (it decides nothing)' || fail '--evidence-only accepted --gate'

# --- 3b. the Socket tool is the operator's configured one, never the first on PATH ---------------------------------------
FAKE="$TEST_ROOT/fakebin"; mkdir -p "$FAKE"
printf '#!/usr/bin/env bash\nprintf '"'"'{"ok":true,"data":{"self":{"score":{"overall":95},"alerts":[{"name":"malware","severity":"critical","category":"supplyChainRisk","example":"npm/fixture@1.0.0"}]},"transitively":{"dependencyCount":0,"alerts":[],"score":{"overall":100}}}}\\n'"'"'\n' > "$FAKE/socket"
chmod +x "$FAKE/socket"
prepare_case tool-config
audit clean - fixture@1.0.0 --ecosystem npm --evidence-only PATH="$FAKE:$MOCKBIN:/usr/bin:/bin"
[[ "$(jq -r .outcome <<<"$OUT")" == clear ]] && pass 'a fake socket first on PATH does not answer for Socket (the configured tool does)' || fail "PATH socket answered: $OUT"
prepare_case tool-none
rm -f "$CASE_AUDIT_CONFIG/tools.json"
audit clean - fixture@1.0.0 --ecosystem npm --evidence-only PATH="$FAKE:$MOCKBIN:/usr/bin:/bin"
[[ "$(jq -r .outcome <<<"$OUT")" == unavailable && "$(calls)" == 0 ]] && pass 'with no tool configured the caller PATH is not consulted: Socket is unavailable (102 on the lane), never clear' || fail "no tool configured: $OUT"
prepare_case tool-standard-dir
rm -f "$CASE_AUDIT_CONFIG/tools.json"; mkdir -p "$CASE_HOME/.local/bin"; ln -s "$MOCKBIN/socket" "$CASE_HOME/.local/bin/socket"
audit clean - fixture@1.0.0 --ecosystem npm --evidence-only PATH="$FAKE:/usr/bin:/bin:$MOCKBIN"
[[ "$(jq -r .outcome <<<"$OUT")" == clear ]] && pass 'with no tool configured the standard install directories are searched' || fail "standard dir: $OUT"
prepare_case tool-bare-name
printf '{"%s":{"socket":"socket"}}\n' "$LOCAL_MACHINE" > "$CASE_AUDIT_CONFIG/tools.json"
audit clean - fixture@1.0.0 --ecosystem npm --evidence-only PATH="$FAKE:/usr/bin:/bin:$MOCKBIN"
[[ "$(jq -r .outcome <<<"$OUT")" == unavailable ]] && pass 'a configured bare name (a PATH lookup) names no tool' || fail "bare name: $OUT"

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

# --- 4b. the cache alone: every block that can be established is kept, whatever else fails ------------------------------
seed() { # <mode> <name> : the ordinary audit stores the entry the evidence-only reading later replays
  audit "$1" - "$2@1.0.0" --ecosystem npm
}
cache_read() { # <extra env...>: the cache-only request for fixture, other, never-seen
  printf '{"roots":[],"cached":[{"name":"fixture","version":"1.0.0"},{"name":"other","version":"1.0.0"},{"name":"never-seen","version":"1.0.0"}]}' > "$CASE/in.json"
  : > "$CASE_LOG"
  audit clean "$CASE/in.json" --ecosystem npm --evidence-only "$@"
}
blocks_of() { jq -c '[.cached_blocks[] | "\(.name)@\(.version)"]' <<<"$OUT"; }
prepare_case cache-only
seed malware fixture; seed clean other
cache_read
if [[ "$RC" == 0 && "$(blocks_of)" == '["fixture@1.0.0"]' && "$(jq -r .cache_gap <<<"$OUT")" == "" && "$(calls)" == 0 ]]; then pass 'the cache is read with no call: only the cached blocking result is reported, no gap'; else fail "cache only: rc=$RC calls=$(calls) $OUT"; fi
# through a symbolic link to the cache directory
ln -s "$CASE_CACHE" "$CASE/cache-link"
cache_read SAFE_AUDIT_SOCKET_CACHE_DIR="$CASE/cache-link"
[[ "$(blocks_of)" == '["fixture@1.0.0"]' && "$(jq -r .cache_gap <<<"$OUT")" == "" ]] && pass 'the block is kept through a linked cache directory' || fail "linked directory: $OUT"
# an unrelated broken entry beside the valid one costs nothing
printf 'not json' > "$CASE_CACHE/0000000000000000000000000000000000000000000000000000000000000000.json"
cache_read
[[ "$(blocks_of)" == '["fixture@1.0.0"]' && "$(jq -r .cache_gap <<<"$OUT")" == "" ]] && pass 'an unrelated broken entry does not discard the block' || fail "unrelated broken entry: $OUT"
# a broken entry AT a requested key is a gap, and the valid block is still kept
other_entry="$(grep -l '"name": *"other"\|"name":"other"' "$CASE_CACHE"/*.json 2>/dev/null | head -n1)"
: > "$other_entry"
cache_read
[[ "$(blocks_of)" == '["fixture@1.0.0"]' && "$(jq -r .cache_gap <<<"$OUT")" != "" ]] && pass 'a requested entry that cannot be read is a gap, and the block already read is kept' || fail "broken requested entry: $OUT"
# a regular file where the cache directory belongs: a gap, never an empty cache
prepare_case cache-file
: > "$CASE/cachefile"
cache_read SAFE_AUDIT_SOCKET_CACHE_DIR="$CASE/cachefile"
[[ "$(blocks_of)" == '[]' && "$(jq -r .cache_gap <<<"$OUT")" != "" ]] && pass 'a regular file in the cache directory'"'"'s place is a gap' || fail "file as directory: $OUT"
# an absent cache is nothing cached, not a gap
prepare_case cache-absent
cache_read
[[ "$(blocks_of)" == '[]' && "$(jq -r .cache_gap <<<"$OUT")" == "" && "$(calls)" == 0 ]] && pass 'an absent cache directory is nothing cached, with no call' || fail "absent cache: $OUT"
# an entry dated in the future is not valid: a gap, no block
prepare_case cache-future
seed malware fixture
entry="$(ls "$CASE_CACHE"/*.json | head -n1)"
jq -c --argjson t "$(( $(date +%s) + 86400 ))" '.fetched_at = $t' "$entry" > "$entry.new" && mv "$entry.new" "$entry"
cache_read
[[ "$(blocks_of)" == '[]' && "$(jq -r .cache_gap <<<"$OUT")" != "" ]] && pass 'an entry dated in the future is not valid (a gap, no block)' || fail "future entry: $OUT"
# an expired entry gives no verdict and is not a failure
prepare_case cache-expired
seed malware fixture
entry="$(ls "$CASE_CACHE"/*.json | head -n1)"
jq -c --argjson t "$(( $(date +%s) - 40 * 86400 ))" '.fetched_at = $t' "$entry" > "$entry.new" && mv "$entry.new" "$entry"
cache_read
[[ "$(blocks_of)" == '[]' && "$(jq -r .cache_gap <<<"$OUT")" == "" ]] && pass 'an expired entry gives no verdict and no gap' || fail "expired entry: $OUT"

# --- 4c. the batch refuses a terminal instead of waiting on it --------------------------------------------------------------
prepare_case tty-stdin
set +e
timeout 20 python3 -I -c '
import os, pty, sys
env = dict(os.environ)
status = pty.spawn([sys.argv[1], "package-audit", "--ecosystem", "npm", "--evidence-only"])
sys.exit(os.waitstatus_to_exitcode(status))' "$SAFE_AUDIT" >/dev/null 2>&1
tty_rc=$?
set -e
[[ "$tty_rc" != 0 && "$tty_rc" != 124 ]] && pass 'the batch refuses a terminal as its input (it does not wait)' || fail "terminal input: rc=$tty_rc"

# --- 5. the token never appears: the mock REFLECTS it, in an error and in a field of a valid success answer ---------------
MARKER="marker-$RANDOM-not-a-credential"
reflected="$(SOCKET_SECURITY_API_TOKEN="$MARKER" MOCK_SOCKET_MODE=reflect-error "$MOCKBIN/socket" score npm fixture@1.0.0 --json 2>/dev/null || true)"
[[ "$reflected" == *"$MARKER"* ]] \
  && pass 'the error mock reflects the marker (the check below can fail)' || fail 'the error mock does not reflect the marker'
reflected="$(SOCKET_SECURITY_API_TOKEN="$MARKER" MOCK_SOCKET_MODE=reflect-success "$MOCKBIN/socket" score npm fixture@1.0.0 --json 2>/dev/null || true)"
[[ "$reflected" == *"$MARKER"* ]] \
  && pass 'the success mock reflects the marker in an extra field' || fail 'the success mock does not reflect the marker'
for mode in reflect-error reflect-success; do
  prepare_case "token-$mode"
  printf '{"roots":[{"name":"fixture","version":"1.0.0"}],"cached":[{"name":"fixture","version":"1.0.0"}]}' > "$CASE/in.json"
  audit "$mode" "$CASE/in.json" --ecosystem npm --evidence-only SOCKET_SECURITY_API_TOKEN="$MARKER"
  if grep -rqF "$MARKER" "$CASE" "$TMPDIR" 2>/dev/null || grep -qF "$MARKER" <<<"$OUT$ERRTXT"; then fail "$mode: the marker reached an output, a log or a file"; else pass "$mode: the marker is in no output, log or file"; fi
  [[ -z "$(find "$CASE_CACHE" -type f 2>/dev/null)" ]] && pass "$mode: nothing was stored in the cache" || fail "$mode: the cache holds a file"
done


# --- 6. an inaccessible cache path is a gap; only a path shown to be absent is absent ------------------------------------
if [[ "$(id -u)" != 0 ]]; then
  prepare_case cache-unsearchable
  mkdir -p "$CASE/locked/cache"
  chmod 000 "$CASE/locked"
  cache_read SAFE_AUDIT_SOCKET_CACHE_DIR="$CASE/locked/cache"
  chmod 755 "$CASE/locked"
  [[ "$(blocks_of)" == '[]' && "$(jq -r .cache_gap <<<"$OUT")" != "" ]] && pass 'a cache under a directory that cannot be searched is a gap, not an absent cache' || fail "unsearchable parent: $OUT"
  prepare_case cache-parent-is-a-file
  : > "$CASE/afile"
  cache_read SAFE_AUDIT_SOCKET_CACHE_DIR="$CASE/afile/cache"
  [[ "$(jq -r .cache_gap <<<"$OUT")" != "" ]] && pass 'a cache under a component that is not a directory is a gap' || fail "component is a file: $OUT"
else
  pass 'unsearchable parent: skipped as root'
fi

# --- 7. the mode is set by the parsed flag only: the environment cannot reach the ordinary audit ---------------------------
for value in 0 1 "" yes; do
  prepare_case "inherited-$value"
  audit clean - fixture@1.0.0 --ecosystem npm EVIDENCE_ONLY_RUN="$value" EVIDENCE_PROGRESS_FILE="$CASE/progress"
  inherited_rc="$RC"; inherited_out="$OUT"
  prepare_case "inherited-control-$value"
  audit clean - fixture@1.0.0 --ecosystem npm
  if [[ "$inherited_rc" == "$RC" && "$RC" == 0 && "$inherited_out" == "$OUT" && ! -e "$TEST_ROOT/inherited-$value/progress" ]]; then pass "EVIDENCE_ONLY_RUN='$value' in the environment changes nothing of the ordinary cold audit (exit $RC, same output)"; else fail "EVIDENCE_ONLY_RUN='$value': exit $inherited_rc vs $RC"; fi
done
prepare_case inherited-flag-as-value
audit clean - fixture@1.0.0 --ecosystem npm --registry --evidence-only
[[ "$(ls "$CASE_AUDIT_CONFIG" "$CASE_DATA" 2>/dev/null | grep -c .)" != 0 || "$RC" != 0 ]] && pass 'the flag text as the VALUE of another option is not the flag (the ordinary start-up ran)' || fail 'the flag text as a value switched the mode on'

# --- 8. the credential helper is the operator's, never the caller's PATH ---------------------------------------------------
prepare_case helper-path
mkdir -p "$CASE_HOME/.config/setup-new-machines/bw-env.d" "$TEST_ROOT/helperbin"
printf 'SOCKET_SECURITY_API_TOKEN=x\n' > "$CASE_HOME/.config/setup-new-machines/bw-env.d/socket.env"
printf '#!/usr/bin/env bash\nprintf ran >> "%s/helper.ran"\nshift 3\nexec "$@"\n' "$CASE" > "$TEST_ROOT/helperbin/bw-env-run"; chmod +x "$TEST_ROOT/helperbin/bw-env-run"
audit clean - fixture@1.0.0 --ecosystem npm --evidence-only PATH="$TEST_ROOT/helperbin:$MOCKBIN:/usr/bin:/bin"
if [[ "$(jq -r .outcome <<<"$OUT")" == unavailable && ! -e "$CASE/helper.ran" && "$(calls)" == 0 ]]; then pass 'a credential helper first on PATH is not run; the reading is unavailable'; else fail "helper on PATH: $OUT"; fi
prepare_case helper-operator
mkdir -p "$CASE_HOME/.config/setup-new-machines/bw-env.d" "$CASE_HOME/.local/bin"
printf 'SOCKET_SECURITY_API_TOKEN=x\n' > "$CASE_HOME/.config/setup-new-machines/bw-env.d/socket.env"
printf '#!/usr/bin/env bash\nprintf ran >> "%s/helper.ran"\nshift 3\nexec "$@"\n' "$CASE" > "$CASE_HOME/.local/bin/bw-env-run"; chmod +x "$CASE_HOME/.local/bin/bw-env-run"
audit clean - fixture@1.0.0 --ecosystem npm --evidence-only
if [[ "$(jq -r .outcome <<<"$OUT")" == clear && -e "$CASE/helper.ran" ]]; then pass 'the helper in the operator'"'"'s locations is the one used'; else fail "operator helper: $OUT"; fi

# --- 9. the lane's call: bounded, owned scratch, completed results survive -----------------------------------------------
# shellcheck source=lib/gate-lib.sh
( . "$ROOT/lib/gate-lib.sh"; declare -F safe_gate_project_lane_socket_call >/dev/null ) && pass 'the lane helpers load' || fail 'the lane helpers do not load'
lane_call() { # <mode> <request-json> <deadline> <extra env...> ; sets CALL_RC, CALL_OUT, CALL_PROGRESS, CALL_DIR, CALL_TMP
  local mode="$1" request="$2" deadline="$3"; shift 3
  prepare_case "call-$RANDOM"
  CALL_DIR="$CASE/lane-scratch"; CALL_TMP="$CASE/auditor-tmp"; mkdir -p "$CALL_DIR" "$CALL_TMP"
  printf '%s' "$request" > "$CASE/req.json"; : > "$CALL_DIR/progress"
  CALL_RC=0
  ( . "$ROOT/lib/gate-lib.sh"
    export HOME="$CASE_HOME" PATH="$MOCKBIN:/usr/bin:/bin" SAFE_AUDIT_CONFIG_DIR="$CASE_AUDIT_CONFIG" SAFE_AUDIT_DATA_DIR="$CASE_DATA/audit" \
      SAFE_RUN_CONFIG_DIR="$CASE_RUN_CONFIG" SAFE_AUDIT_SOCKET_CACHE_DIR="$CASE_CACHE" MOCK_SOCKET_LOG="$CASE_LOG" MOCK_SOCKET_MODE="$mode" \
      SAFE_RUN_TRUST_OVERRIDE=1 TMPDIR="$CALL_TMP" "$@"
    safe_gate_project_lane_socket_call "$SAFE_AUDIT" "$SAFE_CORE_BIN" "$CASE/req.json" "$CASE/out.json" "$deadline" "$CALL_DIR" "$CALL_DIR/progress" ) || CALL_RC=$?
}
two_roots='{"roots":[{"name":"fixture","version":"1.0.0"},{"name":"other","version":"1.0.0"}],"cached":[]}'
lane_call pending '{"roots":[{"name":"fixture","version":"1.0.0"}],"cached":[]}' 2 MOCK_RELEASE_FRESH=1
[[ "$CALL_RC" == 124 ]] && pass 'a stalled reader is ended by its deadline (124)' || fail "deadline: rc=$CALL_RC"
[[ -z "$(ls -A "$CALL_DIR" | grep -v '^progress$')" && -z "$(ls -A "$CALL_TMP")" ]] && pass 'the call'"'"'s private directory and the temporary directory hold nothing afterwards' || fail "scratch left behind: $(ls -A "$CALL_DIR" "$CALL_TMP")"
lane_call reflect-then-stall "$two_roots" 4 SOCKET_SECURITY_API_TOKEN="$MARKER" MOCK_SOCKET_STALL_NAME=fixture
if [[ "$CALL_RC" == 124 ]] && ! grep -rqF "$MARKER" "$CASE" "$CALL_TMP" 2>/dev/null && [[ -z "$(ls -A "$CALL_TMP")" ]]; then pass 'the reflected marker is on no file after a deadline'; else fail "marker after a deadline (rc=$CALL_RC)"; fi
# no deadline utility: the reader is not started
NOTIMEOUT="$TEST_ROOT/no-timeout-bin"; mkdir -p "$NOTIMEOUT"
for b in /usr/bin/* /bin/*; do [[ -e "$NOTIMEOUT/${b##*/}" ]] || ln -s "$b" "$NOTIMEOUT/${b##*/}" 2>/dev/null || true; done
rm -f "$NOTIMEOUT/timeout"
prepare_case no-timeout-utility
printf '%s' "$two_roots" > "$CASE/req.json"
rc=0; ( . "$ROOT/lib/gate-lib.sh"; PATH="$NOTIMEOUT" safe_gate_project_lane_socket_call "$SAFE_AUDIT" "$SAFE_CORE_BIN" "$CASE/req.json" "$CASE/out.json" 5 "$CASE" ) || rc=$?
[[ "$rc" == 126 && ! -e "$CASE/out.json" && "$(calls)" == 0 ]] && pass 'with no deadline utility the reader is not started (126), no call is made' || fail "no timeout utility: rc=$rc"
# completed results survive a later root's stall: the block read first is kept, the unfinished root is unavailable
lane_call malware "$two_roots" 12 MOCK_SOCKET_STALL_NAME=other
if [[ "$CALL_RC" == 124 ]]; then
  printf '%s' "$two_roots" > "$CASE/req.json"
  ( . "$ROOT/lib/gate-lib.sh"; printf '[]' > "$CASE/untied.json"
    safe_gate_project_lane_socket_roots_doc "$CASE/req.json" "$CASE/out.json" "$CASE/doc.json" "the Socket evidence reader ran out of time" "$CALL_DIR/progress" "$CASE/untied.json" "$SAFE_CORE_BIN" )
  [[ "$(jq -r '[.roots[] | "\(.name)=\(.outcome)"] | join(",")' "$CASE/doc.json")" == "fixture=blocked,other=unavailable" ]] && pass 'a block classified before a later root stalls survives; only the unfinished root is unavailable' || fail "progress: $(cat "$CASE/doc.json") / $(cat "$CALL_DIR/progress")"
else
  fail "stall after a block: rc=$CALL_RC"
fi

printf '\n%d passed, %d failed\n' "$PASS_COUNT" "$FAIL_COUNT"
[[ "$FAIL_COUNT" -eq 0 ]]
