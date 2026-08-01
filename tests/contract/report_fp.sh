#!/usr/bin/env bash
# `safe report-fp` — the agent's escalation path for a suspected false positive.
#
# The property that matters most here is a NEGATIVE one. This is the only
# command an agent runs *because* it disagrees with a verdict, so if filing a
# report could quiet the gate — write an allowlist entry, flip a verdict, touch
# install-known — then an agent that can file reports is an agent that can
# bypass. Every case below therefore also asserts that nothing changed.
#
# Hermetic: safe-audit is a stub whose payload each case chooses.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SAFE="$ROOT/bin/safe"

PASS_COUNT=0
FAIL_COUNT=0
pass() { printf 'ok - %s\n' "$*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { printf 'not ok - %s\n' "$*" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }

TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT

STUB_BIN="$TEST_ROOT/bin"
mkdir -p "$STUB_BIN"
cat > "$STUB_BIN/safe-audit" <<'STUB'
#!/usr/bin/env bash
# Records its argv, then emits whatever the case asked for.
printf '%s\n' "$*" >> "${STUB_ARGV_LOG}"
if [[ "${STUB_EMIT_GARBAGE:-0}" == "1" ]]; then
  printf 'not json at all\n'
  exit 1
fi
cat "${STUB_PAYLOAD}"
exit "${STUB_EXIT:-10}"
STUB
chmod +x "$STUB_BIN/safe-audit"

cat > "$TEST_ROOT/payload.json" <<'JSON'
{
  "spec": "happy-dom@20.11.1",
  "ecosystem": "npm",
  "verdict": "BLOCK",
  "resolution": {"status": "ok", "method": "dist-tag", "source": "https://registry.npmjs.org", "range": "latest"},
  "resolved_versions": ["20.11.1"],
  "warn_causes": ["osv_affecting"],
  "socket": {"status": "ok", "note": null},
  "osv": {
    "status": "ok",
    "vulns": [{"id": "GHSA-37j7-fg3j-429f"}, {"id": "GHSA-96g7-g7g9-jxw8"}],
    "classification": {
      "affecting": [
        {"id": "GHSA-37j7-fg3j-429f", "severity": "critical", "fixed": "20.0.0"},
        {"id": "GHSA-96g7-g7g9-jxw8", "severity": "high", "fixed": "15.10.2"}
      ],
      "remediated": [{"id": "GHSA-w4gp-fjgq-3q4g", "severity": "moderate", "fixed": "20.8.9"}]
    }
  }
}
JSON

# A fake safe checkout: report-fp writes into <repo>/inbox.
new_repo() {
  local repo="$TEST_ROOT/$1"
  mkdir -p "$repo/.git" "$repo/bin"
  printf '%s' "$repo"
}

run_report_fp() {
  local repo="$1"; shift
  STUB_ARGV_LOG="$TEST_ROOT/argv.log" \
  STUB_PAYLOAD="${STUB_PAYLOAD:-$TEST_ROOT/payload.json}" \
  STUB_EXIT="${STUB_EXIT:-104}" \
  STUB_EMIT_GARBAGE="${STUB_EMIT_GARBAGE:-0}" \
  SAFE_REPO_DIR="$repo" \
  SAFE_AUDIT_PATH="$STUB_BIN/safe-audit" \
  SAFE_CONFIG_DIR="$TEST_ROOT/config" \
  SAFE_DATA_DIR="$TEST_ROOT/data" \
    "$SAFE" report-fp "$@"
}

case_writes_a_note_with_the_evidence() {
  local repo; repo="$(new_repo repo-evidence)"
  local out
  out="$(run_report_fp "$repo" happy-dom --ecosystem npm --source claude-code 2>&1)" || {
    fail "$FUNCNAME (command failed: $out)"; return
  }
  local note="$repo/inbox/$(date +%F)-claude-code-fp-happy-dom.md"
  [[ -f "$note" ]] || { fail "$FUNCNAME (no note at $note)"; return; }

  # The four things the operator needs to adjudicate without re-running it.
  grep -Fq 'happy-dom' "$note" || { fail "$FUNCNAME (spec missing)"; return; }
  grep -Fq '20.11.1' "$note" || { fail "$FUNCNAME (resolved version missing)"; return; }
  grep -Fq 'GHSA-37j7-fg3j-429f' "$note" || { fail "$FUNCNAME (advisory id missing)"; return; }
  grep -Fq '20.0.0' "$note" || { fail "$FUNCNAME (fixed bound missing)"; return; }
  grep -Fq '104' "$note" || { fail "$FUNCNAME (exit code missing)"; return; }
  pass "$FUNCNAME"
}

case_changes_nothing() {
  # The load-bearing case: filing a report must not be a way to get allowed.
  local repo; repo="$(new_repo repo-inert)"
  rm -rf "$TEST_ROOT/config" "$TEST_ROOT/data"
  run_report_fp "$repo" happy-dom --ecosystem npm >/dev/null 2>&1 || true

  local stray=""
  for f in host-allow.json install-known.json sandbox-known.json blocklist.json; do
    [[ -e "$TEST_ROOT/config/run/$f" ]] && stray="${stray} $f"
    [[ -e "$TEST_ROOT/config/$f" ]] && stray="${stray} $f"
  done
  if [[ -n "$stray" ]]; then
    fail "$FUNCNAME (report-fp wrote trust state:${stray})"
    return
  fi

  # And it must not have asked safe-audit to apply a gate decision.
  if grep -Eq -- '--gate|host-allow|allow' "$TEST_ROOT/argv.log" 2>/dev/null; then
    fail "$FUNCNAME (report-fp invoked an allow path: $(cat "$TEST_ROOT/argv.log"))"
    return
  fi
  pass "$FUNCNAME"
}

case_note_states_that_nothing_was_applied() {
  # An operator skimming the note must not have to infer this.
  local repo; repo="$(new_repo repo-contract)"
  run_report_fp "$repo" happy-dom >/dev/null 2>&1 || true
  local note
  note="$(find "$repo/inbox" -name '*.md' | head -1)"
  if [[ -n "$note" ]] && grep -Fq 'Nothing was auto-applied' "$note"; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME"
  fi
}

case_same_day_collision_suffixes() {
  local repo; repo="$(new_repo repo-collision)"
  run_report_fp "$repo" happy-dom --source agent >/dev/null 2>&1 || true
  run_report_fp "$repo" happy-dom --source agent >/dev/null 2>&1 || true
  local count
  count="$(find "$repo/inbox" -name '*happy-dom*.md' | wc -l | tr -d ' ')"
  if [[ "$count" == "2" ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (expected 2 notes, got $count)"
  fi
}

case_scoped_spec_slug_is_filesystem_safe() {
  local repo; repo="$(new_repo repo-scoped)"
  run_report_fp "$repo" '@vue/test-utils@2.4.6' >/dev/null 2>&1 || true
  local note
  note="$(find "$repo/inbox" -name '*.md' | head -1)"
  if [[ -n "$note" && "$(basename "$note")" == *"vue-test-utils-2.4.6.md" ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (got ${note:-<none>})"
  fi
}

case_valid_but_wrong_shape_output_writes_nothing() {
  # `jq -e .` accepts the scalar `"not-an-object"`. The renderer then dies
  # indexing it — but the old code had already created the note, leaving a
  # truncated half-report that reads like adjudicable evidence and breaking the
  # "nothing was written" guarantee. Shape is validated before anything opens.
  local repo; repo="$(new_repo repo-wrongshape)"
  printf '"not-an-object"\n' > "$TEST_ROOT/scalar.json"
  local status=0
  STUB_PAYLOAD="$TEST_ROOT/scalar.json" run_report_fp "$repo" demo >/dev/null 2>"$TEST_ROOT/err-shape" || status=$?
  if (( status == 0 )); then
    fail "$FUNCNAME (exited 0 on a scalar payload)"
    return
  fi
  if [[ -n "$(find "$repo/inbox" -name '*.md' 2>/dev/null)" ]]; then
    fail "$FUNCNAME (wrote a partial note)"
    return
  fi
  grep -Fq 'nothing was written' "$TEST_ROOT/err-shape" || { fail "$FUNCNAME (no legible cause)"; return; }
  pass "$FUNCNAME"
}

case_dangling_symlink_at_the_note_path_is_not_followed() {
  # `-e` is false for a dangling symlink, so the old existence test walked past
  # one and `>` wrote THROUGH it — the note landed wherever the link pointed,
  # outside the inbox entirely. That turned an inert escalation into a
  # caller-selected write primitive.
  local repo; repo="$(new_repo repo-symlink)"
  mkdir -p "$repo/inbox" "$TEST_ROOT/elsewhere"
  local target="$TEST_ROOT/elsewhere/captured.md"
  ln -s "$target" "$repo/inbox/$(date +%F)-agent-fp-demo.md"
  run_report_fp "$repo" demo >/dev/null 2>&1 || true
  if [[ -e "$target" ]]; then
    fail "$FUNCNAME (wrote through the symlink to $target)"
    return
  fi
  # It must still succeed, into a suffixed path that is a real file.
  local written
  written="$(find "$repo/inbox" -name '*.md' -type f | head -1)"
  if [[ -n "$written" ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (no note written at all)"
  fi
}

case_socket_failure_text_is_not_copied_into_the_note() {
  # socket.note is raw stderr from a failed CLI or vault invocation and can
  # carry a token. The receipt keeps it; the inbox is a far broader surface.
  local repo; repo="$(new_repo repo-socket)"
  jq '.socket = {"status": "error", "note": "auth failed: token sk-SECRET-DO-NOT-LEAK rejected"}' \
    < "$TEST_ROOT/payload.json" > "$TEST_ROOT/socket-fail.json"
  STUB_PAYLOAD="$TEST_ROOT/socket-fail.json" run_report_fp "$repo" demo >/dev/null 2>&1 || true
  local note
  note="$(find "$repo/inbox" -name '*.md' -type f | head -1)"
  [[ -n "$note" ]] || { fail "$FUNCNAME (no note)"; return; }
  if grep -Fq 'sk-SECRET-DO-NOT-LEAK' "$note"; then
    fail "$FUNCNAME (secret-like socket text reached the note)"
    return
  fi
  grep -Fq 'in the receipt, not here' "$note" || { fail "$FUNCNAME (no pointer to the receipt)"; return; }
  pass "$FUNCNAME"
}

case_unreadable_check_output_writes_nothing() {
  # Half a report is worse than none: it would look like adjudicable evidence.
  local repo; repo="$(new_repo repo-garbage)"
  local status=0
  STUB_EMIT_GARBAGE=1 run_report_fp "$repo" happy-dom >/dev/null 2>"$TEST_ROOT/err" || status=$?
  if (( status == 0 )); then
    fail "$FUNCNAME (exited 0 on unreadable check output)"
    return
  fi
  if [[ -d "$repo/inbox" ]] && [[ -n "$(find "$repo/inbox" -name '*.md' 2>/dev/null)" ]]; then
    fail "$FUNCNAME (wrote a note anyway)"
    return
  fi
  grep -Fq 'no readable JSON' "$TEST_ROOT/err" || { fail "$FUNCNAME (no legible cause)"; return; }
  pass "$FUNCNAME"
}

case_hundredth_note_is_allowed() {
  # The first bounded loop incremented before comparing and refused the 100th
  # note while announcing a bound of 100. The retry IS the existence check now,
  # so the last attempt is a real one.
  local repo; repo="$(new_repo repo-boundary)"
  mkdir -p "$repo/inbox"
  local d; d="$(date +%F)"
  : > "$repo/inbox/${d}-agent-fp-demo.md"
  local i
  for ((i = 2; i <= 99; i++)); do : > "$repo/inbox/${d}-agent-fp-demo-${i}.md"; done
  run_report_fp "$repo" demo >/dev/null 2>&1 || { fail "$FUNCNAME (100th note refused)"; return; }
  if [[ -s "$repo/inbox/${d}-agent-fp-demo-100.md" ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (no 100th note written)"
  fi
}

case_exhausted_names_leave_no_note_and_no_temp() {
  # The failure path AFTER the body is rendered: the publish must claim nothing
  # and clean up after itself. The previous design leaked its temp here and, on
  # a copy failure, left a zero-byte note behind as well.
  local repo; repo="$(new_repo repo-exhausted)"
  mkdir -p "$repo/inbox"
  local d; d="$(date +%F)"
  : > "$repo/inbox/${d}-agent-fp-demo.md"
  local i
  for ((i = 2; i <= 100; i++)); do : > "$repo/inbox/${d}-agent-fp-demo-${i}.md"; done
  local status=0
  run_report_fp "$repo" demo >/dev/null 2>"$TEST_ROOT/err-exhaust" || status=$?
  if (( status == 0 )); then
    fail "$FUNCNAME (reported success with no filename claimed)"
    return
  fi
  grep -Fq 'nothing was written' "$TEST_ROOT/err-exhaust" || { fail "$FUNCNAME (no legible cause)"; return; }
  if [[ -n "$(find "$repo/inbox" -name '.report-fp.*' 2>/dev/null)" ]]; then
    fail "$FUNCNAME (temp file leaked into the inbox)"
    return
  fi
  # Every pre-existing note is still empty: nothing was overwritten.
  if [[ -s "$repo/inbox/${d}-agent-fp-demo.md" ]]; then
    fail "$FUNCNAME (clobbered an existing note)"
    return
  fi
  pass "$FUNCNAME"
}

case_success_leaves_no_temp_behind() {
  local repo; repo="$(new_repo repo-clean)"
  run_report_fp "$repo" happy-dom >/dev/null 2>&1 || { fail "$FUNCNAME (command failed)"; return; }
  if [[ -n "$(find "$repo/inbox" -name '.report-fp.*' 2>/dev/null)" ]]; then
    fail "$FUNCNAME (temp file left in the inbox)"
  else
    pass "$FUNCNAME"
  fi
}

case_missing_repo_refuses_legibly() {
  local status=0
  STUB_ARGV_LOG="$TEST_ROOT/argv.log" STUB_PAYLOAD="$TEST_ROOT/payload.json" \
  SAFE_REPO_DIR="$TEST_ROOT/does-not-exist" \
  SAFE_AUDIT_PATH="$STUB_BIN/safe-audit" HOME="$TEST_ROOT/nohome" \
    "$SAFE" report-fp happy-dom >/dev/null 2>"$TEST_ROOT/err3" || status=$?
  if (( status != 0 )) && grep -Fq 'nothing was written' "$TEST_ROOT/err3"; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (status $status)"
  fi
}

case_no_spec_is_a_usage_error() {
  local status=0
  "$SAFE" report-fp >/dev/null 2>&1 || status=$?
  if (( status == 2 )); then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (status $status, expected 2)"
  fi
}

case_writes_a_note_with_the_evidence
case_changes_nothing
case_note_states_that_nothing_was_applied
case_same_day_collision_suffixes
case_scoped_spec_slug_is_filesystem_safe
case_valid_but_wrong_shape_output_writes_nothing
case_dangling_symlink_at_the_note_path_is_not_followed
case_socket_failure_text_is_not_copied_into_the_note
case_unreadable_check_output_writes_nothing
case_hundredth_note_is_allowed
case_exhausted_names_leave_no_note_and_no_temp
case_success_leaves_no_temp_behind
case_missing_repo_refuses_legibly
case_no_spec_is_a_usage_error

printf '\n%d passed, %d failed\n' "$PASS_COUNT" "$FAIL_COUNT"
[[ "$FAIL_COUNT" -eq 0 ]]
