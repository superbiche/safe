#!/usr/bin/env bash
# Scan cache suite: a --deps-only scan whose dependency evidence is unchanged
# replays the recorded result instead of re-running scanners. Hermetic — every
# scanner is a logging stub on PATH, so "did the scanners run again?" is a
# direct assertion on the invocation log, not a timing guess.
#
# The cache may only ever SKIP work. Every doubt (corrupt entry, missing or
# malformed timestamp, expired TTL, unhashable evidence) must fall through to a
# real scan, so those paths are asserted here too.

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
mkdir -p "$MOCKBIN"

# Every scanner logs its invocation and emits the minimal valid document the
# scan pipeline expects on stdout.
for tool in osv-scanner grype syft govulncheck cargo-audit pip-audit socket; do
  cat > "$MOCKBIN/$tool" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$(basename -- "$0")" >> "${SCANNER_LOG:-/dev/null}"
# Lets a case mutate the dependency evidence WHILE the scanners are running,
# which is the window between key derivation and cache store.
[[ -n "${MUTATE_TARGET:-}" && -f "${MUTATE_TARGET:-}" ]] && printf '\n' >> "$MUTATE_TARGET"
case "$(basename -- "$0")" in
  osv-scanner) printf '{"results":[]}\n' ;;
  grype)       printf '{"matches":[]}\n' ;;
  syft)        printf '{"components":[],"metadata":{"tools":[{"name":"syft"}]}}\n' ;;
  *)           printf '{}\n' ;;
esac
exit 0
STUB
  chmod +x "$MOCKBIN/$tool"
done

CASE_DIR=""
CASE_HOME=""
CASE_PROJECT=""
SCANNER_LOG=""
OUT_FILE=""

prepare_case() {
  local name="$1"
  CASE_DIR="$TEST_ROOT/case-$name"
  CASE_HOME="$CASE_DIR/home"
  CASE_PROJECT="$CASE_DIR/project"
  SCANNER_LOG="$CASE_DIR/scanners.log"
  OUT_FILE="$CASE_DIR/scan.out"
  mkdir -p "$CASE_HOME" "$CASE_PROJECT" "$CASE_DIR/audit-config" "$CASE_DIR/audit-data"
  : > "$SCANNER_LOG"
  printf '{"name":"demo","version":"1.0.0"}\n' > "$CASE_PROJECT/package.json"
  printf '{"lockfileVersion":3,"packages":{}}\n' > "$CASE_PROJECT/package-lock.json"
}

# run_scan [scan flags...]
run_scan() {
  : > "$SCANNER_LOG"
  set +e
  (
    cd "$CASE_PROJECT" || exit 99
    env \
      HOME="$CASE_HOME" \
      PATH="$MOCKBIN:/usr/bin:/bin" \
      SCANNER_LOG="$SCANNER_LOG" \
      MUTATE_TARGET="${MUTATE_TARGET:-}" \
      SAFE_AUDIT_SCAN_CACHE_TTL_SECONDS="${SAFE_AUDIT_SCAN_CACHE_TTL_SECONDS:-86400}" \
      SAFE_AUDIT_CONFIG_DIR="$CASE_DIR/audit-config" \
      SAFE_AUDIT_DATA_DIR="$CASE_DIR/audit-data" \
      "$SAFE_AUDIT" scan --deps-only --project . "$@"
  ) > "$OUT_FILE" 2>&1
  STATUS=$?
  set -e
}

run_scan_source_mode() {
  : > "$SCANNER_LOG"
  set +e
  (
    cd "$CASE_PROJECT" || exit 99
    env \
      HOME="$CASE_HOME" \
      PATH="$MOCKBIN:/usr/bin:/bin" \
      SCANNER_LOG="$SCANNER_LOG" \
      MUTATE_TARGET="${MUTATE_TARGET:-}" \
      SAFE_AUDIT_SCAN_CACHE_TTL_SECONDS="${SAFE_AUDIT_SCAN_CACHE_TTL_SECONDS:-86400}" \
      SAFE_AUDIT_CONFIG_DIR="$CASE_DIR/audit-config" \
      SAFE_AUDIT_DATA_DIR="$CASE_DIR/audit-data" \
      "$SAFE_AUDIT" scan --project .
  ) > "$OUT_FILE" 2>&1
  STATUS=$?
  set -e
}

scanner_invocations() {
  wc -l < "$SCANNER_LOG" | tr -d ' '
}

cache_entries() {
  find "$CASE_DIR/audit-data/scan-cache" -maxdepth 1 -name '*.json' 2>/dev/null | wc -l | tr -d ' '
}

assert_hit() {
  local label="$1"
  if ! grep -Fq 'scan cache hit' "$OUT_FILE"; then
    printf 'expected a cache hit; output:\n%s\n' "$(cat "$OUT_FILE")" >&2
    fail "$label"
    return 1
  fi
  return 0
}

assert_no_hit() {
  local label="$1"
  if grep -Fq 'scan cache hit' "$OUT_FILE"; then
    printf 'unexpected cache hit; output:\n%s\n' "$(cat "$OUT_FILE")" >&2
    fail "$label"
    return 1
  fi
  return 0
}

assert_scanners_ran() {
  local label="$1"
  if [[ "$(scanner_invocations)" -eq 0 ]]; then
    printf 'expected scanner invocations, log is empty\n' >&2
    fail "$label"
    return 1
  fi
  return 0
}

assert_no_scanners() {
  local label="$1"
  if [[ "$(scanner_invocations)" -ne 0 ]]; then
    printf 'expected no scanner invocations, got:\n%s\n' "$(cat "$SCANNER_LOG")" >&2
    fail "$label"
    return 1
  fi
  return 0
}

assert_verdict_rendered() {
  local label="$1"
  if ! grep -Fq 'VERDICT:' "$OUT_FILE"; then
    printf 'cached replay did not render a verdict; output:\n%s\n' "$(cat "$OUT_FILE")" >&2
    fail "$label"
    return 1
  fi
  return 0
}

cache_entry_path() {
  find "$CASE_DIR/audit-data/scan-cache" -maxdepth 1 -name '*.json' | head -n 1
}

case_cold_scan_runs_scanners_and_caches() {
  prepare_case "cold-scan"
  run_scan
  [[ "$STATUS" -eq 0 ]] || { printf 'scan exited %s\n%s\n' "$STATUS" "$(cat "$OUT_FILE")" >&2; fail "$FUNCNAME"; return; }
  assert_no_hit "$FUNCNAME" || return
  assert_scanners_ran "$FUNCNAME" || return
  [[ "$(cache_entries)" -eq 1 ]] || { printf 'expected 1 cache entry, got %s\n' "$(cache_entries)" >&2; fail "$FUNCNAME"; return; }
  pass "$FUNCNAME"
}

case_unchanged_evidence_hits_cache_without_scanners() {
  prepare_case "cache-hit"
  run_scan
  assert_scanners_ran "$FUNCNAME" || return
  local cold_verdict
  cold_verdict="$(grep -E '^VERDICT:' "$OUT_FILE" | head -n 1)"

  run_scan
  [[ "$STATUS" -eq 0 ]] || { printf 'cached scan exited %s\n' "$STATUS" >&2; fail "$FUNCNAME"; return; }
  assert_hit "$FUNCNAME" || return
  # The whole point: the scanners are not re-run.
  assert_no_scanners "$FUNCNAME" || return
  assert_verdict_rendered "$FUNCNAME" || return
  # And the replayed verdict is the recorded one, not a fresh guess.
  [[ "$(grep -E '^VERDICT:' "$OUT_FILE" | head -n 1)" == "$cold_verdict" ]] || { fail "$FUNCNAME"; return; }
  pass "$FUNCNAME"
}

case_lockfile_change_invalidates() {
  prepare_case "invalidate"
  run_scan
  assert_scanners_ran "$FUNCNAME" || return
  run_scan
  assert_hit "$FUNCNAME" || return

  printf '{"lockfileVersion":3,"packages":{"node_modules/x":{"version":"1.0.0"}}}\n' > "$CASE_PROJECT/package-lock.json"
  run_scan
  assert_no_hit "$FUNCNAME" || return
  assert_scanners_ran "$FUNCNAME" || return
  [[ "$(cache_entries)" -eq 2 ]] || { printf 'expected 2 cache entries, got %s\n' "$(cache_entries)" >&2; fail "$FUNCNAME"; return; }

  # The new evidence caches in its own right.
  run_scan
  assert_hit "$FUNCNAME" || return
  assert_no_scanners "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_manifest_change_invalidates() {
  prepare_case "invalidate-manifest"
  run_scan
  run_scan
  assert_hit "$FUNCNAME" || return
  # Manifests are evidence too, not just lockfiles.
  printf '{"name":"demo","version":"1.0.1","dependencies":{"left-pad":"^1.3.0"}}\n' > "$CASE_PROJECT/package.json"
  run_scan
  assert_no_hit "$FUNCNAME" || return
  assert_scanners_ran "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_no_cache_flag_bypasses() {
  prepare_case "no-cache-flag"
  run_scan
  run_scan
  assert_hit "$FUNCNAME" || return

  run_scan --no-cache
  assert_no_hit "$FUNCNAME" || return
  assert_scanners_ran "$FUNCNAME" || return

  # --no-cache bypasses the read; the following plain scan still hits.
  run_scan
  assert_hit "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_source_mode_is_never_cached() {
  prepare_case "source-mode"
  run_scan_source_mode
  assert_no_hit "$FUNCNAME" || return
  [[ "$(cache_entries)" -eq 0 ]] || { printf 'source scan wrote a cache entry\n' >&2; fail "$FUNCNAME"; return; }
  run_scan_source_mode
  assert_no_hit "$FUNCNAME" || return
  assert_scanners_ran "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_expired_entry_falls_through() {
  prepare_case "expired"
  run_scan
  run_scan
  assert_hit "$FUNCNAME" || return

  # Backdate the entry past the 24h TTL.
  local entry tmp
  entry="$(cache_entry_path)"
  [[ -n "$entry" ]] || { fail "$FUNCNAME"; return; }
  tmp="$entry.tmp"
  jq --argjson t "$(( $(date +%s) - 90000 ))" '._cache.created_epoch = $t' "$entry" > "$tmp"
  mv "$tmp" "$entry"

  run_scan
  assert_no_hit "$FUNCNAME" || return
  assert_scanners_ran "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_corrupt_entry_falls_through() {
  prepare_case "corrupt"
  run_scan
  run_scan
  assert_hit "$FUNCNAME" || return

  local entry
  entry="$(cache_entry_path)"
  printf 'not json at all\n' > "$entry"
  run_scan
  assert_no_hit "$FUNCNAME" || return
  assert_scanners_ran "$FUNCNAME" || return
  [[ "$STATUS" -eq 0 ]] || { printf 'corrupt cache broke the scan (exit %s)\n' "$STATUS" >&2; fail "$FUNCNAME"; return; }

  # A structurally valid entry that is not a scan result is refused too.
  run_scan
  entry="$(cache_entry_path)"
  printf '{"_cache":{"created_epoch":%s},"unrelated":true}\n' "$(date +%s)" > "$entry"
  run_scan
  assert_no_hit "$FUNCNAME" || return
  assert_scanners_ran "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_missing_timestamp_falls_through() {
  prepare_case "no-timestamp"
  run_scan
  local entry tmp
  entry="$(cache_entry_path)"
  tmp="$entry.tmp"
  jq 'del(._cache.created_epoch)' "$entry" > "$tmp"
  mv "$tmp" "$entry"
  run_scan
  assert_no_hit "$FUNCNAME" || return
  assert_scanners_ran "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_no_evidence_is_not_cacheable() {
  prepare_case "no-evidence"
  rm -f "$CASE_PROJECT/package.json" "$CASE_PROJECT/package-lock.json"
  printf 'nothing to see\n' > "$CASE_PROJECT/README.md"
  run_scan
  [[ "$(cache_entries)" -eq 0 ]] || { printf 'cached a scan with no dependency evidence\n' >&2; fail "$FUNCNAME"; return; }
  run_scan
  assert_no_hit "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# --------------------------------------------------------------------------
# An entry is only replayable for the request that produced it, from a safe
# that computes verdicts the same way. Everything else is a miss — never an
# error, and never someone else's verdict.
# --------------------------------------------------------------------------

# edit_entry <jq program>
edit_entry() {
  local entry tmp
  entry="$(cache_entry_path)"
  [[ -n "$entry" ]] || return 1
  tmp="$entry.tmp"
  jq "$1" "$entry" > "$tmp" && mv "$tmp" "$entry"
}

# assert_miss_after_edit <label> <jq program>
assert_miss_after_edit() {
  local label="$1" program="$2"
  edit_entry "$program" || { printf 'no cache entry to edit\n' >&2; fail "$label"; return 1; }
  run_scan
  # Exit status matters as much as the miss: a cache problem that aborts the
  # scan reads to a PATH wrapper as "scan failed", and the wrapper's
  # non-critical-failure branch then lets the install proceed unscanned.
  [[ "$STATUS" -eq 0 ]] || { printf 'scan exited %s after cache edit\n%s\n' "$STATUS" "$(cat "$OUT_FILE")" >&2; fail "$label"; return 1; }
  assert_no_hit "$label" || return 1
  assert_scanners_ran "$label" || return 1
  return 0
}

case_foreign_envelope_falls_through() {
  prepare_case "foreign-envelope"
  run_scan
  run_scan
  assert_hit "$FUNCNAME" || return

  # A full, fresh, structurally perfect document that answers a DIFFERENT
  # question: same file, wrong key.
  assert_miss_after_edit "$FUNCNAME" '._cache.key = "wrong-key"' || return
  run_scan
  assert_hit "$FUNCNAME" || return
  assert_miss_after_edit "$FUNCNAME" '._cache.target = "/somewhere/else"' || return
  run_scan
  assert_hit "$FUNCNAME" || return
  assert_miss_after_edit "$FUNCNAME" '._cache.machine = "other-host"' || return
  run_scan
  assert_hit "$FUNCNAME" || return
  assert_miss_after_edit "$FUNCNAME" '._cache.mode = "full"' || return
  pass "$FUNCNAME"
}

case_schema_drift_falls_through() {
  prepare_case "schema-drift"
  run_scan
  run_scan
  assert_hit "$FUNCNAME" || return
  # An entry written by a safe that scored verdicts differently.
  assert_miss_after_edit "$FUNCNAME" '._cache.schema = 0' || return
  run_scan
  assert_hit "$FUNCNAME" || return
  assert_miss_after_edit "$FUNCNAME" 'del(._cache.schema)' || return
  pass "$FUNCNAME"
}

case_malformed_timestamp_falls_through() {
  prepare_case "bad-timestamp"
  run_scan
  run_scan
  assert_hit "$FUNCNAME" || return
  # "08" is not a bash number in arithmetic context: read carelessly it aborts
  # the scan instead of missing the cache.
  assert_miss_after_edit "$FUNCNAME" '._cache.created_epoch = "08"' || return
  run_scan
  assert_hit "$FUNCNAME" || return
  assert_miss_after_edit "$FUNCNAME" '._cache.created_epoch = "not-a-time"' || return
  run_scan
  assert_hit "$FUNCNAME" || return
  # A timestamp from the future is a broken clock, not a fresh entry.
  assert_miss_after_edit "$FUNCNAME" '._cache.created_epoch = (now + 86400 | floor)' || return
  pass "$FUNCNAME"
}

case_invalid_verdict_falls_through() {
  prepare_case "bad-verdict"
  run_scan
  run_scan
  assert_hit "$FUNCNAME" || return
  assert_miss_after_edit "$FUNCNAME" '.verdict = "MAYBE"' || return
  run_scan
  assert_hit "$FUNCNAME" || return
  assert_miss_after_edit "$FUNCNAME" '.cve_scan.critical = "0"' || return
  run_scan
  assert_hit "$FUNCNAME" || return
  assert_miss_after_edit "$FUNCNAME" 'del(.audit_totals)' || return
  pass "$FUNCNAME"
}

case_invalid_ttl_disables_cache() {
  prepare_case "bad-ttl"
  SAFE_AUDIT_SCAN_CACHE_TTL_SECONDS="abc" run_scan
  [[ "$STATUS" -eq 0 ]] || { printf 'bad TTL broke the scan (exit %s)\n' "$STATUS" >&2; fail "$FUNCNAME"; return; }
  [[ "$(cache_entries)" -eq 0 ]] || { printf 'stored an entry under an unusable TTL\n' >&2; fail "$FUNCNAME"; return; }
  SAFE_AUDIT_SCAN_CACHE_TTL_SECONDS="abc" run_scan
  assert_no_hit "$FUNCNAME" || return
  assert_scanners_ran "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_evidence_changed_during_scan_is_not_cached() {
  prepare_case "evidence-race"
  # The scanners mutate the lockfile while they run: the result describes
  # bytes that are no longer on disk, so it must not be filed under the key
  # those bytes produced.
  MUTATE_TARGET="$CASE_PROJECT/package-lock.json" run_scan
  [[ "$STATUS" -eq 0 ]] || { printf 'scan exited %s\n' "$STATUS" >&2; fail "$FUNCNAME"; return; }
  [[ "$(cache_entries)" -eq 0 ]] || { printf 'cached a result whose evidence changed mid-scan\n' >&2; fail "$FUNCNAME"; return; }

  # Once the evidence settles, the next scan caches normally.
  run_scan
  [[ "$(cache_entries)" -eq 1 ]] || { printf 'expected 1 entry after a settled scan, got %s\n' "$(cache_entries)" >&2; fail "$FUNCNAME"; return; }
  pass "$FUNCNAME"
}

case_source_reading_scanner_is_not_cached() {
  prepare_case "govulncheck"
  # govulncheck reads ./... — Go source the evidence hash does not cover — so
  # a Go project's result is never replayable.
  rm -f "$CASE_PROJECT/package.json" "$CASE_PROJECT/package-lock.json"
  printf 'module demo\n\ngo 1.22\n' > "$CASE_PROJECT/go.mod"
  printf 'package main\n\nfunc main() {}\n' > "$CASE_PROJECT/main.go"
  run_scan
  [[ "$STATUS" -eq 0 ]] || { printf 'scan exited %s\n%s\n' "$STATUS" "$(cat "$OUT_FILE")" >&2; fail "$FUNCNAME"; return; }
  grep -Fq 'govulncheck' "$SCANNER_LOG" || { printf 'govulncheck never ran; nothing was proven\n%s\n' "$(cat "$SCANNER_LOG")" >&2; fail "$FUNCNAME"; return; }
  [[ "$(cache_entries)" -eq 0 ]] || { printf 'cached a result that read Go source\n' >&2; fail "$FUNCNAME"; return; }
  run_scan
  assert_no_hit "$FUNCNAME" || return
  assert_scanners_ran "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_result_out_hands_back_a_private_copy() {
  prepare_case "result-out"
  local out="$CASE_DIR/result-copy.json"
  run_scan --result-out "$out"
  [[ -s "$out" ]] || { printf '--result-out wrote nothing\n' >&2; fail "$FUNCNAME"; return; }
  jq -e '(.verdict | type) == "string" and ((.audit_totals.critical | type) == "number")' "$out" >/dev/null || {
    printf '--result-out copy is not a result document:\n%s\n' "$(cat "$out")" >&2; fail "$FUNCNAME"; return; }

  # A replay must hand back the same copy, or a caller that decides from the
  # file would be reading a stale one from an earlier run.
  local replayed="$CASE_DIR/result-copy-2.json"
  run_scan --result-out "$replayed"
  assert_hit "$FUNCNAME" || return
  [[ -s "$replayed" ]] || { printf 'cache replay did not honor --result-out\n' >&2; fail "$FUNCNAME"; return; }
  [[ "$(jq -r '.verdict' "$replayed")" == "$(jq -r '.verdict' "$out")" ]] || { fail "$FUNCNAME"; return; }

  # A destination that cannot receive the result is refused BEFORE any
  # scanning happens — proven by the scanner log staying empty, not by the
  # exit code alone.
  : > "$SCANNER_LOG"
  run_scan --result-out "$CASE_DIR/nope/deeper/result.json"
  [[ "$STATUS" -ne 0 ]] || { printf 'unwritable --result-out did not fail\n' >&2; fail "$FUNCNAME"; return; }
  assert_no_scanners "$FUNCNAME" || return

  # A directory would otherwise become "a file created inside it", and the
  # caller would read a path that is still a directory.
  : > "$SCANNER_LOG"
  mkdir -p "$CASE_DIR/adir"
  run_scan --result-out "$CASE_DIR/adir"
  [[ "$STATUS" -ne 0 ]] || { printf 'a directory was accepted as --result-out\n' >&2; fail "$FUNCNAME"; return; }
  [[ -d "$CASE_DIR/adir" ]] || { fail "$FUNCNAME"; return; }
  [[ -z "$(find "$CASE_DIR/adir" -mindepth 1 2>/dev/null)" ]] || { printf 'wrote into the directory instead of refusing\n' >&2; fail "$FUNCNAME"; return; }
  assert_no_scanners "$FUNCNAME" || return
  pass "$FUNCNAME"
}

# derive_key <logical target> <staging root>
# Calls the key function directly: staging-path independence is a property of
# the key, not something a local scan can express (its root IS its target).
derive_key() {
  local target="$1" root="$2"
  SA="$SAFE_AUDIT" TARGET="$target" ROOT="$root" SAFE_AUDIT_NO_INIT=1 bash -c '
    set -euo pipefail
    source "$SA" help >/dev/null 2>&1
    scan_cache_key local "$TARGET" deps "$ROOT" "$ROOT/package.json" "$ROOT/package-lock.json"
  ' 2>/dev/null
}

case_key_is_independent_of_the_staging_directory() {
  prepare_case "staging-independence"
  # A remote scan stages the target into a fresh mktemp directory every run.
  # If the absolute staging path entered the key, two scans of an unchanged
  # remote target would never hit — exactly where a hit is worth most.
  local a="$CASE_DIR/stage-a" b="$CASE_DIR/stage-b"
  mkdir -p "$a" "$b"
  printf '{"name":"demo","version":"1.0.0"}\n' | tee "$a/package.json" > "$b/package.json"
  printf '{"lockfileVersion":3,"packages":{}}\n' | tee "$a/package-lock.json" > "$b/package-lock.json"

  local key_a key_b key_other
  key_a="$(derive_key "/remote/project" "$a")"
  key_b="$(derive_key "/remote/project" "$b")"
  key_other="$(derive_key "/a/different/project" "$b")"

  [[ -n "$key_a" && "$key_a" == "$key_b" ]] || { printf 'staging path leaked into the key: %s vs %s\n' "$key_a" "$key_b" >&2; fail "$FUNCNAME"; return; }
  # The logical target still separates projects.
  [[ "$key_a" != "$key_other" ]] || { printf 'different targets produced the same key\n' >&2; fail "$FUNCNAME"; return; }

  # Content still decides: change a byte, get a different key.
  printf '{"lockfileVersion":3,"packages":{"x":{}}}\n' > "$b/package-lock.json"
  local key_changed
  key_changed="$(derive_key "/remote/project" "$b")"
  [[ "$key_changed" != "$key_a" ]] || { printf 'content change did not change the key\n' >&2; fail "$FUNCNAME"; return; }
  pass "$FUNCNAME"
}

case_unhashed_evidence_blocks_caching() {
  prepare_case "hidden-evidence"
  run_scan
  [[ "$(cache_entries)" -eq 1 ]] || { printf 'baseline did not cache\n' >&2; fail "$FUNCNAME"; return; }

  # A lockfile that discovery cannot see (it walks regular files only) is
  # still read by npm audit. Evidence we did not hash means no caching.
  local elsewhere="$CASE_DIR/elsewhere-lock.json"
  printf '{"lockfileVersion":3,"packages":{}}\n' > "$elsewhere"
  ln -s "$elsewhere" "$CASE_PROJECT/npm-shrinkwrap.json"
  rm -f "$CASE_DIR/audit-data/scan-cache"/*.json
  run_scan
  [[ "$(cache_entries)" -eq 0 ]] || { printf 'cached a project holding evidence that was never hashed\n' >&2; fail "$FUNCNAME"; return; }
  run_scan
  assert_no_hit "$FUNCNAME" || return
  assert_scanners_ran "$FUNCNAME" || return
  pass "$FUNCNAME"
}

case_ecosystem_audit_counts_reach_the_totals() {
  prepare_case "audit-totals"
  run_scan
  local entry
  entry="$(cache_entry_path)"
  [[ -n "$entry" ]] || { fail "$FUNCNAME"; return; }
  # audit_totals is the aggregate gating consumers read: it must exist and
  # never sit below the CVE-scan counts it contains.
  jq -e '
    (.audit_totals | type) == "object"
    and (.audit_totals.critical >= .cve_scan.critical)
    and (.audit_totals.high >= .cve_scan.high)
  ' "$entry" >/dev/null || { printf 'audit_totals missing or below cve_scan:\n%s\n' "$(jq -c '{audit_totals, cve_scan: {critical: .cve_scan.critical, high: .cve_scan.high}}' "$entry")" >&2; fail "$FUNCNAME"; return; }
  pass "$FUNCNAME"
}

main() {
  local case
  for case in \
    case_cold_scan_runs_scanners_and_caches \
    case_unchanged_evidence_hits_cache_without_scanners \
    case_lockfile_change_invalidates \
    case_manifest_change_invalidates \
    case_no_cache_flag_bypasses \
    case_source_mode_is_never_cached \
    case_expired_entry_falls_through \
    case_corrupt_entry_falls_through \
    case_missing_timestamp_falls_through \
    case_no_evidence_is_not_cacheable \
    case_foreign_envelope_falls_through \
    case_schema_drift_falls_through \
    case_malformed_timestamp_falls_through \
    case_invalid_verdict_falls_through \
    case_invalid_ttl_disables_cache \
    case_evidence_changed_during_scan_is_not_cached \
    case_source_reading_scanner_is_not_cached \
    case_result_out_hands_back_a_private_copy \
    case_key_is_independent_of_the_staging_directory \
    case_unhashed_evidence_blocks_caching \
    case_ecosystem_audit_counts_reach_the_totals
  do
    "$case"
  done

  printf '\n%s passed, %s failed\n' "$PASS_COUNT" "$FAIL_COUNT"
  [[ "$FAIL_COUNT" -eq 0 ]]
}

main "$@"
