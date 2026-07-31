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
    case_no_evidence_is_not_cacheable
  do
    "$case"
  done

  printf '\n%s passed, %s failed\n' "$PASS_COUNT" "$FAIL_COUNT"
  [[ "$FAIL_COUNT" -eq 0 ]]
}

main "$@"
