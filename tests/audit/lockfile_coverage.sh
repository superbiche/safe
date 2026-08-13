#!/usr/bin/env bash
# What safe hands osv-scanner, and what happens when the scanner cannot read it.
#
# osv-scanner selects an extractor by filename and treats a file it has no
# extractor for as fatal for the WHOLE batch: exit 127, empty stdout, every
# sibling it already extracted discarded. Discovery was handing it `go.sum`,
# which the Go extractor has never read (it reads go.mod), so every Go repo
# lost its entire OSV tier — and in a mixed repo the Go file took the npm
# results down with it. 54 advisories were invisible in the repo that
# surfaced this. The audit still printed "finished", which is what made the
# loss silent.
#
# Hermetic: no network, no real scanners, every tool a stub.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SAFE_AUDIT="$ROOT/bin/safe-audit"

PASS_COUNT=0
FAIL_COUNT=0
pass() { printf 'ok - %s\n' "$*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { printf 'not ok - %s\n' "$*" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }

TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT

MOCKBIN="$TEST_ROOT/bin"
mkdir -p "$MOCKBIN"

# The stub records every --lockfile it was handed, one call per line, so a
# test can assert on the ARGUMENTS rather than on the scan's conclusions.
# Knobs:
#   SAFE_TEST_OSV_UNREADABLE   basenames it refuses the way the real scanner
#                              refuses a format it cannot extract
#   SAFE_TEST_OSV_PROBE_GARBAGE  probe calls fail in an unrecognized way
#   SAFE_TEST_OSV_EMPTY_BATCH  exit 0 writing nothing (the shape that used to
#                              slip past validation because the status was 0)
cat > "$MOCKBIN/osv-scanner" <<'STUB'
#!/usr/bin/env bash
if [[ "${1:-}" == "--version" ]]; then
  printf 'osv-scanner version: 0.0.0-test\n'
  exit 0
fi
declare -a lockfiles=()
probe=0
for arg in "$@"; do
  case "$arg" in
    --lockfile=*) lockfiles+=("${arg#--lockfile=}") ;;
    --offline) probe=1 ;;
  esac
done
is_unreadable() {
  local base
  base="$(basename "$1")"
  for bad in ${SAFE_TEST_OSV_UNREADABLE:-}; do
    [[ "$base" == "$bad" ]] && return 0
  done
  return 1
}
# Probe path: reproduce what the real scanner says against EMPTY content —
# a missing extractor names itself, a present one complains about the content.
if [[ "$probe" == "1" ]]; then
  if [[ -n "${SAFE_TEST_OSV_PROBE_GARBAGE:-}" ]]; then
    printf 'boom: unexpected failure\n' >&2
    exit 23
  fi
  for lf in ${lockfiles[@]+"${lockfiles[@]}"}; do
    if is_unreadable "$lf"; then
      printf 'could not determine extractor suitable to this file: "%s"\n' "$lf" >&2
      exit 127
    fi
  done
  printf 'extraction failed on specified lockfile\n' >&2
  exit 127
fi
if [[ -n "${SAFE_TEST_OSV_CALLS:-}" ]]; then
  printf '%s\n' "${lockfiles[*]}" >> "$SAFE_TEST_OSV_CALLS"
fi
if [[ -n "${SAFE_TEST_OSV_EMPTY_BATCH:-}" && "${#lockfiles[@]}" -gt 1 ]]; then
  exit 0
fi
if [[ -n "${SAFE_TEST_OSV_EMPTY_BATCH:-}" && "${#lockfiles[@]}" -eq 1 && -n "${SAFE_TEST_OSV_EMPTY_SINGLE:-}" ]]; then
  exit 0
fi
for lf in ${lockfiles[@]+"${lockfiles[@]}"}; do
  if is_unreadable "$lf"; then
    printf 'could not determine extractor suitable to this file: "%s"\n' "$lf" >&2
    exit 127
  fi
done
# One synthetic HIGH advisory per readable lockfile, so the count of surviving
# results is readable from the scan totals: a lost tier scores 0, and a
# fallback that kept one of two lockfiles scores 1.
{
  printf '{"results":['
  sep=""
  for lf in ${lockfiles[@]+"${lockfiles[@]}"}; do
    printf '%s{"source":{"path":"%s","type":"lockfile"},"packages":[{"package":{"name":"p","version":"1.0.0","ecosystem":"npm"},"vulnerabilities":[{"id":"TEST-1","database_specific":{"severity":"HIGH"}}]}]}' "$sep" "$lf"
    sep=","
  done
  printf ']}\n'
}
exit 0
STUB
chmod +x "$MOCKBIN/osv-scanner"

cat > "$MOCKBIN/syft" <<'STUB'
#!/usr/bin/env bash
printf '{"components":[],"metadata":{"tools":[{"name":"syft"}]}}\n'
STUB
chmod +x "$MOCKBIN/syft"

cat > "$MOCKBIN/grype" <<'STUB'
#!/usr/bin/env bash
printf '{"matches":[]}\n'
STUB
chmod +x "$MOCKBIN/grype"

# A project tree carrying exactly the lockfiles named, with every ecosystem
# audit switched off: this suite is about the OSV tier, and a real `npm audit`
# would need the network.
make_project() {
  local name="$1"
  shift
  local dir="$TEST_ROOT/$name"
  mkdir -p "$dir"
  cat > "$dir/.safe-audit" <<'CFG'
ecosystems:
  npm: false
  python: false
  php: false
  rust: false
  go: false
CFG
  local file
  for file in "$@"; do
    mkdir -p "$(dirname "$dir/$file")"
    case "$(basename "$file")" in
      go.mod) printf 'module example.com/x\n\ngo 1.24\n' > "$dir/$file" ;;
      go.sum) printf 'example.com/y v1.0.0 h1:abc=\n' > "$dir/$file" ;;
      bun.lockb) printf 'binary\n' > "$dir/$file" ;;
      *) printf '{}\n' > "$dir/$file" ;;
    esac
  done
  printf '%s' "$dir"
}

# Returns the result document so a test can read tool_status directly.
audit_project() {
  local dir="$1"
  shift
  local result="$dir/result.json"
  rm -f "$result"
  ( cd "$dir" && \
    TMPDIR="$TEST_ROOT/tmp" \
    PATH="$MOCKBIN:$PATH" \
    HOME="$TEST_ROOT/home" \
    SAFE_AUDIT_CONFIG_DIR="$TEST_ROOT/config-$(basename "$dir")" \
    SAFE_AUDIT_DATA_DIR="$TEST_ROOT/data-$(basename "$dir")" \
    env "$@" \
    "$SAFE_AUDIT" repo-audit . --deps-only --no-cache --allow-missing-tools \
      --result-out "$result" ) > "$dir/audit.log" 2>&1 || true
  printf '%s' "$result"
}

mkdir -p "$TEST_ROOT/tmp" "$TEST_ROOT/home"

# --- what reaches the scanner ----------------------------------------------

case_go_sum_is_translated_to_go_mod() {
  local dir calls result
  dir="$(make_project go-mixed go.sum go.mod deploy/package-lock.json)"
  calls="$dir/calls"
  result="$(audit_project "$dir" SAFE_TEST_OSV_CALLS="$calls")"
  local args
  args="$(cat "$calls" 2>/dev/null || true)"
  if [[ "$args" == *"go.mod"* && "$args" != *"go.sum"* && "$args" == *"package-lock.json"* ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (scanner was handed: ${args:-<nothing>})"
  fi
}

case_bun_lock_is_handed_to_the_scanner() {
  local dir calls args
  dir="$(make_project bun-text bun.lock)"
  calls="$dir/calls"
  audit_project "$dir" SAFE_TEST_OSV_CALLS="$calls" >/dev/null
  args="$(cat "$calls" 2>/dev/null || true)"
  if [[ "$args" == *"bun.lock"* ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (scanner was handed: ${args:-<nothing>})"
  fi
}

case_bun_lockb_never_reaches_the_scanner() {
  local dir calls args
  dir="$(make_project bun-binary bun.lockb bun.lock)"
  calls="$dir/calls"
  audit_project "$dir" SAFE_TEST_OSV_CALLS="$calls" >/dev/null
  args="$(cat "$calls" 2>/dev/null || true)"
  # Both files are discovered; the binary one has no extractor, and its text
  # sibling must be passed once rather than twice.
  if [[ "$args" != *"bun.lockb"* && "$args" == *"bun.lock"* ]]; then
    local count
    count="$(tr ' ' '\n' <<<"$args" | grep -c 'bun\.lock$' || true)"
    if [[ "$count" == "1" ]]; then
      pass "$FUNCNAME"
    else
      fail "$FUNCNAME (bun.lock passed $count times)"
    fi
  else
    fail "$FUNCNAME (scanner was handed: ${args:-<nothing>})"
  fi
}

# --- coverage that is lost is reported --------------------------------------

case_unreadable_only_project_reports_missing_coverage() {
  local dir result status
  dir="$(make_project go-sum-only go.sum)"
  result="$(audit_project "$dir")"
  status="$(jq -r '.tool_status["osv-scanner"].status // "absent"' "$result" 2>/dev/null || printf 'absent')"
  local reason
  reason="$(jq -r '.tool_status["osv-scanner"].note // ""' "$result" 2>/dev/null || printf '')"
  if [[ "$status" == "skipped" && "$reason" == *"no osv-parseable lockfile"* ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (status=$status note=$reason)"
  fi
}

case_degraded_coverage_is_stated_on_the_closing_line() {
  local dir
  dir="$(make_project go-sum-line go.sum)"
  audit_project "$dir" >/dev/null
  if grep -q 'repo-audit: finished .* with degraded coverage' "$dir/audit.log"; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (closing line: $(grep 'repo-audit: finished' "$dir/audit.log" || printf '<none>'))"
  fi
}

case_a_clean_project_does_not_claim_degradation() {
  local dir
  dir="$(make_project clean deploy/package-lock.json)"
  audit_project "$dir" >/dev/null
  if grep -q 'repo-audit: finished' "$dir/audit.log" && ! grep -q 'degraded coverage' "$dir/audit.log"; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (closing line: $(grep 'repo-audit: finished' "$dir/audit.log" || printf '<none>'))"
  fi
}

# --- one bad file does not cost the whole tier ------------------------------

case_batch_failure_falls_back_to_scanning_each_lockfile() {
  local dir result
  dir="$(make_project batch-fallback deploy/package-lock.json web/yarn.lock)"
  # The scanner refuses yarn.lock, which kills the batch the way a dropped
  # extractor does. The package-lock results must survive.
  result="$(audit_project "$dir" SAFE_TEST_OSV_UNREADABLE="yarn.lock")"
  local sources status
  sources="$(jq -r '[.tool_status["osv-scanner"].status] | join(",")' "$result" 2>/dev/null || printf '')"
  status="$(jq -r '.tool_status["osv-scanner"].status // "absent"' "$result" 2>/dev/null || printf 'absent')"
  local note
  note="$(jq -r '.tool_status["osv-scanner"].note // ""' "$result" 2>/dev/null || printf '')"
  if [[ "$status" == "partial" && "$note" == *"yarn.lock"* ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (status=$status note=$note)"
  fi
}

case_batch_failure_keeps_the_readable_results() {
  local dir result high
  dir="$(make_project batch-keeps deploy/package-lock.json web/yarn.lock)"
  result="$(audit_project "$dir" SAFE_TEST_OSV_UNREADABLE="yarn.lock")"
  # The stub reports one HIGH advisory per readable lockfile. Losing the tier
  # to the unreadable sibling scores 0; keeping package-lock.json scores 1.
  high="$(jq -r '.cve_scan.high // 0' "$result" 2>/dev/null || printf '0')"
  if [[ "$high" == "1" ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (high advisories surviving: $high, expected 1)"
  fi
}

case_every_lockfile_unreadable_is_an_error_not_a_clean_scan() {
  local dir result status
  dir="$(make_project all-bad deploy/package-lock.json)"
  result="$(audit_project "$dir" SAFE_TEST_OSV_UNREADABLE="package-lock.json")"
  status="$(jq -r '.tool_status["osv-scanner"].status // "absent"' "$result" 2>/dev/null || printf 'absent')"
  if [[ "$status" == "error" ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (status=$status)"
  fi
}

# --- a coverage gap is not a broken scanner ---------------------------------

# bin/safe's install gate decides "scanner broken" — exit 100, unacceptable
# even under --yes — from this predicate over the free-form note. It is copied
# verbatim from bin/safe so the two cannot drift apart silently.
GATE_BROKEN_PREDICATE='
  def broken: (.status // "ok") as $s
    | ($s == "error") or (($s != "ok") and (((.note // "") | test("fail|error"; "i"))));
  [ (.tool_status // {} | to_entries[]? | select(.value | broken) | .key) ] | length > 0
'

case_a_coverage_gap_under_a_failure_named_path_is_not_scanner_breakage() {
  local dir result
  # The project's own directory name is the whole point: interpolating the
  # lockfile PATH into the note made `failure-demo` match the gate's
  # /fail|error/i predicate and turned missing coverage into a hard refusal.
  dir="$(make_project failure-demo bun.lockb)"
  result="$(audit_project "$dir")"
  local note
  note="$(jq -r '.tool_status["osv-scanner"].note // ""' "$result" 2>/dev/null || printf '')"
  if jq -e "$GATE_BROKEN_PREDICATE" "$result" >/dev/null 2>&1; then
    fail "$FUNCNAME (gate would refuse: note=$note)"
    return
  fi
  if [[ "$note" == */* ]]; then
    fail "$FUNCNAME (note carries a path: $note)"
    return
  fi
  if [[ "$note" == *"bun.lockb"* ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (note does not name the format: $note)"
  fi
}

case_both_kinds_of_lost_coverage_are_reported_together() {
  local dir result note
  # legacy/go.sum has no sibling go.mod, so translation drops it; web/yarn.lock
  # is handed over and the scanner refuses it. Both are uncovered, and the
  # annotation used to name only whichever was written last.
  dir="$(make_project mixed-loss legacy/go.sum deploy/package-lock.json web/yarn.lock)"
  result="$(audit_project "$dir" SAFE_TEST_OSV_UNREADABLE="yarn.lock")"
  note="$(jq -r '.tool_status["osv-scanner"].note // ""' "$result" 2>/dev/null || printf '')"
  if [[ "$note" == *"go.sum"* && "$note" == *"yarn.lock"* ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (note names only part of the loss: $note)"
  fi
}

# --- validity is judged on output, not exit status --------------------------

case_zero_exit_with_no_output_is_not_a_clean_scan() {
  local dir result status
  # A wrapper or a future release exiting 0 having written nothing read as an
  # empty, successful scan because validity was only checked when the exit
  # status was nonzero. One lockfile, so there is no fallback to rescue it.
  dir="$(make_project zero-exit deploy/package-lock.json)"
  result="$(audit_project "$dir" SAFE_TEST_OSV_EMPTY_BATCH=1 SAFE_TEST_OSV_EMPTY_SINGLE=1)"
  status="$(jq -r '.tool_status["osv-scanner"].status // "absent"' "$result" 2>/dev/null || printf 'absent')"
  if [[ "$status" == "error" ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (status=$status)"
  fi
}

case_zero_exit_empty_batch_still_recovers_per_lockfile() {
  local dir result high
  dir="$(make_project zero-exit-batch deploy/package-lock.json web/yarn.lock)"
  result="$(audit_project "$dir" SAFE_TEST_OSV_EMPTY_BATCH=1)"
  high="$(jq -r '.cve_scan.high // 0' "$result" 2>/dev/null || printf '0')"
  if [[ "$high" == "2" ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (advisories recovered: $high, expected 2)"
  fi
}

# --- the guard against the next scanner upgrade -----------------------------

case_lockfile_support_reports_a_dropped_extractor() {
  local out rc=0
  out="$(PATH="$MOCKBIN:$PATH" HOME="$TEST_ROOT/home" \
    SAFE_AUDIT_CONFIG_DIR="$TEST_ROOT/config-support" \
    SAFE_AUDIT_DATA_DIR="$TEST_ROOT/data-support" \
    SAFE_TEST_OSV_UNREADABLE="go.mod bun.lock" \
    "$SAFE_AUDIT" lockfile-support --json 2>/dev/null)" || rc=$?
  local unsupported ok
  unsupported="$(jq -r '.unsupported | sort | join(",")' <<<"$out" 2>/dev/null || printf '')"
  ok="$(jq -r '.ok' <<<"$out" 2>/dev/null || printf 'true')"
  if [[ "$unsupported" == "bun.lock,go.mod" && "$ok" == "false" ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (unsupported=$unsupported ok=$ok)"
  fi
}

case_lockfile_support_refuses_to_call_an_unrecognized_failure_support() {
  local out
  # A probe that classified "no error phrase I recognize" as support would
  # report every format healthy against a scanner that crashes on all of them.
  out="$(PATH="$MOCKBIN:$PATH" HOME="$TEST_ROOT/home" \
    SAFE_AUDIT_CONFIG_DIR="$TEST_ROOT/config-support-garbage" \
    SAFE_AUDIT_DATA_DIR="$TEST_ROOT/data-support-garbage" \
    SAFE_TEST_OSV_PROBE_GARBAGE=1 \
    "$SAFE_AUDIT" lockfile-support --json 2>/dev/null)" || true
  local ok unknown
  ok="$(jq -r '.ok' <<<"$out" 2>/dev/null || printf 'true')"
  unknown="$(jq -r '.unknown | length' <<<"$out" 2>/dev/null || printf '0')"
  if [[ "$ok" == "false" && "$unknown" -ge 11 ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (ok=$ok unknown=$unknown)"
  fi
}

# The probe must take its scratch from the shared registry, not a bare mktemp:
# only registered directories are removed by the interrupt/exit traps. This
# asserts the registration (a command-substitution call would lose it — the
# first version did exactly that); the traps themselves are covered by
# tests/audit/tool_resolution.sh, which is where the registry is under test.
case_lockfile_support_leaves_no_scratch_behind() {
  local probe_tmp before after
  probe_tmp="$TEST_ROOT/probe-tmp"
  mkdir -p "$probe_tmp"
  before="$(find "$probe_tmp" -mindepth 1 -maxdepth 1 -type d | wc -l)"
  PATH="$MOCKBIN:$PATH" HOME="$TEST_ROOT/home" TMPDIR="$probe_tmp" \
    SAFE_AUDIT_CONFIG_DIR="$TEST_ROOT/config-support-tmp" \
    SAFE_AUDIT_DATA_DIR="$TEST_ROOT/data-support-tmp" \
    "$SAFE_AUDIT" lockfile-support --json >/dev/null 2>&1 || true
  after="$(find "$probe_tmp" -mindepth 1 -maxdepth 1 -type d | wc -l)"
  if [[ "$before" == "$after" ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (scratch dirs before=$before after=$after)"
  fi
}

case_lockfile_support_passes_on_a_complete_scanner() {
  local out
  out="$(PATH="$MOCKBIN:$PATH" HOME="$TEST_ROOT/home" \
    SAFE_AUDIT_CONFIG_DIR="$TEST_ROOT/config-support-ok" \
    SAFE_AUDIT_DATA_DIR="$TEST_ROOT/data-support-ok" \
    "$SAFE_AUDIT" lockfile-support --json 2>/dev/null)"
  local ok count
  ok="$(jq -r '.ok' <<<"$out" 2>/dev/null || printf 'false')"
  count="$(jq -r '.formats | length' <<<"$out" 2>/dev/null || printf '0')"
  if [[ "$ok" == "true" && "$count" -ge 11 ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (ok=$ok formats=$count)"
  fi
}

case_go_sum_is_translated_to_go_mod
case_bun_lock_is_handed_to_the_scanner
case_bun_lockb_never_reaches_the_scanner
case_unreadable_only_project_reports_missing_coverage
case_degraded_coverage_is_stated_on_the_closing_line
case_a_clean_project_does_not_claim_degradation
case_batch_failure_falls_back_to_scanning_each_lockfile
case_batch_failure_keeps_the_readable_results
case_every_lockfile_unreadable_is_an_error_not_a_clean_scan
case_a_coverage_gap_under_a_failure_named_path_is_not_scanner_breakage
case_both_kinds_of_lost_coverage_are_reported_together
case_zero_exit_with_no_output_is_not_a_clean_scan
case_zero_exit_empty_batch_still_recovers_per_lockfile
case_lockfile_support_reports_a_dropped_extractor
case_lockfile_support_refuses_to_call_an_unrecognized_failure_support
case_lockfile_support_leaves_no_scratch_behind
case_lockfile_support_passes_on_a_complete_scanner

printf '\n%d passed, %d failed\n' "$PASS_COUNT" "$FAIL_COUNT"
[[ "$FAIL_COUNT" -eq 0 ]]
