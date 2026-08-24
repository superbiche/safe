#!/usr/bin/env bash
# safe audit binary-audit release-review is an exec-passthrough to safe-core.
#
# What this suite protects is the seam, not the review: every verdict, every
# refusal and every byte of the report belongs to the Go composite, so bash
# must add nothing on the way there and lose nothing on the way back. That
# leaves exactly two things bash owns — the lockstep pin, which must refuse a
# missing or version-skewed engine as audit-infrastructure breakage rather than
# as a release finding, and exit-code fidelity through the forward.
#
# Hermetic: no network, no downloads, every artifact written into a scratch dir.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SAFE_AUDIT="$ROOT/bin/safe-audit"

PASS_COUNT=0
FAIL_COUNT=0
pass() { printf 'ok - %s\n' "$*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { printf 'not ok - %s\n' "$*" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }

command -v jq >/dev/null 2>&1 || { printf 'not ok - missing required command: jq\n' >&2; exit 1; }
command -v sha256sum >/dev/null 2>&1 || { printf 'not ok - missing required command: sha256sum\n' >&2; exit 1; }

TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT

bash -n "$SAFE_AUDIT"
pass "safe-audit syntax"

# shellcheck source=../lib/safe-core.sh
source "$ROOT/tests/lib/safe-core.sh"
if ! safe_core_test_prepare "$ROOT" "$TEST_ROOT/safe-core"; then
  if [[ "${SAFE_TEST_STRICT:-}" == "1" ]]; then
    printf 'not ok - safe-core could not be built and SAFE_TEST_STRICT=1\n' >&2
    exit 1
  fi
  printf 'SKIP: safe-core could not be built; the forward cannot be exercised\n'
  exit 0
fi

# ENGINE selects which safe-core the forward resolves: the freshly built one by
# default, a stub for the lockstep cases.
ENGINE="$SAFE_CORE_BIN"

run_forward() {
  local rc=0
  HOME="$TEST_ROOT/home" \
  SAFE_CORE_BIN="$ENGINE" \
  SAFE_AUDIT_CONFIG_DIR="$TEST_ROOT/config" \
  SAFE_AUDIT_DATA_DIR="$TEST_ROOT/data" \
    "$SAFE_AUDIT" binary-audit release-review "$@" > "$TEST_ROOT/stdout" 2> "$TEST_ROOT/stderr" || rc=$?
  printf '%s' "$rc"
}

# --- fixtures ---------------------------------------------------------------

FIXTURES="$TEST_ROOT/fixtures"
mkdir -p "$FIXTURES"
printf 'release payload\n' > "$FIXTURES/tool.tar.gz"
( cd "$FIXTURES" && sha256sum tool.tar.gz > checksums.txt )

write_spec() {
  local out="$1" checksum_file="$2"
  cat > "$out" <<EOF
{
  "spec_version": 1,
  "subject": {"repo": "superbiche/safe", "version": "v1.0.0"},
  "artifacts": [
    {"path": "$FIXTURES/tool.tar.gz",
     "asset_name": "tool.tar.gz",
     "evidence": {"checksum_file": "$checksum_file"}}
  ],
  "checks": {"checksum": {"enabled": true}}
}
EOF
}

write_spec "$TEST_ROOT/good.json" "$FIXTURES/checksums.txt"

printf '%s  tool.tar.gz\n' "$(printf 'a different payload\n' | sha256sum | cut -d' ' -f1)" \
  > "$FIXTURES/wrong-checksums.txt"
write_spec "$TEST_ROOT/mismatch.json" "$FIXTURES/wrong-checksums.txt"

# Signature evidence is what lifts a verified artifact from WARN to GO. This
# build verifies no bundle, so the file only has to satisfy the schema.
printf 'bundle\n' > "$FIXTURES/tool.tar.gz.sigstore"
cat > "$TEST_ROOT/signed.json" <<EOF
{
  "spec_version": 1,
  "subject": {"repo": "superbiche/safe", "version": "v1.0.0"},
  "artifacts": [
    {"path": "$FIXTURES/tool.tar.gz",
     "asset_name": "tool.tar.gz",
     "evidence": {"checksum_file": "$FIXTURES/checksums.txt",
                  "signature": {"bundle": "$FIXTURES/tool.tar.gz.sigstore",
                                "identity": "https://example.test/workflow",
                                "oidc_issuer": "https://token.actions.githubusercontent.com"}}}
  ],
  "checks": {"checksum": {"enabled": true}}
}
EOF

printf 'not a spec\n' > "$TEST_ROOT/malformed.json"

# --- passthrough ------------------------------------------------------------

case_clean_release_exits_zero() {
  local rc
  rc=$(run_forward --spec "$TEST_ROOT/signed.json")
  if [[ "$rc" != "0" ]]; then
    fail "$FUNCNAME (exit $rc, want 0; stderr: $(cat "$TEST_ROOT/stderr"))"
    return
  fi
  if ! jq -e '.schema_version == 1 and .verdict == "GO"
              and (.checks | length == 1) and .checks[0].id == "checksum"
              and (.checks[0].reasons | length == 0)' \
      "$TEST_ROOT/stdout" >/dev/null 2>&1; then
    fail "$FUNCNAME (report not forwarded intact: $(cat "$TEST_ROOT/stdout"))"
    return
  fi
  pass "$FUNCNAME"
}

case_verified_release_passes_through() {
  local rc
  rc=$(run_forward --spec "$TEST_ROOT/good.json")
  # The artifact carries no signature evidence, so the composite warns rather
  # than passing clean — what matters here is that the code arrives unchanged.
  if [[ "$rc" != "10" ]]; then
    fail "$FUNCNAME (exit $rc, want 10; stderr: $(cat "$TEST_ROOT/stderr"))"
    return
  fi
  if ! jq -e '.schema_version == 1 and .verdict == "WARN"
              and (.checks | length == 1) and .checks[0].id == "checksum"' \
      "$TEST_ROOT/stdout" >/dev/null 2>&1; then
    fail "$FUNCNAME (report not forwarded intact: $(cat "$TEST_ROOT/stdout"))"
    return
  fi
  pass "$FUNCNAME"
}

case_report_reaches_stdout_only() {
  local rc
  rc=$(run_forward --spec "$TEST_ROOT/good.json")
  if [[ "$rc" != "10" ]]; then
    fail "$FUNCNAME (exit $rc, want 10)"
    return
  fi
  if [[ -s "$TEST_ROOT/stderr" ]]; then
    fail "$FUNCNAME (bash added stderr noise: $(cat "$TEST_ROOT/stderr"))"
    return
  fi
  pass "$FUNCNAME"
}

case_digest_mismatch_blocks() {
  local rc
  rc=$(run_forward --spec "$TEST_ROOT/mismatch.json")
  if [[ "$rc" != "20" ]]; then
    fail "$FUNCNAME (exit $rc, want 20)"
    return
  fi
  if ! jq -e '.verdict == "BLOCK"
              and (.checks[0].reasons | map(.code) | index("digest_mismatch") != null)' \
      "$TEST_ROOT/stdout" >/dev/null 2>&1; then
    fail "$FUNCNAME (report: $(cat "$TEST_ROOT/stdout"))"
    return
  fi
  pass "$FUNCNAME"
}

case_malformed_spec_is_not_a_verdict() {
  local rc
  rc=$(run_forward --spec "$TEST_ROOT/malformed.json")
  if [[ "$rc" != "3" ]]; then
    fail "$FUNCNAME (exit $rc, want 3)"
    return
  fi
  if [[ -s "$TEST_ROOT/stdout" ]]; then
    fail "$FUNCNAME (a refused spec still produced a report)"
    return
  fi
  pass "$FUNCNAME"
}

case_usage_error_passes_through() {
  local rc
  rc=$(run_forward)
  if [[ "$rc" != "2" ]]; then
    fail "$FUNCNAME (exit $rc, want 2)"
    return
  fi
  pass "$FUNCNAME"
}

# --- lockstep ---------------------------------------------------------------

case_version_skew_refuses_as_infrastructure() {
  local fake="$TEST_ROOT/skewed-safe-core" rc
  cat > "$fake" <<'STUB'
#!/usr/bin/env bash
printf '0.0.1\n'
STUB
  chmod +x "$fake"

  ENGINE="$fake"
  rc=$(run_forward --spec "$TEST_ROOT/good.json")
  ENGINE="$SAFE_CORE_BIN"
  if [[ "$rc" != "30" ]]; then
    fail "$FUNCNAME (exit $rc, want 30)"
    return
  fi
  if [[ "$(wc -l < "$TEST_ROOT/stderr")" != "1" ]]; then
    fail "$FUNCNAME (refusal is not a single line: $(cat "$TEST_ROOT/stderr"))"
    return
  fi
  if ! grep -q 'audit-infrastructure breakage' "$TEST_ROOT/stderr" \
    || ! grep -q 'rerun install.sh' "$TEST_ROOT/stderr"; then
    fail "$FUNCNAME (refusal lacks the recovery path: $(cat "$TEST_ROOT/stderr"))"
    return
  fi
  if [[ -s "$TEST_ROOT/stdout" ]]; then
    fail "$FUNCNAME (a skewed engine still produced a report)"
    return
  fi
  pass "$FUNCNAME"
}

case_missing_engine_refuses_as_infrastructure() {
  local rc
  ENGINE="$TEST_ROOT/absent-safe-core"
  rc=$(run_forward --spec "$TEST_ROOT/good.json")
  ENGINE="$SAFE_CORE_BIN"
  if [[ "$rc" != "30" ]]; then
    fail "$FUNCNAME (exit $rc, want 30)"
    return
  fi
  if [[ "$(wc -l < "$TEST_ROOT/stderr")" != "1" ]]; then
    fail "$FUNCNAME (refusal is not a single line: $(cat "$TEST_ROOT/stderr"))"
    return
  fi
  if ! grep -q 'verdict engine missing' "$TEST_ROOT/stderr" \
    || ! grep -q 'rerun install.sh' "$TEST_ROOT/stderr"; then
    fail "$FUNCNAME (unexpected refusal: $(cat "$TEST_ROOT/stderr"))"
    return
  fi
  pass "$FUNCNAME"
}

case_help_advertises_the_composite() {
  if ! "$SAFE_AUDIT" help 2>&1 | grep -q 'binary-audit release-review --spec PATH'; then
    fail "$FUNCNAME"
    return
  fi
  pass "$FUNCNAME"
}

case_clean_release_exits_zero
case_verified_release_passes_through
case_report_reaches_stdout_only
case_digest_mismatch_blocks
case_malformed_spec_is_not_a_verdict
case_usage_error_passes_through
case_version_skew_refuses_as_infrastructure
case_missing_engine_refuses_as_infrastructure
case_help_advertises_the_composite

if (( FAIL_COUNT > 0 )); then
  printf 'release-review forward: %d passed, %d FAILED\n' "$PASS_COUNT" "$FAIL_COUNT" >&2
  exit 1
fi
printf 'release-review forward: %d checks passed\n' "$PASS_COUNT"
