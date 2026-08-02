#!/usr/bin/env bash
# CVSS v4 scorer known-answer suite. The fixture is produced by the pinned
# FIRST JavaScript calculator through generate_cvss4_fixture.js.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SAFE_AUDIT="$ROOT/bin/safe-audit"
FIXTURE="$ROOT/tests/audit/fixtures/cvss4-known-answers.json"

PASS_COUNT=0
FAIL_COUNT=0

pass() { printf 'ok - %s\n' "$*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { printf 'not ok - %s\n' "$*" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }

TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT

extract_defs() {
  local wanted="$1" output="$2"
  awk -v wanted="$wanted" '
    /^JQ_SEVERITY_DEFS=/ { block++; capture = (block == wanted); next }
    capture && /^'\''$/ { exit }
    capture { print }
  ' "$SAFE_AUDIT" > "$output"
}

extract_defs 1 "$TEST_ROOT/remote.jq"
extract_defs 2 "$TEST_ROOT/local.jq"

if cmp -s "$TEST_ROOT/remote.jq" "$TEST_ROOT/local.jq"; then
  pass "local and standalone-remote severity scorers are identical"
else
  diff -u "$TEST_ROOT/remote.jq" "$TEST_ROOT/local.jq" >&2 || true
  fail "local and standalone-remote severity scorers are identical"
fi

fixture_count="$(jq 'length' "$FIXTURE")"
if [[ "$fixture_count" -ge 500 ]]; then
  pass "known-answer fixture contains several hundred vectors ($fixture_count)"
else
  fail "known-answer fixture contains several hundred vectors"
fi

if jq -e '
  ([.[].category] | index("first-example") != null)
  and ([.[].category] | index("all-highest") != null)
  and ([.[].category] | index("all-lowest") != null)
  and ([.[].category] | index("nd-heavy") != null)
  and ([.[].category] | index("bt-random") != null)
  and ([.[].category] | index("bte-random") != null)
  and ([.[].category | select(startswith("boundary-"))] | unique | length == 6)
' "$FIXTURE" >/dev/null; then
  pass "fixture covers FIRST examples, extremes, boundaries, ND, BT, and BTE"
else
  fail "fixture covers FIRST examples, extremes, boundaries, ND, BT, and BTE"
fi

JQ_DEFS="$(<"$TEST_ROOT/local.jq")"
if jq -n --slurpfile fixture "$FIXTURE" "$JQ_DEFS"'
  cvss4_lookup as $lookup
  | cvss4_max_composed as $max_composed
  | cvss4_max_severity as $max_severity
  | [ $fixture[0][]
      | . as $case
      | ($case.vector | [try cvss4_score_with($lookup; $max_composed; $max_severity) catch empty] | first) as $actual_score
      | ($actual_score | if . == null then null else cvss4_score_band end) as $actual_band
      | $case + {
          actual_score: $actual_score,
          actual_band: $actual_band,
          score_ok: ($actual_score == $case.score),
          band_ok: ($actual_band == $case.band)
        }
    ]
' > "$TEST_ROOT/results.json"; then
  pass "jq scorer evaluated every known-answer vector"
else
  fail "jq scorer evaluated every known-answer vector"
  printf '\n%d passed, %d failed\n' "$PASS_COUNT" "$FAIL_COUNT"
  exit 1
fi

score_failures="$(jq '[.[] | select(.score_ok | not)] | length' "$TEST_ROOT/results.json")"
if [[ "$score_failures" -eq 0 ]]; then
  pass "all scores equal the FIRST calculator at 0.1 precision"
else
  jq -r '.[] | select(.score_ok | not) | "\(.vector): expected \(.score), got \(.actual_score)"' "$TEST_ROOT/results.json" | head -n 10 >&2
  fail "all scores equal the FIRST calculator at 0.1 precision"
fi

band_failures="$(jq '[.[] | select(.band_ok | not)] | length' "$TEST_ROOT/results.json")"
if [[ "$band_failures" -eq 0 ]]; then
  pass "all bands equal the FIRST calculator bands"
else
  jq -r '.[] | select(.band_ok | not) | "\(.vector): expected \(.band), got \(.actual_band)"' "$TEST_ROOT/results.json" | head -n 10 >&2
  fail "all bands equal the FIRST calculator bands"
fi

if jq -ne "$JQ_DEFS"'
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:BOGUS"
  ]
  | map(((try cvss4_band catch empty) // "high"))
  | . == ["high", "high", "high"]
' >/dev/null; then
  pass "invalid, non-4.0, and truncated vectors retain the high floor"
else
  fail "invalid, non-4.0, and truncated vectors retain the high floor"
fi

printf '\n%d passed, %d failed\n' "$PASS_COUNT" "$FAIL_COUNT"
[[ "$FAIL_COUNT" -eq 0 ]]
