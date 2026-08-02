#!/usr/bin/env bash
# Development cross-check against the pinned FIRST JavaScript calculator.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SAFE_AUDIT="$ROOT/bin/safe-audit"
GENERATOR="$ROOT/tests/audit/generate_cvss4_fixture.js"

if ! command -v node >/dev/null 2>&1; then
  printf 'SKIP - CVSS v4 exhaustive cross-check requires node\n'
  exit 0
fi

# The oracle is not in the tree (tmp/ is gitignored): bootstrap it, hash-
# pinned, so a fresh clone can run this and regenerate the fixture. Offline
# is a legible skip — the committed known-answer suite still guards.
if ! bash "$ROOT/tests/audit/fetch_cvss4_ref.sh" >/dev/null 2>&1; then
  printf 'SKIP - CVSS v4 reference oracle unavailable; run tests/audit/fetch_cvss4_ref.sh\n'
  exit 0
fi

TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT

awk '
  /^JQ_SEVERITY_DEFS=/ { block++; capture = (block == 2); next }
  capture && /^'\''$/ { exit }
  capture { print }
' "$SAFE_AUDIT" > "$TEST_ROOT/severity.jq"
JQ_DEFS="$(<"$TEST_ROOT/severity.jq")"

node "$GENERATOR" --exhaustive > "$TEST_ROOT/official.tsv"
cut -f1 "$TEST_ROOT/official.tsv" \
  | jq -Rnr "$JQ_DEFS"'
      cvss4_lookup as $lookup
      | cvss4_max_composed as $max_composed
      | cvss4_max_severity as $max_severity
      | inputs
      | . as $vector
      | ([try cvss4_score_with($lookup; $max_composed; $max_severity) catch empty] | first) as $score
      | if $score == null then [$vector, "ERROR", "ERROR"]
        else [$vector, (($score * 10) | round), ($score | cvss4_score_band)]
        end
      | @tsv
    ' > "$TEST_ROOT/jq.tsv"

paste "$TEST_ROOT/official.tsv" "$TEST_ROOT/jq.tsv" \
  | awk -F '\t' '$1 != $4 || $2 != $5 || $3 != $6' > "$TEST_ROOT/mismatches.tsv"

total="$(wc -l < "$TEST_ROOT/official.tsv" | tr -d ' ')"
mismatches="$(wc -l < "$TEST_ROOT/mismatches.tsv" | tr -d ' ')"
printf 'CVSS v4 exhaustive cross-check: %s vectors, %s mismatches\n' "$total" "$mismatches"

if [[ "$total" -ne 110096 ]]; then
  printf 'expected 110096 vectors (104976 base + 5120 BT/BTE)\n' >&2
  exit 1
fi
if [[ "$mismatches" -ne 0 ]]; then
  head -n 20 "$TEST_ROOT/mismatches.tsv" >&2
  exit 1
fi
