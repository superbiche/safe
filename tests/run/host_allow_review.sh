#!/usr/bin/env bash
# safe run host-allow review: staleness classification, usage join, digest.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SAFE_RUN="$ROOT/bin/safe-run"

pass() { printf 'ok - %s\n' "$*"; }
fail() { printf 'not ok - %s\n' "$*" >&2; exit 1; }

require() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

require bash
require jq

bash -n "$SAFE_RUN"
pass "bash syntax"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# The repo tree is kept deliberately: the digest used to land in its inbox, and
# every digest case below asserts that nothing is written here any more.
mkdir -p "$tmp/config" "$tmp/data" "$tmp/audit-data" "$tmp/bin" \
  "$tmp/safe-config" "$tmp/repo/.git" "$tmp/repo/bin" "$tmp/repo/inbox"

digest_json="$tmp/safe-config/audit/host-allow-digest.json"
digest_md="$tmp/safe-config/audit/host-allow-digest.md"

cat > "$tmp/config/host-allow.json" <<'JSON'
{"packages":{
  "clean-pkg":{"version":"2.1.4","sha":"a","ecosystem":"npm","added":"2026-07-01","reason":"was catch-22"},
  "warn-pkg":{"version":"1.3.0","sha":"b","ecosystem":"npm","added":"2026-05-01","reason":"real warn"},
  "block-pkg":{"version":"0.0.1","sha":"c","ecosystem":"npm","added":"2026-06-01","reason":"went bad"},
  "infra-pkg":{"version":"1.0.0","sha":"d","ecosystem":"npm","added":"2026-06-15","reason":"socket down"},
  "slow-pkg":{"version":"3.0.0","sha":"e","ecosystem":"npm","added":"2026-06-20","reason":"audit hangs"}
}}
JSON

# Two executions of clean-pkg; the audit log's HOST_ALLOW tier line for the
# same exec must NOT double the count. One install-gate override for warn-pkg.
cat > "$tmp/audit-data/host-allow-log.jsonl" <<'JSON'
{"timestamp":"2026-07-30T10:00:00+02:00","package":"clean-pkg","version":"2.1.4","runner":"npx"}
{"timestamp":"2026-08-01T11:00:00+02:00","package":"clean-pkg","version":"2.1.4","runner":"npx"}
JSON
cat > "$tmp/data/audit.log" <<'LOG'
2026-08-01T11:00:00+02:00 | npx | clean-pkg@2.1.4 | HOST_ALLOW | non-tty | OK
2026-08-02T09:00:00+02:00 | install:npm | warn-pkg@1.3.0 | GATE | non-tty | HOST_ALLOW_OVERRIDE
LOG

cat > "$tmp/bin/safe-audit-stub" <<'SH'
#!/usr/bin/env bash
printf 'noinit=%s %s\n' "${SAFE_AUDIT_NO_INIT:-}" "$*" >> "${STUB_CALL_LOG:-/dev/null}"
spec="$2"
case "$spec" in
  clean-pkg@*)   printf '{"verdict":"GO","warn_causes":[]}\n'; exit 0 ;;
  warn-pkg@*)    printf '{"verdict":"WARN","warn_causes":["osv_affecting"]}\n'; exit 10 ;;
  block-pkg@*)   printf '{"verdict":"BLOCK","warn_causes":[]}\n'; exit 20 ;;
  infra-pkg@*)   printf '{"verdict":"WARN","warn_causes":["socket_rate_limited"]}\n'; exit 10 ;;
  slow-pkg@*)    sleep 5; printf '{"verdict":"GO","warn_causes":[]}\n'; exit 0 ;;
  empty-pkg@*)   exit 0 ;;
  garbage-pkg@*) printf 'not json at all\n'; exit 20 ;;
  contradict-pkg@*) printf '{"verdict":"GO","warn_causes":["socket_rate_limited"]}\n'; exit 0 ;;
esac
SH
chmod +x "$tmp/bin/safe-audit-stub"

# SAFE_CONFIG_DIR, not SAFE_AUDIT_CONFIG_DIR: the digest path is derived, and
# the derivation is what these cases have to exercise. SAFE_REPO_DIR is gone —
# the digest no longer knows what a repo is.
run_safe_run() {
  SAFE_RUN_CONFIG_DIR="$tmp/config" \
  SAFE_RUN_DATA_DIR="$tmp/data" \
  SAFE_AUDIT_DATA_DIR="$tmp/audit-data" \
  SAFE_CONFIG_DIR="$tmp/safe-config" \
  SAFE_AUDIT_BIN="$tmp/bin/safe-audit-stub" \
  SAFE_HOST_ALLOW_REVIEW_TIMEOUT=1 \
  SAFE_RUN_NO_INIT=1 \
  STUB_CALL_LOG="$tmp/stub-calls.log" \
    "$SAFE_RUN" "$@"
}

run_review() {
  run_safe_run host-allow review "$@"
}

# --- classification -------------------------------------------------------
report=$(run_review --json)

status_of() { jq -r --arg n "$1" '.entries[] | select(.name == $n) | .status' <<<"$report"; }

[[ "$(status_of clean-pkg)" == "removable" ]] || fail "GO entry should be removable"
pass "GO verdict classifies as removable"

[[ "$(status_of warn-pkg)" == "keep" ]] || fail "finding WARN should be keep"
pass "WARN with a real finding classifies as keep"

[[ "$(status_of infra-pkg)" == "unknown" ]] || fail "infra-only WARN should be unknown"
pass "infra-only WARN classifies as unknown (never stale)"

[[ "$(status_of block-pkg)" == "review-urgent" ]] || fail "BLOCK should be review-urgent"
pass "BLOCK verdict classifies as review-urgent"

[[ "$(status_of slow-pkg)" == "unknown" ]] || fail "probe timeout should be unknown"
pass "probe timeout classifies as unknown"

# --- usage join -----------------------------------------------------------
uses=$(jq -r '.entries[] | select(.name == "clean-pkg") | .times_used' <<<"$report")
[[ "$uses" == "2" ]] || fail "clean-pkg should count 2 executions (got $uses; HOST_ALLOW audit-log line must not double-count)"
pass "execution log counted once (no audit-log double count)"

uses=$(jq -r '.entries[] | select(.name == "warn-pkg") | .times_used' <<<"$report")
[[ "$uses" == "1" ]] || fail "warn-pkg should count 1 gate override (got $uses)"
pass "install-gate HOST_ALLOW_OVERRIDE counted"

last=$(jq -r '.entries[] | select(.name == "clean-pkg") | .last_used' <<<"$report")
[[ "$last" == "2026-08-01T11:00:00+02:00" ]] || fail "clean-pkg last_used wrong: $last"
pass "last_used is the max timestamp"

never=$(jq -r '.entries[] | select(.name == "block-pkg") | .never_used' <<<"$report")
[[ "$never" == "true" ]] || fail "block-pkg should be never_used"
pass "never_used flagged"

# --- summary --------------------------------------------------------------
summary=$(jq -c '.summary' <<<"$report")
expected='{"total":5,"removable":1,"keep":1,"review-urgent":1,"unknown":2,"unaudited":0,"never_used":3}'
[[ "$summary" == "$expected" ]] || fail "summary mismatch: $summary"
pass "summary counts"

# --- human output ---------------------------------------------------------
human=$(run_review)
grep -q "URGENT: block-pkg@0.0.1" <<<"$human" || fail "human output missing URGENT line"
grep -q "safe run host-allow remove clean-pkg" <<<"$human" || fail "human output missing remove hint"
grep -q "never evidence of staleness" <<<"$human" || fail "human output missing unknown note"
pass "human output carries urgent, removable, and unknown hints"

# --- --no-audit -----------------------------------------------------------
: >| "$tmp/stub-calls.log"
noaudit=$(run_review --json --no-audit)
[[ "$(jq -r '.summary.unaudited' <<<"$noaudit")" == "5" ]] || fail "--no-audit should mark all unaudited"
[[ ! -s "$tmp/stub-calls.log" ]] || fail "--no-audit must not invoke safe-audit"
pass "--no-audit skips probes"

# --- digest ---------------------------------------------------------------
# The digest is machine-local state under the safe config root, never a note in
# the repo's inbox: that lane is for asks, and a report that regenerates every
# week is not one.
run_review --digest >/dev/null 2>&1
[[ -f "$digest_json" ]] || fail "digest JSON not written to $digest_json"
[[ -f "$digest_md" ]] || fail "digest markdown not written to $digest_md"
jq -e '.summary.removable == 1 and .summary."review-urgent" == 1' "$digest_json" >/dev/null \
  || fail "digest JSON summary wrong: $(jq -c '.summary' "$digest_json")"
jq -e '.generated | type == "string" and (. != "")' "$digest_json" >/dev/null \
  || fail "digest JSON missing its generated timestamp"
grep -q "safe run host-allow remove clean-pkg" "$digest_md" || fail "digest missing remove suggestion"
grep -q "URGENT" "$digest_md" || fail "digest missing urgent flag"
pass "digest writes report JSON and rendered markdown to the config path"

[[ -z "$(find "$tmp/repo" -type f -print -quit)" ]] || fail "digest wrote into the repo tree: $(find "$tmp/repo" -type f)"
pass "digest writes nothing into the safe repo"

# Overwritten per run, not preserved: the old inbox note was dated and kept,
# this file is the latest review or it is lying.
printf 'sentinel\n' >> "$digest_md"
run_review --digest >/dev/null 2>&1
if grep -q "sentinel" "$digest_md"; then fail "digest markdown was not overwritten"; fi
pass "each run replaces the digest"

# Nothing actionable still writes: a review that found nothing has to clear
# yesterday's findings, or status keeps reporting decisions that are gone.
cat > "$tmp/config/host-allow.json" <<'JSON'
{"packages":{
  "warn-pkg":{"version":"1.3.0","sha":"b","ecosystem":"npm","added":"2026-05-01","reason":"real warn"},
  "infra-pkg":{"version":"1.0.0","sha":"d","ecosystem":"npm","added":"2026-06-15","reason":"socket down"}
}}
JSON
run_review --digest >/dev/null 2>&1
[[ -f "$digest_json" ]] || fail "digest not written when nothing is actionable"
jq -e '.summary.removable == 0 and .summary."review-urgent" == 0 and .summary.total == 2' \
  "$digest_json" >/dev/null || fail "nothing-actionable digest has wrong counts: $(jq -c '.summary' "$digest_json")"
pass "a review with nothing actionable still writes the digest, with zero counts"

# --- status renders the digest --------------------------------------------
printf '{"runners":{}}\n' > "$tmp/config/config.json"
out=$(run_safe_run status 2>/dev/null)
grep -q "review digest:  nothing actionable (reviewed " <<<"$out" \
  || fail "status missing the quiet digest line: $out"
pass "status reports a digest with nothing actionable"

# Back to the actionable set, so status has counts to report.
cat > "$tmp/config/host-allow.json" <<'JSON'
{"packages":{
  "clean-pkg":{"version":"2.1.4","sha":"a","ecosystem":"npm","added":"2026-07-01","reason":"was catch-22"},
  "block-pkg":{"version":"0.0.1","sha":"c","ecosystem":"npm","added":"2026-06-01","reason":"went bad"}
}}
JSON
run_review --digest >/dev/null 2>&1
out=$(run_safe_run status 2>/dev/null)
grep -q "review digest:  1 removable, 1 review-urgent (reviewed " <<<"$out" \
  || fail "status missing the actionable digest counts: $out"
grep -q "safe run host-allow remove <name>" <<<"$out" || fail "status missing the remove hint: $out"
pass "status reports removable and review-urgent counts with the review date"

# --- remove drops the handled entry ---------------------------------------
run_safe_run host-allow remove clean-pkg >/dev/null 2>&1
jq -e '[.entries[] | select(.name == "clean-pkg")] | length == 0' "$digest_json" >/dev/null \
  || fail "removed entry still in the digest"
jq -e '.summary.total == 1 and .summary.removable == 0 and .summary."review-urgent" == 1' \
  "$digest_json" >/dev/null || fail "digest counts not recomputed after removal: $(jq -c '.summary' "$digest_json")"
if grep -q "clean-pkg" "$digest_md"; then fail "removed entry still rendered in the digest markdown"; fi
pass "host-allow remove drops the entry from the digest and recomputes the counts"

out=$(run_safe_run status 2>/dev/null)
grep -q "review digest:  0 removable, 1 review-urgent (reviewed " <<<"$out" \
  || fail "status did not follow the recomputed digest: $out"
pass "status stops reporting a removed entry"

# Removing something the digest never carried is a no-op, never a failure:
# the digest is a convenience surface and must not be able to fail a removal.
run_safe_run host-allow remove block-pkg >/dev/null 2>&1 || fail "removal failed"
mv "$tmp/config/host-allow.json" "$tmp/config/host-allow.json.bak"
printf '{"packages":{"never-reviewed":{"version":"1.0.0","sha":"z","ecosystem":"npm","added":"2026-07-01","reason":"x"}}}\n' \
  > "$tmp/config/host-allow.json"
run_safe_run host-allow remove never-reviewed >/dev/null 2>&1 || fail "removal of an unreviewed entry failed"
pass "removing an entry the digest never carried is a no-op"

# An unreadable digest shows a marker rather than reading as "no findings".
printf 'not json at all\n' > "$digest_json"
out=$(run_safe_run status 2>/dev/null)
grep -q "review digest:  UNREADABLE at " <<<"$out" || fail "status hid a malformed digest: $out"
pass "status marks an unreadable digest instead of reporting zero findings"

# Absent digest: no review has run yet.
rm -f "$digest_json" "$digest_md"
out=$(run_safe_run status 2>/dev/null)
grep -q "review digest:  no review has run yet" <<<"$out" || fail "status missing the never-reviewed line: $out"
pass "status says so when no review has run"

# A review WITHOUT --digest writes nothing.
mv "$tmp/config/host-allow.json.bak" "$tmp/config/host-allow.json"
run_review --json >/dev/null 2>&1
[[ ! -e "$digest_json" ]] || fail "review without --digest wrote a digest"
pass "review without --digest writes no digest"

# --- probe payload corroboration (F2) -------------------------------------
cat > "$tmp/config/host-allow.json" <<'JSON'
{"packages":{
  "empty-pkg":{"version":"1.0.0","sha":"f","ecosystem":"npm","added":"2026-07-01","reason":"probe lies"},
  "garbage-pkg":{"version":"2.0.0","sha":"g","ecosystem":"npm","added":"2026-07-01","reason":"probe garbage"}
}}
JSON
report=$(run_review --json)
[[ "$(status_of empty-pkg)" == "unknown" ]] || fail "exit-0 probe with empty stdout must be unknown, not removable"
pass "exit 0 without corroborating GO payload is unknown"
[[ "$(status_of garbage-pkg)" == "unknown" ]] || fail "exit-20 probe with garbage stdout must be unknown"
pass "exit 20 without corroborating BLOCK payload is unknown"

cat > "$tmp/config/host-allow.json" <<'JSON'
{"packages":{
  "contradict-pkg":{"version":"1.0.0","sha":"h","ecosystem":"npm","added":"2026-07-01","reason":"go with causes"}
}}
JSON
report=$(run_review --json)
[[ "$(status_of contradict-pkg)" == "unknown" ]] || fail "GO with warn causes must be unknown, not removable"
pass "GO payload carrying warn causes is unknown"

# --- probes must not seed audit state (F1b) -------------------------------
grep -q '^noinit=1 ' "$tmp/stub-calls.log" || fail "probes must run with SAFE_AUDIT_NO_INIT=1"
pass "probes pass SAFE_AUDIT_NO_INIT=1"

# --- review must not seed run state (F1a) ---------------------------------
fresh="$tmp/fresh"
SAFE_RUN_CONFIG_DIR="$fresh/config" \
SAFE_RUN_DATA_DIR="$fresh/data" \
SAFE_AUDIT_DATA_DIR="$fresh/audit-data" \
SAFE_CONFIG_DIR="$fresh/safe-config" \
SAFE_AUDIT_BIN="$tmp/bin/safe-audit-stub" \
  "$SAFE_RUN" host-allow review --no-audit >/dev/null 2>&1 || true
[[ ! -e "$fresh/config/host-allow.json" ]] || fail "review seeded host-allow.json on a fresh machine"
[[ ! -e "$fresh/data/audit.log" ]] || fail "review seeded audit.log on a fresh machine"
[[ ! -e "$fresh/safe-config/audit" ]] || fail "review seeded the digest directory on a fresh machine"
pass "review does not seed trust, audit, or digest state (no SAFE_RUN_NO_INIT)"

# --- chronological last_used across offsets (F3) --------------------------
# Append order is chronological; the second line is the later instant
# (01:15Z) but the lexically smaller string. A lexical max would pick line 1.
cat > "$tmp/config/host-allow.json" <<'JSON'
{"packages":{
  "clean-pkg":{"version":"2.1.4","sha":"a","ecosystem":"npm","added":"2026-07-01","reason":"dst pair"}
}}
JSON
cat > "$tmp/audit-data/host-allow-log.jsonl" <<'JSON'
{"timestamp":"2026-10-25T02:30:00+02:00","package":"clean-pkg","version":"2.1.4","runner":"npx"}
{"timestamp":"2026-10-25T02:15:00+01:00","package":"clean-pkg","version":"2.1.4","runner":"npx"}
JSON
: >| "$tmp/data/audit.log"
report=$(run_review --json)
last=$(jq -r '.entries[0].last_used' <<<"$report")
[[ "$last" == "2026-10-25T02:15:00+01:00" ]] || fail "last_used picked lexical, not chronological: $last"
pass "last_used is chronological across UTC offsets"

# Concurrent writers can append out of timestamp order: the later instant
# sits on the FIRST line here, and must still win.
cat > "$tmp/audit-data/host-allow-log.jsonl" <<'JSON'
{"timestamp":"2026-10-25T02:15:00+01:00","package":"clean-pkg","version":"2.1.4","runner":"npx"}
{"timestamp":"2026-10-25T02:30:00+02:00","package":"clean-pkg","version":"2.1.4","runner":"npx"}
JSON
report=$(run_review --json)
last=$(jq -r '.entries[0].last_used' <<<"$report")
[[ "$last" == "2026-10-25T02:15:00+01:00" ]] || fail "last_used must pick the greatest instant, not the last line: $last"
pass "last_used survives out-of-order appends"

# --- malformed entries degrade, not abort (F4) ----------------------------
cat > "$tmp/config/host-allow.json" <<'JSON'
{"packages":{
  "broken-entry":"not an object",
  "block-pkg":{"version":"0.0.1","sha":"c","ecosystem":"npm","added":"2026-06-01","reason":"went bad"}
}}
JSON
report=$(run_review --json)
[[ "$(status_of broken-entry)" == "unknown" ]] || fail "malformed entry should report unknown"
[[ "$(status_of block-pkg)" == "review-urgent" ]] || fail "entries after a malformed one must still be classified"
pass "malformed entry degrades to unknown; the rest of the list survives"

cat > "$tmp/config/host-allow.json" <<'JSON'
{"packages":"nope"}
JSON
if run_review --json >/dev/null 2>"$tmp/malformed-err"; then
  fail "unreadable host-allow file must be a legible error, not an empty report"
fi
grep -q "unreadable or malformed" "$tmp/malformed-err" || fail "missing legible malformed-file error"
pass "unreadable host-allow file errors legibly"

printf 'host-allow review: all cases passed\n'
