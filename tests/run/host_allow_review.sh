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

mkdir -p "$tmp/config" "$tmp/data" "$tmp/audit-data" "$tmp/bin" \
  "$tmp/repo/.git" "$tmp/repo/bin" "$tmp/repo/inbox"

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
printf '%s\n' "$*" >> "${STUB_CALL_LOG:-/dev/null}"
spec="$2"
case "$spec" in
  clean-pkg@*) printf '{"verdict":"GO","warn_causes":[]}\n'; exit 0 ;;
  warn-pkg@*)  printf '{"verdict":"WARN","warn_causes":["osv_affecting"]}\n'; exit 10 ;;
  block-pkg@*) printf '{"verdict":"BLOCK","warn_causes":[]}\n'; exit 20 ;;
  infra-pkg@*) printf '{"verdict":"WARN","warn_causes":["socket_rate_limited"]}\n'; exit 10 ;;
  slow-pkg@*)  sleep 5; printf '{"verdict":"GO","warn_causes":[]}\n'; exit 0 ;;
esac
SH
chmod +x "$tmp/bin/safe-audit-stub"

run_review() {
  SAFE_RUN_CONFIG_DIR="$tmp/config" \
  SAFE_RUN_DATA_DIR="$tmp/data" \
  SAFE_AUDIT_DATA_DIR="$tmp/audit-data" \
  SAFE_AUDIT_BIN="$tmp/bin/safe-audit-stub" \
  SAFE_HOST_ALLOW_REVIEW_TIMEOUT=1 \
  SAFE_REPO_DIR="$tmp/repo" \
  SAFE_RUN_NO_INIT=1 \
  STUB_CALL_LOG="$tmp/stub-calls.log" \
    "$SAFE_RUN" host-allow review "$@"
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
note="$tmp/repo/inbox/$(date -I)-safe-host-allow-digest.md"
run_review --digest >/dev/null 2>&1
[[ -f "$note" ]] || fail "digest note not written"
grep -q "safe run host-allow remove clean-pkg" "$note" || fail "digest missing remove suggestion"
grep -q "URGENT" "$note" || fail "digest missing urgent flag"
pass "digest note written when actionable"

printf 'sentinel\n' >> "$note"
run_review --digest >/dev/null 2>&1
grep -q "sentinel" "$note" || fail "existing digest note was overwritten"
pass "existing digest note preserved"

# Nothing actionable: only the infra and warn entries -> no note.
rm -f "$note"
cat > "$tmp/config/host-allow.json" <<'JSON'
{"packages":{
  "warn-pkg":{"version":"1.3.0","sha":"b","ecosystem":"npm","added":"2026-05-01","reason":"real warn"},
  "infra-pkg":{"version":"1.0.0","sha":"d","ecosystem":"npm","added":"2026-06-15","reason":"socket down"}
}}
JSON
run_review --digest >/dev/null 2>&1
[[ ! -f "$note" ]] || fail "digest note written with nothing actionable"
pass "no digest note when nothing actionable"

printf 'host-allow review: all cases passed\n'
