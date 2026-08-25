#!/usr/bin/env bash
# safe run host-allow export / import: fleet machine replication.
#
# Invariants under test:
#   - export is read-only (never seeds trust files on a bare machine), projects
#     ONLY the declared portable fields (no legacy-key leak), and fails loudly
#     on a malformed local trust file.
#   - a real import is an operator-only trust escalation: non-TTY refuses with
#     exit 102, names an import-specific replayable command (no bogus --reason),
#     and the gate sits BEFORE any write OR state initialization.
#   - --dry-run is the read-only exception (runs non-TTY, seeds nothing).
#   - import only writes entries whose EXACT version verifies against the
#     registry: source specs / ranges / tags / unverifiable / divergent-sha
#     entries are skipped, never written on faith.
#   - import never overwrites a divergent local pin, preserves the original
#     grant date on a round trip, and skips malformed shapes without aborting
#     after a partial write.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SAFE_RUN="$ROOT/bin/safe-run"

pass() { printf 'ok - %s\n' "$*"; }
fail() { printf 'not ok - %s\n' "$*" >&2; exit 1; }

require() { command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"; }

require bash
require jq

bash -n "$SAFE_RUN"
pass "bash syntax"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/bin"

# Stub curl: the integrity re-fetch import performs. Known versions return an
# integrity; `drift-pkg` returns one that DIFFERS from the export file; any
# other URL 404s (curl -f exit 22 => registry_integrity returns empty).
# The registry echoes back the resolved .version; import requires it to equal
# the requested one. `range-pkg/1.x` resolves to a DIFFERENT version (as a
# range would), so import must reject it despite a 200 response.
cat > "$tmp/bin/curl" <<'SH'
#!/usr/bin/env bash
url="${!#}"
case "$url" in
  *registry.npmjs.org/fresh-pkg/1.2.3)    printf '{"version":"1.2.3","dist":{"integrity":"sha512-FRESH"}}\n' ;;
  *registry.npmjs.org/keep-pkg/4.5.6)     printf '{"version":"4.5.6","dist":{"integrity":"sha512-KEEP"}}\n' ;;
  *registry.npmjs.org/drift-pkg/9.9.9)    printf '{"version":"9.9.9","dist":{"integrity":"sha512-REGISTRY"}}\n' ;;
  *registry.npmjs.org/conflict-pkg/2.0.0) printf '{"version":"2.0.0","dist":{"integrity":"sha512-TWO"}}\n' ;;
  *registry.npmjs.org/range-pkg/1.x)      printf '{"version":"1.9.9","dist":{"integrity":"sha512-RANGE"}}\n' ;;
  *pypi.org/pypi/epoch-pkg/1!2.0/json)    printf '{"info":{"version":"1!2.0"},"urls":[{"digests":{"sha256":"DEADBEEF"}}]}\n' ;;
  *) exit 22 ;;
esac
SH
chmod +x "$tmp/bin/curl"

# A machine-1 export document (as `export` would emit it).
cat > "$tmp/export.json" <<'JSON'
{
  "schema": "safe-host-allow-export/1",
  "exported": "2026-08-25",
  "packages": {
    "fresh-pkg": {"version":"1.2.3","sha":"sha512-FRESH","ecosystem":"npm","added":"2026-07-01","reason":"machine-1 daily tool"},
    "keep-pkg":  {"version":"4.5.6","sha":"sha512-KEEP","ecosystem":"npm","added":"2026-07-02","reason":"reviewed on machine 1"}
  }
}
JSON

fresh_config() { rm -rf "$tmp/config"; mkdir -p "$tmp/config"; }

run_safe_run() {
  # NO_INIT so we control the config-dir state per case.
  SAFE_RUN_CONFIG_DIR="$tmp/config" \
  SAFE_RUN_DATA_DIR="$tmp/data" \
  SAFE_AUDIT_DATA_DIR="$tmp/audit-data" \
  SAFE_RUN_NO_INIT=1 \
  PATH="$tmp/bin:$PATH" \
    "$SAFE_RUN" "$@"
}

# python3 pty wrapper so a real import can satisfy the TTY gate.
pty_run() {
  python3 -c '
import pty, sys, os
status = pty.spawn(sys.argv[1:])
sys.exit(os.waitstatus_to_exitcode(status))
' bash -c "$1"
}

# --- export: read-only on a bare machine ----------------------------------
# NO_INIT unset so ensure_dirs would run for a non-exempt path; export is
# exempt, so it must read-only-report and seed nothing.
rm -rf "$tmp/config"
out=$(SAFE_RUN_CONFIG_DIR="$tmp/config" SAFE_RUN_DATA_DIR="$tmp/data" \
      SAFE_AUDIT_DATA_DIR="$tmp/audit-data" PATH="$tmp/bin:$PATH" \
      "$SAFE_RUN" host-allow export)
[[ "$(jq -r '.schema' <<<"$out")" == "safe-host-allow-export/1" ]] || fail "export schema wrong: $out"
[[ "$(jq -r '.packages | length' <<<"$out")" == "0" ]] || fail "bare export should be empty: $out"
[[ ! -e "$tmp/config/host-allow.json" ]] || fail "export must not seed trust files (read-only)"
pass "export on a bare machine is read-only and emits an empty schema doc"

# --- export: populated, projects ONLY declared fields (F3) -----------------
fresh_config
cat > "$tmp/config/host-allow.json" <<'JSON'
{"packages":{
  "fresh-pkg":{"version":"1.2.3","sha":"sha512-FRESH","ecosystem":"npm","added":"2026-07-01","reason":"machine-1 daily tool","behavioral_ack":"legacy-secretish"},
  "keep-pkg":{"version":"4.5.6","sha":"sha512-KEEP","ecosystem":"npm","added":"2026-07-02","reason":"reviewed on machine 1"}
}}
JSON
out=$(run_safe_run host-allow export)
[[ "$(jq -r '.packages | keys | join(",")' <<<"$out")" == "fresh-pkg,keep-pkg" ]] || fail "export missing entries: $out"
[[ "$(jq -r '.packages["fresh-pkg"].reason' <<<"$out")" == "machine-1 daily tool" ]] || fail "export dropped reason"
[[ "$(jq -r '.packages["fresh-pkg"].sha' <<<"$out")" == "sha512-FRESH" ]] || fail "export dropped integrity"
[[ "$(jq -r '.packages["fresh-pkg"] | has("behavioral_ack")' <<<"$out")" == "false" ]] || fail "export must not leak undeclared fields"
[[ "$(jq -r '.packages["fresh-pkg"] | keys | join(",")' <<<"$out")" == "added,ecosystem,reason,sha,version" ]] || fail "export must project exactly the 5 declared fields: $(jq -c '.packages["fresh-pkg"]' <<<"$out")"
pass "export projects only the declared fields (no legacy-key leak)"

# --- export: malformed local trust file fails loudly (F3) ------------------
fresh_config
printf '{"packages":7}\n' > "$tmp/config/host-allow.json"
set +e
out=$(run_safe_run host-allow export 2>&1)
rc=$?
set -e
[[ "$rc" != "0" ]] || fail "malformed host-allow file must fail export, not export empty"
grep -q "malformed" <<<"$out" || fail "malformed-source error not legible: $out"
# Boolean .packages must not slip through a `// {}` fallback as an empty export.
printf '{"packages":false}\n' > "$tmp/config/host-allow.json"
set +e
out=$(run_safe_run host-allow export 2>&1)
rc=$?
set -e
[[ "$rc" != "0" ]] || fail "boolean .packages must fail export, not export empty"
grep -q "malformed" <<<"$out" || fail "boolean-source error not legible: $out"
pass "export refuses a malformed local trust file (scalar and boolean) instead of emitting empty"

# --- import --dry-run: read-only, runs non-TTY, seeds nothing (F5) ---------
rm -rf "$tmp/bare"
set +e
out=$(SAFE_RUN_CONFIG_DIR="$tmp/bare/config" SAFE_RUN_DATA_DIR="$tmp/bare/data" \
      SAFE_AUDIT_DATA_DIR="$tmp/bare/audit" PATH="$tmp/bin:$PATH" \
      "$SAFE_RUN" host-allow import "$tmp/export.json" --dry-run </dev/null 2>&1)
rc=$?
set -e
[[ "$rc" == "0" ]] || fail "dry-run must run non-TTY (got $rc): $out"
grep -q "would-add fresh-pkg@1.2.3" <<<"$out" || fail "dry-run must preview fresh-pkg: $out"
grep -q "would-add keep-pkg@4.5.6" <<<"$out" || fail "dry-run must preview keep-pkg: $out"
[[ ! -e "$tmp/bare/config" ]] || fail "dry-run on a bare machine must seed nothing (found $tmp/bare/config)"
pass "import --dry-run previews the delta non-TTY and seeds no state on a bare machine"

# --- import (real): non-TTY refuses with exit 102, seeds nothing (F5/F6) ---
rm -rf "$tmp/bare"
set +e
out=$(SAFE_RUN_CONFIG_DIR="$tmp/bare/config" SAFE_RUN_DATA_DIR="$tmp/bare/data" \
      SAFE_AUDIT_DATA_DIR="$tmp/bare/audit" PATH="$tmp/bin:$PATH" \
      "$SAFE_RUN" host-allow import "$tmp/export.json" </dev/null 2>&1)
rc=$?
set -e
[[ "$rc" == "102" ]] || fail "non-TTY real import must exit 102 (got $rc): $out"
grep -q "safe run host-allow import" <<<"$out" || fail "refusal must name the import command: $out"
grep -q -- "--reason" <<<"$out" && fail "import refusal must NOT append --reason (import takes none): $out"
[[ ! -e "$tmp/bare/config" ]] || fail "refused non-TTY import must seed nothing"
pass "real import refuses non-TTY with exit 102, an import-specific hint, and seeds nothing"

# --- import (real): non-TTY refusal shell-quotes a spaced path (F6) --------
cp "$tmp/export.json" "$tmp/allow file.json"
set +e
out=$(run_safe_run host-allow import "$tmp/allow file.json" </dev/null 2>&1)
set -e
grep -qF "'$tmp/allow file.json'" <<<"$out" || grep -qF "$tmp/allow\ file.json" <<<"$out" \
  || fail "refusal must shell-quote a spaced path: $out"
pass "import refusal shell-quotes a path containing spaces"

if command -v python3 >/dev/null 2>&1; then
  # --- import (real, TTY): registry-fetched sha, preserved reason + date ---
  fresh_config
  printf '{"packages":{}}\n' > "$tmp/config/host-allow.json"
  cmd="SAFE_RUN_CONFIG_DIR='$tmp/config' SAFE_RUN_DATA_DIR='$tmp/data' SAFE_AUDIT_DATA_DIR='$tmp/audit-data' SAFE_RUN_NO_INIT=1 PATH='$tmp/bin':\$PATH '$SAFE_RUN' host-allow import '$tmp/export.json'"
  out=$(pty_run "$cmd" 2>&1) || fail "TTY import failed: $out"
  entry=$(jq -c '.packages["fresh-pkg"]' "$tmp/config/host-allow.json")
  [[ "$(jq -r '.version' <<<"$entry")" == "1.2.3" ]] || fail "import wrong version: $entry"
  [[ "$(jq -r '.sha' <<<"$entry")" == "sha512-FRESH" ]] || fail "import must store the registry-fetched sha: $entry"
  [[ "$(jq -r '.reason' <<<"$entry")" == "machine-1 daily tool" ]] || fail "import must preserve the reason: $entry"
  [[ "$(jq -r '.added' <<<"$entry")" == "2026-07-01" ]] || fail "import must preserve the original add date (F4): $entry"
  [[ "$(jq -r '.packages["keep-pkg"].version' "$tmp/config/host-allow.json")" == "4.5.6" ]] || fail "import dropped keep-pkg"
  pass "TTY import stores the registry sha, preserves the reason, and preserves the original add date"

  # --- import: a legal PEP440 epoch version is not falsely rejected (N1) ----
  fresh_config
  printf '{"packages":{}}\n' > "$tmp/config/host-allow.json"
  cat > "$tmp/epoch.json" <<'JSON'
{"schema":"safe-host-allow-export/1","exported":"2026-08-25","packages":{
  "epoch-pkg":{"version":"1!2.0","sha":"sha256-DEADBEEF","ecosystem":"python","added":"2026-07-01","reason":"epoch pin"}
}}
JSON
  cmd="SAFE_RUN_CONFIG_DIR='$tmp/config' SAFE_RUN_DATA_DIR='$tmp/data' SAFE_AUDIT_DATA_DIR='$tmp/audit-data' SAFE_RUN_NO_INIT=1 PATH='$tmp/bin':\$PATH '$SAFE_RUN' host-allow import '$tmp/epoch.json'"
  out=$(pty_run "$cmd" 2>&1) || fail "TTY epoch import failed: $out"
  [[ "$(jq -r '.packages["epoch-pkg"].version' "$tmp/config/host-allow.json")" == "1!2.0" ]] || fail "a legal PEP440 epoch pin must import: $out"
  [[ "$(jq -r '.packages["epoch-pkg"].sha' "$tmp/config/host-allow.json")" == "sha256-DEADBEEF" ]] || fail "epoch import must store the pypi-verified sha"
  pass "import accepts a legal PEP440 epoch version and verifies it against pypi"

  # --- import: a calendar-invalid date falls back to today (N2) -------------
  fresh_config
  printf '{"packages":{}}\n' > "$tmp/config/host-allow.json"
  cat > "$tmp/baddate.json" <<'JSON'
{"schema":"safe-host-allow-export/1","exported":"2026-08-25","packages":{
  "fresh-pkg":{"version":"1.2.3","sha":"sha512-FRESH","ecosystem":"npm","added":"2026-02-30","reason":"impossible date"}
}}
JSON
  cmd="SAFE_RUN_CONFIG_DIR='$tmp/config' SAFE_RUN_DATA_DIR='$tmp/data' SAFE_AUDIT_DATA_DIR='$tmp/audit-data' SAFE_RUN_NO_INIT=1 PATH='$tmp/bin':\$PATH '$SAFE_RUN' host-allow import '$tmp/baddate.json'"
  out=$(pty_run "$cmd" 2>&1) || fail "TTY bad-date import failed: $out"
  stored_date=$(jq -r '.packages["fresh-pkg"].added' "$tmp/config/host-allow.json")
  [[ "$stored_date" != "2026-02-30" ]] || fail "a calendar-invalid date must not be persisted"
  [[ "$stored_date" == "$(date -I)" ]] || fail "invalid date must fall back to today (got $stored_date)"
  pass "import rejects a calendar-invalid add date and stamps today instead"

  # --- import: a non-registry / non-exact spec never becomes a grant (F1) --
  fresh_config
  printf '{"packages":{}}\n' > "$tmp/config/host-allow.json"
  cat > "$tmp/evil.json" <<'JSON'
{"schema":"safe-host-allow-export/1","exported":"2026-08-25","packages":{
  "src-pkg":  {"version":"file:/tmp/attacker","sha":"sha512-x","ecosystem":"npm","added":"2026-07-01","reason":"looks reviewed"},
  "git-pkg":  {"version":"git+ssh://git@h/x.git","sha":"sha512-x","ecosystem":"npm","added":"2026-07-01","reason":"looks reviewed"},
  "caret-pkg":{"version":"^1.0.0","sha":"sha512-x","ecosystem":"npm","added":"2026-07-01","reason":"looks reviewed"},
  "tag-pkg":  {"version":"next","sha":"sha512-x","ecosystem":"npm","added":"2026-07-01","reason":"looks reviewed"},
  "range-pkg":{"version":"1.x","sha":"sha512-x","ecosystem":"npm","added":"2026-07-01","reason":"format-passes but registry resolves elsewhere"},
  "ghost-pkg":{"version":"1.0.0","sha":"sha512-x","ecosystem":"npm","added":"2026-07-01","reason":"exact but unknown to registry"}
}}
JSON
  cmd="SAFE_RUN_CONFIG_DIR='$tmp/config' SAFE_RUN_DATA_DIR='$tmp/data' SAFE_AUDIT_DATA_DIR='$tmp/audit-data' SAFE_RUN_NO_INIT=1 PATH='$tmp/bin':\$PATH '$SAFE_RUN' host-allow import '$tmp/evil.json'"
  out=$(pty_run "$cmd" 2>&1) || fail "TTY evil import failed: $out"
  [[ "$(jq -r '.packages | length' "$tmp/config/host-allow.json")" == "0" ]] || fail "no non-exact / unverifiable spec may be written: $(jq -c .packages "$tmp/config/host-allow.json")"
  grep -q "not an exact pinned version" <<<"$out" || fail "must reject non-exact versions: $out"
  grep -q "could not verify this version against the registry" <<<"$out" || fail "must skip an unverifiable exact version: $out"
  pass "import writes no source-spec, range, tag, or registry-unverifiable entry (F1)"

  # --- import: malformed shapes skipped, no partial-write abort (F2) -------
  fresh_config
  printf '{"packages":{}}\n' > "$tmp/config/host-allow.json"
  cat > "$tmp/scalar.json" <<'JSON'
{"schema":"safe-host-allow-export/1","exported":"2026-08-25","packages":7}
JSON
  set +e
  out=$(run_safe_run host-allow import "$tmp/scalar.json" --dry-run </dev/null 2>&1)
  rc=$?
  set -e
  [[ "$rc" != "0" ]] || fail "a scalar .packages must fail, not succeed empty"
  grep -q "malformed" <<<"$out" || fail "scalar .packages error not legible: $out"

  # A boolean .packages must not pass a `// {}` fallback as an empty import.
  printf '{"schema":"safe-host-allow-export/1","exported":"2026-08-25","packages":false}\n' > "$tmp/bool.json"
  set +e
  out=$(run_safe_run host-allow import "$tmp/bool.json" --dry-run </dev/null 2>&1)
  rc=$?
  set -e
  [[ "$rc" != "0" ]] || fail "a boolean .packages must fail, not succeed empty"
  grep -q "malformed" <<<"$out" || fail "boolean .packages error not legible: $out"

  cat > "$tmp/mixed-shape.json" <<'JSON'
{"schema":"safe-host-allow-export/1","exported":"2026-08-25","packages":{
  "a-good":"not-an-object",
  "fresh-pkg":{"version":"1.2.3","sha":"sha512-FRESH","ecosystem":"npm","added":"2026-07-01","reason":"valid after a bad sibling"}
}}
JSON
  cmd="SAFE_RUN_CONFIG_DIR='$tmp/config' SAFE_RUN_DATA_DIR='$tmp/data' SAFE_AUDIT_DATA_DIR='$tmp/audit-data' SAFE_RUN_NO_INIT=1 PATH='$tmp/bin':\$PATH '$SAFE_RUN' host-allow import '$tmp/mixed-shape.json'"
  out=$(pty_run "$cmd" 2>&1) || fail "TTY mixed-shape import must not abort: $out"
  grep -q "entry is not an object" <<<"$out" || fail "must explain the non-object skip: $out"
  [[ "$(jq -r '.packages | keys | join(",")' "$tmp/config/host-allow.json")" == "fresh-pkg" ]] || fail "the valid entry must still be applied (no partial-write abort): $(jq -c .packages "$tmp/config/host-allow.json")"
  pass "import fails loudly on a scalar envelope and skips a non-object entry without aborting"

  # --- import: never overwrites a divergent local pin ---------------------
  fresh_config
  cat > "$tmp/config/host-allow.json" <<'JSON'
{"packages":{"conflict-pkg":{"version":"1.0.0","sha":"sha512-ONE","ecosystem":"npm","added":"2026-06-01","reason":"local pin"}}}
JSON
  cat > "$tmp/conflict.json" <<'JSON'
{"schema":"safe-host-allow-export/1","exported":"2026-08-25","packages":{
  "conflict-pkg":{"version":"2.0.0","sha":"sha512-TWO","ecosystem":"npm","added":"2026-07-01","reason":"machine-1 newer"}
}}
JSON
  cmd="SAFE_RUN_CONFIG_DIR='$tmp/config' SAFE_RUN_DATA_DIR='$tmp/data' SAFE_AUDIT_DATA_DIR='$tmp/audit-data' SAFE_RUN_NO_INIT=1 PATH='$tmp/bin':\$PATH '$SAFE_RUN' host-allow import '$tmp/conflict.json'"
  out=$(pty_run "$cmd" 2>&1) || fail "TTY conflict import failed: $out"
  grep -q "CONFLICT conflict-pkg" <<<"$out" || fail "must report the conflict: $out"
  [[ "$(jq -r '.packages["conflict-pkg"].version' "$tmp/config/host-allow.json")" == "1.0.0" ]] || fail "import must not overwrite a divergent local pin"
  pass "import reports a divergent pin as a conflict and leaves the local entry untouched"

  # --- import: integrity mismatch is skipped loudly -----------------------
  fresh_config
  printf '{"packages":{}}\n' > "$tmp/config/host-allow.json"
  cat > "$tmp/drift.json" <<'JSON'
{"schema":"safe-host-allow-export/1","exported":"2026-08-25","packages":{
  "drift-pkg":{"version":"9.9.9","sha":"sha512-STALE","ecosystem":"npm","added":"2026-07-01","reason":"machine-1"}
}}
JSON
  cmd="SAFE_RUN_CONFIG_DIR='$tmp/config' SAFE_RUN_DATA_DIR='$tmp/data' SAFE_AUDIT_DATA_DIR='$tmp/audit-data' SAFE_RUN_NO_INIT=1 PATH='$tmp/bin':\$PATH '$SAFE_RUN' host-allow import '$tmp/drift.json'"
  out=$(pty_run "$cmd" 2>&1) || fail "TTY drift import failed: $out"
  grep -q "integrity mismatch" <<<"$out" || fail "must flag the integrity mismatch: $out"
  [[ "$(jq -r '.packages | length' "$tmp/config/host-allow.json")" == "0" ]] || fail "mismatched entry must not be written"
  pass "import skips an entry whose file sha diverges from the registry"

  # --- import: reason/ecosystem validation, valid entry applied -----------
  fresh_config
  printf '{"packages":{}}\n' > "$tmp/config/host-allow.json"
  cat > "$tmp/mixed.json" <<'JSON'
{"schema":"safe-host-allow-export/1","exported":"2026-08-25","packages":{
  "fresh-pkg":{"version":"1.2.3","sha":"sha512-FRESH","ecosystem":"npm","added":"2026-07-01","reason":"valid"},
  "no-reason-pkg":{"version":"1.0.0","sha":"sha512-X","ecosystem":"npm","added":"2026-07-01","reason":""},
  "weird-eco-pkg":{"version":"1.0.0","sha":"sha512-Z","ecosystem":"cobol","added":"2026-07-01","reason":"nope"}
}}
JSON
  cmd="SAFE_RUN_CONFIG_DIR='$tmp/config' SAFE_RUN_DATA_DIR='$tmp/data' SAFE_AUDIT_DATA_DIR='$tmp/audit-data' SAFE_RUN_NO_INIT=1 PATH='$tmp/bin':\$PATH '$SAFE_RUN' host-allow import '$tmp/mixed.json'"
  out=$(pty_run "$cmd" 2>&1) || fail "TTY mixed import failed: $out"
  [[ "$(jq -r '.packages | keys | join(",")' "$tmp/config/host-allow.json")" == "fresh-pkg" ]] || fail "only the valid entry should be written: $(jq -c .packages "$tmp/config/host-allow.json")"
  grep -q "no reason" <<<"$out" || fail "must explain the reason-less skip: $out"
  grep -q "unknown ecosystem" <<<"$out" || fail "must explain the ecosystem skip: $out"
  pass "import skips invalid entries with cause and applies the valid ones"
else
  printf 'SKIP - python3 unavailable; TTY import flows untested\n'
fi

# --- import: wrong schema refused crisply (before the TTY gate) ------------
fresh_config
printf '{"packages":{}}\n' > "$tmp/config/host-allow.json"
printf '{"packages":{"x":{"version":"1.0.0"}}}\n' > "$tmp/raw.json"
set +e
out=$(run_safe_run host-allow import "$tmp/raw.json" </dev/null 2>&1)
rc=$?
set -e
[[ "$rc" != "0" ]] || fail "wrong-schema import must fail"
grep -q "expected schema safe-host-allow-export/1" <<<"$out" || fail "schema refusal not legible: $out"
pass "import refuses a file without the export schema"

# --- import: missing file ---------------------------------------------------
set +e
out=$(run_safe_run host-allow import "$tmp/nope.json" </dev/null 2>&1)
rc=$?
set -e
[[ "$rc" != "0" ]] || fail "missing import file must fail"
grep -q "cannot read import file" <<<"$out" || fail "missing-file error not legible: $out"
pass "import refuses a missing file"

printf 'all host-allow export/import tests passed\n'
