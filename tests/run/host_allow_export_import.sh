#!/usr/bin/env bash
# safe run host-allow export / import: fleet machine replication.
#
# Invariants under test:
#   - export is read-only (never seeds trust files on a bare machine) and
#     emits a schema-marked portable document with no secrets beyond the
#     public registry integrity hash.
#   - a real import is an operator-only trust escalation: non-TTY refuses with
#     exit 102 and names the verbatim command; the gate sits BEFORE any write.
#   - --dry-run is the read-only exception (runs non-TTY, writes nothing).
#   - import re-fetches integrity from the registry (never trusts the file's
#     sha over a divergent one) and never silently overwrites a divergent pin.
#   - wrong-schema files are refused crisply; invalid entries are skipped, not
#     fatal.

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

# Stub curl: the integrity re-fetch import performs. `fresh-pkg` and
# `keep-pkg` return an integrity that MATCHES the export file; `drift-pkg`
# returns one that DIFFERS (the export's sha is stale/mutated).
cat > "$tmp/bin/curl" <<'SH'
#!/usr/bin/env bash
url="${!#}"
case "$url" in
  *registry.npmjs.org/fresh-pkg/1.2.3)  printf '{"dist":{"integrity":"sha512-FRESH"}}\n' ;;
  *registry.npmjs.org/keep-pkg/4.5.6)   printf '{"dist":{"integrity":"sha512-KEEP"}}\n' ;;
  *registry.npmjs.org/drift-pkg/9.9.9)  printf '{"dist":{"integrity":"sha512-REGISTRY"}}\n' ;;
  *registry.npmjs.org/conflict-pkg/2.0.0) printf '{"dist":{"integrity":"sha512-TWO"}}\n' ;;
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

# --- export: populated -----------------------------------------------------
fresh_config
cat > "$tmp/config/host-allow.json" <<'JSON'
{"packages":{
  "fresh-pkg":{"version":"1.2.3","sha":"sha512-FRESH","ecosystem":"npm","added":"2026-07-01","reason":"machine-1 daily tool"},
  "keep-pkg":{"version":"4.5.6","sha":"sha512-KEEP","ecosystem":"npm","added":"2026-07-02","reason":"reviewed on machine 1"}
}}
JSON
out=$(run_safe_run host-allow export)
[[ "$(jq -r '.packages | keys | join(",")' <<<"$out")" == "fresh-pkg,keep-pkg" ]] || fail "export missing entries: $out"
[[ "$(jq -r '.packages["fresh-pkg"].reason' <<<"$out")" == "machine-1 daily tool" ]] || fail "export dropped reason"
[[ "$(jq -r '.packages["fresh-pkg"].sha' <<<"$out")" == "sha512-FRESH" ]] || fail "export dropped integrity"
pass "export dumps the populated allow set with reason + integrity"

# --- import --dry-run: read-only, runs non-TTY -----------------------------
fresh_config
printf '{"packages":{}}\n' > "$tmp/config/host-allow.json"
set +e
out=$(run_safe_run host-allow import "$tmp/export.json" --dry-run </dev/null 2>&1)
rc=$?
set -e
[[ "$rc" == "0" ]] || fail "dry-run must run non-TTY (got $rc): $out"
grep -q "would-add fresh-pkg@1.2.3" <<<"$out" || fail "dry-run must preview fresh-pkg: $out"
grep -q "would-add keep-pkg@4.5.6" <<<"$out" || fail "dry-run must preview keep-pkg: $out"
[[ "$(jq -r '.packages | length' "$tmp/config/host-allow.json")" == "0" ]] || fail "dry-run must write nothing"
pass "import --dry-run previews the delta non-TTY and writes nothing"

# --- import (real): non-TTY refuses with exit 102 --------------------------
fresh_config
printf '{"packages":{}}\n' > "$tmp/config/host-allow.json"
set +e
out=$(run_safe_run host-allow import "$tmp/export.json" </dev/null 2>&1)
rc=$?
set -e
[[ "$rc" == "102" ]] || fail "non-TTY real import must exit 102 (got $rc): $out"
grep -q "safe run host-allow import" <<<"$out" || fail "refusal must name the verbatim command: $out"
[[ "$(jq -r '.packages | length' "$tmp/config/host-allow.json")" == "0" ]] || fail "refused import must write nothing"
pass "real import refuses non-TTY with exit 102, writes nothing"

if command -v python3 >/dev/null 2>&1; then
  # --- import (real, TTY): re-fetches integrity, preserves reason ----------
  fresh_config
  printf '{"packages":{}}\n' > "$tmp/config/host-allow.json"
  cmd="SAFE_RUN_CONFIG_DIR='$tmp/config' SAFE_RUN_DATA_DIR='$tmp/data' SAFE_AUDIT_DATA_DIR='$tmp/audit-data' SAFE_RUN_NO_INIT=1 PATH='$tmp/bin':\$PATH '$SAFE_RUN' host-allow import '$tmp/export.json'"
  out=$(pty_run "$cmd" 2>&1) || fail "TTY import failed: $out"
  entry=$(jq -c '.packages["fresh-pkg"]' "$tmp/config/host-allow.json")
  [[ "$(jq -r '.version' <<<"$entry")" == "1.2.3" ]] || fail "import wrong version: $entry"
  [[ "$(jq -r '.sha' <<<"$entry")" == "sha512-FRESH" ]] || fail "import must store the registry-fetched sha: $entry"
  [[ "$(jq -r '.reason' <<<"$entry")" == "machine-1 daily tool" ]] || fail "import must preserve the reason: $entry"
  [[ "$(jq -r '.packages["keep-pkg"].version' "$tmp/config/host-allow.json")" == "4.5.6" ]] || fail "import dropped keep-pkg"
  pass "TTY import writes entries with the registry-fetched sha and the imported reason"

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

  # --- import: invalid entries skipped, valid ones still applied -----------
  fresh_config
  printf '{"packages":{}}\n' > "$tmp/config/host-allow.json"
  cat > "$tmp/mixed.json" <<'JSON'
{"schema":"safe-host-allow-export/1","exported":"2026-08-25","packages":{
  "fresh-pkg":{"version":"1.2.3","sha":"sha512-FRESH","ecosystem":"npm","added":"2026-07-01","reason":"valid"},
  "no-reason-pkg":{"version":"1.0.0","sha":"sha512-X","ecosystem":"npm","added":"2026-07-01","reason":""},
  "latest-pkg":{"version":"latest","sha":"sha512-Y","ecosystem":"npm","added":"2026-07-01","reason":"bad"},
  "weird-eco-pkg":{"version":"1.0.0","sha":"sha512-Z","ecosystem":"cobol","added":"2026-07-01","reason":"nope"}
}}
JSON
  cmd="SAFE_RUN_CONFIG_DIR='$tmp/config' SAFE_RUN_DATA_DIR='$tmp/data' SAFE_AUDIT_DATA_DIR='$tmp/audit-data' SAFE_RUN_NO_INIT=1 PATH='$tmp/bin':\$PATH '$SAFE_RUN' host-allow import '$tmp/mixed.json'"
  out=$(pty_run "$cmd" 2>&1) || fail "TTY mixed import failed: $out"
  [[ "$(jq -r '.packages | keys | join(",")' "$tmp/config/host-allow.json")" == "fresh-pkg" ]] || fail "only the valid entry should be written: $(jq -c .packages "$tmp/config/host-allow.json")"
  grep -q "no reason" <<<"$out" || fail "must explain the reason-less skip: $out"
  grep -q "non-pinned version" <<<"$out" || fail "must explain the latest skip: $out"
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
