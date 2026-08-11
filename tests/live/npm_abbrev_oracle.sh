#!/usr/bin/env bash
# LIVE suite — compares the shipped npm command/alias snapshot with the npm
# command source that safe's real delegate executes. This is read-only: npm
# only reports its global prefix and Node only imports cmd-list.js.
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
PASS=0
FAIL=0

pass() { printf 'ok - %s\n' "$1"; PASS=$((PASS + 1)); }
fail() { printf 'FAIL - %s\n' "$1"; FAIL=$((FAIL + 1)); }

# shellcheck source=/dev/null
source "$ROOT/lib/gate-lib.sh" >/dev/null 2>&1 || {
  printf 'FAIL - cannot source lib/gate-lib.sh\n'
  exit 1
}

real_npm="$(safe_gate_resolve_real npm 2>/dev/null || true)"
if [[ -z "$real_npm" ]]; then
  printf 'SKIP: no real (non-wrapper) npm available; live abbreviation oracle skipped\n'
  exit 0
fi
if ! command -v node >/dev/null 2>&1; then
  printf 'SKIP: node is unavailable; live abbreviation oracle skipped\n'
  exit 0
fi

prefix="$("$real_npm" prefix -g 2>/dev/null || true)"
cmd_list="${prefix%/}/lib/node_modules/npm/lib/utils/cmd-list.js"
if [[ ! -r "$cmd_list" ]]; then
  fail "npm command map is unavailable at the delegate's global prefix"
  printf '%s passed, %s failed\n' "$PASS" "$FAIL"
  exit 1
fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/safe-live-npm-abbrev.XXXXXX") || exit 1
trap 'rm -rf -- "$WORK"' EXIT

safe_gate_npm_dispatch_snapshot | LC_ALL=C sort > "$WORK/shipped"
if ! node - "$cmd_list" > "$WORK/installed" <<'NODE'
const { commands, aliases } = require(process.argv[2])
for (const command of commands) process.stdout.write(`command\t${command}\n`)
for (const [alias, target] of Object.entries(aliases)) {
  process.stdout.write(`alias\t${alias}\t${target}\n`)
}
NODE
then
  fail "installed npm cmd-list.js could not be read by Node"
elif diff -u "$WORK/shipped" <(LC_ALL=C sort "$WORK/installed"); then
  pass "shipped command and alias snapshot matches the real npm delegate"
else
  fail "npm command or alias map drifted; update the snapshot and classifier deliberately"
fi

printf '%s passed, %s failed\n' "$PASS" "$FAIL"
(( FAIL == 0 ))
