#!/usr/bin/env bash
# scripts-allow: operator grant surface + gate-side npm 12 allow-scripts
# injection. The global ignore-scripts default must never change; grants are
# exact-identity; agents can never self-grant (TTY gate).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SAFE_RUN="$ROOT/bin/safe-run"
GATE_LIB="$ROOT/lib/gate-lib.sh"

pass() { printf 'ok - %s\n' "$*"; }
fail() { printf 'not ok - %s\n' "$*" >&2; exit 1; }

require() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

require bash
require jq

bash -n "$SAFE_RUN"
bash -n "$GATE_LIB"
pass "bash syntax"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/config" "$tmp/data" "$tmp/audit-data" "$tmp/bin"
printf '{"packages":{}}\n' > "$tmp/config/scripts-allow.json"

run_safe_run() {
  SAFE_RUN_CONFIG_DIR="$tmp/config" \
  SAFE_RUN_DATA_DIR="$tmp/data" \
  SAFE_AUDIT_DATA_DIR="$tmp/audit-data" \
  SAFE_RUN_NO_INIT=1 \
    "$SAFE_RUN" "$@"
}

# --- operator gate --------------------------------------------------------
set +e
out=$(run_safe_run scripts-allow add left-pad@1.3.0 </dev/null 2>&1)
rc=$?
set -e
[[ "$rc" == "102" ]] || fail "non-TTY add must exit 102 (got $rc)"
grep -q "interactive operator terminal" <<<"$out" || fail "non-TTY refusal not legible"
grep -q "scripts-allow add left-pad@1.3.0" <<<"$out" || fail "refusal must name the exact operator command"
pass "non-TTY add refused with exit 102 and the verbatim operator command"

# --- TTY flow (pty via python3) -------------------------------------------
pty_run() {
  # Runs a shell command on a real pty, feeding "y\n" as operator input.
  printf 'y\n' | python3 -c '
import pty, sys, os
status = pty.spawn(sys.argv[1:])
sys.exit(os.waitstatus_to_exitcode(status))
' bash -c "$1"
}

if command -v python3 >/dev/null 2>&1; then
  # Stubs: podman (audit preflight GO) and curl (registry version doc +
  # integrity fetch) — the add must show the scripts it authorizes.
  cat > "$tmp/bin/podman" <<'SH'
#!/usr/bin/env bash
case "$1" in
  image) exit 0 ;;
  run) printf '{"verdict":"GO"}\n' ;;
  *) exit 1 ;;
esac
SH
  cat > "$tmp/bin/curl" <<'SH'
#!/usr/bin/env bash
url="${!#}"
case "$url" in
  *registry.npmjs.org/left-pad/1.3.0)
    printf '{"name":"left-pad","version":"1.3.0","scripts":{"postinstall":"node fetch-binary.js","test":"tap"},"dist":{"integrity":"sha512-STUB"}}\n' ;;
  *) exit 22 ;;
esac
SH
  chmod +x "$tmp/bin/podman" "$tmp/bin/curl"

  add_cmd="SAFE_RUN_CONFIG_DIR='$tmp/config' SAFE_RUN_DATA_DIR='$tmp/data' SAFE_AUDIT_DATA_DIR='$tmp/audit-data' SAFE_RUN_NO_INIT=1 PATH='$tmp/bin':\$PATH '$SAFE_RUN' scripts-allow add left-pad@1.3.0 --reason 'needs binary fetch'"
  out=$(pty_run "$add_cmd" 2>&1) || fail "TTY add failed: $out"
  grep -q "postinstall: node fetch-binary.js" <<<"$out" || fail "add must display the scripts being authorized"
  grep -q "granted install scripts for left-pad@1.3.0" <<<"$out" || fail "add did not confirm the grant"

  entry=$(jq -c '.packages["left-pad"]' "$tmp/config/scripts-allow.json")
  [[ "$(jq -r '.version' <<<"$entry")" == "1.3.0" ]] || fail "grant entry version wrong: $entry"
  [[ "$(jq -r '.scripts.postinstall' <<<"$entry")" == "node fetch-binary.js" ]] || fail "grant must snapshot the reviewed scripts"
  [[ "$(jq -r '.scripts | has("test")' <<<"$entry")" == "false" ]] || fail "non-lifecycle scripts must not be stored"
  [[ "$(jq -r '.sha' <<<"$entry")" == "sha512-STUB" ]] || fail "grant entry missing integrity"
  pass "TTY add reviews scripts, snapshots them, records integrity"

  out=$(pty_run "SAFE_RUN_CONFIG_DIR='$tmp/config' SAFE_RUN_DATA_DIR='$tmp/data' SAFE_AUDIT_DATA_DIR='$tmp/audit-data' SAFE_RUN_NO_INIT=1 PATH='$tmp/bin':\$PATH '$SAFE_RUN' scripts-allow add left-pad@^1.3.0 --reason x" 2>&1) && \
    fail "range spec must be rejected"
  grep -q "exact version" <<<"$out" || fail "range rejection not legible: $out"
  pass "range/tag specs rejected (exact identity only)"
else
  printf 'SKIP - python3 unavailable; TTY add flow untested\n'
  jq -n '{packages:{"left-pad":{version:"1.3.0",sha:"sha512-STUB",ecosystem:"npm",added:"2026-08-03",reason:"seeded",scripts:{postinstall:"node fetch-binary.js"}}}}' \
    > "$tmp/config/scripts-allow.json"
fi

# --- list / remove --------------------------------------------------------
out=$(run_safe_run scripts-allow list)
grep -q "left-pad@1.3.0" <<<"$out" || fail "list missing entry"
grep -q "postinstall" <<<"$out" || fail "list must show which scripts were reviewed"
grep -q "ignore-scripts default never changes" <<<"$out" || fail "list missing invariant note"
pass "list shows entry with reviewed scripts"

run_safe_run scripts-allow remove left-pad >/dev/null 2>&1
[[ "$(jq -r '.packages | length' "$tmp/config/scripts-allow.json")" == "0" ]] || fail "remove did not delete entry"
pass "remove deletes the grant"

# --- gate injection -------------------------------------------------------
jq -n '{packages:{
  "opencode-ai":{version:"0.5.0",sha:"s",ecosystem:"npm",added:"2026-08-03",reason:"platform binary",scripts:{postinstall:"node install.js"}},
  "sharp":{version:"0.34.0",sha:"s2",ecosystem:"npm",added:"2026-08-03",reason:"native dep",scripts:{install:"node-gyp"}}
}}' > "$tmp/config/scripts-allow.json"

make_npm_stub() {
  local version="$1"
  cat > "$tmp/bin/npm" <<SH
#!/usr/bin/env bash
if [[ "\$1" == "--version" ]]; then printf '%s\n' "$version"; exit 0; fi
{
  printf 'args=%s\n' "\$*"
  printf 'ignore_scripts=%s\n' "\${npm_config_ignore_scripts:-unset}"
  printf 'allow_scripts=%s\n' "\${npm_config_allow_scripts:-unset}"
  printf 'strict=%s\n' "\${npm_config_strict_allow_scripts:-unset}"
} > "$tmp/npm-invocation.log"
SH
  chmod +x "$tmp/bin/npm"
}

run_gate() {
  # No safe-audit on PATH: the gate warns and proceeds, which is exactly the
  # path that must still perform the scripts-env injection.
  PATH="$tmp/bin:/usr/bin:/bin" \
  SAFE_RUN_CONFIG_DIR="$tmp/config" \
  SAFE_RUN_DATA_DIR="$tmp/data" \
    bash -c "source '$GATE_LIB'; safe_gate_main npm \"\$@\"" gate "$@"
}

make_npm_stub 12.0.2
rm -f "$tmp/npm-invocation.log"
run_gate install -g opencode-ai@0.5.0 >/dev/null 2>&1 || true
[[ -f "$tmp/npm-invocation.log" ]] || fail "gate did not exec npm"
grep -q '^ignore_scripts=false$' "$tmp/npm-invocation.log" || fail "injection missing ignore_scripts=false: $(cat "$tmp/npm-invocation.log")"
grep -q '^allow_scripts=opencode-ai@0.5.0,sharp@0.34.0$' "$tmp/npm-invocation.log" || fail "allow list must carry every granted identity: $(cat "$tmp/npm-invocation.log")"
grep -q '^strict=true$' "$tmp/npm-invocation.log" || fail "strict mode not set"
pass "exact grant match injects npm 12 allow-scripts (strict, full grant list)"

rm -f "$tmp/npm-invocation.log"
err_out=$( (run_gate install -g opencode-ai >/dev/null) 2>&1 ) || true
grep -q '^ignore_scripts=unset$' "$tmp/npm-invocation.log" || fail "bare name must not inject: $(cat "$tmp/npm-invocation.log")"
grep -q "pinned to opencode-ai@0.5.0" <<<"$err_out" || fail "bare-name install must hint the pinned grant"
pass "unpinned spec gets the pinned-grant hint, no injection"

rm -f "$tmp/npm-invocation.log"
run_gate install -g left-pad@9.9.9 >/dev/null 2>&1 || true
grep -q '^ignore_scripts=unset$' "$tmp/npm-invocation.log" || fail "ungranted package must not inject"
pass "no grant, no injection"

make_npm_stub 11.6.1
rm -f "$tmp/npm-invocation.log"
err_out=$( (run_gate install -g opencode-ai@0.5.0 >/dev/null) 2>&1 ) || true
grep -q '^ignore_scripts=unset$' "$tmp/npm-invocation.log" || fail "npm 11 must not receive injection"
grep -q "needs >= 12" <<<"$err_out" || fail "npm 11 fallback message missing"
pass "npm < 12: no injection, legible fallback"

printf 'scripts-allow: all cases passed\n'
