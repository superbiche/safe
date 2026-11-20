#!/usr/bin/env bash
# `safe install --host --manager npm` extracts the packages to audit on its own, before the gate (bin/safe,
# safe_install_npm_packages), and then hands the command to the gate (safe_gate_dispatch). The extraction reads
# `--flag=word` as a flag with no operand, as npm does NOT for a Boolean flag (it leaves `word` a package). This suite
# shows the command cannot reach npm with a package nobody audited: every form either is refused by the gate, or
# reaches npm only after the gate audited the package npm would fetch (ticket 1675, review item 10).
set -uo pipefail

# SAFE_TEST_ISOLATION_MARKER: every suite owns a scratch HOME and safe state.
# shellcheck disable=SC1091
# shellcheck source=tests/lib/test-isolation.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/test-isolation.sh"
safe_test_setup_isolation || exit 1
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
pass() { printf 'ok - %s\n' "$*"; }
fail() { printf 'not ok - %s\n' "$*" >&2; exit 1; }

tmp="$(mktemp -d)"
safe_test_compose_exit_trap "rm -rf \"\$tmp\""
export ROOT tmp
mkdir -p "$tmp/bin" "$tmp/project"
printf '#!/usr/bin/env bash\nexit 0\n' > "$tmp/bin/npm"
chmod +x "$tmp/bin/npm"
export PATH="$tmp/bin:$PATH"
printf '{"name":"host-extraction","version":"1.0.0"}\n' > "$tmp/project/package.json"

# the gate library, then its effects stubbed (bin/safe sources the library again inside cmd_install)
{
  printf 'source "%s/lib/gate-lib.sh"\n' "$ROOT"
  cat <<'STUBS'
safe_gate_check() { printf 'AUDIT %s\n' "$1" >> "$tmp/rec"; return 0; }
safe_gate_check_many() { shift; local p; for p in "$@"; do printf 'AUDIT %s\n' "$p" >> "$tmp/rec"; done; return 0; }
safe_gate_scan_project() { return 0; }
safe_gate_private_npm_project() { return 0; }
safe_gate_project_lane_enabled() { return 1; }
safe_gate_npm_scripts_env() { return 0; }
safe_gate_err() { printf '%s\n' "$*" >> "$tmp/err"; }
safe_gate_exec_real() { printf 'DELEGATE %s\n' "$*" >> "$tmp/rec"; exit 0; }
STUBS
} > "$tmp/gate-lib-stubbed.sh"

# $1.. the arguments of `safe install --host --yes`; the record is $tmp/rec: EXTRACT (audited by bin/safe before the
# gate), AUDIT (audited by the gate), DELEGATE (npm was run, with these arguments); the status is in $tmp/rc.
run_install() {
  : > "$tmp/rec"; rm -f "$tmp/rc"
  printf '%s\0' "$@" > "$tmp/args"
  bash <<'INNER'
source <(sed '/^argv0=/,$d' "$ROOT/bin/safe")
source "$ROOT/lib/gate-lib.sh"
set +e
cd "$tmp/project" || exit 1
mapfile -d "" -t ARGS < "$tmp/args"
gate_lib_path() { printf '%s' "$tmp/gate-lib-stubbed.sh"; }
safe_install_gate_log() { :; }
safe_install_trustable_package() { return 1; }
safe_install_audit_package() { printf "EXTRACT %s\n" "$1" >> "$tmp/rec"; return 0; }
safe_install_scan_target_flags() { :; }
rc=0
( cmd_install --host --yes "${ARGS[@]}" ) >/dev/null 2>"$tmp/stderr" || rc=$?
printf '%s' "$rc" > "$tmp/rc"
exit 0
INNER
}

# every package npm would fetch must be audited (by the gate) whenever npm is run
check() {
  local label="$1" want="$2"; shift 2
  run_install "$@"
  if grep -q '^DELEGATE ' "$tmp/rec"; then
    grep -q "^AUDIT ${want}\$" "$tmp/rec" || fail "$label: npm was run and '${want}' was not audited by the gate ($(tr '\n' ';' < "$tmp/rec"))"
    pass "$label: npm is run only after the gate audited ${want}"
  else
    [[ "$(cat "$tmp/rc" 2>/dev/null)" != 0 ]] || fail "$label: neither refused nor run ($(tr "\n" ";" < "$tmp/rec") $(head -c 300 "$tmp/stderr"))"
    pass "$label: refused (status $(cat "$tmp/rc")) and npm was not run"
  fi
}

for flag in ignore-scripts save save-dev save-exact dry-run force legacy-peer-deps no-audit; do
  check "--${flag}=evilpkg" evilpkg "--${flag}=evilpkg"
  # with a package the extraction does see, the gate must still audit the one it does not
  check "--${flag}=evilpkg okpkg" evilpkg "--${flag}=evilpkg" okpkg
done
# npm has no `--filter`: a name it does not know leaves the word after it a package (the extraction skips it as pnpm's)
check "--filter sample@1.0.0" sample@1.0.0 --filter sample@1.0.0
check "--filter sample@1.0.0 okpkg" sample@1.0.0 --filter sample@1.0.0 okpkg
check "--workspace=a evilpkg" evilpkg --workspace=a evilpkg
