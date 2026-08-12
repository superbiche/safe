#!/usr/bin/env bash
# Scanner resolution and scratch-directory lifecycle.
#
# Two defects motivate this suite, and both were silent:
#
#   - A scanner that does not RESOLVE is reported missing, and a missing
#     scanner degrades the verdict to WARN. Callers with a trimmed PATH —
#     agents, CI steps, `bash -c` children, Makefiles — resolved none of the
#     scanners installed outside ~/.local/bin, so every verdict they saw was
#     degraded, and a degraded verdict is indistinguishable from a finding.
#     Worse, a detection run from such an environment REWROTE the machine's
#     tool cache to nulls, so the degradation outlived the session that
#     caused it.
#   - Seven scan paths created a scratch directory and never removed it. The
#     leak was unbounded: 1382 orphaned scratches accumulated on one
#     workstation, scanner bundles among them at hundreds of megabytes, until
#     /tmp hit its quota and every suite failed at once.
#
# Hermetic: no network, no real scanners, every tool a stub.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SAFE_AUDIT="$ROOT/bin/safe-audit"

PASS_COUNT=0
FAIL_COUNT=0
pass() { printf 'ok - %s\n' "$*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { printf 'not ok - %s\n' "$*" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }

TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT

# The resolver's last resort is a list of standard install directories under
# $HOME. Pointing HOME at an empty tree is what keeps this suite hermetic:
# without it, the real ~/.local/bin/osv-scanner answers every lookup and the
# assertions pass for the wrong reason.
FAKE_HOME="$TEST_ROOT/home"
mkdir -p "$FAKE_HOME/.local/bin"

# A scanner installed somewhere a trimmed PATH will not look.
OFFPATH_BIN="$TEST_ROOT/offpath"
mkdir -p "$OFFPATH_BIN"
cat > "$OFFPATH_BIN/osv-scanner" <<'STUB'
#!/usr/bin/env bash
printf '{"results":[]}\n'
STUB
chmod +x "$OFFPATH_BIN/osv-scanner"

# A different build of the same scanner, this one reachable on PATH.
ONPATH_BIN="$TEST_ROOT/onpath"
mkdir -p "$ONPATH_BIN"
cp "$OFFPATH_BIN/osv-scanner" "$ONPATH_BIN/osv-scanner"

# Sourcing the dispatcher gives direct access to the resolver. `set -- --version`
# keeps main() from doing anything on load.
resolve_in() {
  local config_dir="$1" tool="$2" path_value="$3"
  PATH="$path_value" \
  HOME="$FAKE_HOME" \
  SAFE_AUDIT_CONFIG_DIR="$config_dir" \
  SAFE_AUDIT_DATA_DIR="$TEST_ROOT/data" \
  SAFE_AUDIT_PATH="$SAFE_AUDIT" \
  TOOL="$tool" \
    bash -c 'set -- --version; source "$SAFE_AUDIT_PATH" >/dev/null; resolve_local_tool "$TOOL"'
}

write_tool_cache() {
  local config_dir="$1" tool="$2" tool_path="$3"
  mkdir -p "$config_dir"
  printf '{"local":{"%s":"%s"}}\n' "$tool" "$tool_path" > "$config_dir/tools.json"
}

# --- resolution order -------------------------------------------------------

case_trimmed_path_resolves_through_the_tool_cache() {
  local config_dir="$TEST_ROOT/config-trimmed"
  write_tool_cache "$config_dir" "osv-scanner" "$OFFPATH_BIN/osv-scanner"
  local got
  got="$(resolve_in "$config_dir" osv-scanner "/usr/bin:/bin")"
  if [[ "$got" == "$OFFPATH_BIN/osv-scanner" ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (got '${got:-<empty>}')"
  fi
}

case_caller_path_wins_over_the_tool_cache() {
  # PATH order is the caller's expressed preference: a mise shim, a test mock
  # or a project-local build must not be overridden by a cached absolute path.
  local config_dir="$TEST_ROOT/config-pathwins"
  write_tool_cache "$config_dir" "osv-scanner" "$OFFPATH_BIN/osv-scanner"
  local got
  got="$(resolve_in "$config_dir" osv-scanner "$ONPATH_BIN:/usr/bin:/bin")"
  if [[ "$got" == "$ONPATH_BIN/osv-scanner" ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (got '${got:-<empty>}')"
  fi
}

case_stale_cache_entry_is_not_returned() {
  # A cached path that no longer exists must not be handed to a scan: an
  # unexecutable path is not coverage.
  local config_dir="$TEST_ROOT/config-stale"
  write_tool_cache "$config_dir" "osv-scanner" "$TEST_ROOT/removed/osv-scanner"
  local got
  got="$(resolve_in "$config_dir" osv-scanner "/usr/bin:/bin")"
  if [[ -z "$got" ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (got '$got')"
  fi
}

case_unknown_tool_resolves_to_nothing() {
  local config_dir="$TEST_ROOT/config-unknown"
  mkdir -p "$config_dir"
  printf '{}\n' > "$config_dir/tools.json"
  local got
  got="$(resolve_in "$config_dir" osv-scanner "/usr/bin:/bin")"
  if [[ -z "$got" ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (got '$got')"
  fi
}

# --- detection must not downgrade a working cache ---------------------------

case_detection_keeps_a_still_valid_cached_path() {
  # The regression this guards: one probe from a trimmed environment rewrote
  # the machine's cache to nulls, and every later scan on that machine
  # reported the scanners missing until someone refreshed by hand.
  local config_dir="$TEST_ROOT/config-nodowngrade"
  write_tool_cache "$config_dir" "osv-scanner" "$OFFPATH_BIN/osv-scanner"
  PATH="/usr/bin:/bin" \
  HOME="$FAKE_HOME" \
  SAFE_AUDIT_CONFIG_DIR="$config_dir" \
  SAFE_AUDIT_DATA_DIR="$TEST_ROOT/data" \
  SAFE_AUDIT_PATH="$SAFE_AUDIT" \
    bash -c 'set -- --version; source "$SAFE_AUDIT_PATH" >/dev/null; detect_machine_tools local 1' >/dev/null 2>&1 || true
  local kept
  kept="$(jq -r '.local["osv-scanner"] // ""' "$config_dir/tools.json")"
  if [[ "$kept" == "$OFFPATH_BIN/osv-scanner" ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (cache now '${kept:-null}')"
  fi
}

case_detection_drops_a_cached_path_that_is_gone() {
  # The other half: a tool that genuinely disappeared must stop being
  # reported as present, or the scan claims coverage it does not have.
  local config_dir="$TEST_ROOT/config-drop"
  local doomed="$TEST_ROOT/doomed/osv-scanner"
  mkdir -p "$(dirname "$doomed")"
  cp "$OFFPATH_BIN/osv-scanner" "$doomed"
  write_tool_cache "$config_dir" "osv-scanner" "$doomed"
  rm -rf "$(dirname "$doomed")"
  PATH="/usr/bin:/bin" \
  HOME="$FAKE_HOME" \
  SAFE_AUDIT_CONFIG_DIR="$config_dir" \
  SAFE_AUDIT_DATA_DIR="$TEST_ROOT/data" \
  SAFE_AUDIT_PATH="$SAFE_AUDIT" \
    bash -c 'set -- --version; source "$SAFE_AUDIT_PATH" >/dev/null; detect_machine_tools local 1' >/dev/null 2>&1 || true
  local kept
  kept="$(jq -r '.local["osv-scanner"] // "null"' "$config_dir/tools.json")"
  if [[ "$kept" == "null" ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (cache kept '$kept')"
  fi
}

# --- scratch lifecycle ------------------------------------------------------

# Counts scratch directories created inside an isolated TMPDIR, so the assertion
# cannot be confused by anything else on the machine.
scratch_count() {
  find "$1" -mindepth 1 -maxdepth 1 -type d -name 'tmp.*' 2>/dev/null | wc -l | tr -d ' '
}

case_scratch_dirs_are_removed_on_success() {
  local tmpdir="$TEST_ROOT/tmp-success"
  mkdir -p "$tmpdir"
  TMPDIR="$tmpdir" \
  SAFE_AUDIT_PATH="$SAFE_AUDIT" \
    bash -c 'set -- --version
      source "$SAFE_AUDIT_PATH" >/dev/null
      install_process_cleanup_traps
      new_scratch_dir d; printf "x" > "$d/marker"
      new_scratch_dir e; printf "x" > "$e/marker"
      exit 0' >/dev/null 2>&1 || true
  local left
  left="$(scratch_count "$tmpdir")"
  if [[ "$left" == "0" ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME ($left left behind)"
  fi
}

case_scratch_dirs_are_removed_on_failure() {
  # The path that actually leaked in production: an early return or a die()
  # skipped every hand-written rm.
  local tmpdir="$TEST_ROOT/tmp-failure"
  mkdir -p "$tmpdir"
  TMPDIR="$tmpdir" \
  SAFE_AUDIT_PATH="$SAFE_AUDIT" \
    bash -c 'set -- --version
      source "$SAFE_AUDIT_PATH" >/dev/null
      install_process_cleanup_traps
      new_scratch_dir d; printf "x" > "$d/marker"
      die "simulated failure"' >/dev/null 2>&1 || true
  local left
  left="$(scratch_count "$tmpdir")"
  if [[ "$left" == "0" ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME ($left left behind)"
  fi
}

case_a_real_scan_leaves_no_scratch_behind() {
  local tmpdir="$TEST_ROOT/tmp-scan"
  local project="$TEST_ROOT/scan-project"
  mkdir -p "$tmpdir" "$project"
  printf '{"name":"p","version":"1.0.0","dependencies":{}}\n' > "$project/package.json"
  printf '{"name":"p","version":"1.0.0","lockfileVersion":3,"packages":{}}\n' > "$project/package-lock.json"

  local mockbin="$TEST_ROOT/scan-mockbin"
  mkdir -p "$mockbin"
  for tool in osv-scanner grype syft; do
    cat > "$mockbin/$tool" <<'STUB'
#!/usr/bin/env bash
case "$(basename -- "$0")" in
  osv-scanner) printf '{"results":[]}\n' ;;
  grype)       printf '{"matches":[]}\n' ;;
  syft)        printf '{"components":[],"metadata":{"tools":[{"name":"syft"}]}}\n' ;;
esac
exit 0
STUB
    chmod +x "$mockbin/$tool"
  done

  ( cd "$project" && TMPDIR="$tmpdir" PATH="$mockbin:$PATH" \
      SAFE_AUDIT_CONFIG_DIR="$TEST_ROOT/config-scan" \
      SAFE_AUDIT_DATA_DIR="$TEST_ROOT/data-scan" \
      "$SAFE_AUDIT" repo-audit . --deps-only --allow-missing-tools ) >/dev/null 2>&1 || true

  local left
  left="$(scratch_count "$tmpdir")"
  if [[ "$left" == "0" ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME ($left left behind)"
  fi
}

case_trimmed_path_resolves_through_the_tool_cache
case_caller_path_wins_over_the_tool_cache
case_stale_cache_entry_is_not_returned
case_unknown_tool_resolves_to_nothing
case_detection_keeps_a_still_valid_cached_path
case_detection_drops_a_cached_path_that_is_gone
case_scratch_dirs_are_removed_on_success
case_scratch_dirs_are_removed_on_failure
case_a_real_scan_leaves_no_scratch_behind

printf '\n%d passed, %d failed\n' "$PASS_COUNT" "$FAIL_COUNT"
[[ "$FAIL_COUNT" -eq 0 ]]
