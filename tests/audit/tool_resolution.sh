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

# --- a broken tools.json self-heals instead of poisoning every audit --------

source_and_run() {
  # Source the dispatcher against a given config dir and run one statement.
  local config_dir="$1" stmt="$2"
  HOME="$FAKE_HOME" \
  SAFE_AUDIT_CONFIG_DIR="$config_dir" \
  SAFE_AUDIT_DATA_DIR="$TEST_ROOT/data" \
  SAFE_AUDIT_PATH="$SAFE_AUDIT" \
  STMT="$stmt" \
    bash -c 'set -- --version; source "$SAFE_AUDIT_PATH" >/dev/null; eval "$STMT"' >/dev/null 2>&1 || true
}

case_tool_cache_set_persists_from_an_empty_cache() {
  # The live footgun: a 0-byte tools.json is not "missing", so the old seed
  # skipped it; tool_cache_set's jq then read zero documents, wrote an empty
  # file while exiting 0, and clobbered the cache back to empty — so detection
  # could never persist a scanner and every audit reported all scanners missing.
  local config_dir="$TEST_ROOT/config-empty-set"
  mkdir -p "$config_dir"
  : > "$config_dir/tools.json"   # 0 bytes: the poison
  source_and_run "$config_dir" \
    'tool_cache_set local "$(build_tool_entry_json /opt/osv "" "" "" "" "" "")"'
  if jq -e 'type == "object"' "$config_dir/tools.json" >/dev/null 2>&1 \
     && [[ "$(jq -r '.local["osv-scanner"] // ""' "$config_dir/tools.json")" == "/opt/osv" ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (tools.json='$(cat "$config_dir/tools.json")')"
  fi
}

case_empty_tools_file_normalizes_to_an_object() {
  local config_dir="$TEST_ROOT/config-empty-norm"
  mkdir -p "$config_dir"
  : > "$config_dir/tools.json"
  source_and_run "$config_dir" 'ensure_tools_file'
  if [[ "$(cat "$config_dir/tools.json")" == "{}" ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (tools.json='$(cat "$config_dir/tools.json")')"
  fi
}

case_garbage_and_array_tools_files_normalize_to_an_object() {
  # Garbage does not parse; `[]` parses but still breaks `.[$m] = $entry`.
  # `jq -e type=="object"` rejects both, so both self-heal.
  local ok=1 shape
  for shape in 'not json at all' '[]' '42' 'null'; do
    local config_dir="$TEST_ROOT/config-shape-$RANDOM"
    mkdir -p "$config_dir"
    printf '%s' "$shape" > "$config_dir/tools.json"
    source_and_run "$config_dir" 'ensure_tools_file'
    [[ "$(cat "$config_dir/tools.json")" == "{}" ]] || { ok=0; break; }
  done
  if [[ "$ok" == "1" ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (shape '$shape' left '$(cat "$config_dir/tools.json")')"
  fi
}

case_multi_document_tools_file_normalizes_to_a_single_object() {
  # A multi-document stream passes a naive `type=="object"` because jq bases -e
  # on the LAST document, so `[]\n{}` reads as an object. It must still
  # normalize: a two-object cache makes `.[$m]=$entry` apply to every document
  # and tool_cache_path emit two newline-joined paths, which fail the executable
  # check — the very scanner-missing symptom the guard exists to prevent.
  local config_dir="$TEST_ROOT/config-multidoc"
  mkdir -p "$config_dir"
  printf '[]\n{}\n' > "$config_dir/tools.json"
  source_and_run "$config_dir" 'ensure_tools_file'
  if [[ "$(cat "$config_dir/tools.json")" == "{}" ]] \
     && [[ "$(jq -s 'length' "$config_dir/tools.json" 2>/dev/null)" == "1" ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (tools.json='$(cat "$config_dir/tools.json")')"
  fi
}

case_tool_cache_set_over_a_multi_document_cache_stays_single() {
  # The write path must not perpetuate a stream: a `{}\n{}` cache would make jq
  # emit two objects and the output validator must reject that, not install it.
  local config_dir="$TEST_ROOT/config-multidoc-set"
  mkdir -p "$config_dir"
  printf '{}\n{}\n' > "$config_dir/tools.json"
  source_and_run "$config_dir" \
    'tool_cache_set local "$(build_tool_entry_json /opt/osv "" "" "" "" "" "")"'
  if [[ "$(jq -s 'length' "$config_dir/tools.json" 2>/dev/null)" == "1" ]] \
     && [[ "$(jq -r '.local["osv-scanner"] // ""' "$config_dir/tools.json" 2>/dev/null)" == "/opt/osv" ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (tools.json='$(cat "$config_dir/tools.json")')"
  fi
}

case_a_valid_tools_file_is_left_untouched() {
  # ensure_tools_file must never stomp a good cache.
  local config_dir="$TEST_ROOT/config-valid"
  mkdir -p "$config_dir"
  printf '{"local":{"osv-scanner":"/keep/me"}}\n' > "$config_dir/tools.json"
  source_and_run "$config_dir" 'ensure_tools_file'
  if [[ "$(jq -r '.local["osv-scanner"] // ""' "$config_dir/tools.json")" == "/keep/me" ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (tools.json='$(cat "$config_dir/tools.json")')"
  fi
}

# --- tools.json is SHARED state: replace it atomically, and rarely ----------
#
# Every gated build's repo-audit preflight refreshes detection, so tools.json
# has many concurrent writers and many concurrent readers. Two properties keep
# that survivable, and both are asserted below:
#
#   1. A replace is a rename WITHIN the config filesystem. Staging in $TMPDIR
#      (routinely a tmpfs) made `mv` a cross-device copy-then-unlink, and a
#      reader landing inside that window saw a truncated cache — which
#      ensure_tools_file then reset to `{}`, which read as "missing required
#      scanners", which failed the gate closed on scanners that were installed
#      the whole time.
#   2. The steady state does not write at all. Detection that reproduces the
#      cached entry skips the write, so the contended window is not even
#      entered on the runs that had nothing to say. This is rarity, not
#      absence: a machine whose PATH resolves a scanner elsewhere than the
#      cache holds differs on every scan, and writes on every scan.

SCAN_MOCKBIN="$TEST_ROOT/cache-scan-mockbin"
mkdir -p "$SCAN_MOCKBIN"
for tool in osv-scanner grype syft; do
  cat > "$SCAN_MOCKBIN/$tool" <<'STUB'
#!/usr/bin/env bash
case "$(basename -- "$0")" in
  osv-scanner) printf '{"results":[]}\n' ;;
  grype)       printf '{"matches":[]}\n' ;;
  syft)        printf '{"components":[],"metadata":{"tools":[{"name":"syft"}]}}\n' ;;
esac
exit 0
STUB
  chmod +x "$SCAN_MOCKBIN/$tool"
done

# A minimal npm project: enough evidence for a --deps-only scan to have work.
make_scan_project() {
  local project="$1"
  mkdir -p "$project"
  printf '{"name":"p","version":"1.0.0","dependencies":{}}\n' > "$project/package.json"
  printf '{"name":"p","version":"1.0.0","lockfileVersion":3,"packages":{}}\n' > "$project/package-lock.json"
}

run_hermetic_scan() {
  local config_dir="$1" project="$2"
  ( cd "$project" && HOME="$FAKE_HOME" PATH="$SCAN_MOCKBIN:$PATH" \
      SAFE_AUDIT_CONFIG_DIR="$config_dir" \
      SAFE_AUDIT_DATA_DIR="$TEST_ROOT/data-cache-scan" \
      "$SAFE_AUDIT" repo-audit . --deps-only --allow-missing-tools ) >/dev/null 2>&1 || true
}

case_an_unchanged_detection_does_not_rewrite_the_cache() {
  # The inode is the oracle: an atomic replace is a rename, which always
  # installs a NEW inode at the path. An unchanged inode after a second scan
  # is proof no replace happened — string-comparing the contents could not
  # tell a skipped write from a rewrite of identical bytes.
  local config_dir="$TEST_ROOT/config-idempotent"
  local project="$TEST_ROOT/idempotent-project"
  mkdir -p "$config_dir"
  make_scan_project "$project"

  run_hermetic_scan "$config_dir" "$project"
  local first_inode
  first_inode="$(stat -c '%i' "$config_dir/tools.json" 2>/dev/null || printf '')"

  run_hermetic_scan "$config_dir" "$project"
  local second_inode
  second_inode="$(stat -c '%i' "$config_dir/tools.json" 2>/dev/null || printf '')"

  if [[ -n "$first_inode" && "$first_inode" == "$second_inode" ]] \
     && jq -e -s 'length == 1 and (.[0] | type == "object")' "$config_dir/tools.json" >/dev/null 2>&1 \
     && [[ "$(jq -r '.local["osv-scanner"] // ""' "$config_dir/tools.json")" == "$SCAN_MOCKBIN/osv-scanner" ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (inode ${first_inode:-<none>} -> ${second_inode:-<none>}, cache='$(cat "$config_dir/tools.json" 2>/dev/null)')"
  fi
}

case_cache_write_stages_beside_the_cache_not_in_tmpdir() {
  # Where the staging file lands IS the fix, and a survivable oracle for it is
  # not "$TMPDIR ends up empty" — a bare `mktemp` + `mv` empties $TMPDIR too,
  # by moving the staged file out of it. Point $TMPDIR at a path that does not
  # exist instead: `mktemp` with no template cannot allocate there and the
  # write fails, while `mktemp "$CONFIG_DIR/..."` carries its own directory and
  # never consults $TMPDIR at all. A write that still lands is proof the
  # staging file was allocated beside the destination.
  local config_dir="$TEST_ROOT/config-stage-beside"
  mkdir -p "$config_dir"
  printf '{}\n' > "$config_dir/tools.json"

  TMPDIR="$TEST_ROOT/tmpdir-that-does-not-exist" \
  HOME="$FAKE_HOME" \
  SAFE_AUDIT_CONFIG_DIR="$config_dir" \
  SAFE_AUDIT_DATA_DIR="$TEST_ROOT/data" \
  SAFE_AUDIT_PATH="$SAFE_AUDIT" \
    bash -c 'set -- --version; source "$SAFE_AUDIT_PATH" >/dev/null
      tool_cache_set local "$(build_tool_entry_json /opt/osv "" "" "" "" "" "")"' \
    >/dev/null 2>&1 || true

  # And the staging file is consumed by the rename, never left beside the cache.
  local leftovers
  leftovers="$(find "$config_dir" -maxdepth 1 -name '.tools.json.*' 2>/dev/null | wc -l | tr -d ' ')"
  if [[ "$(jq -r '.local["osv-scanner"] // ""' "$config_dir/tools.json" 2>/dev/null)" == "/opt/osv" ]] \
     && [[ "$leftovers" == "0" ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME ($leftovers staging leftovers, cache='$(cat "$config_dir/tools.json" 2>/dev/null)')"
  fi
}

# --- an unreadable cache is breakage, never a missing scanner ---------------

# A directory where tools.json belongs defeats both recovery paths at once:
# jq cannot read it, and ensure_tools_file's `printf > file` reset cannot heal
# it. What is left is a cache that cannot be read — infrastructure to repair,
# and the one thing it must never be called is a missing scanner.
make_unreadable_tools_file() {
  local config_dir="$1"
  mkdir -p "$config_dir/tools.json"
}

case_an_unreadable_cache_refuses_as_breakage_not_missing_scanners() {
  # SAFE_AUDIT_NO_INIT keeps the startup ensure_dirs from refusing before the
  # decision seam is reached: this case is about what the seam DECIDES, not
  # about the startup guard (that is the e2e case below).
  local config_dir="$TEST_ROOT/config-unreadable-seam"
  make_unreadable_tools_file "$config_dir"

  local out rc=0
  out="$(HOME="$FAKE_HOME" \
    SAFE_AUDIT_NO_INIT=1 \
    SAFE_AUDIT_CONFIG_DIR="$config_dir" \
    SAFE_AUDIT_DATA_DIR="$TEST_ROOT/data" \
    SAFE_AUDIT_PATH="$SAFE_AUDIT" \
      bash -c 'set -- --version; source "$SAFE_AUDIT_PATH" >/dev/null
        confirm_scan_with_missing_tools local' 2>&1)" || rc=$?

  if (( rc != 0 )) \
     && [[ "$out" == *"audit-infrastructure breakage"* ]] \
     && [[ "$out" != *"missing required scanners"* ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (rc=$rc, out='$out')"
  fi
}

case_an_unreadable_cache_refuses_the_whole_scan() {
  # End to end: the startup normalizer cannot write `{}` over a directory
  # either, and an unguarded redirect would fail that with a raw shell error.
  # The refusal must be safe's own single line, in the infrastructure wording.
  #
  # The line COUNT is the assertion, not a substring. A substring check passes
  # just as happily on two lines as on one, and two lines is exactly the bug
  # this guards: `> "$FILE" 2>/dev/null` silences stderr only AFTER bash has
  # already tried to open the file and printed its own diagnostic, so the
  # refusal arrives as bash's "Is a directory" followed by safe's line. stderr
  # is captured on its own so the count means what it says.
  local config_dir="$TEST_ROOT/config-unreadable-e2e"
  local project="$TEST_ROOT/unreadable-project"
  local errfile="$TEST_ROOT/unreadable-e2e.err"
  make_unreadable_tools_file "$config_dir"
  make_scan_project "$project"

  local rc=0
  ( cd "$project" && HOME="$FAKE_HOME" PATH="$SCAN_MOCKBIN:$PATH" \
      SAFE_AUDIT_CONFIG_DIR="$config_dir" \
      SAFE_AUDIT_DATA_DIR="$TEST_ROOT/data-unreadable" \
      "$SAFE_AUDIT" repo-audit . --deps-only --allow-missing-tools ) \
    >/dev/null 2>"$errfile" || rc=$?

  local err lines
  err="$(cat "$errfile")"
  lines="$(wc -l < "$errfile" | tr -d ' ')"

  if (( rc != 0 )) \
     && [[ "$lines" == "1" ]] \
     && [[ "$err" == *"audit-infrastructure breakage"* ]] \
     && [[ "$err" != *"missing required scanners"* ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (rc=$rc, stderr lines=$lines, err='$err')"
  fi
}

case_the_shared_sbom_is_replaced_not_rewritten_in_place() {
  # The SBOM is shared per machine per day exactly like the result document,
  # and `safe audit diff` reads it. The inode is the oracle, same as for the
  # scanner cache: a `cp` onto the live path keeps the inode and fills the file
  # in place — which IS the window a reader can land in — while an atomic
  # publish renames a fully written file over it and always installs a new one.
  #
  # The scan cache is disabled: a replayed second scan never rebuilds the
  # result, so it would never republish the SBOM and the oracle would read a
  # skipped write as a preserved inode.
  local config_dir="$TEST_ROOT/config-sbom"
  local data_dir="$TEST_ROOT/data-sbom"
  local project="$TEST_ROOT/sbom-project"
  mkdir -p "$config_dir"
  make_scan_project "$project"

  local scan
  scan() {
    ( cd "$project" && HOME="$FAKE_HOME" PATH="$SCAN_MOCKBIN:$PATH" \
        SAFE_AUDIT_SCAN_NO_CACHE=1 \
        SAFE_AUDIT_CONFIG_DIR="$config_dir" \
        SAFE_AUDIT_DATA_DIR="$data_dir" \
        "$SAFE_AUDIT" repo-audit . --deps-only --allow-missing-tools ) >/dev/null 2>&1 || true
  }

  scan
  local sbom first_inode second_inode
  sbom="$(find "$data_dir/sbom" -maxdepth 2 -name '*-sbom.cdx.json' 2>/dev/null | head -n 1)"
  first_inode="$(stat -c '%i' "$sbom" 2>/dev/null || printf '')"

  scan
  second_inode="$(stat -c '%i' "$sbom" 2>/dev/null || printf '')"

  if [[ -n "$first_inode" && -n "$second_inode" && "$first_inode" != "$second_inode" ]] \
     && jq -e 'type == "object"' "$sbom" >/dev/null 2>&1; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (sbom='${sbom:-<none>}', inode ${first_inode:-<none>} -> ${second_inode:-<none>})"
  fi
}

case_an_absent_tool_still_reports_as_missing() {
  # The other half of the distinction: a cache that READS fine and simply does
  # not name the scanner is a genuinely missing scanner, and must keep taking
  # the missing-tools path rather than being upgraded to breakage.
  local config_dir="$TEST_ROOT/config-genuinely-missing"
  mkdir -p "$config_dir"
  printf '{"local":{}}\n' > "$config_dir/tools.json"

  local out rc=0
  out="$(HOME="$FAKE_HOME" \
    SAFE_AUDIT_NO_INIT=1 \
    SAFE_AUDIT_CONFIG_DIR="$config_dir" \
    SAFE_AUDIT_DATA_DIR="$TEST_ROOT/data" \
    SAFE_AUDIT_PATH="$SAFE_AUDIT" \
      bash -c 'set -- --version; source "$SAFE_AUDIT_PATH" >/dev/null
        confirm_scan_with_missing_tools local' 2>&1)" || rc=$?

  if (( rc == 2 )) \
     && [[ "$out" == *"missing required scanners"* ]] \
     && [[ "$out" != *"audit-infrastructure breakage"* ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (rc=$rc, out='$out')"
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
case_tool_cache_set_persists_from_an_empty_cache
case_empty_tools_file_normalizes_to_an_object
case_garbage_and_array_tools_files_normalize_to_an_object
case_multi_document_tools_file_normalizes_to_a_single_object
case_tool_cache_set_over_a_multi_document_cache_stays_single
case_a_valid_tools_file_is_left_untouched
case_an_unchanged_detection_does_not_rewrite_the_cache
case_cache_write_stages_beside_the_cache_not_in_tmpdir
case_an_unreadable_cache_refuses_as_breakage_not_missing_scanners
case_an_unreadable_cache_refuses_the_whole_scan
case_the_shared_sbom_is_replaced_not_rewritten_in_place
case_an_absent_tool_still_reports_as_missing
case_scratch_dirs_are_removed_on_success
case_scratch_dirs_are_removed_on_failure
case_a_real_scan_leaves_no_scratch_behind

printf '\n%d passed, %d failed\n' "$PASS_COUNT" "$FAIL_COUNT"
[[ "$FAIL_COUNT" -eq 0 ]]
