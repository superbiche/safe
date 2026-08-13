#!/usr/bin/env bash
# Ecosystem-audit normalization suite.
#
# Each of npm audit, pip-audit, composer audit, cargo-audit and govulncheck
# reports in its own shape, and those shapes decide a verdict: their counts
# feed `audit_totals`, which `safe install --project` refuses on. Two failure
# modes matter more than any others and both are asserted here:
#
#   - counting the wrong thing (pip-audit lists DEPENDENCIES, each carrying its
#     own `vulns`; counting the outer list makes every clean project a pile of
#     findings)
#   - reporting a broken scanner as a successful zero-finding scan, which is
#     indistinguishable from a clean project
#
# Hermetic: every scanner is a stub whose output this suite chooses.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SAFE_AUDIT="$ROOT/bin/safe-audit"

PASS_COUNT=0
FAIL_COUNT=0
pass() { printf 'ok - %s\n' "$*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { printf 'not ok - %s\n' "$*" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }

TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT

MOCKBIN="$TEST_ROOT/mockbin"
mkdir -p "$MOCKBIN"

# Core scanners: always clean, so every finding in this suite comes from an
# ecosystem audit and nowhere else.
for tool in osv-scanner grype syft; do
  cat > "$MOCKBIN/$tool" <<'STUB'
#!/usr/bin/env bash
case "$(basename -- "$0")" in
  osv-scanner) printf '{"results":[]}\n' ;;
  grype)       printf '{"matches":[]}\n' ;;
  syft)        printf '{"components":[],"metadata":{"tools":[{"name":"syft"}]}}\n' ;;
esac
exit 0
STUB
  chmod +x "$MOCKBIN/$tool"
done

# Ecosystem scanners: stdout comes from ${TOOL}_OUT, exit code from ${TOOL}_RC.
# Both `npm audit` and `pip-audit` exit nonzero when they FIND something, so a
# nonzero exit alone can never be read as failure.
for tool in npm pip-audit composer cargo-audit govulncheck; do
  cat > "$MOCKBIN/$tool" <<'STUB'
#!/usr/bin/env bash
name="$(basename -- "$0")"
var="$(printf '%s' "$name" | tr 'a-z-' 'A-Z_')"
out_var="${var}_OUT"
rc_var="${var}_RC"
printf '%s' "${!out_var:-}"
exit "${!rc_var:-0}"
STUB
  chmod +x "$MOCKBIN/$tool"
done
# `cargo audit` is invoked as `cargo audit`, with cargo-audit only probed for
# availability.
cat > "$MOCKBIN/cargo" <<'STUB'
#!/usr/bin/env bash
[[ "${1:-}" == "audit" ]] || exit 0
printf '%s' "${CARGO_AUDIT_OUT:-}"
exit "${CARGO_AUDIT_RC:-0}"
STUB
chmod +x "$MOCKBIN/cargo"

CASE_DIR=""; CASE_PROJECT=""; RESULT=""
prepare_case() {
  local name="$1"
  CASE_DIR="$TEST_ROOT/case-$name"
  CASE_PROJECT="$CASE_DIR/project"
  RESULT="$CASE_DIR/result.json"
  mkdir -p "$CASE_PROJECT" "$CASE_DIR/home" "$CASE_DIR/audit-config" "$CASE_DIR/audit-data"
}

# run_scan <env assignments...>
run_scan() {
  set +e
  (
    cd "$CASE_PROJECT" || exit 99
    env \
      HOME="$CASE_DIR/home" \
      PATH="$MOCKBIN:/usr/bin:/bin" \
      SAFE_AUDIT_CONFIG_DIR="$CASE_DIR/audit-config" \
      SAFE_AUDIT_DATA_DIR="$CASE_DIR/audit-data" \
      SAFE_AUDIT_SCAN_NO_CACHE=1 \
      "$@" \
      "$SAFE_AUDIT" repo-audit . --deps-only --result-out "$RESULT"
  ) > "$CASE_DIR/scan.out" 2>&1
  STATUS=$?
  set -e
}

# assert_jq <label> <jq program>
assert_jq() {
  local label="$1" program="$2"
  if [[ ! -s "$RESULT" ]]; then
    printf 'no result document; scan output:\n%s\n' "$(cat "$CASE_DIR/scan.out")" >&2
    fail "$label"
    return 1
  fi
  if ! jq -e "$program" "$RESULT" >/dev/null 2>&1; then
    printf 'assertion failed: %s\nresult:\n%s\n' "$program" \
      "$(jq -c '{verdict, audit_totals, ecosystem_audits}' "$RESULT")" >&2
    fail "$label"
    return 1
  fi
  return 0
}

case_pip_audit_clean_project_stays_clean() {
  prepare_case "pip-clean"
  printf 'requests==2.32.0\n' > "$CASE_PROJECT/requirements.txt"
  # Real pip-audit shape: one entry per DEPENDENCY, advisories under .vulns.
  run_scan PIP_AUDIT_OUT='[{"name":"requests","version":"2.32.0","vulns":[]},{"name":"idna","version":"3.7","vulns":[]}]'
  assert_jq "$FUNCNAME" '
    (.ecosystem_audits[] | select(.scanner == "pip-audit")
      | .status == "ok" and .total == 0 and .medium == 0)
    and (.audit_totals.critical == 0 and .audit_totals.medium == 0)
    and .verdict == "GO"
  ' || return
  pass "$FUNCNAME"
}

case_pip_audit_counts_advisories_not_dependencies() {
  prepare_case "pip-vulns"
  printf 'affected==1.0.0\n' > "$CASE_PROJECT/requirements.txt"
  run_scan PIP_AUDIT_RC=1 PIP_AUDIT_OUT='{"dependencies":[{"name":"affected","version":"1.0.0","vulns":[{"id":"PYSEC-1","fix_versions":["1.0.1"]},{"id":"PYSEC-2","severity":"high"}]},{"name":"clean","version":"2.0","vulns":[]}]}'
  assert_jq "$FUNCNAME" '
    (.ecosystem_audits[] | select(.scanner == "pip-audit")
      | .status == "ok" and .total == 2 and .high == 1 and .unknown == 1)
    and .verdict == "WARN"
  ' || return
  pass "$FUNCNAME"
}

case_npm_audit_maps_severity_bands() {
  prepare_case "npm-sev"
  printf '{"name":"demo","version":"1.0.0"}\n' > "$CASE_PROJECT/package.json"
  printf '{"lockfileVersion":3,"packages":{}}\n' > "$CASE_PROJECT/package-lock.json"
  run_scan NPM_RC=1 NPM_OUT='{"metadata":{"vulnerabilities":{"info":0,"low":2,"moderate":1,"high":0,"critical":3,"total":6}}}'
  assert_jq "$FUNCNAME" '
    (.ecosystem_audits[] | select(.scanner == "npm-audit")
      | .status == "ok" and .critical == 3 and .medium == 1 and .low == 2)
    and .audit_totals.critical == 3
    and (.audit_totals.ecosystem[] | select(.scanner == "npm-audit") | .critical == 3)
  ' || return
  pass "$FUNCNAME"
}

case_broken_scanner_is_an_error_not_a_clean_result() {
  prepare_case "npm-broken"
  printf '{"name":"demo","version":"1.0.0"}\n' > "$CASE_PROJECT/package.json"
  printf '{"lockfileVersion":3,"packages":{}}\n' > "$CASE_PROJECT/package-lock.json"
  # Cannot reach its advisory database: nonzero exit, nothing on stdout.
  run_scan NPM_RC=1 NPM_OUT=''
  assert_jq "$FUNCNAME" '
    (.ecosystem_audits[] | select(.scanner == "npm-audit")
      | .status == "error" and .total == 0 and ((.note // "") | test("failed")))
    and .verdict == "WARN"
  ' || return
  # And the aggregate must not count a broken scanner as evidence of anything.
  assert_jq "$FUNCNAME" '.audit_totals.critical == 0' || return
  pass "$FUNCNAME"
}

case_garbage_output_is_an_error() {
  prepare_case "npm-garbage"
  printf '{"name":"demo","version":"1.0.0"}\n' > "$CASE_PROJECT/package.json"
  printf '{"lockfileVersion":3,"packages":{}}\n' > "$CASE_PROJECT/package-lock.json"
  # Exit 0 with output that is not an audit document at all.
  run_scan NPM_RC=0 NPM_OUT='<!DOCTYPE html><html>proxy login page</html>'
  assert_jq "$FUNCNAME" '
    .ecosystem_audits[] | select(.scanner == "npm-audit") | .status == "error"
  ' || return
  pass "$FUNCNAME"
}

case_composer_advisories_are_keyed_by_package() {
  prepare_case "composer"
  printf '{"name":"demo/app"}\n' > "$CASE_PROJECT/composer.json"
  run_scan COMPOSER_RC=2 COMPOSER_OUT='{"advisories":{"vendor/pkg":[{"advisoryId":"PKSA-1","severity":"critical"},{"advisoryId":"PKSA-2","severity":"medium"}],"other/pkg":[{"advisoryId":"PKSA-3"}]}}'
  assert_jq "$FUNCNAME" '
    .ecosystem_audits[] | select(.scanner == "composer-audit")
      | .status == "ok" and .total == 3 and .critical == 1 and .medium == 1 and .unknown == 1
  ' || return
  assert_jq "$FUNCNAME" '.audit_totals.critical == 1 and .verdict == "WARN"' || return
  pass "$FUNCNAME"
}

case_cargo_audit_derives_severity_from_cvss() {
  prepare_case "cargo"
  printf '[package]\nname = "demo"\n' > "$CASE_PROJECT/Cargo.toml"
  # RustSec advisories usually carry a CVSS vector and no severity word.
  run_scan CARGO_AUDIT_RC=1 CARGO_AUDIT_OUT='{"vulnerabilities":{"list":[{"advisory":{"id":"RUSTSEC-2026-0001","cvss":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},{"advisory":{"id":"RUSTSEC-2026-0002"}}]}}'
  assert_jq "$FUNCNAME" '
    .ecosystem_audits[] | select(.scanner == "cargo-audit")
      | .status == "ok" and .total == 2 and .critical == 1 and .unknown == 1
  ' || return
  assert_jq "$FUNCNAME" '.audit_totals.critical == 1' || return
  pass "$FUNCNAME"
}

case_govulncheck_counts_unique_findings() {
  prepare_case "go"
  printf 'module demo\n\ngo 1.22\n' > "$CASE_PROJECT/go.mod"
  printf 'package main\nfunc main() {}\n' > "$CASE_PROJECT/main.go"
  run_scan GOVULNCHECK_RC=0 GOVULNCHECK_OUT='{"config":{"protocol_version":"v1.0.0"}}
{"finding":{"osv":"GO-2026-0001","trace":[{"module":"x"}]}}
{"finding":{"osv":"GO-2026-0001","trace":[{"module":"x","function":"f"}]}}
{"finding":{"osv":"GO-2026-0002"}}'
  assert_jq "$FUNCNAME" '
    .ecosystem_audits[] | select(.scanner == "govulncheck")
      | .status == "ok" and .total == 2 and .unknown == 2
  ' || return
  pass "$FUNCNAME"
}

case_govulncheck_empty_stream_is_an_error() {
  prepare_case "go-broken"
  printf 'module demo\n\ngo 1.22\n' > "$CASE_PROJECT/go.mod"
  # A working govulncheck always emits at least its config record.
  run_scan GOVULNCHECK_RC=1 GOVULNCHECK_OUT=''
  assert_jq "$FUNCNAME" '
    .ecosystem_audits[] | select(.scanner == "govulncheck") | .status == "error"
  ' || return
  pass "$FUNCNAME"
}

case_project_mode_refuses_a_broken_scanner_under_yes() {
  prepare_case "install-broken"
  printf '{"name":"demo","version":"1.0.0"}\n' > "$CASE_PROJECT/package.json"
  printf '{"lockfileVersion":3,"packages":{}}\n' > "$CASE_PROJECT/package-lock.json"
  local rc=0
  set +e
  (
    cd "$CASE_PROJECT" || exit 99
    env \
      HOME="$CASE_DIR/home" \
      PATH="$MOCKBIN:/usr/bin:/bin" \
      SAFE_AUDIT_PATH="$SAFE_AUDIT" \
      SAFE_AUDIT_CONFIG_DIR="$CASE_DIR/audit-config" \
      SAFE_AUDIT_DATA_DIR="$CASE_DIR/audit-data" \
      SAFE_DATA_DIR="$CASE_DIR/safe-data" \
      SAFE_AUDIT_SCAN_NO_CACHE=1 \
      NPM_RC=1 NPM_OUT='' \
      "$ROOT/bin/safe" install --project --yes
  ) > "$CASE_DIR/install.out" 2> "$CASE_DIR/install.err"
  rc=$?
  set -e
  # A scanner that ran and failed is infrastructure breakage: --yes accepts
  # warnings, never an unchecked project.
  [[ "$rc" -eq 100 ]] || { printf 'expected rc=100, got %s\n%s\n' "$rc" "$(cat "$CASE_DIR/install.err")" >&2; fail "$FUNCNAME"; return; }
  grep -Fq 'scanner failure (npm-audit)' "$CASE_DIR/install.err" || { cat "$CASE_DIR/install.err" >&2; fail "$FUNCNAME"; return; }
  [[ "$(wc -l < "$CASE_DIR/install.err")" -eq 1 ]] || { cat "$CASE_DIR/install.err" >&2; fail "$FUNCNAME"; return; }
  pass "$FUNCNAME"
}

case_project_mode_accepts_a_clean_python_project() {
  prepare_case "install-clean"
  printf 'requests==2.32.0\n' > "$CASE_PROJECT/requirements.txt"
  local rc=0
  set +e
  (
    cd "$CASE_PROJECT" || exit 99
    env \
      HOME="$CASE_DIR/home" \
      PATH="$MOCKBIN:/usr/bin:/bin" \
      SAFE_AUDIT_PATH="$SAFE_AUDIT" \
      SAFE_AUDIT_CONFIG_DIR="$CASE_DIR/audit-config" \
      SAFE_AUDIT_DATA_DIR="$CASE_DIR/audit-data" \
      SAFE_DATA_DIR="$CASE_DIR/safe-data" \
      SAFE_AUDIT_SCAN_NO_CACHE=1 \
      PIP_AUDIT_OUT='[{"name":"requests","version":"2.32.0","vulns":[]}]' \
      "$ROOT/bin/safe" install --project
  ) > "$CASE_DIR/install.out" 2> "$CASE_DIR/install.err"
  rc=$?
  set -e
  # The regression this guards: counting dependencies made every clean Python
  # project a WARN that a non-interactive shell then refused with 102.
  [[ "$rc" -eq 0 ]] || { printf 'expected rc=0, got %s\n%s\n%s\n' "$rc" "$(cat "$CASE_DIR/install.out")" "$(cat "$CASE_DIR/install.err")" >&2; fail "$FUNCNAME"; return; }
  grep -Fq 'verdict:   GO' "$CASE_DIR/install.out" || { cat "$CASE_DIR/install.out" >&2; fail "$FUNCNAME"; return; }
  pass "$FUNCNAME"
}

case_pnpm_project_is_unsupported_coverage_not_breakage() {
  prepare_case "pnpm"
  printf '{"name":"demo","version":"1.0.0"}\n' > "$CASE_PROJECT/package.json"
  printf "lockfileVersion: '9.0'\n" > "$CASE_PROJECT/pnpm-lock.yaml"
  # npm audit cannot read a pnpm lockfile. Reporting that as scanner breakage
  # would put every pnpm project behind an operator prompt.
  run_scan NPM_RC=1 NPM_OUT=''
  assert_jq "$FUNCNAME" '
    (.ecosystem_audits[] | select(.scanner == "npm-audit")
      | .status == "unsupported" and ((.note // "") | test("pnpm/yarn")))
    and .verdict == "GO"
  ' || return
  pass "$FUNCNAME"
}

case_bun_lock_project_is_covered_not_a_false_warn() {
  prepare_case "bun-text"
  printf '{"name":"demo","version":"1.0.0"}\n' > "$CASE_PROJECT/package.json"
  printf '{"lockfileVersion":1,"workspaces":{"":{"name":"demo"}},"packages":{}}\n' > "$CASE_PROJECT/bun.lock"
  # osv-scanner reads bun.lock, so the dependencies ARE covered and `npm audit`
  # being unable to read it is the same non-event as for a pnpm project.
  # Before bun lockfiles were discovered at all, this WARNed as "no lockfile".
  run_scan NPM_RC=1 NPM_OUT=''
  assert_jq "$FUNCNAME" '
    (.ecosystem_audits[] | select(.scanner == "npm-audit") | .status == "unsupported")
    and .verdict == "GO"
  ' || return
  pass "$FUNCNAME"
}

case_bun_lockb_only_project_still_warns() {
  prepare_case "bun-binary"
  printf '{"name":"demo","version":"1.0.0"}\n' > "$CASE_PROJECT/package.json"
  printf 'binary\n' > "$CASE_PROJECT/bun.lockb"
  # Nothing reads the binary format: npm audit cannot, and osv-scanner has no
  # extractor for it. Discovering the file must not be mistaken for covering
  # its dependencies.
  run_scan NPM_RC=1 NPM_OUT=''
  assert_jq "$FUNCNAME" '
    .verdict == "WARN"
    and (.tool_status["osv-scanner"].status == "skipped")
  ' || return
  pass "$FUNCNAME"
}

case_pip_audit_covers_every_declared_target() {
  prepare_case "pip-multi"
  printf 'app==1.0.0\n' > "$CASE_PROJECT/requirements.txt"
  printf 'devtool==2.0.0\n' > "$CASE_PROJECT/requirements-dev.txt"
  # The runner used to stop at the first target it found, so an advisory that
  # only affects a dev dependency was never submitted at all.
  local argv_log="$CASE_DIR/pip-argv.log"
  cat > "$MOCKBIN/pip-audit" <<STUB
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$argv_log"
case "\$*" in
  *requirements-dev.txt*) printf '%s' '{"dependencies":[{"name":"devtool","version":"2.0.0","vulns":[{"id":"PYSEC-DEV","severity":"critical"}]}]}' ;;
  *) printf '%s' '{"dependencies":[{"name":"app","version":"1.0.0","vulns":[]}]}' ;;
esac
exit 1
STUB
  chmod +x "$MOCKBIN/pip-audit"
  run_scan
  # Restore the shared stub for later cases.
  cat > "$MOCKBIN/pip-audit" <<'STUB'
#!/usr/bin/env bash
printf '%s' "${PIP_AUDIT_OUT:-}"
exit "${PIP_AUDIT_RC:-0}"
STUB
  chmod +x "$MOCKBIN/pip-audit"

  grep -Fq 'requirements-dev.txt' "$argv_log" || { printf 'pip-audit was never asked about the dev requirements:\n%s\n' "$(cat "$argv_log")" >&2; fail "$FUNCNAME"; return; }
  assert_jq "$FUNCNAME" '
    (.ecosystem_audits[] | select(.scanner == "pip-audit")
      | .status == "ok" and .total == 1 and .critical == 1)
  ' || return
  pass "$FUNCNAME"
}

case_pyproject_is_audited_by_path_not_by_environment() {
  prepare_case "pip-pyproject"
  printf '[project]\nname = "demo"\n' > "$CASE_PROJECT/pyproject.toml"
  local argv_log="$CASE_DIR/pip-argv.log"
  cat > "$MOCKBIN/pip-audit" <<STUB
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$argv_log"
printf '%s' '{"dependencies":[]}'
exit 0
STUB
  chmod +x "$MOCKBIN/pip-audit"
  run_scan
  cat > "$MOCKBIN/pip-audit" <<'STUB'
#!/usr/bin/env bash
printf '%s' "${PIP_AUDIT_OUT:-}"
exit "${PIP_AUDIT_RC:-0}"
STUB
  chmod +x "$MOCKBIN/pip-audit"

  # A bare `pip-audit -f json` audits the ACTIVE ENVIRONMENT, not the project.
  local argv
  argv="$(cat "$argv_log")"
  [[ "$argv" == *"$CASE_PROJECT"* ]] || { printf 'pyproject audit did not name the project path: %s\n' "$argv" >&2; fail "$FUNCNAME"; return; }
  pass "$FUNCNAME"
}

case_govulncheck_partial_stream_is_an_error() {
  prepare_case "go-partial"
  printf 'module demo\n\ngo 1.22\n' > "$CASE_PROJECT/go.mod"
  printf 'package main\nfunc main() {}\n' > "$CASE_PROJECT/main.go"
  # Valid config record, then the process dies mid-write. Tolerating the
  # unparsable tail would report a confident zero findings.
  run_scan GOVULNCHECK_RC=1 GOVULNCHECK_OUT='{"config":{"protocol_version":"v1.0.0"}}
{"finding":{"osv":"GO-2026-000'
  assert_jq "$FUNCNAME" '
    .ecosystem_audits[] | select(.scanner == "govulncheck") | .status == "error"
  ' || return
  pass "$FUNCNAME"
}

case_govulncheck_nonzero_exit_is_an_error() {
  prepare_case "go-rc"
  printf 'module demo\n\ngo 1.22\n' > "$CASE_PROJECT/go.mod"
  printf 'package main\nfunc main() {}\n' > "$CASE_PROJECT/main.go"
  # A complete-looking prefix and then a failed run: in -json mode findings
  # are reported IN the stream, so a nonzero exit is the run breaking.
  run_scan GOVULNCHECK_RC=1 GOVULNCHECK_OUT='{"config":{"protocol_version":"v1.0.0"}}'
  assert_jq "$FUNCNAME" '
    .ecosystem_audits[] | select(.scanner == "govulncheck") | .status == "error"
  ' || return
  pass "$FUNCNAME"
}

case_pip_audit_partial_failure_keeps_what_was_found() {
  prepare_case "pip-partial"
  printf 'app==1.0.0\n' > "$CASE_PROJECT/requirements.txt"
  printf 'devtool==2.0.0\n' > "$CASE_PROJECT/requirements-dev.txt"
  # requirements.txt finds a critical; requirements-dev.txt then breaks. The
  # critical must survive: erasing it behind an unrelated failure is how a
  # real finding disappears.
  cat > "$MOCKBIN/pip-audit" <<'STUB'
#!/usr/bin/env bash
case "$*" in
  *requirements-dev.txt*) printf 'resolution error
' >&2; exit 2 ;;
  *) printf '%s' '{"dependencies":[{"name":"app","version":"1.0.0","vulns":[{"id":"PYSEC-1","severity":"critical"}]}]}'; exit 1 ;;
esac
STUB
  chmod +x "$MOCKBIN/pip-audit"
  run_scan
  cat > "$MOCKBIN/pip-audit" <<'STUB'
#!/usr/bin/env bash
printf '%s' "${PIP_AUDIT_OUT:-}"
exit "${PIP_AUDIT_RC:-0}"
STUB
  chmod +x "$MOCKBIN/pip-audit"

  assert_jq "$FUNCNAME" '
    (.ecosystem_audits[] | select(.scanner == "pip-audit")
      | .status == "partial" and .critical == 1 and ((.note // "") | test("requirements-dev")))
    and .audit_totals.critical == 1
    and .verdict == "WARN"
  ' || return
  pass "$FUNCNAME"
}

case_pip_audit_partial_does_not_gate_as_broken() {
  prepare_case "install-pip-partial"
  printf 'app==1.0.0\n' > "$CASE_PROJECT/requirements.txt"
  printf 'devtool==2.0.0\n' > "$CASE_PROJECT/requirements-dev.txt"
  # requirements.txt audits clean; requirements-dev.txt breaks -> status
  # "partial", note "pip-audit failed for: ...". A partial run DID cover part
  # of the project, so the gate must disclose it and WARN, never hard-refuse
  # it as a broken scanner. The old /fail|error/ note-regex turned "one target
  # failed" into "nothing was checked" (exit 100), an unrescuable dead end.
  cat > "$MOCKBIN/pip-audit" <<'STUB'
#!/usr/bin/env bash
case "$*" in
  *requirements-dev.txt*) printf 'resolution error
' >&2; exit 2 ;;
  *) printf '%s' '{"dependencies":[{"name":"app","version":"1.0.0","vulns":[]}]}'; exit 0 ;;
esac
STUB
  chmod +x "$MOCKBIN/pip-audit"
  local rc=0
  set +e
  (
    cd "$CASE_PROJECT" || exit 99
    env \
      HOME="$CASE_DIR/home" \
      PATH="$MOCKBIN:/usr/bin:/bin" \
      SAFE_AUDIT_PATH="$SAFE_AUDIT" \
      SAFE_AUDIT_CONFIG_DIR="$CASE_DIR/audit-config" \
      SAFE_AUDIT_DATA_DIR="$CASE_DIR/audit-data" \
      SAFE_DATA_DIR="$CASE_DIR/safe-data" \
      SAFE_AUDIT_SCAN_NO_CACHE=1 \
      "$ROOT/bin/safe" install --project --yes
  ) > "$CASE_DIR/install.out" 2> "$CASE_DIR/install.err"
  rc=$?
  set -e
  # Restore the shared stub for later cases.
  cat > "$MOCKBIN/pip-audit" <<'STUB'
#!/usr/bin/env bash
printf '%s' "${PIP_AUDIT_OUT:-}"
exit "${PIP_AUDIT_RC:-0}"
STUB
  chmod +x "$MOCKBIN/pip-audit"

  # A partial scanner is not broken infrastructure: --yes accepts the WARN.
  [[ "$rc" -eq 0 ]] || { printf 'expected rc=0, got %s\n%s\n%s\n' "$rc" "$(cat "$CASE_DIR/install.out")" "$(cat "$CASE_DIR/install.err")" >&2; fail "$FUNCNAME"; return; }
  if grep -Fq 'scanner failure' "$CASE_DIR/install.err"; then
    printf 'partial pip-audit wrongly refused as broken:\n%s\n' "$(cat "$CASE_DIR/install.err")" >&2; fail "$FUNCNAME"; return
  fi
  grep -Eq 'not run:.*pip-audit' "$CASE_DIR/install.out" || { printf 'partial pip-audit not disclosed:\n%s\n' "$(cat "$CASE_DIR/install.out")" >&2; fail "$FUNCNAME"; return; }
  grep -Fq 'verdict:   WARN' "$CASE_DIR/install.out" || { cat "$CASE_DIR/install.out" >&2; fail "$FUNCNAME"; return; }
  pass "$FUNCNAME"
}

case_lockless_npm_project_is_not_clean() {
  prepare_case "no-lock"
  # package.json only: osv-scanner has no lockfile to read and npm audit has
  # none either, so NOTHING covers these dependencies. GO would mean "we
  # looked at nothing".
  printf '{"name":"demo","dependencies":{"left-pad":"^1.0.0"}}\n' > "$CASE_PROJECT/package.json"
  run_scan
  assert_jq "$FUNCNAME" '
    (.ecosystem_audits[] | select(.scanner == "npm-audit")
      | .status == "unsupported" and ((.note // "") | test("not audited")))
    and .verdict == "WARN"
  ' || return
  pass "$FUNCNAME"
}

case_pnpm_project_still_caches() {
  prepare_case "pnpm-cache"
  printf '{"name":"demo","version":"1.0.0"}\n' > "$CASE_PROJECT/package.json"
  printf "lockfileVersion: '9.0'\n" > "$CASE_PROJECT/pnpm-lock.yaml"
  # A deterministic "unsupported" record is decided by files that are in the
  # cache key, so it must not defeat caching for every pnpm user.
  set +e
  (
    cd "$CASE_PROJECT" || exit 99
    env HOME="$CASE_DIR/home" PATH="$MOCKBIN:/usr/bin:/bin" \
      SAFE_AUDIT_CONFIG_DIR="$CASE_DIR/audit-config" \
      SAFE_AUDIT_DATA_DIR="$CASE_DIR/audit-data" \
      "$SAFE_AUDIT" repo-audit . --deps-only --result-out "$RESULT"
  ) > "$CASE_DIR/scan-cached.out" 2>&1
  local rc=$?
  set -e
  [[ "$rc" -eq 0 ]] || { printf 'scan exited %s\n%s\n' "$rc" "$(cat "$CASE_DIR/scan-cached.out")" >&2; fail "$FUNCNAME"; return; }
  local entries
  entries="$(find "$CASE_DIR/audit-data/scan-cache" -maxdepth 1 -name '*.json' 2>/dev/null | wc -l | tr -d ' ')"
  [[ "$entries" -eq 1 ]] || { printf 'expected 1 cache entry for a pnpm project, got %s\n' "$entries" >&2; fail "$FUNCNAME"; return; }
  pass "$FUNCNAME"
}

case_missing_tool_is_reported_not_fatal_when_allowed() {
  prepare_case "missing-tool"
  printf '[package]\nname = "demo"\n' > "$CASE_PROJECT/Cargo.toml"
  # cargo-audit absent: without --allow-missing-tools a non-interactive scan
  # refuses to run at all, which made a Rust project unauditable from any
  # non-TTY caller. With it, the gap is a record the caller can act on.
  rm -f "$MOCKBIN/cargo-audit" "$MOCKBIN/cargo"
  run_scan
  local rc_without="$STATUS"
  set +e
  (
    cd "$CASE_PROJECT" || exit 99
    env HOME="$CASE_DIR/home" PATH="$MOCKBIN:/usr/bin:/bin" \
      SAFE_AUDIT_CONFIG_DIR="$CASE_DIR/audit-config" \
      SAFE_AUDIT_DATA_DIR="$CASE_DIR/audit-data" \
      SAFE_AUDIT_SCAN_NO_CACHE=1 \
      "$SAFE_AUDIT" repo-audit . --deps-only --allow-missing-tools --result-out "$RESULT"
  ) > "$CASE_DIR/scan-allowed.out" 2>&1
  local rc_with=$?
  set -e
  # Restore the stubs for later cases.
  cat > "$MOCKBIN/cargo" <<'STUB'
#!/usr/bin/env bash
[[ "${1:-}" == "audit" ]] || exit 0
printf '%s' "${CARGO_AUDIT_OUT:-}"
exit "${CARGO_AUDIT_RC:-0}"
STUB
  cat > "$MOCKBIN/cargo-audit" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
  chmod +x "$MOCKBIN/cargo" "$MOCKBIN/cargo-audit"

  [[ "$rc_without" -ne 0 ]] || { printf 'a missing scanner silently produced a result\n' >&2; fail "$FUNCNAME"; return; }
  [[ "$rc_with" -eq 0 ]] || { printf '--allow-missing-tools still refused (exit %s):\n%s\n' "$rc_with" "$(cat "$CASE_DIR/scan-allowed.out")" >&2; fail "$FUNCNAME"; return; }
  assert_jq "$FUNCNAME" '
    (.ecosystem_audits[] | select(.scanner == "cargo-audit")
      | .status == "skipped" and ((.note // "") | test("unavailable")))
    and .verdict == "WARN"
  ' || return
  pass "$FUNCNAME"
}

case_local_and_remote_normalizers_stay_identical() {
  # The remote scan helper ships its own copy of these functions. A fix applied
  # to one copy and not the other is a silent divergence in what a remote scan
  # reports, so the two blocks are compared verbatim.
  local marker_start marker_end
  marker_start='# --- ecosystem audit normalizers'
  marker_end='# --- end ecosystem audit normalizers ---'
  local blocks
  blocks="$(awk -v s="$marker_start" -v e="$marker_end" '
    index($0, s) == 1 {inblock = 1; n++}
    inblock {print n "\t" $0}
    index($0, e) == 1 {inblock = 0}
  ' "$SAFE_AUDIT")"
  local count
  count="$(printf '%s\n' "$blocks" | awk -F'\t' '{print $1}' | sort -u | wc -l)"
  [[ "$count" -eq 2 ]] || { printf 'expected 2 normalizer blocks, found %s\n' "$count" >&2; fail "$FUNCNAME"; return; }
  local a b
  a="$(printf '%s\n' "$blocks" | awk -F'\t' '$1 == 1 {print substr($0, index($0, "\t") + 1)}')"
  b="$(printf '%s\n' "$blocks" | awk -F'\t' '$1 == 2 {print substr($0, index($0, "\t") + 1)}')"
  if [[ "$a" != "$b" ]]; then
    diff <(printf '%s\n' "$a") <(printf '%s\n' "$b") | head -20 >&2
    fail "$FUNCNAME"
    return
  fi
  pass "$FUNCNAME"
}

main() {
  local case
  for case in \
    case_pip_audit_clean_project_stays_clean \
    case_pip_audit_counts_advisories_not_dependencies \
    case_npm_audit_maps_severity_bands \
    case_broken_scanner_is_an_error_not_a_clean_result \
    case_garbage_output_is_an_error \
    case_composer_advisories_are_keyed_by_package \
    case_cargo_audit_derives_severity_from_cvss \
    case_govulncheck_counts_unique_findings \
    case_govulncheck_empty_stream_is_an_error \
    case_project_mode_refuses_a_broken_scanner_under_yes \
    case_project_mode_accepts_a_clean_python_project \
    case_pnpm_project_is_unsupported_coverage_not_breakage \
    case_bun_lock_project_is_covered_not_a_false_warn \
    case_bun_lockb_only_project_still_warns \
    case_pip_audit_covers_every_declared_target \
    case_pyproject_is_audited_by_path_not_by_environment \
    case_govulncheck_partial_stream_is_an_error \
    case_govulncheck_nonzero_exit_is_an_error \
    case_pip_audit_partial_failure_keeps_what_was_found \
    case_pip_audit_partial_does_not_gate_as_broken \
    case_lockless_npm_project_is_not_clean \
    case_pnpm_project_still_caches \
    case_missing_tool_is_reported_not_fatal_when_allowed \
    case_local_and_remote_normalizers_stay_identical
  do
    "$case"
  done

  printf '\n%s passed, %s failed\n' "$PASS_COUNT" "$FAIL_COUNT"
  [[ "$FAIL_COUNT" -eq 0 ]]
}

main "$@"
