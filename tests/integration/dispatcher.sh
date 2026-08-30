#!/usr/bin/env bash
set -euo pipefail

# #87: this suite exercises trust reads/writes (incl. `safe install --trust-host`)
# through a relocated SAFE_CONFIG_DIR for hermeticity; bless it as authoritative
# so the trust-redirect guard is a no-op here. The guard itself is covered by
# tests/run/trust_store_redirect.sh.
export SAFE_RUN_TRUST_OVERRIDE=1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SAFE="$ROOT/bin/safe"

pass() { printf 'ok - %s\n' "$*"; }
fail() { printf 'not ok - %s\n' "$*" >&2; exit 1; }

require() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

require bash
require jq

bash -n "$SAFE"
pass "dispatcher syntax"

completion_file="$ROOT/lib/completions/_safe"
grep -Fq 'safe doctor [--json]' < <("$SAFE" --help) || fail "safe help missing doctor"
grep -Fq 'safe run host-allow' < <(SAFE_RUN_NO_INIT=1 "$SAFE" run help) || fail "safe run help missing dispatcher form"
grep -Fq 'safe audit machine-audit' < <(SAFE_AUDIT_NO_INIT=1 "$SAFE" audit help) || fail "safe audit help missing dispatcher form"
grep -Fq "'doctor:show local readiness diagnostics'" "$completion_file" || fail "top-level completion missing doctor"
grep -Fq "doctor option' '--json'" "$completion_file" || fail "doctor completion missing --json"
pass "help and completion"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

shim="$tmp/bin"
mkdir -p "$shim"
cp "$SAFE" "$shim/safe"
chmod +x "$shim/safe"

cat > "$shim/safe-run" <<'SH'
#!/usr/bin/env bash
case "${1:-}" in
  version|--version|-v) echo "safe-run mock" ;;
  status) echo "config: ${SAFE_CONFIG_DIR:-$HOME/.config/safe}/run" ;;
  *) printf 'safe-run'; for arg in "$@"; do printf '\t%s' "$arg"; done; printf '\n' ;;
esac
SH
chmod +x "$shim/safe-run"

cat > "$shim/safe-audit" <<'SH'
#!/usr/bin/env bash
case "${1:-}" in
  --version|-v) echo "safe-audit mock" ;;
  status) echo "config: ${SAFE_CONFIG_DIR:-$HOME/.config/safe}/audit" ;;
  package-audit) printf 'safe-audit'; for arg in "$@"; do printf '\t%s' "$arg"; done; printf '\n'; exit "${SAFE_AUDIT_STUB_STATUS:-0}" ;;
  repo-audit)
    { printf 'safe-audit'; for arg in "$@"; do printf '\t%s' "$arg"; done; printf '\n'; } >> "${SAFE_AUDIT_STUB_SCAN_LOG:-/dev/null}"
    { printf 'safe-audit'; for arg in "$@"; do printf '\t%s' "$arg"; done; printf '\n'; }
    # The caller receives its own copy through --result-out; the published
    # per-day path is only ever a display string.
    result_out=""
    prev=""
    for arg in "$@"; do
      [[ "$prev" == "--result-out" ]] && result_out="$arg"
      prev="$arg"
    done
    result="${SAFE_AUDIT_STUB_SCAN_RESULT:-}"
    if [[ -n "$result" && "${SAFE_AUDIT_STUB_SCAN_NO_RESULT:-0}" != "1" ]]; then
      cve_critical="${SAFE_AUDIT_STUB_SCAN_CRITICAL:-0}"
      cve_high="${SAFE_AUDIT_STUB_SCAN_HIGH:-0}"
      eco_critical="${SAFE_AUDIT_STUB_SCAN_ECO_CRITICAL:-0}"
      tool_status="${SAFE_AUDIT_STUB_TOOL_STATUS:-}"
      [[ -n "$tool_status" ]] || tool_status='{"osv-scanner":{"status":"ok","note":null},"syft":{"status":"ok","note":null},"grype":{"status":"ok","note":null}}'
      eco_audits="${SAFE_AUDIT_STUB_ECOSYSTEM_AUDITS:-}"
      [[ -n "$eco_audits" ]] || eco_audits='[]'
      eco_totals="${SAFE_AUDIT_STUB_ECO_TOTALS:-}"
      [[ -n "$eco_totals" ]] || eco_totals='[]'
      cat > "$result" <<JSON
{
  "machine": "local",
  "verdict": "${SAFE_AUDIT_STUB_SCAN_VERDICT:-GO}",
  "summary": {"packages_total": ${SAFE_AUDIT_STUB_SCAN_PACKAGES:-12}},
  "cve_scan": {
    "critical": ${cve_critical},
    "high": ${cve_high},
    "medium": 0,
    "low": 0,
    "findings": [
      {"source": "osv", "id": "GHSA-test-crit", "severity": "CRITICAL", "package": "evilpkg", "version": "1.2.3"},
      {"source": "grype", "id": "CVE-2026-0001", "severity": "High", "package": "warnpkg", "version": "2.0.0"}
    ]
  },
  "audit_totals": {
    "critical": $((cve_critical + eco_critical)),
    "high": ${cve_high},
    "medium": 0,
    "low": 0,
    "unknown": 0,
    "cve_scan": {"critical": ${cve_critical}, "high": ${cve_high}, "medium": 0, "low": 0},
    "ecosystem": ${eco_totals},
    "deduplicated": false
  },
  "tool_status": ${tool_status},
  "ecosystem_audits": ${eco_audits}
}
JSON
      [[ -n "$result_out" ]] && cp "$result" "$result_out"
      [[ "${SAFE_AUDIT_STUB_SCAN_NO_DETAILS:-0}" == "1" ]] || printf 'Details: %s\n' "$result"
    fi
    exit "${SAFE_AUDIT_STUB_SCAN_EXIT:-0}"
    ;;
  *) printf 'safe-audit'; for arg in "$@"; do printf '\t%s' "$arg"; done; printf '\n' ;;
esac
SH
chmod +x "$shim/safe-audit"

cat > "$shim/npm" <<'SH'
#!/usr/bin/env bash
printf '%s' "$(basename "$0")"
for arg in "$@"; do
  printf '\t%s' "$arg"
done
printf '\n'
SH
chmod +x "$shim/npm"
ln -s npm "$shim/pnpm"
ln -s npm "$shim/yarn"
ln -s npm "$shim/bun"
ln -s npm "$shim/composer"

[[ "$("$shim/safe" run --version)" == "safe-run mock" ]] || fail "safe run did not route"
[[ "$("$shim/safe" audit --version)" == "safe-audit mock" ]] || fail "safe audit did not route"
[[ "$("$shim/safe" install --allow-scripts cowsay@1.6.0)" == $'safe-run\tinstall\t--allow-scripts\tcowsay@1.6.0' ]] || fail "safe install did not route to safe run install"
host_install_output="$(PATH="$shim:$PATH" "$shim/safe" install --yes -g cowsay@1.6.0)"
grep -Fq $'safe-audit\tpackage-audit\tcowsay@1.6.0\t--ecosystem\tnpm' <<<"$host_install_output" || fail "safe install did not audit global npm package"
grep -Fq $'npm\tinstall\t-g\tcowsay@1.6.0' <<<"$host_install_output" || fail "safe install did not forward global npm flags"
trust_config="$tmp/trust-config"
trust_install_output="$(PATH="$shim:$PATH" SAFE_CONFIG_DIR="$trust_config" "$shim/safe" install --yes --trust-host -g cowsay@1.6.0)"
grep -Fq $'npm\tinstall\t-g\tcowsay@1.6.0' <<<"$trust_install_output" || fail "safe install --trust-host did not install package"
jq -e '.packages.cowsay.version == "1.6.0" and .packages.cowsay.ecosystem == "npm"' "$trust_config/run/host-allow.json" >/dev/null || fail "safe install --trust-host did not add exact host-allow entry"

# #87 F4: the same --trust-host write, but with the trust store redirected AND
# the override token OFF, must hard-refuse (exit 100) before writing anything —
# a gated agent cannot forge a host-allow entry through a relocated config root.
notoken_config="$tmp/notoken-trust-config"
set +e
notoken_out="$(PATH="$shim:$PATH" SAFE_CONFIG_DIR="$notoken_config" SAFE_RUN_TRUST_OVERRIDE=0 \
  "$shim/safe" install --yes --trust-host -g cowsay@1.6.0 2>&1)"
notoken_rc=$?
set -e
[[ "$notoken_rc" -eq 100 ]] || fail "safe install --trust-host on an unblessed redirected store must exit 100 (got $notoken_rc)"
grep -Fq 'trust store redirected' <<<"$notoken_out" || fail "--trust-host refusal must be the trust-redirect message, not an incidental exit 100"
[[ ! -f "$notoken_config/run/host-allow.json" ]] || fail "refused --trust-host must not write the redirected host-allow store"
pass "safe install --trust-host refuses an unblessed redirected write (exit 100, nothing written)"

# #87 F1: the redirect twin — SAFE_RUN_CONFIG_DIR is the other documented run
# root, and the dispatcher must honor the same SAFE_RUN_CONFIG_DIR > SAFE_CONFIG_DIR
# precedence as safe-run/safe-audit/gate-lib. Before the F1 fix bin/safe ignored
# this variable, so an unblessed SAFE_RUN_CONFIG_DIR redirect wrote the canonical
# store instead of refusing.
runredir_config="$tmp/notoken-run-config"
set +e
runredir_out="$(PATH="$shim:$PATH" SAFE_RUN_CONFIG_DIR="$runredir_config" SAFE_RUN_TRUST_OVERRIDE=0 \
  "$shim/safe" install --yes --trust-host -g cowsay@1.6.0 2>&1)"
runredir_rc=$?
set -e
[[ "$runredir_rc" -eq 100 ]] || fail "safe install --trust-host on an unblessed SAFE_RUN_CONFIG_DIR redirect must exit 100 (got $runredir_rc)"
grep -Fq 'trust store redirected' <<<"$runredir_out" || fail "SAFE_RUN_CONFIG_DIR redirect refusal must be the trust-redirect message"
[[ ! -f "$runredir_config/host-allow.json" ]] || fail "refused --trust-host must not write the SAFE_RUN_CONFIG_DIR store"
pass "safe install --trust-host honors the SAFE_RUN_CONFIG_DIR redirect too (F1 precedence)"

refusal_case() {
  local label="$1" expected_rc="$2" stub_status="$3" fragment="$4"
  shift 4
  local rc=0 errfile="$tmp/refusal-$label.err"
  PATH="$shim:$PATH" SAFE_CONFIG_DIR="$tmp/refusal-$label-config" SAFE_AUDIT_STUB_STATUS="$stub_status" \
    "$shim/safe" install "$@" >/dev/null 2>"$errfile" </dev/null || rc=$?
  [[ "$rc" -eq "$expected_rc" ]] || { cat "$errfile" >&2; fail "safe install $label expected rc=$expected_rc, got rc=$rc"; }
  grep -Fq "$fragment" "$errfile" || { cat "$errfile" >&2; fail "safe install $label missing refusal fragment: $fragment"; }
  grep -Fq "safe explain" "$errfile" || fail "safe install $label refusal missing safe explain pointer"
}
refusal_case audit-warn 100 10 'safe: BLOCKED npm install of warnme@1.0.0' --yes -g warnme@1.0.0
refusal_case audit-block 104 20 'safe: BLOCKED npm install of blockme@1.0.0' --yes -g blockme@1.0.0
refusal_case audit-fail 100 42 'safe audit failed with exit 42 (fail closed)' --yes -g failme@1.0.0
refusal_case non-tty-confirm 102 0 'BLOCKED install — interactive confirmation required' -g okpkg@1.0.0
pass "safe install policy refusals use BLOCKED contract and exit codes"

# --- safe install project mode ---------------------------------------------
# No package spec + a manifest in cwd = bulk audit of the project's dependency
# evidence. Audits only: it must never run a package manager.
project_case() {
  local label="$1" expected_rc="$2" dir="$3"
  shift 3
  local rc=0
  PROJECT_OUT="$tmp/project-$label.out"
  PROJECT_ERR="$tmp/project-$label.err"
  PROJECT_SCAN_LOG="$tmp/project-$label.scan.log"
  : > "$PROJECT_SCAN_LOG"
  (
    cd "$dir" || exit 99
    PATH="$shim:$PATH" \
    SAFE_CONFIG_DIR="$tmp/project-$label-config" \
    SAFE_DATA_DIR="$tmp/project-$label-data" \
    SAFE_AUDIT_STUB_SCAN_RESULT="$tmp/project-$label-result.json" \
    SAFE_AUDIT_STUB_SCAN_LOG="$PROJECT_SCAN_LOG" \
    "$@" \
    "$shim/safe" install "${PROJECT_ARGS[@]}"
  ) >"$PROJECT_OUT" 2>"$PROJECT_ERR" </dev/null || rc=$?
  [[ "$rc" -eq "$expected_rc" ]] || {
    printf 'stdout:\n%s\nstderr:\n%s\n' "$(cat "$PROJECT_OUT")" "$(cat "$PROJECT_ERR")" >&2
    fail "safe install project $label expected rc=$expected_rc, got rc=$rc"
  }
}

project_dir="$tmp/project-src"
mkdir -p "$project_dir"
printf '{"name":"demo"}\n' > "$project_dir/package.json"

# Clean project, non-interactive: exit 0 quietly, scan run in deps-only mode.
PROJECT_ARGS=()
project_case clean 0 "$project_dir" env SAFE_AUDIT_STUB_SCAN_VERDICT=GO
grep -Fq $'safe-audit\trepo-audit\t.\t--deps-only\t--allow-missing-tools' "$PROJECT_SCAN_LOG" || fail "project mode did not run a deps-only scan"
# An ecosystem auditor that is not installed must not abort the scan: this
# mode reports it as not run and lets its own policy decide.
grep -Fq -- '--allow-missing-tools' "$PROJECT_SCAN_LOG" || fail "project scan can be aborted by a missing scanner"
grep -Fq 'safe install: project audit' "$PROJECT_OUT" || fail "project mode printed no summary"
grep -Fq 'manifests: package.json' "$PROJECT_OUT" || fail "project mode summary omits the audited manifests"
grep -Fq 'verdict:   GO' "$PROJECT_OUT" || fail "project mode summary omits the verdict"

# The explicit flag forces the same mode.
PROJECT_ARGS=(--project)
project_case flag 0 "$project_dir" env SAFE_AUDIT_STUB_SCAN_VERDICT=GO
grep -Fq $'safe-audit\trepo-audit\t.\t--deps-only\t--allow-missing-tools' "$PROJECT_SCAN_LOG" || fail "safe install --project did not scan"

# WARN needs an operator: non-TTY refuses 102, --yes accepts.
PROJECT_ARGS=()
project_case warn-nontty 102 "$project_dir" env SAFE_AUDIT_STUB_SCAN_VERDICT=WARN SAFE_AUDIT_STUB_SCAN_HIGH=2
grep -Fq 'safe: BLOCKED project audit' "$PROJECT_ERR" || fail "project WARN refusal missing BLOCKED contract"
grep -Fq 'safe explain' "$PROJECT_ERR" || fail "project WARN refusal missing safe explain pointer"
grep -Fq 'top findings:' "$PROJECT_OUT" || fail "project summary omits top findings for high severity"
grep -Fq 'CVE-2026-0001' "$PROJECT_OUT" || fail "project summary omits the advisory id"

PROJECT_ARGS=(--yes)
project_case warn-yes 0 "$project_dir" env SAFE_AUDIT_STUB_SCAN_VERDICT=WARN SAFE_AUDIT_STUB_SCAN_HIGH=2

# Critical findings are the project-scale BLOCK: 104 even under --yes.
PROJECT_ARGS=()
project_case critical 104 "$project_dir" env SAFE_AUDIT_STUB_SCAN_VERDICT=WARN SAFE_AUDIT_STUB_SCAN_CRITICAL=1
grep -Fq 'critical advisories' "$PROJECT_ERR" || fail "project critical refusal does not name the finding count"
grep -Fq 'osv/grype 1' "$PROJECT_ERR" || fail "project critical refusal does not attribute the finding to a source"
grep -Fq 'GHSA-test-crit' "$PROJECT_OUT" || fail "project summary omits the critical advisory id"

PROJECT_ARGS=(--yes)
project_case critical-yes 104 "$project_dir" env SAFE_AUDIT_STUB_SCAN_VERDICT=WARN SAFE_AUDIT_STUB_SCAN_CRITICAL=3

# A critical seen only by an ecosystem audit (npm audit, composer audit) is
# still a critical: cve_scan alone would have reported a clean project.
PROJECT_ARGS=(--yes)
project_case ecosystem-critical 104 "$project_dir" env \
  SAFE_AUDIT_STUB_SCAN_VERDICT=WARN \
  SAFE_AUDIT_STUB_SCAN_ECO_CRITICAL=2 \
  SAFE_AUDIT_STUB_ECOSYSTEM_AUDITS='[{"scanner":"npm-audit","status":"ok","total":2,"critical":2,"high":0,"medium":0,"low":0,"unknown":0,"note":null}]' \
  SAFE_AUDIT_STUB_ECO_TOTALS='[{"scanner":"npm-audit","total":2,"critical":2,"high":0,"medium":0,"low":0,"unknown":0}]'
grep -Fq 'critical advisories' "$PROJECT_ERR" || fail "ecosystem-only critical was not refused as critical"
# The refusal names WHICH scanner saw it: a summed number would double-count
# an advisory that osv, grype and npm audit all report.
grep -Fq 'npm-audit 2' "$PROJECT_ERR" || fail "critical refusal does not attribute the finding to a scanner"
grep -Fq 'ecosystem: npm-audit' "$PROJECT_OUT" || fail "project summary omits the per-scanner breakdown"

# A BLOCK verdict is a refusal even when the CVE counts are zero.
PROJECT_ARGS=(--yes)
project_case block-verdict 104 "$project_dir" env SAFE_AUDIT_STUB_SCAN_VERDICT=BLOCK

# Fail closed when the scan cannot be trusted: no result document, a scanner
# that failed outright, an unknown verdict, or a broken scanner.
PROJECT_ARGS=()
project_case no-result 100 "$project_dir" env SAFE_AUDIT_STUB_SCAN_NO_RESULT=1
grep -Fq 'produced no result' "$PROJECT_ERR" || fail "unreadable scan result did not fail closed legibly"
PROJECT_ARGS=()
project_case scan-failed 100 "$project_dir" env SAFE_AUDIT_STUB_SCAN_EXIT=3
grep -Fq 'BLOCKED project audit' "$PROJECT_ERR" || fail "failed scan did not fail closed"

# An unknown verdict string is not a clean project.
PROJECT_ARGS=(--yes)
project_case unknown-verdict 100 "$project_dir" env SAFE_AUDIT_STUB_SCAN_VERDICT=PROBABLY_FINE
grep -Fq 'not readable as a verdict' "$PROJECT_ERR" || fail "unknown verdict was not refused as unreadable"

# A scanner that ran and FAILED is broken infrastructure: --yes cannot accept
# it, and it must not read as a vulnerability. "broken" is the structural
# status "error" (what a real failed grype writes — safe-audit maps its
# {"error":...} output to status:"error"), never a "skipped"/"partial" status
# second-guessed by a note that happens to contain "fail": a skipped scanner is
# unavailable coverage (WARN), not breakage.
PROJECT_ARGS=(--yes)
project_case scanner-broken 100 "$project_dir" env \
  SAFE_AUDIT_STUB_SCAN_VERDICT=WARN \
  SAFE_AUDIT_STUB_TOOL_STATUS='{"osv-scanner":{"status":"ok","note":null},"syft":{"status":"ok","note":null},"grype":{"status":"error","note":"grype failed"}}'
grep -Fq 'scanner failure (grype)' "$PROJECT_ERR" || fail "broken scanner was not named as infrastructure breakage"
grep -Fq 'safe doctor' "$PROJECT_ERR" || fail "scanner failure refusal offers no recovery path"
! grep -Fqi 'critical' "$PROJECT_ERR" || fail "infrastructure failure reads as a vulnerability finding"
[[ "$(wc -l < "$PROJECT_ERR")" -eq 1 ]] || {
  cat "$PROJECT_ERR" >&2
  fail "scanner failure refusal is not a single stderr line"
}

# A scanner that is merely absent is reported, not refused: the verdict is
# already WARN and the operator is told what was not looked at.
PROJECT_ARGS=(--yes)
project_case scanner-absent 0 "$project_dir" env \
  SAFE_AUDIT_STUB_SCAN_VERDICT=WARN \
  SAFE_AUDIT_STUB_ECOSYSTEM_AUDITS='[{"scanner":"cargo-audit","status":"skipped","total":0,"critical":0,"high":0,"medium":0,"low":0,"note":"cargo-audit unavailable"}]'
grep -Fq 'not run:' "$PROJECT_OUT" || fail "project summary hides a scanner that never ran"
grep -Fq 'cargo-audit' "$PROJECT_OUT" || fail "project summary does not name the missing scanner"

# safe audit missing entirely: policy refusal with the contract shape, not a
# bare usage error.
PROJECT_ARGS=()
project_case audit-missing 100 "$project_dir" env SAFE_AUDIT_PATH="$tmp/definitely-not-here"
grep -Fq 'safe: BLOCKED project audit' "$PROJECT_ERR" || fail "missing safe audit did not use the BLOCKED contract"
grep -Fq 'to allow:' "$PROJECT_ERR" || fail "missing safe audit refusal has no allow clause"
[[ "$(wc -l < "$PROJECT_ERR")" -eq 1 ]] || fail "missing safe audit refusal is not a single stderr line"

# A directory with no manifest is not a project: the old usage error stands.
empty_dir="$tmp/project-empty"
mkdir -p "$empty_dir"
PROJECT_ARGS=(--project)
project_case no-manifest 1 "$empty_dir" env
grep -Fq 'found no manifest' "$PROJECT_ERR" || fail "--project without a manifest did not explain itself"

# A named package still takes the spec path, manifest or not.
PROJECT_ARGS=(--yes -g cowsay@1.6.0)
project_case spec-still-audits 0 "$project_dir" env
grep -Fq $'safe-audit\tpackage-audit\tcowsay@1.6.0\t--ecosystem\tnpm' "$PROJECT_OUT" || fail "spec install stopped auditing in a project dir"
grep -Fq $'npm\tinstall\t-g\tcowsay@1.6.0' "$PROJECT_OUT" || fail "spec install stopped delegating in a project dir"
[[ ! -s "$PROJECT_SCAN_LOG" ]] || fail "spec install ran a project scan"

# Project mode installs NOTHING, so it must never absorb an install request.
# "exit 0, audit printed, package never installed" is the failure to avoid.
PROJECT_ARGS=(--project --yes cowsay@1.6.0)
project_case mixed-spec 1 "$project_dir" env
grep -Fq 'takes no package arguments' "$PROJECT_ERR" || fail "--project silently swallowed a package spec"
[[ ! -s "$PROJECT_SCAN_LOG" ]] || fail "--project with a spec still ran a scan"
! grep -Fq $'npm\tinstall' "$PROJECT_OUT" || fail "--project with a spec ran a package manager"

PROJECT_ARGS=(--project --yes -g cowsay@1.6.0)
project_case mixed-global 1 "$project_dir" env
grep -Fq 'cannot be combined' "$PROJECT_ERR" || fail "--project accepted a global install request"
[[ ! -s "$PROJECT_SCAN_LOG" ]] || fail "--project with -g still ran a scan"

PROJECT_ARGS=(--project --host)
project_case mixed-host 1 "$project_dir" env
grep -Fq 'cannot be combined' "$PROJECT_ERR" || fail "--project accepted an install-mode flag"

# An install-mode flag with no package is still an install request: the usual
# usage error stands rather than a silent audit-only success.
PROJECT_ARGS=(--yes -g)
project_case flags-without-spec 1 "$project_dir" env
grep -Fq 'usage: safe install --host' "$PROJECT_ERR" || fail "-g with no package became a project audit"
[[ ! -s "$PROJECT_SCAN_LOG" ]] || fail "-g with no package ran a project scan"
pass "safe install project mode audits, refuses, and fails closed"

explain_output="$("$SAFE" explain)"
grep -Fq '100  blocked by policy' <<<"$explain_output" || fail "safe explain missing exit code table"
grep -Fq 'safe run host-allow add' <<<"$explain_output" || fail "safe explain missing allow flow"
grep -Fq 'safe report-fp' <<<"$explain_output" || fail "safe explain missing the false-positive path"
# Prose is wrapped at render time, so a multi-word phrase can straddle a line
# break. Content assertions go against the JSON, which is the actual contract;
# the text is checked for structure only.
explain_json="$("$SAFE" explain --json)"
jq -e '.agent_rules | any(test("never attempt them yourself"))' >/dev/null <<<"$explain_json" ||
  fail "safe explain --json missing agent guidance"
jq -e '.schema_version == 1 and (.exit_codes | length) > 0' >/dev/null <<<"$explain_json" ||
  fail "safe explain --json is not a usable contract document"
pass "safe explain prints the agent contract in text and JSON"
set +e
latest_trust_output="$(PATH="$shim:$PATH" SAFE_CONFIG_DIR="$tmp/latest-trust-config" "$shim/safe" install --yes --trust-host -g cowsay 2>&1)"
latest_trust_rc=$?
set -e
[[ "$latest_trust_rc" -ne 0 ]] || fail "safe install --trust-host allowed latest"
! grep -Fq $'npm\tinstall\t-g\tcowsay' <<<"$latest_trust_output" || fail "safe install --trust-host installed latest before refusing trust"
yarn_install_output="$(PATH="$shim:$PATH" "$shim/safe" install --yes --yarn -g typescript@5.0.0)"
grep -Fq $'safe-audit\tpackage-audit\ttypescript@5.0.0\t--ecosystem\tnpm' <<<"$yarn_install_output" || fail "safe install did not audit global yarn package"
grep -Fq $'yarn\tglobal\tadd\ttypescript@5.0.0' <<<"$yarn_install_output" || fail "safe install did not translate global yarn install"
pnpm_install_output="$(PATH="$shim:$PATH" "$shim/safe" install --yes --pnpm -g cowsay@1.6.0)"
grep -Fq $'safe-audit\tpackage-audit\tcowsay@1.6.0\t--ecosystem\tnpm' <<<"$pnpm_install_output" || fail "safe install did not audit global pnpm package"
grep -Fq $'pnpm\tadd\t-g\tcowsay@1.6.0' <<<"$pnpm_install_output" || fail "safe install did not translate global pnpm install"
bun_install_output="$(PATH="$shim:$PATH" "$shim/safe" install --yes --bun -g cowsay@1.6.0)"
grep -Fq $'safe-audit\tpackage-audit\tcowsay@1.6.0\t--ecosystem\tnpm' <<<"$bun_install_output" || fail "safe install did not audit global bun package"
grep -Fq $'bun\tadd\t-g\tcowsay@1.6.0' <<<"$bun_install_output" || fail "safe install did not translate global bun install"
composer_install_output="$(PATH="$shim:$PATH" "$shim/safe" install --yes --composer -g vendor/pkg:^1)"
grep -Fq $'safe-audit\tpackage-audit\tvendor/pkg@^1\t--ecosystem\tcomposer' <<<"$composer_install_output" || fail "safe install did not audit global composer package"
grep -Fq $'composer\tglobal\trequire\tvendor/pkg:^1' <<<"$composer_install_output" || fail "safe install did not translate global composer install"
expected_safe_version="$(awk -F'"' '/^SAFE_VERSION=/ {print $2; exit}' "$SAFE")"
grep -q "^safe ${expected_safe_version}$" < <("$shim/safe" version) || fail "safe version missing top-level version"
grep -q '^=== audit ===$' < <("$shim/safe" status) || fail "safe status missing audit section"
pass "dispatcher routes"

vendor_home="$tmp/vendor-home"
vendor_bin="$tmp/vendor-tool"
printf 'old\n' > "$vendor_bin"
chmod +x "$vendor_bin"
HOME="$vendor_home" "$ROOT/bin/safe" vendor update \
  --name fixture \
  --path "$vendor_bin" \
  --reason "test update" \
  --rollback "restore old fixture" \
  -- bash -c 'printf new > "$1"' _ "$vendor_bin" >/dev/null
jq -e '
  .name == "fixture"
  and .reason == "test update"
  and .rollback == "restore old fixture"
  and .exit_code == 0
  and .before.sha256 != .after.sha256
  and (.command | length) > 0
' "$vendor_home/.local/share/safe/vendor/audit.log" >/dev/null || fail "safe vendor update did not write audit record"
pass "safe vendor update records before/after hashes"

set +e
HOME="$tmp/vendor-fail-home" "$ROOT/bin/safe" vendor update \
  --name fixture \
  --path "$vendor_bin" \
  --reason "test failed update" \
  -- bash -c 'exit 7' >/dev/null 2>/dev/null
vendor_rc=$?
set -e
[[ "$vendor_rc" -eq 7 ]] || fail "safe vendor update did not preserve command exit"
jq -e '.exit_code == 7' "$tmp/vendor-fail-home/.local/share/safe/vendor/audit.log" >/dev/null || fail "safe vendor update did not log failed command"
pass "safe vendor update logs failed command"

cap_tmp="$(mktemp -d)"
trap 'rm -rf "$tmp" "$cap_tmp"' EXIT
direct_json="$(
  SAFE_AUDIT_CONFIG_DIR="$cap_tmp/config" \
  SAFE_AUDIT_DATA_DIR="$cap_tmp/data" \
    "$ROOT/bin/safe-audit" capabilities --json
)"
routed_json="$(
  SAFE_AUDIT_CONFIG_DIR="$cap_tmp/config" \
  SAFE_AUDIT_DATA_DIR="$cap_tmp/data" \
    "$ROOT/bin/safe" audit capabilities --json
)"
[[ "$(jq -cS . <<<"$direct_json")" == "$(jq -cS . <<<"$routed_json")" ]] || fail "safe audit capabilities did not match direct compatibility binary output"
jq -e '.command == "safe audit capabilities" and .groups["binary-audit"]["release-review"] == true and .groups.setup["create-bundle"] == true' <<<"$routed_json" >/dev/null || fail "safe audit capabilities returned an unexpected payload"
[[ ! -e "$cap_tmp/data/checks" ]] || fail "safe audit capabilities wrote audit checks"
pass "dispatcher capabilities"

SAFE_CONFIG_DIR="$tmp/config" SAFE_DATA_DIR="$tmp/data" "$ROOT/bin/safe-run" status | grep -F "config: $tmp/config/run" >/dev/null || fail "safe-run config path"
SAFE_CONFIG_DIR="$tmp/config" SAFE_DATA_DIR="$tmp/data" "$ROOT/bin/safe-audit" status | grep -F "config: $tmp/config/audit" >/dev/null || fail "safe-audit config path"
pass "config paths"

doctor_tmp="$(mktemp -d)"
trap 'rm -rf "$tmp" "$cap_tmp" "$doctor_tmp"' EXIT
doctor_json="$(
  SAFE_CONFIG_DIR="$doctor_tmp/config" \
  SAFE_DATA_DIR="$doctor_tmp/data" \
  SAFE_ZSH_COMPLETION_DIR="$doctor_tmp/site-functions" \
    "$ROOT/bin/safe" doctor --json
)"
jq -e '
  .command == "safe doctor"
  and (.version | type == "string" and length > 0)
  and (.paths.safe_run.resolved | type == "string" and length > 0)
  and (.paths.safe_audit.resolved | type == "string" and length > 0)
  and (.dispatch.audit_version_parity | has("supported"))
  and (.dispatch.run_version_parity | has("supported"))
' <<<"$doctor_json" >/dev/null || fail "safe doctor returned an unexpected payload"
[[ ! -e "$doctor_tmp/data" ]] || fail "safe doctor created data directory"
[[ ! -e "$doctor_tmp/config" ]] || fail "safe doctor created config directory"
pass "doctor contract and non-persistence"

make_path_shim() {
  local dir="$1"
  shift
  mkdir -p "$dir"
  local cmd real
  for cmd in "$@"; do
    real="$(command -v "$cmd" 2>/dev/null || true)"
    [[ -n "$real" ]] || fail "missing command for PATH shim: $cmd"
    ln -sf "$real" "$dir/$cmd"
  done
}

minimal_path_dir="$doctor_tmp/minimal-path"
make_path_shim "$minimal_path_dir" bash env jq readlink dirname basename awk ps sleep sort tr
limited_json="$(
  PATH="$minimal_path_dir" \
  SAFE_CONFIG_DIR="$doctor_tmp/minimal-config" \
  SAFE_DATA_DIR="$doctor_tmp/minimal-data" \
  SAFE_ZSH_COMPLETION_DIR="$doctor_tmp/minimal-site-functions" \
    "$ROOT/bin/safe" doctor --json
)"
jq -e '
  .features.release_review.ready == false
  and (.features.release_review.missing | index("cosign") != null)
  and (.features.release_review.missing | index("podman") != null)
  and .features.safe_run_sandbox.ready == false
  and (.features.safe_run_sandbox.missing | index("podman") != null)
' <<<"$limited_json" >/dev/null || fail "doctor did not downgrade missing dependency readiness"
pass "doctor missing dependency readiness"

doctor_fail_dir="$doctor_tmp/fail-capabilities"
mkdir -p "$doctor_fail_dir"
cp "$SAFE" "$doctor_fail_dir/safe"
chmod +x "$doctor_fail_dir/safe"
cat > "$doctor_fail_dir/safe-run" <<'SH'
#!/usr/bin/env bash
case "${1:-}" in
  version|--version|-v) echo "safe-run mock" ;;
  *) exit 0 ;;
esac
SH
chmod +x "$doctor_fail_dir/safe-run"
cat > "$doctor_fail_dir/safe-audit" <<'SH'
#!/usr/bin/env bash
case "${1:-}" in
  --version|-v) echo "safe-audit mock" ;;
  capabilities) echo "failed" >&2; exit 23 ;;
  *) exit 0 ;;
esac
SH
chmod +x "$doctor_fail_dir/safe-audit"
failed_capabilities_json="$("$doctor_fail_dir/safe" doctor --json)"
jq -e '
  .features.safe_audit_capabilities.available == false
  and .features.release_review.supported == false
  and (.features.release_review.missing | index("safe audit capabilities") != null)
' <<<"$failed_capabilities_json" >/dev/null || fail "doctor did not handle capabilities lookup failure"
pass "doctor capabilities downgrade"

# ---------------------------------------------------------------------------
# safe vendor update presets
# ---------------------------------------------------------------------------
vendor_tmp="$tmp/vendor"
mkdir -p "$vendor_tmp/bin"
cat > "$vendor_tmp/bin/faketool" <<'SH'
#!/usr/bin/env bash
case "${1:-}" in
  --version) echo "faketool 9.9.9" ;;
  *) : ;;
esac
SH
chmod +x "$vendor_tmp/bin/faketool"

# Unknown preset is refused legibly.
set +e
PATH="$vendor_tmp/bin:$PATH" SAFE_DATA_DIR="$vendor_tmp/data" \
  "$SAFE" vendor update --preset bogus --reason x -- true 2>"$vendor_tmp/bogus.err"
rc=$?
set -e
[[ "$rc" -ne 0 ]] || fail "unknown vendor preset was not refused"
grep -q 'unknown vendor preset' "$vendor_tmp/bogus.err" || fail "unknown preset error not legible"
pass "vendor preset: unknown name refused"

# A preset whose binary is not on PATH refuses asking for --path. Use a clean
# PATH with only safe's own dependencies so the vendor tool is guaranteed
# absent regardless of what is installed on the host.
cleanbin="$vendor_tmp/cleanbin"
mkdir -p "$cleanbin"
for dep in bash jq sha256sum readlink date awk head mkdir true env dirname basename cat; do
  dep_path="$(command -v "$dep" 2>/dev/null)" && ln -sf "$dep_path" "$cleanbin/$dep"
done
set +e
PATH="$cleanbin" SAFE_DATA_DIR="$vendor_tmp/data" \
  bash "$SAFE" vendor update --preset gh --reason x -- true 2>"$vendor_tmp/nopath.err"
rc=$?
set -e
[[ "$rc" -ne 0 ]] || fail "preset with missing binary was not refused"
grep -q 'pass --path' "$vendor_tmp/nopath.err" || fail "missing-binary error does not point to --path"
pass "vendor preset: missing binary asks for --path"

# --preset resolves name/path/version-cmd; the audit log records the resolved
# fields and the version probe output.
cat > "$vendor_tmp/bin/codex" <<'SH'
#!/usr/bin/env bash
case "${1:-}" in
  --version) echo "codex 1.2.3" ;;
  *) : ;;
esac
SH
chmod +x "$vendor_tmp/bin/codex"
PATH="$vendor_tmp/bin:$PATH" SAFE_DATA_DIR="$vendor_tmp/data2" \
  "$SAFE" vendor update --preset codex --reason "preset test" -- true >/dev/null 2>&1
log="$vendor_tmp/data2/vendor/audit.log"
[[ -s "$log" ]] || fail "vendor preset run wrote no audit log"
jq -e '.name == "codex" and (.path | endswith("/codex")) and .reason == "preset test" and .exit_code == 0 and (.before.version.output | test("codex 1.2.3"))' "$log" >/dev/null \
  || fail "vendor preset audit entry missing resolved fields"
pass "vendor preset: resolves fields and logs version probe"
