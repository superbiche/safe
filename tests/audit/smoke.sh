#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SAFE_AUDIT="$ROOT/bin/safe-audit"
INSTALL="$ROOT/install.sh"

pass() { printf 'ok - %s\n' "$*"; }
fail() { printf 'not ok - %s\n' "$*" >&2; exit 1; }

require() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

require bash
require jq
require curl
require tar

bash -n "$SAFE_AUDIT"
bash -n "$INSTALL"
pass "bash syntax"

SAFE_AUDIT_PATH="$SAFE_AUDIT" \
  bash -c '
    set -- --version
    source "$SAFE_AUDIT_PATH" >/dev/null
    sleep 30 &
    child=$!
    terminate_descendants
    ! kill -0 "$child" 2>/dev/null
  ' || fail "process cleanup did not stop child process"
pass "process cleanup stops child processes"

help_output="$("$SAFE_AUDIT" --help)"
grep -q 'safe audit capabilities \[--json\]' <<<"$help_output" || fail "help omits capabilities"
grep -q 'safe audit ioc --update' <<<"$help_output" || fail "help omits ioc --update"
grep -q 'safe audit setup --create-bundle' <<<"$help_output" || fail "help omits setup --create-bundle"
grep -q 'safe audit verify sigstore-bundle' <<<"$help_output" || fail "help omits verify sigstore-bundle"
grep -q 'safe audit verify tuf-bootstrap' <<<"$help_output" || fail "help omits verify tuf-bootstrap"
pass "help output"

grep -q 'capabilities' "$ROOT/lib/completions/_safe" || fail "completion omits capabilities"
grep -q 'capabilities_opts=(--json)' "$ROOT/lib/completions/_safe" || fail "completion omits capabilities --json"
grep -q 'sigstore-bundle' "$ROOT/lib/completions/_safe" || fail "completion omits sigstore-bundle"
grep -q 'tuf-bootstrap' "$ROOT/lib/completions/_safe" || fail "completion omits tuf-bootstrap"
pass "completion output"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

audit_version="$("$SAFE_AUDIT" --version | awk '{print $NF}')"
capabilities_json="$(
  SAFE_AUDIT_CONFIG_DIR="$tmp/cap-config" \
  SAFE_AUDIT_DATA_DIR="$tmp/cap-data" \
    "$SAFE_AUDIT" capabilities --json
)"
jq -e --arg version "$audit_version" '
  .command == "safe audit capabilities"
  and .version == $version
  and .capabilities == {
    "scan": true,
    "check": true,
    "release.github": true,
    "vuln.github-release": true,
    "verify.release-asset": true,
    "verify.sigstore-bundle": true,
    "verify.tuf-bootstrap": true,
    "binary.exec": true,
    "ioc.lookup": true,
    "ioc.list": true,
    "ioc.update": true,
    "setup.machine": true,
    "setup.create-bundle": true,
    "diff": true,
    "status": true
  }
  and .groups == {
    "top_level": {
      "scan": true,
      "check": true,
      "diff": true,
      "status": true
    },
    "release": {
      "github": true
    },
    "vuln": {
      "github-release": true
    },
    "verify": {
      "release-asset": true,
      "sigstore-bundle": true,
      "tuf-bootstrap": true
    },
    "binary": {
      "exec": true
    },
    "ioc": {
      "lookup": true,
      "list": true,
      "update": true
    },
    "setup": {
      "machine": true,
      "create-bundle": true
    }
  }
' <<<"$capabilities_json" >/dev/null || fail "capabilities json contract changed"
[[ ! -e "$tmp/cap-data/checks" ]] || fail "capabilities wrote audit checks"
pass "capabilities json contract"

fixture="$tmp/cisa-kev.json"
fixture_url="file://$fixture"
today="$(date +%F)"
cat > "$fixture" <<JSON
{
  "title": "CISA Known Exploited Vulnerabilities Catalog",
  "catalogVersion": "test",
  "dateReleased": "${today}T00:00:00Z",
  "count": 2,
  "vulnerabilities": [
    {
      "cveID": "CVE-2026-0001",
      "vendorProject": "Example",
      "product": "Example Product",
      "vulnerabilityName": "Recent test vulnerability",
      "dateAdded": "$today",
      "shortDescription": "Test",
      "requiredAction": "Patch",
      "dueDate": "2026-06-01",
      "knownRansomwareCampaignUse": "Unknown",
      "notes": "",
      "cwes": ["CWE-79"]
    },
    {
      "cveID": "CVE-2020-0001",
      "vendorProject": "Example",
      "product": "Old Product",
      "vulnerabilityName": "Old test vulnerability",
      "dateAdded": "2020-01-01",
      "shortDescription": "Test",
      "requiredAction": "Patch",
      "dueDate": "2020-02-01",
      "knownRansomwareCampaignUse": "Unknown",
      "notes": "",
      "cwes": []
    }
  ]
}
JSON

SAFE_AUDIT_CONFIG_DIR="$tmp/config" \
SAFE_AUDIT_DATA_DIR="$tmp/data" \
SAFE_AUDIT_CISA_KEV_URL="$fixture_url" \
  "$SAFE_AUDIT" ioc --update --since 7d >/dev/null

jq -e '.strings == ["CVE-2026-0001"]' "$tmp/data/ioc/cisa-kev-ioc.json" >/dev/null || fail "ioc --update did not filter fixture"
pass "ioc update fixture"

scanroot="$tmp/scanroot"
mkdir -p "$scanroot"
printf 'marker CVE-2026-0001\n' > "$scanroot/marker.txt"

SAFE_AUDIT_CONFIG_DIR="$tmp/config-scan" \
SAFE_AUDIT_DATA_DIR="$tmp/data-scan" \
SAFE_AUDIT_CISA_KEV_URL="$fixture_url" \
SAFE_AUDIT_IOC_ROOT="$scanroot" \
  "$SAFE_AUDIT" ioc --update --since 7d --machine local >/dev/null

result="$(find "$tmp/data-scan/ioc" -maxdepth 1 -type f -name '*cisa-kev.json' | sort | tail -n 1)"
[[ -n "$result" ]] || fail "ioc scan result not written"
jq -e '.scans[0].string_hits | length == 1' "$result" >/dev/null || fail "ioc scan did not find fixture marker"
pass "ioc update scan"

project="$tmp/project"
mkdir -p "$project/app" "$project/vendor"
cat > "$project/.safe-audit" <<'YAML'
ignore:
  - vendor
YAML
printf '{}\n' > "$project/app/package-lock.json"
printf '{}\n' > "$project/vendor/package-lock.json"

lockfiles="$(
  SAFE_AUDIT_CONFIG_DIR="$tmp/config-ignore" \
  SAFE_AUDIT_DATA_DIR="$tmp/data-ignore" \
  SAFE_AUDIT_PATH="$SAFE_AUDIT" \
  PROJECT_PATH="$project" \
    bash -c 'set -- --version; source "$SAFE_AUDIT_PATH" >/dev/null; gather_projects_from_source "$PROJECT_PATH"; printf "%s\n" "${CURRENT_LOCKFILES[@]}"'
)"
grep -q '/app/package-lock.json$' <<<"$lockfiles" || fail "ignore test missed app lockfile"
if grep -q '/vendor/package-lock.json$' <<<"$lockfiles"; then
  fail "ignore test included vendor lockfile"
fi
pass ".safe-audit ignore"

pruned_files="$(
  SAFE_AUDIT_CONFIG_DIR="$tmp/config-prune" \
  SAFE_AUDIT_DATA_DIR="$tmp/data-prune" \
  SAFE_AUDIT_PATH="$SAFE_AUDIT" \
  PROJECT_PATH="$project" \
    bash -c 'set -- --version; source "$SAFE_AUDIT_PATH" >/dev/null; find_source_files_pruned "$PROJECT_PATH" | tr "\0" "\n"'
)"
grep -q '/app/package-lock.json$' <<<"$pruned_files" || fail "pruned find missed app lockfile"
if grep -q '/vendor/package-lock.json$' <<<"$pruned_files"; then
  fail "pruned find traversed ignored vendor directory"
fi
pass "ignored root directories are pruned"

stage="$tmp/stage"
SAFE_AUDIT_CONFIG_DIR="$tmp/config-stage" \
SAFE_AUDIT_DATA_DIR="$tmp/data-stage" \
SAFE_AUDIT_PATH="$SAFE_AUDIT" \
PROJECT_PATH="$project" \
STAGE_PATH="$stage" \
  bash -c 'set -- --version; source "$SAFE_AUDIT_PATH" >/dev/null; gather_stage_locally "$PROJECT_PATH" "$STAGE_PATH"'
[[ -f "$stage/app/package-lock.json" ]] || fail "staging missed app lockfile"
[[ ! -e "$stage/vendor/package-lock.json" ]] || fail "staging copied ignored vendor lockfile"
pass "staged manifests honor ignore"

exclude_args="$(
  SAFE_AUDIT_CONFIG_DIR="$tmp/config-excludes" \
  SAFE_AUDIT_DATA_DIR="$tmp/data-excludes" \
  SAFE_AUDIT_PATH="$SAFE_AUDIT" \
  PROJECT_PATH="$project" \
    bash -c 'set -- --version; source "$SAFE_AUDIT_PATH" >/dev/null; gather_projects_from_source "$PROJECT_PATH"; syft_exclude_args_for_current_scan' | tr '\0' '\n'
)"
grep -q '^vendor$' <<<"$exclude_args" || fail "syft excludes omitted vendor pattern"
grep -q '^vendor/\*\*$' <<<"$exclude_args" || fail "syft excludes omitted vendor subtree pattern"
pass "syft exclude args"

default_bundle_path="$(
  SAFE_AUDIT_CONFIG_DIR="$tmp/config-default-bundle" \
  SAFE_AUDIT_DATA_DIR="$tmp/data-default-bundle" \
  SAFE_AUDIT_PATH="$SAFE_AUDIT" \
    bash -c 'set -- --version; source "$SAFE_AUDIT_PATH" >/dev/null; resolve_scanner_bundle_path latest'
)"
[[ "$default_bundle_path" == "$tmp/data-default-bundle/tool-bundles/scanners.tar.gz" ]] || fail "default bundle path did not resolve"
pass "default bundle path"

mockbin="$tmp/mockbin"
mkdir -p "$mockbin"
for tool in osv-scanner syft grype; do
  cat > "$mockbin/$tool" <<SH
#!/usr/bin/env bash
if [[ "\${1:-}" == "--version" ]]; then
  echo "$tool mock 1.2.3"
elif [[ "$tool" == "grype" && "\${1:-}" == "db" && "\${2:-}" == "status" ]]; then
  printf '{"valid":true,"built":"%sT00:00:00Z","path":"/tmp/grype.db","schemaVersion":"5"}\n' "$today"
else
  case "$tool" in
    syft) printf '{"components":[]}\n' ;;
    grype) printf '{"matches":[]}\n' ;;
    osv-scanner) printf '{"results":[]}\n' ;;
  esac
fi
SH
  chmod +x "$mockbin/$tool"
done

mock_bundle="$tmp/mock-scanners.tar.gz"
PATH="$mockbin:$PATH" \
SAFE_AUDIT_CONFIG_DIR="$tmp/config-mock-bundle" \
SAFE_AUDIT_DATA_DIR="$tmp/data-mock-bundle" \
SAFE_AUDIT_PATH="$SAFE_AUDIT" \
BUNDLE_PATH="$mock_bundle" \
  bash -c 'set -- --version; source "$SAFE_AUDIT_PATH" >/dev/null; create_scanner_bundle "$BUNDLE_PATH" >/dev/null'
tar -xzf "$mock_bundle" -C "$tmp" manifest.json
jq -e '.tools | length == 3 and all(.[]; (.name and .source and (.version | test("mock 1.2.3"))))' "$tmp/manifest.json" >/dev/null || fail "bundle manifest omitted version metadata"
pass "bundle manifest version fields"

health="$tmp/grype-health.json"
PATH="$mockbin:$PATH" \
SAFE_AUDIT_CONFIG_DIR="$tmp/config-grype" \
SAFE_AUDIT_DATA_DIR="$tmp/data-grype" \
SAFE_AUDIT_PATH="$SAFE_AUDIT" \
HEALTH_PATH="$health" \
  bash -c 'set -- --version; source "$SAFE_AUDIT_PATH" >/dev/null; grype_db_health_json local "$HEALTH_PATH"'
jq -e '.healthy == true and .status == "ok" and .schema_version == "5"' "$health" >/dev/null || fail "grype db health did not parse mocked JSON"
pass "grype db health json"

grype_invalid_bin="$tmp/grype-invalid-bin"
mkdir -p "$grype_invalid_bin"
cat > "$grype_invalid_bin/grype" <<'SH'
#!/usr/bin/env bash
if [[ "${1:-}" == "db" && "${2:-}" == "status" ]]; then
  printf '{"schemaVersion":"","path":"/tmp/grype.db","valid":false,"error":"database does not exist"}\n'
  exit 1
fi
printf 'grype mock\n'
SH
chmod +x "$grype_invalid_bin/grype"
invalid_health="$tmp/grype-invalid-health.json"
PATH="$grype_invalid_bin:$PATH" \
SAFE_AUDIT_CONFIG_DIR="$tmp/config-grype-invalid" \
SAFE_AUDIT_DATA_DIR="$tmp/data-grype-invalid" \
SAFE_AUDIT_PATH="$SAFE_AUDIT" \
HEALTH_PATH="$invalid_health" \
  bash -c 'set -- --version; source "$SAFE_AUDIT_PATH" >/dev/null; grype_db_health_json local "$HEALTH_PATH"'
jq -e '.healthy == false and .status == "invalid" and .error == "database does not exist" and .exit_code == 1' "$invalid_health" >/dev/null || fail "grype db health discarded nonzero json"
pass "grype db health nonzero json"

setup_db_bin="$tmp/setup-db-bin"
setup_db_state="$tmp/setup-db-state"
mkdir -p "$setup_db_bin"
cat > "$setup_db_bin/grype" <<SH
#!/usr/bin/env bash
case "\${1:-} \${2:-}" in
  "db status")
    if [[ -f "$setup_db_state" ]]; then
      printf '{"valid":true,"built":"%sT00:00:00Z","path":"/tmp/grype.db","schemaVersion":"5"}\n' "$today"
      exit 0
    fi
    printf '{"valid":false,"error":"database does not exist"}\n'
    exit 1
    ;;
  "db update")
    touch "$setup_db_state"
    exit 0
    ;;
  *)
    printf 'grype mock\n'
    ;;
esac
SH
for tool in syft osv-scanner socket; do
  cat > "$setup_db_bin/$tool" <<'SH'
#!/usr/bin/env bash
printf 'tool mock\n'
SH
done
chmod +x "$setup_db_bin/grype" "$setup_db_bin/syft" "$setup_db_bin/osv-scanner" "$setup_db_bin/socket"
PATH="$setup_db_bin:$PATH" \
SAFE_AUDIT_CONFIG_DIR="$tmp/config-setup-db" \
SAFE_AUDIT_DATA_DIR="$tmp/data-setup-db" \
SAFE_AUDIT_PATH="$SAFE_AUDIT" \
  bash -c 'set -- --version; source "$SAFE_AUDIT_PATH" >/dev/null; setup_machine local "" 0 0 >/dev/null'
[[ -f "$setup_db_state" ]] || fail "setup did not initialize missing grype DB"
pass "setup initializes grype db"

grype_case="$tmp/grype-case.json"
cat > "$grype_case" <<'JSON'
{
  "matches": [
    {"vulnerability": {"severity": "Critical"}},
    {"vulnerability": {"severity": "High"}},
    {"vulnerability": {"severity": "Medium"}},
    {"vulnerability": {"severity": "Low"}}
  ]
}
JSON
case_counts="$(
  SAFE_AUDIT_CONFIG_DIR="$tmp/config-grype-case" \
  SAFE_AUDIT_DATA_DIR="$tmp/data-grype-case" \
  SAFE_AUDIT_PATH="$SAFE_AUDIT" \
  GRYPE_CASE="$grype_case" \
    bash -c 'set -- --version; source "$SAFE_AUDIT_PATH" >/dev/null; printf "%s %s %s %s\n" "$(count_grype_severity "$GRYPE_CASE" critical)" "$(count_grype_severity "$GRYPE_CASE" high)" "$(count_grype_severity "$GRYPE_CASE" medium)" "$(count_grype_severity "$GRYPE_CASE" low)"'
)"
[[ "$case_counts" == "1 1 1 1" ]] || fail "grype severity counting is case-sensitive"
pass "grype severity case handling"

SAFE_AUDIT_CONFIG_DIR="$tmp/config-missing" \
SAFE_AUDIT_DATA_DIR="$tmp/data-missing" \
SAFE_AUDIT_PATH="$SAFE_AUDIT" \
  bash -c '
    set -- --version
    source "$SAFE_AUDIT_PATH" >/dev/null
    tool_cache_set local "{\"osv-scanner\":null,\"grype\":null,\"syft\":null,\"govulncheck\":null,\"cargo-audit\":null,\"pip-audit\":null,\"socket\":null}"
    ! confirm_scan_with_missing_tools local
  ' || fail "missing tools did not skip in non-TTY"
pass "missing tools non-tty skip"

missing_output="$(
  SAFE_AUDIT_CONFIG_DIR="$tmp/config-missing-advice" \
  SAFE_AUDIT_DATA_DIR="$tmp/data-missing-advice" \
  SAFE_AUDIT_PATH="$SAFE_AUDIT" \
    bash -c '
      set -- --version
      source "$SAFE_AUDIT_PATH" >/dev/null
      tool_cache_set local "{\"osv-scanner\":null,\"grype\":null,\"syft\":null,\"govulncheck\":null,\"cargo-audit\":null,\"pip-audit\":null,\"socket\":null}"
      confirm_scan_with_missing_tools local "/tmp/example project"
    ' 2>&1 || true
)"
grep -q 'safe audit setup local' <<<"$missing_output" || fail "missing tools advice omitted setup command"
grep -q -- '--bundle <scanners.tar.gz>' <<<"$missing_output" || fail "missing tools advice omitted bundle guidance"
grep -q "safe audit scan --machine local --project /tmp/example\\\\ project" <<<"$missing_output" || fail "missing tools advice omitted scan rerun command"
pass "missing tools bundle then scan advice"

missing_default_output="$(
  SAFE_AUDIT_CONFIG_DIR="$tmp/config-missing-install" \
  SAFE_AUDIT_DATA_DIR="$tmp/data-missing-install" \
  SAFE_AUDIT_PATH="$SAFE_AUDIT" \
    bash -c '
      set -- --version
      source "$SAFE_AUDIT_PATH" >/dev/null
      is_tty() { return 0; }
      setup_machine() { printf "unexpected setup\n"; return 1; }
      tool_cache_set local "{\"osv-scanner\":null,\"grype\":null,\"syft\":null,\"govulncheck\":null,\"cargo-audit\":null,\"pip-audit\":null,\"socket\":null}"
      ! printf "\n" | confirm_scan_with_missing_tools local "/tmp/example project"
    ' 2>&1
)" || fail "missing tools default skip did not return nonzero"
grep -q '\[y/N\]' <<<"$missing_default_output" || fail "missing tools prompt omitted skip default"
if grep -q 'unexpected setup' <<<"$missing_default_output"; then
  fail "missing tools default triggered setup"
fi
pass "missing tools skip default"

partial_choice_output="$(
  SAFE_AUDIT_CONFIG_DIR="$tmp/config-missing-partial" \
  SAFE_AUDIT_DATA_DIR="$tmp/data-missing-partial" \
  SAFE_AUDIT_PATH="$SAFE_AUDIT" \
    bash -c '
      set -- --version
      source "$SAFE_AUDIT_PATH" >/dev/null
      is_tty() { return 0; }
      setup_machine() { printf "unexpected setup\n"; return 1; }
      tool_cache_set local "{\"osv-scanner\":null,\"grype\":null,\"syft\":null,\"govulncheck\":null,\"cargo-audit\":null,\"pip-audit\":null,\"socket\":null}"
      printf "y\n" | confirm_scan_with_missing_tools local
    ' 2>&1
)" || fail "missing tools partial choice did not continue"
if grep -q 'unexpected setup' <<<"$partial_choice_output"; then
  fail "missing tools partial choice installed scanners"
fi
pass "missing tools partial choice"

setup_refusal_output="$(
  SAFE_AUDIT_CONFIG_DIR="$tmp/config-missing-install-fail" \
  SAFE_AUDIT_DATA_DIR="$tmp/data-missing-install-fail" \
  SAFE_AUDIT_PATH="$SAFE_AUDIT" \
    bash -c '
      set -- --version
      source "$SAFE_AUDIT_PATH" >/dev/null
      detect_machine_tools() {
        tool_cache_set "$1" "{\"osv-scanner\":null,\"grype\":null,\"syft\":null,\"govulncheck\":null,\"cargo-audit\":null,\"pip-audit\":null,\"socket\":null}"
      }
      ! setup_machine local "" 0 0
    ' 2>&1
)" || fail "setup missing tools refusal did not return nonzero"
grep -q 'setup no longer downloads or runs external installers' <<<"$setup_refusal_output" || fail "setup refusal omitted external installer warning"
grep -q 'safe audit setup --create-bundle' <<<"$setup_refusal_output" || fail "setup refusal omitted bundle creation guidance"
pass "setup refuses unauthenticated installers"

SAFE_AUDIT_CONFIG_DIR="$tmp/config-missing-install-noop" \
SAFE_AUDIT_DATA_DIR="$tmp/data-missing-install-noop" \
SAFE_AUDIT_PATH="$SAFE_AUDIT" \
  bash -c '
    set -- --version
    source "$SAFE_AUDIT_PATH" >/dev/null
    is_tty() { return 0; }
    setup_machine() { return 1; }
    tool_cache_set local "{\"osv-scanner\":null,\"grype\":null,\"syft\":null,\"govulncheck\":null,\"cargo-audit\":null,\"pip-audit\":null,\"socket\":null}"
    ! printf "\n" | confirm_scan_with_missing_tools local
  ' || fail "missing tools default skip did not stop"
pass "missing tools default skip stops"

remote_interrupt_output="$(
  SAFE_AUDIT_CONFIG_DIR="$tmp/config-remote-interrupt" \
  SAFE_AUDIT_DATA_DIR="$tmp/data-remote-interrupt" \
  SAFE_AUDIT_PATH="$SAFE_AUDIT" \
  STAGE_PATH="$tmp/stage-interrupt" \
    bash -c '
      set -- --version
      source "$SAFE_AUDIT_PATH" >/dev/null
      jq ".machines.remote = {\"type\":\"ssh\",\"host\":\"remote\"}" "$MACHINES_FILE" > "$MACHINES_FILE.tmp"
      mv "$MACHINES_FILE.tmp" "$MACHINES_FILE"
      ssh_batch() { return 130; }
      if gather_stage_remotely remote /tmp "$STAGE_PATH"; then
        rc=0
      else
        rc=$?
      fi
      [[ "$rc" -ge 130 ]]
    ' 2>&1
)" || fail "remote staging interrupt did not return nonzero"
if grep -q 'falling back to manifest staging' <<<"$remote_interrupt_output"; then
  fail "remote staging interrupt triggered fallback"
fi
pass "remote staging interrupt does not fallback"

target_order="$(
  SAFE_AUDIT_CONFIG_DIR="$tmp/config-target-order" \
  SAFE_AUDIT_DATA_DIR="$tmp/data-target-order" \
  SAFE_AUDIT_PATH="$SAFE_AUDIT" \
    bash -c '
      set -- --version
      source "$SAFE_AUDIT_PATH" >/dev/null
      parse_machine_targets default --all
      printf "%s\n" "${MACHINE_TARGETS[@]}"
    '
)"
[[ "$target_order" == "local" ]] || fail "--all did not preserve configured machine order"
pass "--all preserves configured machine order"

required_local_tools="$(
  SAFE_AUDIT_CONFIG_DIR="$tmp/config-required-local" \
  SAFE_AUDIT_DATA_DIR="$tmp/data-required-local" \
  SAFE_AUDIT_PATH="$SAFE_AUDIT" \
    bash -c 'set -- --version; source "$SAFE_AUDIT_PATH" >/dev/null; required_tools_for_machine local'
)"
if grep -q '^socket$' <<<"$required_local_tools"; then
  fail "local scanner setup required optional socket CLI"
fi
required_remote_tools="$(
  SAFE_AUDIT_CONFIG_DIR="$tmp/config-required-remote" \
  SAFE_AUDIT_DATA_DIR="$tmp/data-required-remote" \
  SAFE_AUDIT_PATH="$SAFE_AUDIT" \
    bash -c '
      set -- --version
      source "$SAFE_AUDIT_PATH" >/dev/null
      jq ".machines.remote = {\"type\":\"ssh\",\"host\":\"remote\"}" "$MACHINES_FILE" > "$MACHINES_FILE.tmp"
      mv "$MACHINES_FILE.tmp" "$MACHINES_FILE"
      required_tools_for_machine remote
    '
)"
if grep -q '^socket$' <<<"$required_remote_tools"; then
  fail "remote required scanner tools included socket"
fi
pass "socket optional for scanner setup"

machine_root="$(
  SAFE_AUDIT_CONFIG_DIR="$tmp/config-machine-root" \
  SAFE_AUDIT_DATA_DIR="$tmp/data-machine-root" \
  SAFE_AUDIT_PATH="$SAFE_AUDIT" \
    bash -c '
      set -- --version
      source "$SAFE_AUDIT_PATH" >/dev/null
      jq ".machines.local.scan_root = \"/tmp/projects\"" "$MACHINES_FILE" > "$MACHINES_FILE.tmp"
      mv "$MACHINES_FILE.tmp" "$MACHINES_FILE"
      machine_scan_root local
    '
)"
[[ "$machine_root" == "/tmp/projects" ]] || fail "machine scan_root was not honored"
pass "machine scan_root"

unreachable_output="$(
  SAFE_AUDIT_CONFIG_DIR="$tmp/config-unreachable" \
  SAFE_AUDIT_DATA_DIR="$tmp/data-unreachable" \
  SAFE_AUDIT_PATH="$SAFE_AUDIT" \
    bash -c '
      set -- --version
      source "$SAFE_AUDIT_PATH" >/dev/null
      jq ".machines.remote = {\"type\":\"ssh\",\"host\":\"remote\"}" "$MACHINES_FILE" > "$MACHINES_FILE.tmp"
      mv "$MACHINES_FILE.tmp" "$MACHINES_FILE"
      ssh_batch() { return 255; }
      detect_machine_tools() { printf "unexpected detect\n"; return 1; }
      scan_machine remote
    ' 2>&1
)" || fail "unreachable machine scan failed"
grep -q 'remote: host unreachable; skipping scan' <<<"$unreachable_output" || fail "unreachable machine warning missing"
if grep -q 'unexpected detect' <<<"$unreachable_output"; then
  fail "unreachable machine still attempted tool detection"
fi
pass "unreachable machine warning"

SAFE_AUDIT_CONFIG_DIR="$tmp/config-machine-arg" \
SAFE_AUDIT_DATA_DIR="$tmp/data-machine-arg" \
  "$SAFE_AUDIT" scan --machine >/dev/null 2>"$tmp/machine-arg.err" && fail "--machine without value succeeded"
grep -q -- '--machine requires a comma-separated list' "$tmp/machine-arg.err" || fail "--machine missing value did not report usage error"
pass "--machine missing value handling"

SAFE_AUDIT_CONFIG_DIR="$tmp/config-strategy" \
SAFE_AUDIT_DATA_DIR="$tmp/data-strategy" \
SAFE_AUDIT_PATH="$SAFE_AUDIT" \
PATH="$mockbin:$PATH" \
  bash -c '
    set -- --version
    source "$SAFE_AUDIT_PATH" >/dev/null
    jq ".machines.remote = {\"type\":\"ssh\",\"host\":\"remote\"}" "$MACHINES_FILE" > "$MACHINES_FILE.tmp"
    mv "$MACHINES_FILE.tmp" "$MACHINES_FILE"
    tool_cache_set remote "{\"osv-scanner\":null,\"grype\":null,\"syft\":null,\"govulncheck\":null,\"cargo-audit\":null,\"pip-audit\":null,\"socket\":null}"
    machine_supports_remote_direct_scan remote && exit 1
    machine_supports_remote_tunneled_scan remote
  ' || fail "scan strategy fallback decisions failed"
pass "scan strategy fallback decisions"

sbom_root="$tmp/data-diff/sbom/local"
mkdir -p "$sbom_root"
old="$sbom_root/2026-01-01-sbom.cdx.json"
mid="$sbom_root/2026-02-01-sbom.cdx.json"
new="$sbom_root/2026-03-01-sbom.cdx.json"
printf '{"components":[]}\n' > "$old"
printf '{"components":[]}\n' > "$mid"
printf '{"components":[]}\n' > "$new"
touch -d '2026-01-01 00:00:00' "$old"
touch -d '2026-02-01 00:00:00' "$mid"
touch -d '2026-03-01 00:00:00' "$new"
selected="$(
  SAFE_AUDIT_CONFIG_DIR="$tmp/config-diff" \
  SAFE_AUDIT_DATA_DIR="$tmp/data-diff" \
  SAFE_AUDIT_PATH="$SAFE_AUDIT" \
    bash -c 'set -- --version; source "$SAFE_AUDIT_PATH" >/dev/null; select_previous_sbom local "$1" "2026-02-15"' _ "$new"
)"
[[ "$selected" == "$mid" ]] || fail "diff --since selected wrong previous snapshot"
pass "diff since previous snapshot"

if command -v osv-scanner >/dev/null 2>&1 && command -v syft >/dev/null 2>&1 && command -v grype >/dev/null 2>&1; then
  bundle="$tmp/scanners.tar.gz"
  SAFE_AUDIT_CONFIG_DIR="$tmp/config-bundle" \
  SAFE_AUDIT_DATA_DIR="$tmp/data-bundle" \
    "$SAFE_AUDIT" setup --create-bundle "$bundle" >/dev/null
  bundle_listing="$(tar -tzf "$bundle")"
  grep -q '^manifest.json$' <<<"$bundle_listing" || fail "bundle missing manifest"
  grep -q '^bin/osv-scanner$' <<<"$bundle_listing" || fail "bundle missing osv-scanner"
  grep -q '^bin/syft$' <<<"$bundle_listing" || fail "bundle missing syft"
  grep -q '^bin/grype$' <<<"$bundle_listing" || fail "bundle missing grype"
  pass "scanner bundle"
else
  pass "scanner bundle skipped because scanners are not all installed"
fi

bash "$ROOT/tests/audit/external_binary.sh"
