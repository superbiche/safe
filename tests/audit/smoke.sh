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
grep -q 'safe audit machine-audit \[--verbose\]' <<<"$help_output" || fail "help omits machine-audit --verbose"
grep -q '\[--deps-only | --full\]' <<<"$help_output" || fail "help omits scan mode options"
grep -q '\[--no-cache\]' <<<"$help_output" || fail "help omits scan --no-cache"
grep -q 'safe audit ioc --update' <<<"$help_output" || fail "help omits ioc --update"
grep -q 'safe audit setup --create-bundle' <<<"$help_output" || fail "help omits setup --create-bundle"
grep -q 'safe audit binary-audit release-review --spec' <<<"$help_output" || fail "help omits binary-audit release-review"
pass "help output"

grep -q 'capabilities' "$ROOT/lib/completions/_safe" || fail "completion omits capabilities"
grep -q 'capabilities_opts=(--json)' "$ROOT/lib/completions/_safe" || fail "completion omits capabilities --json"
grep -q 'machine_audit_opts=(--all --machine --project --verbose --deps-only --full --no-cache --result-out --allow-missing-tools)' "$ROOT/lib/completions/_safe" || fail "completion omits machine-audit mode options"
# Every option safe audit machine-audit advertises in --help must be completable: the
# old assertion pinned an exact list, so it passed precisely BECAUSE new flags
# were missing.
for scan_flag in $(SAFE_AUDIT_NO_INIT=1 "$ROOT/bin/safe-audit" help 2>/dev/null | grep -oE '^\s+safe audit machine-audit .*' | grep -oE '\-\-[a-z-]+' | sort -u); do
  grep -q -- "$scan_flag" <<<"$(grep -E '^\s+machine_audit_opts=' "$ROOT/lib/completions/_safe")" || fail "completion omits scan flag: $scan_flag"
done
grep -q 'binary_audit_subcmds=(release-review)' "$ROOT/lib/completions/_safe" || fail "completion omits binary-audit release-review"
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
    "package-audit": true,
    "repo-audit": true,
    "machine-audit": true,
    "binary-audit.release-review": true,
    "ioc.lookup": true,
    "ioc.list": true,
    "ioc.update": true,
    "setup.machine": true,
    "setup.create-bundle": true,
    "diff": true,
    "status": true
  }
  and .versions == {
    "binary-audit.release-review": {
      "spec_version": 3,
      "report_schema_version": 1
    }
  }
  and .groups == {
    "top_level": {
      "package-audit": true,
      "repo-audit": true,
      "machine-audit": true,
      "diff": true,
      "status": true
    },
    "binary-audit": {
      "release-review": true
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
mkdir -p "$project/app" "$project/vendor" "$project/node_modules/pkg"
cat > "$project/.safe-audit" <<'YAML'
ignore:
  - vendor
YAML
printf '{}\n' > "$project/app/package-lock.json"
printf 'console.log("app")\n' > "$project/app/index.js"
printf '{}\n' > "$project/vendor/package-lock.json"
printf 'console.log("dependency")\n' > "$project/node_modules/pkg/index.js"

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
[[ -f "$stage/app/index.js" ]] || fail "source staging missed first-party source file"
[[ ! -e "$stage/vendor/package-lock.json" ]] || fail "staging copied ignored vendor lockfile"
[[ ! -e "$stage/node_modules/pkg/index.js" ]] || fail "source staging copied default-excluded node_modules"
pass "source staging honors project and default excludes"

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

discovery_verbose="$(
  SAFE_AUDIT_CONFIG_DIR="$tmp/config-discovery-verbose" \
  SAFE_AUDIT_DATA_DIR="$tmp/data-discovery-verbose" \
  SAFE_AUDIT_PATH="$SAFE_AUDIT" \
  PROJECT_PATH="$project" \
    bash -c 'set -- --version; source "$SAFE_AUDIT_PATH" >/dev/null; SAFE_AUDIT_VERBOSE=1 gather_projects_from_source "$PROJECT_PATH"' 2>&1
)"
project_quoted="$(printf '%q' "$project")"
grep -Fq "verbose: project discovery: source=$project_quoted" <<<"$discovery_verbose" || fail "verbose discovery omitted source"
grep -Fq 'verbose: project discovery: manifests=2 lockfiles=1 project_roots=1 syft_excludes=2' <<<"$discovery_verbose" || fail "verbose discovery omitted counts"
grep -Fq "verbose: project root: $project_quoted" <<<"$discovery_verbose" || fail "verbose discovery omitted project root"
grep -Fq "verbose: lockfile: $project/app/package-lock.json" <<<"$discovery_verbose" || fail "verbose discovery omitted lockfile"
if grep -Fq "$project/vendor/package-lock.json" <<<"$discovery_verbose"; then
  fail "verbose discovery included ignored vendor lockfile"
fi
pass "verbose project discovery scope"

home_scan="$tmp/home-scan"
mkdir -p "$home_scan/project/src" "$home_scan/project/node_modules/pkg" "$home_scan/random"
printf '{"name":"demo"}\n' > "$home_scan/project/package.json"
printf 'console.log("source")\n' > "$home_scan/project/src/index.js"
printf 'console.log("dependency")\n' > "$home_scan/project/node_modules/pkg/index.js"
printf 'console.log("not a project")\n' > "$home_scan/random/outside.js"
home_stage="$tmp/home-stage"
SAFE_AUDIT_CONFIG_DIR="$tmp/config-home-stage" \
SAFE_AUDIT_DATA_DIR="$tmp/data-home-stage" \
SAFE_AUDIT_PATH="$SAFE_AUDIT" \
HOME_SCAN="$home_scan" \
HOME_STAGE="$home_stage" \
  bash -c 'set -- --version; source "$SAFE_AUDIT_PATH" >/dev/null; gather_stage_locally "$HOME_SCAN" "$HOME_STAGE" source 0'
[[ -f "$home_stage/project/package.json" ]] || fail "default home staging missed project manifest"
[[ -f "$home_stage/project/src/index.js" ]] || fail "default home staging missed project source"
[[ ! -e "$home_stage/project/node_modules/pkg/index.js" ]] || fail "default home staging copied node_modules"
[[ ! -e "$home_stage/random/outside.js" ]] || fail "default home staging copied non-project source"
pass "default scan stages discovered projects only"

remote_stage_fixture="$tmp/remote-stage-fixture"
mkdir -p "$remote_stage_fixture/src" "$remote_stage_fixture/node_modules/pkg"
printf '{"name":"remote-demo"}\n' > "$remote_stage_fixture/package.json"
printf 'console.log("remote source")\n' > "$remote_stage_fixture/src/index.js"
printf 'console.log("remote dependency")\n' > "$remote_stage_fixture/node_modules/pkg/index.js"
remote_source_stage="$tmp/remote-source-stage"
remote_full_stage="$tmp/remote-full-stage"
mkdir -p "$remote_source_stage" "$remote_full_stage"
SAFE_AUDIT_CONFIG_DIR="$tmp/config-remote-source-stage" \
SAFE_AUDIT_DATA_DIR="$tmp/data-remote-source-stage" \
SAFE_AUDIT_PATH="$SAFE_AUDIT" \
REMOTE_STAGE_FIXTURE="$remote_stage_fixture" \
REMOTE_SOURCE_STAGE="$remote_source_stage" \
  bash -c 'set -- --version; source "$SAFE_AUDIT_PATH" >/dev/null; remote_stage_helper_script | bash -s -- "$REMOTE_STAGE_FIXTURE" source 1 | tar -xzf - -C "$REMOTE_SOURCE_STAGE"'
SAFE_AUDIT_CONFIG_DIR="$tmp/config-remote-full-stage" \
SAFE_AUDIT_DATA_DIR="$tmp/data-remote-full-stage" \
SAFE_AUDIT_PATH="$SAFE_AUDIT" \
REMOTE_STAGE_FIXTURE="$remote_stage_fixture" \
REMOTE_FULL_STAGE="$remote_full_stage" \
  bash -c 'set -- --version; source "$SAFE_AUDIT_PATH" >/dev/null; remote_stage_helper_script | bash -s -- "$REMOTE_STAGE_FIXTURE" full 1 | tar -xzf - -C "$REMOTE_FULL_STAGE"'
[[ -f "$remote_source_stage/src/index.js" ]] || fail "remote source staging missed first-party source"
[[ ! -e "$remote_source_stage/node_modules/pkg/index.js" ]] || fail "remote source staging copied node_modules"
[[ -f "$remote_full_stage/node_modules/pkg/index.js" ]] || fail "remote full staging missed node_modules"
pass "remote staging honors source vs full mode"

# Nested repositories: a linked worktree or a nested clone under the target is
# a second copy of the same codebase. Auditing them as part of the target
# multiplied every finding by the number of copies (12x on the Laravel + pnpm
# project with 11 worktrees under .task/ that motivated this). Submodules are
# NOT copies — they are the parent's own dependencies — and stay discovered.
nested_fixture="$tmp/nested-repos/app"
mkdir -p "$nested_fixture/.git" \
  "$nested_fixture/.task/wt" \
  "$nested_fixture/nested-clone/.git" \
  "$nested_fixture/sub" \
  "$nested_fixture/packages/lib"
printf '{"name":"app"}\n' > "$nested_fixture/package.json"
printf '{"lockfileVersion":3}\n' > "$nested_fixture/package-lock.json"
# A linked worktree: .git is a FILE pointing into the parent's worktrees dir.
printf 'gitdir: %s/.git/worktrees/wt\n' "$nested_fixture" > "$nested_fixture/.task/wt/.git"
printf '{"name":"wt"}\n' > "$nested_fixture/.task/wt/package.json"
printf '{"lockfileVersion":3}\n' > "$nested_fixture/.task/wt/package-lock.json"
# A nested independent clone: .git is a DIRECTORY.
printf '{"name":"clone"}\n' > "$nested_fixture/nested-clone/package.json"
printf '{"lockfileVersion":3}\n' > "$nested_fixture/nested-clone/package-lock.json"
# A submodule: .git is a file pointing into the parent's .git/modules.
printf 'gitdir: ../.git/modules/sub\n' > "$nested_fixture/sub/.git"
printf '{"name":"sub"}\n' > "$nested_fixture/sub/package.json"
printf '{"lockfileVersion":3}\n' > "$nested_fixture/sub/package-lock.json"
# An ordinary monorepo package carries no .git and is never a nested repo.
printf '{"name":"lib"}\n' > "$nested_fixture/packages/lib/package.json"
printf '{"lockfileVersion":3}\n' > "$nested_fixture/packages/lib/package-lock.json"

nested_report="$tmp/nested-discovery.txt"
SAFE_AUDIT_CONFIG_DIR="$tmp/config-nested" \
SAFE_AUDIT_DATA_DIR="$tmp/data-nested" \
SAFE_AUDIT_PATH="$SAFE_AUDIT" \
NESTED_FIXTURE="$nested_fixture" \
  bash -c 'set -- --version; source "$SAFE_AUDIT_PATH" >/dev/null
    gather_projects_from_source "$NESTED_FIXTURE" 1 2>/dev/null
    for lf in "${CURRENT_LOCKFILES[@]}"; do printf "lockfile %s\n" "${lf#$NESTED_FIXTURE/}"; done
    for r in "${CURRENT_PROJECT_ROOTS[@]}"; do printf "root %s\n" "${r#$NESTED_FIXTURE/}"; done
    for x in "${CURRENT_SYFT_EXCLUDES[@]}"; do printf "exclude %s\n" "$x"; done' > "$nested_report"

grep -qx 'lockfile package-lock.json' "$nested_report" || fail "nested-repo prune dropped the target's own lockfile"
grep -qx 'lockfile packages/lib/package-lock.json' "$nested_report" || fail "nested-repo prune dropped a monorepo package"
grep -qx 'lockfile sub/package-lock.json' "$nested_report" || fail "nested-repo prune dropped a submodule"
grep -q 'lockfile .task/wt/' "$nested_report" && fail "linked worktree was discovered as part of its parent"
grep -q 'lockfile nested-clone/' "$nested_report" && fail "nested clone was discovered as part of its parent"
grep -qx 'root sub' "$nested_report" || fail "submodule lost its project root"
grep -q 'root .task/wt' "$nested_report" && fail "linked worktree kept a project root"
grep -qx 'exclude .task/wt' "$nested_report" || fail "syft excludes missed the linked worktree"
grep -qx 'exclude .task/wt/**' "$nested_report" || fail "syft excludes missed the linked worktree subtree"
grep -qx 'exclude nested-clone' "$nested_report" || fail "syft excludes missed the nested clone"
grep -qx 'exclude nested-clone/**' "$nested_report" || fail "syft excludes missed the nested clone subtree"
pass "nested repositories are pruned, submodules kept"

# The same rule must NOT empty a machine-audit scan: a scan root is a plain
# directory holding independent repositories side by side, and none of them has
# a .git-carrying ancestor under the root.
machine_scan_root="$tmp/nested-repos/scanroot"
mkdir -p "$machine_scan_root/repo-a/.git" "$machine_scan_root/repo-b/.git" "$machine_scan_root/repo-a/.task/wt"
printf '{"name":"a"}\n' > "$machine_scan_root/repo-a/package.json"
printf '{"lockfileVersion":3}\n' > "$machine_scan_root/repo-a/package-lock.json"
printf '{"name":"b"}\n' > "$machine_scan_root/repo-b/package.json"
printf '{"lockfileVersion":3}\n' > "$machine_scan_root/repo-b/package-lock.json"
printf 'gitdir: %s/repo-a/.git/worktrees/wt\n' "$machine_scan_root" > "$machine_scan_root/repo-a/.task/wt/.git"
printf '{"lockfileVersion":3}\n' > "$machine_scan_root/repo-a/.task/wt/package-lock.json"

machine_report="$tmp/nested-machine-discovery.txt"
SAFE_AUDIT_CONFIG_DIR="$tmp/config-nested-machine" \
SAFE_AUDIT_DATA_DIR="$tmp/data-nested-machine" \
SAFE_AUDIT_PATH="$SAFE_AUDIT" \
MACHINE_SCAN_ROOT="$machine_scan_root" \
  bash -c 'set -- --version; source "$SAFE_AUDIT_PATH" >/dev/null
    gather_projects_from_source "$MACHINE_SCAN_ROOT" 1 2>/dev/null
    for lf in "${CURRENT_LOCKFILES[@]}"; do printf "lockfile %s\n" "${lf#$MACHINE_SCAN_ROOT/}"; done' > "$machine_report"

grep -qx 'lockfile repo-a/package-lock.json' "$machine_report" || fail "scan root lost an independent repository"
grep -qx 'lockfile repo-b/package-lock.json' "$machine_report" || fail "scan root lost an independent repository"
grep -q 'lockfile repo-a/.task/wt/' "$machine_report" && fail "worktree inside a scan-root repository was discovered"
pass "independent repositories under a scan root stay discovered"

# Remote staging applies the same rule server-side: the .git entries it needs
# to see it never stages, so a stage built without the rule hands the local
# scan a tree where the duplication is already invisible.
nested_remote_stage="$tmp/nested-remote-stage"
mkdir -p "$nested_remote_stage"
SAFE_AUDIT_CONFIG_DIR="$tmp/config-nested-remote" \
SAFE_AUDIT_DATA_DIR="$tmp/data-nested-remote" \
SAFE_AUDIT_PATH="$SAFE_AUDIT" \
NESTED_FIXTURE="$nested_fixture" \
NESTED_REMOTE_STAGE="$nested_remote_stage" \
  bash -c 'set -- --version; source "$SAFE_AUDIT_PATH" >/dev/null; remote_stage_helper_script | bash -s -- "$NESTED_FIXTURE" source 1 | tar -xzf - -C "$NESTED_REMOTE_STAGE"'
[[ -f "$nested_remote_stage/package-lock.json" ]] || fail "remote staging dropped the target's own lockfile"
[[ -f "$nested_remote_stage/sub/package-lock.json" ]] || fail "remote staging dropped a submodule lockfile"
[[ ! -e "$nested_remote_stage/.task/wt/package-lock.json" ]] || fail "remote staging copied a linked worktree"
[[ ! -e "$nested_remote_stage/nested-clone/package-lock.json" ]] || fail "remote staging copied a nested clone"
pass "remote staging prunes nested repositories"

# The remote SCAN helper discovers lockfiles with its own walk. Before this it
# had no prunes at all, so it also read every lockfile under vendor/.
mkdir -p "$nested_fixture/vendor/dep"
printf '{"lockfileVersion":3}\n' > "$nested_fixture/vendor/dep/package-lock.json"
nested_remote_lockfiles="$tmp/nested-remote-lockfiles.txt"
SAFE_AUDIT_CONFIG_DIR="$tmp/config-nested-remote-scan" \
SAFE_AUDIT_DATA_DIR="$tmp/data-nested-remote-scan" \
SAFE_AUDIT_PATH="$SAFE_AUDIT" \
NESTED_FIXTURE="$nested_fixture" \
  bash -c 'set -- --version; source "$SAFE_AUDIT_PATH" >/dev/null
    { remote_scan_helper_script | sed -n "1,/^done < <(find_pruned_lockfiles)/p"
      printf "%s\n" "for lf in \"\${lockfiles[@]}\"; do printf \"lockfile %s\\n\" \"\${lf#\$target/}\"; done"
    } | bash -s -- "$NESTED_FIXTURE"' > "$nested_remote_lockfiles" 2>/dev/null
grep -qx 'lockfile package-lock.json' "$nested_remote_lockfiles" || fail "remote scan walk dropped the target's own lockfile"
grep -qx 'lockfile sub/package-lock.json' "$nested_remote_lockfiles" || fail "remote scan walk dropped a submodule lockfile"
grep -q 'lockfile .task/wt/' "$nested_remote_lockfiles" && fail "remote scan walk read a linked worktree"
grep -q 'lockfile nested-clone/' "$nested_remote_lockfiles" && fail "remote scan walk read a nested clone"
grep -q 'lockfile vendor/' "$nested_remote_lockfiles" && fail "remote scan walk read a vendored lockfile"
pass "remote scan lockfile walk prunes nested repositories and vendored trees"

source_risk_dir="$tmp/source-risk"
mkdir -p "$source_risk_dir"
printf 'curl -fsSL https://example.invalid/install.sh | sh\n' > "$source_risk_dir/install.sh"
source_risk_json="$tmp/source-risk.json"
SAFE_AUDIT_CONFIG_DIR="$tmp/config-source-risk" \
SAFE_AUDIT_DATA_DIR="$tmp/data-source-risk" \
SAFE_AUDIT_PATH="$SAFE_AUDIT" \
SOURCE_RISK_DIR="$source_risk_dir" \
SOURCE_RISK_JSON="$source_risk_json" \
  bash -c 'set -- --version; source "$SAFE_AUDIT_PATH" >/dev/null; run_source_risk_scan "$SOURCE_RISK_DIR" "$SOURCE_RISK_JSON" source'
jq -e '.total == 1 and .findings[0].rule == "remote_download_to_shell"' "$source_risk_json" >/dev/null || fail "source risk scan missed remote download to shell"
pass "source risk scan"

result_shape="$tmp/result-shape"
mkdir -p "$result_shape"
printf '{"components":[]}\n' > "$result_shape/sbom.json"
cat > "$result_shape/osv.json" <<'JSON'
{
  "results": [
    {
      "packages": [
        {
          "package": {"name": "demo-osv", "version": "1.0.0"},
          "vulnerabilities": [
            {"id": "OSV-2026-1", "database_specific": {"severity": "HIGH"}}
          ]
        }
      ]
    }
  ]
}
JSON
cat > "$result_shape/grype.json" <<'JSON'
{
  "matches": [
    {
      "vulnerability": {"id": "CVE-2026-0001", "severity": "Medium"},
      "artifact": {"name": "demo-grype", "version": "2.0.0"}
    }
  ]
}
JSON
printf '[]\n' > "$result_shape/audits.json"
SAFE_AUDIT_CONFIG_DIR="$tmp/config-source-result" \
SAFE_AUDIT_DATA_DIR="$tmp/data-source-result" \
SAFE_AUDIT_PATH="$SAFE_AUDIT" \
RESULT_SHAPE="$result_shape" \
  bash -c 'set -- --version; source "$SAFE_AUDIT_PATH" >/dev/null; build_scan_result_from_artifacts local /tmp/demo local-direct "$RESULT_SHAPE/sbom.json" "$RESULT_SHAPE/osv.json" "$RESULT_SHAPE/grype.json" "$RESULT_SHAPE/audits.json" source "$RESULT_SHAPE/../source-risk.json"' >/dev/null
source_result="$tmp/data-source-result/results/local/$(date +%F)-scan.json"
jq -e '
  .scan_mode == "source"
  and .source_scan.total == 1
  and .cve_scan.high == 1
  and .cve_scan.medium == 1
  and (.cve_scan.findings | length) == 2
  and .verdict == "WARN"
' "$source_result" >/dev/null || fail "source scan result shape missing or verdict not warned"
pass "source scan result integration"

ecosystem_scope="$tmp/ecosystem-scope"
mkdir -p "$ecosystem_scope"
printf '{"name":"node-only"}\n' > "$ecosystem_scope/package.json"
ecosystem_scope_json="$(
  SAFE_AUDIT_CONFIG_DIR="$tmp/config-ecosystem-scope" \
  SAFE_AUDIT_DATA_DIR="$tmp/data-ecosystem-scope" \
  SAFE_AUDIT_PATH="$SAFE_AUDIT" \
  ECOSYSTEM_SCOPE="$ecosystem_scope" \
    bash -c '
      set -- --version
      source "$SAFE_AUDIT_PATH" >/dev/null
      run_npm_audit_dir() { printf "%s\n" "$(render_ecosystem_audit_json npm-audit ok 0 0 0 0 0)" > "$2"; }
      run_cargo_audit_dir() { printf "unexpected cargo audit\n" >&2; return 1; }
      run_project_ecosystem_audits "$ECOSYSTEM_SCOPE" "$ECOSYSTEM_SCOPE/out"
    '
)"
jq -e 'length == 1 and .[0].scanner == "npm-audit"' <<<"$ecosystem_scope_json" >/dev/null || fail "ecosystem audits ran unrelated project tools"
pass "ecosystem audits are scoped to detected ecosystems"

missing_audit_tools="$(
  SAFE_AUDIT_CONFIG_DIR="$tmp/config-project-tools" \
  SAFE_AUDIT_DATA_DIR="$tmp/data-project-tools" \
  SAFE_AUDIT_PATH="$SAFE_AUDIT" \
  ECOSYSTEM_SCOPE="$ecosystem_scope" \
    bash -c '
      set -- --version
      source "$SAFE_AUDIT_PATH" >/dev/null
      project_audit_tool_available() { return 1; }
      gather_projects_from_source "$ECOSYSTEM_SCOPE" >/dev/null
      missing_project_audit_tools_for_current_projects
    '
)"
grep -q '^npm$' <<<"$missing_audit_tools" || fail "node audit tool was not required"
if grep -q '^cargo-audit$' <<<"$missing_audit_tools"; then
  fail "node-only project required cargo-audit"
fi
pass "project audit tool requirements are scoped"

rust_scope="$tmp/rust-scope"
mkdir -p "$rust_scope"
printf '[package]\nname = "demo"\nversion = "0.1.0"\n' > "$rust_scope/Cargo.toml"
missing_project_output="$(
  SAFE_AUDIT_CONFIG_DIR="$tmp/config-project-tools-missing" \
  SAFE_AUDIT_DATA_DIR="$tmp/data-project-tools-missing" \
  SAFE_AUDIT_PATH="$SAFE_AUDIT" \
  RUST_SCOPE="$rust_scope" \
    bash -c '
      set -- --version
      source "$SAFE_AUDIT_PATH" >/dev/null
      project_audit_tool_available() { [[ "$1" != "cargo-audit" ]]; }
      gather_projects_from_source "$RUST_SCOPE" >/dev/null
      confirm_scan_with_missing_project_audit_tools local "$RUST_SCOPE"
    ' 2>&1 || true
)"
grep -q 'missing project audit tools.*cargo-audit' <<<"$missing_project_output" || fail "missing project audit prompt omitted cargo-audit"
grep -q 'cargo install cargo-audit' <<<"$missing_project_output" || fail "missing project audit prompt omitted install hint"
grep -q 'skipping scan because project audit tools are missing in non-TTY mode' <<<"$missing_project_output" || fail "missing project audit tools did not fail closed"
pass "missing project audit tools fail closed"

partial_result="$tmp/partial-result"
mkdir -p "$partial_result"
printf '{"components":[]}\n' > "$partial_result/sbom.json"
printf '{"results":[]}\n' > "$partial_result/osv.json"
printf '{"matches":[]}\n' > "$partial_result/grype.json"
printf '[{"scanner":"cargo-audit","status":"skipped","total":0,"critical":0,"high":0,"medium":0,"low":0,"note":"cargo-audit unavailable"}]\n' > "$partial_result/audits.json"
printf '{"status":"ok","note":null,"scanned_files":0,"total":0,"findings":[]}\n' > "$partial_result/source.json"
partial_summary="$(
  SAFE_AUDIT_CONFIG_DIR="$tmp/config-partial-result" \
  SAFE_AUDIT_DATA_DIR="$tmp/data-partial-result" \
  SAFE_AUDIT_PATH="$SAFE_AUDIT" \
  PARTIAL_RESULT="$partial_result" \
    bash -c 'set -- --version; source "$SAFE_AUDIT_PATH" >/dev/null; build_scan_result_from_artifacts local /tmp/demo local-direct "$PARTIAL_RESULT/sbom.json" "$PARTIAL_RESULT/osv.json" "$PARTIAL_RESULT/grype.json" "$PARTIAL_RESULT/audits.json" source "$PARTIAL_RESULT/source.json"'
)"
partial_result_json="$tmp/data-partial-result/results/local/$(date +%F)-scan.json"
jq -e '.verdict == "WARN"' "$partial_result_json" >/dev/null || fail "partial ecosystem audit did not warn"
grep -q 'cargo-audit: skipped (cargo-audit unavailable)' <<<"$partial_summary" || fail "partial ecosystem audit summary looked like zero advisories"
pass "partial ecosystem audit reports skipped tools"

partial_core="$tmp/partial-core"
mkdir -p "$partial_core"
cat > "$partial_core/sbom.json" <<'JSON'
{"components":[],"metadata":{"tools":[{"name":"safe-audit","note":"syft unavailable"}]}}
JSON
printf '{"results":[],"skipped":"osv-scanner unavailable","skip_reason":"scanner_unavailable"}\n' > "$partial_core/osv.json"
printf '{"matches":[],"skipped":"grype unavailable"}\n' > "$partial_core/grype.json"
printf '[]\n' > "$partial_core/audits.json"
printf '{"status":"ok","note":null,"scanned_files":0,"total":0,"findings":[]}\n' > "$partial_core/source.json"
partial_core_summary="$(
  SAFE_AUDIT_CONFIG_DIR="$tmp/config-partial-core" \
  SAFE_AUDIT_DATA_DIR="$tmp/data-partial-core" \
  SAFE_AUDIT_PATH="$SAFE_AUDIT" \
  PARTIAL_CORE="$partial_core" \
    bash -c 'set -- --version; source "$SAFE_AUDIT_PATH" >/dev/null; build_scan_result_from_artifacts local /tmp/demo local-direct "$PARTIAL_CORE/sbom.json" "$PARTIAL_CORE/osv.json" "$PARTIAL_CORE/grype.json" "$PARTIAL_CORE/audits.json" source "$PARTIAL_CORE/source.json"'
)"
partial_core_json="$tmp/data-partial-core/results/local/$(date +%F)-scan.json"
jq -e '.verdict == "WARN" and .tool_status["osv-scanner"].status == "skipped" and .tool_status.syft.status == "skipped" and .tool_status.grype.status == "skipped"' "$partial_core_json" >/dev/null || fail "partial core scanner result did not warn"
grep -q 'osv-scanner: skipped (osv-scanner unavailable)' <<<"$partial_core_summary" || fail "partial core summary omitted osv skip"
grep -q 'syft: skipped (syft unavailable)' <<<"$partial_core_summary" || fail "partial core summary omitted syft skip"
grep -q 'grype: skipped (grype unavailable)' <<<"$partial_core_summary" || fail "partial core summary omitted grype skip"
pass "partial core scanner audit reports skipped tools"

syft_tools_shape="$tmp/syft-tools-shape"
mkdir -p "$syft_tools_shape"
cat > "$syft_tools_shape/sbom.json" <<'JSON'
{
  "components": [],
  "metadata": {
    "tools": {
      "components": [
        {"type": "application", "name": "syft", "version": "1.0.0"}
      ]
    }
  }
}
JSON
printf '{"results":[],"skipped":"no lockfiles discovered","skip_reason":"no_lockfiles"}\n' > "$syft_tools_shape/osv.json"
printf '{"matches":[]}\n' > "$syft_tools_shape/grype.json"
printf '[]\n' > "$syft_tools_shape/audits.json"
printf '{"status":"ok","note":null,"scanned_files":0,"total":0,"findings":[]}\n' > "$syft_tools_shape/source.json"
SAFE_AUDIT_CONFIG_DIR="$tmp/config-syft-tools-shape" \
SAFE_AUDIT_DATA_DIR="$tmp/data-syft-tools-shape" \
SAFE_AUDIT_PATH="$SAFE_AUDIT" \
SYFT_TOOLS_SHAPE="$syft_tools_shape" \
  bash -c 'set -- --version; source "$SAFE_AUDIT_PATH" >/dev/null; build_scan_result_from_artifacts local /tmp/demo local-direct "$SYFT_TOOLS_SHAPE/sbom.json" "$SYFT_TOOLS_SHAPE/osv.json" "$SYFT_TOOLS_SHAPE/grype.json" "$SYFT_TOOLS_SHAPE/audits.json" source "$SYFT_TOOLS_SHAPE/source.json"' >/dev/null
syft_tools_shape_json="$tmp/data-syft-tools-shape/results/local/$(date +%F)-scan.json"
[[ -s "$syft_tools_shape_json" ]] || fail "syft tools components shape produced empty result"
jq -e '.tool_status.syft.status == "ok" and .tool_status["osv-scanner"].status == "ok"' "$syft_tools_shape_json" >/dev/null || fail "syft tools components shape did not parse"
pass "syft cyclonedx tools components shape"

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

osv_nonzero_bin="$tmp/osv-nonzero-bin"
mkdir -p "$osv_nonzero_bin"
cat > "$osv_nonzero_bin/osv-scanner" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" > "$OSV_ARGS_FILE"
printf 'Scanned test lockfile and found packages\n' >&2
cat <<'JSON'
{
  "results": [
    {
      "packages": [
        {
          "package": {"name": "demo", "version": "1.0.0"},
          "vulnerabilities": [
            {"id": "OSV-TEST-1", "database_specific": {"severity": "HIGH"}}
          ]
        }
      ]
    }
  ]
}
JSON
exit 1
SH
chmod +x "$osv_nonzero_bin/osv-scanner"
printf '{}\n' > "$tmp/osv-lock.json"
osv_nonzero_result="$tmp/osv-nonzero.json"
osv_nonzero_stderr="$(
  PATH="$osv_nonzero_bin:$PATH" \
  SAFE_AUDIT_CONFIG_DIR="$tmp/config-osv-nonzero" \
  SAFE_AUDIT_DATA_DIR="$tmp/data-osv-nonzero" \
  SAFE_AUDIT_PATH="$SAFE_AUDIT" \
  OSV_ARGS_FILE="$tmp/osv-args.txt" \
  OSV_NONZERO_RESULT="$osv_nonzero_result" \
  OSV_LOCK="$tmp/osv-lock.json" \
    bash -c 'set -- --version; source "$SAFE_AUDIT_PATH" >/dev/null; osv_scan_lockfiles local "$OSV_NONZERO_RESULT" "$OSV_LOCK"' 2>&1
)"
if grep -q 'osv-scanner failed' <<<"$osv_nonzero_stderr"; then
  fail "valid OSV JSON with nonzero exit was treated as scanner failure"
fi
jq -e '.results[0].packages[0].vulnerabilities[0].id == "OSV-TEST-1"' "$osv_nonzero_result" >/dev/null || fail "valid OSV JSON with nonzero exit was not preserved"
grep -q '^scan source --format json --lockfile=' "$tmp/osv-args.txt" || fail "osv-scanner invocation omitted scan source lockfile form"
pass "osv nonzero valid json preserved"

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
grep -q "safe audit machine-audit --machine local --project /tmp/example\\\\ project" <<<"$missing_output" || fail "missing tools advice omitted scan rerun command"
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

scan_missing_core="$tmp/scan-missing-core"
mkdir -p "$scan_missing_core"
scan_missing_core_output="$(
  SAFE_AUDIT_CONFIG_DIR="$tmp/config-scan-missing-core" \
  SAFE_AUDIT_DATA_DIR="$tmp/data-scan-missing-core" \
  SAFE_AUDIT_PATH="$SAFE_AUDIT" \
  SCAN_MISSING_CORE="$scan_missing_core" \
    bash -c '
      set -- --version
      source "$SAFE_AUDIT_PATH" >/dev/null
      detect_machine_tools() {
        tool_cache_set "$1" "{\"osv-scanner\":null,\"grype\":null,\"syft\":null,\"govulncheck\":null,\"cargo-audit\":null,\"pip-audit\":null,\"socket\":null}"
      }
      set +e
      repo_audit_command "$SCAN_MISSING_CORE"
      rc=$?
      set -e
      printf "RC=%s\n" "$rc"
    ' 2>&1
)"
grep -q 'RC=2' <<<"$scan_missing_core_output" || fail "scan with missing core tools did not fail closed"
grep -q 'skipping scan because required scanners are missing in non-TTY mode' <<<"$scan_missing_core_output" || fail "scan missing core tools omitted skip reason"
if grep -q 'repo-audit: finished' <<<"$scan_missing_core_output"; then
  fail "scan with missing core tools logged finished"
fi
pass "scan missing core tools exits nonzero"

scan_missing_project_tool="$tmp/scan-missing-project-tool"
mkdir -p "$scan_missing_project_tool"
printf '[package]\nname = "demo"\nversion = "0.1.0"\n' > "$scan_missing_project_tool/Cargo.toml"
scan_missing_project_tool_output="$(
  SAFE_AUDIT_CONFIG_DIR="$tmp/config-scan-missing-project-tool" \
  SAFE_AUDIT_DATA_DIR="$tmp/data-scan-missing-project-tool" \
  SAFE_AUDIT_PATH="$SAFE_AUDIT" \
  SCAN_MISSING_PROJECT_TOOL="$scan_missing_project_tool" \
    bash -c '
      set -- --version
      source "$SAFE_AUDIT_PATH" >/dev/null
      detect_machine_tools() {
        tool_cache_set "$1" "{\"osv-scanner\":\"/bin/true\",\"grype\":\"/bin/true\",\"syft\":\"/bin/true\",\"govulncheck\":null,\"cargo-audit\":null,\"pip-audit\":null,\"socket\":null}"
      }
      project_audit_tool_available() { [[ "$1" != "cargo-audit" ]]; }
      set +e
      repo_audit_command "$SCAN_MISSING_PROJECT_TOOL"
      rc=$?
      set -e
      printf "RC=%s\n" "$rc"
    ' 2>&1
)"
grep -q 'RC=2' <<<"$scan_missing_project_tool_output" || fail "scan with missing project audit tool did not fail closed"
grep -q 'missing project audit tools.*cargo-audit' <<<"$scan_missing_project_tool_output" || fail "scan missing project audit tool omitted tool"
if grep -q 'repo-audit: finished' <<<"$scan_missing_project_tool_output"; then
  fail "scan with missing project audit tool logged finished"
fi
pass "scan missing project audit tools exits nonzero"

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

scan_project="$tmp/project path"
mkdir -p "$scan_project"
scan_project_output="$(
  SAFE_AUDIT_CONFIG_DIR="$tmp/config-project-target-log" \
  SAFE_AUDIT_DATA_DIR="$tmp/data-project-target-log" \
  SAFE_AUDIT_PATH="$SAFE_AUDIT" \
  PROJECT_PATH="$scan_project" \
    bash -c '
      set -- --version
      source "$SAFE_AUDIT_PATH" >/dev/null
      jq ".machines = {\"rainbow\": {\"type\":\"local\"}, \"remote\": {\"type\":\"ssh\", \"host\":\"remote\"}}" "$MACHINES_FILE" > "$MACHINES_FILE.tmp"
      mv "$MACHINES_FILE.tmp" "$MACHINES_FILE"
      machine_reachable() { return 0; }
      detect_machine_tools() { return 0; }
      confirm_scan_with_missing_tools() { return 0; }
      scan_source_into_result() { printf "SCAN\t%s\t%s\t%s\t%s\t%s\t%s\n" "$1" "$2" "$3" "$4" "$5" "$6"; }
      repo_audit_command --verbose "$PROJECT_PATH"
    ' 2>&1
)"
scan_project_quoted="$(printf '%q' "$scan_project")"
grep -Fq "repo-audit: starting project $scan_project_quoted" <<<"$scan_project_output" || fail "project scan start log omitted target path"
grep -Fq "repo-audit: finished project $scan_project_quoted" <<<"$scan_project_output" || fail "project scan finish log omitted target path"
# The vocabulary leak this surface split exists to kill: repo-audit has no
# machine dimension, so no machine name may appear in its progress lines. The
# machine still shows in `verbose:` lines below — that is scan_machine's own
# internal logging, shared with machine-audit, and not this surface's voice.
while IFS= read -r progress_line; do
  case "$progress_line" in
    *rainbow*|*remote*) fail "repo-audit progress line named a machine: $progress_line" ;;
  esac
done < <(grep -E 'repo-audit: (starting|finished|failed) ' <<<"$scan_project_output" || true)
grep -Fq "verbose: repo-audit mode: source" <<<"$scan_project_output" || fail "verbose scan omitted default source mode"
grep -Fq "verbose: rainbow: resolved target=$scan_project_quoted" <<<"$scan_project_output" || fail "verbose scan omitted resolved project target"
grep -Fq "verbose: rainbow: using local direct scan source=$scan_project_quoted" <<<"$scan_project_output" || fail "verbose scan omitted local project source"
grep -Fq $'SCAN\trainbow\t'"$scan_project"$'\t'"$scan_project"$'\tlocal-direct\tsource\t1' <<<"$scan_project_output" || fail "project scan did not pass target path, mode, and strategy"
if grep -Fq $'SCAN\tremote\t' <<<"$scan_project_output"; then
  fail "project scan without --all scanned remote machine"
fi
pass "project scan verbose logs targeted local path"

scan_full_output="$(
  SAFE_AUDIT_CONFIG_DIR="$tmp/config-scan-full" \
  SAFE_AUDIT_DATA_DIR="$tmp/data-scan-full" \
  SAFE_AUDIT_PATH="$SAFE_AUDIT" \
  PROJECT_PATH="$scan_project" \
    bash -c '
      set -- --version
      source "$SAFE_AUDIT_PATH" >/dev/null
      scan_machine() { printf "SCAN\t%s\t%s\t%s\n" "$1" "${2:-}" "${3:-}"; }
      repo_audit_command --full "$PROJECT_PATH"
    ' 2>&1
)"
grep -Fq $'SCAN\tlocal\t'"$scan_project"$'\tfull' <<<"$scan_full_output" || fail "--full did not select full scan mode"
pass "full scan mode"

scan_deps_output="$(
  SAFE_AUDIT_CONFIG_DIR="$tmp/config-scan-deps" \
  SAFE_AUDIT_DATA_DIR="$tmp/data-scan-deps" \
  SAFE_AUDIT_PATH="$SAFE_AUDIT" \
  PROJECT_PATH="$scan_project" \
    bash -c '
      set -- --version
      source "$SAFE_AUDIT_PATH" >/dev/null
      scan_machine() { printf "SCAN\t%s\t%s\t%s\n" "$1" "${2:-}" "${3:-}"; }
      repo_audit_command --deps-only "$PROJECT_PATH"
    ' 2>&1
)"
grep -Fq $'SCAN\tlocal\t'"$scan_project"$'\tdeps' <<<"$scan_deps_output" || fail "--deps-only did not select deps scan mode"
pass "deps-only scan mode"

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
  "$SAFE_AUDIT" machine-audit --machine >/dev/null 2>"$tmp/machine-arg.err" && fail "--machine without value succeeded"
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
