#!/usr/bin/env bash
# Fixture-parity corpus: the bash binary-audit sub-lanes and the Go
# release-review composite, run over the SAME releases, with their verdicts
# diffed.
#
# Why this exists (AGENTS.md § Tests, "Binary-audit variant"): the composite is
# a new surface the bash suites cannot exercise through their own CLIs, so the
# parity belt for it is a corpus rather than a ported test file. It stays until
# the six bash sub-lanes are deleted, and only the commit that deletes them may
# delete it.
#
# Both lanes are driven through ONE local fixture server over real HTTP —
# bash through curl, the composite through net/http. Mocking curl on one side
# and the HTTP client on the other would compare two different fixtures and
# call the result parity.
#
# Two kinds of case:
#
#   PARITY    — both lanes must reach the same verdict.
#   DIVERGENT — the lanes must differ, in the exact way the divergence ledger
#               in docs/release-review.md records. A ledgered divergence with
#               no case here is a claim nothing checks; a case that starts
#               agreeing means the ledger entry is stale.
#
# Strict belt: this suite shells out to go, jq and curl. Under
# SAFE_TEST_STRICT=1 (exported by tests/run-all.sh) a missing prerequisite is a
# FAILURE, not a skip — an unrun belt must read red. Invoked standalone it
# skips, so a developer without the toolchain is not blocked.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SAFE_AUDIT="$ROOT/bin/safe-audit"

PASS_COUNT=0
FAIL_COUNT=0
pass() { printf 'ok - %s\n' "$*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { printf 'not ok - %s\n' "$*" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }

unavailable() {
  if [[ "${SAFE_TEST_STRICT:-}" == "1" ]]; then
    printf 'not ok - %s and SAFE_TEST_STRICT=1; the parity corpus must run\n' "$1" >&2
    exit 1
  fi
  printf 'SKIP: %s; the parity corpus is skipped\n' "$1"
  exit 0
}

for tool in go jq curl; do
  command -v "$tool" >/dev/null 2>&1 || unavailable "$tool is unavailable"
done

TEST_ROOT="$(mktemp -d)"
SERVER_PID=""
cleanup() {
  [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null
  rm -rf "$TEST_ROOT"
}
trap cleanup EXIT

# shellcheck source=../lib/safe-core.sh
source "$ROOT/tests/lib/safe-core.sh"
safe_core_test_prepare "$ROOT" "$TEST_ROOT/safe-core" || unavailable "safe-core could not be built"

SERVER_BIN="$TEST_ROOT/fixture-server"
if ! ( cd "$ROOT" && CGO_ENABLED=0 GOFLAGS=-buildvcs=false \
    go build -o "$SERVER_BIN" ./tests/corpus/fixture-server ); then
  unavailable "the fixture server could not be built"
fi

# --- fixtures ---------------------------------------------------------------

FIXTURES="$TEST_ROOT/fixtures"
REPO="example/tool"
VERSION="v1.2.3"
ASSET="tool_1.2.3_linux_amd64.tar.gz"

# Timestamps are computed per run. A fixture dated a fixed day is "old enough"
# today and stays old enough forever, so a static date silently stops testing
# the minimum-age rule.
iso_days_ago() { date -u -d "$1 days ago" +%Y-%m-%dT%H:%M:%SZ; }
OLD_PUBLISH="$(iso_days_ago 30)"
OLDER_PUBLISH="$(iso_days_ago 60)"

# write_fixture <scenario> <api path> <body>
write_fixture() {
  local scenario="$1" path="$2" body="$3"
  mkdir -p "$FIXTURES/$scenario"
  printf '%s\n' "$body" > "$FIXTURES/$scenario/${path//\//_}.json"
}

# write_status <scenario> <api path> <http status>
write_status() {
  local scenario="$1" path="$2" status="$3"
  mkdir -p "$FIXTURES/$scenario"
  printf '%s\n' "$status" > "$FIXTURES/$scenario/${path//\//_}.status"
}

RELEASE_PATH="repos/$REPO/releases/tags/$VERSION"
RELEASES_PATH="repos/$REPO/releases"
COMPARE_PATH="repos/$REPO/compare/v1.2.2...$VERSION"
REF_PATH="repos/$REPO/git/ref/tags/$VERSION"
COMMIT_PATH="repos/$REPO/commits/abc123"
ADVISORIES_PATH="repos/$REPO/security-advisories"

release_json() {
  local published="$1" draft="$2" prerelease="$3" asset="$4"
  printf '{"tag_name":"%s","draft":%s,"prerelease":%s,"published_at":"%s","html_url":"https://example.invalid/r","body":"notes","assets":[{"name":"%s","browser_download_url":"https://example.invalid/a"}]}' \
    "$VERSION" "$draft" "$prerelease" "$published" "$asset"
}

releases_json() {
  printf '[{"tag_name":"%s","draft":false,"prerelease":false,"published_at":"%s"},{"tag_name":"v1.2.2","draft":false,"prerelease":false,"published_at":"%s"}]' \
    "$VERSION" "$OLD_PUBLISH" "$OLDER_PUBLISH"
}

COMPARE_SAFE='{"files":[{"filename":"cmd/tool/main.go"},{"filename":"README.md"}]}'
COMPARE_RISKY='{"files":[{"filename":".github/workflows/release.yml"},{"filename":"cmd/tool/main.go"}]}'
REF_COMMIT='{"object":{"type":"commit","sha":"abc123"}}'
COMMIT_VERIFIED='{"commit":{"verification":{"verified":true,"reason":"valid"}}}'
COMMIT_UNVERIFIED='{"commit":{"verification":{"verified":false,"reason":"unsigned"}}}'

# seed_release_scenario lays down a complete, healthy release, which each
# scenario then spoils in exactly one way.
seed_release_scenario() {
  local scenario="$1"
  write_fixture "$scenario" "$RELEASE_PATH" "$(release_json "$OLD_PUBLISH" false false "$ASSET")"
  write_fixture "$scenario" "$RELEASES_PATH" "$(releases_json)"
  write_fixture "$scenario" "$COMPARE_PATH" "$COMPARE_SAFE"
  write_fixture "$scenario" "$REF_PATH" "$REF_COMMIT"
  write_fixture "$scenario" "$COMMIT_PATH" "$COMMIT_VERIFIED"
}

seed_release_scenario release-clean

seed_release_scenario release-draft
write_fixture release-draft "$RELEASE_PATH" "$(release_json "$OLD_PUBLISH" true false "$ASSET")"

seed_release_scenario release-too-new
write_fixture release-too-new "$RELEASE_PATH" "$(release_json "$(iso_days_ago 1)" false false "$ASSET")"

seed_release_scenario release-wrong-asset
write_fixture release-wrong-asset "$RELEASE_PATH" "$(release_json "$OLD_PUBLISH" false false "some-other-file.tar.gz")"

seed_release_scenario release-high-risk
write_fixture release-high-risk "$COMPARE_PATH" "$COMPARE_RISKY"

seed_release_scenario release-unverified
write_fixture release-unverified "$COMMIT_PATH" "$COMMIT_UNVERIFIED"

# The release itself is absent: GitHub answers 404, which both lanes read as
# evidence about the release.
seed_release_scenario release-absent
rm -f "$FIXTURES/release-absent/${RELEASE_PATH//\//_}.json"

# DIVERGENT (ledger 10): GitHub answers 500. bash reads that as a finding about
# the release; the composite reads it as its own breakage.
seed_release_scenario release-server-error
write_status release-server-error "$RELEASE_PATH" 500

# DIVERGENT (ledger 11): the release history spans two pages. bash reads only
# the first and resolves no predecessor; the composite follows the Link header.
seed_release_scenario release-paginated
write_fixture release-paginated "$RELEASES_PATH" \
  "$(printf '[{"tag_name":"%s","draft":false,"prerelease":false,"published_at":"%s"}]' "$VERSION" "$OLD_PUBLISH")"
printf '[{"tag_name":"v1.2.2","draft":false,"prerelease":false,"published_at":"%s"}]\n' "$OLDER_PUBLISH" \
  > "$FIXTURES/release-paginated/${RELEASES_PATH//\//_}_page2.json"

advisory_json() {
  local id="$1" severity="$2" range="$3"
  printf '[{"ghsa_id":"%s","cve_id":"CVE-2026-0001","severity":"%s","html_url":"https://example.invalid/%s","summary":"corpus advisory","updated_at":"%s","vulnerabilities":[{"package":{"ecosystem":"go","name":"github.com/example/tool"},"vulnerable_version_range":"%s","patched_versions":"v2.0.0"}]}]' \
    "$id" "$severity" "$id" "$OLDER_PUBLISH" "$range"
}

mkdir -p "$FIXTURES/vuln-zero"
write_fixture vuln-zero "$ADVISORIES_PATH" '[]'
write_fixture vuln-low "$ADVISORIES_PATH" "$(advisory_json GHSA-low low '<v2.0.0')"
write_fixture vuln-high "$ADVISORIES_PATH" "$(advisory_json GHSA-high high '<v2.0.0')"
write_fixture vuln-unmatched "$ADVISORIES_PATH" "$(advisory_json GHSA-old critical '<1.0.0')"

# DIVERGENT (ledger 12): the advisory names an empty range. bash skips it and
# reports a clean feed; the composite cannot map it and fails closed.
write_fixture vuln-blank-range "$ADVISORIES_PATH" "$(advisory_json GHSA-blank high '')"

# DIVERGENT (ledger 10), advisory side.
mkdir -p "$FIXTURES/vuln-feed-error"
write_status vuln-feed-error "$ADVISORIES_PATH" 500

# --- the server both lanes talk to ------------------------------------------

"$SERVER_BIN" -dir "$FIXTURES" > "$TEST_ROOT/server.url" 2> "$TEST_ROOT/server.err" &
SERVER_PID=$!

BASE_URL=""
for _ in $(seq 1 100); do
  BASE_URL="$(head -n 1 "$TEST_ROOT/server.url" 2>/dev/null || true)"
  [[ -n "$BASE_URL" ]] && break
  sleep 0.05
done
[[ -n "$BASE_URL" ]] || { printf 'not ok - the fixture server never reported an address: %s\n' "$(cat "$TEST_ROOT/server.err")" >&2; exit 1; }

# --- the two lanes ----------------------------------------------------------

# GITHUB_TOKEN is cleared for both lanes. A developer's real token must never
# leave the machine because a test suite ran, and a token present on one side
# only would make the two lanes send different requests.
run_lane() {
  local name="$1" scenario="$2"
  shift 2
  local rc=0
  env -u GITHUB_TOKEN \
    HOME="$TEST_ROOT/home" \
    SAFE_CORE_BIN="$SAFE_CORE_BIN" \
    SAFE_AUDIT_CONFIG_DIR="$TEST_ROOT/config-$name" \
    SAFE_AUDIT_DATA_DIR="$TEST_ROOT/data-$name" \
    SAFE_AUDIT_GITHUB_API_BASE_URL="$BASE_URL/$scenario" \
    SAFE_AUDIT_GITHUB_RELEASE_MIN_AGE_DAYS=3 \
    "$SAFE_AUDIT" binary-audit "$@" > "$TEST_ROOT/$name.out" 2> "$TEST_ROOT/$name.err" || rc=$?
  printf '%s' "$rc"
}

bash_release_verdict() {
  local scenario="$1"
  run_lane "bash-$scenario" "$scenario" release github \
    --repo "$REPO" --version "$VERSION" --asset "$ASSET" --json >/dev/null
  jq -r '.verdict' < "$TEST_ROOT/bash-$scenario.out" 2>/dev/null || printf 'UNREADABLE'
}

bash_vuln_verdict() {
  local scenario="$1"
  run_lane "bash-$scenario" "$scenario" vuln github-release \
    --repo "$REPO" --version "$VERSION" --json >/dev/null
  jq -r '.verdict' < "$TEST_ROOT/bash-$scenario.out" 2>/dev/null || printf 'UNREADABLE'
}

write_spec() {
  local scenario="$1" checks="$2"
  local spec="$TEST_ROOT/spec-$scenario.json"
  cat > "$spec" <<EOF
{
  "spec_version": 1,
  "subject": {"repo": "$REPO", "version": "$VERSION"},
  "artifacts": [{"path": "dist/$ASSET", "asset_name": "$ASSET"}],
  "checks": {$checks}
}
EOF
  printf '%s' "$spec"
}

composite_verdict() {
  local scenario="$1" checks="$2" spec
  spec="$(write_spec "$scenario" "$checks")"
  run_lane "composite-$scenario" "$scenario" release-review --spec "$spec" >/dev/null
  jq -r '.verdict' < "$TEST_ROOT/composite-$scenario.out" 2>/dev/null || printf 'UNREADABLE'
}

release_checks="\"release\": {\"enabled\": true, \"asset\": \"$ASSET\"}"
vuln_checks='"vuln": {"enabled": true}'

# parity <scenario> <checks> <expected verdict>
parity() {
  local scenario="$1" checks="$2" want="$3" lane="$4"
  local bash_verdict composite
  if [[ "$lane" == "release" ]]; then
    bash_verdict="$(bash_release_verdict "$scenario")"
  else
    bash_verdict="$(bash_vuln_verdict "$scenario")"
  fi
  composite="$(composite_verdict "$scenario" "$checks")"

  if [[ "$bash_verdict" != "$composite" ]]; then
    fail "parity $scenario (bash=$bash_verdict composite=$composite — the lanes disagree and no ledger entry says they may)"
    return
  fi
  if [[ "$bash_verdict" != "$want" ]]; then
    fail "parity $scenario (both lanes say $bash_verdict, want $want)"
    return
  fi
  pass "parity $scenario — both lanes $want"
}

# divergent <scenario> <checks> <bash verdict> <composite verdict> <ledger entry>
divergent() {
  local scenario="$1" checks="$2" want_bash="$3" want_composite="$4" ledger="$5" lane="$6"
  local bash_verdict composite
  if [[ "$lane" == "release" ]]; then
    bash_verdict="$(bash_release_verdict "$scenario")"
  else
    bash_verdict="$(bash_vuln_verdict "$scenario")"
  fi
  composite="$(composite_verdict "$scenario" "$checks")"

  if [[ "$bash_verdict" == "$composite" ]]; then
    fail "divergence $ledger, $scenario (both lanes say $bash_verdict — the ledger entry is stale)"
    return
  fi
  if [[ "$bash_verdict" != "$want_bash" || "$composite" != "$want_composite" ]]; then
    fail "divergence $ledger, $scenario (bash=$bash_verdict want $want_bash; composite=$composite want $want_composite)"
    return
  fi
  pass "divergence $ledger, $scenario — bash $bash_verdict, composite $composite"
}

parity release-clean       "$release_checks" GO    release
parity release-draft       "$release_checks" BLOCK release
parity release-too-new     "$release_checks" BLOCK release
parity release-wrong-asset "$release_checks" BLOCK release
parity release-high-risk   "$release_checks" BLOCK release
parity release-unverified  "$release_checks" BLOCK release
parity release-absent      "$release_checks" BLOCK release

divergent release-server-error "$release_checks" BLOCK ERROR "10 (404 is evidence, everything else is infrastructure)" release
divergent release-paginated    "$release_checks" BLOCK GO    "11 (paginated listings are followed)" release

parity vuln-zero      "$vuln_checks" GO    vuln
parity vuln-unmatched "$vuln_checks" GO    vuln
parity vuln-low       "$vuln_checks" WARN  vuln
parity vuln-high      "$vuln_checks" BLOCK vuln

divergent vuln-blank-range "$vuln_checks" GO    BLOCK "12 (an unreadable range is ambiguous, not absent)" vuln
divergent vuln-feed-error  "$vuln_checks" BLOCK ERROR "10 (404 is evidence, everything else is infrastructure)" vuln

# --- divergence 13: the exec sandbox drops the shell ------------------------
#
# This one is asserted on the invocation, not on the verdict. Both lanes run the
# artifact and both come back GO — the injected command in the hostile name
# succeeds, so even the exploited run looks clean, which is precisely why a
# verdict comparison would prove nothing here. What differs is what reaches
# podman.
case_exec_shell_drop() {
  local sandbox="$TEST_ROOT/sandbox"
  local artifact_dir="$sandbox/artifacts"
  local mockbin="$sandbox/bin"
  mkdir -p "$artifact_dir" "$mockbin"

  local hostile='x|touch PWNED'
  printf '#!/bin/sh\nexit 0\n' > "$artifact_dir/$hostile"
  chmod +x "$artifact_dir/$hostile"

  cat > "$mockbin/podman" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$@" > "$MOCK_PODMAN_LOG"
exit 0
SH
  chmod +x "$mockbin/podman"

  local bash_log="$sandbox/bash-argv.log" composite_log="$sandbox/composite-argv.log"

  env -u GITHUB_TOKEN PATH="$mockbin:$PATH" MOCK_PODMAN_LOG="$bash_log" \
    HOME="$TEST_ROOT/home" \
    SAFE_AUDIT_CONFIG_DIR="$TEST_ROOT/config-exec-bash" \
    SAFE_AUDIT_DATA_DIR="$TEST_ROOT/data-exec-bash" \
    "$SAFE_AUDIT" binary-audit exec "$artifact_dir/$hostile" --json >/dev/null 2>&1 || true

  local spec="$TEST_ROOT/spec-exec.json"
  cat > "$spec" <<EOF
{
  "spec_version": 1,
  "subject": {"repo": "$REPO", "version": "$VERSION"},
  "artifacts": [{"path": "$artifact_dir/$hostile"}],
  "checks": {"exec": {"enabled": true, "artifact": "$artifact_dir/$hostile", "timeout_seconds": 10}}
}
EOF
  env -u GITHUB_TOKEN PATH="$mockbin:$PATH" MOCK_PODMAN_LOG="$composite_log" \
    HOME="$TEST_ROOT/home" \
    SAFE_CORE_BIN="$SAFE_CORE_BIN" \
    SAFE_AUDIT_CONFIG_DIR="$TEST_ROOT/config-exec-composite" \
    SAFE_AUDIT_DATA_DIR="$TEST_ROOT/data-exec-composite" \
    "$SAFE_AUDIT" binary-audit release-review --spec "$spec" >/dev/null 2>&1 || true

  if [[ ! -s "$bash_log" || ! -s "$composite_log" ]]; then
    fail "divergence 13, exec argv (a lane never invoked podman)"
    return
  fi
  # The bash lane splices the name into shell program text.
  if ! grep -Fxq -- '-c' "$bash_log" || ! grep -Fq -- "exec /artifact/$hostile" "$bash_log"; then
    fail "divergence 13, exec argv (the bash lane no longer builds an sh -c wrapper — the ledger entry is stale)"
    return
  fi
  # The composite passes it as a path, whole, with no shell anywhere.
  if ! grep -Fxq -- "/artifact/$hostile" "$composite_log"; then
    fail "divergence 13, exec argv (the composite did not pass the artifact as one argv entry)"
    return
  fi
  if grep -Fxq -- '-c' "$composite_log" || grep -Fxq -- 'sh' "$composite_log"; then
    fail "divergence 13, exec argv (a shell reached the composite's podman invocation)"
    return
  fi
  if [[ -e "$artifact_dir/PWNED" || -e "$PWD/PWNED" ]]; then
    fail "divergence 13, exec argv (the artifact name executed as a command)"
    return
  fi
  pass "divergence 13, exec argv — bash wraps in sh -c, the composite passes a path"
}

case_exec_shell_drop

# --- divergences 1-4: the ledger entries this slice inherited -----------------
#
# The corpus covers every verdict-affecting ledger entry, not only the ones the
# slice that built it introduced. Entries 1-4 came from slices 1 and 2, and
# until they had a case here the claim that the composite diverges from bash in
# exactly those ways was a claim nothing checked.

# path_farm_without <excluded tool>... — a PATH holding the tools safe-audit
# needs and nothing else, so "this tool is not installed" is something a case
# can state on any machine. Relying on the host not having podman or cosign
# would make these cases pass or vanish depending on who runs them.
path_farm_without() {
  local farm="$TEST_ROOT/farm-${*// /-}"
  mkdir -p "$farm"
  local tool resolved excluded
  for tool in bash sh env cat cp mv rm mkdir mktemp dirname basename readlink \
              sed awk tr cut head tail sort uniq wc find grep date chmod stat \
              id uname jq sha256sum shasum curl timeout sleep printf ls touch; do
    excluded=0
    for skip in "$@"; do
      [[ "$tool" == "$skip" ]] && excluded=1
    done
    (( excluded )) && continue
    resolved="$(command -v "$tool" 2>/dev/null)" || continue
    ln -sf "$resolved" "$farm/$tool"
  done
  printf '%s' "$farm"
}

# run_in_farm <farm> <name> <extra env assignments...> -- <safe-audit args...>
farm_verdict() {
  local farm="$1" name="$2"
  shift 2
  local rc=0
  env -i -u GITHUB_TOKEN \
    PATH="$farm" \
    HOME="$TEST_ROOT/home" \
    SAFE_CORE_BIN="$SAFE_CORE_BIN" \
    SAFE_AUDIT_CONFIG_DIR="$TEST_ROOT/config-$name" \
    SAFE_AUDIT_DATA_DIR="$TEST_ROOT/data-$name" \
    "$SAFE_AUDIT" binary-audit "$@" > "$TEST_ROOT/$name.out" 2> "$TEST_ROOT/$name.err" || rc=$?
  jq -r '.verdict' < "$TEST_ROOT/$name.out" 2>/dev/null || printf 'UNREADABLE'
}

trust_spec() {
  local name="$1" checks="$2"
  local spec="$TEST_ROOT/spec-$name.json"
  cat > "$spec" <<EOF
{
  "spec_version": 1,
  "subject": {"repo": "$REPO", "version": "$VERSION"},
  "artifacts": [$3],
  "checks": {$checks}
}
EOF
  printf '%s' "$spec"
}

TRUST="$TEST_ROOT/trust"
mkdir -p "$TRUST"
printf 'release payload\n' > "$TRUST/tool.bin"
printf '{}\n' > "$TRUST/tool.sigstore.json"

# Ledger 1 (PARITY): a checksum file with several entries and none naming the
# asset. bash falls back to the FIRST digest and calls it a mismatch; the
# composite says there is no entry for this asset. Different codes, and the
# ledger's own claim is that the verdict is the same — this is the case that
# holds it to that.
case_checksum_single_entry_fallback() {
  local checksums="$TRUST/multi-checksums.txt"
  {
    printf '%s  other-file-a.tar.gz\n' "$(printf 'not the payload\n' | sha256sum | cut -d' ' -f1)"
    printf '%s  other-file-b.tar.gz\n' "$(printf 'also not it\n' | sha256sum | cut -d' ' -f1)"
  } > "$checksums"

  local farm bash_verdict composite spec
  farm="$(path_farm_without)"
  bash_verdict="$(farm_verdict "$farm" ledger1-bash \
    verify release-asset --artifact "$TRUST/tool.bin" --checksum "$checksums" --json)"
  spec="$(trust_spec ledger1 '"checksum": {"enabled": true}' \
    "{\"path\": \"$TRUST/tool.bin\", \"asset_name\": \"tool.bin\", \"evidence\": {\"checksum_file\": \"$checksums\"}}")"
  composite="$(farm_verdict "$farm" ledger1-composite release-review --spec "$spec")"

  if [[ "$bash_verdict" != "BLOCK" || "$composite" != "BLOCK" ]]; then
    fail "parity ledger 1, checksum no-entry (bash=$bash_verdict composite=$composite, want both BLOCK)"
    return
  fi
  if ! jq -e '.checks[0].reasons | map(.code) | index("no_entry_for_artifact") != null' \
      < "$TEST_ROOT/ledger1-composite.out" >/dev/null 2>&1; then
    fail "parity ledger 1, checksum no-entry (the composite did not name the absent entry: $(cat "$TEST_ROOT/ledger1-composite.out"))"
    return
  fi
  pass "parity ledger 1, checksum no-entry — both lanes BLOCK by different codes"
}

# Ledger 2 (DIVERGENT): cosign is not installed. bash reports a missing tool as
# a finding about the release; the composite reports it as its own tooling
# absent, with an install as the recovery.
case_missing_cosign() {
  local farm bash_verdict composite spec
  farm="$(path_farm_without cosign)"
  bash_verdict="$(farm_verdict "$farm" ledger2-bash \
    verify sigstore-bundle --artifact "$TRUST/tool.bin" --bundle "$TRUST/tool.sigstore.json" \
    --identity 'https://example.invalid/workflow' --oidc-issuer 'https://token.actions.githubusercontent.com' --json)"
  spec="$(trust_spec ledger2 '"signature": {"enabled": true}' \
    "{\"path\": \"$TRUST/tool.bin\", \"asset_name\": \"tool.bin\", \"evidence\": {\"signature\": {\"bundle\": \"$TRUST/tool.sigstore.json\", \"identity\": \"https://example.invalid/workflow\", \"oidc_issuer\": \"https://token.actions.githubusercontent.com\"}}}")"
  composite="$(farm_verdict "$farm" ledger2-composite release-review --spec "$spec")"

  if [[ "$bash_verdict" != "BLOCK" || "$composite" != "ERROR" ]]; then
    fail "divergence 2, missing cosign (bash=$bash_verdict want BLOCK; composite=$composite want ERROR)"
    return
  fi
  pass "divergence 2, missing cosign — bash BLOCK, composite ERROR"
}

# Ledger 3 (DIVERGENT): podman is not installed. The bash lane understated a
# review that never ran as a WARN about the binary.
case_missing_podman() {
  local farm bash_verdict composite spec
  farm="$(path_farm_without podman)"
  bash_verdict="$(farm_verdict "$farm" ledger3-bash exec "$TRUST/tool.bin" --json)"
  spec="$(trust_spec ledger3 "\"exec\": {\"enabled\": true, \"artifact\": \"$TRUST/tool.bin\", \"timeout_seconds\": 10}" \
    "{\"path\": \"$TRUST/tool.bin\", \"asset_name\": \"tool.bin\"}")"
  composite="$(farm_verdict "$farm" ledger3-composite release-review --spec "$spec")"

  if [[ "$bash_verdict" != "WARN" || "$composite" != "ERROR" ]]; then
    fail "divergence 3, missing podman (bash=$bash_verdict want WARN; composite=$composite want ERROR)"
    return
  fi
  pass "divergence 3, missing podman — bash WARN, composite ERROR"
}

# Ledger 4 (DIVERGENT): the binary to smoke is not where the spec says. The same
# observation is BLOCK in the checksum check, and one composite must not
# classify one observation two ways.
case_missing_exec_artifact() {
  local farm bash_verdict composite spec absent="$TRUST/absent-binary"
  farm="$(path_farm_without podman)"
  bash_verdict="$(farm_verdict "$farm" ledger4-bash exec "$absent" --json)"
  spec="$(trust_spec ledger4 "\"exec\": {\"enabled\": true, \"artifact\": \"$absent\", \"timeout_seconds\": 10}" \
    "{\"path\": \"$TRUST/tool.bin\", \"asset_name\": \"tool.bin\"}")"
  composite="$(farm_verdict "$farm" ledger4-composite release-review --spec "$spec")"

  if [[ "$bash_verdict" != "WARN" || "$composite" != "BLOCK" ]]; then
    fail "divergence 4, missing exec artifact (bash=$bash_verdict want WARN; composite=$composite want BLOCK)"
    return
  fi
  if ! jq -e '.checks[0].reasons | map(.code) | index("artifact_missing") != null' \
      < "$TEST_ROOT/ledger4-composite.out" >/dev/null 2>&1; then
    fail "divergence 4, missing exec artifact (the composite did not name the absent artifact)"
    return
  fi
  pass "divergence 4, missing exec artifact — bash WARN, composite BLOCK"
}

case_checksum_single_entry_fallback
case_missing_cosign
case_missing_podman
case_missing_exec_artifact

if (( FAIL_COUNT > 0 )); then
  printf 'parity corpus: %d passed, %d FAILED\n' "$PASS_COUNT" "$FAIL_COUNT" >&2
  exit 1
fi
printf 'parity corpus: %d cases passed\n' "$PASS_COUNT"
