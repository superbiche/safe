#!/usr/bin/env bash
# safe audit tools-scan: dispatch to safe-core, the silent --publish contract
# and the error path. Scan logic is covered by internal/toolscan's Go tests;
# this suite covers what the bash entry point adds.
#
# Hermetic: mise, syft and grype are stubs.

set -euo pipefail

# SAFE_TEST_ISOLATION_MARKER: every suite owns a scratch HOME and safe state.
# shellcheck source=tests/lib/test-isolation.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/test-isolation.sh"
safe_test_setup_isolation || exit 1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SAFE_AUDIT="$ROOT/bin/safe-audit"
PASS_COUNT=0
FAIL_COUNT=0

pass() { printf 'ok - %s\n' "$*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { printf 'not ok - %s\n' "$*" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }

TEST_ROOT="$(mktemp -d)"
safe_test_compose_exit_trap "rm -rf \"\$TEST_ROOT\""

. "$ROOT/tests/lib/safe-core.sh"
safe_core_test_prepare "$ROOT" "$TEST_ROOT/safe-core" || exit 1

MOCKBIN="$TEST_ROOT/mockbin"
INSTALL="$TEST_ROOT/installs/aqua-minio-mc/1"
mkdir -p "$MOCKBIN" "$INSTALL"
printf '{"artifacts":[{"name":"golang.org/x/crypto"}]}\n' > "$INSTALL/sbom.json"

cat > "$MOCKBIN/mise" <<MOCK
#!/usr/bin/env bash
case "\$2" in
  --installed) printf '{"aqua:minio/mc":[{"version":"1","install_path":"$INSTALL","installed":true}]}\n' ;;
  --prunable) printf '{}\n' ;;
  *) exit 64 ;;
esac
MOCK
cat > "$MOCKBIN/syft" <<'MOCK'
#!/usr/bin/env bash
[[ "$1" == version ]] && { echo '{"version":"1.54.0"}'; exit 0; }
for a in "$@"; do
  case "$a" in
    dir:*) target="${a#dir:}" ;;
    syft-json=*) out="${a#syft-json=}" ;;
  esac
done
cp "$target/sbom.json" "$out"
MOCK
cat > "$MOCKBIN/grype" <<'MOCK'
#!/usr/bin/env bash
[[ "$1" == version ]] && { echo '{"version":"0.120.0"}'; exit 0; }
[[ "$1 $2" == "db update" ]] && exit 0
[[ "$1 $2" == "db status" ]] && { echo '{"built":"2026-10-06T06:32:14Z","valid":true}'; exit 0; }
echo '{"matches":[{"vulnerability":{"id":"GHSA-x","severity":"Critical","fix":{"versions":["0.45.0"]}},"artifact":{"name":"golang.org/x/crypto","version":"v0.40.0"}}]}'
MOCK
chmod +x "$MOCKBIN"/*

export SAFE_CORE_BIN="$TEST_ROOT/safe-core"
export SAFE_AUDIT_CONFIG_DIR="$TEST_ROOT/config"
export SAFE_AUDIT_DATA_DIR="$TEST_ROOT/data"

# --publish prints nothing and writes the publication.
out="$TEST_ROOT/state/tool-vulns/testhost.json"
set +e
stdout=$(PATH="$MOCKBIN:$PATH" "$SAFE_AUDIT" tools-scan --publish --out "$out" --host testhost 2>"$TEST_ROOT/err")
rc=$?
set -e
if [[ $rc -eq 0 && -z "$stdout" && ! -s "$TEST_ROOT/err" ]] \
  && jq -e '.schema == "tool-vulns/1" and .host == "testhost" and .error == null
            and .tools == [{"tool":"aqua:minio/mc","version":"1","components":1,"critical":1,"high":0,
              "advisories":[{"id":"GHSA-x","severity":"Critical","component":"golang.org/x/crypto",
                "component_version":"v0.40.0","fixed_in":["0.45.0"]}]}]' "$out" >/dev/null; then
  pass "--publish writes the report and prints nothing"
else
  fail "--publish: rc=$rc stdout=[$stdout] stderr=[$(cat "$TEST_ROOT/err")]"
fi
[[ -n "$(find "$SAFE_AUDIT_DATA_DIR/tools-scan/sbom" -name '*.syft.json')" ]] \
  && pass "SBOMs are cached under the audit data dir" || fail "no cached SBOM under $SAFE_AUDIT_DATA_DIR/tools-scan/sbom"

# Without --publish the report goes to stdout.
if PATH="$MOCKBIN:$PATH" "$SAFE_AUDIT" tools-scan --host testhost 2>/dev/null | jq -e '.tools[0].critical == 1' >/dev/null; then
  pass "without --publish the report is printed"
else
  fail "without --publish no report on stdout"
fi

# Every version failing is a failed run, not a clean one.
cp "$MOCKBIN/grype" "$TEST_ROOT/grype.ok"
cat > "$MOCKBIN/grype" <<'MOCK'
#!/usr/bin/env bash
[[ "$1" == version ]] && { echo '{"version":"0.120.0"}'; exit 0; }
[[ "$1 $2" == "db update" ]] && exit 0
[[ "$1 $2" == "db status" ]] && { echo '{"built":"2026-10-06T06:32:14Z","valid":true}'; exit 0; }
echo "matcher crashed" >&2
exit 1
MOCK
chmod +x "$MOCKBIN/grype"
set +e
PATH="$MOCKBIN:$PATH" "$SAFE_AUDIT" tools-scan --publish --out "$out" --host testhost >/dev/null 2>"$TEST_ROOT/err"
rc=$?
set -e
if [[ $rc -eq 3 && $(wc -l < "$TEST_ROOT/err") -eq 1 ]] && grep -q 'no tool version could be scanned' "$TEST_ROOT/err" \
  && jq -e '.error != null and .tools == null and (.errors | length) == 1 and .errors[0].stage == "match"' "$out" >/dev/null; then
  pass "a run where every version fails publishes an error and exits 3"
else
  fail "all versions failing: rc=$rc stderr=[$(cat "$TEST_ROOT/err")] report=$(jq -c . "$out")"
fi
mv "$TEST_ROOT/grype.ok" "$MOCKBIN/grype"

# A run that cannot scan still publishes, says why on stderr and exits 3.
rm "$MOCKBIN/grype"
set +e
PATH="$MOCKBIN:/usr/bin:/bin" "$SAFE_AUDIT" tools-scan --publish --out "$out" --host testhost >/dev/null 2>"$TEST_ROOT/err"
rc=$?
set -e
if [[ $rc -eq 3 ]] && grep -q 'grype missing' "$TEST_ROOT/err" \
  && jq -e '.error != null and .tools == null and .db.usable == null' "$out" >/dev/null; then
  pass "a scan that cannot run publishes unknown findings and exits 3"
else
  fail "missing grype: rc=$rc stderr=[$(cat "$TEST_ROOT/err")] report=$(jq -c . "$out")"
fi

# A safe-core from another release is refused before it runs.
printf '#!/usr/bin/env bash\necho 0.0.1\n' > "$TEST_ROOT/old-core"
chmod +x "$TEST_ROOT/old-core"
set +e
SAFE_CORE_BIN="$TEST_ROOT/old-core" "$SAFE_AUDIT" tools-scan >/dev/null 2>"$TEST_ROOT/err"
rc=$?
set -e
if [[ $rc -ne 0 ]] && grep -q 'safe-core 0.0.1 does not match' "$TEST_ROOT/err"; then
  pass "version-skewed safe-core is refused"
else
  fail "skewed safe-core: rc=$rc stderr=[$(cat "$TEST_ROOT/err")]"
fi

printf '%d passed, %d failed\n' "$PASS_COUNT" "$FAIL_COUNT"
[[ $FAIL_COUNT -eq 0 ]]
