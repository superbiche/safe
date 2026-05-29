#!/usr/bin/env bash
set -euo pipefail

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
  *) printf 'safe-audit'; for arg in "$@"; do printf '\t%s' "$arg"; done; printf '\n' ;;
esac
SH
chmod +x "$shim/safe-audit"

[[ "$("$shim/safe" run --version)" == "safe-run mock" ]] || fail "safe run did not route"
[[ "$("$shim/safe" audit --version)" == "safe-audit mock" ]] || fail "safe audit did not route"
[[ "$("$shim/safe" install --allow-scripts cowsay@1.6.0)" == $'safe-run\tinstall\t--allow-scripts\tcowsay@1.6.0' ]] || fail "safe install did not route to safe-run install"
grep -q '^safe 1.0.0$' < <("$shim/safe" version) || fail "safe version missing top-level version"
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
[[ "$(jq -cS . <<<"$direct_json")" == "$(jq -cS . <<<"$routed_json")" ]] || fail "safe audit capabilities did not match direct safe-audit output"
jq -e '.command == "safe audit capabilities" and .groups.verify["sigstore-bundle"] == true and .groups.setup["create-bundle"] == true' <<<"$routed_json" >/dev/null || fail "safe audit capabilities returned an unexpected payload"
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
  .features.verify_sigstore_bundle.ready == false
  and (.features.verify_sigstore_bundle.missing | index("cosign") != null)
  and .features.binary_exec.ready == false
  and (.features.binary_exec.missing | index("podman") != null)
  and .features.safe_run_sandbox.ready == false
  and (.features.safe_run_sandbox.missing | index("podman") != null)
  and .features.verify_release_asset.ready == false
  and (.features.verify_release_asset.missing | index("sha256sum|shasum") != null)
  and .features.verify_tuf_bootstrap.ready == false
  and (.features.verify_tuf_bootstrap.missing | index("sha256sum|shasum") != null)
  and (.features.verify_tuf_bootstrap.missing | index("python3|python") != null)
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
  and .features.verify_sigstore_bundle.supported == false
  and (.features.verify_sigstore_bundle.missing | index("safe audit capabilities") != null)
  and .features.binary_exec.supported == false
' <<<"$failed_capabilities_json" >/dev/null || fail "doctor did not handle capabilities lookup failure"
pass "doctor capabilities downgrade"
