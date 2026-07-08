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
grep -Fq 'safe run host-allow' < <(SAFE_RUN_NO_INIT=1 "$SAFE" run help) || fail "safe run help missing dispatcher form"
grep -Fq 'safe audit scan' < <(SAFE_AUDIT_NO_INIT=1 "$SAFE" audit help) || fail "safe audit help missing dispatcher form"
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
  check) printf 'safe-audit'; for arg in "$@"; do printf '\t%s' "$arg"; done; printf '\n'; exit "${SAFE_AUDIT_STUB_STATUS:-0}" ;;
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
grep -Fq $'safe-audit\tcheck\tcowsay@1.6.0\t--ecosystem\tnpm' <<<"$host_install_output" || fail "safe install did not audit global npm package"
grep -Fq $'npm\tinstall\t-g\tcowsay@1.6.0' <<<"$host_install_output" || fail "safe install did not forward global npm flags"
trust_config="$tmp/trust-config"
trust_install_output="$(PATH="$shim:$PATH" SAFE_CONFIG_DIR="$trust_config" "$shim/safe" install --yes --trust-host -g cowsay@1.6.0)"
grep -Fq $'npm\tinstall\t-g\tcowsay@1.6.0' <<<"$trust_install_output" || fail "safe install --trust-host did not install package"
jq -e '.packages.cowsay.version == "1.6.0" and .packages.cowsay.ecosystem == "npm"' "$trust_config/run/host-allow.json" >/dev/null || fail "safe install --trust-host did not add exact host-allow entry"

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

explain_output="$("$SAFE" explain)"
grep -Fq '100  blocked by policy' <<<"$explain_output" || fail "safe explain missing exit code table"
grep -Fq 'never attempt them yourself' <<<"$explain_output" || fail "safe explain missing agent guidance"
grep -Fq 'safe run host-allow add' <<<"$explain_output" || fail "safe explain missing allow flow"
pass "safe explain prints the agent contract"
set +e
latest_trust_output="$(PATH="$shim:$PATH" SAFE_CONFIG_DIR="$tmp/latest-trust-config" "$shim/safe" install --yes --trust-host -g cowsay 2>&1)"
latest_trust_rc=$?
set -e
[[ "$latest_trust_rc" -ne 0 ]] || fail "safe install --trust-host allowed latest"
! grep -Fq $'npm\tinstall\t-g\tcowsay' <<<"$latest_trust_output" || fail "safe install --trust-host installed latest before refusing trust"
yarn_install_output="$(PATH="$shim:$PATH" "$shim/safe" install --yes --yarn -g typescript@5.0.0)"
grep -Fq $'safe-audit\tcheck\ttypescript@5.0.0\t--ecosystem\tnpm' <<<"$yarn_install_output" || fail "safe install did not audit global yarn package"
grep -Fq $'yarn\tglobal\tadd\ttypescript@5.0.0' <<<"$yarn_install_output" || fail "safe install did not translate global yarn install"
pnpm_install_output="$(PATH="$shim:$PATH" "$shim/safe" install --yes --pnpm -g cowsay@1.6.0)"
grep -Fq $'safe-audit\tcheck\tcowsay@1.6.0\t--ecosystem\tnpm' <<<"$pnpm_install_output" || fail "safe install did not audit global pnpm package"
grep -Fq $'pnpm\tadd\t-g\tcowsay@1.6.0' <<<"$pnpm_install_output" || fail "safe install did not translate global pnpm install"
bun_install_output="$(PATH="$shim:$PATH" "$shim/safe" install --yes --bun -g cowsay@1.6.0)"
grep -Fq $'safe-audit\tcheck\tcowsay@1.6.0\t--ecosystem\tnpm' <<<"$bun_install_output" || fail "safe install did not audit global bun package"
grep -Fq $'bun\tadd\t-g\tcowsay@1.6.0' <<<"$bun_install_output" || fail "safe install did not translate global bun install"
composer_install_output="$(PATH="$shim:$PATH" "$shim/safe" install --yes --composer -g vendor/pkg:^1)"
grep -Fq $'safe-audit\tcheck\tvendor/pkg@^1\t--ecosystem\tcomposer' <<<"$composer_install_output" || fail "safe install did not audit global composer package"
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
