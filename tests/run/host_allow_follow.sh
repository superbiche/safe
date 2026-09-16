#!/usr/bin/env bash
# Signed fleet replication. All state, keys and registry responses are fixtures.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SAFE_RUN="$ROOT/bin/safe-run"
pass() { printf 'ok - %s\n' "$*"; }
fail() { printf 'not ok - %s\n' "$*" >&2; exit 1; }
for tool in gpg gpgconf python3 jq; do
  command -v "$tool" >/dev/null || fail "missing required command: $tool"
done
tmp=$(mktemp -d)
cleanup() {
  gpgconf --homedir "$tmp/gnupg" --kill gpg-agent >/dev/null 2>&1 || true
  rm -rf -- "$tmp"
}
trap cleanup EXIT
export HOME="$tmp/home" GNUPGHOME="$tmp/gnupg"
export SAFE_RUN_CONFIG_DIR="$HOME/.config/safe/run" SAFE_RUN_DATA_DIR="$tmp/data"
export SAFE_AUDIT_DATA_DIR="$tmp/audit" SAFE_RUN_TRUST_OVERRIDE=0 SAFE_RUN_NO_INIT=0
mkdir -p "$GNUPGHOME" "$SAFE_RUN_CONFIG_DIR" "$tmp/bin"
chmod 700 "$GNUPGHOME"
export PATH="$tmp/bin:$PATH"
cat > "$tmp/bin/hostname" <<'STUB'
#!/usr/bin/env bash
printf 'rainbow\n'
STUB
chmod +x "$tmp/bin/hostname"
gpg --no-options --batch --pinentry-mode loopback --passphrase '' \
  --quick-generate-key 'Safe fixture origin <origin@example.invalid>' ed25519 sign 0 > "$tmp/keygen.log" 2>&1 || { cat "$tmp/keygen.log" >&2; fail "fixture key generation failed"; }
fingerprint=$(gpg --no-options --batch --with-colons --list-keys 2>/dev/null | awk -F: '$1 == "fpr" {print $10; exit}')
printf '{"follow":{"signing_key":"%s"}}\n' "$fingerprint" > "$SAFE_RUN_CONFIG_DIR/config.json"
cat > "$SAFE_RUN_CONFIG_DIR/host-allow.json" <<'JSON'
{"packages":{"fresh-pkg":{"version":"1.2.3","sha":"sha512-FRESH","ecosystem":"npm","added":"2026-07-01","reason":"origin grant","private_field":"must not export"}}}
JSON
pty_run() {
  python3 -c 'import pty,sys,os; sys.exit(os.waitstatus_to_exitcode(pty.spawn(sys.argv[1:])))' "$@"
}
expect_rc() {
  local expected="$1"; shift
  local rc=0
  "$@" > "$tmp/output" 2>&1 </dev/null || rc=$?
  [[ "$rc" == "$expected" ]] || fail "expected exit $expected, got $rc: $(cat "$tmp/output")"
}
expect_rc 102 "$SAFE_RUN" host-allow export --sign --out "$tmp/refused"
[[ ! -e "$tmp/refused" ]] || fail 'refused export wrote output'
pass 'signed export refuses non-TTY before writing'
pty_run "$SAFE_RUN" host-allow export --sign > "$tmp/output" 2>&1 || fail 'signed export failed'
export_file="$HOME/Sync/state/safe/host-allow.rainbow.json"
[[ -s "$export_file" && -s "$export_file.asc" ]] || fail 'missing signed export pair'
gpg --no-options --batch --verify "$export_file.asc" "$export_file" > "$tmp/verify.log" 2>&1 || fail 'signature does not verify'
jq -e '.schema == "safe-host-allow-export/2" and .host == "rainbow" and (.exported_at | type == "string") and (.packages["fresh-pkg"] | keys == ["added","ecosystem","reason","sha","version"])' "$export_file" >/dev/null || fail 'wrong signed document'
pass 'signed export produces verifiable v2 document, metadata and portable fields'
pty_run "$SAFE_RUN" host-allow export --sign --out "$tmp/custom output" > "$tmp/output" 2>&1 || fail 'custom directory failed'
[[ -s "$tmp/custom output/host-allow.rainbow.json.asc" ]] || fail 'custom directory ignored'
pass 'signed export supports explicit output directory'
"$SAFE_RUN" host-allow export | jq -e '.schema == "safe-host-allow-export/1" and (has("host") | not)' >/dev/null || fail 'unsigned compatibility'
expect_rc 1 "$SAFE_RUN" host-allow export --out "$tmp/unused"
expect_rc 1 "$SAFE_RUN" host-allow export --sign --yes
expect_rc 102 "$SAFE_RUN" host-allow import "$export_file"
pass 'unsigned export unchanged; v2 import retains TTY gate; unknown flags rejected'
printf 'all signed export tests passed\n'
