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

# The origin signature has been made; now this fixture acts as agent-dev.
cat > "$tmp/bin/hostname" <<'STUB'
#!/usr/bin/env bash
printf 'agent-dev\n'
STUB
cat > "$tmp/bin/curl" <<'STUB'
#!/usr/bin/env bash
if [[ "${TEST_CONCURRENT_PIN:-0}" == "1" ]]; then
  jq '.packages["fresh-pkg"] = {version:"9.9.9", reason:"concurrent local grant", ecosystem:"npm"}' \
    "$SAFE_RUN_CONFIG_DIR/host-allow.json" > "$SAFE_RUN_CONFIG_DIR/concurrent.json"
  mv "$SAFE_RUN_CONFIG_DIR/concurrent.json" "$SAFE_RUN_CONFIG_DIR/host-allow.json"
fi
case "${!#}" in
  *registry.npmjs.org/fresh-pkg/1.2.3) printf '{"version":"1.2.3","dist":{"integrity":"sha512-FRESH"}}' ;;
  *registry.npmjs.org/range-pkg/1.x) printf '{"version":"1.2.3","dist":{"integrity":"sha512-FRESH"}}' ;;
  *pypi.org/pypi/epoch-pkg/1!2.0/json) printf '{"info":{"version":"1!2.0"},"urls":[{"digests":{"sha256":"EPOCH"}}]}' ;;
  *) exit 22 ;;
esac
STUB
chmod +x "$tmp/bin/curl"
rm -f "$SAFE_RUN_CONFIG_DIR/host-allow.json"
expect_rc 102 "$SAFE_RUN" host-allow follow-signer add "$fingerprint"
jq -e '.follow | has("signers") | not' "$SAFE_RUN_CONFIG_DIR/config.json" >/dev/null || fail 'non-TTY added a signer'
expect_rc 1 "$SAFE_RUN" host-allow follow-signer add DEADBEEF
pty_run "$SAFE_RUN" host-allow follow-signer add "$fingerprint" > "$tmp/output" 2>&1 || fail 'signer add failed'
pty_run "$SAFE_RUN" host-allow follow-signer add "${fingerprint,,}" > "$tmp/output" 2>&1 || fail 'signer idempotence failed'
jq -e --arg f "$fingerprint" '.follow.signers == [$f]' "$SAFE_RUN_CONFIG_DIR/config.json" >/dev/null || fail 'signer not pinned exactly once'
pass 'follow-signer requires TTY and full fingerprint; stores one normalized pin'
expect_rc 0 "$SAFE_RUN" host-allow follow --dry-run
grep -q 'would-add fresh-pkg@1.2.3' "$tmp/output" || fail 'missing dry-run plan'
[[ ! -e "$SAFE_RUN_CONFIG_DIR/host-allow.json" ]] || fail 'dry-run created trust store'
[[ ! -e "$SAFE_RUN_CONFIG_DIR/blocked.json" ]] || fail 'dry-run initialized run state'
expect_rc 0 "$SAFE_RUN" host-allow follow
jq -e '.packages["fresh-pkg"] | .version == "1.2.3" and .added == "2026-07-01" and .followed_from == "rainbow" and .sha == "sha512-FRESH"' "$SAFE_RUN_CONFIG_DIR/host-allow.json" >/dev/null || fail 'follow grant differs'
cp "$SAFE_RUN_CONFIG_DIR/host-allow.json" "$tmp/local-before.json"
expect_rc 0 "$SAFE_RUN" host-allow follow
cmp "$tmp/local-before.json" "$SAFE_RUN_CONFIG_DIR/host-allow.json" || fail 'repeat follow changed store'
pass 'non-TTY follow applies signed grant with original date and provenance; repeat is a no-op'

# Per-case directory keeps invalid siblings from contaminating other tests.
mkdir "$tmp/incoming"
cp "$export_file" "$tmp/original.json"
reset_incoming() { rm -f "$tmp/incoming/"*; }
sign_document() {
  gpg --no-options --batch --yes --armor --local-user "$1" --detach-sign --output "$2.asc" -- "$2" > "$tmp/sign.log" 2>&1 || fail 'fixture signing failed'
}
expect_follow_failure() {
  expect_rc 1 "$SAFE_RUN" host-allow follow --from "$tmp/incoming" "$@"
  grep -q 'operator override:.*host-allow import' "$tmp/output" || fail 'missing operator import hint'
  cmp "$tmp/local-before.json" "$SAFE_RUN_CONFIG_DIR/host-allow.json" || fail 'failure altered local grant'
}
cp "$export_file" "$tmp/incoming/host-allow.rainbow.json"
expect_follow_failure
grep -q '1 signature skips' "$tmp/output" || fail 'unsigned skip not counted'
[[ $(grep -c 'WARN follow: skipped' "$tmp/output") == 1 ]] || fail 'expected one WARN line for unsigned file'
pass 'unsigned export skipped, counted, non-zero, with TTY import override'
cp "$export_file.asc" "$tmp/incoming/host-allow.rainbow.json.asc"
printf ' ' >> "$tmp/incoming/host-allow.rainbow.json"
expect_follow_failure
pass 'tampered signed document is rejected'
gpg --no-options --batch --pinentry-mode loopback --passphrase '' \
  --quick-generate-key 'Safe fixture other <other@example.invalid>' ed25519 sign 0 > "$tmp/keygen.log" 2>&1 || fail 'second fixture key generation failed'
other_fingerprint=$(gpg --no-options --batch --with-colons --list-keys 'other@example.invalid' 2>/dev/null | awk -F: '$1 == "fpr" {print $10; exit}')
sign_document "$other_fingerprint" "$tmp/incoming/host-allow.rainbow.json"
expect_follow_failure
pass 'untrusted signer rejected even when its public key exists in the ambient keyring'
reset_incoming
jq '.packages["fresh-pkg"].version = "2.0.0"' "$export_file" > "$tmp/incoming/host-allow.rainbow.json"
sign_document "$fingerprint" "$tmp/incoming/host-allow.rainbow.json"
expect_follow_failure
grep -q 'CONFLICT fresh-pkg.*host-allow update fresh-pkg@2.0.0' "$tmp/output" || fail 'missing conflict/update hint'
expect_follow_failure --dry-run
pass 'different local pin preserved in apply and preview'
reset_incoming
printf 'invalid unsigned own-host file\n' > "$tmp/incoming/host-allow.agent-dev.json"
expect_rc 0 "$SAFE_RUN" host-allow follow --from "$tmp/incoming"
pass 'own-host export ignored without signature checks'
reset_incoming
jq '.host = "tuxedo" | .packages = {"epoch-pkg":{"version":"1!2.0","ecosystem":"python","sha":"sha256-EPOCH","reason":"second origin","added":"2026-06-03"}}' "$export_file" > "$tmp/incoming/host-allow.tuxedo.json"
sign_document "$other_fingerprint" "$tmp/incoming/host-allow.tuxedo.json"
pty_run "$SAFE_RUN" host-allow follow-signer add "$other_fingerprint" > "$tmp/output" 2>&1 || fail 'second signer add failed'
expect_rc 0 "$SAFE_RUN" host-allow follow --from "$tmp/incoming" --dry-run
cmp "$tmp/local-before.json" "$SAFE_RUN_CONFIG_DIR/host-allow.json" || fail 'populated dry-run altered store'
expect_rc 0 "$SAFE_RUN" host-allow follow --from "$tmp/incoming"
jq -e '.packages | length == 2 and (. ["epoch-pkg"] | .version == "1!2.0" and .followed_from == "tuxedo" and .added == "2026-06-03")' "$SAFE_RUN_CONFIG_DIR/host-allow.json" >/dev/null || fail 'union failed'
cp "$SAFE_RUN_CONFIG_DIR/host-allow.json" "$tmp/local-before.json"
pass 'second signed host adds Python epoch pin without removing local grants'
expect_rc 102 "$SAFE_RUN" host-allow follow-signer remove "$other_fingerprint"
pty_run "$SAFE_RUN" host-allow follow-signer remove "$other_fingerprint" > "$tmp/output" 2>&1 || fail 'signer removal failed'
expect_follow_failure
pass 'removing signer revokes future acceptance without deleting existing grants'

# Fresh missing entries must pass every import validation check.
reset_incoming
jq '.packages = {
 "no-reason":{"version":"1.2.3","reason":""},
 "unknown-eco":{"version":"1.2.3","reason":"x","ecosystem":"cobol"},
 "tag-pkg":{"version":"latest","reason":"x"},
 "range-pkg":{"version":"1.x","reason":"x"},
 "source-pkg":{"version":"file:/tmp/x","reason":"x"},
 "bad-field":{"version":"1.2.3","reason":{}},
 "unresolved":{"version":"1.2.3","reason":"x"},
 "fresh-pkg":{"version":"1.2.3","reason":"x","sha":"sha512-WRONG"}
}' "$export_file" > "$tmp/incoming/host-allow.rainbow.json"
# Remove fresh-pkg locally to exercise the integrity check, preserving epoch-pkg.
jq 'del(.packages["fresh-pkg"])' "$tmp/local-before.json" > "$SAFE_RUN_CONFIG_DIR/host-allow.json"
cp "$SAFE_RUN_CONFIG_DIR/host-allow.json" "$tmp/local-before.json"
sign_document "$fingerprint" "$tmp/incoming/host-allow.rainbow.json"
expect_follow_failure
for cause in 'no reason' 'unknown ecosystem' 'not an exact pinned' 'invalid entry field types' 'could not verify' 'integrity mismatch'; do
  grep -q "$cause" "$tmp/output" || fail "missing rejection: $cause"
done
pass 'same import validator rejects bad types, missing reasons, unknown ecosystems, non-exact pins, unresolved versions and changed integrity'

# Preview must model the whole UNION, including conflicts between source files.
reset_incoming
cp "$export_file" "$tmp/incoming/host-allow.rainbow.json"
cp "$export_file.asc" "$tmp/incoming/host-allow.rainbow.json.asc"
jq '.host="tuxedo" | .packages["fresh-pkg"].version="2.0.0"' "$export_file" > "$tmp/incoming/host-allow.tuxedo.json"
sign_document "$fingerprint" "$tmp/incoming/host-allow.tuxedo.json"
expect_follow_failure --dry-run
grep -q 'would-add fresh-pkg' "$tmp/output" || fail 'preview missing first addition'
grep -q 'CONFLICT fresh-pkg' "$tmp/output" || fail 'preview missed cross-file conflict'
pass 'dry-run detects cross-source conflict without mutating the local store'

# An invalid signature in one file must not suppress another valid file.
rm -f "$tmp/incoming/host-allow.tuxedo.json.asc"
expect_rc 1 "$SAFE_RUN" host-allow follow --from "$tmp/incoming"
jq -e '.packages | has("fresh-pkg") and has("epoch-pkg")' "$SAFE_RUN_CONFIG_DIR/host-allow.json" >/dev/null || fail 'invalid sibling prevented valid union'
pass 'bad sibling is counted while a valid signed file still applies'

expect_rc 1 "$SAFE_RUN" host-allow follow --yes
expect_rc 1 "$SAFE_RUN" host-allow follow -y
expect_rc 1 "$SAFE_RUN" host-allow follow --from
expect_rc 100 env SAFE_RUN_CONFIG_DIR="$tmp/redirected" "$SAFE_RUN" host-allow follow --dry-run
[[ ! -e "$tmp/redirected" ]] || fail 'redirect refusal seeded state'
pass 'no yes-style override; malformed flags and unblessed redirected stores refuse'
reset_incoming
cp "$export_file" "$tmp/incoming/host-allow.rainbow.json"
sign_document "$fingerprint" "$tmp/incoming/host-allow.rainbow.json"
jq 'del(.packages["fresh-pkg"])' "$SAFE_RUN_CONFIG_DIR/host-allow.json" > "$tmp/no-fresh.json"
cp "$tmp/no-fresh.json" "$SAFE_RUN_CONFIG_DIR/host-allow.json"
expect_rc 1 env TEST_CONCURRENT_PIN=1 "$SAFE_RUN" host-allow follow --from "$tmp/incoming"
jq -e '.packages["fresh-pkg"].version == "9.9.9"' "$SAFE_RUN_CONFIG_DIR/host-allow.json" >/dev/null || fail 'concurrent local pin overwritten'
grep -q 'CONFLICT fresh-pkg' "$tmp/output" || fail 'missing concurrent conflict'
pass 'UNION writer rechecks local pin after registry fetch under a grant-writer lock'

cp "$tmp/no-fresh.json" "$SAFE_RUN_CONFIG_DIR/host-allow.json"
cp "$tmp/no-fresh.json" "$tmp/local-before.json"
jq '.host = "forged-host"' "$export_file" > "$tmp/incoming/host-allow.rainbow.json"
sign_document "$fingerprint" "$tmp/incoming/host-allow.rainbow.json"
expect_follow_failure
grep -q 'host metadata' "$tmp/output" || fail 'host metadata mismatch not identified'
jq '.packages = false' "$export_file" > "$tmp/incoming/host-allow.rainbow.json"
sign_document "$fingerprint" "$tmp/incoming/host-allow.rainbow.json"
expect_follow_failure
grep -q 'malformed' "$tmp/output" || fail 'malformed signed envelope accepted'
pass 'signed envelope and host identity are validated before any grant'

# A pinned primary also authorizes its signing subkey; never pin short IDs.
gpg --no-options --batch --pinentry-mode loopback --passphrase '' --quick-add-key "$fingerprint" ed25519 sign 0 > "$tmp/keygen.log" 2>&1 || fail 'signing subkey generation failed'
subkey=$(gpg --no-options --batch --with-colons --list-keys "$fingerprint" 2>/dev/null | awk -F: '$1 == "sub" {want=1; next} want && $1 == "fpr" {print $10; exit}')
cp "$export_file" "$tmp/incoming/host-allow.rainbow.json"
sign_document "$subkey!" "$tmp/incoming/host-allow.rainbow.json"
expect_rc 0 "$SAFE_RUN" host-allow follow --from "$tmp/incoming"
pass 'signing subkey verifies through its pinned primary fingerprint'

# With no safe-specific selector, respect GPG's configured default key.
jq 'del(.follow.signing_key)' "$SAFE_RUN_CONFIG_DIR/config.json" > "$tmp/config-next.json"
cp "$tmp/config-next.json" "$SAFE_RUN_CONFIG_DIR/config.json"
printf 'default-key %s\n' "$other_fingerprint" > "$GNUPGHOME/gpg.conf"
pty_run "$SAFE_RUN" host-allow export --sign --out "$tmp/default-key" > "$tmp/output" 2>&1 || fail 'default-key export failed'
gpg --no-options --batch --status-fd 1 --verify "$tmp/default-key/host-allow.agent-dev.json.asc" "$tmp/default-key/host-allow.agent-dev.json" > "$tmp/default-status" 2>/dev/null || fail 'default-key signature failed'
grep -q "VALIDSIG $other_fingerprint " "$tmp/default-status" || fail 'GPG configured default key ignored'
pass 'signing key selection honors GPG default-key when follow.signing_key is absent'

# A failed signing operation must leave the published pair untouched.
cp "$export_file" "$tmp/export-before.json"
cp "$export_file.asc" "$tmp/export-before.asc"
jq '.follow.signing_key = "0000000000000000000000000000000000000000"' "$SAFE_RUN_CONFIG_DIR/config.json" > "$tmp/config-next.json"
cp "$tmp/config-next.json" "$SAFE_RUN_CONFIG_DIR/config.json"
cat > "$tmp/bin/hostname" <<'STUB'
#!/usr/bin/env bash
printf 'rainbow\n'
STUB
if pty_run "$SAFE_RUN" host-allow export --sign > "$tmp/output" 2>&1; then fail 'unavailable signing key succeeded'; fi
cmp "$tmp/export-before.json" "$export_file" || fail 'failed signing changed document'
cmp "$tmp/export-before.asc" "$export_file.asc" || fail 'failed signing changed signature'
pass 'signing failure preserves both previously published files'
printf 'all host-allow signed export/follow tests passed\n'
