#!/usr/bin/env bash
# Signed fleet replication. All state, keys and registry responses are fixtures.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SAFE_RUN="$ROOT/bin/safe-run"
pass() { printf 'ok - %s\n' "$*"; }
fail() { printf 'not ok - %s\n' "$*" >&2; exit 1; }
for tool in gpg gpgconf python3 jq flock timeout; do
  command -v "$tool" >/dev/null || fail "missing required command: $tool"
done
tmp=$(mktemp -d)
locker_pid="" remove_pid="" follow_pid=""
cleanup() {
  [[ ! -d "$tmp/registry-control" ]] || touch "$tmp/registry-control/release"
  [[ -z "$follow_pid" ]] || kill "$follow_pid" 2>/dev/null || true
  [[ -z "$locker_pid" ]] || kill "$locker_pid" 2>/dev/null || true
  [[ -z "$remove_pid" ]] || kill "$remove_pid" 2>/dev/null || true
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
[[ " $* " == *" --max-time 10 "* ]] || exit 99
[[ "${TEST_REGISTRY_OUTAGE:-0}" != 1 ]] || exit 22
if [[ -n "${TEST_REGISTRY_CONTROL:-}" ]]; then
  touch "$TEST_REGISTRY_CONTROL/started"
  while [[ ! -e "$TEST_REGISTRY_CONTROL/release" ]]; do sleep 0.02; done
fi
if [[ "${TEST_CONCURRENT_PIN:-0}" == "1" ]]; then
  jq '.packages["fresh-pkg"] = {version:"9.9.9", reason:"concurrent local grant", ecosystem:"npm"}' \
    "$SAFE_RUN_CONFIG_DIR/host-allow.json" > "$SAFE_RUN_CONFIG_DIR/concurrent.json"
  mv "$SAFE_RUN_CONFIG_DIR/concurrent.json" "$SAFE_RUN_CONFIG_DIR/host-allow.json"
fi
case "${!#}" in
  *registry.npmjs.org/fresh-pkg/1.2.3) printf '{"version":"1.2.3","dist":{"integrity":"sha512-FRESH"}}' ;;
  *registry.npmjs.org/fresh-pkg/2.0.0) printf '{"version":"2.0.0","dist":{"integrity":"sha512-FRESH"}}' ;;
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
grep -q 'already at the current generation' "$tmp/output" || fail 'repeat generation is not a quiet no-op'
[[ $(wc -l < "$tmp/output") == 1 ]] || fail 'steady state should print one info line'
cmp "$tmp/local-before.json" "$SAFE_RUN_CONFIG_DIR/host-allow.json" || fail 'repeat follow changed store'
pass 'non-TTY follow applies signed grant with original date and provenance; repeat generation is a quiet successful no-op'

# Per-case directory keeps invalid siblings from contaminating other tests.
mkdir "$tmp/incoming"
cp "$export_file" "$tmp/original.json"
reset_incoming() { rm -f "$tmp/incoming/"* "$SAFE_RUN_CONFIG_DIR/follow-state.json"; }
sign_document() {
  gpg --no-options --batch --yes --armor --local-user "$1" --detach-sign --output "$2.asc" -- "$2" > "$tmp/sign.log" 2>&1 || fail 'fixture signing failed'
}
expect_follow_failure() {
  expect_rc 1 "$SAFE_RUN" host-allow follow --from "$tmp/incoming"
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
jq 'del(.packages["fresh-pkg"].followed_from, .packages["fresh-pkg"].followed_generation) | .packages["fresh-pkg"].reason = "local operator pin"' "$SAFE_RUN_CONFIG_DIR/host-allow.json" > "$tmp/local-repin.json"
cp "$tmp/local-repin.json" "$SAFE_RUN_CONFIG_DIR/host-allow.json"
cp "$SAFE_RUN_CONFIG_DIR/host-allow.json" "$tmp/local-before.json"
jq '.packages["fresh-pkg"].version = "2.0.0"' "$export_file" > "$tmp/incoming/host-allow.rainbow.json"
sign_document "$fingerprint" "$tmp/incoming/host-allow.rainbow.json"
rm -f "$tmp/data/audit.log"
expect_rc 0 "$SAFE_RUN" host-allow follow --dry-run --from "$tmp/incoming"
grep -q 'would-replace fresh-pkg@1.2.3 -> @2.0.0' "$tmp/output" || fail 'dry-run missed signed replacement'
cmp "$tmp/local-before.json" "$SAFE_RUN_CONFIG_DIR/host-allow.json" || fail 'replacement preview altered local grant'
[[ ! -e "$SAFE_RUN_CONFIG_DIR/follow-state.json" ]] || fail 'replacement preview advanced ledger'
[[ ! -e "$tmp/data/audit.log" ]] || fail 'replacement preview wrote audit log'
expect_rc 0 "$SAFE_RUN" host-allow follow --from "$tmp/incoming"
jq -e '.packages["fresh-pkg"] | .version == "2.0.0" and .added == "2026-07-01" and .followed_from == "rainbow" and .sha == "sha512-FRESH"' "$SAFE_RUN_CONFIG_DIR/host-allow.json" >/dev/null || fail 'signed replacement differs'
jq -e '.origins.rainbow.applied == ["fresh-pkg@2.0.0"] and .origins.rainbow.replaced == ["fresh-pkg@1.2.3->2.0.0"]' "$SAFE_RUN_CONFIG_DIR/follow-state.json" >/dev/null || fail 'replacement ledger record differs'
grep -q 'host-allow-follow | fresh-pkg@2.0.0 | TRUST | non-tty | REPLACED | old_pin=@1.2.3 new_pin=@2.0.0 origin_host=rainbow generation=' "$tmp/data/audit.log" || fail 'replacement audit event missing'
grep -q 'followed fresh-pkg@2.0.0 from rainbow (replaced local pin @1.2.3)' "$tmp/output" || fail 'replacement info line missing'
pass 'signed follow replaces a different local pin, records the replacement, and previews without writes'

# An operator re-pin survives an equal generation, then a newer signed
# generation re-aligns it to the publishing host's pin.
printf '{"packages":{"fresh-pkg":{"version":"9.9.9","reason":"local re-pin","ecosystem":"npm"}}}\n' > "$SAFE_RUN_CONFIG_DIR/host-allow.json"
expect_rc 0 "$SAFE_RUN" host-allow follow --from "$tmp/incoming"
jq -e '.packages["fresh-pkg"].version == "9.9.9"' "$SAFE_RUN_CONFIG_DIR/host-allow.json" >/dev/null || fail 'equal generation changed a local re-pin'
repin_stamp=$(date -u -d "$(jq -r '.exported_at' "$export_file") + 60 seconds" +%Y-%m-%dT%H:%M:%SZ)
jq --arg stamp "$repin_stamp" '.exported_at = $stamp' "$export_file" > "$tmp/incoming/host-allow.rainbow.json"
sign_document "$fingerprint" "$tmp/incoming/host-allow.rainbow.json"
expect_rc 0 "$SAFE_RUN" host-allow follow --from "$tmp/incoming"
jq -e '.packages["fresh-pkg"].version == "1.2.3"' "$SAFE_RUN_CONFIG_DIR/host-allow.json" >/dev/null || fail 'newer generation did not re-align local re-pin'
grep -q 'followed fresh-pkg@1.2.3 from rainbow (replaced local pin @9.9.9)' "$tmp/output" || fail 'newer re-alignment info line missing'
pass 'local re-pin survives an equal generation and is replaced by a newer signed generation'

# A newer signed generation wins across origins regardless of glob order.
cross_base=$(date -d "$(jq -r '.exported_at' "$export_file")" +%s)
cross_newer=$(date -u -d "@$((cross_base + 7200))" +%Y-%m-%dT%H:%M:%SZ)
cross_older=$(date -u -d "@$((cross_base + 3600))" +%Y-%m-%dT%H:%M:%SZ)
reset_incoming
printf '{"packages":{}}\n' > "$SAFE_RUN_CONFIG_DIR/host-allow.json"
jq --arg stamp "$cross_newer" '.host = "rainbow" | .exported_at = $stamp | .packages["fresh-pkg"].version = "2.0.0"' "$export_file" > "$tmp/incoming/host-allow.rainbow.json"
jq --arg stamp "$cross_older" '.host = "tuxedo" | .exported_at = $stamp | .packages["fresh-pkg"].version = "1.2.3"' "$export_file" > "$tmp/incoming/host-allow.tuxedo.json"
sign_document "$fingerprint" "$tmp/incoming/host-allow.rainbow.json"
sign_document "$fingerprint" "$tmp/incoming/host-allow.tuxedo.json"
expect_rc 1 "$SAFE_RUN" host-allow follow --from "$tmp/incoming"
jq -e '.packages["fresh-pkg"].version == "2.0.0" and .packages["fresh-pkg"].followed_from == "rainbow" and .packages["fresh-pkg"].followed_generation == $stamp' --arg stamp "$cross_newer" "$SAFE_RUN_CONFIG_DIR/host-allow.json" >/dev/null || fail 'older cross-origin statement downgraded the newer pin'
jq -e '.origins.rainbow.applied == ["fresh-pkg@2.0.0"] and .origins.tuxedo.applied == []' "$SAFE_RUN_CONFIG_DIR/follow-state.json" >/dev/null || fail 'older cross-origin identity was consumed'
grep -q 'refusing fresh-pkg@1.2.3 from tuxedo: local pin @2.0.0 from rainbow' "$tmp/output" || fail 'cross-origin warning did not name both origins'
expect_rc 1 "$SAFE_RUN" host-allow follow --from "$tmp/incoming"
jq -e '.origins.tuxedo.applied == []' "$SAFE_RUN_CONFIG_DIR/follow-state.json" >/dev/null || fail 'lagging origin stopped retrying after its first refusal'
cp "$tmp/incoming/host-allow.tuxedo.json" "$tmp/tuxedo-cross.json"
cp "$tmp/incoming/host-allow.tuxedo.json.asc" "$tmp/tuxedo-cross.json.asc"
cp "$tmp/incoming/host-allow.rainbow.json" "$tmp/rainbow-cross.json"
cp "$tmp/incoming/host-allow.rainbow.json.asc" "$tmp/rainbow-cross.json.asc"
cp "$SAFE_RUN_CONFIG_DIR/follow-state.json" "$tmp/state-with-refusal.json"

reset_incoming
mkdir "$tmp/older-first" "$tmp/newer-second"
cp "$tmp/tuxedo-cross.json" "$tmp/older-first/host-allow.tuxedo.json"
cp "$tmp/tuxedo-cross.json.asc" "$tmp/older-first/host-allow.tuxedo.json.asc"
cp "$tmp/rainbow-cross.json" "$tmp/newer-second/host-allow.rainbow.json"
cp "$tmp/rainbow-cross.json.asc" "$tmp/newer-second/host-allow.rainbow.json.asc"
printf '{"packages":{}}\n' > "$SAFE_RUN_CONFIG_DIR/host-allow.json"
expect_rc 0 "$SAFE_RUN" host-allow follow --from "$tmp/older-first"
expect_rc 0 "$SAFE_RUN" host-allow follow --from "$tmp/newer-second"
jq -e '.packages["fresh-pkg"].version == "2.0.0" and .packages["fresh-pkg"].followed_from == "rainbow" and .packages["fresh-pkg"].followed_generation == $stamp' --arg stamp "$cross_newer" "$SAFE_RUN_CONFIG_DIR/host-allow.json" >/dev/null || fail 'newer cross-origin statement did not re-align the older pin'
jq -e '.origins.tuxedo.applied == ["fresh-pkg@1.2.3"] and .origins.rainbow.applied == ["fresh-pkg@2.0.0"]' "$SAFE_RUN_CONFIG_DIR/follow-state.json" >/dev/null || fail 'reversed cross-origin order did not apply both generations'
cp "$tmp/local-before.json" "$SAFE_RUN_CONFIG_DIR/host-allow.json"
rm -rf -- "$tmp/older-first" "$tmp/newer-second"
pass 'newest signed statement wins across origins; an older statement stays retryable'

# A refusal survives an operator TTY re-pin, including a dry-run. The
# lagging origin remains red until it publishes a newer generation.
cp "$tmp/tuxedo-cross.json" "$tmp/incoming/host-allow.tuxedo.json"
cp "$tmp/tuxedo-cross.json.asc" "$tmp/incoming/host-allow.tuxedo.json.asc"
cp "$tmp/rainbow-cross.json" "$tmp/incoming/host-allow.rainbow.json"
cp "$tmp/rainbow-cross.json.asc" "$tmp/incoming/host-allow.rainbow.json.asc"
cp "$tmp/state-with-refusal.json" "$SAFE_RUN_CONFIG_DIR/follow-state.json"
cp "$SAFE_RUN_CONFIG_DIR/host-allow.json" "$tmp/local-before-refused-repin.json"
cp "$SAFE_RUN_CONFIG_DIR/follow-state.json" "$tmp/state-before-refused-repin.json"
printf '{"packages":{"fresh-pkg":{"version":"3.0.0","reason":"local TTY re-pin","ecosystem":"npm"}}}\n' > "$SAFE_RUN_CONFIG_DIR/host-allow.json"
expect_rc 1 "$SAFE_RUN" host-allow follow --from "$tmp/incoming"
jq -e '.packages["fresh-pkg"].version == "3.0.0" and (.packages["fresh-pkg"] | has("followed_from") | not)' "$SAFE_RUN_CONFIG_DIR/host-allow.json" >/dev/null || fail 'refused origin replaced a TTY re-pin'
grep -q 'follow: skipped fresh-pkg@1.2.3 from tuxedo' "$tmp/output" || fail 'repeated refusal did not print the quiet skip'
cmp "$tmp/state-before-refused-repin.json" "$SAFE_RUN_CONFIG_DIR/follow-state.json" || fail 'repeated refusal changed the ledger'
cp "$SAFE_RUN_CONFIG_DIR/host-allow.json" "$tmp/local-after-refused-repin.json"
expect_rc 1 "$SAFE_RUN" host-allow follow --dry-run --from "$tmp/incoming"
grep -q 'follow: skipped fresh-pkg@1.2.3 from tuxedo' "$tmp/output" || fail 'dry-run did not print the refused skip'
cmp "$tmp/local-after-refused-repin.json" "$SAFE_RUN_CONFIG_DIR/host-allow.json" || fail 'refused dry-run changed the store'
cmp "$tmp/state-before-refused-repin.json" "$SAFE_RUN_CONFIG_DIR/follow-state.json" || fail 'refused dry-run changed the ledger'
pass 'same-generation refusals survive a TTY re-pin and dry-run'

# A repaired followed-generation must be compared again even when the
# identity remains in refusal memory. The memory-only path is for entries with
# no generation, where there is no safe comparison to make.
reset_incoming
printf '{"packages":{"fresh-pkg":{"version":"1.2.3","sha":"sha512-FRESH","ecosystem":"npm","added":"2026-07-01","reason":"repaired followed grant","followed_from":"rainbow","followed_generation":"%s"}}}\n' "$cross_older" > "$SAFE_RUN_CONFIG_DIR/host-allow.json"
printf '{"origins":{"rainbow":{"accepted":"%s","applied":[],"replaced":[],"refused":["fresh-pkg@2.0.0"]}}}\n' "$cross_newer" > "$SAFE_RUN_CONFIG_DIR/follow-state.json"
jq --arg stamp "$cross_newer" '.host = "rainbow" | .exported_at = $stamp | .packages["fresh-pkg"].version = "2.0.0"' "$export_file" > "$tmp/incoming/host-allow.rainbow.json"
sign_document "$fingerprint" "$tmp/incoming/host-allow.rainbow.json"
expect_rc 0 "$SAFE_RUN" host-allow follow --from "$tmp/incoming"
jq -e '.packages["fresh-pkg"].version == "2.0.0" and .packages["fresh-pkg"].followed_generation == $stamp' --arg stamp "$cross_newer" "$SAFE_RUN_CONFIG_DIR/host-allow.json" >/dev/null || fail 'repaired generation did not re-derive the refusal decision'
jq -e '.origins.rainbow.refused == [] and .origins.rainbow.applied == ["fresh-pkg@2.0.0"]' "$SAFE_RUN_CONFIG_DIR/follow-state.json" >/dev/null || fail 'repaired generation refusal was not cleared after apply'
pass 'generation-bearing refused identities are re-derived before comparison'

# A 1.63.0-shaped followed entry has no stamp, but its applied identity and
# origin ledger still recover the accepted generation before comparison.
reset_incoming
mkdir "$tmp/legacy"
printf '{"packages":{"fresh-pkg":{"version":"2.0.0","sha":"sha512-FRESH","ecosystem":"npm","added":"2026-07-01","reason":"legacy followed grant","followed_from":"rainbow"}}}\n' > "$SAFE_RUN_CONFIG_DIR/host-allow.json"
printf '{"origins":{"rainbow":{"accepted":"%s","applied":["fresh-pkg@2.0.0"],"replaced":[]}}}\n' "$cross_newer" > "$SAFE_RUN_CONFIG_DIR/follow-state.json"
cp "$SAFE_RUN_CONFIG_DIR/host-allow.json" "$tmp/legacy-before.json"
cp "$tmp/tuxedo-cross.json" "$tmp/legacy/host-allow.tuxedo.json"
cp "$tmp/tuxedo-cross.json.asc" "$tmp/legacy/host-allow.tuxedo.json.asc"
expect_rc 1 "$SAFE_RUN" host-allow follow --from "$tmp/legacy"
cmp "$tmp/legacy-before.json" "$SAFE_RUN_CONFIG_DIR/host-allow.json" || fail 'legacy followed entry was replaced by an older statement'
grep -q 'refusing fresh-pkg@1.2.3 from tuxedo: local pin @2.0.0 from rainbow' "$tmp/output" || fail 'legacy generation backfill did not refuse the lagging origin'
rm -rf -- "$tmp/legacy"
cp "$tmp/local-before.json" "$SAFE_RUN_CONFIG_DIR/host-allow.json"
pass 'legacy followed entries derive their accepted generation on first follow'

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

# A malformed local entry is a named conflict, while a valid sibling in the
# same signed file still applies. Exercise both null and versionless shapes.
reset_incoming
jq '.host = "rainbow" | .packages = {
 "fresh-pkg":{"version":"1.2.3","ecosystem":"npm","sha":"sha512-FRESH","reason":"fresh grant","added":"2026-07-01"},
 "epoch-pkg":{"version":"1!2.0","ecosystem":"python","sha":"sha256-EPOCH","reason":"sibling grant","added":"2026-06-03"}
}' "$export_file" > "$tmp/incoming/host-allow.rainbow.json"
sign_document "$fingerprint" "$tmp/incoming/host-allow.rainbow.json"
printf '{"packages":{"fresh-pkg":null}}\n' > "$SAFE_RUN_CONFIG_DIR/host-allow.json"
expect_rc 1 "$SAFE_RUN" host-allow follow --from "$tmp/incoming"
grep -q 'CONFLICT fresh-pkg: local pins @invalid, follow has @1.2.3' "$tmp/output" || fail 'null local entry was not named as a conflict'
jq -e '.packages["epoch-pkg"].version == "1!2.0"' "$SAFE_RUN_CONFIG_DIR/host-allow.json" >/dev/null || fail 'null entry blocked the valid sibling'
jq -e '.origins.rainbow.applied | index("epoch-pkg@1!2.0") != null' "$SAFE_RUN_CONFIG_DIR/follow-state.json" >/dev/null || fail 'null entry sibling was not recorded'
reset_incoming
jq '.host = "rainbow" | .packages = {
 "fresh-pkg":{"version":"1.2.3","ecosystem":"npm","sha":"sha512-FRESH","reason":"fresh grant","added":"2026-07-01"},
 "epoch-pkg":{"version":"1!2.0","ecosystem":"python","sha":"sha256-EPOCH","reason":"sibling grant","added":"2026-06-03"}
}' "$export_file" > "$tmp/incoming/host-allow.rainbow.json"
sign_document "$fingerprint" "$tmp/incoming/host-allow.rainbow.json"
printf '{"packages":{"fresh-pkg":{"reason":"missing version"}}}\n' > "$SAFE_RUN_CONFIG_DIR/host-allow.json"
expect_rc 1 "$SAFE_RUN" host-allow follow --from "$tmp/incoming"
grep -q 'CONFLICT fresh-pkg: local pins @invalid, follow has @1.2.3' "$tmp/output" || fail 'versionless local entry was not named as a conflict'
jq -e '.packages["epoch-pkg"].version == "1!2.0"' "$SAFE_RUN_CONFIG_DIR/host-allow.json" >/dev/null || fail 'versionless entry blocked the valid sibling'
jq -e '.origins.rainbow.applied | index("epoch-pkg@1!2.0") != null' "$SAFE_RUN_CONFIG_DIR/follow-state.json" >/dev/null || fail 'versionless entry sibling was not recorded'
cp "$tmp/local-before.json" "$SAFE_RUN_CONFIG_DIR/host-allow.json"
pass 'null and versionless local entries report named conflicts while valid siblings apply'

# Preview must model the whole UNION, including conflicts between source files.
reset_incoming
cp "$export_file" "$tmp/incoming/host-allow.rainbow.json"
cp "$export_file.asc" "$tmp/incoming/host-allow.rainbow.json.asc"
preview_stamp=$(date -u -d "$(jq -r '.exported_at' "$export_file") + 60 seconds" +%Y-%m-%dT%H:%M:%SZ)
jq --arg stamp "$preview_stamp" '.host="tuxedo" | .exported_at=$stamp | .packages["fresh-pkg"].version="2.0.0"' "$export_file" > "$tmp/incoming/host-allow.tuxedo.json"
sign_document "$fingerprint" "$tmp/incoming/host-allow.tuxedo.json"
expect_rc 0 "$SAFE_RUN" host-allow follow --from "$tmp/incoming" --dry-run
grep -q 'would-add fresh-pkg' "$tmp/output" || fail 'preview missing first addition'
grep -q 'would-replace fresh-pkg@1.2.3 -> @2.0.0' "$tmp/output" || fail 'preview missed cross-source replacement'
cmp "$tmp/local-before.json" "$SAFE_RUN_CONFIG_DIR/host-allow.json" || fail 'cross-source replacement preview altered local grant'
pass 'dry-run models signed replacement across source files without mutating the local store'

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
rm -f "$SAFE_RUN_CONFIG_DIR/follow-state.json"
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

# Review regressions use the same isolated follower, never the real keyring.
cat > "$tmp/bin/hostname" <<'STUB'
#!/usr/bin/env bash
printf 'agent-dev\n'
STUB
reset_incoming
cp "$export_file" "$tmp/incoming/host-allow.rainbow.json"
sign_document "$fingerprint" "$tmp/incoming/host-allow.rainbow.json"
state_file="$SAFE_RUN_CONFIG_DIR/follow-state.json"
original_stamp=$(jq -r '.exported_at' "$export_file")
original_epoch=$(date -d "$original_stamp" +%s)
newer_stamp=$(date -u -d "@$((original_epoch + 60))" +%Y-%m-%dT%H:%M:%SZ)
older_stamp=$(date -u -d "@$((original_epoch - 60))" +%Y-%m-%dT%H:%M:%SZ)
rm -f "$SAFE_RUN_CONFIG_DIR/host-allow.json.lock"
expect_rc 0 "$SAFE_RUN" host-allow follow --dry-run --from "$tmp/incoming"
[[ ! -e "$state_file" && ! -e "$SAFE_RUN_CONFIG_DIR/host-allow.json.lock" ]] || fail 'dry-run created generation or lock state'
expect_rc 0 "$SAFE_RUN" host-allow follow --from "$tmp/incoming"
jq -e --arg stamp "$original_stamp" '.origins.rainbow.accepted == $stamp' "$state_file" >/dev/null || fail 'generation not recorded'
"$SAFE_RUN" host-allow remove fresh-pkg > "$tmp/output" 2>&1
cp "$state_file" "$tmp/state-before.json"
cp "$SAFE_RUN_CONFIG_DIR/host-allow.json" "$tmp/local-before.json"
expect_rc 0 "$SAFE_RUN" host-allow follow --from "$tmp/incoming"
cmp "$tmp/local-before.json" "$SAFE_RUN_CONFIG_DIR/host-allow.json" || fail 'equal generation re-added a removed grant'
[[ $(wc -l < "$tmp/output") == 1 ]] || fail 'equal generation should print one info line'
jq --arg stamp "$older_stamp" '.exported_at = $stamp' "$export_file" > "$tmp/incoming/host-allow.rainbow.json"
sign_document "$fingerprint" "$tmp/incoming/host-allow.rainbow.json"
expect_follow_failure
cmp "$tmp/state-before.json" "$state_file" || fail 'older replay changed high-water mark'
pass 'equal and older signed generations cannot re-add a removed grant via --from'

# Equivalent timestamp spellings must share the applied-identity ledger.
equivalent_stamp=$(date -u -d "@$original_epoch" +%Y-%m-%dT%H:%M:%SZ)
jq --arg stamp "$equivalent_stamp" '.exported_at = $stamp' "$export_file" > "$tmp/incoming/host-allow.rainbow.json"
sign_document "$fingerprint" "$tmp/incoming/host-allow.rainbow.json"
expect_rc 0 "$SAFE_RUN" host-allow follow --from "$tmp/incoming"
cmp "$tmp/local-before.json" "$SAFE_RUN_CONFIG_DIR/host-allow.json" || fail 'timezone-equivalent generation re-added removed grant'
pass 'freshness compares timestamp instants rather than timezone strings'

jq --arg stamp "$newer_stamp" '.exported_at = $stamp' "$export_file" > "$tmp/incoming/host-allow.rainbow.json"
sign_document "$fingerprint" "$tmp/incoming/host-allow.rainbow.json"
expect_rc 0 "$SAFE_RUN" host-allow follow --dry-run --from "$tmp/incoming"
grep -q 'would-add fresh-pkg' "$tmp/output" || fail 'newer preview did not plan addition'
cmp "$tmp/state-before.json" "$state_file" || fail 'dry-run advanced high-water mark'
cmp "$tmp/local-before.json" "$SAFE_RUN_CONFIG_DIR/host-allow.json" || fail 'newer dry-run changed trust store'
expect_rc 0 "$SAFE_RUN" host-allow follow --from "$tmp/incoming"
jq -e --arg stamp "$newer_stamp" '.origins.rainbow.accepted == $stamp' "$state_file" >/dev/null || fail 'newer generation did not advance state'
jq -e '.packages | has("fresh-pkg")' "$SAFE_RUN_CONFIG_DIR/host-allow.json" >/dev/null || fail 'newer signed statement did not apply'
pass 'newer generation applies and advances state; dry-run leaves existing state byte-identical'

# Keep another origin's mark when updating this one, and fail closed on bad state.
jq '.origins.tuxedo = {accepted:"2026-01-01T00:00:00Z",applied:[]}' "$state_file" > "$tmp/state-next.json"
cp "$tmp/state-next.json" "$state_file"
next_stamp=$(date -u -d "@$((original_epoch + 120))" +%Y-%m-%dT%H:%M:%SZ)
jq --arg stamp "$next_stamp" '.exported_at = $stamp' "$export_file" > "$tmp/incoming/host-allow.rainbow.json"
sign_document "$fingerprint" "$tmp/incoming/host-allow.rainbow.json"
expect_rc 0 "$SAFE_RUN" host-allow follow --from "$tmp/incoming"
jq -e --arg stamp "$next_stamp" '.origins.rainbow.accepted == $stamp and .origins.tuxedo.accepted == "2026-01-01T00:00:00Z"' "$state_file" >/dev/null || fail 'state lost another origin'
cp "$state_file" "$tmp/state-before.json"
cp "$SAFE_RUN_CONFIG_DIR/host-allow.json" "$tmp/local-before.json"
printf '{"origins":{"rainbow":{"accepted":"tomorrow","applied":[]}}}\n' > "$state_file"
expect_follow_failure
grep -q 'malformed timestamp' "$tmp/output" || fail 'invalid state timestamp not surfaced'
printf '{"origins":false}\n' > "$state_file"
expect_follow_failure
grep -q 'malformed follow-state' "$tmp/output" || fail 'invalid state envelope not surfaced'
cp "$tmp/state-before.json" "$state_file"
jq '.exported_at="2026-02-30T00:00:00Z"' "$export_file" > "$tmp/incoming/host-allow.rainbow.json"
sign_document "$fingerprint" "$tmp/incoming/host-allow.rainbow.json"
expect_follow_failure
cmp "$tmp/state-before.json" "$state_file" || fail 'invalid export timestamp changed state'
pass 'per-origin state is preserved and malformed state/export timestamps fail closed'

# Partial validation failures leave only the successful identities consumed;
# later retries must not replay those additions after operator removal.
reset_incoming
jq --arg stamp "$next_stamp" '.exported_at=$stamp | .packages["bad-pkg"]={version:"latest",reason:"bad sibling"}' "$export_file" > "$tmp/incoming/host-allow.rainbow.json"
sign_document "$fingerprint" "$tmp/incoming/host-allow.rainbow.json"
expect_rc 1 "$SAFE_RUN" host-allow follow --from "$tmp/incoming"
[[ -s "$state_file" ]] || fail 'partially accepted generation not consumed'
"$SAFE_RUN" host-allow remove fresh-pkg > "$tmp/output" 2>&1
cp "$SAFE_RUN_CONFIG_DIR/host-allow.json" "$tmp/local-before.json"
expect_follow_failure
grep -q 'not an exact pinned' "$tmp/output" || fail 'unapplied invalid entry was not retried'
jq -e '.origins.rainbow.applied == ["fresh-pkg@1.2.3"]' "$state_file" >/dev/null || fail 'ledger did not isolate successful entry'
pass 'partial entry failures cannot leave successful grants replayable after removal'

# Removal must wait for the shared writer lock, not race its read/modify/write.
# Lock readiness and process completion are explicit markers, not elapsed-time claims.
cp "$tmp/export-before.json" "$SAFE_RUN_CONFIG_DIR/host-allow.json"
(
  flock -x 9
  touch "$tmp/lock-ready"
  while [[ ! -e "$tmp/release-lock" ]]; do sleep 0.02; done
) 9>"$SAFE_RUN_CONFIG_DIR/host-allow.json.lock" &
locker_pid=$!
for ((attempt=0; attempt<100; attempt++)); do
  [[ -e "$tmp/lock-ready" ]] && break
  sleep 0.02
done
[[ -e "$tmp/lock-ready" ]] || fail 'lock holder did not become ready'
(
  "$SAFE_RUN" host-allow remove fresh-pkg > "$tmp/remove-output" 2>&1
  touch "$tmp/remove-completed"
) &
remove_pid=$!
sleep 0.2
blocked=1
[[ ! -e "$tmp/remove-completed" ]] || blocked=0
jq -e '.packages | has("fresh-pkg")' "$SAFE_RUN_CONFIG_DIR/host-allow.json" >/dev/null || blocked=0
touch "$tmp/release-lock"
wait "$locker_pid"
locker_pid=""
wait "$remove_pid"
remove_pid=""
[[ "$blocked" == 1 ]] || fail 'remove completed while the host-allow writer lock was held'
jq -e '.packages | has("fresh-pkg") | not' "$SAFE_RUN_CONFIG_DIR/host-allow.json" >/dev/null || fail 'remove failed after lock release'
pass 'remove blocks under the shared writer lock and succeeds after release'

# A registry outage must leave identities retryable in the same generation.
reset_incoming
cp "$export_file" "$tmp/incoming/host-allow.rainbow.json"
sign_document "$fingerprint" "$tmp/incoming/host-allow.rainbow.json"
expect_rc 1 env TEST_REGISTRY_OUTAGE=1 "$SAFE_RUN" host-allow follow --from "$tmp/incoming"
jq -e '.origins.rainbow.applied == []' "$state_file" >/dev/null || fail 'outage consumed unapplied grants'
cp "$state_file" "$tmp/outage-state.json"
expect_rc 0 "$SAFE_RUN" host-allow follow --dry-run --from "$tmp/incoming"
cmp "$tmp/outage-state.json" "$state_file" || fail 'retry preview mutated ledger'
expect_rc 0 "$SAFE_RUN" host-allow follow --from "$tmp/incoming"
jq -e '.packages["fresh-pkg"].version == "1.2.3"' "$SAFE_RUN_CONFIG_DIR/host-allow.json" >/dev/null || fail 'outage retry did not apply grant'
jq -e '.origins.rainbow.applied == ["fresh-pkg@1.2.3"]' "$state_file" >/dev/null || fail 'successful retry not recorded'
pass 'outage then recovery applies the unchanged signed generation on retry'
for ((repeat=0; repeat<3; repeat++)); do
  expect_rc 0 env TEST_REGISTRY_OUTAGE=1 "$SAFE_RUN" host-allow follow --from "$tmp/incoming"
  [[ $(wc -l < "$tmp/output") == 1 ]] || fail 'steady state prints more than one info line'
  grep -q 'already at the current generation' "$tmp/output" || fail 'missing quiet steady-state info'
  if grep -qE 'WARN|operator override|host-allow import' "$tmp/output"; then fail 'steady state suggests an override'; fi
done
pass 'three unchanged runs return zero with one quiet info line and no registry dependency'

# A reported trust-store publication failure must also leave that identity
# retryable. The mv stub fails only when the final target is the trust store;
# ledger renames continue normally so this reaches the store publication path.
reset_incoming
jq '.packages["fresh-pkg"].version = "2.0.0"' "$export_file" > "$tmp/incoming/host-allow.rainbow.json"
sign_document "$fingerprint" "$tmp/incoming/host-allow.rainbow.json"
printf '{"packages":{"fresh-pkg":{"version":"1.2.3","sha":"sha512-FRESH","ecosystem":"npm","added":"2026-06-01","reason":"local operator pin"}}}\n' > "$SAFE_RUN_CONFIG_DIR/host-allow.json"
cp "$SAFE_RUN_CONFIG_DIR/host-allow.json" "$tmp/local-before.json"
rm -f "$tmp/data/audit.log"
cat > "$tmp/bin/mv" <<'STUB'
#!/usr/bin/env bash
if [[ "${TEST_FAIL_HOST_STORE:-0}" == 1 && "${!#}" == "$SAFE_RUN_CONFIG_DIR/host-allow.json" ]]; then exit 1; fi
exec /usr/bin/mv "$@"
STUB
chmod +x "$tmp/bin/mv"
expect_rc 1 env TEST_FAIL_HOST_STORE=1 "$SAFE_RUN" host-allow follow --from "$tmp/incoming"
jq -e '.origins.rainbow.applied == []' "$state_file" >/dev/null || fail 'failed store publication consumed identity'
cmp "$tmp/local-before.json" "$SAFE_RUN_CONFIG_DIR/host-allow.json" || fail 'failed store publication changed local grant'
if [[ -e "$tmp/data/audit.log" ]] && grep -q 'REPLACED' "$tmp/data/audit.log"; then fail 'failed store publication wrote replacement audit'; fi
expect_rc 0 "$SAFE_RUN" host-allow follow --from "$tmp/incoming"
jq -e '.packages["fresh-pkg"].version == "2.0.0"' "$SAFE_RUN_CONFIG_DIR/host-allow.json" >/dev/null || fail 'store-failure retry did not replace local pin'
jq -e '.origins.rainbow.applied == ["fresh-pkg@2.0.0"]' "$state_file" >/dev/null || fail 'store-failure retry did not complete'
pass 'explicit local publication failure rolls back only the failed identity for retry'

# Registry validation must not hold the store lock. Explicit readiness markers
# keep the proof independent of the registry stub's sleep duration.
reset_incoming
jq '.packages["a-kept"]={version:"5.0.0",reason:"local grant",ecosystem:"npm"}' "$export_file" > "$tmp/incoming/host-allow.rainbow.json"
sign_document "$fingerprint" "$tmp/incoming/host-allow.rainbow.json"
printf '{"packages":{"a-kept":{"version":"5.0.0","reason":"local grant","ecosystem":"npm"}}}\n' > "$SAFE_RUN_CONFIG_DIR/host-allow.json"
mkdir "$tmp/registry-control"
env TEST_REGISTRY_CONTROL="$tmp/registry-control" "$SAFE_RUN" host-allow follow --from "$tmp/incoming" > "$tmp/slow-follow.log" 2>&1 &
follow_pid=$!
for ((attempt=0; attempt<250; attempt++)); do
  [[ -e "$tmp/registry-control/started" ]] && break
  sleep 0.02
done
[[ -e "$tmp/registry-control/started" ]] || fail 'registry stub did not start'
remove_rc=0
timeout 2 "$SAFE_RUN" host-allow remove a-kept > "$tmp/remove-output" 2>&1 || remove_rc=$?
[[ "$remove_rc" == 0 ]] || fail 'remove blocked behind registry I/O'
[[ ! -e "$tmp/registry-control/release" ]] || fail 'registry released before remove proof'
jq -e '.packages | has("a-kept") | not' "$SAFE_RUN_CONFIG_DIR/host-allow.json" >/dev/null || fail 'remove failed during registry I/O'
touch "$tmp/registry-control/release"
wait "$follow_pid"
follow_pid=""
jq -e '.packages | has("fresh-pkg") and (has("a-kept") | not)' "$SAFE_RUN_CONFIG_DIR/host-allow.json" >/dev/null || fail 'follow lost concurrent removal'
pass 'remove completes while registry is stalled; follow preserves its removal on commit'

# Bound actual contention too: use the production timeout, not a test bypass.
exec {held_lock}>"$SAFE_RUN_CONFIG_DIR/host-allow.json.lock"
flock -x "$held_lock"
expect_rc 1 timeout 13 "$SAFE_RUN" host-allow remove fresh-pkg
grep -q 'another writer is running (lock timeout after 10s)' "$tmp/output" || fail 'lock timeout lacks clear recovery message'
flock -u "$held_lock"
exec {held_lock}>&-
pass 'store-lock contention times out with a writer-busy recovery hint'

# Sign with the healthy primary, then let an unrelated subkey expire. GPG
# emits KEYEXPIRED even though this signature remains GOODSIG/VALIDSIG.
reset_incoming
gpg --no-options --batch --pinentry-mode loopback --passphrase '' \
  --quick-add-key "$fingerprint" ed25519 sign seconds=3 > "$tmp/keygen.log" 2>&1 || fail 'rotating subkey generation failed'
rotating_subkey=$(gpg --no-options --batch --with-colons --list-keys "$fingerprint" 2>/dev/null | awk -F: '$1 == "sub" {want=1; next} want && $1 == "fpr" {last=$10; want=0} END {print last}')
cp "$export_file" "$tmp/incoming/host-allow.rainbow.json"
sign_document "$fingerprint!" "$tmp/incoming/host-allow.rainbow.json"
cp "$export_file" "$tmp/expired-subkey.json"
sign_document "$rotating_subkey!" "$tmp/expired-subkey.json"
for ((attempt=0; attempt<100; attempt++)); do
  validity=$(gpg --no-options --batch --with-colons --list-keys "$fingerprint" 2>/dev/null | awk -F: -v f="$rotating_subkey" '$1 == "sub" {v=$2} $1 == "fpr" && $10 == f {print v}')
  [[ "$validity" == e ]] && break
  sleep 0.1
done
[[ "$validity" == e ]] || fail 'unrelated subkey did not expire'
gpg --no-options --batch --status-fd 1 --verify "$tmp/incoming/host-allow.rainbow.json.asc" "$tmp/incoming/host-allow.rainbow.json" > "$tmp/unrelated-status" 2>/dev/null || fail 'healthy primary signature no longer verifies'
grep -q '^\[GNUPG:\] KEYEXPIRED ' "$tmp/unrelated-status" || fail 'fixture did not exercise KEYEXPIRED'
grep -q '^\[GNUPG:\] GOODSIG ' "$tmp/unrelated-status" || fail 'fixture lacks GOODSIG'
"$SAFE_RUN" host-allow remove fresh-pkg > "$tmp/output" 2>&1
expect_rc 0 "$SAFE_RUN" host-allow follow --from "$tmp/incoming"
jq -e '.packages | has("fresh-pkg")' "$SAFE_RUN_CONFIG_DIR/host-allow.json" >/dev/null || fail 'unrelated expired subkey blocked primary signature'
pass 'healthy primary signature applies despite an unrelated expired subkey'

# The unrelated key-level warning is harmless; a signature actually made by
# that expired subkey must still be refused with unchanged store and ledger.
cp "$SAFE_RUN_CONFIG_DIR/host-allow.json" "$tmp/local-before.json"
cp "$state_file" "$tmp/subkey-state.json"
cp "$tmp/expired-subkey.json.asc" "$tmp/incoming/host-allow.rainbow.json.asc"
expect_follow_failure
cmp "$tmp/subkey-state.json" "$state_file" || fail 'expired signing subkey changed ledger'
pass 'expired signing subkey is still refused although its primary remains healthy'

# Expire a real short-lived key after signing and pinning it while still live.
reset_incoming
gpg --no-options --batch --pinentry-mode loopback --passphrase '' \
  --quick-generate-key 'Safe fixture expiring <expiring@example.invalid>' ed25519 sign seconds=8 > "$tmp/keygen.log" 2>&1 || fail 'expiring fixture key generation failed'
expiring_fingerprint=$(gpg --no-options --batch --with-colons --list-keys 'expiring@example.invalid' 2>/dev/null | awk -F: '$1 == "fpr" {print $10; exit}')
cp "$export_file" "$tmp/incoming/host-allow.rainbow.json"
sign_document "$expiring_fingerprint" "$tmp/incoming/host-allow.rainbow.json"
pty_run "$SAFE_RUN" host-allow follow-signer add "$expiring_fingerprint" > "$tmp/output" 2>&1 || fail 'live expiring signer pin failed'
for ((attempt=0; attempt<100; attempt++)); do
  validity=$(gpg --no-options --batch --with-colons --list-keys "$expiring_fingerprint" 2>/dev/null | awk -F: '$1 == "pub" {print $2; exit}')
  [[ "$validity" == e ]] && break
  sleep 0.1
done
[[ "$validity" == e ]] || fail 'fixture key did not expire within bounded wait'
cp "$SAFE_RUN_CONFIG_DIR/host-allow.json" "$tmp/local-before.json"
expect_follow_failure
grep -q '1 signature skips' "$tmp/output" || fail 'expired key not counted as signature failure'
[[ ! -e "$state_file" ]] || fail 'expired signature advanced generation state'
pass 'expired pinned primary cannot authorize a previously signed grant'

# Import the key's real revocation certificate into the ambient follower ring.
reset_incoming
cp "$export_file" "$tmp/incoming/host-allow.rainbow.json"
sign_document "$fingerprint" "$tmp/incoming/host-allow.rainbow.json"
sed 's/^://' "$GNUPGHOME/openpgp-revocs.d/$fingerprint.rev" > "$tmp/revoke.asc"
gpg --no-options --batch --import "$tmp/revoke.asc" > "$tmp/revoke.log" 2>&1 || fail 'fixture revocation import failed'
validity=$(gpg --no-options --batch --with-colons --list-keys "$fingerprint" 2>/dev/null | awk -F: '$1 == "pub" {print $2; exit}')
[[ "$validity" == r ]] || fail 'fixture key not revoked'
expect_follow_failure
grep -q '1 signature skips' "$tmp/output" || fail 'revoked key not counted as signature failure'
[[ ! -e "$state_file" ]] || fail 'revoked signature advanced generation state'
pass 'revoked pinned primary cannot authorize a previously signed grant'
cp "$SAFE_RUN_CONFIG_DIR/config.json" "$tmp/config-before.json"
if pty_run "$SAFE_RUN" host-allow follow-signer add "$fingerprint" > "$tmp/output" 2>&1; then fail 'revoked signer admitted'; fi
grep -q 'revoked or expired' "$tmp/output" || fail 'dead-key admission refusal not legible'
cmp "$tmp/config-before.json" "$SAFE_RUN_CONFIG_DIR/config.json" || fail 'revoked signer admission changed config'
if pty_run "$SAFE_RUN" host-allow follow-signer add "$expiring_fingerprint" > "$tmp/output" 2>&1; then fail 'expired signer admitted'; fi
cmp "$tmp/config-before.json" "$SAFE_RUN_CONFIG_DIR/config.json" || fail 'expired signer admission changed config'
pass 'follow-signer add refuses revoked and expired primary keys at a real TTY'

# Independently exercise the verification-status belt, including expired
# signatures and adverse subkeys even when a primary itself is still usable.
SAFE_RUN_PATH="$SAFE_RUN" STATUS_FIXTURE_DIR="$tmp" SAFE_RUN_NO_INIT=1 bash -c '
  set -euo pipefail
  set -- version
  source "$SAFE_RUN_PATH" >/dev/null
  printf "[GNUPG:] VALIDSIG fixture\n" > "$STATUS_FIXTURE_DIR/status-fixture"
  if follow_signature_current "$STATUS_FIXTURE_DIR/status-fixture"; then exit 1; fi
  for adverse in REVKEYSIG EXPKEYSIG EXPSIG; do
    printf "[GNUPG:] GOODSIG fixture\n[GNUPG:] %s fixture\n[GNUPG:] VALIDSIG fixture\n" "$adverse" > "$STATUS_FIXTURE_DIR/status-fixture"
    if follow_signature_current "$STATUS_FIXTURE_DIR/status-fixture"; then exit 1; fi
  done
  for harmless in KEYEXPIRED KEYREVOKED; do
    printf "[GNUPG:] GOODSIG fixture\n[GNUPG:] %s fixture\n[GNUPG:] VALIDSIG fixture\n" "$harmless" > "$STATUS_FIXTURE_DIR/status-fixture"
    follow_signature_current "$STATUS_FIXTURE_DIR/status-fixture" || exit 1
  done
' safe-run || fail 'verification-status belt accepted adverse status or rejected good-only status'
pass 'verification status rejects adverse signature tokens but accepts key-level tokens with GOODSIG'
printf 'all host-allow signed export/follow tests passed\n'
