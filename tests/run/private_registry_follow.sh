#!/usr/bin/env bash
# Fleet propagation of private-registry trust through the signed channel the
# host-allow follow already uses. Keys, registries and clients are fixtures.
set -uo pipefail

# SAFE_TEST_ISOLATION_MARKER: every suite owns a scratch HOME and safe state.
# shellcheck source=tests/lib/test-isolation.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/test-isolation.sh"
safe_test_setup_isolation || exit 1
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUN="$ROOT/bin/safe-run"
AUDIT="$ROOT/bin/safe-audit"
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
safe_test_compose_exit_trap cleanup
export tmp

# shellcheck source=tests/lib/safe-core.sh
source "$ROOT/tests/lib/safe-core.sh"
if ! safe_core_test_prepare "$ROOT" "$tmp/safe-core"; then
  [[ "${SAFE_TEST_STRICT:-}" == "1" ]] && fail "safe-core could not be built under SAFE_TEST_STRICT=1"
  printf 'SKIP: safe-core unavailable\n'
  exit 0
fi

export HOME="$tmp/home" GNUPGHOME="$tmp/gnupg"
export SAFE_RUN_CONFIG_DIR="$HOME/.config/safe/run" SAFE_RUN_DATA_DIR="$tmp/data"
export SAFE_AUDIT_DATA_DIR="$tmp/audit" SAFE_RUN_TRUST_OVERRIDE=0 SAFE_RUN_NO_INIT=0
export SAFE_AUDIT_AUDIT_LOG="$tmp/audit/audit-log.jsonl" SAFE_AUDIT_BIN="$AUDIT"
mkdir -p "$GNUPGHOME" "$SAFE_RUN_CONFIG_DIR" "$tmp/bin"
chmod 700 "$GNUPGHOME"
export PATH="$tmp/bin:$PATH"
SYNC="$HOME/Sync/state/safe"
NPM_ORIGIN="https://git.example.test:8443/api/packages/owner/npm"
SRI_A="sha512-$(printf 'A%.0s' {1..86})=="
SRI_B="sha512-$(printf 'B%.0s' {1..86})=="
export NPM_ORIGIN SRI_A

set_host() { printf '#!/usr/bin/env bash\nprintf "%s\\n"\n' "$1" > "$tmp/bin/hostname"; chmod +x "$tmp/bin/hostname"; }
cat > "$tmp/bin/npm" <<'NPM'
#!/usr/bin/env bash
spec="$2"; version="${spec##*@}"
printf '{"version":"%s","dist":{"tarball":"%s/@p%%2fx/-/%s/x-%s.tgz","integrity":"%s"},"time":{}}\n' \
  "$version" "$NPM_ORIGIN" "$version" "$version" "${FAKE_SRI:-$SRI_A}"
NPM
chmod +x "$tmp/bin/npm"
printf '@p:registry=%s/\n' "$NPM_ORIGIN" > "$HOME/.npmrc"
pty_run() { python3 -c 'import pty,sys,os; sys.exit(os.waitstatus_to_exitcode(pty.spawn(sys.argv[1:])))' "$@"; }

keygen() {
  gpg --no-options --batch --pinentry-mode loopback --passphrase '' \
    --quick-generate-key "$1" ed25519 sign 0 > "$tmp/keygen.log" 2>&1 || { cat "$tmp/keygen.log" >&2; fail "key generation"; }
  gpg --no-options --batch --with-colons --list-keys "$1" 2>/dev/null | awk -F: '$1 == "fpr" {print $10; exit}'
}
fpr=$(keygen 'Safe fixture origin <origin@example.invalid>')
other=$(keygen 'Unrelated <other@example.invalid>')
config="$SAFE_RUN_CONFIG_DIR/config.json"
signers() { # signing key + pinned signers
  jq -n --arg k "$fpr" --args '{follow: {signing_key: $k, signers: $ARGS.positional}}' "$@" > "$config"
}
policy="$SAFE_RUN_CONFIG_DIR/private-registries.json"
pins="$SAFE_RUN_CONFIG_DIR/private-pins.json"
ledger="$SAFE_RUN_CONFIG_DIR/private-follow-state.json"
gate() { # spec -> rc
  local rc=0
  SAFE_AUDIT_RESULT_OUT="$tmp/result.json" "$AUDIT" package-audit "$1" --ecosystem npm --gate install > "$tmp/out" 2>&1 || rc=$?
  printf '%s' "$rc"
}

# --- origin: rainbow -----------------------------------------------------------
set_host rainbow
signers "$fpr"
mkdir -p "$SYNC"
printf '{"packages":{}}\n' > "$SAFE_RUN_CONFIG_DIR/host-allow.json"
pty_run "$RUN" host-allow export --sign > "$tmp/out" 2>&1 || fail "host-allow export: $(cat "$tmp/out")"
pty_run "$RUN" private-registry add p-npm --ecosystem npm --origin "$NPM_ORIGIN" --namespace '@p/*' --reason "my registry" > "$tmp/out" 2>&1 \
  || fail "origin add: $(cat "$tmp/out")"
statement="$SYNC/private-registries.rainbow.json"
[[ -s "$statement" && -s "$statement.asc" ]] || fail "an origin add did not publish the signed statement: $(cat "$tmp/out")"
gpg --no-options --batch --verify "$statement.asc" "$statement" > /dev/null 2>&1 || fail "statement signature"
jq -e '.schema == "safe-private-registries-export/1" and .host == "rainbow" and (.registries["p-npm"].namespace == ["@p/*"])' "$statement" >/dev/null \
  || fail "statement shape: $(cat "$statement")"
rc=0; "$RUN" private-registry export --sign > "$tmp/out" 2>&1 </dev/null || rc=$?
[[ "$rc" == 102 ]] || fail "signed export without a terminal: rc=$rc"
pty_run "$RUN" private-registry pin add @p/x@1.0.0 --ecosystem npm > "$tmp/out" 2>&1 || fail "origin pin add: $(cat "$tmp/out")"
jq -e --arg s "$SRI_A" '.pins | to_entries | length == 1 and .[0].value.integrity.sri == $s' "$statement" >/dev/null || fail "pin not republished"
! grep -q '_authToken\|password\|token' "$statement" || fail "statement carries credential-shaped fields"
pass "an origin publishes its private-registry statement with every TTY change; export --sign needs a terminal"
cp "$statement" "$tmp/statement-gen1.json"; cp "$statement.asc" "$tmp/statement-gen1.json.asc"

# --- follower: agent-dev ---------------------------------------------------------
set_host agent-dev
mv "$SAFE_RUN_CONFIG_DIR" "$tmp/origin-config"
mkdir -p "$SAFE_RUN_CONFIG_DIR"
signers "$fpr"
"$RUN" host-allow follow --dry-run > "$tmp/out" 2>&1 || fail "dry run: $(cat "$tmp/out")"
grep -q 'would follow private registries from rainbow' "$tmp/out" || fail "dry run did not report: $(cat "$tmp/out")"
[[ ! -e "$ledger" ]] || fail "dry run wrote the ledger"
"$RUN" host-allow follow > "$tmp/out" 2>&1 || fail "follow: $(cat "$tmp/out")"
jq -e '.origins.rainbow.registries["p-npm"] and (.origins.rainbow.pins | length == 1)' "$ledger" >/dev/null || fail "ledger: $(cat "$ledger" 2>/dev/null)"
[[ ! -e "$policy" && ! -e "$pins" ]] || fail "follow wrote into the local stores"
r=$(gate @p/x@1.0.0)
[[ "$r" == 18 ]] && jq -e '.private_registry.pin == "matched:operator:followed:rainbow"' "$tmp/result.json" >/dev/null \
  || fail "followed gate: rc=$r $(cat "$tmp/out")"
r=$(FAKE_SRI="$SRI_B" gate @p/x@1.0.0)
[[ "$r" == 20 ]] || fail "followed pin vs other bytes: $r"
"$RUN" host-allow follow > "$tmp/out" 2>&1 || fail "second follow"
grep -q 'already at the current generation' "$tmp/out" || fail "equal generation not a no-op: $(cat "$tmp/out")"
pass "a follower takes the statement through host-allow follow into its ledger only; the followed pin decides (18 / 20)"

# signer removal withdraws at once, without a follow
signers
r=$(gate @p/x@1.0.0)
[[ "$r" != 18 ]] && ! grep -q 'ALLOWED_VIA_PRIVATE_REGISTRY' "$tmp/out" || fail "an unpinned signer's statement still trusted"
signers "$fpr"
pass "removing the signer withdraws its private registries at the next gate decision"

# tampered, wrong-key and mismatched pairs are skipped; ledger unchanged
cp "$ledger" "$tmp/ledger.before"
jq '.registries["p-npm"].origin = "https://evil.example.test/npm"' "$statement" > "$tmp/t.json" && cp "$tmp/t.json" "$statement"
rc=0; "$RUN" host-allow follow > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" == 1 ]] && grep -q 'skipped' "$tmp/out" && cmp -s "$ledger" "$tmp/ledger.before" || fail "tampered statement: rc=$rc"
gpg --no-options --batch --yes --local-user "$other" --armor --detach-sign --output "$statement.asc" "$statement" 2>/dev/null
rc=0; "$RUN" host-allow follow > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" == 1 ]] && cmp -s "$ledger" "$tmp/ledger.before" || fail "wrong key: rc=$rc"
rm -f "$statement.asc"
rc=0; "$RUN" host-allow follow > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" == 1 ]] && cmp -s "$ledger" "$tmp/ledger.before" || fail "unsigned statement: rc=$rc"
# equal generation, different bytes, validly signed: a collision changes nothing
jq '.registries["p-npm"].reason = "replayed"' "$tmp/statement-gen1.json" > "$statement"
gpg --no-options --batch --yes --local-user "$fpr" --armor --detach-sign --output "$statement.asc" "$statement" 2>/dev/null
rc=0; "$RUN" host-allow follow > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" == 1 ]] && grep -q 'collision' "$tmp/out" && cmp -s "$ledger" "$tmp/ledger.before" || fail "collision: rc=$rc $(cat "$tmp/out")"
pass "tampered, foreign-signed, unsigned and same-generation-collision statements are refused (exit 1) and change nothing"

# a newer generation replaces: removal at the origin propagates
set_host rainbow
mv "$SAFE_RUN_CONFIG_DIR" "$tmp/follower-config"; mv "$tmp/origin-config" "$SAFE_RUN_CONFIG_DIR"
cp "$tmp/statement-gen1.json" "$statement"; cp "$tmp/statement-gen1.json.asc" "$statement.asc"
sleep 1
printf '@p/x@1.0.0\n' | pty_run "$RUN" private-registry pin revoke @p/x@1.0.0 --ecosystem npm > "$tmp/out" 2>&1 || fail "origin revoke: $(cat "$tmp/out")"
cp "$statement" "$tmp/statement-gen2.json"; cp "$statement.asc" "$tmp/statement-gen2.json.asc"
set_host agent-dev
mv "$SAFE_RUN_CONFIG_DIR" "$tmp/origin-config"; mv "$tmp/follower-config" "$SAFE_RUN_CONFIG_DIR"
"$RUN" host-allow follow > "$tmp/out" 2>&1 || fail "follow gen2: $(cat "$tmp/out")"
r=$(gate @p/x@1.0.0)
[[ "$r" == 20 ]] && jq -e '.private_registry.decision == "private_pin_revoked"' "$tmp/result.json" >/dev/null || fail "revocation did not propagate: rc=$r"
pass "a revocation at the origin propagates to followers (20)"

cp "$tmp/statement-gen1.json" "$statement"; cp "$tmp/statement-gen1.json.asc" "$statement.asc"
rc=0; "$RUN" host-allow follow > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" == 1 ]] && grep -q 'older statement' "$tmp/out" || fail "older generation replay: rc=$rc $(cat "$tmp/out")"
pass "replaying an older signed statement is refused"

set_host rainbow
mv "$SAFE_RUN_CONFIG_DIR" "$tmp/follower-config"; mv "$tmp/origin-config" "$SAFE_RUN_CONFIG_DIR"
cp "$tmp/statement-gen2.json" "$statement"; cp "$tmp/statement-gen2.json.asc" "$statement.asc"
sleep 1
pty_run "$RUN" private-registry remove p-npm > "$tmp/out" 2>&1 || fail "origin remove"
set_host agent-dev
mv "$SAFE_RUN_CONFIG_DIR" "$tmp/origin-config"; mv "$tmp/follower-config" "$SAFE_RUN_CONFIG_DIR"
"$RUN" host-allow follow > "$tmp/out" 2>&1 || fail "follow gen3: $(cat "$tmp/out")"
rc=0; "$AUDIT" private-fetch @p/x@1.0.0 --ecosystem npm > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" == 3 ]] || fail "registry removed at the origin still private on the follower: rc=$rc"
pass "a registry removed at the origin is withdrawn from followers by the newer statement"

# a local registry for the same namespace on another origin conflicts
cp "$tmp/statement-gen2.json" "$tmp/s2.json"
"$tmp/safe-core" private-trust forget-origin --follow-state "$ledger" --host rainbow || fail "forget-origin"
jq -n --arg o "$NPM_ORIGIN" '{schema: "safe-private-registries/1", registries: {"local": {ecosystem: "npm", origin: "https://other.example.test/npm", namespace: ["@p/*"], pin_mode: "tofu", cooldown_days: 0}}}' > "$policy"
cp "$tmp/statement-gen2.json" "$statement"; cp "$tmp/statement-gen2.json.asc" "$statement.asc"
"$RUN" host-allow follow > /dev/null 2>&1 || fail "re-follow gen2"
r=$(gate @p/x@1.0.0)
[[ "$r" == 19 ]] && jq -e '.private_registry.decision == "private_registry_conflict"' "$tmp/result.json" >/dev/null || fail "conflict: rc=$r"
rc=0; "$RUN" private-registry list > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" == 1 ]] && grep -q 'CONFLICT' "$tmp/out" || fail "list did not name the conflict"
pass "a namespace claimed by two origins fails closed (19) and is named by list"

rc=0; "$RUN" private-registry forget-origin rainbow > "$tmp/out" 2>&1 </dev/null || rc=$?
[[ "$rc" == 102 ]] || fail "forget-origin without a terminal: rc=$rc"
pass "forget-origin needs an operator terminal"

printf 'all private-registry follow tests passed\n'
