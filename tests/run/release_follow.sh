#!/usr/bin/env bash
# L7: signed safe release follower. Every repository, keyring and install root
# in this suite is disposable and lives below the shared isolation tree.
set -euo pipefail

# SAFE_TEST_ISOLATION_MARKER: every suite owns a scratch HOME and safe state.
# shellcheck disable=SC1091
# shellcheck source=tests/lib/test-isolation.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/test-isolation.sh"
safe_test_setup_isolation || exit 1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
pass() { printf 'ok - %s\n' "$*"; }
fail() { printf 'not ok - %s\n' "$*" >&2; exit 1; }
for tool in bash git gpg gpgconf jq flock timeout tar go; do
  command -v "$tool" >/dev/null 2>&1 || fail "missing required command: $tool"
done

tmp="$SAFE_TEST_ROOT/release-follow"
mkdir -p "$tmp"
export HOME="$tmp/home" GNUPGHOME="$tmp/gnupg"
export SAFE_CONFIG_DIR="$HOME/.config/safe" SAFE_DATA_DIR="$tmp/data"
export SAFE_BIN_DIR="$tmp/bin" SAFE_RUN_CONFIG_DIR="$SAFE_CONFIG_DIR/run"
export SAFE_RUN_DATA_DIR="$SAFE_DATA_DIR/run" SAFE_RUN_TRUST_OVERRIDE=0
mkdir -p "$HOME" "$GNUPGHOME" "$SAFE_CONFIG_DIR/run" "$SAFE_DATA_DIR" "$SAFE_BIN_DIR"
chmod 700 "$GNUPGHOME"

gpg --no-options --batch --pinentry-mode loopback --passphrase '' \
  --quick-generate-key 'L7 signer <l7@example.invalid>' ed25519 sign 0 \
  >/dev/null 2>&1 || fail 'signer key generation failed'
fingerprint=$(gpg --no-options --batch --with-colons --list-keys 2>/dev/null |
  awk -F: '$1 == "fpr" {print $10; exit}')
[[ "$fingerprint" =~ ^[A-F0-9]{40}$ ]] || fail 'signer fingerprint unavailable'
printf '{"follow":{"signers":["%s"]}}\n' "$fingerprint" > "$SAFE_RUN_CONFIG_DIR/config.json"

checkout="$tmp/checkout"
origin="$tmp/origin.git"
git clone --quiet --no-hardlinks "$ROOT" "$checkout"
cp "$ROOT/bin/safe" "$checkout/bin/safe"
cp "$ROOT/install.sh" "$checkout/install.sh"
git init --bare --quiet "$origin"
git -C "$checkout" remote set-url origin "$origin"
git -C "$checkout" config user.name 'L7 test'
git -C "$checkout" config user.email l7@example.invalid
git -C "$checkout" config commit.gpgSign false
git -C "$checkout" tag -d v1.64.0 v1.64.1 >/dev/null 2>&1 || true
git -C "$checkout" tag -s -u "$fingerprint" -m v1.64.1 v1.64.1
git -C "$checkout" push --quiet --set-upstream origin HEAD
git -C "$checkout" push --quiet origin refs/tags/v1.64.1
git --git-dir "$origin" symbolic-ref HEAD refs/heads/release-follow
git -C "$checkout" remote set-head origin -a >/dev/null 2>&1 || true

PATH=/usr/bin:/bin SAFE_BIN_DIR="$SAFE_BIN_DIR" SAFE_CONFIG_DIR="$SAFE_CONFIG_DIR" \
  SAFE_DATA_DIR="$SAFE_DATA_DIR" SAFE_RUN_CONFIG_DIR="$SAFE_RUN_CONFIG_DIR" \
  SAFE_RUN_DATA_DIR="$SAFE_RUN_DATA_DIR" bash "$checkout/install.sh" --run \
  >/dev/null 2>&1 || fail 'base fixture install failed'
driver="$SAFE_BIN_DIR/safe"
[[ "$(SAFE_CONFIG_DIR="$SAFE_CONFIG_DIR" SAFE_DATA_DIR="$SAFE_DATA_DIR" "$driver" --version 2>/dev/null | sed -n '1s/^safe //p')" == 1.64.1 ]] || fail 'base safe version not installed'

make_release() {
  local version="$1" mode="${2:-signed}" other_key="${3:-}"
  printf '%s\n' "$version" > "$checkout/VERSION"
  sed -i -E "s/^SAFE_VERSION=\"[0-9]+\.[0-9]+\.[0-9]+\"/SAFE_VERSION=\"$version\"/" "$checkout/bin/safe"
  git -C "$checkout" add VERSION bin/safe
  git -C "$checkout" commit --quiet -m "fixture $version"
  case "$mode" in
    signed)
      git -c gpg.format=openpgp -c gpg.program=/usr/bin/gpg -C "$checkout" tag -s -u "${other_key:-$fingerprint}" -m "$version" "v$version" ;;
    unsigned)
      git -C "$checkout" tag -a -m "$version" "v$version" ;;
    lightweight)
      git -C "$checkout" tag "v$version" ;;
    mismatch)
      git -c gpg.format=openpgp -c gpg.program=/usr/bin/gpg -C "$checkout" tag -s -u "$fingerprint" -m "v$version-real" "v$version-real"
      mismatch_oid=$(git -C "$checkout" rev-parse "v$version-real")
      git -C "$checkout" update-ref "refs/tags/v$version" "$mismatch_oid" ;;
    badsig)
      git -c gpg.format=openpgp -c gpg.program=/usr/bin/gpg -C "$checkout" tag -s -u "$fingerprint" -m "$version" "v$version"
      badsig_file="$tmp/badsig.$version"
      git -C "$checkout" cat-file tag "v$version" > "$badsig_file"
      sed -i "s/^$version$/tampered-$version/" "$badsig_file"
      badsig_oid=$(git -C "$checkout" mktag < "$badsig_file")
      git -C "$checkout" update-ref "refs/tags/v$version" "$badsig_oid" ;;
    *) fail "unknown fixture release mode: $mode" ;;
  esac
  git -C "$checkout" push --quiet origin HEAD "refs/tags/v$version" 2>/dev/null ||
    git -C "$checkout" push --quiet origin HEAD "refs/tags/v$version" --force
  git -C "$checkout" remote set-head origin -a >/dev/null 2>&1 || true
}

run_follow() {
  local output rc=0
  output=$(SAFE_CONFIG_DIR="$SAFE_CONFIG_DIR" SAFE_DATA_DIR="$SAFE_DATA_DIR" \
    SAFE_RUN_CONFIG_DIR="$SAFE_RUN_CONFIG_DIR" SAFE_RUN_DATA_DIR="$SAFE_RUN_DATA_DIR" \
    PATH="${FOLLOW_PATH:-$PATH}" "$driver" release follow "$@" 2>&1) || rc=$?
  printf '%s\n' "$output" > "$tmp/last-output"
  FOLLOW_OUTPUT="$output"
  FOLLOW_RC="$rc"
}

make_release 1.64.2
run_follow
[[ "$FOLLOW_RC" == 0 ]] || fail "happy path failed: $FOLLOW_OUTPUT"
grep -q 'installed v1.64.2 signer=' <<<"$FOLLOW_OUTPUT" || fail "happy path did not report signer: $FOLLOW_OUTPUT"
grep -q "RELEASE_FOLLOWED from=1.64.1 to=1.64.2 signer=$fingerprint tag_object=" "$SAFE_RUN_DATA_DIR/audit.log" || fail 'follow event missing'
[[ "$(SAFE_CONFIG_DIR="$SAFE_CONFIG_DIR" SAFE_DATA_DIR="$SAFE_DATA_DIR" "$SAFE_BIN_DIR/safe" --version 2>/dev/null | sed -n '1s/^safe //p')" == 1.64.2 ]] || fail 'happy path installed wrong version'
driver="$SAFE_BIN_DIR/safe"
pass 'signed descendant installs exact archive bytes and logs the primary fingerprint'

run_follow
[[ "$FOLLOW_RC" == 0 && "$FOLLOW_OUTPUT" == 'safe: release follow: nothing newer than 1.64.2' ]] || fail 'no-newer path was not a quiet success'
pass 'nothing newer is a zero exit with one line'

make_release 1.64.3 unsigned
before_record=$(sha256sum "$SAFE_CONFIG_DIR/release-follow.json")
before_audit=$(sha256sum "$SAFE_RUN_DATA_DIR/audit.log")
run_follow --dry-run
[[ "$FOLLOW_RC" == 1 ]] || fail 'unsigned candidate was not refused'
grep -q 'operator override:' <<<"$FOLLOW_OUTPUT" || fail 'unsigned refusal lacks manual path'
run_follow --dry-run
[[ "$FOLLOW_RC" == 1 ]] || fail 'dry-run unsigned candidate unexpectedly passed'
[[ "$(sha256sum "$SAFE_CONFIG_DIR/release-follow.json")" == "$before_record" ]] || fail 'dry-run changed the record'
[[ "$(sha256sum "$SAFE_RUN_DATA_DIR/audit.log")" == "$before_audit" ]] || fail 'dry-run changed the audit log'
pass 'unsigned candidate and dry-run write protections hold'
git -C "$checkout" tag -d v1.64.3 >/dev/null
git --git-dir "$origin" update-ref -d refs/tags/v1.64.3

make_release 1.64.4 lightweight
run_follow
[[ "$FOLLOW_RC" == 1 ]] || fail 'lightweight tag was not refused'
git -C "$checkout" tag -d v1.64.4 >/dev/null
git --git-dir "$origin" update-ref -d refs/tags/v1.64.4
make_release 1.64.5 mismatch
run_follow
[[ "$FOLLOW_RC" == 1 ]] || fail 'embedded tag-name mismatch was not refused'
git -C "$checkout" tag -d v1.64.5 v1.64.5-real >/dev/null
git --git-dir "$origin" update-ref -d refs/tags/v1.64.5
git --git-dir "$origin" update-ref -d refs/tags/v1.64.5-real
make_release 1.64.6 badsig
run_follow
[[ "$FOLLOW_RC" == 1 ]] || fail 'BADSIG tag was not refused'
git -C "$checkout" tag -d v1.64.6 >/dev/null
git --git-dir "$origin" update-ref -d refs/tags/v1.64.6
pass 'lightweight, mismatched-name and bad-signature tags are refused'

gpg --no-options --batch --pinentry-mode loopback --passphrase '' \
  --quick-generate-key 'wrong <wrong@example.invalid>' ed25519 sign 0 >/dev/null 2>&1
wrong_fingerprint=$(gpg --no-options --batch --with-colons --list-keys 'wrong@example.invalid' 2>/dev/null |
  awk -F: '$1 == "pub" {seen=1} seen && $1 == "fpr" {print $10; exit}')
make_release 1.64.7 signed "$wrong_fingerprint"
run_follow
[[ "$FOLLOW_RC" == 1 ]] || fail 'wrong-key tag was not refused'
git -C "$checkout" tag -d v1.64.7 >/dev/null
git --git-dir "$origin" update-ref -d refs/tags/v1.64.7
pass 'wrong-key tag is refused'

gpg --no-options --batch --pinentry-mode loopback --passphrase '' \
  --quick-generate-key 'expired <expired@example.invalid>' ed25519 sign 0 >/dev/null 2>&1
expired_fingerprint=$(gpg --no-options --batch --with-colons --list-keys 'expired@example.invalid' 2>/dev/null |
  awk -F: '$1 == "pub" {seen=1} seen && $1 == "fpr" {print $10; exit}')
make_release 1.64.8 signed "$expired_fingerprint"
gpg --no-options --batch --pinentry-mode loopback --passphrase '' \
  --quick-set-expire "$expired_fingerprint" seconds=1 >/dev/null 2>&1 || fail 'could not expire disposable test key'
sleep 2
run_follow
[[ "$FOLLOW_RC" == 1 ]] || fail 'expired-key tag was not refused'
git -C "$checkout" tag -d v1.64.8 >/dev/null
git --git-dir "$origin" update-ref -d refs/tags/v1.64.8

pass 'expired-key tags are refused'

gpg --no-options --batch --pinentry-mode loopback --passphrase '' \
  --quick-generate-key 'revoked <revoked@example.invalid>' ed25519 sign 0 >/dev/null 2>&1
revoked_fingerprint=$(gpg --no-options --batch --with-colons --list-keys 'revoked@example.invalid' 2>/dev/null |
  awk -F: '$1 == "fpr" {print $10; exit}')
make_release 1.64.9 signed "$revoked_fingerprint"
sed 's/^://' "$GNUPGHOME/openpgp-revocs.d/$revoked_fingerprint.rev" > "$tmp/revoke.asc"
gpg --no-options --batch --import "$tmp/revoke.asc" >/dev/null 2>&1 || fail 'could not revoke disposable test key'
run_follow
[[ "$FOLLOW_RC" == 1 ]] || fail 'revoked-key tag was not refused'
git -C "$checkout" tag -d v1.64.9 >/dev/null
git --git-dir "$origin" update-ref -d refs/tags/v1.64.9
pass 'revoked-key tags are refused'

make_release 1.64.0 signed
run_follow
[[ "$FOLLOW_RC" == 0 && "$FOLLOW_OUTPUT" == 'safe: release follow: nothing newer than 1.64.2' ]] || fail 'downgrade changed the installed release'
git -C "$checkout" tag -d v1.64.0 >/dev/null
git --git-dir "$origin" update-ref -d refs/tags/v1.64.0
pass 'older release tags cannot downgrade'

bad_repo="$tmp/bad-repo"
git clone --quiet --no-hardlinks "$checkout" "$bad_repo"
git -C "$bad_repo" remote set-url origin "$origin"
git -C "$bad_repo" checkout --quiet --orphan unrelated
git -C "$bad_repo" rm -rf --quiet .
printf '1.65.0\n' > "$bad_repo/VERSION"
git -C "$bad_repo" add VERSION
git -C "$bad_repo" commit --quiet -m unrelated
git -C "$bad_repo" tag -s -u "$fingerprint" -m v1.65.0 v1.65.0
git -C "$bad_repo" push --quiet origin refs/tags/v1.65.0
run_follow
[[ "$FOLLOW_RC" == 1 ]] || fail 'non-descendant candidate was not refused'
pass 'non-descendant candidate is refused'

git --git-dir "$origin" update-ref -d refs/tags/v1.65.0
git -C "$checkout" checkout --quiet -B release-follow v1.64.2
printf 'dirty\n' > "$checkout/DIRTY"
make_release 1.65.1 signed
run_follow --checkout "$checkout"
[[ "$FOLLOW_RC" == 0 ]] || fail "dirty checkout install failed: $FOLLOW_OUTPUT"
grep -q 'WARN checkout is dirty' <<<"$FOLLOW_OUTPUT" || fail 'dirty checkout warning missing'
[[ -f "$checkout/DIRTY" ]] || fail 'dirty checkout was modified'
pass 'dirty checkout installs the verified archive and warns on branch advancement'

make_release 1.65.2 signed
git -C "$checkout" config gpg.program "$tmp/hostile-gpg"
git -C "$checkout" config gpg.format ssh
git -C "$checkout" config tag.gpgSign true
printf '#!/usr/bin/env bash\nexit 99\n' > "$tmp/hostile-gpg"
chmod +x "$tmp/hostile-gpg"
run_follow
[[ "$FOLLOW_RC" == 0 ]] || fail "hostile git config bypassed or broke verification: $FOLLOW_OUTPUT"
pass 'hostile gpg.program, gpg.format and tag.gpgSign cannot bypass verification'

shadow="$tmp/shadow"
mkdir -p "$shadow"
printf '#!/usr/bin/env bash\nexit 99\n' > "$shadow/git"
printf '#!/usr/bin/env bash\nexit 99\n' > "$shadow/gpg"
chmod +x "$shadow/git" "$shadow/gpg"
make_release 1.65.3 signed
FOLLOW_PATH="$shadow:/usr/bin:/bin" run_follow
[[ "$FOLLOW_RC" == 0 ]] || fail "PATH-shadowed git/gpg affected follow: $FOLLOW_OUTPUT"
unset FOLLOW_PATH
pass 'PATH-shadowed git and gpg cannot affect follow'

make_release 1.65.4 signed
rm -f "$SAFE_RUN_CONFIG_DIR/config.json"
run_follow
[[ "$FOLLOW_RC" == 1 ]] || fail 'missing pinned signers were not refused'
grep -q 'follow-signer add <primary-fingerprint> at a TTY' <<<"$FOLLOW_OUTPUT" || fail 'missing-signer bootstrap hint missing'
printf '{"follow":{"signers":["%s"]}}\n' "$fingerprint" > "$SAFE_RUN_CONFIG_DIR/config.json"
pass 'no pinned signer refuses without ambient-key fallback'

make_release 1.65.5 signed
lockfile="$SAFE_RUN_DATA_DIR/release-follow.lock"
exec {lock_fd}>"$lockfile"
flock -x "$lock_fd"
run_follow
flock -u "$lock_fd"
exec {lock_fd}>&-
[[ "$FOLLOW_RC" == 1 ]] || fail 'lock contention was not refused'
grep -q 'another pass is running' <<<"$FOLLOW_OUTPUT" || fail 'lock contention message missing'
grep -q 'RELEASE_FOLLOW_REFUSED reason=another pass is running' "$SAFE_RUN_DATA_DIR/audit.log" || fail 'lock refusal was not audited'
pass 'release-follow passes are bounded to one writer'

rm -f "$SAFE_CONFIG_DIR/release-follow.json"
run_follow
[[ "$FOLLOW_RC" == 1 ]] || fail 'missing checkout record was not refused'
grep -q 'checkout record is missing' <<<"$FOLLOW_OUTPUT" || fail 'missing-record refusal missing'
pass 'missing checkout record has an operator recovery path'

printf 'release-follow: all cases passed\n'
