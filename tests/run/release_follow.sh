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
LEGACY_DRIVER="$ROOT/tests/fixtures/release_follow_pre_fix.sh"
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
# The clone carries the repository's real tags; the fixture must not collide
# with them, so strip every tag before building the ladder.
git -C "$checkout" tag -l | xargs -r git -C "$checkout" tag -d
# The fixture ladder derives from the checkout's own VERSION so landing a real
# release never hard-breaks the suite: the base release is whatever the tree
# ships, every candidate is a successive patch bump of it, and RV[0] is a
# guaranteed-older downgrade probe.
base_version="$(tr -d '[:space:]' < "$checkout/VERSION")"
declare -a RV
RV[0]="$(printf '%d.99.99' "$(( ${base_version%%.*} - 1 ))")"
for __i in $(seq 1 18); do
  RV[$__i]="$(printf '%s.%d' "${base_version%.*}" "$(( ${base_version##*.} + __i ))")"
done
git -C "$checkout" tag -s -u "$fingerprint" -m "$base_version" "v$base_version"
git -C "$checkout" push --quiet --set-upstream origin HEAD
git -C "$checkout" push --quiet origin "refs/tags/v$base_version"
git --git-dir "$origin" symbolic-ref HEAD refs/heads/release-follow
git -C "$checkout" remote set-head origin -a >/dev/null 2>&1 || true

PATH=/usr/bin:/bin SAFE_BIN_DIR="$SAFE_BIN_DIR" SAFE_CONFIG_DIR="$SAFE_CONFIG_DIR" \
  SAFE_DATA_DIR="$SAFE_DATA_DIR" SAFE_RUN_CONFIG_DIR="$SAFE_RUN_CONFIG_DIR" \
  SAFE_RUN_DATA_DIR="$SAFE_RUN_DATA_DIR" bash "$checkout/install.sh" --run \
  >/dev/null 2>&1 || fail 'base fixture install failed'
driver="$SAFE_BIN_DIR/safe"
[[ "$(SAFE_CONFIG_DIR="$SAFE_CONFIG_DIR" SAFE_DATA_DIR="$SAFE_DATA_DIR" "$driver" --version 2>/dev/null | sed -n '1s/^safe //p')" == "$base_version" ]] || fail 'base safe version not installed'
status_file="$SAFE_CONFIG_DIR/release-follow-status.json"

mkdir -p "$HOME/.config/go"
printf 'GOTOOLCHAIN=go1.99.0\n' > "$HOME/.config/go/env"
mkdir -p "$TMPDIR/go-work-module"
printf 'module example.invalid/release-follow-work\n\ngo 1.26.0\n' > "$TMPDIR/go-work-module/go.mod"
printf 'go 1.26.0\n\nuse ./go-work-module\n' > "$TMPDIR/go.work"

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

plant_replace_commit() {
  local repo="$1" candidate="$2" parent="$3" marker="$4" version="$5"
  local version_oid install_oid evil_tree evil_commit
  printf '%s\n' "$version" | git -C "$repo" hash-object -w --stdin > "$tmp/version-blob"
  version_oid=$(cat "$tmp/version-blob")
  cat > "$tmp/evil-install" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'evil replacement\\n' > '$marker'
cat > "\$SAFE_BIN_DIR/safe" <<'SAFE'
#!/usr/bin/env bash
printf 'safe $version\\n'
SAFE
chmod +x "\$SAFE_BIN_DIR/safe"
EOF
  install_oid=$(git -C "$repo" hash-object -w "$tmp/evil-install")
  evil_tree=$(printf '100644 blob %s\tVERSION\n100755 blob %s\tinstall.sh\n' "$version_oid" "$install_oid" |
    git -C "$repo" mktree)
  evil_commit=$(git -C "$repo" commit-tree "$evil_tree" -p "$parent" -m 'evil replacement')
  git -C "$repo" update-ref "refs/replace/$candidate" "$evil_commit"
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

make_release ${RV[1]}
run_follow
[[ "$FOLLOW_RC" == 0 ]] || fail "happy path failed: $FOLLOW_OUTPUT"
grep -q "installed v${RV[1]} signer=" <<<"$FOLLOW_OUTPUT" || fail "happy path did not report signer: $FOLLOW_OUTPUT"
grep -q "RELEASE_FOLLOWED from=$base_version to=${RV[1]} signer=$fingerprint tag_object=" "$SAFE_RUN_DATA_DIR/audit.log" || fail 'follow event missing'
[[ "$(SAFE_CONFIG_DIR="$SAFE_CONFIG_DIR" SAFE_DATA_DIR="$SAFE_DATA_DIR" "$SAFE_BIN_DIR/safe" --version 2>/dev/null | sed -n '1s/^safe //p')" == ${RV[1]} ]] || fail 'happy path installed wrong version'
[[ -f "$status_file" && ! -L "$status_file" ]] || fail 'last-pass status file is not a regular file'
jq -e ".installed_before == \"$base_version\" and .candidate == \"v${RV[1]}\" and .verdict == \"installed\" and (.time | strings)" "$status_file" >/dev/null ||
  fail 'installed last-pass status is malformed'
status_output=$(SAFE_CONFIG_DIR="$SAFE_CONFIG_DIR" SAFE_DATA_DIR="$SAFE_DATA_DIR" "$driver" status 2>/dev/null)
grep -q '^release follow: installed ' <<<"$status_output" || fail 'status did not print the installed release-follow line'
driver="$SAFE_BIN_DIR/safe"
pass 'signed descendant installs exact archive bytes, ignores hostile Go configuration and parent go.work, and logs the primary fingerprint'

run_follow
[[ "$FOLLOW_RC" == 0 && "$FOLLOW_OUTPUT" == "safe: release follow: nothing newer than ${RV[1]}" ]] || fail 'no-newer path was not a quiet success'
jq -e '.candidate == null and .verdict == "nothing-newer"' "$status_file" >/dev/null || fail 'nothing-newer status was not recorded'
rm -f -- "$status_file"
run_follow --dry-run
[[ "$FOLLOW_RC" == 0 && "$FOLLOW_OUTPUT" == "safe: release follow: nothing newer than ${RV[1]}" ]] || fail 'dry-run nothing-newer path was not a quiet success'
[[ ! -e "$status_file" ]] || fail 'dry-run nothing-newer wrote last-pass status'
pass 'nothing newer is a zero exit with one line'

make_release ${RV[2]} unsigned
before_record=$(sha256sum "$SAFE_CONFIG_DIR/release-follow.json")
before_audit=$(sha256sum "$SAFE_RUN_DATA_DIR/audit.log")
rm -f -- "$status_file"
run_follow --dry-run
[[ "$FOLLOW_RC" == 1 ]] || fail 'unsigned candidate was not refused'
grep -q 'operator override:' <<<"$FOLLOW_OUTPUT" || fail 'unsigned refusal lacks manual path'
run_follow --dry-run
[[ "$FOLLOW_RC" == 1 ]] || fail 'dry-run unsigned candidate unexpectedly passed'
[[ "$(sha256sum "$SAFE_CONFIG_DIR/release-follow.json")" == "$before_record" ]] || fail 'dry-run changed the record'
[[ "$(sha256sum "$SAFE_RUN_DATA_DIR/audit.log")" == "$before_audit" ]] || fail 'dry-run changed the audit log'
[[ ! -e "$status_file" ]] || fail 'dry-run unsigned candidate wrote last-pass status'
pass 'unsigned candidate and dry-run write protections hold'
git -C "$checkout" tag -d v${RV[2]} >/dev/null
git --git-dir "$origin" update-ref -d refs/tags/v${RV[2]}

make_release ${RV[3]} lightweight
run_follow
[[ "$FOLLOW_RC" == 1 ]] || fail 'lightweight tag was not refused'
git -C "$checkout" tag -d v${RV[3]} >/dev/null
git --git-dir "$origin" update-ref -d refs/tags/v${RV[3]}
make_release ${RV[4]} mismatch
run_follow
[[ "$FOLLOW_RC" == 1 ]] || fail 'embedded tag-name mismatch was not refused'
git -C "$checkout" tag -d v${RV[4]} v${RV[4]}-real >/dev/null
git --git-dir "$origin" update-ref -d refs/tags/v${RV[4]}
git --git-dir "$origin" update-ref -d refs/tags/v${RV[4]}-real
make_release ${RV[5]} badsig
run_follow
[[ "$FOLLOW_RC" == 1 ]] || fail 'BADSIG tag was not refused'
git -C "$checkout" tag -d v${RV[5]} >/dev/null
git --git-dir "$origin" update-ref -d refs/tags/v${RV[5]}
jq -e ".verdict == \"refused\" and .candidate == \"v${RV[5]}\"" "$status_file" >/dev/null || fail 'refusal last-pass status was not recorded'
doctor_json=$(SAFE_CONFIG_DIR="$SAFE_CONFIG_DIR" SAFE_DATA_DIR="$SAFE_DATA_DIR" \
  SAFE_RUN_CONFIG_DIR="$SAFE_RUN_CONFIG_DIR" SAFE_RUN_DATA_DIR="$SAFE_RUN_DATA_DIR" "$driver" doctor --json 2>/dev/null) ||
  fail 'doctor JSON failed while checking release-follow refusal'
jq -e '.environment.release_follow.warning | strings | contains("refused")' <<<"$doctor_json" >/dev/null ||
  fail 'doctor did not warn on a release-follow refusal'
stale_time=$(date -u -d '4 days ago' +%Y-%m-%dT%H:%M:%SZ)
jq --arg time "$stale_time" '.time = $time | .verdict = "nothing-newer"' "$status_file" > "$tmp/stale-status"
mv -f "$tmp/stale-status" "$status_file"
doctor_json=$(SAFE_CONFIG_DIR="$SAFE_CONFIG_DIR" SAFE_DATA_DIR="$SAFE_DATA_DIR" \
  SAFE_RUN_CONFIG_DIR="$SAFE_RUN_CONFIG_DIR" SAFE_RUN_DATA_DIR="$SAFE_RUN_DATA_DIR" "$driver" doctor --json 2>/dev/null) ||
  fail 'doctor JSON failed while checking release-follow staleness'
jq -e '.environment.release_follow.warning | strings | contains("stale")' <<<"$doctor_json" >/dev/null ||
  fail 'doctor did not warn on stale release-follow state'
pass 'lightweight, mismatched-name and bad-signature tags are refused'

gpg --no-options --batch --pinentry-mode loopback --passphrase '' \
  --quick-generate-key 'wrong <wrong@example.invalid>' ed25519 sign 0 >/dev/null 2>&1
wrong_fingerprint=$(gpg --no-options --batch --with-colons --list-keys 'wrong@example.invalid' 2>/dev/null |
  awk -F: '$1 == "pub" {seen=1} seen && $1 == "fpr" {print $10; exit}')
make_release ${RV[6]} signed "$wrong_fingerprint"
run_follow
[[ "$FOLLOW_RC" == 1 ]] || fail 'wrong-key tag was not refused'
git -C "$checkout" tag -d v${RV[6]} >/dev/null
git --git-dir "$origin" update-ref -d refs/tags/v${RV[6]}
pass 'wrong-key tag is refused'

gpg --no-options --batch --pinentry-mode loopback --passphrase '' \
  --quick-generate-key 'expired <expired@example.invalid>' ed25519 sign 0 >/dev/null 2>&1
expired_fingerprint=$(gpg --no-options --batch --with-colons --list-keys 'expired@example.invalid' 2>/dev/null |
  awk -F: '$1 == "pub" {seen=1} seen && $1 == "fpr" {print $10; exit}')
make_release ${RV[7]} signed "$expired_fingerprint"
gpg --no-options --batch --pinentry-mode loopback --passphrase '' \
  --quick-set-expire "$expired_fingerprint" seconds=1 >/dev/null 2>&1 || fail 'could not expire disposable test key'
sleep 2
run_follow
[[ "$FOLLOW_RC" == 1 ]] || fail 'expired-key tag was not refused'
git -C "$checkout" tag -d v${RV[7]} >/dev/null
git --git-dir "$origin" update-ref -d refs/tags/v${RV[7]}

pass 'expired-key tags are refused'

gpg --no-options --batch --pinentry-mode loopback --passphrase '' \
  --quick-generate-key 'revoked <revoked@example.invalid>' ed25519 sign 0 >/dev/null 2>&1
revoked_fingerprint=$(gpg --no-options --batch --with-colons --list-keys 'revoked@example.invalid' 2>/dev/null |
  awk -F: '$1 == "fpr" {print $10; exit}')
make_release ${RV[8]} signed "$revoked_fingerprint"
sed 's/^://' "$GNUPGHOME/openpgp-revocs.d/$revoked_fingerprint.rev" > "$tmp/revoke.asc"
gpg --no-options --batch --import "$tmp/revoke.asc" >/dev/null 2>&1 || fail 'could not revoke disposable test key'
run_follow
[[ "$FOLLOW_RC" == 1 ]] || fail 'revoked-key tag was not refused'
git -C "$checkout" tag -d v${RV[8]} >/dev/null
git --git-dir "$origin" update-ref -d refs/tags/v${RV[8]}
pass 'revoked-key tags are refused'

make_release ${RV[0]} signed
run_follow
[[ "$FOLLOW_RC" == 0 && "$FOLLOW_OUTPUT" == "safe: release follow: nothing newer than ${RV[1]}" ]] || fail 'downgrade changed the installed release'
git -C "$checkout" tag -d v${RV[0]} >/dev/null
git --git-dir "$origin" update-ref -d refs/tags/v${RV[0]}
pass 'older release tags cannot downgrade'

bad_repo="$tmp/bad-repo"
git clone --quiet --no-hardlinks "$checkout" "$bad_repo"
git -C "$bad_repo" remote set-url origin "$origin"
git -C "$bad_repo" checkout --quiet --orphan unrelated
git -C "$bad_repo" rm -rf --quiet .
printf "${RV[9]}\n" > "$bad_repo/VERSION"
git -C "$bad_repo" add VERSION
git -C "$bad_repo" commit --quiet -m unrelated
git -C "$bad_repo" tag -s -u "$fingerprint" -m v${RV[9]} v${RV[9]}
git -C "$bad_repo" push --quiet origin refs/tags/v${RV[9]}
run_follow
[[ "$FOLLOW_RC" == 1 ]] || fail 'non-descendant candidate was not refused'
pass 'non-descendant candidate is refused'

git --git-dir "$origin" update-ref -d refs/tags/v${RV[9]}
git -C "$checkout" checkout --quiet -B release-follow v${RV[1]}
printf 'dirty\n' > "$checkout/DIRTY"
make_release ${RV[10]} signed
run_follow --checkout "$checkout"
[[ "$FOLLOW_RC" == 0 ]] || fail "dirty checkout install failed: $FOLLOW_OUTPUT"
grep -q 'WARN checkout is dirty' <<<"$FOLLOW_OUTPUT" || fail 'dirty checkout warning missing'
[[ -f "$checkout/DIRTY" ]] || fail 'dirty checkout was modified'
pass 'dirty checkout installs the verified archive and warns on branch advancement'

make_release ${RV[11]} signed
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
make_release ${RV[12]} signed
FOLLOW_PATH="$shadow:/usr/bin:/bin" run_follow
[[ "$FOLLOW_RC" == 0 ]] || fail "PATH-shadowed git/gpg affected follow: $FOLLOW_OUTPUT"
unset FOLLOW_PATH
pass 'PATH-shadowed git and gpg cannot affect follow'

make_release ${RV[13]} signed
rm -f "$SAFE_RUN_CONFIG_DIR/config.json"
run_follow
[[ "$FOLLOW_RC" == 1 ]] || fail 'missing pinned signers were not refused'
grep -q 'follow-signer add <primary-fingerprint> at a TTY' <<<"$FOLLOW_OUTPUT" || fail 'missing-signer bootstrap hint missing'
printf '{"follow":{"signers":["%s"]}}\n' "$fingerprint" > "$SAFE_RUN_CONFIG_DIR/config.json"
pass 'no pinned signer refuses without ambient-key fallback'

make_release ${RV[14]} signed
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

replace_candidate=$(git -C "$checkout" rev-parse "refs/tags/v${RV[14]}^{commit}")
replace_parent=$(git -C "$checkout" rev-parse "refs/tags/v${RV[12]}^{commit}")
replace_marker="$tmp/current-replace-marker"
plant_replace_commit "$checkout" "$replace_candidate" "$replace_parent" "$replace_marker" ${RV[14]}
run_follow
[[ "$FOLLOW_RC" == 0 ]] || fail "replace-ref candidate was not safely handled: $FOLLOW_OUTPUT"
[[ ! -e "$replace_marker" ]] || fail 'replace-ref archive installed the evil marker'
grep -q "RELEASE_FOLLOWED from=${RV[12]} to=${RV[14]} signer=" "$SAFE_RUN_DATA_DIR/audit.log" || fail 'replace-ref safe follow event missing'
git -C "$checkout" update-ref -d "refs/replace/$replace_candidate"
pass 'replace-ref candidate installs genuine bytes and never attributes evil bytes'

[[ -f "$LEGACY_DRIVER" && ! -x "$LEGACY_DRIVER" ]] || fail 'pre-fix replacement-ref fixture is missing or executable'
legacy_repo="$tmp/legacy-repo"
legacy_origin="$tmp/legacy-origin.git"
git init --quiet "$legacy_repo"
git init --bare --quiet "$legacy_origin"
git -C "$legacy_repo" config user.name 'legacy fixture'
git -C "$legacy_repo" config user.email legacy@example.invalid
printf '1.64.1\n' > "$legacy_repo/VERSION"
printf '#!/usr/bin/env bash\nexit 0\n' > "$legacy_repo/install.sh"
chmod +x "$legacy_repo/install.sh"
git -C "$legacy_repo" add VERSION install.sh
git -C "$legacy_repo" commit --quiet -m base
legacy_parent=$(git -C "$legacy_repo" rev-parse HEAD)
git -c gpg.format=openpgp -c gpg.program=/usr/bin/gpg -C "$legacy_repo" tag -s -u "$fingerprint" -m v1.64.1 v1.64.1
git -C "$legacy_repo" remote add origin "$legacy_origin"
git -C "$legacy_repo" push --quiet origin HEAD refs/tags/v1.64.1
printf '1.64.2\n' > "$legacy_repo/VERSION"
cat > "$legacy_repo/install.sh" <<'LEGACY_INSTALL'
#!/usr/bin/env bash
set -euo pipefail
cat > "$SAFE_BIN_DIR/safe" <<'SAFE'
#!/usr/bin/env bash
printf 'safe 1.64.2\n'
SAFE
chmod +x "$SAFE_BIN_DIR/safe"
LEGACY_INSTALL
chmod +x "$legacy_repo/install.sh"
git -C "$legacy_repo" add VERSION install.sh
git -C "$legacy_repo" commit --quiet -m candidate
git -c gpg.format=openpgp -c gpg.program=/usr/bin/gpg -C "$legacy_repo" tag -s -u "$fingerprint" -m v1.64.2 v1.64.2
git -C "$legacy_repo" push --quiet origin HEAD refs/tags/v1.64.2
legacy_candidate=$(git -C "$legacy_repo" rev-parse 'refs/tags/v1.64.2^{commit}')
legacy_marker="$tmp/legacy-replace-marker"
plant_replace_commit "$legacy_repo" "$legacy_candidate" "$legacy_parent" "$legacy_marker" 1.64.2
legacy_data="$tmp/legacy-data"
legacy_bin="$tmp/legacy-bin"
legacy_config="$tmp/legacy-config"
legacy_home="$tmp/legacy-home"
mkdir -p "$legacy_home"
mkdir -p "$legacy_config" "$legacy_data/run" "$legacy_bin"
set +e
legacy_output=$(env -i HOME="$legacy_home" GNUPGHOME="$GNUPGHOME" PATH=/usr/bin:/bin \
  SAFE_CONFIG_DIR="$legacy_config" SAFE_BIN_DIR="$legacy_bin" SAFE_DATA_DIR="$legacy_data" \
  SAFE_RELEASE_FOLLOW_CHECKOUT="$legacy_repo" SAFE_RELEASE_FOLLOW_TAG=v1.64.2 \
  SAFE_RELEASE_FOLLOW_PRE_FIX_FIXTURE=1 \
  bash "$LEGACY_DRIVER" 2>&1)
legacy_rc=$?
set -e
printf '%s\n' "$legacy_output" > "$tmp/legacy-output"
[[ "$legacy_rc" == 0 ]] || fail "pre-fix fixture did not reproduce the replace-ref vulnerability (rc=$legacy_rc)"
[[ -e "$legacy_marker" ]] || fail 'pre-fix fixture did not install the evil replacement marker'
pass 'replace-ref regression is non-vacuous: the checked-in pre-fix fixture fails it'

make_release ${RV[15]} signed
touch "$checkout/.git/info/grafts"
run_follow
[[ "$FOLLOW_RC" == 1 ]] || fail 'graft checkout was not refused'
grep -q 'checkout uses grafts' <<<"$FOLLOW_OUTPUT" || fail 'graft refusal message missing'
rm -f "$checkout/.git/info/grafts"
touch "$checkout/.git/shallow"
run_follow
[[ "$FOLLOW_RC" == 1 ]] || fail 'shallow checkout was not refused'
grep -q 'checkout is shallow' <<<"$FOLLOW_OUTPUT" || fail 'shallow refusal message missing'
rm -f "$checkout/.git/shallow"
pass 'grafts and shallow ancestry metadata are refused'

candidate_1656_tag=$(git -C "$checkout" rev-parse refs/tags/v${RV[15]})
candidate_1655_commit=$(git -C "$checkout" rev-parse "refs/tags/v${RV[14]}^{commit}")
git -C "$checkout" update-ref refs/tags/v${RV[15]} "$candidate_1655_commit"
run_follow
[[ "$FOLLOW_RC" == 1 ]] || fail 'rejected local tag update was not refused'
grep -q "v${RV[15]}" <<<"$FOLLOW_OUTPUT" || fail 'rejected tag name missing'
grep -q 'repair with' <<<"$FOLLOW_OUTPUT" || fail 'rejected tag repair missing'
git -C "$checkout" update-ref refs/tags/v${RV[15]} "$candidate_1656_tag"
hostile_ssh="$tmp/hostile-ssh"
upload_pack_path="$(git --exec-path)/git-upload-pack"
cat > "$hostile_ssh" <<EOF
#!/usr/bin/env bash
printf 'remote: [rejected] ;evil\$IFS\n' >&2
exec $upload_pack_path '$origin'
EOF
chmod +x "$hostile_ssh"
git -C "$checkout" config remote.origin.url ssh://git@local/tmp/origin.git
git -C "$checkout" config core.sshCommand "$hostile_ssh"
git -C "$checkout" update-ref refs/tags/v${RV[15]} "$candidate_1655_commit"
run_follow
[[ "$FOLLOW_RC" == 1 ]] || fail 'hostile remote rejection was not refused'
[[ "$FOLLOW_OUTPUT" != *evil* ]] || fail 'hostile remote text entered the repair command'
grep -q "origin tag update rejected for v${RV[15]}" <<<"$FOLLOW_OUTPUT" || fail 'anchored rejected-tag parse missed the ref-status tag'
git -C "$checkout" update-ref refs/tags/v${RV[15]} "$candidate_1656_tag"
git -C "$checkout" config --unset core.sshCommand
git -C "$checkout" remote set-url origin "$origin"
git -C "$checkout" remote set-url origin "$tmp/missing-origin.git"
run_follow
[[ "$FOLLOW_RC" == 1 ]] || fail 'transport failure was not refused'
grep -q 'transport failure fetching origin' <<<"$FOLLOW_OUTPUT" || fail 'transport failure message missing'
grep -q 'missing-origin.git' <<<"$FOLLOW_OUTPUT" || fail 'origin URL missing from transport failure'
grep -q 'origin must be fetchable with no agent and no credentials' <<<"$FOLLOW_OUTPUT" || fail 'anonymous-origin requirement missing'
git -C "$checkout" remote set-url origin "$origin"
pass 'fetch rejection parsing ignores hostile remote text and keeps transport repairs distinct'

make_release ${RV[16]} signed
printf 'install.sh export-ignore\n' > "$checkout/.git/info/attributes"
run_follow
[[ "$FOLLOW_RC" == 1 ]] || fail 'checkout info attributes were not refused'
grep -q 'verified archive tree differs' <<<"$FOLLOW_OUTPUT" || fail 'checkout info attribute tree refusal missing'
rm -f "$checkout/.git/info/attributes"
run_follow
[[ "$FOLLOW_RC" == 0 ]] || fail "genuine tree equality after info attributes failed: $FOLLOW_OUTPUT"

make_release ${RV[17]} signed
attribute_file="$tmp/core-attributes"
printf 'install.sh export-ignore\n' > "$attribute_file"
git -C "$checkout" config core.attributesFile "$attribute_file"
run_follow
[[ "$FOLLOW_RC" == 1 ]] || fail 'core.attributesFile was not refused'
grep -q 'verified archive tree differs' <<<"$FOLLOW_OUTPUT" || fail 'core.attributesFile tree refusal missing'
git -C "$checkout" config --unset core.attributesFile
run_follow
[[ "$FOLLOW_RC" == 0 ]] || fail "genuine tree equality after core.attributesFile failed: $FOLLOW_OUTPUT"
pass 'archive tree equality refuses checkout attributes and accepts genuine bytes'

union_checkout="$tmp/union-checkout"
union_config="$tmp/union-config"
union_data="$tmp/union-data"
union_bin="$tmp/union-bin"
union_home="$tmp/union-home"
union_stub="$tmp/union-stub"
git clone --quiet --no-hardlinks "$checkout" "$union_checkout"
cp "$ROOT/install.sh" "$union_checkout/install.sh"
mkdir -p "$union_config" "$union_data" "$union_bin" "$union_home" "$union_stub"
printf '#!/usr/bin/env bash\nexit 0\n' > "$union_stub/systemctl"
chmod +x "$union_stub/systemctl"
union_env=(HOME="$union_home" PATH="$union_stub:/usr/bin:/bin" SAFE_CONFIG_DIR="$union_config"
  SAFE_DATA_DIR="$union_data" SAFE_BIN_DIR="$union_bin" SAFE_ZSHRC="$union_home/.zshrc")
env -i "${union_env[@]}" bash "$union_checkout/install.sh" --run >/dev/null 2>&1 || fail 'union base install failed'
env -i "${union_env[@]}" bash "$union_checkout/install.sh" --review-timer >/dev/null 2>&1 || fail 'review-timer-only install failed'
if ! jq -e '.install_flags == ["--run", "--review-timer"]' "$union_config/release-follow.json" >/dev/null; then
  jq -c . "$union_config/release-follow.json" >&2 || true
  fail 'review-timer-only install narrowed the record'
fi
env -i "${union_env[@]}" bash "$union_checkout/install.sh" --no-wrappers >/dev/null 2>&1 || fail 'no-wrappers install failed'
jq -e '.install_flags == ["--no-wrappers", "--review-timer"]' "$union_config/release-follow.json" >/dev/null ||
  fail 'no-wrappers did not preserve the component union'
env -i "${union_env[@]}" bash "$union_checkout/install.sh" --wrappers >/dev/null 2>&1 || fail 'wrappers install failed'
jq -e '.install_flags == ["--all", "--review-timer"]' "$union_config/release-follow.json" >/dev/null ||
  fail 'wrappers did not re-enable wrappers in the union'
env -i "${union_env[@]}" bash "$union_checkout/install.sh" --no-wrappers >/dev/null 2>&1 || fail 'no-wrappers repeat install failed'
jq -e '.install_flags == ["--all", "--review-timer"]' "$union_config/release-follow.json" >/dev/null ||
  fail 'no-wrappers narrowed an existing wrapper union'
pass 'installer records the component union and preserves no-wrappers semantics'

probe_driver="$tmp/probe-driver"
cp "$driver" "$probe_driver"
printf "${RV[18]}\n" > "$checkout/VERSION"
sed -i -E "s/^SAFE_VERSION=\"[0-9]+\\.[0-9]+\\.[0-9]+\"/SAFE_VERSION=\"${RV[18]}\"/" "$checkout/bin/safe"
cat > "$checkout/install.sh" <<'PROBE_INSTALL'
#!/usr/bin/env bash
set -euo pipefail
rm -f -- "$SAFE_BIN_DIR/safe"
PROBE_INSTALL
chmod +x "$checkout/install.sh"
git -C "$checkout" add VERSION bin/safe install.sh
git -C "$checkout" commit --quiet -m 'fixture probe failure'
git -c gpg.format=openpgp -c gpg.program=/usr/bin/gpg -C "$checkout" tag -s -u "$fingerprint" -m v${RV[18]} v${RV[18]}
git -C "$checkout" push --quiet origin HEAD refs/tags/v${RV[18]}
driver="$probe_driver"
run_follow
[[ "$FOLLOW_RC" != 127 ]] || fail 'post-install probe leaked exit 127'
grep -q 'post-install safe --version probe failed' <<<"$FOLLOW_OUTPUT" || fail 'probe failure refusal missing'
grep -q 'RELEASE_FOLLOW_REFUSED reason=post-install safe --version probe failed' "$SAFE_RUN_DATA_DIR/audit.log" ||
  fail 'probe failure was not audited'
cp "$probe_driver" "$SAFE_BIN_DIR/safe"
driver="$SAFE_BIN_DIR/safe"
pass 'post-install probe failures are audited and return the refusal status'

rm -f "$SAFE_CONFIG_DIR/release-follow.json"
run_follow
[[ "$FOLLOW_RC" == 1 ]] || fail 'missing checkout record was not refused'
grep -q 'checkout record is missing' <<<"$FOLLOW_OUTPUT" || fail 'missing-record refusal missing'
pass 'missing checkout record has an operator recovery path'

printf 'release-follow: all cases passed\n'
