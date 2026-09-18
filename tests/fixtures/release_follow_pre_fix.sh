#!/usr/bin/env bash
# Deliberately minimal pre-fix fixture for the replacement-ref regression.
# It starts after tag verification and retains only the vulnerable archive
# addressing: git archive follows refs/replace when GIT_NO_REPLACE_OBJECTS is
# absent. Do not use this as an updater.
set -euo pipefail

[[ "${SAFE_RELEASE_FOLLOW_PRE_FIX_FIXTURE:-}" == 1 ]] || {
  printf '%s\n' 'release-follow pre-fix fixture is test-only; run it through tests/run/release_follow.sh' >&2
  exit 125
}

checkout="${SAFE_RELEASE_FOLLOW_CHECKOUT:?}"
installed="${SAFE_RELEASE_FOLLOW_INSTALLED:?}"
tag="${SAFE_RELEASE_FOLLOW_TAG:?}"
bin_dir="${SAFE_BIN_DIR:?}"
audit_log="${SAFE_RELEASE_FOLLOW_AUDIT_LOG:-${SAFE_DATA_DIR:?}/run/audit.log}"
archive_dir=$(mktemp -d "${TMPDIR:-/tmp}/safe-release-follow-fixture.XXXXXX")
release_follow_fixture_cleanup() { rm -rf -- "$archive_dir"; }
trap 'release_follow_fixture_cleanup' EXIT

candidate_commit=$(git -C "$checkout" rev-parse "refs/tags/$tag^{commit}")
tag_object=$(git -C "$checkout" rev-parse "refs/tags/$tag")
git -C "$checkout" archive --format=tar "$candidate_commit" | tar -xf - -C "$archive_dir"
( cd "$archive_dir" && SAFE_BIN_DIR="$bin_dir" bash install.sh --run )

mkdir -p -- "$(dirname -- "$audit_log")"
printf '%s | release-follow | RELEASE_FOLLOWED from=%s to=%s signer=%s tag_object=%s\n' \
  "$(date -Iseconds)" "$installed" "${tag#v}" \
  "${SAFE_RELEASE_FOLLOW_SIGNER:-fixture-signer}" "$tag_object" >> "$audit_log"
