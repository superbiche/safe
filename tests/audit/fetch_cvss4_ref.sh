#!/usr/bin/env bash
# Bootstraps the CVSS v4 reference oracle into tmp/cvss4-ref/ for
# generate_cvss4_fixture.js and cvss4_exhaustive.sh. The committed
# known-answer suite needs nothing from here; only regeneration and the
# exhaustive cross-check do. Content is pinned twice: by upstream commit
# AND by per-file sha256, so a moved tag or force-push upstream cannot
# silently change the oracle.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REF="${CVSS4_REF_DIR:-$ROOT/tmp/cvss4-ref}"
SHA="c5b0d409ae9f57c44264c6ce5f27d89298e1d32a"
BASE_URL="https://raw.githubusercontent.com/FIRSTdotorg/cvss-v4-calculator/$SHA"

declare -A HASHES=(
  [cvss_lookup.js]=d533fe625d95e15b7b488a4bf93dab5f7df16b7e38b0c8ee01281d7b31a8165e
  [max_composed.js]=be707cc82c17993a04a84e47b1a8aaa1d0d212b56852254659ce77fd7d959f63
  [max_severity.js]=f838ecb41bfd5114456e7fa7df8a8449ca2735c176867886fa34bd011dee0b24
  [cvss_score.js]=453ce6767b5c3939b51d1f21315f2649e47b5abeca674be287e94b524472a1bc
)

mkdir -p "$REF"
for f in "${!HASHES[@]}"; do
  if [[ -f "$REF/$f" ]] \
    && [[ "$(sha256sum "$REF/$f" | awk '{print $1}')" == "${HASHES[$f]}" ]]; then
    continue
  fi
  curl -fsS --max-time 30 -o "$REF/$f" "$BASE_URL/$f"
  got="$(sha256sum "$REF/$f" | awk '{print $1}')"
  if [[ "$got" != "${HASHES[$f]}" ]]; then
    rm -f "$REF/$f"
    printf 'fetch_cvss4_ref: %s hash mismatch (got %s) — refusing the oracle\n' "$f" "$got" >&2
    exit 1
  fi
done
printf '%s\n' "$SHA" > "$REF/PROVENANCE-SHA.txt"
printf 'fetch_cvss4_ref: reference ready at %s (pinned %s)\n' "$REF" "$SHA"
