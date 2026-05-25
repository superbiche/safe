#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SAFE_AUDIT="$ROOT/bin/safe-audit"

pass() { printf 'ok - %s\n' "$*"; }
fail() { printf 'not ok - %s\n' "$*" >&2; exit 1; }

require() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

require bash
require jq
require sha256sum
require timeout

bash -n "$SAFE_AUDIT"
pass "external audit syntax"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

mockbin="$tmp/mockbin"
fixtures="$tmp/fixtures"
nocosignbin="$tmp/nocosignbin"
nopythonbin="$tmp/nopythonbin"
bridgefailbin="$tmp/bridgefailbin"
mkdir -p "$mockbin" "$fixtures" "$nocosignbin" "$nopythonbin" "$bridgefailbin"

cat > "$mockbin/curl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

output=""
writeout=""
url=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o)
      output="$2"
      shift 2
      ;;
    -w)
      writeout="$2"
      shift 2
      ;;
    -H|-A|-X)
      shift 2
      ;;
    -d|--data|--data-binary)
      shift 2
      ;;
    -s|-S|-L|-f|-fsS|-sS|-fsSL|-sSL)
      shift
      ;;
    *)
      url="$1"
      shift
      ;;
  esac
done

mode="${MOCK_CURL_MODE:-}"
status=200
body=""

case "$mode:$url" in
  release_success:https://api.github.com/repos/example/tool/releases/tags/v1.2.3)
    body="$MOCK_FIXTURES/release-success.json"
    ;;
  release_success:https://api.github.com/repos/example/tool/releases?per_page=100)
    body="$MOCK_FIXTURES/releases-list.json"
    ;;
  release_success:https://api.github.com/repos/example/tool/compare/v1.2.2...v1.2.3)
    body="$MOCK_FIXTURES/compare-safe.json"
    ;;
  release_success:https://api.github.com/repos/example/tool/git/ref/tags/v1.2.3)
    body="$MOCK_FIXTURES/ref.json"
    ;;
  release_success:https://api.github.com/repos/example/tool/commits/abc123)
    body="$MOCK_FIXTURES/commit-verified.json"
    ;;

  release_draft:https://api.github.com/repos/example/tool/releases/tags/v1.2.3)
    body="$MOCK_FIXTURES/release-draft.json"
    ;;
  release_draft:https://api.github.com/repos/example/tool/releases?per_page=100)
    body="$MOCK_FIXTURES/releases-list.json"
    ;;
  release_draft:https://api.github.com/repos/example/tool/compare/v1.2.2...v1.2.3)
    body="$MOCK_FIXTURES/compare-safe.json"
    ;;
  release_draft:https://api.github.com/repos/example/tool/git/ref/tags/v1.2.3)
    body="$MOCK_FIXTURES/ref.json"
    ;;
  release_draft:https://api.github.com/repos/example/tool/commits/abc123)
    body="$MOCK_FIXTURES/commit-verified.json"
    ;;

  release_risky:https://api.github.com/repos/example/tool/releases/tags/v1.2.3)
    body="$MOCK_FIXTURES/release-success.json"
    ;;
  release_risky:https://api.github.com/repos/example/tool/releases?per_page=100)
    body="$MOCK_FIXTURES/releases-list.json"
    ;;
  release_risky:https://api.github.com/repos/example/tool/compare/v1.2.2...v1.2.3)
    body="$MOCK_FIXTURES/compare-risky.json"
    ;;
  release_risky:https://api.github.com/repos/example/tool/git/ref/tags/v1.2.3)
    body="$MOCK_FIXTURES/ref.json"
    ;;
  release_risky:https://api.github.com/repos/example/tool/commits/abc123)
    body="$MOCK_FIXTURES/commit-verified.json"
    ;;

  release_unverified:https://api.github.com/repos/example/tool/releases/tags/v1.2.3)
    body="$MOCK_FIXTURES/release-success.json"
    ;;
  release_unverified:https://api.github.com/repos/example/tool/releases?per_page=100)
    body="$MOCK_FIXTURES/releases-list.json"
    ;;
  release_unverified:https://api.github.com/repos/example/tool/compare/v1.2.2...v1.2.3)
    body="$MOCK_FIXTURES/compare-safe.json"
    ;;
  release_unverified:https://api.github.com/repos/example/tool/git/ref/tags/v1.2.3)
    body="$MOCK_FIXTURES/ref.json"
    ;;
  release_unverified:https://api.github.com/repos/example/tool/commits/abc123)
    body="$MOCK_FIXTURES/commit-unverified.json"
    ;;

  vuln_zero:https://api.github.com/repos/example/tool/security-advisories?per_page=100)
    body="$MOCK_FIXTURES/advisories-zero.json"
    ;;
  vuln_low:https://api.github.com/repos/example/tool/security-advisories?per_page=100)
    body="$MOCK_FIXTURES/advisories-low.json"
    ;;
  vuln_high:https://api.github.com/repos/example/tool/security-advisories?per_page=100)
    body="$MOCK_FIXTURES/advisories-high.json"
    ;;
  vuln_unavailable:*)
    exit 22
    ;;
  *)
    printf 'unexpected mock curl request: %s (%s)\n' "$url" "$mode" >&2
    exit 22
    ;;
esac

[[ -n "$output" ]] || exit 22
cat "$body" > "$output"
if [[ -n "$writeout" ]]; then
  printf '%s' "$status"
fi
SH
chmod +x "$mockbin/curl"

cat > "$mockbin/cosign" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

command_name="${1:-}"
shift || true

case "$command_name" in
  verify-blob)
    bundle=""
    identity=""
    identity_regexp=""
    issuer=""
    issuer_regexp=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --bundle)
          bundle="$2"
          shift 2
          ;;
        --certificate)
          shift 2
          ;;
        --signature)
          shift 2
          ;;
        --certificate-identity)
          identity="$2"
          shift 2
          ;;
        --certificate-identity-regexp)
          identity_regexp="$2"
          shift 2
          ;;
        --certificate-oidc-issuer)
          issuer="$2"
          shift 2
          ;;
        --certificate-oidc-issuer-regexp)
          issuer_regexp="$2"
          shift 2
          ;;
        --new-bundle-format=true|--new-bundle-format)
          shift
          ;;
        *)
          shift
          ;;
      esac
    done

    if [[ -n "$bundle" ]]; then
      if [[ "${MOCK_COSIGN_BUNDLE_MODE:-ok}" == "fail" ]]; then
        printf 'bundle verification failed\n' >&2
        exit 1
      fi

      expected_identity='keyless@projectsigstore.iam.gserviceaccount.com'
      expected_issuer='https://accounts.google.com'
      identity_ok=0
      issuer_ok=0
      if [[ -n "$identity" && "$identity" == "$expected_identity" ]]; then
        identity_ok=1
      fi
      if [[ -n "$identity_regexp" && "$expected_identity" =~ $identity_regexp ]]; then
        identity_ok=1
      fi
      if [[ -n "$issuer" && "$issuer" == "$expected_issuer" ]]; then
        issuer_ok=1
      fi
      if [[ -n "$issuer_regexp" && "$expected_issuer" =~ $issuer_regexp ]]; then
        issuer_ok=1
      fi
      if (( identity_ok == 1 && issuer_ok == 1 )); then
        printf 'Verified OK\n'
        exit 0
      fi
      printf 'bundle signer policy mismatch\n' >&2
      exit 1
    fi

    if [[ "${MOCK_COSIGN_MODE:-ok}" == "fail" ]]; then
      printf 'signature verification failed\n' >&2
      exit 1
    fi

    expected_identity='^https://github\.com/example/tool/\.github/workflows/release\.yml@refs/tags/v1\.2\.3$'
    expected_issuer='https://token.actions.githubusercontent.com'
    if [[ "$identity_regexp" != "$expected_identity" || "$issuer" != "$expected_issuer" ]]; then
      printf 'certificate identity or issuer mismatch\n' >&2
      exit 1
    fi

    printf 'Verified OK\n'
    ;;
  initialize)
    mirror=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --mirror)
          mirror="$2"
          shift 2
          ;;
        --root|--root-checksum)
          shift 2
          ;;
        *)
          shift
          ;;
      esac
    done

    if [[ "${MOCK_COSIGN_TUF_MODE:-ok}" == "fail" ]]; then
      printf 'tuf initialize failed\n' >&2
      exit 1
    fi

    mirror_path=""
    if [[ "$mirror" == file://* ]]; then
      mirror_path="${mirror#file://}"
    elif [[ "$mirror" == http://127.0.0.1:* ]]; then
      mirror_path="${MOCK_COSIGN_BRIDGE_ROOT:-}"
    fi
    repo_dir="$HOME/.sigstore/root/mock-tuf"
    targets_dir="$repo_dir/targets"
    mkdir -p "$targets_dir"
    mkdir -p "$HOME/.sigstore/root"
    printf '{"mirror":"%s"}\n' "$mirror" > "$HOME/.sigstore/root/remote.json"
    if [[ -f "$mirror_path/1.targets.json" ]]; then
      cp "$mirror_path/1.targets.json" "$repo_dir/targets.json"
    elif [[ -f "$mirror_path/targets.json" ]]; then
      cp "$mirror_path/targets.json" "$repo_dir/targets.json"
    fi
    if [[ -f "$repo_dir/targets.json" && -d "$mirror_path/targets" ]]; then
      while IFS=$'\t' read -r target_name target_sha; do
        [[ -n "$target_name" && -n "$target_sha" ]] || continue
        case ",${MOCK_COSIGN_TUF_SKIP_TARGETS:-}," in
          *,"$target_name",*) continue ;;
        esac
        source_path="$mirror_path/targets/$target_sha.$target_name"
        [[ -f "$source_path" ]] || continue
        mkdir -p "$(dirname "$targets_dir/$target_name")"
        cp "$source_path" "$targets_dir/$target_name"
      done < <(jq -r '.signed.targets | to_entries[] | [.key, (.value.hashes.sha256 // "")] | @tsv' "$repo_dir/targets.json")
    fi
    printf 'Initialized\n'
    ;;
  *)
    printf 'unsupported mock cosign command: %s\n' "$command_name" >&2
    exit 1
    ;;
esac
SH
chmod +x "$mockbin/cosign"

cat > "$mockbin/podman" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$@" > "$MOCK_PODMAN_LOG"
if [[ "${MOCK_PODMAN_TOUCH_XDG:-0}" == "1" ]]; then
  for expected in \
    HOME=/tmp/home \
    XDG_CONFIG_HOME=/tmp/xdg-config \
    XDG_CACHE_HOME=/tmp/xdg-cache \
    XDG_STATE_HOME=/tmp/xdg-state
  do
    found=0
    for arg in "$@"; do
      if [[ "$arg" == "$expected" ]]; then
        found=1
        break
      fi
    done
    if (( found == 0 )); then
      printf 'failed to create config directory: missing %s\n' "$expected" >&2
      exit 1
    fi
  done
  printf 'config/cache/state paths are writable\n'
  exit 0
fi
printf 'podman stdout summary\n'
printf 'podman stderr summary\n' >&2
exit "${MOCK_PODMAN_RC:-0}"
SH
chmod +x "$mockbin/podman"

for tool in awk bash basename cat cp cut date dirname find grep head jq kill mkdir mktemp mv ps pwd sed sha256sum sleep sort touch tr wc; do
  ln -sf "$(command -v "$tool")" "$nocosignbin/$tool"
  ln -sf "$(command -v "$tool")" "$nopythonbin/$tool"
  ln -sf "$(command -v "$tool")" "$bridgefailbin/$tool"
done
ln -sf "$mockbin/cosign" "$nopythonbin/cosign"
ln -sf "$mockbin/cosign" "$bridgefailbin/cosign"

cat > "$bridgefailbin/python3" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "-" && "$#" -eq 3 ]]; then
  printf '%s\n' "$$" > "$MOCK_BRIDGE_FAIL_PID_FILE"
  sleep 30
  exit 0
fi
if [[ "${1:-}" == "-" && "$#" -eq 2 ]]; then
  exit 1
fi
exec /usr/bin/python3 "$@"
SH
chmod +x "$bridgefailbin/python3"

cat > "$fixtures/release-success.json" <<'JSON'
{
  "tag_name": "v1.2.3",
  "draft": false,
  "prerelease": false,
  "published_at": "2026-05-10T12:00:00Z",
  "html_url": "https://github.com/example/tool/releases/tag/v1.2.3",
  "body": "Stable release for tests.",
  "assets": [
    {
      "name": "tool_1.2.3_linux_amd64.tar.gz",
      "browser_download_url": "https://github.com/example/tool/releases/download/v1.2.3/tool_1.2.3_linux_amd64.tar.gz"
    }
  ]
}
JSON

cat > "$fixtures/release-draft.json" <<'JSON'
{
  "tag_name": "v1.2.3",
  "draft": true,
  "prerelease": false,
  "published_at": "2026-05-10T12:00:00Z",
  "html_url": "https://github.com/example/tool/releases/tag/v1.2.3",
  "body": "Draft release for tests.",
  "assets": [
    {
      "name": "tool_1.2.3_linux_amd64.tar.gz",
      "browser_download_url": "https://github.com/example/tool/releases/download/v1.2.3/tool_1.2.3_linux_amd64.tar.gz"
    }
  ]
}
JSON

cat > "$fixtures/releases-list.json" <<'JSON'
[
  { "tag_name": "v1.2.3", "draft": false, "prerelease": false, "published_at": "2026-05-10T12:00:00Z" },
  { "tag_name": "v1.2.2", "draft": false, "prerelease": false, "published_at": "2026-05-01T12:00:00Z" }
]
JSON

cat > "$fixtures/compare-safe.json" <<'JSON'
{
  "files": [
    { "filename": "cmd/tool/main.go" },
    { "filename": "README.md" }
  ]
}
JSON

cat > "$fixtures/compare-risky.json" <<'JSON'
{
  "files": [
    { "filename": ".github/workflows/release.yml" },
    { "filename": "cmd/tool/main.go" }
  ]
}
JSON

cat > "$fixtures/ref.json" <<'JSON'
{
  "object": {
    "type": "commit",
    "sha": "abc123"
  }
}
JSON

cat > "$fixtures/commit-verified.json" <<'JSON'
{
  "commit": {
    "verification": {
      "verified": true,
      "reason": "valid"
    }
  }
}
JSON

cat > "$fixtures/commit-unverified.json" <<'JSON'
{
  "commit": {
    "verification": {
      "verified": false,
      "reason": "unsigned"
    }
  }
}
JSON

cat > "$fixtures/advisories-zero.json" <<'JSON'
[]
JSON

cat > "$fixtures/advisories-low.json" <<'JSON'
[
  {
    "ghsa_id": "GHSA-low-test",
    "cve_id": "CVE-2026-0001",
    "severity": "low",
    "html_url": "https://github.com/example/tool/security/advisories/GHSA-low-test",
    "summary": "Low severity test advisory",
    "updated_at": "2026-05-01T12:00:00Z",
    "vulnerabilities": [
      {
        "package": {
          "ecosystem": "go",
          "name": "github.com/example/tool"
        },
        "vulnerable_version_range": "<v2.0.0",
        "patched_versions": "v2.0.0"
      }
    ]
  }
]
JSON

cat > "$fixtures/advisories-high.json" <<'JSON'
[
  {
    "ghsa_id": "GHSA-high-test",
    "cve_id": "CVE-2026-0002",
    "severity": "high",
    "html_url": "https://github.com/example/tool/security/advisories/GHSA-high-test",
    "summary": "High severity test advisory",
    "updated_at": "2026-05-01T12:00:00Z",
    "vulnerabilities": [
      {
        "package": {
          "ecosystem": "go",
          "name": "github.com/example/tool"
        },
        "vulnerable_version_range": "<v2.0.0",
        "patched_versions": "v2.0.0"
      }
    ]
  }
]
JSON

run_json() {
  local name="$1"
  shift
  local out="$tmp/$name.json" err="$tmp/$name.err"
  set +e
  SAFE_AUDIT_CONFIG_DIR="$tmp/config-$name" \
  SAFE_AUDIT_DATA_DIR="$tmp/data-$name" \
  SAFE_AUDIT_GITHUB_API_BASE_URL="https://api.github.com" \
  SAFE_AUDIT_GITHUB_RELEASE_MIN_AGE_DAYS=3 \
  PATH="$mockbin:$PATH" \
  MOCK_FIXTURES="$fixtures" \
    "$SAFE_AUDIT" "$@" >"$out" 2>"$err"
  RUN_RC=$?
  set -e
  RUN_OUT="$out"
  RUN_ERR="$err"
}

run_json_real() {
  local name="$1"
  shift
  local out="$tmp/$name.json" err="$tmp/$name.err"
  set +e
  SAFE_AUDIT_CONFIG_DIR="$tmp/config-$name" \
  SAFE_AUDIT_DATA_DIR="$tmp/data-$name" \
    "$SAFE_AUDIT" "$@" >"$out" 2>"$err"
  RUN_RC=$?
  set -e
  RUN_OUT="$out"
  RUN_ERR="$err"
}

MOCK_CURL_MODE=release_success run_json release_success release github --repo example/tool --version v1.2.3 --asset tool_1.2.3_linux_amd64.tar.gz --json
[[ "$RUN_RC" == "0" ]] || fail "release github success rc=$RUN_RC"
jq -e '.verdict == "GO" and .data.previous_tag == "v1.2.2" and .data.tag_commit_sha == "abc123"' "$RUN_OUT" >/dev/null || fail "release github success payload"
pass "release github success"

MOCK_CURL_MODE=release_draft run_json release_draft release github --repo example/tool --version v1.2.3 --asset tool_1.2.3_linux_amd64.tar.gz --json
[[ "$RUN_RC" == "20" ]] || fail "release github draft rc=$RUN_RC"
jq -e '.verdict == "BLOCK" and any(.reasons[]; .code == "release_channel")' "$RUN_OUT" >/dev/null || fail "release github draft verdict"
pass "release github draft block"

MOCK_CURL_MODE=release_unverified run_json release_unverified release github --repo example/tool --version v1.2.3 --asset tool_1.2.3_linux_amd64.tar.gz --json
[[ "$RUN_RC" == "20" ]] || fail "release github unverified rc=$RUN_RC"
jq -e '.verdict == "BLOCK" and any(.reasons[]; .code == "tag_verification_failed")' "$RUN_OUT" >/dev/null || fail "release github unverified verdict"
pass "release github tag verification block"

MOCK_CURL_MODE=release_risky run_json release_risky release github --repo example/tool --version v1.2.3 --asset tool_1.2.3_linux_amd64.tar.gz --json
[[ "$RUN_RC" == "20" ]] || fail "release github risky rc=$RUN_RC"
jq -e '.verdict == "BLOCK" and any(.reasons[]; .code == "high_risk_paths") and (.data.high_risk_paths | length == 1)' "$RUN_OUT" >/dev/null || fail "release github risky verdict"
pass "release github high-risk path block"

MOCK_CURL_MODE=vuln_zero run_json vuln_zero vuln github-release --repo example/tool --version v1.2.3 --json
[[ "$RUN_RC" == "0" ]] || fail "vuln zero rc=$RUN_RC"
jq -e '.verdict == "GO" and .data.matched_advisory_count == 0' "$RUN_OUT" >/dev/null || fail "vuln zero payload"
pass "vuln zero findings"

MOCK_CURL_MODE=vuln_unavailable run_json vuln_unavailable vuln github-release --repo example/tool --version v1.2.3 --json
[[ "$RUN_RC" == "20" ]] || fail "vuln unavailable rc=$RUN_RC"
jq -e '.verdict == "BLOCK" and any(.reasons[]; .code == "feed_unavailable")' "$RUN_OUT" >/dev/null || fail "vuln unavailable verdict"
pass "vuln feed unavailable block"

MOCK_CURL_MODE=vuln_low run_json vuln_low vuln github-release --repo example/tool --version v1.2.3 --json
[[ "$RUN_RC" == "10" ]] || fail "vuln low rc=$RUN_RC"
jq -e '.verdict == "WARN" and .data.matched_advisory_count == 1 and any(.reasons[]; .code == "known_advisory")' "$RUN_OUT" >/dev/null || fail "vuln low verdict"
pass "vuln severity warn mapping"

MOCK_CURL_MODE=vuln_high run_json vuln_high vuln github-release --repo example/tool --version v1.2.3 --json
[[ "$RUN_RC" == "20" ]] || fail "vuln high rc=$RUN_RC"
jq -e '.verdict == "BLOCK" and .data.high_or_critical_match_count == 1 and any(.reasons[]; .code == "known_advisory_high_severity")' "$RUN_OUT" >/dev/null || fail "vuln high verdict"
pass "vuln severity block mapping"

artifact_dir="$tmp/artifacts"
mkdir -p "$artifact_dir"
artifact="$artifact_dir/tool.bin"
checksum="$artifact_dir/tool.sha256"
cert="$artifact_dir/tool.pem"
sig="$artifact_dir/tool.sig"
printf 'payload\n' > "$artifact"
sha="$(sha256sum "$artifact" | awk '{print $1}')"
printf '%s  %s\n' "$sha" "$(basename "$artifact")" > "$checksum"
printf 'cert\n' > "$cert"
printf 'sig\n' > "$sig"
bundle_json="$artifact_dir/tool.sigstore.json"
cat > "$bundle_json" <<'JSON'
{
  "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
  "verificationMaterial": {
    "certificate": {
      "rawBytes": "Zm9v"
    }
  },
  "messageSignature": {
    "messageDigest": {
      "algorithm": "SHA2_256",
      "digest": "AAAA"
    },
    "signature": "AQ=="
  }
}
JSON

run_json verify_signed verify release-asset --artifact "$artifact" --checksum "$checksum" --certificate "$cert" --signature "$sig" --certificate-identity-regexp '^https://github\.com/example/tool/\.github/workflows/release\.yml@refs/tags/v1\.2\.3$' --certificate-oidc-issuer https://token.actions.githubusercontent.com --json
[[ "$RUN_RC" == "0" ]] || fail "verify signed rc=$RUN_RC"
jq -e '.verdict == "GO" and .data.signature_verified == true and .data.expected_sha256 == .data.actual_sha256' "$RUN_OUT" >/dev/null || fail "verify signed payload"
pass "verify signed checksum success"

PATH="$nocosignbin" \
  SAFE_AUDIT_CONFIG_DIR="$tmp/config-verify-missing-tool" \
  SAFE_AUDIT_DATA_DIR="$tmp/data-verify-missing-tool" \
  "$SAFE_AUDIT" verify release-asset --artifact "$artifact" --checksum "$checksum" --certificate "$cert" --signature "$sig" --certificate-identity-regexp '^https://github\.com/example/tool/\.github/workflows/release\.yml@refs/tags/v1\.2\.3$' --certificate-oidc-issuer https://token.actions.githubusercontent.com --json >"$tmp/verify-missing-tool.json" 2>"$tmp/verify-missing-tool.err" || true
jq -e '.verdict == "BLOCK" and any(.reasons[]; .code == "missing_tool")' "$tmp/verify-missing-tool.json" >/dev/null || fail "verify missing cosign tool"
pass "verify missing tool block"

run_json verify_missing_sidecar verify release-asset --artifact "$artifact" --checksum "$checksum" --certificate "$artifact_dir/missing.pem" --signature "$sig" --certificate-identity-regexp '^https://github\.com/example/tool/\.github/workflows/release\.yml@refs/tags/v1\.2\.3$' --certificate-oidc-issuer https://token.actions.githubusercontent.com --json
[[ "$RUN_RC" == "20" ]] || fail "verify missing sidecar rc=$RUN_RC"
jq -e '.verdict == "BLOCK" and any(.reasons[]; .code == "missing_asset")' "$RUN_OUT" >/dev/null || fail "verify missing sidecar verdict"
pass "verify missing sidecar block"

MOCK_COSIGN_MODE=fail run_json verify_signature_fail verify release-asset --artifact "$artifact" --checksum "$checksum" --certificate "$cert" --signature "$sig" --certificate-identity-regexp '^https://github\.com/example/tool/\.github/workflows/release\.yml@refs/tags/v1\.2\.3$' --certificate-oidc-issuer https://token.actions.githubusercontent.com --json
[[ "$RUN_RC" == "20" ]] || fail "verify signature failure rc=$RUN_RC"
jq -e '.verdict == "BLOCK" and any(.reasons[]; .code == "signature_failure")' "$RUN_OUT" >/dev/null || fail "verify signature failure verdict"
pass "verify signature failure block"

bad_checksum="$artifact_dir/tool.bad.sha256"
printf '%064d  %s\n' 0 "$(basename "$artifact")" > "$bad_checksum"
run_json verify_checksum_mismatch verify release-asset --artifact "$artifact" --checksum "$bad_checksum" --json
[[ "$RUN_RC" == "20" ]] || fail "verify checksum mismatch rc=$RUN_RC"
jq -e '.verdict == "BLOCK" and any(.reasons[]; .code == "checksum_failure")' "$RUN_OUT" >/dev/null || fail "verify checksum mismatch verdict"
pass "verify checksum mismatch block"

run_json verify_policy_mismatch verify release-asset --artifact "$artifact" --checksum "$checksum" --certificate "$cert" --signature "$sig" --certificate-identity-regexp '^https://wrong.example$' --certificate-oidc-issuer https://token.actions.githubusercontent.com --json
[[ "$RUN_RC" == "20" ]] || fail "verify identity mismatch rc=$RUN_RC"
jq -e '.verdict == "BLOCK" and any(.reasons[]; .code == "signature_failure")' "$RUN_OUT" >/dev/null || fail "verify identity mismatch verdict"
pass "verify identity or issuer mismatch block"

run_json verify_checksum_only verify release-asset --artifact "$artifact" --checksum "$checksum" --json
[[ "$RUN_RC" == "10" ]] || fail "verify checksum only rc=$RUN_RC"
jq -e '.verdict == "WARN" and any(.reasons[]; .code == "policy_mismatch")' "$RUN_OUT" >/dev/null || fail "verify checksum only verdict"
pass "verify checksum-only warn"

run_json verify_require_signature verify release-asset --artifact "$artifact" --checksum "$checksum" --require-signature --json
[[ "$RUN_RC" == "20" ]] || fail "verify require signature rc=$RUN_RC"
jq -e '.verdict == "BLOCK" and any(.reasons[]; .code == "policy_mismatch")' "$RUN_OUT" >/dev/null || fail "verify require signature verdict"
pass "verify require signature block"

run_json verify_sigstore_bundle verify sigstore-bundle --artifact "$artifact" --bundle "$bundle_json" --identity keyless@projectsigstore.iam.gserviceaccount.com --oidc-issuer https://accounts.google.com --json
[[ "$RUN_RC" == "0" ]] || fail "verify sigstore bundle rc=$RUN_RC"
jq -e '.verdict == "GO" and .data.policy_status == "matched" and .data.verification_tool == "cosign verify-blob"' "$RUN_OUT" >/dev/null || fail "verify sigstore bundle payload"
pass "verify sigstore bundle success"

PATH="$nocosignbin" \
  SAFE_AUDIT_CONFIG_DIR="$tmp/config-verify-sigstore-missing-tool" \
  SAFE_AUDIT_DATA_DIR="$tmp/data-verify-sigstore-missing-tool" \
  "$SAFE_AUDIT" verify sigstore-bundle --artifact "$artifact" --bundle "$bundle_json" --identity keyless@projectsigstore.iam.gserviceaccount.com --oidc-issuer https://accounts.google.com --json >"$tmp/verify-sigstore-missing-tool.json" 2>"$tmp/verify-sigstore-missing-tool.err" || true
jq -e '.verdict == "BLOCK" and any(.reasons[]; .code == "missing_tool")' "$tmp/verify-sigstore-missing-tool.json" >/dev/null || fail "verify sigstore missing cosign tool"
pass "verify sigstore missing tool block"

run_json verify_sigstore_missing_bundle verify sigstore-bundle --artifact "$artifact" --bundle "$artifact_dir/missing.sigstore.json" --identity keyless@projectsigstore.iam.gserviceaccount.com --oidc-issuer https://accounts.google.com --json
[[ "$RUN_RC" == "20" ]] || fail "verify sigstore missing bundle rc=$RUN_RC"
jq -e '.verdict == "BLOCK" and any(.reasons[]; .code == "missing_asset")' "$RUN_OUT" >/dev/null || fail "verify sigstore missing bundle verdict"
pass "verify sigstore missing bundle block"

MOCK_COSIGN_BUNDLE_MODE=fail run_json verify_sigstore_signature_fail verify sigstore-bundle --artifact "$artifact" --bundle "$bundle_json" --identity keyless@projectsigstore.iam.gserviceaccount.com --oidc-issuer https://accounts.google.com --json
[[ "$RUN_RC" == "20" ]] || fail "verify sigstore signature failure rc=$RUN_RC"
jq -e '.verdict == "BLOCK" and any(.reasons[]; .code == "signature_failure")' "$RUN_OUT" >/dev/null || fail "verify sigstore signature failure verdict"
pass "verify sigstore signature failure block"

run_json verify_sigstore_identity_mismatch verify sigstore-bundle --artifact "$artifact" --bundle "$bundle_json" --identity wrong@example.com --oidc-issuer https://accounts.google.com --json
[[ "$RUN_RC" == "20" ]] || fail "verify sigstore identity mismatch rc=$RUN_RC"
jq -e '.verdict == "BLOCK" and .data.policy_status == "identity_mismatch" and any(.reasons[]; .code == "identity_mismatch")' "$RUN_OUT" >/dev/null || fail "verify sigstore identity mismatch verdict"
pass "verify sigstore identity mismatch block"

run_json verify_sigstore_issuer_mismatch verify sigstore-bundle --artifact "$artifact" --bundle "$bundle_json" --identity keyless@projectsigstore.iam.gserviceaccount.com --oidc-issuer https://issuer.example.com --json
[[ "$RUN_RC" == "20" ]] || fail "verify sigstore issuer mismatch rc=$RUN_RC"
jq -e '.verdict == "BLOCK" and .data.policy_status == "issuer_mismatch" and any(.reasons[]; .code == "issuer_mismatch")' "$RUN_OUT" >/dev/null || fail "verify sigstore issuer mismatch verdict"
pass "verify sigstore issuer mismatch block"

tuf_mirror="$tmp/tuf-mirror"
tuf_mirror_missing_blob="$tmp/tuf-mirror-missing-blob"
mkdir -p "$tuf_mirror/targets"
tuf_root="$tmp/root.json"
tuf_pub_source="$tmp/artifact-source.pub"
tuf_json_source="$tmp/signing-config-source.json"
tuf_bin_source="$tmp/artifact-source.bin"
tuf_target="$tmp/artifact.pub"
tuf_trimmed_target="$tmp/artifact-trimmed.pub"
tuf_spacey_target="$tmp/artifact-spacey.pub"
tuf_json_target="$tmp/signing-config.json"
tuf_bin_target="$tmp/artifact.bin"
tuf_bad_target="$tmp/artifact-bad.pub"
printf '{"signed":{"_type":"root"}}\n' > "$tuf_root"
printf 'artifact-key\n' > "$tuf_pub_source"
printf '{"issuer":"sigstore"}\n' > "$tuf_json_source"
printf 'binary-data\n' > "$tuf_bin_source"
tuf_pub_sha="$(sha256sum "$tuf_pub_source" | awk '{print $1}')"
tuf_json_sha="$(sha256sum "$tuf_json_source" | awk '{print $1}')"
tuf_bin_sha="$(sha256sum "$tuf_bin_source" | awk '{print $1}')"
cp "$tuf_pub_source" "$tuf_mirror/targets/$tuf_pub_sha.artifact.pub"
cp "$tuf_json_source" "$tuf_mirror/targets/$tuf_json_sha.signing-config.json"
cp "$tuf_bin_source" "$tuf_mirror/targets/$tuf_bin_sha.artifact.bin"
jq -n \
  --arg pub_sha "$tuf_pub_sha" \
  --argjson pub_len "$(wc -c < "$tuf_pub_source" | tr -d '[:space:]')" \
  --arg json_sha "$tuf_json_sha" \
  --argjson json_len "$(wc -c < "$tuf_json_source" | tr -d '[:space:]')" \
  --arg bin_sha "$tuf_bin_sha" \
  --argjson bin_len "$(wc -c < "$tuf_bin_source" | tr -d '[:space:]')" \
  '{
    signed: {
      _type: "targets",
      targets: {
        "artifact.pub": {
          hashes: { sha256: $pub_sha },
          length: $pub_len
        },
        "signing-config.json": {
          hashes: { sha256: $json_sha },
          length: $json_len
        },
        "artifact.bin": {
          hashes: { sha256: $bin_sha },
          length: $bin_len
        }
      }
    }
  }' > "$tuf_mirror/1.targets.json"
cp "$tuf_pub_source" "$tuf_target"
printf 'artifact-key' > "$tuf_trimmed_target"
printf 'artifact-key \n' > "$tuf_spacey_target"
printf '{"issuer":"sigstore"}' > "$tuf_json_target"
printf 'binary-data' > "$tuf_bin_target"
printf 'wrong-key\n' > "$tuf_bad_target"
cp -R "$tuf_mirror" "$tuf_mirror_missing_blob"
rm -f "$tuf_mirror_missing_blob/targets/$tuf_pub_sha.artifact.pub"
root_sha="$(sha256sum "$tuf_root" | awk '{print $1}')"

MOCK_COSIGN_BRIDGE_ROOT="$tuf_mirror" run_json verify_tuf_bootstrap verify tuf-bootstrap --mirror "$tuf_mirror" --root "$tuf_root" --root-checksum "$root_sha" --target artifact.pub="$tuf_target" --json
[[ "$RUN_RC" == "0" ]] || fail "verify tuf bootstrap rc=$RUN_RC"
jq -e '
  .verdict == "GO"
  and (.checks[] | select(.id == "mirror_bridge") | .verdict) == "GO"
  and .data.mirror_transport == "http-bridge"
  and (.data.effective_mirror_url | startswith("http://127.0.0.1:"))
  and (.data.targets | length) == 1
  and .data.targets[0].matched == true
  and .data.targets[0].verification_source == "materialized"
  and .data.targets[0].match_source == "materialized_strict"
' "$RUN_OUT" >/dev/null || fail "verify tuf bootstrap payload"
pass "verify tuf bootstrap success"

MOCK_COSIGN_BRIDGE_ROOT="$tuf_mirror" MOCK_COSIGN_TUF_SKIP_TARGETS=artifact.pub run_json verify_tuf_bootstrap_fallback verify tuf-bootstrap --mirror "$tuf_mirror" --root "$tuf_root" --root-checksum "$root_sha" --target artifact.pub="$tuf_target" --json
[[ "$RUN_RC" == "0" ]] || fail "verify tuf bootstrap fallback rc=$RUN_RC"
jq -e '
  .verdict == "GO"
  and .data.targets[0].verification_source == "mirror_blob"
  and .data.targets[0].match_source == "mirror_blob_strict"
  and .data.targets[0].materialized_available == false
' "$RUN_OUT" >/dev/null || fail "verify tuf bootstrap fallback payload"
pass "verify tuf bootstrap fallback success"

MOCK_COSIGN_BRIDGE_ROOT="$tuf_mirror" run_json verify_tuf_bootstrap_file_url verify tuf-bootstrap --mirror "file://$tuf_mirror" --root "$tuf_root" --root-checksum "$root_sha" --target artifact.pub="$tuf_target" --json
[[ "$RUN_RC" == "0" ]] || fail "verify tuf bootstrap file url rc=$RUN_RC"
jq -e '
  .verdict == "GO"
  and (.checks[] | select(.id == "mirror_bridge") | .verdict) == "GO"
  and .data.mirror == ("file://" + $mirror)
  and .data.mirror_transport == "http-bridge"
' --arg mirror "$tuf_mirror" "$RUN_OUT" >/dev/null || fail "verify tuf bootstrap file url payload"
pass "verify tuf bootstrap file url success"

MOCK_COSIGN_BRIDGE_ROOT="$tuf_mirror" run_json verify_tuf_trimmed_pub verify tuf-bootstrap --mirror "$tuf_mirror" --root "$tuf_root" --root-checksum "$root_sha" --target artifact.pub="$tuf_trimmed_target" --json
[[ "$RUN_RC" == "0" ]] || fail "verify tuf trimmed pub rc=$RUN_RC"
jq -e '
  .verdict == "GO"
  and .data.targets[0].match_source == "materialized_trimmed_newline"
  and .data.targets[0].comparison_mode == "trimmed_newline"
' "$RUN_OUT" >/dev/null || fail "verify tuf trimmed pub payload"
pass "verify tuf trimmed pub success"

MOCK_COSIGN_BRIDGE_ROOT="$tuf_mirror" run_json verify_tuf_trimmed_json verify tuf-bootstrap --mirror "$tuf_mirror" --root "$tuf_root" --root-checksum "$root_sha" --target signing-config.json="$tuf_json_target" --json
[[ "$RUN_RC" == "0" ]] || fail "verify tuf trimmed json rc=$RUN_RC"
jq -e '
  .verdict == "GO"
  and .data.targets[0].name == "signing-config.json"
  and .data.targets[0].match_source == "materialized_trimmed_newline"
  and .data.targets[0].comparison_mode == "trimmed_newline"
' "$RUN_OUT" >/dev/null || fail "verify tuf trimmed json payload"
pass "verify tuf trimmed json success"

MOCK_COSIGN_BRIDGE_ROOT="$tuf_mirror" run_json verify_tuf_missing_input verify tuf-bootstrap --mirror "$tuf_mirror" --root "$tuf_root" --root-checksum "$root_sha" --target artifact.pub="$tmp/missing-artifact.pub" --json
[[ "$RUN_RC" == "20" ]] || fail "verify tuf missing input rc=$RUN_RC"
jq -e '.verdict == "BLOCK" and any(.reasons[]; .code == "missing_trust_input")' "$RUN_OUT" >/dev/null || fail "verify tuf missing input verdict"
pass "verify tuf missing input block"

MOCK_COSIGN_BRIDGE_ROOT="$tuf_mirror_missing_blob" run_json verify_tuf_missing_mirror_blob verify tuf-bootstrap --mirror "$tuf_mirror_missing_blob" --root "$tuf_root" --root-checksum "$root_sha" --target artifact.pub="$tuf_target" --json
[[ "$RUN_RC" == "20" ]] || fail "verify tuf missing mirror blob rc=$RUN_RC"
jq -e '
  .verdict == "BLOCK"
  and any(.reasons[]; .code == "trusted_mirror_target_invalid")
  and .data.targets[0].status == "trusted_mirror_target_invalid"
' "$RUN_OUT" >/dev/null || fail "verify tuf missing mirror blob verdict"
pass "verify tuf missing mirror blob block"

MOCK_COSIGN_BRIDGE_ROOT="$tuf_mirror" run_json verify_tuf_mismatch verify tuf-bootstrap --mirror "$tuf_mirror" --root "$tuf_root" --root-checksum "$root_sha" --target artifact.pub="$tuf_bad_target" --json
[[ "$RUN_RC" == "20" ]] || fail "verify tuf mismatch rc=$RUN_RC"
jq -e '.verdict == "BLOCK" and any(.reasons[]; .code == "trust_material_mismatch")' "$RUN_OUT" >/dev/null || fail "verify tuf mismatch verdict"
pass "verify tuf trust material mismatch block"

MOCK_COSIGN_BRIDGE_ROOT="$tuf_mirror" run_json verify_tuf_binary_strict verify tuf-bootstrap --mirror "$tuf_mirror" --root "$tuf_root" --root-checksum "$root_sha" --target artifact.bin="$tuf_bin_target" --json
[[ "$RUN_RC" == "20" ]] || fail "verify tuf binary strict rc=$RUN_RC"
jq -e '
  .verdict == "BLOCK"
  and any(.reasons[]; .code == "trust_material_mismatch")
  and .data.targets[0].name == "artifact.bin"
' "$RUN_OUT" >/dev/null || fail "verify tuf binary strict verdict"
pass "verify tuf binary strict block"

MOCK_COSIGN_BRIDGE_ROOT="$tuf_mirror" run_json verify_tuf_spacey_pub verify tuf-bootstrap --mirror "$tuf_mirror" --root "$tuf_root" --root-checksum "$root_sha" --target artifact.pub="$tuf_spacey_target" --json
[[ "$RUN_RC" == "20" ]] || fail "verify tuf spacey pub rc=$RUN_RC"
jq -e '
  .verdict == "BLOCK"
  and any(.reasons[]; .code == "trust_material_mismatch")
  and .data.targets[0].name == "artifact.pub"
' "$RUN_OUT" >/dev/null || fail "verify tuf spacey pub verdict"
pass "verify tuf spacey pub block"

MOCK_COSIGN_BRIDGE_ROOT="$tuf_mirror" run_json verify_tuf_root_mismatch verify tuf-bootstrap --mirror "$tuf_mirror" --root "$tuf_root" --root-checksum "$(printf '%064d' 0)" --target artifact.pub="$tuf_target" --json
[[ "$RUN_RC" == "20" ]] || fail "verify tuf root mismatch rc=$RUN_RC"
jq -e '.verdict == "BLOCK" and any(.reasons[]; .code == "trust_root_mismatch")' "$RUN_OUT" >/dev/null || fail "verify tuf root mismatch verdict"
pass "verify tuf trust root mismatch block"

MOCK_COSIGN_BRIDGE_ROOT="$tuf_mirror" run_json verify_tuf_policy_mismatch verify tuf-bootstrap --mirror "$tuf_mirror" --root "$tuf_root" --root-checksum "$root_sha" --target missing.pub="$tuf_target" --json
[[ "$RUN_RC" == "20" ]] || fail "verify tuf policy mismatch rc=$RUN_RC"
jq -e '.verdict == "BLOCK" and any(.reasons[]; .code == "policy_mismatch")' "$RUN_OUT" >/dev/null || fail "verify tuf policy mismatch verdict"
pass "verify tuf policy mismatch block"

PATH="$nopythonbin" \
MOCK_COSIGN_BRIDGE_ROOT="$tuf_mirror" \
SAFE_AUDIT_CONFIG_DIR="$tmp/config-verify-tuf-missing-python" \
SAFE_AUDIT_DATA_DIR="$tmp/data-verify-tuf-missing-python" \
  "$SAFE_AUDIT" verify tuf-bootstrap --mirror "$tuf_mirror" --root "$tuf_root" --root-checksum "$root_sha" --target artifact.pub="$tuf_target" --json >"$tmp/verify-tuf-missing-python.json" 2>"$tmp/verify-tuf-missing-python.err" || true
jq -e '
  .verdict == "BLOCK"
  and (.checks[] | select(.id == "mirror_bridge") | .verdict) == "BLOCK"
  and any(.reasons[]; .code == "missing_tool" and .data.missing == "python3|python")
' "$tmp/verify-tuf-missing-python.json" >/dev/null || fail "verify tuf missing python verdict"
pass "verify tuf missing python block"

bridge_fail_pid_file="$tmp/bridge-fail.pid"
PATH="$bridgefailbin" \
MOCK_COSIGN_BRIDGE_ROOT="$tuf_mirror" \
MOCK_BRIDGE_FAIL_PID_FILE="$bridge_fail_pid_file" \
SAFE_AUDIT_CONFIG_DIR="$tmp/config-verify-tuf-bridge-fail" \
SAFE_AUDIT_DATA_DIR="$tmp/data-verify-tuf-bridge-fail" \
  "$SAFE_AUDIT" verify tuf-bootstrap --mirror "$tuf_mirror" --root "$tuf_root" --root-checksum "$root_sha" --target artifact.pub="$tuf_target" --json >"$tmp/verify-tuf-bridge-fail.json" 2>"$tmp/verify-tuf-bridge-fail.err" || true
jq -e '
  .verdict == "BLOCK"
  and (.checks[] | select(.id == "mirror_bridge") | .verdict) == "BLOCK"
  and any(.reasons[]; .code == "bootstrap_failure")
  and ((.checks | map(.id) | index("tuf_initialize")) == null)
' "$tmp/verify-tuf-bridge-fail.json" >/dev/null || fail "verify tuf bridge failure verdict"
bridge_fail_pid="$(cat "$bridge_fail_pid_file")"
if kill -0 "$bridge_fail_pid" 2>/dev/null; then
  fail "verify tuf bridge failure leaked background bridge process"
fi
pass "verify tuf bridge failure cleanup"

live_tuf_fixture="$ROOT/tests/fixtures/tuf-bootstrap-live"
if command -v cosign >/dev/null 2>&1 && { command -v python3 >/dev/null 2>&1 || command -v python >/dev/null 2>&1; }; then
  run_json_real verify_tuf_live_dir verify tuf-bootstrap \
    --mirror "$live_tuf_fixture/mirror" \
    --root "$live_tuf_fixture/root.json" \
    --root-checksum "$(sha256sum "$live_tuf_fixture/root.json" | awk '{print $1}')" \
    --target signing_config.json="$live_tuf_fixture/trust/signing_config.json" \
    --target signing_config.v0.2.json="$live_tuf_fixture/trust/signing_config.v0.2.json" \
    --target trusted_root.json="$live_tuf_fixture/trust/trusted_root.json" \
    --json
  [[ "$RUN_RC" == "0" ]] || fail "verify live tuf dir rc=$RUN_RC"
  jq -e '
    .verdict == "GO"
    and .data.mirror_transport == "http-bridge"
    and (.data.effective_mirror_url | startswith("http://127.0.0.1:"))
    and (.checks[] | select(.id == "mirror_bridge") | .verdict) == "GO"
    and (.checks[] | select(.id == "tuf_initialize") | .verdict) == "GO"
    and (.data.targets | length) == 3
    and all(.data.targets[]; .matched == true)
    and any(.data.targets[]; .name == "signing_config.json" and .verification_source == "mirror_blob" and .match_source == "mirror_blob_strict")
  ' "$RUN_OUT" >/dev/null || fail "verify live tuf dir payload"
  pass "verify live tuf dir success"

  run_json_real verify_tuf_live_file_url verify tuf-bootstrap \
    --mirror "file://$live_tuf_fixture/mirror" \
    --root "$live_tuf_fixture/root.json" \
    --root-checksum "$(sha256sum "$live_tuf_fixture/root.json" | awk '{print $1}')" \
    --target signing_config.json="$live_tuf_fixture/trust/signing_config.json" \
    --target signing_config.v0.2.json="$live_tuf_fixture/trust/signing_config.v0.2.json" \
    --target trusted_root.json="$live_tuf_fixture/trust/trusted_root.json" \
    --json
  [[ "$RUN_RC" == "0" ]] || fail "verify live tuf file url rc=$RUN_RC"
  jq -e '
    .verdict == "GO"
    and .data.mirror == ("file://" + $mirror)
    and .data.mirror_transport == "http-bridge"
    and (.data.effective_mirror_url | startswith("http://127.0.0.1:"))
    and all(.data.targets[]; .matched == true)
    and any(.data.targets[]; .name == "signing_config.json" and .verification_source == "mirror_blob" and .match_source == "mirror_blob_strict")
  ' --arg mirror "$live_tuf_fixture/mirror" "$RUN_OUT" >/dev/null || fail "verify live tuf file url payload"
  pass "verify live tuf file url success"
else
  pass "verify live tuf integration skipped because cosign or python is unavailable"
fi

binary="$artifact_dir/tool-exec"
printf '#!/bin/sh\necho hello\n' > "$binary"
chmod +x "$binary"
MOCK_CURL_MODE=release_success MOCK_PODMAN_LOG="$tmp/podman.log" run_json binary_exec binary exec "$binary" --json -- --version
[[ "$RUN_RC" == "0" ]] || fail "binary exec rc=$RUN_RC"
jq -e '.verdict == "GO" and .data.runtime_status == "ok" and (.data.stdout_summary | contains("podman stdout summary")) and (.data.stderr_summary | contains("podman stderr summary"))' "$RUN_OUT" >/dev/null || fail "binary exec payload"
grep -q -- '--network=none' "$tmp/podman.log" || fail "binary exec missing --network=none"
grep -q -- '--read-only' "$tmp/podman.log" || fail "binary exec missing --read-only"
grep -q -- '--tmpfs' "$tmp/podman.log" || fail "binary exec missing --tmpfs"
grep -q -- '^HOME=/tmp/home$' "$tmp/podman.log" || fail "binary exec missing writable HOME"
grep -q -- '^XDG_CONFIG_HOME=/tmp/xdg-config$' "$tmp/podman.log" || fail "binary exec missing writable XDG_CONFIG_HOME"
grep -q -- '^XDG_CACHE_HOME=/tmp/xdg-cache$' "$tmp/podman.log" || fail "binary exec missing writable XDG_CACHE_HOME"
grep -q -- '^XDG_STATE_HOME=/tmp/xdg-state$' "$tmp/podman.log" || fail "binary exec missing writable XDG_STATE_HOME"
grep -q -- '/artifact:ro,z' "$tmp/podman.log" || fail "binary exec missing read-only artifact bind"
jq -e '
  .data.sandbox_env == {
    "HOME": "/tmp/home",
    "XDG_CONFIG_HOME": "/tmp/xdg-config",
    "XDG_CACHE_HOME": "/tmp/xdg-cache",
    "XDG_STATE_HOME": "/tmp/xdg-state"
  }
  and (.checks[] | select(.id == "sandbox_policy") | .data.env) == .data.sandbox_env
' "$RUN_OUT" >/dev/null || fail "binary exec writable env payload"
pass "binary exec sandbox command and output capture"

MOCK_CURL_MODE=release_success MOCK_PODMAN_LOG="$tmp/podman-xdg.log" MOCK_PODMAN_TOUCH_XDG=1 run_json binary_exec_xdg binary exec "$binary" --json -- --version
[[ "$RUN_RC" == "0" ]] || fail "binary exec xdg rc=$RUN_RC"
jq -e '.verdict == "GO" and .data.runtime_status == "ok" and (.data.stdout_summary | contains("config/cache/state paths are writable"))' "$RUN_OUT" >/dev/null || fail "binary exec xdg payload"
pass "binary exec writable HOME/XDG behavior"
