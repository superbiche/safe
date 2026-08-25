package releasereview

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// countLines reports how many lines a file holds, used to count how many times
// the fake cosign was invoked (it appends one line per verify-blob to
// MOCK_COSIGN_CALL_LOG).
func countLines(t *testing.T, path string) int {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	trimmed := strings.TrimRight(string(content), "\n")
	if trimmed == "" {
		return 0
	}
	return strings.Count(trimmed, "\n") + 1
}

// lowerCosignTimeout shortens the cosign subprocess deadline for one test and
// restores it afterward, so a test can drive a real timeout against a fake
// cosign asked to hang (MOCK_COSIGN_SLEEP) instead of waiting out the production
// two minutes. Tests using it must not run in parallel: the timeout is a
// process-global var, like PATH.
func lowerCosignTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	previous := cosignSubprocessTimeout
	cosignSubprocessTimeout = d
	t.Cleanup(func() { cosignSubprocessTimeout = previous })
}

// lowerCosignKillDelay shortens the WaitDelay grace for one test, so the
// pipe-drain stall an orphaned child produces (MOCK_COSIGN_ORPHAN) is reached in
// milliseconds instead of the production five seconds. Same non-parallel caveat.
func lowerCosignKillDelay(t *testing.T, d time.Duration) {
	t.Helper()
	previous := cosignKillDelay
	cosignKillDelay = d
	t.Cleanup(func() { cosignKillDelay = previous })
}

// The checks in this package shell out to cosign and podman, so the tests put
// fakes on PATH instead. The fakes are shell scripts driven by environment
// variables, mirroring the knobs the bash suites' mocks already expose
// (tests/audit/external_binary.sh), so a behavior pinned on one side is
// recognizable on the other.
//
// Tests using these must not run in parallel: PATH is process-global.

// mockIdentity and mockIssuer are the signer the fake cosign will accept. A
// policy naming anything else is what "the wrong signer" looks like here.
const (
	mockIdentity = "https://github.com/example/tool/.github/workflows/release.yml@refs/tags/v1.2.3"
	mockIssuer   = "https://token.actions.githubusercontent.com"
)

// fakeHelpers are the system tools the fake scripts themselves need. They are
// linked in because PATH is replaced rather than prepended: a real cosign on
// the developer's machine must not be reachable from a test that asked for
// none, and "tool missing" is otherwise not something a test can state.
var fakeHelpers = []string{"bash", "cat", "cp", "dirname", "mkdir", "sleep", "wc"}

// withFakeTools builds a bin dir holding the named fakes, points PATH at it
// alone, and returns the dir. Naming no tool is how a test says "this tool is
// not installed".
func withFakeTools(t *testing.T, tools ...string) string {
	t.Helper()
	bin := t.TempDir()

	for _, helper := range fakeHelpers {
		resolved, err := exec.LookPath(helper)
		if err != nil {
			t.Skipf("the fake tools need %s on PATH: %v", helper, err)
		}
		if err := os.Symlink(resolved, filepath.Join(bin, helper)); err != nil {
			t.Fatalf("link %s: %v", helper, err)
		}
	}
	for _, tool := range tools {
		script, ok := fakeScripts[tool]
		if !ok {
			t.Fatalf("no fake defined for %q", tool)
		}
		path := filepath.Join(bin, tool)
		if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
			t.Fatalf("write fake %s: %v", tool, err)
		}
	}

	t.Setenv("PATH", bin)
	return bin
}

var fakeScripts = map[string]string{"cosign": fakeCosign, "podman": fakePodman}

// fakeCosign answers verify-blob against a fixed signer and materializes a TUF
// cache for initialize. MOCK_COSIGN_BRIDGE_ROOT names the mirror directory it
// reads, exactly as the bash mock does — the loopback URL it is handed is not
// fetched, so the bridge gets its own unit test rather than being exercised
// only indirectly here.
//
// initialize derives each target's name and digest from the mirror blob's own
// `<sha>.<name>` filename (the convention buildTUFMirror lays down) rather than
// parsing targets.json, so the fake needs no jq — a helper whose absence would
// otherwise let every test in this package skip to a vacuous green.
const fakeCosign = `#!/usr/bin/env bash
set -euo pipefail

command_name="${1:-}"
shift || true

# MOCK_COSIGN_ORPHAN: cosign exits cleanly but leaves a child holding its stdout
# pipe past the parent's exit. os/exec then waits WaitDelay and gives up with
# exec.ErrWaitDelay — the pipe-drain stall, which is not the context deadline. A
# backgrounded sleep inherits stdout; the parent exits 0 at once.
if [[ -n "${MOCK_COSIGN_ORPHAN:-}" ]]; then
  sleep "$MOCK_COSIGN_ORPHAN" &
  exit 0
fi

# Per-invocation counter (verify-blob only): a test can both assert which calls
# were made (line count) and hang a chosen one.
call_index=0
if [[ "$command_name" == "verify-blob" && -n "${MOCK_COSIGN_CALL_LOG:-}" ]]; then
  printf 'x\n' >> "$MOCK_COSIGN_CALL_LOG"
  call_index=$(( $(wc -l < "$MOCK_COSIGN_CALL_LOG") ))
fi

# MOCK_COSIGN_SLEEP hangs every invocation; MOCK_COSIGN_SLEEP_ON_CALL hangs only
# the Nth verify-blob. exec replaces this shell so the deadline's SIGTERM lands
# on sleep directly rather than orphaning it behind bash — nothing after the
# sleep is meant to run when a test asks cosign to hang.
if [[ -n "${MOCK_COSIGN_SLEEP_ON_CALL:-}" ]]; then
  if [[ "$call_index" == "$MOCK_COSIGN_SLEEP_ON_CALL" ]]; then
    exec sleep "${MOCK_COSIGN_SLEEP:-5}"
  fi
elif [[ -n "${MOCK_COSIGN_SLEEP:-}" ]]; then
  exec sleep "$MOCK_COSIGN_SLEEP"
fi

case "$command_name" in
  verify-blob)
    identity=""; identity_regexp=""; issuer=""; issuer_regexp=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --certificate-identity) identity="$2"; shift 2 ;;
        --certificate-identity-regexp) identity_regexp="$2"; shift 2 ;;
        --certificate-oidc-issuer) issuer="$2"; shift 2 ;;
        --certificate-oidc-issuer-regexp) issuer_regexp="$2"; shift 2 ;;
        *) shift ;;
      esac
    done

    if [[ "${MOCK_COSIGN_BUNDLE_MODE:-ok}" == "fail" ]]; then
      printf 'bundle verification failed\n' >&2
      exit 1
    fi

    expected_identity="${MOCK_COSIGN_IDENTITY:?}"
    expected_issuer="${MOCK_COSIGN_ISSUER:?}"
    identity_ok=0
    issuer_ok=0
    [[ -n "$identity" && "$identity" == "$expected_identity" ]] && identity_ok=1
    [[ -n "$identity_regexp" && "$expected_identity" =~ $identity_regexp ]] && identity_ok=1
    [[ -n "$issuer" && "$issuer" == "$expected_issuer" ]] && issuer_ok=1
    [[ -n "$issuer_regexp" && "$expected_issuer" =~ $issuer_regexp ]] && issuer_ok=1

    # Split policy: each half of the policy verifies on its own, but the two
    # together do not. A multi-signature bundle can look like this, and it is
    # the shape that would let a failed verification report no reason at all.
    if [[ "${MOCK_COSIGN_SPLIT_POLICY:-0}" == "1" ]]; then
      if [[ -n "$identity_regexp" && "$identity_regexp" == ".*" ]] ||
         [[ -n "$issuer_regexp" && "$issuer_regexp" == ".*" ]]; then
        printf 'Verified OK\n'
        exit 0
      fi
      printf 'bundle signer policy mismatch\n' >&2
      exit 1
    fi

    if (( identity_ok == 1 && issuer_ok == 1 )); then
      printf 'Verified OK\n'
      exit 0
    fi
    printf 'bundle signer policy mismatch\n' >&2
    exit 1
    ;;
  initialize)
    if [[ "${MOCK_COSIGN_TUF_MODE:-ok}" == "fail" ]]; then
      printf 'tuf initialize failed\n' >&2
      exit 1
    fi
    if [[ "${MOCK_COSIGN_TUF_MODE:-ok}" == "empty" ]]; then
      printf 'Initialized\n'
      exit 0
    fi

    mirror_path="${MOCK_COSIGN_BRIDGE_ROOT:-}"
    repo_dir="$HOME/.sigstore/root/mock-tuf"
    targets_dir="$repo_dir/targets"
    mkdir -p "$targets_dir"
    if [[ -f "$mirror_path/targets.json" ]]; then
      cp "$mirror_path/targets.json" "$repo_dir/targets.json"
    fi
    if [[ -d "$mirror_path/targets" ]]; then
      for blob in "$mirror_path"/targets/*; do
        [[ -f "$blob" ]] || continue
        base="${blob##*/}"
        # Blobs are named <sha>.<name>; the sha is dot-free, so the first dot
        # splits the digest from the (possibly dotted) target name.
        target_name="${base#*.}"
        [[ -n "$target_name" ]] || continue
        case ",${MOCK_COSIGN_TUF_SKIP_TARGETS:-}," in
          *,"$target_name",*) continue ;;
        esac
        mkdir -p "$(dirname "$targets_dir/$target_name")"
        cp "$blob" "$targets_dir/$target_name"
      done
    fi
    printf 'Initialized\n'
    ;;
  *)
    printf 'unsupported mock cosign command: %s\n' "$command_name" >&2
    exit 1
    ;;
esac
`

// fakePodman logs the flags it was handed so the sandbox policy can be asserted
// on, and exits however the test asks. MOCK_PODMAN_SLEEP is how a test makes a
// run outlive its deadline.
const fakePodman = `#!/usr/bin/env bash
set -euo pipefail
if [[ -n "${MOCK_PODMAN_LOG:-}" ]]; then
  printf '%s\n' "$@" > "$MOCK_PODMAN_LOG"
fi
if [[ -n "${MOCK_PODMAN_SLEEP:-}" ]]; then
  sleep "$MOCK_PODMAN_SLEEP"
fi
# MOCK_PODMAN_SPEW_LINES makes the fake emit that many ~1 KiB lines to BOTH
# streams (pure bash builtins, no extra helper on PATH), standing in for a
# binary that floods its output past the reviewer's in-memory capture cap.
if [[ -n "${MOCK_PODMAN_SPEW_LINES:-}" ]]; then
  line="$(printf 'x%.0s' {1..1000})"
  for (( i = 0; i < MOCK_PODMAN_SPEW_LINES; i++ )); do
    printf '%s\n' "$line"
    printf '%s\n' "$line" >&2
  done
fi
printf 'podman stdout summary\n'
printf 'podman stderr summary\n' >&2
exit "${MOCK_PODMAN_RC:-0}"
`
