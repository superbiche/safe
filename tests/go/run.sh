#!/usr/bin/env bash
# Go unit/analysis coverage belongs in the aggregate suite, not only in the
# install harness that happens to compile safe-core for wrapper cases. Keep
# explicit failure propagation: the aggregate runner must never turn a failed
# Go check into a false-green final printf. Self-test with an exported failing
# go function: this script and tests/run-all.sh must both return non-zero.
# Under SAFE_TEST_STRICT=1 (exported by tests/run-all.sh) a missing Go
# toolchain is a failure, not a skip: an unrun belt must read red.
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)

# Resolve the real go toolchain, never safe's own gate wrapper — the belt must
# not route `go vet`/`go test` through the live gate (real-tool.sh).
# shellcheck source=tests/lib/real-tool.sh
source "${ROOT}/tests/lib/real-tool.sh"
if ! GO="$(real_tool go)"; then
  if command -v go >/dev/null 2>&1; then
    reason="go on PATH is only safe's gate wrapper, no real toolchain behind it"
  else
    reason="Go is unavailable"
  fi
  if [[ "${SAFE_TEST_STRICT:-}" == "1" ]]; then
    printf 'FAIL: %s and SAFE_TEST_STRICT=1; the Go parity belt must run\n' "$reason" >&2
    exit 1
  fi
  printf 'SKIP: %s; go vet ./... and go test ./... are skipped\n' "$reason"
  exit 0
fi

cd "${ROOT}" || exit 1

# Formatting is part of the belt: unformatted Go landed once (1.47.0) because
# nothing checked, and stayed on main for two weeks. gofmt -l prints offenders
# and says nothing when clean; the tracked-dir list keeps it off fixtures.
unformatted=$(gofmt -l cmd internal)
if [[ -n "${unformatted}" ]]; then
  printf 'FAIL: gofmt drift in:\n%s\n' "${unformatted}" >&2
  exit 1
fi

"$GO" vet ./...
"$GO" test ./...
printf 'go: gofmt, vet and tests passed\n'
