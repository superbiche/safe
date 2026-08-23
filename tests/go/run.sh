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

if ! command -v go >/dev/null 2>&1; then
  if [[ "${SAFE_TEST_STRICT:-}" == "1" ]]; then
    printf 'FAIL: Go is unavailable and SAFE_TEST_STRICT=1; the Go parity belt must run\n' >&2
    exit 1
  fi
  printf 'SKIP: Go is unavailable; go vet ./... and go test ./... are skipped\n'
  exit 0
fi

cd "${ROOT}" || exit 1
go vet ./...
go test ./...
printf 'go: vet and tests passed\n'
