#!/usr/bin/env bash
# Go unit/analysis coverage belongs in the aggregate suite, not only in the
# install harness that happens to compile safe-core for wrapper cases. Keep
# explicit failure propagation: the aggregate runner must never turn a failed
# Go check into a false-green final printf. Self-test with an exported failing
# go function: this script and tests/run-all.sh must both return non-zero.
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)

if ! command -v go >/dev/null 2>&1; then
  printf 'SKIP: Go is unavailable; go vet ./... and go test ./... are skipped\n'
  exit 0
fi

cd "${ROOT}" || exit 1
go vet ./...
go test ./...
printf 'go: vet and tests passed\n'
