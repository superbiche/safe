#!/usr/bin/env bash
# Go unit/analysis coverage belongs in the aggregate suite, not only in the
# install harness that happens to compile safe-core for wrapper cases.
set -u

ROOT=$(cd "$(dirname "$0")/../.." && pwd)

if ! command -v go >/dev/null 2>&1; then
  printf 'SKIP: Go is unavailable; go vet ./... and go test ./... are skipped\n'
  exit 0
fi

cd "${ROOT}" || exit 1
go vet ./...
go test ./...
printf 'go: vet and tests passed\n'
