#!/usr/bin/env bash
# Shared helper: build the safe-core binary that decides verdicts under test.
#
# safe-audit resolves safe-core as its own sibling, which only exists in an
# installed layout. A suite that runs bin/safe-audit straight from the repo has
# no sibling, and since a missing verdict engine fails closed, every check
# would refuse as audit-infrastructure breakage. Such suites point
# SAFE_CORE_BIN at a freshly built binary instead.
#
# The binary is built from the working tree, not reused from an install, so a
# suite always exercises the decision layer it ships with rather than whatever
# happens to be installed on the host.

# safe_core_test_prepare <repo-root> <output-path>
# Exports SAFE_CORE_BIN on success. Returns non-zero if Go is unavailable or
# the build fails; callers decide whether that is a skip or a hard failure.
safe_core_test_prepare() {
  local root="$1" out="$2"

  if ! command -v go >/dev/null 2>&1; then
    printf 'SKIP: Go is unavailable; safe-core cannot be built\n' >&2
    return 1
  fi

  if ! ( cd "$root" && go build -trimpath \
      -ldflags "-X main.version=$(tr -d '[:space:]' < VERSION)" \
      -o "$out" ./cmd/safe-core ); then
    printf 'not ok - safe-core test binary build failed\n' >&2
    return 1
  fi

  export SAFE_CORE_BIN="$out"
  return 0
}
