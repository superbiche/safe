#!/usr/bin/env bash
# Explicit opt-in live probe: safe-audit's composed syft exclusions must be
# grammar-valid for the REAL syft on this machine and must exclude exactly the
# intended package set. The hermetic smoke suite pins the emitted strings; this
# catches a syft whose matcher disagrees with them (it is how a single nested
# repository silently cost a target its whole SBOM). Run
# `bash tests/live/syft_exclude_oracle.sh` manually; it is excluded from
# tests/run-all.sh because it needs an installed syft binary.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=tests/lib/real-tool.sh
source "$ROOT/tests/lib/real-tool.sh"

pass() { printf 'ok - %s\n' "$*"; }
fail() { printf 'not ok - %s\n' "$*" >&2; exit 1; }

SYFT_BIN="${SYFT_BIN:-$(real_tool syft || true)}"
if [[ -z "$SYFT_BIN" ]]; then
  printf 'SKIP syft_exclude_oracle: no real syft on PATH (set SYFT_BIN to override)\n'
  exit 0
fi

bash -n "$ROOT/bin/safe-audit"

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

# The scan root is itself a repository (root .git), holding: the project's own
# package, a workspace package, a submodule, a config-ignored vendor/ tree, a
# nested clone, and a nested clone whose NAME carries glob metacharacters
# (bracket and brace flavors, each with a lookalike sibling that must
# survive). The root config also exercises the authored-prefix shapes (`./x`
# root-only, `*/x` one level, `**/x` any depth) with deeper lookalikes that
# must NOT be excluded, and a nested config whose ignore is scoped to its own
# directory (deeper names inside excluded, same-named paths outside kept).
fix="$scratch/scanroot"
mkdir -p "$fix/.git" \
  "$fix/app" \
  "$fix/packages/lib" \
  "$fix/sub" \
  "$fix/vendor" \
  "$fix/clone[1]/.git" \
  "$fix/brace{a,b}/.git" \
  "$fix/bracea" \
  "$fix/rootonly" \
  "$fix/deep/rootonly" \
  "$fix/onelevel" \
  "$fix/deep/onelevel" \
  "$fix/deep/nested/onelevel" \
  "$fix/discard" \
  "$fix/cfg/keep" \
  "$fix/cfg/ignored" \
  "$fix/cfg/deep/ignored" \
  "$fix/other/cfg/ignored" \
  "$fix/deps-cache/uv/sdists-v9/.git"
cat > "$fix/.safe-audit" <<'YAML'
ignore:
  - vendor
  - ./rootonly
  - */onelevel
  - **/discard
YAML
cat > "$fix/cfg/.safe-audit" <<'YAML'
ignore:
  - ignored
YAML
mk_lock() { printf '{"name":"%s","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"%s","version":"1.0.0"}}}\n' "$1" "$1" > "$2"; }
mk_lock app "$fix/app/package-lock.json"
mk_lock lib "$fix/packages/lib/package-lock.json"
mk_lock sub "$fix/sub/package-lock.json"
mk_lock vendor "$fix/vendor/package-lock.json"
mk_lock clone1 "$fix/clone[1]/package-lock.json"
mk_lock brace2 "$fix/brace{a,b}/package-lock.json"
mk_lock sibling "$fix/bracea/package-lock.json"
mk_lock rootonly "$fix/rootonly/package-lock.json"
mk_lock deeprootonly "$fix/deep/rootonly/package-lock.json"
mk_lock onelevel "$fix/onelevel/package-lock.json"
mk_lock deeponelevel "$fix/deep/onelevel/package-lock.json"
mk_lock nestedonelevel "$fix/deep/nested/onelevel/package-lock.json"
mk_lock discard "$fix/discard/package-lock.json"
mk_lock cfgkeep "$fix/cfg/keep/package-lock.json"
mk_lock cfgignored "$fix/cfg/ignored/package-lock.json"
mk_lock cfgdeep "$fix/cfg/deep/ignored/package-lock.json"
mk_lock outside "$fix/other/cfg/ignored/package-lock.json"
mk_lock sdist "$fix/deps-cache/uv/sdists-v9/package-lock.json"
printf 'gitdir: %s/.git/modules/sub\n' "$fix" > "$fix/sub/.git"

mapfile -d '' -t exclude_args < <(
  SAFE_AUDIT_PATH="$ROOT/bin/safe-audit" FIXTURE="$fix" \
    bash -c 'set -- --version; source "$SAFE_AUDIT_PATH" >/dev/null
      gather_projects_from_source "$FIXTURE" 1 2>/dev/null
      syft_exclude_args_for_current_scan'
)
(( ${#exclude_args[@]} % 2 == 0 )) || fail "exclude args are not --exclude/value pairs"
(( ${#exclude_args[@]} > 0 )) || fail "no exclude args were composed for the fixture"

# The syft invocation must work from an unrelated cwd: patterns are resolved
# against the SOURCE, not the caller's directory.
sbom="$scratch/sbom.json"
if ! (cd / && "$SYFT_BIN" "dir:$fix" -o json "${exclude_args[@]}" > "$sbom" 2>"$sbom.stderr"); then
  printf 'not ok - real syft rejected the composed exclusions:\n' >&2
  cat "$sbom.stderr" >&2
  exit 1
fi
paths="$(jq -r '[.artifacts[].locations[].path] | unique | sort | map(select(endswith("package-lock.json"))) | join("\n")' "$sbom")"

# syft reports artifact locations relative to the scanned root, with a
# leading slash — assert on that canonical form so the probe stays
# independent of where the run happened to execute.
expect_present() {
  grep -Fxq "/$1" <<<"$paths" || fail "syft dropped an intended package: $1"
}
expect_absent() {
  if grep -Fxq "/$1" <<<"$paths"; then fail "syft kept a package it must exclude: $1"; fi
}

expect_present "app/package-lock.json"
expect_present "packages/lib/package-lock.json"
expect_present "sub/package-lock.json"
expect_present "bracea/package-lock.json"
expect_present "deep/rootonly/package-lock.json"
expect_present "deep/nested/onelevel/package-lock.json"
expect_present "cfg/keep/package-lock.json"
expect_present "other/cfg/ignored/package-lock.json"
expect_absent "vendor/package-lock.json"
expect_absent "clone[1]/package-lock.json"
expect_absent "brace{a,b}/package-lock.json"
expect_absent "rootonly/package-lock.json"
# `*/onelevel` is one level AS AUTHORED: it covers X/onelevel (and, via the
# paired `*/onelevel/**`, that subtree) but not `onelevel` itself, which has
# no preceding segment — on the find side the same shape (`-path root/*/x`)
# is equally blind to a root-level `x`. A two-level lookalike distinguishes
# the authored shape from a broadened `**/*/onelevel`.
expect_present "onelevel/package-lock.json"
expect_absent "deep/onelevel/package-lock.json"
expect_absent "discard/package-lock.json"
expect_absent "cfg/ignored/package-lock.json"
expect_absent "cfg/deep/ignored/package-lock.json"
expect_absent "deps-cache/uv/sdists-v9/package-lock.json"
pass "real syft accepts the exclusions and keeps exactly the intended package set"
