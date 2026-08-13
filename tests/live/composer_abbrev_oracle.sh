#!/usr/bin/env bash
# LIVE suite — verifies Composer's read-only help dispatch through the same
# real-tool resolver as the gate. No package command or registry access occurs.
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
PASS=0
FAIL=0

pass() { printf 'ok - %s\n' "$1"; PASS=$((PASS + 1)); }
fail() { printf 'FAIL - %s\n' "$1"; FAIL=$((FAIL + 1)); }

# shellcheck source=/dev/null
source "$ROOT/lib/gate-lib.sh" >/dev/null 2>&1 || {
  printf 'FAIL - cannot source lib/gate-lib.sh\n'
  exit 1
}

real_composer="$(safe_gate_resolve_real composer 2>/dev/null || true)"
if [[ -z "$real_composer" ]]; then
  printf 'SKIP: no real (non-wrapper) composer available; live abbreviation oracle skipped\n'
  exit 0
fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/safe-live-composer-abbrev.XXXXXX") || exit 1
trap 'rm -rf -- "$WORK"' EXIT
mkdir -p "$WORK/work" "$WORK/home"

# Every real Composer probe runs from an empty project with global plugins,
# scripts, and cache disabled. The oracle observes dispatch only; it must not
# activate a project/global plugin or reuse a real Composer cache.
probe_composer() {
  (
    cd "$WORK/work" || exit 1
    HOME="$WORK/home" \
      COMPOSER_HOME="$WORK/composer-home" \
      "$real_composer" --no-plugins --no-scripts --no-cache "$@"
  )
}

for token in u up Update; do
  if probe_composer "$token" --help > "$WORK/$token" 2>&1 \
    && grep -Eq '^[[:space:]]*update[[:space:]]' "$WORK/$token"; then
    pass "composer $token --help resolves to update"
  else
    fail "composer $token --help did not resolve to update"
  fi
done

# reinstall and create-project are gated, so their abbreviations must refuse in
# the gate. These probes prove the real Composer resolves those prefixes to the
# gated command — the empirical anchor for the noncanonical-refusal entries.
if probe_composer creat --help > "$WORK/creat" 2>&1 \
  && grep -Fq 'Creates new project from a package' "$WORK/creat"; then
  pass 'composer creat --help resolves to create-project'
else
  fail 'composer creat --help did not resolve to create-project'
fi
for token in reins reinst; do
  if probe_composer "$token" --help > "$WORK/$token" 2>&1 \
    && grep -Eq '^[[:space:]]*reinstall[[:space:]]' "$WORK/$token"; then
    pass "composer $token --help resolves to reinstall"
  else
    fail "composer $token --help did not resolve to reinstall"
  fi
done

# `global` is a proxy command and Symfony accepts every unique prefix. Asking
# for its own help proves dispatch without entering the global project or
# touching a registry.
for token in g globa; do
  if probe_composer "$token" --help > "$WORK/global-$token" 2>&1 \
    && grep -Fq 'Allows running commands in the global composer dir' "$WORK/global-$token"; then
    pass "composer $token --help resolves to global"
  else
    fail "composer $token --help did not resolve to global"
  fi
done

# The gate ships a command snapshot so it can refuse gated-looking aliases and
# abbreviations without asking Composer to load config on an install path. A
# Composer upgrade that adds an exact command overlapping those prefixes must
# fail loudly here rather than turn that exact command into a false refusal.
if probe_composer list --raw > "$WORK/commands" 2> "$WORK/commands.err"; then
  command_count=0
  while read -r command _; do
    [[ -n "$command" ]] || continue
    command_count=$((command_count + 1))
    # Symfony's retry is case-insensitive. Check both the installed spelling
    # and an upper-case variant, so an exact built-in always wins before the
    # gated-prefix refusal regardless of how the user typed it.
    for spelling in "$command" "${command^^}"; do
      if target="$(safe_gate_composer_noncanonical_target "$spelling")"; then
        fail "composer exact command $spelling would refuse as $target"
      fi
    done
  done < "$WORK/commands"
  if (( command_count == 0 )); then
    fail 'composer list --raw returned no exact command names'
  else
    pass "composer list --raw exact commands do not false-refuse ($command_count built-ins; case variants checked)"
  fi
else
  fail 'composer list --raw could not derive the exact-command refusal boundary'
fi

printf '%s passed, %s failed\n' "$PASS" "$FAIL"
(( FAIL == 0 ))
