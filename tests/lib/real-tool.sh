#!/usr/bin/env bash
# Shared helper: resolve the REAL toolchain binary for a tool, skipping safe's
# own gate wrapper.
#
# On a safe-gated machine `~/.local/bin/<tool>` is a generated gate wrapper
# (`exec safe gate <tool> -- "$@"`) that precedes the real toolchain on PATH.
# A test that BUILDS or RUNS the toolchain (the Go parity belt: `go build`,
# `go vet`, `go test`) must call the toolchain DIRECTLY — routing the belt's
# own build through the live gate is non-hermetic (audit + host-allow-log
# side effects, and a hard failure when $HOME is read-only), and the belt is
# harness, not a package install to audit. (PR #141 review F1.)
#
# Detection mirrors gate-lib.sh `safe_gate_is_wrapper` EXACTLY: a generated
# wrapper carries `# safe-gate-wrapper` within the first TWO lines of its
# leading 4096 bytes. The two-line scope is load-bearing — scanning the whole
# probe would treat a real toolchain whose LATER content happens to contain the
# marker bytes as a wrapper, so the belt would refuse a `go` the live gate
# accepts as real (PR #142 review F1). Kept as a small self-contained copy so
# the belt does not source — and so cannot be broken by — the gate library it
# exists to test; `tests/contract/wrapper_detect_parity.sh` guards the two
# detectors against drifting apart.

# real_tool_is_wrapper <path> — true when <path> is a safe gate wrapper.
real_tool_is_wrapper() {
  local line i=0
  while (( i < 2 )) && IFS= read -r line; do
    i=$((i + 1))
    case "$line" in
      *'# safe-gate-wrapper'*) return 0 ;;
    esac
  done < <(LC_ALL=C head -c 4096 -- "$1" 2>/dev/null | tr -d '\0')
  return 1
}

# real_tool <name> — print the absolute path of the first <name> on PATH that
# is NOT a safe gate wrapper, and return 0. Return non-zero (printing nothing)
# when <name> is absent, or present ONLY as the gate wrapper with no real
# toolchain behind it. Callers use `command -v <name>` to tell the two apart
# for an accurate skip/fail message.
real_tool() {
  local tool="$1" dir cand IFS=:
  for dir in $PATH; do
    # An empty PATH element means cwd; never resolve a toolchain from there.
    cand="$dir/$tool"
    [[ -n "$dir" && -x "$cand" && ! -d "$cand" ]] || continue
    real_tool_is_wrapper "$cand" && continue
    printf '%s\n' "$cand"
    return 0
  done
  return 1
}
