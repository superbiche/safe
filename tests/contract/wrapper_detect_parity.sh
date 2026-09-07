#!/usr/bin/env bash
# Regression: the belt's `real_tool_is_wrapper` (tests/lib/real-tool.sh) must
# agree with the gate's `safe_gate_is_wrapper` (lib/gate-lib.sh) on what a safe
# gate wrapper is. They are deliberately SEPARATE copies — the parity belt must
# not source the gate library it exists to test — so nothing but this suite
# stops them drifting apart. PR #142 review F1 was exactly such a drift: the
# belt scanned the whole 4096-byte probe while the gate accepts the marker only
# in the first two lines, so a real `go` with the marker in a later comment was
# a wrapper to the belt and real to the gate.

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
# gate-lib defines safe_gate_is_wrapper + SAFE_GATE_MARKER_PROBE_BYTES; real-tool
# defines real_tool_is_wrapper. Both are plain libraries, safe to source.
source "$ROOT/lib/gate-lib.sh"
source "$ROOT/tests/lib/real-tool.sh"

PASS_COUNT=0
FAIL_COUNT=0
pass() { PASS_COUNT=$((PASS_COUNT + 1)); printf 'ok - %s\n' "$1"; }
fail() { FAIL_COUNT=$((FAIL_COUNT + 1)); printf 'not ok - %s\n' "$1" >&2; }

# Both detectors must return the SAME verdict on a fixture.
check_parity() {
  local name="$1" file="$2" g b
  safe_gate_is_wrapper "$file" && g=wrapper || g=real
  real_tool_is_wrapper "$file" && b=wrapper || b=real
  if [[ "$g" == "$b" ]]; then
    pass "$name (both: $g)"
  else
    fail "$name (gate=$g belt=$b)"
  fi
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

printf '# safe-gate-wrapper v1 tool=go\nexec safe gate go -- "$@"\n' > "$tmp/l1"
check_parity "marker on line 1 is a wrapper" "$tmp/l1"

printf '#!/usr/bin/env bash\n# safe-gate-wrapper v1 tool=go\nexec safe gate go -- "$@"\n' > "$tmp/l2"
check_parity "marker on line 2 (canonical wrapper) is a wrapper" "$tmp/l2"

# The F1 divergence: a marker past line 2 must NOT count for either detector.
printf '#!/usr/bin/env bash\necho hi\n# safe-gate-wrapper stray comment\n' > "$tmp/l3"
check_parity "marker past line 2 is NOT a wrapper" "$tmp/l3"

printf '#!/usr/bin/env bash\necho real toolchain\n' > "$tmp/none"
check_parity "no marker is not a wrapper" "$tmp/none"

# ELF-shaped real binary (NUL bytes, no marker), like /usr/bin/go.
printf '\177ELF\0\0\0\0 real go binary \n' > "$tmp/elf"
check_parity "binary without marker is not a wrapper" "$tmp/elf"

# A marker beyond the 4096-byte probe must not count for either.
{ printf '#!/usr/bin/env bash\n'; head -c 5000 /dev/zero | tr '\0' 'x'; printf '\n# safe-gate-wrapper past the probe\n'; } > "$tmp/far"
check_parity "marker beyond the 4096-byte probe is not a wrapper" "$tmp/far"

# Direct assertion of the F1 regression (belt must treat a line-3 marker as real).
if real_tool_is_wrapper "$tmp/l3"; then
  fail "F1 regression: belt still flags a line-3 marker as a wrapper"
else
  pass "F1 regression: belt treats a line-3 marker as a real toolchain"
fi

printf '\n%d passed, %d failed\n' "$PASS_COUNT" "$FAIL_COUNT"
[[ "$FAIL_COUNT" -eq 0 ]]
