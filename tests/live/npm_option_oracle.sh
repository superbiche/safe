#!/usr/bin/env bash
# LIVE suite — the gate's reading of npm's option syntax against the npm it delegates to (ticket 1675).
#
# npm parses its argument vector with nopt, which reads `--flag=value` as `--flag value`: a Boolean-typed flag
# leaves a value other than true/false as a positional argument, a String-typed one re-reads a value that
# looks like a flag. The gate's front door (safe_gate_npm_front_door) refuses every `=`-form value npm does
# not consume, from a snapshot of npm's option types (SAFE_GATE_NPM_OPTIONS / SAFE_GATE_NPM_SHORTHANDS).
# Read-only: Node imports npm's own parser and definitions; nothing is installed or run.
#
#   1. DRIFT      the shipped snapshot against the installed npm's definitions: every option and shorthand the
#                 npm defines is in the snapshot, with the same facts (the snapshot is a union over npm
#                 versions, so it may hold more).
#   2. READING    the bash reading (safe_gate_nopt_parse), over a snapshot of THIS npm alone, against npm's own
#                 parser on a generated corpus: the same positional arguments, the same global mode.
#   3. GATE       (SAFE_ORACLE_GATE=1: slow) the gate's whole reading, with the shipped snapshot, against npm's
#                 own on the corpus: for every command line the gate refuses or agrees with npm on the command,
#                 the packages it audits and the global mode. A disagreement that is not in
#                 tests/live/npm_option_oracle.known fails.
#
# Corpus size: tiny by default (one option in 16), SAFE_ORACLE_SAMPLE=N for one in N, SAFE_ORACLE_FULL=1 for all.
set -uo pipefail

# SAFE_TEST_ISOLATION_MARKER: every suite owns a scratch HOME and safe state.
# shellcheck source=tests/lib/test-isolation.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/test-isolation.sh"
export SAFE_TEST_ISOLATION_KEEP_TOOLS=1
safe_test_setup_isolation || exit 1

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
PASS=0
FAIL=0
pass() { printf 'ok - %s\n' "$1"; PASS=$((PASS + 1)); }
fail() { printf 'FAIL - %s\n' "$1"; FAIL=$((FAIL + 1)); }

# shellcheck source=/dev/null
source "$ROOT/lib/gate-lib.sh" >/dev/null 2>&1 || { printf 'FAIL - cannot source lib/gate-lib.sh\n'; exit 1; }

# The npm to read: SAFE_LIVE_NPM_DIR (the directory holding npm's package.json, e.g.
# ~/.local/share/mise/installs/node/<v>/lib/node_modules/npm), else the npm the gate delegates to.
if ! command -v node >/dev/null 2>&1; then
  printf 'SKIP: node is unavailable; the npm option oracle is skipped\n'
  exit 0
fi
if [[ -n "${SAFE_LIVE_NPM_DIR:-}" ]]; then
  npm_dir="${SAFE_LIVE_NPM_DIR%/}"
else
  real_npm="$(safe_gate_resolve_real npm 2>/dev/null || true)"
  if [[ -z "$real_npm" ]]; then
    printf 'SKIP: no real (non-wrapper) npm available; the npm option oracle is skipped\n'
    exit 0
  fi
  if ! prefix="$(safe_test_npm_global_prefix "$real_npm")"; then
    printf '%s\n' "$prefix"
    exit 0
  fi
  npm_dir="${prefix%/}/lib/node_modules/npm"
fi
if [[ ! -r "$npm_dir/node_modules/nopt/lib/nopt-lib.js" || ! -r "$npm_dir/node_modules/@npmcli/config/lib/definitions/index.js" ]]; then
  fail "npm's parser and definitions are unavailable at $npm_dir"
  printf '%s passed, %s failed\n' "$PASS" "$FAIL"
  exit 1
fi
printf '# npm: %s (%s)\n' "$npm_dir" "$(node -p "require('$npm_dir/package.json').version" 2>/dev/null)"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/safe-live-npm-option.XXXXXX") || exit 1
safe_test_compose_exit_trap "rm -rf -- \"\$WORK\""

# --- 1. drift --------------------------------------------------------------------------
if ! node "$ROOT/scripts/npm-option-snapshot.cjs" --one "$npm_dir" > "$WORK/installed" 2>"$WORK/installed.err"; then
  fail "the installed npm's definitions could not be read ($(head -n 1 "$WORK/installed.err"))"
else
  missing=""
  while IFS=$'\t' read -r kind name value; do
    if [[ "$kind" == opt ]]; then
      shipped=""
      for pair in "${SAFE_GATE_NPM_OPTIONS[@]}"; do [[ "${pair%%=*}" == "$name" ]] && shipped="${pair#*=}"; done
      [[ -n "$shipped" ]] || { missing="$missing $name(not in the snapshot)"; continue; }
      [[ "$shipped" == "-" ]] && shipped=""
      # the snapshot is a union: the installed letters must be among the shipped ones
      for (( i=0; i<${#value}; i++ )); do
        [[ "$shipped" == *"${value:i:1}"* ]] || missing="$missing $name(letter ${value:i:1})"
      done
    else
      shipped=""
      for pair in "${SAFE_GATE_NPM_SHORTHANDS[@]}"; do [[ "${pair%%=*}" == "$name" ]] && shipped="${pair#*=}"; done
      [[ "$shipped" == "$value" ]] || missing="$missing $name(shorthand: shipped '${shipped}' installed '${value}')"
    fi
  done < "$WORK/installed"
  if [[ -z "$missing" ]]; then
    pass "the shipped option snapshot covers the installed npm's options and shorthands"
  else
    fail "the option snapshot drifted from the installed npm:${missing}"
  fi
fi

# --- 2. the reading -----------------------------------------------------------------------
sample="${SAFE_ORACLE_SAMPLE:-16}"
[[ "${SAFE_ORACLE_FULL:-0}" != 1 ]] || sample=1
node "$ROOT/tests/lib/npm-option-corpus.cjs" "$npm_dir" --sample="$sample" > "$WORK/corpus" 2>"$WORK/corpus.err"
corpus_size="$(wc -l < "$WORK/corpus")"
printf '# corpus: %s cases (%s)\n' "$corpus_size" "$(cat "$WORK/corpus.err")"
if (( corpus_size < 100 )); then
  fail "the corpus is empty"
else
  out="$(
    # this npm alone: the reading is compared with the parser that ran, not with a union of versions
    source <(node "$ROOT/scripts/npm-option-snapshot.cjs" "$npm_dir")
    SAFE_GATE_NOPT_LOADED=""
    US=$'\x1f'; n=0; bad=0; shown=0
    while IFS=$'\x1e' read -r argsline remain global command pkgopt; do
      IFS="$US" read -r -a args <<<"$argsline"
      safe_gate_nopt_parse "${args[@]}"
      got="$(IFS="$US"; printf '%s' "${SAFE_GATE_NOPT_REMAIN[*]-}")"
      n=$((n + 1))
      if [[ "$got" != "$remain" || "$SAFE_GATE_NOPT_GLOBAL" != "$global" ]]; then
        bad=$((bad + 1))
        (( shown++ < 10 )) && printf 'DIFF %s\n' "${argsline//$US/ }"
      fi
    done < "$WORK/corpus"
    printf 'reading: %d cases, %d differ\n' "$n" "$bad"
  )"
  printf '%s\n' "$out" | sed 's/^/# /'
  if grep -q ' 0 differ$' <<<"$out"; then
    pass "the bash reading of npm's options equals npm's own parser on the corpus (positional arguments and global mode)"
  else
    fail "the bash reading differs from npm's parser"
  fi
fi

# --- 3. the gate ----------------------------------------------------------------------------
if [[ "${SAFE_ORACLE_GATE:-0}" == 1 ]]; then
  bash "$ROOT/tests/lib/npm-option-gate-oracle.sh" --show 100000 < "$WORK/corpus" > "$WORK/gate.out" 2>&1
  tail -n 6 "$WORK/gate.out" | sed 's/^/# /'
  known="$ROOT/tests/live/npm_option_oracle.known"
  unknown=0
  while IFS= read -r line; do
    [[ "$line" == DISAGREE* ]] || continue
    hit=0
    while IFS= read -r pat; do
      [[ -z "$pat" || "$pat" == \#* ]] && continue
      if [[ "$line" =~ $pat ]]; then hit=1; break; fi
    done < "$known"
    (( hit )) || { unknown=$((unknown + 1)); (( unknown <= 15 )) && printf '# unlisted: %s\n' "$line"; }
  done < "$WORK/gate.out"
  if (( unknown == 0 )); then
    pass "for every command line of the corpus the gate refuses or agrees with npm on the command, the packages it audits and the global mode (known residual disagreements aside, tests/live/npm_option_oracle.known)"
  else
    fail "$unknown disagreement(s) between the gate's reading and npm's that are not listed"
  fi
else
  printf '# the gate-level oracle is slow: SAFE_ORACLE_GATE=1 runs it\n'
fi

printf '%s passed, %s failed\n' "$PASS" "$FAIL"
(( FAIL == 0 ))
