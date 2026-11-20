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

HOME_REAL="$HOME"   # (the isolation below replaces HOME; the reference npm installs live under the real one)
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
# (npm 8 has no nopt-lib.js and keeps its definitions under lib/utils/config)
if [[ ! -r "$npm_dir/node_modules/nopt/package.json" ]] || { [[ ! -r "$npm_dir/node_modules/@npmcli/config/lib/definitions/index.js" ]] && [[ ! -r "$npm_dir/lib/utils/config/definitions.js" ]]; }; then
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
  while IFS=$'\t' read -r kind name value lits; do
    if [[ "$kind" == opt ]]; then
      # the reading of this npm must be one the snapshot lists: among the variants of a version-dependent name, the
      # shipped one otherwise
      reading="${value:--}${lits:+:$lits}"
      listed=""
      for pair in "${SAFE_GATE_NPM_VARIANT_OPTIONS[@]}"; do
        [[ "${pair%%=*}" == "$name" ]] && listed=";${pair#*=};"
      done
      if [[ -n "$listed" && "$listed" != *";${reading};"* ]]; then
        missing="$missing $name(reading ${reading} is not among its variants)"
      elif [[ -z "$listed" ]]; then
        for pair in "${SAFE_GATE_NPM_OPTIONS[@]}"; do
          [[ "${pair%%=*}" == "$name" && "${pair#*=}" != "$reading" && "${pair#*=}" != "${reading}:" ]] && missing="$missing $name(shipped ${pair#*=}, installed ${reading}, and not a listed variant)"
        done
      fi
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
# The corpus is made of the union of the names the reference npm versions define (SAFE_LIVE_NPM_REFERENCES, a
# comma separated list of npm directories; default: every npm of the mise node installs), read by THIS npm's own parser:
# a name this npm does not define is tried against it as the unknown name it is to it.
references="${SAFE_LIVE_NPM_REFERENCES:-}"
if [[ -z "$references" ]]; then
  for d in "${HOME_REAL:-$HOME}"/.local/share/mise/installs/node/*.*.*/lib/node_modules/npm; do
    [[ -r "$d/package.json" ]] && references="${references:+$references,}$d"
  done
fi
node "$ROOT/tests/lib/npm-option-corpus.cjs" "$npm_dir" ${references:+--union="$references"} --sample="$sample" > "$WORK/corpus" 2>"$WORK/corpus.err"
corpus_rc=$?
corpus_size="$(wc -l < "$WORK/corpus")"
# a producer that failed after writing rows must not set its own denominator
if (( corpus_rc != 0 )); then
  fail "the corpus producer failed (status $corpus_rc: $(head -n 1 "$WORK/corpus.err")); its output is not used"
  printf '%s passed, %s failed\n' "$PASS" "$FAIL"
  exit 1
fi
printf '# corpus: %s cases (%s)\n' "$corpus_size" "$(cat "$WORK/corpus.err")"
if (( corpus_size < 100 )); then
  fail "the corpus is empty"
else
  out="$(
    # this npm alone: the reading is compared with the parser that ran, not with a union of versions
    source <(node "$ROOT/scripts/npm-option-snapshot.cjs" "$npm_dir")
    SAFE_GATE_NOPT_LOADED=""
    US=$'\x1f'; n=0; bad=0; shown=0
    # shellcheck source=tests/lib/npm-option-corpus.sh
    source "$ROOT/tests/lib/npm-option-corpus.sh"
    n=0; bad=0; shown=0
    npm_major="$(node -p "require('$npm_dir/package.json').version.split('.')[0]")"
    while IFS=$'\t' read -r f_args f_remain f_global f_command f_pkgopt f_call f_locglobal; do
      npm_corpus_list "$f_args" args
      npm_corpus_list "$f_remain" want
      safe_gate_nopt_parse "${args[@]}"
      n=$((n + 1))
      got="$(printf '%s\x1f' "${SAFE_GATE_NOPT_REMAIN[@]}")"; wantj="$(printf '%s\x1f' "${want[@]}")"
      # the gate's reading takes --global only; the location counts for the npm that acts on it (npm 9 and later)
      gate_mode="$SAFE_GATE_NOPT_GLOBAL"
      (( npm_major >= 9 )) && [[ "$SAFE_GATE_NOPT_LOCGLOBAL" == 1 ]] && gate_mode=1
      if [[ "$got" != "$wantj" || "$gate_mode" != "$f_global" || "$SAFE_GATE_NOPT_LOCGLOBAL" != "${f_locglobal:-0}" ]]; then
        bad=$((bad + 1))
        (( shown++ < 10 )) && printf 'DIFF %s\n' "${f_args}"
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

# --- 2b. the global-mode controls (read-only: `npm prefix` installs, fetches and runs nothing) ------------------
# What THIS npm acts on: `npm --location global prefix` prints the installation prefix on npm 9 and later and the
# project prefix on npm 8.1.0 (which parses the location and does not act on it); `-g` prints the installation prefix on
# all of them. The corpus's global-mode field is derived from the same rule, so this is the control that it is true.
ctrl_home="$WORK/ctrl-home"; ctrl_proj="$WORK/ctrl-proj"; mkdir -p "$ctrl_home" "$ctrl_proj"
printf '{"name":"ctrl","version":"1.0.0"}\n' > "$ctrl_proj/package.json"
node_bin="$(dirname "$(dirname "$(dirname "$npm_dir")")")/bin/node"
[[ -x "$node_bin" ]] || node_bin="$(command -v node)"
prefix_of() { ( cd "$ctrl_proj" && env -i HOME="$ctrl_home" PATH="$(dirname "$node_bin"):/usr/bin:/bin" "$node_bin" "$npm_dir/bin/npm-cli.js" "$@" prefix 2>/dev/null | head -n 1 ); }
ctrl_loc="$(prefix_of --location global)"; ctrl_g="$(prefix_of -g)"; ctrl_plain="$(prefix_of)"
npm_major="$(node -p "require('$npm_dir/package.json').version.split('.')[0]")"
if [[ -z "$ctrl_g" || "$ctrl_g" == "$ctrl_plain" ]]; then
  printf '# the mode controls could not tell -g from the project (%s): skipped\n' "${ctrl_g:-no output}"
elif [[ "$ctrl_g" != "$ctrl_proj"* ]] && { { (( npm_major >= 9 )) && [[ "$ctrl_loc" == "$ctrl_g" ]]; } || { (( npm_major < 9 )) && [[ "$ctrl_loc" == "$ctrl_plain" ]]; }; }; then
  pass "this npm acts on --location global as the corpus assumes (location acts from npm 9 on): -g and the location give the installation prefix, or the location the project's on npm 8"
else
  fail "this npm's mode controls disagree with the corpus rule (-g: $ctrl_g, --location global: $ctrl_loc, plain: $ctrl_plain)"
fi

# --- 3. the gate ----------------------------------------------------------------------------
if [[ "${SAFE_ORACLE_GATE:-0}" == 1 ]]; then
  bash "$ROOT/tests/lib/npm-option-gate-oracle.sh" --show 100000 --expect "$corpus_size" < "$WORK/corpus" > "$WORK/gate.out" 2>&1
  gate_rc=$?
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
  # the helper's own failure (an incomplete run, a harness error, a disagreement) fails the suite even when no line is read
  if (( gate_rc == 2 )) || ! grep -q '^oracle: [0-9]* cases' "$WORK/gate.out"; then
    fail "the gate-level oracle did not complete (status $gate_rc)"
  elif (( unknown == 0 && (gate_rc == 0 || $(grep -c '^DISAGREE' "$WORK/gate.out") > 0) )); then
    pass "for every command line of the corpus the gate refuses or agrees with npm on the command, the packages it audits (name and version), the delegation, the project scan and the global mode (known residual disagreements aside, tests/live/npm_option_oracle.known)"
  else
    fail "$unknown disagreement(s) between the gate's reading and npm's that are not listed (helper status $gate_rc)"
  fi
else
  printf '# the gate-level oracle is slow: SAFE_ORACLE_GATE=1 runs it\n'
fi

printf '%s passed, %s failed\n' "$PASS" "$FAIL"
(( FAIL == 0 ))
