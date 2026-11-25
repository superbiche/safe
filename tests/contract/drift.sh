#!/usr/bin/env bash
# Agent-contract single-source suite.
#
# The contract used to live in three hand-written places: the `safe explain`
# heredoc, the tables in docs/agents.md, and whatever a harness instruction
# file had copied. They drifted — an agent reading the docs and an agent
# running `safe explain` were told different things about the same gate, and
# nothing failed when they diverged.
#
# docs/contract/agent-contract.json is now the only source. This suite is what
# makes that true rather than aspirational: it fails when a rendered surface
# stops matching the source, and when a claim the contract makes stops matching
# what the code actually does.

set -euo pipefail

# SAFE_TEST_ISOLATION_MARKER: every suite owns a scratch HOME and safe state.
# shellcheck source=tests/lib/test-isolation.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/test-isolation.sh"
safe_test_setup_isolation || exit 1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SAFE="$ROOT/bin/safe"
CONTRACT="$ROOT/docs/contract/agent-contract.json"

PASS_COUNT=0
FAIL_COUNT=0
pass() { printf 'ok - %s\n' "$*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { printf 'not ok - %s\n' "$*" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }

TEST_ROOT="$(mktemp -d)"
safe_test_compose_exit_trap "rm -rf \"\$TEST_ROOT\""

# --- the source itself ------------------------------------------------------

case_contract_is_valid_json() {
  if jq -e . >/dev/null 2>&1 < "$CONTRACT"; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME"
  fi
}

case_contract_has_every_required_key() {
  # A missing key renders as an empty section rather than an error, so the
  # shape is asserted explicitly.
  if jq -e '
    .schema_version and .title and .intro and .one_rule
    and (.gated_surfaces | type == "array" and length > 0)
    and (.exit_codes | type == "array" and length > 0)
    and (.agent_rules | type == "array" and length > 0)
    and (.escalation | type == "array" and length > 0)
    and .version_resolution.rule and .version_resolution.never_latest
    and .report_fp.command and .report_fp.contract
    and (.allow_flows | type == "array" and length > 0)
    and .harness_snippet
  ' >/dev/null 2>&1 < "$CONTRACT"; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME"
  fi
}

case_every_exit_code_tells_an_agent_what_to_do() {
  # An exit code with no agent_action is a code an agent has to guess about,
  # which is how bypasses get invented.
  local bad
  bad="$(jq -r '[.exit_codes[] | select((.agent_action // "") == "") | .code] | join(", ")' < "$CONTRACT")"
  if [[ -z "$bad" ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (codes without agent_action: $bad)"
  fi
}

# --- rendered surfaces stay in sync -----------------------------------------

case_docs_are_not_stale() {
  if "$ROOT/scripts/render-contract.sh" --check >/dev/null 2>&1; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (run scripts/render-contract.sh)"
  fi
}

case_hand_editing_a_generated_block_is_caught() {
  # The guard has to actually fire, or "docs are not stale" passes forever by
  # accident. Edit a copy and prove --check rejects it.
  local sandbox="$TEST_ROOT/sandbox"
  mkdir -p "$sandbox"
  cp -rL "$ROOT/docs" "$ROOT/scripts" "$ROOT/share" "$sandbox/"
  "$sandbox/scripts/render-contract.sh" --check >/dev/null 2>&1 || {
    fail "$FUNCNAME (the unedited copy does not pass --check)"
    return
  }
  [[ -f "$sandbox/docs/agents.md" && ! -L "$sandbox/docs/agents.md" ]] || {
    fail 'generated surface copy is not a regular file'
    return
  }
  # Inside a generated block — an edit OUTSIDE the markers is legitimate
  # hand-written prose and must keep passing.
  sed -i 's/^| 100 |/| 100 | HAND EDITED |/' "$sandbox/docs/agents.md"
  # Re-anchor the copy's ROOT by running the copied script from the copy.
  if "$sandbox/scripts/render-contract.sh" --check >/dev/null 2>&1; then
    fail "$FUNCNAME (a hand-edited doc passed --check)"
    return
  fi
  # The agent skill is a rendered surface too.
  cp "$ROOT/docs/agents.md" "$sandbox/docs/agents.md"
  sed -i 's/^| 102 |/| 102 | HAND EDITED |/' "$sandbox/share/agent/skills/safe/SKILL.md"
  if "$sandbox/scripts/render-contract.sh" --check >/dev/null 2>&1; then
    fail "$FUNCNAME (a hand-edited agent skill passed --check)"
  else
    pass "$FUNCNAME"
  fi
}

case_release_follow_tree_has_no_gitattributes() {
  local tracked_files
  # The follower refuses a signed .gitattributes because reproducing Git's
  # archive attribute transformations inside the tree-hash check is unsafe.
  tracked_files=$(git -C "$ROOT" ls-files) || {
    fail 'release-follow tree could not be enumerated'
    return
  }
  if grep -Eq '(^|/)\.gitattributes$' <<<"$tracked_files"; then
    fail 'release-follow refuses .gitattributes trees'
  else
    pass 'release-follow tree has no .gitattributes'
  fi
}

case_explain_json_is_the_contract_verbatim() {
  local emitted
  emitted="$(SAFE_AGENT_CONTRACT="$CONTRACT" "$SAFE" explain --json)"
  if diff -q <(jq -S . < "$CONTRACT") <(jq -S . <<<"$emitted") >/dev/null 2>&1; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME"
  fi
}

case_explain_text_renders_from_the_contract() {
  # Not a golden-file comparison: those rot on every wording change. Instead,
  # assert that content only present in the JSON reaches the text.
  local out
  out="$(SAFE_AGENT_CONTRACT="$CONTRACT" "$SAFE" explain)"
  local code missing=""
  while read -r code; do
    grep -Fq "  ${code}  " <<<"$out" || missing="${missing} ${code}"
  done < <(jq -r '.exit_codes[].code' < "$CONTRACT")
  if [[ -n "$missing" ]]; then
    fail "$FUNCNAME (exit codes missing from text:${missing})"
    return
  fi
  grep -Fq "$(jq -r '.report_fp.command' < "$CONTRACT")" <<<"$out" || {
    fail "$FUNCNAME (report-fp command missing)"; return
  }
  grep -Fq "$(jq -r '.refusal_format' < "$CONTRACT")" <<<"$out" || {
    fail "$FUNCNAME (refusal format missing)"; return
  }
  pass "$FUNCNAME"
}

case_explain_fails_loudly_without_a_contract() {
  # Silently printing nothing would leave an agent with no contract and no
  # signal that it is missing one.
  # Run a copy from a directory with no ../docs and a HOME with no installed
  # contract, so every candidate in the resolution chain genuinely misses.
  local isolated="$TEST_ROOT/isolated/bin"
  mkdir -p "$isolated"
  cp "$SAFE" "$isolated/safe"
  local status=0
  HOME="$TEST_ROOT/isolated" SAFE_CONFIG_DIR="$TEST_ROOT/isolated/.config/safe" \
    "$isolated/safe" explain >/dev/null 2>"$TEST_ROOT/err" || status=$?
  if (( status != 0 )) && grep -Fq 'agent contract not found' "$TEST_ROOT/err"; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (status $status)"
  fi
}

case_malformed_contract_is_refused() {
  printf '{"schema_version": 1, "title": "trunc' > "$TEST_ROOT/bad.json"
  local status=0
  SAFE_AGENT_CONTRACT="$TEST_ROOT/bad.json" "$SAFE" explain >/dev/null 2>"$TEST_ROOT/err2" || status=$?
  if (( status != 0 )) && grep -Fq 'not readable JSON' "$TEST_ROOT/err2"; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (status $status)"
  fi
}

# --- the contract must not lie about the code -------------------------------

case_exit_codes_match_the_dispatcher() {
  # A documented code that no refusal can emit, or a refusal code that is
  # undocumented, is worse than no table: agents branch on these.
  local documented emitted
  documented="$(jq -r '[.exit_codes[].code | tostring] | sort | join(" ")' < "$CONTRACT")"
  emitted="$(
    { grep -oE 'refuse (1[0-9]{2})' "$ROOT/bin/safe" || true; } |
      awk '{print $2}' | sort -u | tr '\n' ' '
  )"
  local code missing=""
  for code in $emitted; do
    [[ " $documented " == *" $code "* ]] || missing="${missing} ${code}"
  done
  if [[ -z "$missing" ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (emitted but undocumented:${missing})"
  fi
}

case_version_constant_matches_version_file() {
  # Two version sources drifted at the 1.2.0 cut: the VERSION file was
  # bumped and the SAFE_VERSION constant in bin/safe was not, so the
  # installed binary reported the old release.
  local file_v const_v
  file_v="$(tr -d '[:space:]' < "$ROOT/VERSION")"
  const_v="$(sed -n 's/^SAFE_VERSION="\(.*\)"$/\1/p' "$ROOT/bin/safe" | head -n 1)"
  if [[ -n "$file_v" && "$file_v" == "$const_v" ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (VERSION file '$file_v' vs bin/safe SAFE_VERSION '$const_v')"
  fi
}

case_audit_version_constant_matches_version_file() {
  # bin/safe-audit carries its own expected version because it is installed as
  # a standalone executable and pins safe-core unconditionally. A third version
  # source is a third drift surface, so it is guarded like the first two.
  local file_v const_v
  file_v="$(tr -d '[:space:]' < "$ROOT/VERSION")"
  const_v="$(sed -n 's/^SAFE_VERSION="${SAFE_VERSION:-\(.*\)}"$/\1/p' "$ROOT/bin/safe-audit" | head -n 1)"
  if [[ -n "$file_v" && "$file_v" == "$const_v" ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (VERSION file '$file_v' vs bin/safe-audit SAFE_VERSION '$const_v')"
  fi
}

case_contract_never_suggests_latest() {
  # The standing operator ruling: allow entries are pinned to resolved
  # versions, and nothing safe prints may model `@latest` as acceptable.
  if grep -oE '[a-z>]+@latest' "$CONTRACT" | grep -qv 'pkg>@latest'; then
    fail "$FUNCNAME (a bare @latest suggestion is in the contract)"
    return
  fi
  # The two mentions that ARE allowed are the prohibitions themselves.
  if jq -e '(.version_resolution.never_latest | test("ALWAYS install exact pinned versions.*NEVER execute or hand the operator"))' >/dev/null 2>&1 < "$CONTRACT"; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (the never-latest rule is missing)"
  fi
}

case_gated_tools_match_the_installed_wrapper_set() {
  # docs claiming a tool is gated when install.sh writes no wrapper for it is
  # the drift that made agents trust a gate that was not there.
  local installed surface tool missing=""
  installed="$(sed -n 's/^GATE_TOOLS=(\(.*\))$/\1/p' "$ROOT/install.sh")"
  # Commas AND newlines collapse to spaces: the surfaces are separate records,
  # so a tool at the start of the second one is newline-preceded, not
  # space-preceded, and a naive match reports it missing.
  surface="$(jq -r '.gated_surfaces[].surface' < "$CONTRACT" | tr ',\n' '  ')"
  for tool in $installed; do
    [[ " $surface " == *" $tool "* ]] || missing="${missing} ${tool}"
  done
  if [[ -z "$missing" ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (wrapped but undocumented:${missing})"
  fi
}

case_gated_tool_lists_stay_in_sync() {
  # The install list is the deployable wrapper set. The dispatcher and safe-run
  # keep explicit copies so each executable can work without sourcing an
  # installer; drift would otherwise turn `safe run <tool>` into a bypass or a
  # surprising package fetch.
  local installed dispatcher runner
  installed="$(sed -n 's/^GATE_TOOLS=(\(.*\))$/\1/p' "$ROOT/install.sh")"
  dispatcher="$(sed -n 's/^SAFE_GATE_TOOL_LIST=(\(.*\))$/\1/p' "$ROOT/bin/safe")"
  runner="$(sed -n 's/^SAFE_RUN_GATED_TOOLS=(\(.*\))$/\1/p' "$ROOT/bin/safe-run")"
  if [[ -n "$installed" && "$installed" == "$dispatcher" && "$installed" == "$runner" ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (install='$installed' dispatcher='$dispatcher' safe-run='$runner')"
  fi
}

function_block() {
  local name="$1"
  awk -v start="${name}() {" '
    $0 == start { in_block=1; print; next }
    in_block && /^[A-Za-z_][A-Za-z0-9_]*\(\) \{$/ { exit }
    in_block { print }
  ' "$ROOT/lib/gate-lib.sh"
}

case_npm_classifier_snapshot_routes_every_alias() {
  # shellcheck source=/dev/null
  source "$ROOT/lib/gate-lib.sh"
  local kind key target expected actual bad=""
  while IFS=$'\t' read -r kind key target; do
    if [[ "$kind" == "command" ]]; then
      target="$key"
    else
      target="$(safe_gate_npm_deref_alias "$target")" || {
        bad="${bad} ${key}(broken-alias)"
        continue
      }
    fi
    expected="$(safe_gate_npm_target_class "$target")" || expected=""
    actual="$(safe_gate_npm_subcommand_class "$key")" || actual=""
    [[ "$actual" == "$expected" ]] || bad="${bad} ${key}=${actual:-passthrough}/${expected:-passthrough}"
  done < <(safe_gate_npm_dispatch_snapshot)

  if [[ -z "$bad" ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (classifier drift:${bad})"
  fi
}

case_npm_literal_sites_consult_the_classifier() {
  local audit_op lockdiff npm_like
  audit_op="$(function_block safe_gate_audit_op)"
  lockdiff="$(function_block safe_gate_npm_lockdiff_subcommand)"
  npm_like="$(function_block safe_gate_npm_like)"

  if [[ "$audit_op" == *safe_gate_npm_subcommand_class* &&
        "$lockdiff" == *safe_gate_npm_subcommand_class* &&
        "$npm_like" == *'npm_class="$(safe_gate_npm_subcommand_class'* &&
        "$npm_like" == *'case "${npm_class}" in'* &&
        "$npm_like" != *'npm:exec|npm:x'* ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (a former npm literal route bypasses the classifier)"
  fi
}

case_infra_cause_sets_match_between_gates() {
  # safe-audit routes an infra-only WARN to the TTY-override exit (11) using
  # GATE_INFRA_WARN_CAUSES; safe-run classifies the same causes for host-allow
  # review with HOST_ALLOW_REVIEW_INFRA_CAUSES. If the two sets drift, the two
  # gates disagree on what counts as an audit-infrastructure outage — one would
  # offer the honest override where the other treats the WARN as a finding.
  # They must be byte-identical.
  local audit_set run_set
  audit_set="$(sed -n "s/^GATE_INFRA_WARN_CAUSES='\(.*\)'$/\1/p" "$ROOT/bin/safe-audit" | head -n1)"
  run_set="$(sed -n "s/^HOST_ALLOW_REVIEW_INFRA_CAUSES='\(.*\)'$/\1/p" "$ROOT/bin/safe-run" | head -n1)"
  if [[ -n "$audit_set" && "$audit_set" == "$run_set" ]] && jq -e . >/dev/null 2>&1 <<<"$audit_set"; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (safe-audit '$audit_set' vs safe-run '$run_set')"
  fi
}

case_operator_terminal_helpers_match_between_gates() {
  # bin/safe loads lib/gate-lib.sh lazily, so it carries its own copy of the
  # operator-terminal predicate and prompt writer. Both copies must stay
  # byte-identical or the two install gates disagree on who the operator is.
  local fn lib_def safe_def
  for fn in safe_gate_operator_terminal safe_gate_tty_printf safe_gate_mirror_stderr; do
    lib_def="$(sed -n "/^${fn}() {$/,/^}$/p" "$ROOT/lib/gate-lib.sh")"
    safe_def="$(sed -n "/^${fn}() {$/,/^}$/p" "$ROOT/bin/safe")"
    if [[ -z "$lib_def" || "$lib_def" != "$safe_def" ]]; then
      fail "$FUNCNAME ($fn differs between lib/gate-lib.sh and bin/safe)"
      return
    fi
  done
  for fn in safe_gate_operator_terminal safe_gate_tty_printf safe_gate_mirror_stderr; do
    lib_def="$(sed -n "/^${fn}() {$/,/^}$/p" "$ROOT/lib/gate-lib.sh")"
    safe_def="$(sed -n "/^${fn}() {$/,/^}$/p" "$ROOT/bin/safe-run")"
    if [[ -z "$lib_def" || "$lib_def" != "$safe_def" ]]; then
      fail "$FUNCNAME ($fn differs between lib/gate-lib.sh and bin/safe-run)"
      return
    fi
  done
  # the core's writer of the standing decision (cmd/safe-core/one_shot.go) checks the same predicate itself: its marker list is the
  # shells' list, name for name, so a fifth marker cannot be added to one and not the other
  local shell_markers core_markers
  shell_markers="$(sed -n '/^safe_gate_operator_terminal() {$/,/^}$/p' "$ROOT/lib/gate-lib.sh" | grep -o '[A-Z_]*:-}' | sed 's/:-}//' | tr '\n' ' ')"
  core_markers="$(sed -n '/^var operatorMarkers = /p' "$ROOT/cmd/safe-core/one_shot.go" | grep -o '"[A-Z_]*"' | tr -d '"' | tr '\n' ' ')"
  if [[ -z "$shell_markers" || "$shell_markers" != "$core_markers" ]]; then
    fail "$FUNCNAME (the shells' agent markers [${shell_markers}] and the core's [${core_markers}] differ)"
    return
  fi
  pass "$FUNCNAME"
}

# The npm option snapshot (the front door's tables) is internally consistent, and the reading built on it
# behaves as nopt does on the facts the front door exists for. The live oracle (tests/live/npm_option_oracle.sh)
# compares the snapshot and the reading with the npm the gate delegates to; this is the hermetic half.
case_npm_option_snapshot_is_consistent_and_reads_like_nopt() {
  # shellcheck source=/dev/null
  source "$ROOT/lib/gate-lib.sh"
  local pair key letters tok bad="" prev="" short exp ok
  local LC_ALL=C
  # names sorted and unique, letters from the known set
  for pair in "${SAFE_GATE_NPM_OPTIONS[@]}"; do
    key="${pair%%=*}"; letters="${pair#*=}"
    [[ "${letters}" =~ ^(-|[ABSNTY]+(:[A-Za-z0-9_.,-]*)?)$ ]] || bad="${bad} ${key}(letters:${letters})"
    [[ -z "${prev}" || "${prev}" < "${key}" ]] || bad="${bad} ${key}(order)"
    prev="${key}"
  done
  # every option a shorthand expands to is a known option (or a negation of one)
  safe_gate_nopt_load
  for pair in "${SAFE_GATE_NPM_SHORTHANDS[@]}"; do
    short="${pair%%=*}"; exp="${pair#*=}"
    for tok in ${exp}; do
      [[ "${tok}" == --* ]] || continue
      key="${tok#--}"; key="${key#no-}"
      [[ -n "${SAFE_GATE_NOPT_FLAGS[${key}]+set}" ]] || bad="${bad} ${short}->${tok}(unknown option)"
    done
  done
  # nopt's facts: (arguments => the values it leaves loose; its positional arguments; global mode)
  check() { # <expected loose count> <expected remain, space-joined> <expected global> <args...>
    local want_loose="$1" want_remain="$2" want_global="$3"; shift 3
    safe_gate_nopt_parse "$@"
    [[ "${#SAFE_GATE_NOPT_LOOSE[@]}" == "${want_loose}" && "${SAFE_GATE_NOPT_REMAIN[*]-}" == "${want_remain}" && "${SAFE_GATE_NOPT_GLOBAL}" == "${want_global}" ]] \
      || bad="${bad} [$*]=>loose:${#SAFE_GATE_NOPT_LOOSE[@]},remain:${SAFE_GATE_NOPT_REMAIN[*]-},global:${SAFE_GATE_NOPT_GLOBAL}"
  }
  check 1 'install evil' 0 --json=install evil            # Boolean: the value stays an argument
  check 1 'install evil' 0 install --json=evil
  check 0 'install evil' 0 --json=true install evil       # true/false are consumed
  check 0 'install evil' 0 --json=false install evil
  check 0 'install evil' 0 --registry=https://r/ install evil   # a url-typed option consumes it
  check 0 'install evil' 1 -g install evil
  check 1 'install evil' 1 -g=install evil                # a shorthand is the Boolean it expands to
  check 1 'x install evil' 1 -gf=x install evil           # a cluster, the value left over
  check 1 'evil install' 0 --no-json=evil install         # --no- makes any option Boolean
  check 1 'install evil' 0 install --jso=evil             # an abbreviated name
  check 1 'install evil' 1 --tag=-g install evil          # a String option re-reads a value that looks like a flag (here: -g)
  check 0 'install evil' 0 --location=global install evil   # the location never decides the gate's global mode (npm 8.1.0 does not act on it) ...
  safe_gate_nopt_parse --location=global install evil
  [[ "${SAFE_GATE_NOPT_LOCGLOBAL}" == 1 ]] || bad="${bad} (--location=global is not seen as a global location)"   # ... it is seen, and the gate refuses it
  check 0 'install evil' 0 --frobnicate=x install evil    # an unknown name consumes it
  check 0 'install --json=evil' 0 install -- --json=evil  # after the terminator nothing is an option
  # the version-dependent names: each is a known option (or shorthand), has at least two distinct readings, and every
  # reading is `@` (a version that does not define it) or the same letters the union holds; the oldest reference is 8.1.0
  local r n
  for pair in "${SAFE_GATE_NPM_VARIANT_OPTIONS[@]}"; do
    key="${pair%%=*}"
    [[ -n "${SAFE_GATE_NOPT_FLAGS[${key}]+set}" ]] || bad="${bad} ${key}(variant of no known option)"
    IFS=';' read -r -a rs <<<"${pair#*=}"
    (( ${#rs[@]} >= 2 )) || bad="${bad} ${key}(variant with one reading)"
    for r in "${rs[@]}"; do
      [[ "${r}" == @ || "${r}" =~ ^(-|[ABSNTY]+)(:[A-Za-z0-9_.,-]*)?$ ]] || bad="${bad} ${key}(reading ${r})"
    done
  done
  for pair in "${SAFE_GATE_NPM_VARIANT_SHORTHANDS[@]}"; do
    key="${pair%%=*}"
    [[ -n "${SAFE_GATE_NOPT_SHORT[${key}]+set}" ]] || bad="${bad} ${key}(variant of no known shorthand)"
  done
  [[ " ${SAFE_GATE_NPM_REFERENCE_VERSIONS} " == *" 8.1.0 "* ]] || bad="${bad} (the reference versions do not include 8.1.0)"
  n=0; for pair in "${SAFE_GATE_NPM_VARIANT_OPTIONS[@]}"; do n=$((n + 1)); done
  (( n >= 40 )) || bad="${bad} (only ${n} version-dependent options)"
  # a version-dependent option is read every way: the five lines of the review each refuse or audit the package
  safe_gate_npm_variant_check install --allow-git evilpkg >/dev/null 2>&1 && bad="${bad} (--allow-git evilpkg went through)"
  safe_gate_npm_variant_check install --allow-git=none evilpkg >/dev/null 2>&1 || bad="${bad} (--allow-git=none refused)"
  if [[ -z "${bad}" ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (${bad# })"
  fi
}

# The project lane's refusals are terminal and its one question has one place (ticket 1686): tests/contract/lane_lint.py reads shell
# COMMANDS and where they sit (quoted text blanked, continuations joined, the function tracked), not substrings of a line.
case_lane_structure_lint_is_clean() {
  local found
  if found="$(python3 -I "${ROOT}/tests/contract/lane_lint.py" "${ROOT}/lib/gate-lib.sh")"; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (${found//$'\n'/; })"
  fi
}

# The mutations that slipped through the lints of earlier rounds are kept as fixtures the lint must reject: a diagnostic that contains
# the word `return`, a second question whose wording is on the next shell line, the hand-over status raised inside the runner or by a
# call of its helper, a second call of the question outside conclude, a plain removed return, a `return` that sits in a subshell
# while its owner goes on, a refusal in a pipeline, and a refusal that passes a kind outside the closed list. Also the state a
# confirmation rests on (the mark, the phase, the start-up-input flag) written anywhere but by its owner, a question asked through
# the outcome handler from a function that may not ask, a prompt called outside its loop, and a reserved status as a literal.
case_lane_structure_lint_rejects_the_known_mutations() {
  local dir="${TEST_ROOT}/lane-lint" bad="" name
  mkdir -p "${dir}"
  python3 -I - "${ROOT}/lib/gate-lib.sh" "${dir}" <<'PY' || { fail "$FUNCNAME (the fixtures could not be written)"; return; }
import re, sys
src = open(sys.argv[1], encoding="utf-8").read()
out = sys.argv[2]
def write(name, text):
    assert text != src, name
    open(f"{out}/{name}.sh", "w", encoding="utf-8").write(text)
def find(pattern):
    m = re.search(pattern, src)
    assert m, pattern
    return m
m = find(r'(safe_gate_project_lane_refuse 100 "\$\{verb\}" "admission returned no usable document[^\n]*\n)\s*return \$\?\n')
write("diagnostic-with-the-word-return", src[:m.start()] + m.group(1) + src[m.end():])
m = find(r'(safe_gate_project_lane_cleanup\(\) \{\n)')
write("second-question-on-the-next-line", src[:m.end()] + '  safe_gate_confirm_infra x "a" "b" \\\n    "run this command on the one-shot route? [y/N] "\n' + src[m.end():])
m = find(r'(safe_gate_project_lane_run\(\) \{\n)')
write("hand-over-in-the-runner", src[:m.end()] + "  SAFE_GATE_LANE_PASS=1\n" + src[m.end():])
c = find(r'(safe_gate_project_lane_cleanup\(\) \{\n)')
write("hand-over-helper-called-outside-its-owners", src[:c.end()] + "  safe_gate_project_lane_hand_over_silent\n  return $?\n" + src[c.end():])
write("question-outside-conclude", src[:m.end()] + "  safe_gate_project_lane_one_shot_question a b\n" + src[m.end():])
m = find(r'(safe_gate_project_lane_refuse 100 "\$\{verb\}" "the project directory cannot be read"[^\n]*\n)\s*return \$\?\n')
write("plain-return-removed", src[:m.start()] + m.group(1) + src[m.end():])
write("return-in-a-subshell", src[:m.start()] + "    ( " + m.group(1).lstrip() .rstrip("\n") + "; return $? )\n" + src[m.end():])
write("refusal-in-a-pipeline", src[:m.start()] + m.group(1).rstrip("\n").replace("safe_gate_project_lane_refuse 100", "safe_gate_project_lane_refuse 100", 1) + " | cat\n    return $?\n" + src[m.end():])
m = find(r'(safe_gate_project_lane_unsupported_kind command_form "\$\{verb\}" "an option before the verb")')
write("a-kind-outside-the-closed-list", src[:m.start()] + m.group(1).replace("command_form", "startup_input") + src[m.end():])
# the state a confirmation rests on, its askers and the reserved statuses (R6, R7, R8)
n = find(r'(safe_gate_project_lane_private_names\(\) \{\n)')
def inside(name, line):
    write(name, src[:n.end()] + line + src[n.end():])
inside("mark-raised-outside-its-owner", "  SAFE_GATE_LANE_REFUSAL_MARK=1\n")
inside("mark-from-a-variable", "  SAFE_GATE_LANE_REFUSAL_MARK=${one}\n")
inside("mark-by-arithmetic", "  (( SAFE_GATE_LANE_REFUSAL_MARK = 1 ))\n")
inside("start-up-flag-cleared", "  SAFE_GATE_LANE_CONFIG_NEVER=0\n")
inside("start-up-flag-unset", "  unset SAFE_GATE_LANE_CONFIG_NEVER\n")
inside("phase-declared-local", "  local SAFE_GATE_LANE_PHASE=routing\n")
inside("question-through-the-outcome-handler", '  safe_gate_project_lane_query "declined" safe_gate_confirm_infra "this command" "a" "b" "run it? [y/N] " && return 253\n')
inside("reserved-status-as-a-literal", "  exit 252\n")
j = find(r'(  SAFE_GATE_LANE_PHASE=judging\n)')
write("phase-set-back-to-routing", src[:j.end()] + "  SAFE_GATE_LANE_PHASE=routing\n" + src[j.end():])
k = find(r'(safe_gate_project_lane_conclude\(\) \{\n)')
write("mark-raised-where-the-question-is-asked", src[:k.end()] + "  SAFE_GATE_LANE_REFUSAL_MARK=1\n" + src[k.end():])
r = find(r'(safe_gate_project_lane_run\(\) \{\n)')
write("prompt-called-outside-its-loop", src[:r.end()] + "  safe_gate_project_lane_prompt_gap || return $?\n" + src[r.end():])
c9 = re.search(r"(safe_gate_project_lane_cleanup\(\) \{\n)", src)
write("pin-question-asked-outside-the-route", src[:c9.end()] + "  safe_gate_project_lane_pin_ask_npm \"$@\" || return 1\n" + src[c9.end():])
write("pin-data-question-asked-outside-the-route", src[:c9.end()] + "  safe_gate_project_lane_pin_here || return 1\n" + src[c9.end():])
write("pin-route-called-outside-the-runner", src[:c9.end()] + "  safe_gate_project_lane_pin_route x && return 1\n" + src[c9.end():])
write("the-store-named-outside-the-two-questions", src[:c9.end()] + "  \"${SAFE_DIR}/safe-core\" one-shot-store check --home \"${HOME}\" || return 1\n" + src[c9.end():])
r9 = re.search(r"  if \(\( ! plain_global \)\) && safe_gate_project_lane_pin_route \"\$\{verb\}\" \"\$@\"; then\n", src)
assert r9, "the route call"
write("pin-route-read-twice", src[:r9.start()] + '  if (( ! plain_global )) && safe_gate_project_lane_pin_route "${verb}" "$@"; then :; fi\n' + src[r9.start():])
write("pin-route-never-read", src[:r9.start()] + '  if false; then\n' + src[r9.end():])
blk = re.search(r"  if \(\( ! plain_global \)\) && safe_gate_project_lane_pin_route \"\$\{verb\}\" \"\$@\"; then\n[^\n]*\n[^\n]*\n  fi\n", src)
assert blk, "the route block"
tail = src.replace(blk.group(0), "", 1)
anchor = tail.index("  if (( plain_global )); then\n    safe_gate_project_lane_hand_over_silent")
write("pin-route-moved-below-the-spelled-global-guards", tail[:anchor] + blk.group(0) + tail[anchor:])
write("a-refusal-before-the-pin-lookup", src[:blk.start()] + '  safe_gate_project_lane_unsupported_kind command_form "${verb}" "x"\n  return $?\n' + src[blk.start():])
a = re.search(r"  safe_gate_project_lane_pin_npm_line prefix \"\$\{scratch\}\" \"\$@\" \|\| return 1\n", src)
assert a, "the prefix question"
write("prefix-question-asked-twice-in-its-owner", src[:a.end()] + a.group(0) + src[a.end():])
b = re.search(r"  safe_gate_project_lane_pin_npm_line root \"\$\{scratch\}\" \"\$@\" \|\| return 1\n", src)
assert b, "the root question"
write("root-question-never-asked", src[:b.start()] + src[b.end():])
write("a-question-asked-outside-its-owner", src[:c9.end()] + '  safe_gate_project_lane_pin_npm_line root "$@" || return 1\n' + src[c9.end():])
# the reviewer's two mutations (round two): two prefix questions on ONE logical line; a refusal of the lint's whole set before the lookup
write("two-prefix-questions-on-one-line", src[:a.start()] + '  safe_gate_project_lane_pin_npm_line prefix "${scratch}" "$@" || return 1; safe_gate_project_lane_pin_npm_line prefix "${scratch}" "$@" || return 1\n' + src[a.end():])
write("pin-lookup-called-outside-the-bounded-route", src[:c9.end()] + '  safe_gate_project_lane_pin_lookup x || return 1\n' + src[c9.end():])
write("pin-bounded-called-outside-the-route", src[:c9.end()] + '  safe_gate_project_lane_pin_bounded x || return 1\n' + src[c9.end():])
# R11 (ticket 1638): the lane runs no lifecycle script
fz = find(r'(safe_gate_project_lane_cleanup\(\) \{\n)')
# each fixture breaks ONE rule: a script word inside an owner of npm that carries the flag; npm started outside the owners with the flag
# and no script word; the flag missing inside an owner; the binder given another command
fo = find(r'(safe_gate_project_lane_frozen_check\(\) \{\n)')
# (the report function is where a helpful rebuild would be written: it is held like every other function of the lane, and the words
# that run scripts live in its text function only)
sr = find(r'(  local -a args=\(project-scripts --lock "\$\{lockfile\}" --limit 25\)\n)')
write("a-rebuild-in-the-lane", src[:sr.end()] + '  node-gyp rebuild >/dev/null 2>&1\n' + src[sr.end():])
write("a-bare-npm-in-the-lane", src[:sr.end()] + '  npm ci --ignore-scripts >/dev/null 2>&1\n' + src[sr.end():])
write("an-npm-run-started-by-an-owner", src[:fo.end()] + '  safe_gate_lane_npm_in "${frozen}" run prepare --ignore-scripts || return 1\n' + src[fo.end():])
fc = find(r'  frozen_args=\(ci --ignore-scripts ')
write("a-frozen-command-that-is-not-ci", src[:fc.start()] + '  frozen_args=(install --ignore-scripts ' + src[fc.end():])
tx = find(r"(safe_gate_project_lane_scripts_lines\(\) \{\n)  jq -r '\n")
write("the-report-text-names-the-shell", src[:tx.end(1)] + '  safe_gate_lane_clean x\n' + src[tx.end(1):])
te = find(r"(     else empty end\)'\n)\}\n")
write("a-command-after-the-report-text", src[:te.end(1)] + '  true\n' + src[te.end(1):])
write("an-npm-started-outside-the-lane-owners", src[:fz.end()] + '  "${SAFE_GATE_LANE_ENV[@]}" "${SAFE_GATE_LANE_NPM[@]}" --ignore-scripts ci || return 1\n' + src[fz.end():])
write("an-npm-without-the-flag-in-an-owner", src[:fo.end()] + '  safe_gate_lane_npm_in "${frozen}" ci || return 1\n' + src[fo.end():])
write("scripts-enabled-by-an-option", src[:fo.end()] + '  safe_gate_lane_npm_in "${frozen}" ci --ignore-scripts --dangerously-allow-all-scripts || return 1\n' + src[fo.end():])
fr = find(r'  frozen_args=\(ci --ignore-scripts ')
write("frozen-install-without-ignore-scripts", src[:fr.start()] + '  frozen_args=(ci ' + src[fr.end():])
pj = find(r'    safe_gate_lane_npm_in "\$\{proj\}" --package-lock-only --ignore-scripts ')
write("projection-without-ignore-scripts", src[:pj.start()] + '    safe_gate_lane_npm_in "${proj}" --package-lock-only ' + src[pj.end():])
bd = find(r'-- "\$\{SAFE_GATE_LANE_NPM\[@\]\}" "\$\{frozen_args\[@\]\}"\)')
write("binder-given-something-else", src[:bd.start()] + '-- "${SAFE_GATE_LANE_NPM[@]}" "${proj_args[@]}")' + src[bd.end():])
write("an-unsupported-refusal-before-the-pin-lookup", src[:blk.start()] + '  safe_gate_project_lane_unsupported 100 "${verb}" "x" "y"\n  return $?\n' + src[blk.start():])
# R10: a step of the standing route under timeout(1) sits in a process group of its own and outlives the route's one deadline
def under_timeout(name, plain):
    assert src.count(plain) == 1, plain
    write(name, src.replace(plain, plain.replace('"${', 'timeout --kill-after=2s 10s "${', 1)))
under_timeout("the-question-under-timeout", '    "${launch[@]}" "--cache=${scratch}"')
under_timeout("the-data-question-under-timeout", '  "${core}" one-shot-store check </dev/null')
under_timeout("the-verification-under-timeout", '  "${core}" one-shot-store verify "${prefix_answer}"')
PY
  # every fixture the program above wrote is checked: a fixture cannot be written and left out of a list
  local file count=0
  for file in "${dir}"/*.sh; do
    [[ -f "${file}" ]] || continue
    count=$((count + 1))
    name="${file##*/}"
    if python3 -I "${ROOT}/tests/contract/lane_lint.py" "${file}" >/dev/null; then
      bad="${bad} ${name%.sh}"
    fi
  done
  (( count >= 50 )) || bad="${bad} (only ${count} fixtures were written)"
  if [[ -z "${bad}" ]]; then
    pass "$FUNCNAME"
  else
    fail "$FUNCNAME (the lint accepted:${bad})"
  fi
}


case_contract_is_valid_json
case_contract_has_every_required_key
case_every_exit_code_tells_an_agent_what_to_do
case_docs_are_not_stale
case_hand_editing_a_generated_block_is_caught
case_release_follow_tree_has_no_gitattributes
case_explain_json_is_the_contract_verbatim
case_explain_text_renders_from_the_contract
case_explain_fails_loudly_without_a_contract
case_malformed_contract_is_refused
case_exit_codes_match_the_dispatcher
case_contract_never_suggests_latest
case_version_constant_matches_version_file
case_audit_version_constant_matches_version_file
case_gated_tools_match_the_installed_wrapper_set
case_gated_tool_lists_stay_in_sync
case_npm_classifier_snapshot_routes_every_alias
case_npm_literal_sites_consult_the_classifier
case_infra_cause_sets_match_between_gates
case_operator_terminal_helpers_match_between_gates
case_npm_option_snapshot_is_consistent_and_reads_like_nopt
case_lane_structure_lint_is_clean
case_lane_structure_lint_rejects_the_known_mutations

printf '\n%d passed, %d failed\n' "$PASS_COUNT" "$FAIL_COUNT"
[[ "$FAIL_COUNT" -eq 0 ]]
