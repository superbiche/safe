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

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SAFE="$ROOT/bin/safe"
CONTRACT="$ROOT/docs/contract/agent-contract.json"

PASS_COUNT=0
FAIL_COUNT=0
pass() { printf 'ok - %s\n' "$*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { printf 'not ok - %s\n' "$*" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }

TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT

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
  cp -r "$ROOT/docs" "$ROOT/scripts" "$sandbox/"
  # Inside a generated block — an edit OUTSIDE the markers is legitimate
  # hand-written prose and must keep passing.
  sed -i 's/^| 100 |/| 100 | HAND EDITED |/' "$sandbox/docs/agents.md"
  # Re-anchor the copy's ROOT by running the copied script from the copy.
  if "$sandbox/scripts/render-contract.sh" --check >/dev/null 2>&1; then
    fail "$FUNCNAME (a hand-edited doc passed --check)"
  else
    pass "$FUNCNAME"
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

case_contract_never_suggests_latest() {
  # The standing operator ruling: allow entries are pinned to resolved
  # versions, and nothing safe prints may model `@latest` as acceptable.
  if grep -oE '[a-z>]+@latest' "$CONTRACT" | grep -qv 'pkg>@latest'; then
    fail "$FUNCNAME (a bare @latest suggestion is in the contract)"
    return
  fi
  # The two mentions that ARE allowed are the prohibitions themselves.
  if jq -e '(.version_resolution.never_latest | test("Never suggest"))' >/dev/null 2>&1 < "$CONTRACT"; then
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

case_contract_is_valid_json
case_contract_has_every_required_key
case_every_exit_code_tells_an_agent_what_to_do
case_docs_are_not_stale
case_hand_editing_a_generated_block_is_caught
case_explain_json_is_the_contract_verbatim
case_explain_text_renders_from_the_contract
case_explain_fails_loudly_without_a_contract
case_malformed_contract_is_refused
case_exit_codes_match_the_dispatcher
case_contract_never_suggests_latest
case_gated_tools_match_the_installed_wrapper_set

printf '\n%d passed, %d failed\n' "$PASS_COUNT" "$FAIL_COUNT"
[[ "$FAIL_COUNT" -eq 0 ]]
