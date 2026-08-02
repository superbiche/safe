#!/usr/bin/env bash
# Render the generated sections of docs/agents.md from the agent contract.
#
# docs/contract/agent-contract.json is the single source for three surfaces:
# `safe explain` (rendered at runtime), `safe explain --json` (emitted
# verbatim), and the tables in docs/agents.md (rendered here). They used to be
# hand-written in three places and drifted, so an agent reading the docs and an
# agent running `safe explain` were told different things about the same gate.
#
#   scripts/render-contract.sh            rewrite docs/agents.md in place
#   scripts/render-contract.sh --check    exit 1 if it is out of date (CI/tests)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="$ROOT/docs/contract/agent-contract.json"
TARGET="$ROOT/docs/agents.md"

CHECK=0
[[ "${1:-}" == "--check" ]] && CHECK=1

[[ -r "$CONTRACT" ]] || { printf 'render-contract: missing %s\n' "$CONTRACT" >&2; exit 1; }
[[ -r "$TARGET" ]] || { printf 'render-contract: missing %s\n' "$TARGET" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { printf 'render-contract: jq is required\n' >&2; exit 1; }

# Each section name maps to a jq program producing the block body.
section_body() {
  case "$1" in
    gated-surfaces)
      jq -r '
        "| Surface | Mechanism | Refusal source |",
        "| --- | --- | --- |",
        (.gated_surfaces[] | "| `\(.surface)` | \(.mechanism) | \(.refusal) |"),
        "",
        "**Audited subcommands.** " + .audited_subcommands,
        "",
        "**Passthrough.** " + .passthrough
      ' < "$CONTRACT"
      ;;
    preflight)
      jq -r '.preflight' < "$CONTRACT"
      ;;
    exit-codes)
      jq -r '
        "| Code | Meaning | What an agent should do |",
        "| --- | --- | --- |",
        (.exit_codes[] | "| \(.code) | \(.meaning | ascii_downcase[0:1] as $f | ($f | ascii_upcase) + .[1:]) | \(.agent_action) |")
      ' < "$CONTRACT"
      ;;
    version-resolution)
      jq -r '
        .version_resolution | .rule, "", .never_latest, "", .unresolvable
      ' < "$CONTRACT"
      ;;
    escalation)
      jq -r '
        "| Situation | Signal | Action |",
        "| --- | --- | --- |",
        (.escalation[] | "| \(.situation) | \(.signal) | \(.action) |")
      ' < "$CONTRACT"
      ;;
    report-fp)
      jq -r '
        .report_fp
        | "```bash", .command, "```",
          "",
          .what_it_does,
          "",
          "**" + .contract + "**"
      ' < "$CONTRACT"
      ;;
    allow-flows)
      # Comments aligned to the longest command: this block is read by agents
      # and by the operator, and a ragged one is harder to scan.
      jq -r '
        ([.allow_flows[].command | length] | max) as $w
        | .allow_flows_note,
          "",
          "```bash",
          (.allow_flows[] | .command + (" " * ($w - (.command | length) + 3)) + "# " + .purpose),
          "```"
      ' < "$CONTRACT"
      ;;
    harness-snippet)
      jq -r '"```markdown", .harness_snippet, "```"' < "$CONTRACT"
      ;;
    *)
      printf 'render-contract: unknown section: %s\n' "$1" >&2
      return 1
      ;;
  esac
}

rendered="$(mktemp)"
trap 'rm -f "$rendered"' EXIT

# Walk the target, copying everything outside the markers and substituting the
# body of every marked block. An unknown or unclosed marker is a hard error:
# silently passing through a stale block is exactly the drift this prevents.
section=""
while IFS= read -r line || [[ -n "$line" ]]; do
  if [[ "$line" =~ ^\<!--\ BEGIN\ GENERATED:\ ([a-z-]+)\ --\>$ ]]; then
    [[ -z "$section" ]] || { printf 'render-contract: nested BEGIN in %s\n' "$TARGET" >&2; exit 1; }
    section="${BASH_REMATCH[1]}"
    printf '%s\n' "$line"
    section_body "$section"
    continue
  fi
  if [[ "$line" =~ ^\<!--\ END\ GENERATED:\ ([a-z-]+)\ --\>$ ]]; then
    [[ "$section" == "${BASH_REMATCH[1]}" ]] || {
      printf 'render-contract: END %s does not match BEGIN %s\n' "${BASH_REMATCH[1]}" "${section:-<none>}" >&2
      exit 1
    }
    section=""
    printf '%s\n' "$line"
    continue
  fi
  [[ -n "$section" ]] && continue   # old body, replaced above
  printf '%s\n' "$line"
done < "$TARGET" > "$rendered"

[[ -z "$section" ]] || { printf 'render-contract: unclosed section %s\n' "$section" >&2; exit 1; }

if (( CHECK )); then
  if cmp -s "$rendered" "$TARGET"; then
    printf 'render-contract: docs/agents.md is up to date\n'
    exit 0
  fi
  printf 'render-contract: docs/agents.md is STALE — run scripts/render-contract.sh\n' >&2
  diff -u "$TARGET" "$rendered" >&2 || true
  exit 1
fi

cp "$rendered" "$TARGET"
printf 'render-contract: rendered %s\n' "$TARGET"
