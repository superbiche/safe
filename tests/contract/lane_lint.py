#!/usr/bin/env python3
"""Structural lint of the npm project lane's refusals and hand-overs (ticket 1686).

Usage: python3 -I lane_lint.py <gate-lib.sh>. Prints one line per violation ("line:function:rule: text") and exits 1 when
there is any. It reads SHELL COMMANDS and where they sit: a logical line is a command line with its continuations joined,
quoted text is blanked before a command is looked for (so a diagnostic that contains the word `return` is not a `return`), and the
function a line belongs to is tracked.

Rules
  R1  every call of a refusal or hand-over function is followed, on the same logical line or the next one, by a `return`
      command: nothing of the lane runs between a refusal and its top level.
  R2  the one-shot question has ONE entry point: safe_gate_project_lane_one_shot_question, called only from
      safe_gate_project_lane_conclude, and its wording appears nowhere else; the confirmation prompt helper
      (safe_gate_confirm_infra) is called in the lane only from the functions allowed to ask; conclude is called only from the
      lane's entry.
  R3  the hand-over status is raised only by the functions that own it, by assignment and by calling its helpers.
  R4  a refusal that carries a kind passes a kind of the closed list (safe_gate_project_lane_kinds), as a bare word.
  R10 no step of the standing route runs under timeout(1): the command would sit in a process group of its own and outlive the
      route's one deadline, which stops the route's group.
  R11 the lane runs no lifecycle script (ticket 1638): every npm the lane starts carries --ignore-scripts on its own command line (the
      projections, the probe, the frozen check and the frozen installation the binder runs), npm is started by the lane's few owners
      only, no word that runs or enables scripts (rebuild, run-script, install-scripts, --allow-scripts, ...) appears as a command word or
      an option of the lane, and the binder is given the frozen command and nothing else. npm is never a bare command word of the lane
      (it is started through the owners' resolved command only), and what an owner starts is one of the lane's three commands (config,
      a --package-lock-only projection, ci): `npm run`, `npm exec` and the like run code whatever --ignore-scripts says. The words
      that run scripts are written in one function, the text of the report (safe_gate_project_lane_scripts_lines), which is one jq
      program (`jq -rs`) from its first line to its last, holding exactly one jq: it names no variable, function or substitution of the shell.
  R9  the standing decision is read in one place: the route is called once, from the runner; the data question and the question to
      npm are called from the route only; the core's store is named by those two functions only.
  R5  a refusal or hand-over is never inside a pipeline, a command substitution or a subshell: what it records would be lost
      with the child shell while its owner went on (a `return` in the child does not end the owner).
  R6  the state a confirmation rests on has owners, in the whole file: the mark of a confirmable refusal is raised only by
      safe_gate_project_lane_refuse_kind, the phase is `routing` only at the lane's entry and `judging` only in the runner, the
      start-up-input flag is cleared only at the entry and raised only where a configuration document is read; none of these
      names is written, unset or declared anywhere else.
  R7  a question has askers: the lane's outcome handler (query, ask, answer) is called only from the prompt functions and the
      one-shot question, and the prompt functions only from the loop that owns them.
  R8  the reserved statuses are never written as literals: they are raised through their helpers only.
"""
import re
import sys

REFUSALS = ("safe_gate_project_lane_refuse_kind", "safe_gate_project_lane_refuse", "safe_gate_project_lane_unsupported_kind",
            "safe_gate_project_lane_unsupported", "safe_gate_project_lane_baseline_refuse", "safe_gate_project_lane_verb_refusal",
            "safe_gate_project_lane_window_refuse", "safe_gate_project_lane_oneshot", "safe_gate_project_lane_hand_over_silent",
            "safe_gate_project_lane_unresolved_silent")
KINDED = ("safe_gate_project_lane_refuse_kind", "safe_gate_project_lane_unsupported_kind")
HAND_OVERS = ("safe_gate_project_lane_hand_over_silent", "safe_gate_project_lane_unresolved_silent")
HAND_OVER_CALLERS = {"safe_gate_project_lane_oneshot", "safe_gate_project_lane_conclude", "safe_gate_project_lane_run"}
EXEMPT_BODIES = set(REFUSALS) | {"safe_gate_project_lane_decide"}  # the wrappers' own last statement is the call
ASKERS = {"safe_gate_project_lane_one_shot_question", "safe_gate_project_lane_prompt_gap", "safe_gate_project_lane_prompt_socket"}
PASS_OWNERS = {"safe_gate_project_lane_hand_over_silent", "safe_gate_project_lane_unresolved_silent", "safe_gate_project_lane_in_subshell"}
QUESTION_WORDING = "run this command on the one-shot route"
# R6: name -> {value pattern -> the functions that may assign it}; any other mention of the bare name is a violation
STATE = {
    "SAFE_GATE_LANE_REFUSAL_MARK": {"1": {"safe_gate_project_lane_refuse_kind"},
                                    "0": {"safe_gate_project_lane_refuse", "safe_gate_project_lane_conclude",
                                          "safe_gate_project_lane_in_subshell"}},
    "SAFE_GATE_LANE_REFUSAL_KIND": {"*": {"safe_gate_project_lane_refuse", "safe_gate_project_lane_refuse_kind"}},
    "SAFE_GATE_LANE_PHASE": {"routing": {"safe_gate_project_lane_in_subshell"}, "judging": {"safe_gate_project_lane_run"}},
    "SAFE_GATE_LANE_CONFIG_NEVER": {"0": {"safe_gate_project_lane_in_subshell"}, "1": {"safe_gate_project_lane_config_seen"}},
}
# R7
HANDLER = ("safe_gate_project_lane_query", "safe_gate_project_lane_ask", "safe_gate_project_lane_answer")
HANDLER_CALLERS = {"safe_gate_project_lane_query", "safe_gate_project_lane_one_shot_question", "safe_gate_project_lane_grant",
                   "safe_gate_project_lane_prompt_malice", "safe_gate_project_lane_prompt_blocking",
                   "safe_gate_project_lane_prompt_adverse", "safe_gate_project_lane_prompt_socket",
                   "safe_gate_project_lane_prompt_gap"}
PROMPTS = ("safe_gate_project_lane_prompt_malice", "safe_gate_project_lane_prompt_blocking",
           "safe_gate_project_lane_prompt_adverse", "safe_gate_project_lane_prompt_socket", "safe_gate_project_lane_prompt_gap")
PROMPT_CALLERS = {"safe_gate_project_lane_prompts"}
GRANT_CALLERS = {"safe_gate_project_lane_prompt_blocking", "safe_gate_project_lane_prompt_adverse",
                 "safe_gate_project_lane_prompt_socket"}
PROMPTS_LOOP_CALLERS = {"safe_gate_project_lane_run"}
# R9: the standing decision is read in ONE place, with two questions asked from ONE place each
PIN_CALLERS = {"safe_gate_project_lane_pin_route": {"safe_gate_project_lane_run"},
               "safe_gate_project_lane_pin_bounded": {"safe_gate_project_lane_pin_route"},
               "safe_gate_project_lane_pin_lookup": {"safe_gate_project_lane_pin_bounded"},
               "safe_gate_project_lane_pin_here": {"safe_gate_project_lane_pin_lookup"},
               "safe_gate_project_lane_pin_ask_npm": {"safe_gate_project_lane_pin_lookup"},
               "safe_gate_project_lane_pin_npm_line": {"safe_gate_project_lane_pin_ask_npm"}}
RUNNER = "safe_gate_project_lane_run"
# a call that ends the run (a refusal or a hand-over): none may come before the pin lookup but the two that capture the directory
RUN_ENDERS = REFUSALS
PIN_CORE_USERS = {"safe_gate_project_lane_pin_here", "safe_gate_project_lane_pin_ask_npm"}
# R10: the functions the route's one deadline bounds; none of them may run a command under timeout(1)
PIN_BOUNDED = {"safe_gate_project_lane_pin_core", "safe_gate_project_lane_pin_here", "safe_gate_project_lane_pin_npm_line",
               "safe_gate_project_lane_pin_ask_npm", "safe_gate_project_lane_pin_lookup"}

# R11
NPM_OWNERS = {"safe_gate_lane_npm_in", "safe_gate_project_lane_run", "safe_gate_project_lane_frozen_probe", "safe_gate_project_lane_frozen_check"}
NPM_FIRST_WORDS = {"config", "--package-lock-only", "ci"}
SCRIPT_TEXT = "safe_gate_project_lane_scripts_lines"
SCRIPT_WORDS = re.compile(r"(?<![A-Za-z0-9_\-])(rebuild|run-script|install-scripts|approve-scripts|--allow-scripts|--strict-allow-scripts|"
                          r"--dangerously-allow-all-scripts|--no-ignore-scripts|--ignore-scripts=false)(?![A-Za-z0-9_])")

FN = re.compile(r"^(safe_gate_[A-Za-z0-9_]+)\(\)\s*\{")


def strip(line):
    """Blank quoted text and drop a trailing comment: what is left is shell syntax and bare words."""
    out, i, quote = [], 0, ""
    while i < len(line):
        c = line[i]
        if quote:
            if c == "\\" and quote == '"' and i + 1 < len(line):
                i += 2
                continue
            if c == quote:
                quote = ""
                out.append(c)
            i += 1
            continue
        if c in "\"'":
            quote = c
            out.append(c)
        elif c == "#" and (i == 0 or line[i - 1] in " \t;"):
            break
        else:
            out.append(c)
        i += 1
    return "".join(out)


def in_child_shell(bare, name):
    """True when the call of `name` sits in a pipeline, a command substitution or a subshell of its logical line."""
    at = re.search(r"(?<![A-Za-z0-9_])" + re.escape(name) + r"(?![A-Za-z0-9_])", bare)
    if not at:
        return False
    before, after = bare[: at.start()], bare[at.end():]
    # unclosed `$(` or a bare `(` (a subshell) before the call; `${...}` and `((...))` are not
    depth = 0
    i = 0
    while i < len(before):
        two = before[i:i + 2]
        if two == "$(" or (before[i] == "(" and before[i:i + 2] != "((") :
            depth += 1
        elif before[i] == ")":
            depth -= 1
        i += 1
    if depth > 0:
        return True
    if re.search(r"\|(?!\|)\s*$", before) and not before.rstrip().endswith("||"):
        return True
    inner = after
    while True:  # an argument's own substitution is the argument's business, not the call's
        reduced = re.sub(r"\$\([^()]*\)", "", inner)
        if reduced == inner:
            break
        inner = reduced
    if re.match(r"[^|&;]*(?<!\|)\|(?!\|)", inner):
        return True
    return False


def command_at(text, name):
    return re.search(r"(?:^|[;&|({]|\bthen\b|\bdo\b|\belse\b|\bif\b|\belif\b|\bwhile\b|\buntil\b|!)\s*" + re.escape(name) + r"(?![A-Za-z0-9_])", text) is not None


def returns(text):
    return re.search(r"(?:^|[;&|({]|\bthen\b|\bdo\b|\belse\b)\s*return(?![A-Za-z0-9_])", text) is not None


def logical_lines(path):
    lines, fn, current, start, owner = [], "", "", 0, ""
    for number, raw in enumerate(open(path, encoding="utf-8").read().split("\n"), 1):
        match = FN.match(raw)
        if match and not current:
            fn = match.group(1)
        if not current:
            start, owner = number, fn
        if raw.endswith("\\"):
            current += raw[:-1] + " "
            continue
        current += raw
        lines.append((start, owner, current))
        current = ""
        if raw == "}":
            fn = ""
    return lines


def closed_kinds(logical):
    for _, fn, text in logical:
        if fn == "safe_gate_project_lane_kinds" and "printf" in text:
            return set(re.findall(r"[a-z_]+", text.split("'%s\\n'", 1)[-1])) - {"printf"}
    return set()


def main(path):
    problems = []
    logical = logical_lines(path)
    kinds = closed_kinds(logical)
    if not kinds:
        return ["0::R4: the closed list of kinds is not found"]
    lane = [(n, fn, text, strip(text)) for n, fn, text in logical if fn.startswith(("safe_gate_project_lane_", "safe_gate_lane_"))]
    for index, (number, fn, text, bare) in enumerate(lane):
        if bare.lstrip().startswith("#") or FN.match(text):
            continue
        if fn in EXEMPT_BODIES and not command_at(bare, "SAFE_GATE_LANE_PASS="):
            continue
        for name in REFUSALS:
            if command_at(bare, name):
                if in_child_shell(bare, name):
                    problems.append(f"{number}:{fn}:R5: {name} is called in a pipeline, a substitution or a subshell")
                after = bare[bare.index(name):]
                nxt = ""
                for later in lane[index + 1:]:
                    if later[3].strip():
                        nxt = later[3]
                        break
                if not (returns(after) or re.match(r"\s*return(?![A-Za-z0-9_])", nxt)):
                    problems.append(f"{number}:{fn}:R1: {name} is not followed by a return")
                break
        if command_at(bare, "safe_gate_project_lane_one_shot_question") and fn != "safe_gate_project_lane_conclude":
            problems.append(f"{number}:{fn}:R2: the one-shot question is called outside conclude")
        if command_at(bare, "safe_gate_project_lane_conclude") and fn != "safe_gate_project_lane_in_subshell":
            problems.append(f"{number}:{fn}:R2: conclude is called outside the lane's entry")
        if command_at(bare, "safe_gate_confirm_infra") and fn not in ASKERS and not fn.startswith("safe_gate_confirm_"):
            problems.append(f"{number}:{fn}:R2: a confirmation prompt is asked in a function that may not ask")
        for name in KINDED:
            if command_at(bare, name):
                match = re.search(re.escape(name) + r"\s+([A-Za-z0-9_${}\"]+)", text)
                word = match.group(1) if match else ""
                if word not in kinds:
                    problems.append(f"{number}:{fn}:R4: {name} passes {word!r}, which is not a kind of the closed list")
        for name in HAND_OVERS:
            if command_at(bare, name) and fn not in HAND_OVER_CALLERS and fn != name:
                problems.append(f"{number}:{fn}:R3: {name} is called outside the functions that own the hand-over")
        if QUESTION_WORDING in text and fn != "safe_gate_project_lane_one_shot_question":
            problems.append(f"{number}:{fn}:R2: the one-shot question's wording is outside its entry point")
        if re.search(r"(?:^|[;&|({]|\bthen\b|\bdo\b|\belse\b)\s*SAFE_GATE_LANE_PASS=", bare) and fn not in PASS_OWNERS:
            problems.append(f"{number}:{fn}:R3: the hand-over status is raised outside its owners")
    # R6, over the whole file: who writes the state a confirmation rests on
    for number, fn, text in logical:
        bare = strip(text)
        if bare.lstrip().startswith("#"):
            continue
        for name, owners in STATE.items():
            for hit in re.finditer(r"(?<![A-Za-z0-9_{$])" + name + r"(?![A-Za-z0-9_])", bare):
                assignment = re.match(r"=([A-Za-z0-9_]*)", bare[hit.end():])
                if not assignment:
                    problems.append(f"{number}:{fn}:R6: {name} is written, unset or declared outside a plain assignment")
                    continue
                value = assignment.group(1)
                allowed = owners.get(value) if value in owners else owners.get("*")
                if allowed is None:
                    problems.append(f"{number}:{fn}:R6: {name} is given a value its owners never give ({value!r})")
                elif fn not in allowed:
                    problems.append(f"{number}:{fn}:R6: {name} is assigned {value!r} outside its owners")
    # R7 and R8, in the lane
    starts = {FN.match(text).group(1): number for number, _, text in logical if FN.match(text)}
    before = ""
    for number, fn, text, bare in lane:
        if bare.lstrip().startswith("#") or FN.match(text):
            continue
        for name in HANDLER:
            if command_at(bare, name) and fn not in HANDLER_CALLERS:
                problems.append(f"{number}:{fn}:R7: the outcome handler ({name}) is called by a function that may not ask")
        for name in PROMPTS:
            if command_at(bare, name) and fn not in PROMPT_CALLERS:
                problems.append(f"{number}:{fn}:R7: {name} is called outside the loop that owns the prompts")
        if command_at(bare, "safe_gate_project_lane_grant") and fn not in GRANT_CALLERS:
            problems.append(f"{number}:{fn}:R7: the host-grant prompt is called outside the prompts that own it")
        if command_at(bare, "safe_gate_project_lane_prompts") and fn not in PROMPTS_LOOP_CALLERS:
            problems.append(f"{number}:{fn}:R7: the prompt loop is called outside the runner")
        for name, callers in PIN_CALLERS.items():
            if command_at(bare, name) and fn not in callers:
                problems.append(f"{number}:{fn}:R9: {name} is called outside the one place that owns it")
        if fn in PIN_BOUNDED and re.search(r"(?<![A-Za-z0-9_\-.])timeout(?![A-Za-z0-9_])", bare):
            problems.append(f"{number}:{fn}:R10: a step of the standing route runs under timeout, out of reach of the route's deadline")
        # R11: no lifecycle script in the lane
        # (the report's text function prints the commands that run them, as a jq program that spans lines: it is held to being text)
        if fn == SCRIPT_TEXT:
            first = number == starts.get(fn, -1) + 1
            if re.search(r"\$\(|`|\$\{|(?<![A-Za-z0-9_])(?:safe|SAFE)_", text) or (first and text != "  jq -rs '") or (text == "}" and not before.endswith("'")):
                problems.append(f"{number}:{fn}:R11: the report's text function is not one jq program (it names something of the shell)")
            before = text
            continue
        if SCRIPT_WORDS.search(bare):
            problems.append(f"{number}:{fn}:R11: a word that runs or enables lifecycle scripts is a command word or an option of the lane")
        if command_at(bare, "npm") or command_at(bare, "npx") or re.search(r"(?<![A-Za-z0-9_\-])(?:command|exec|env)\s+np[mx](?![A-Za-z0-9_\-])", bare):
            problems.append(f"{number}:{fn}:R11: npm is a bare command word of the lane (the lane starts npm through its owners only)")
        started = re.search(r"(?<![A-Za-z0-9_])safe_gate_lane_npm_in\s+\S+\s+(\S+)", bare)
        if command_at(bare, "safe_gate_lane_npm_in") and (not started or started.group(1) not in NPM_FIRST_WORDS):
            problems.append(f"{number}:{fn}:R11: an owner starts an npm command that is not one of the lane's three (config, a projection, ci)")
        if bare.lstrip().startswith("frozen_args=(") and not bare.lstrip().startswith("frozen_args=(ci "):
            problems.append(f"{number}:{fn}:R11: the frozen command is not npm ci")
        launches = command_at(bare, "safe_gate_lane_npm_in") or bare.lstrip().startswith("frozen_args=(")
        if (launches or "SAFE_GATE_LANE_NPM[@]" in text) and fn not in NPM_OWNERS and fn != "safe_gate_npm_probe_run":
            problems.append(f"{number}:{fn}:R11: npm is started outside the owners that carry --ignore-scripts")
        if launches and not FN.match(text) and "--ignore-scripts" not in bare.split():
            problems.append(f"{number}:{fn}:R11: an npm of the lane is started without --ignore-scripts")
        if fn == RUNNER and re.search(r'-- "\$\{SAFE_GATE_LANE_NPM\[@\]\}"', text) and "${frozen_args[@]}" not in text:
            problems.append(f"{number}:{fn}:R11: the binder is given something other than the frozen command")
        if "one-shot-store" in text and fn not in PIN_CORE_USERS:
            problems.append(f"{number}:{fn}:R9: the standing decision's store is named outside the two questions")
        if re.search(r"(?:^|[;&|({]|\bthen\b|\bdo\b|\belse\b)\s*(?:return|exit)\s+25[23](?![0-9])", bare):
            problems.append(f"{number}:{fn}:R8: a reserved status is written as a literal")
    # R11: the report's text function holds exactly one jq (a second invocation would be a second program in a function held to being one)
    jq_words = sum(len(re.findall(r"(?<![A-Za-z0-9_\-])jq(?![A-Za-z0-9_\-])", t)) for n, fn, t, b in lane if fn == SCRIPT_TEXT and not FN.match(t))
    if jq_words != 1:
        problems.append(f"0:{SCRIPT_TEXT}:R11: the report's text function holds {jq_words} jq words, not exactly one")
    if len([1 for n, fn, t, b in lane if command_at(b, "safe_gate_project_lane_pin_route") and fn == "safe_gate_project_lane_run"]) != 1:
        problems.append("0::R9: the runner does not read the standing decision exactly once")
    # R9, each question is counted at its owner: one prefix question and one root question in the helper that asks them
    ask = [b for n, fn, t, b in lane if fn == "safe_gate_project_lane_pin_ask_npm"]
    for word in ("prefix", "root"):
        count = sum(len(re.findall(r"(?:^|[;&|({]|\bif\b|!)\s*safe_gate_project_lane_pin_npm_line\s+" + word + r"(?![A-Za-z0-9_])", b)) for b in ask)
        if count != 1:
            problems.append(f"0::R9: the {word} question is asked {count} times in its owner, not once")
    # R9, position: the lookup follows the directory capture and precedes every lane-specific refusal or hand-over
    run = [(n, t, b) for n, fn, t, b in lane if fn == RUNNER and not b.lstrip().startswith("#")]
    route = [n for n, t, b in run if command_at(b, "safe_gate_project_lane_pin_route")]
    capture = [n for n, t, b in run if "pwd -P" in t]
    if len(route) == 1:
        if not capture or capture[0] > route[0]:
            problems.append("0::R9: the pin lookup comes before the directory capture")
        # before the lookup the runner may end the run twice and no more: the capture's two refusals (the directory cannot be read, its
        # path holds a newline), both after the capture line. Counted by position, never by the words of a diagnostic.
        enders = [n for n, t, b in run if n < route[0] and not FN.match(t) and any(command_at(b, name) for name in RUN_ENDERS)]
        if len(enders) != 2 or any(n < capture[0] for n in enders):
            problems.append(f"{enders[0] if enders else 0}:{RUNNER}:R9: a refusal or hand-over comes before the pin lookup (two are the capture's own)")
    names = {fn for _, fn, _ in logical}
    if "safe_gate_project_lane_one_shot_question" not in names or "safe_gate_project_lane_conclude" not in names:
        problems.append("0::R2: the lane has no top-level question")
    elif not any(command_at(b, "safe_gate_project_lane_one_shot_question") and fn == "safe_gate_project_lane_conclude" for _, fn, _, b in lane):
        problems.append("0::R2: conclude does not ask the question")
    return problems


if __name__ == "__main__":
    found = main(sys.argv[1])
    for line in found:
        print(line)
    sys.exit(1 if found else 0)
