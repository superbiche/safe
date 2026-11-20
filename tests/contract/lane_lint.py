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
  R3  the hand-over status is raised only by the functions that own it.
"""
import re
import sys

REFUSALS = ("safe_gate_project_lane_refuse", "safe_gate_project_lane_refuse_fixed", "safe_gate_project_lane_unsupported",
            "safe_gate_project_lane_unsupported_fixed", "safe_gate_project_lane_verb_refusal", "safe_gate_project_lane_window_refuse",
            "safe_gate_project_lane_oneshot", "safe_gate_project_lane_hand_over_silent", "safe_gate_project_lane_unresolved_silent")
EXEMPT_BODIES = set(REFUSALS) | {"safe_gate_project_lane_decide"}  # the wrappers' own last statement is the call
ASKERS = {"safe_gate_project_lane_one_shot_question", "safe_gate_project_lane_prompt_gap", "safe_gate_project_lane_prompt_socket"}
PASS_OWNERS = {"safe_gate_project_lane_hand_over_silent", "safe_gate_project_lane_unresolved_silent", "safe_gate_project_lane_in_subshell"}
QUESTION_WORDING = "run this command on the one-shot route"

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


def command_at(text, name):
    return re.search(r"(?:^|[;&|({]|\bthen\b|\bdo\b|\belse\b|!)\s*" + re.escape(name) + r"(?![A-Za-z0-9_])", text) is not None


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


def main(path):
    problems = []
    logical = logical_lines(path)
    lane = [(n, fn, text, strip(text)) for n, fn, text in logical if fn.startswith(("safe_gate_project_lane_", "safe_gate_lane_"))]
    for index, (number, fn, text, bare) in enumerate(lane):
        if bare.lstrip().startswith("#") or FN.match(text):
            continue
        if fn in EXEMPT_BODIES and not command_at(bare, "SAFE_GATE_LANE_PASS="):
            continue
        for name in REFUSALS:
            if command_at(bare, name):
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
        if QUESTION_WORDING in text and fn != "safe_gate_project_lane_one_shot_question":
            problems.append(f"{number}:{fn}:R2: the one-shot question's wording is outside its entry point")
        if re.search(r"(?:^|[;&|({]|\bthen\b|\bdo\b|\belse\b)\s*SAFE_GATE_LANE_PASS=", bare) and fn not in PASS_OWNERS:
            problems.append(f"{number}:{fn}:R3: the hand-over status is raised outside its owners")
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
