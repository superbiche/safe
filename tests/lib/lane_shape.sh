#!/usr/bin/env bash
# One definition of what the project lane's auditor entries answer (ticket 1884): tests/lib/lane_auditor_shapes.json names, for each
# entry the lane calls, the members of its answer and their types. The real entry's answer is held to it by tests/contract/lane_auditor.sh;
# every stand-in a suite uses for that entry is held to the SAME definition (lane_shape_check below), so a stand-in that writes a member the
# real entry does not, or misses one it does, fails a case of its own suite.
#
# A shape is JSON: a string names a type ("string", "number", "boolean", "null", "object", "array", "any", or alternatives with "|");
# an object lists its members (a name ending in "?" is optional) and an answer may carry no member the shape does not name; an array of
# one shape says every element has it (an empty array conforms). A member named "*" gives the shape of every member not named otherwise
# (and allows them): a contract that names only what the consumer reads says {"*": "any"}.

LANE_SHAPES_FILE="${LANE_SHAPES_FILE:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/lane_auditor_shapes.json}"

# lane_shape_check <entry> <answer file>: prints one problem per line and returns 1 when the answer does not conform to the entry's shape.
lane_shape_check() {
  local entry="$1" file="$2" problems
  problems="$(jq -r --arg entry "$entry" --slurpfile shapes "${LANE_SHAPES_FILE}" '
    def check($v; $s; $p):
      if ($s | type) == "string" then
        (if $s == "any" or (($s | split("|")) | index($v | type)) != null then [] else ["\($p): is \($v | type), the contract says \($s)"] end)
      elif ($s | type) == "array" then
        (if ($v | type) != "array" then ["\($p): is \($v | type), the contract says an array"]
         else [range(0; $v | length) as $i | check($v[$i]; $s[0]; "\($p)[\($i)]")] | add // [] end)
      else
        (if ($v | type) != "object" then ["\($p): is \($v | type), the contract says an object"]
         else ([$s | keys[] | . as $k | select($k != "*" and ($k | endswith("?") | not)) | select($v | has($k) | not) | "\($p).\($k): missing"])
              + ([$v | keys[] | . as $k | select(($s | has("*")) or ($s | has($k)) or ($s | has($k + "?")) | not) | "\($p).\($k): a member the contract does not name"])
              + ([$s | to_entries[] | select(.key != "*") | (.key | rtrimstr("?")) as $k | .value as $sub | select($v | has($k)) | check($v[$k]; $sub; "\($p).\($k)")] | add // [])
              + (if ($s | has("*")) then [$v | to_entries[] | .key as $k | .value as $val | select(($s | has($k)) or ($s | has($k + "?")) | not) | check($val; $s["*"]; "\($p).\($k)")] | add // [] else [] end)
         end)
      end;
    ($shapes[0][$entry]) as $shape
    | if $shape == null then ["no shape named \($entry)"] else check(.; $shape; $entry) end | .[]' "${file}" 2>&1)" || problems="${problems:-the answer is not one JSON document}"
  [[ -z "${problems}" ]] || { printf '%s\n' "${problems}"; return 1; }
}
