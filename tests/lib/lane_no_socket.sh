#!/usr/bin/env bash
# The premise of a lane scenario that says "no Socket tool": it is established, not assumed (ticket 1884, review round 1).
#
# The auditor finds a `socket` program on the PATH (a login shell's `command -v socket`) the first time it scans a project and writes it into the
# home's tool cache, and the Socket reader then runs whatever the cache names. A scenario that keeps the machine's PATH therefore runs the
# machine's Socket tool, with the machine's credentials, after its first scan. The machine's own `socket` tool is NEVER run by any suite.
#
# lane_no_socket_check <PATH value> <home>: returns 1, and says what it found, when a program named `socket` is reachable by the PATH or when the
# home's tool cache (<home>/.config/safe/audit/tools.json) names a Socket tool. A scenario calls it before and after each case.
lane_no_socket_check() {
  local path_value="$1" home="$2" dir tools="$2/.config/safe/audit/tools.json" found=0
  local IFS=:
  for dir in $path_value; do
    [[ -n "$dir" && -d "$dir" ]] || continue
    if [[ -e "$dir/socket" || -L "$dir/socket" ]]; then
      printf 'a socket program is reachable: %s/socket\n' "$dir" >&2
      found=1
    fi
  done
  unset IFS
  if [[ -s "$tools" ]] && jq -e '[.[]? | objects | .socket? // empty | select(. != "")] | length > 0' "$tools" >/dev/null 2>&1; then
    printf 'the tool cache %s names a Socket tool: %s\n' "$tools" "$(jq -c '[.[]? | objects | .socket? // empty]' "$tools")" >&2
    found=1
  fi
  return "$found"
}
