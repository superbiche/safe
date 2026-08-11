#!/usr/bin/env bash
# Live contract probe for Socket's package-score envelope. This deliberately
# never prints Socket output: an error response can include account context.

set -euo pipefail

if ! command -v socket >/dev/null 2>&1; then
  printf 'SKIP socket_envelope: socket CLI is unavailable\n'
  exit 0
fi
if [[ ! -v SOCKET_SECURITY_API_TOKEN ]]; then
  printf 'SKIP socket_envelope: SOCKET_SECURITY_API_TOKEN is unset\n'
  exit 0
fi
if ! command -v timeout >/dev/null 2>&1; then
  printf 'SKIP socket_envelope: timeout is unavailable\n'
  exit 0
fi

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
result="$scratch/socket.json"
error="$scratch/socket.stderr"

set +e
timeout --kill-after=2s 30s socket package score npm brace-expansion@2.1.4 --json >"$result" 2>"$error"
rc=$?
set -e
if (( rc != 0 )); then
  printf 'not ok - live Socket score command failed (exit %s; response withheld)\n' "$rc" >&2
  exit 1
fi

if jq -e '
  (.ok == true)
  and (.data.self.score.overall | type == "number")
  and (.data.self.alerts | type == "array")
  and ([.data.self.alerts[]?
        | select((.severity | type) != "string"
                 or (.severity as $severity
                     | ["critical", "high", "middle", "low"] | index($severity) | not))]
       | length == 0)
' "$result" >/dev/null 2>&1; then
  printf 'ok - live Socket package-score envelope matches the gated schema\n'
else
  printf 'not ok - live Socket package-score envelope changed (response withheld)\n' >&2
  exit 1
fi
