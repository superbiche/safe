#!/usr/bin/env bash
# Explicit opt-in live contract probe for Socket's package-score envelope.
# Run `bash tests/live/socket_envelope.sh` manually; it is excluded from
# tests/run-all.sh because it makes a real network call. This deliberately
# never prints Socket output: an error response can include account context.

set -euo pipefail

if ! command -v socket >/dev/null 2>&1; then
  printf 'SKIP socket_envelope: socket CLI is unavailable\n'
  exit 0
fi
# Deliberately NOT gated on SOCKET_SECURITY_API_TOKEN: the socket CLI also
# authenticates from its own stored credentials (`socket login`), so an
# env-var gate skipped this probe permanently on the machines where it
# matters most — which is how an envelope-shape fiction survived in the
# fixtures for a whole slice. Authentication is decided by the real call
# below: an auth failure skips, anything else is a genuine result.
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
  # Names only, never the response body: an error payload can carry account
  # context. An unauthenticated runner is a skip, not a contract failure.
  if grep -qiE 'token|api key|unauthor|auth' "$result" "$error" 2>/dev/null; then
    printf 'SKIP socket_envelope: socket CLI is not authenticated (run: socket login)\n'
    exit 0
  fi
  printf 'not ok - live Socket score command failed (exit %s; response withheld)\n' "$rc" >&2
  exit 1
fi

if jq -e '
  (.ok == true)
  and (.data | type == "object")
  and (.data.self | type == "object")
  and (.data.self.score | type == "object")
  and (.data.self.score.overall | type == "number")
  and (.data.self.alerts | type == "array")
  and (.data.transitively | type == "object")
  and ([.data.self.alerts[]?
        | select((type != "object")
                 or ((.name | type) != "string") or (.name | length) == 0
                 or ((.severity | type) != "string")
                 or (.severity as $severity
                     | ["critical", "high", "middle", "low"] | index($severity) | not)
                 or ((.category | type) != "string") or (.category | length) == 0)]
       | length == 0)
' "$result" >/dev/null 2>&1; then
  printf 'ok - live Socket package-score envelope matches the gated schema\n'
else
  printf 'not ok - live Socket package-score envelope changed (response withheld)\n' >&2
  exit 1
fi

# The assertions above are VACUOUS on a package with no alerts, and
# brace-expansion has none — so they witnessed nothing about alert shape while
# reading as coverage (review F4). node-ipc@10.1.1 is an immutable published
# version that carries the alert this gate's only BLOCK depends on: severity
# `critical` in category `supplyChainRisk`. If Socket ever renames either, the
# malice BLOCK stops firing, and this is the assertion that says so.
alerts="$scratch/alerts.json"
set +e
timeout --kill-after=2s 30s socket package score npm node-ipc@10.1.1 --json >"$alerts" 2>"$error"
rc=$?
set -e
if (( rc != 0 )); then
  printf 'not ok - live Socket alert-witness query failed (exit %s; response withheld)\n' "$rc" >&2
  exit 1
fi

if jq -e '
  ((.data.self.alerts | length) > 0)
  and ([.data.self.alerts[]
        | select(.severity == "critical" and .category == "supplyChainRisk")]
       | length > 0)
  and ([.data.self.alerts[]
        | select((.name | type) == "string" and (.name | length) > 0
                 and (.example | type) == "string")]
       | length) == (.data.self.alerts | length)
' "$alerts" >/dev/null 2>&1; then
  printf 'ok - live Socket alert objects carry the malice class the BLOCK reads\n'
else
  printf 'not ok - live Socket alert contract changed: no critical/supplyChainRisk alert on a known-flagged version, or alert members moved (response withheld)\n' >&2
  exit 1
fi
