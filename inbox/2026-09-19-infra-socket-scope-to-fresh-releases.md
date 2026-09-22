# Call Socket only where it adds unique evidence: fresh npm and Python releases

Date: 2026-09-19. Source: infra session (machine-setup fleet work on rainbow, tuxedo, agent-dev).
Operator ruling in chat the same day: direction approved; the `safe` session owns the design.

## Observation
Socket is the largest source of friction in `safe`. The operator reaches the rate limit (429)
fast. Each Socket failure (`socket_rate_limited`, `socket_error` on timeout, `socket_auth_failed`)
stops the install and needs an operator confirmation in a TTY. That rule also applies to old
releases, where Socket adds the least.

Live case, 2026-09-19: on tuxedo, `fleet-follow.service` could not install five Go tools
(`50-go-tools`). Each audit ended with "socket score timed out after 15s". Probable cause, not
verified: the Socket token comes from the Bitwarden vault, and no one answers the unlock prompt in
a systemd unit. The same installs passed on rainbow and agent-dev, where Socket answered
`socket_not_found` (tolerated through `install.auto_allow_tolerate`).

Evidence is thin: `safe` keeps no verdict log. The Socket cache on rainbow holds 58 results in
about 38 days (47 npm, 5 python, 4 go, 1 rust, 1 php). The operator estimates that Socket gives a
usable answer for about 10 % of calls. Nothing measures that figure today.

## What Socket adds
- Behavior-based malware detection on a fresh release. No other layer does this. OSV knows only
  published advisories.
- The value is in npm and Python. For go and cargo, Socket answers "no record" almost each time.
- The release-age rule covers much of the same risk: most malicious packages are removed in days.

## Proposal (operator-approved direction)
1. Call Socket only for a release younger than the age threshold, in npm and Python.
2. Do not call Socket for an older release, or for go and cargo. OSV, the blocklist and the age
   rule decide.
3. Keep the failure rule as it is today. When `safe` calls Socket and Socket does not answer, `safe`
   does not install by default and the operator confirms in a TTY. Nothing blocks more than today,
   and nothing installs silently. The gain is frequency: fewer calls, so fewer 429 answers and
   fewer "fresh release, Socket 429: wait, check it yourself, or accept the risk" prompts.
4. A Socket `malware` verdict always blocks.

## Degraded replacement to evaluate
`safe` had a sandbox audit path before. It could replace Socket in a degraded mode: when Socket
gives no answer for a fresh release, or for ecosystems where Socket has no data. The `safe`
session decides if and how.

## Suggested first step
Add a verdict log (package, ecosystem, release age, Socket status and reason, final verdict). It
measures the real share of useful Socket calls before the rule changes.

## Constraint
This change relaxes a `safe` rule. Only the operator rules on it. Agents do not change the `safe`
configuration or weaken enforcement.
