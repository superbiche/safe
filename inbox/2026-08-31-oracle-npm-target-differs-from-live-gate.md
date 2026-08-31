# Live oracle attests a different npm than the gate delegates to

Captured 2026-08-31 (#244 slice, implementer find during the r2 fix batch).

`tests/live/npm_config_oracle.sh` resolves npm the way the gate does (first
non-wrapper npm on PATH) and, under the test harness's PATH, lands on
`/usr/bin/npm` — the distro Node-22 npm, version 10.9.8. The operator's live
gated shell resolves the mise shim instead and delegates to npm 12.0.2
(verified: `npm --version` through the installed gate prints 12.0.2). So the
suite's oracle assertions have been attesting npm behaviors against a
different build than the one the live gate actually delegates to.

Mitigation already shipped in #244: the suite prints its resolved target as
its first line (`# npm oracle target: <path> (<version>)`), so the skew can
never be invisible again, and two behaviors that differ between the builds
(env-PWD pinning, `${VAR?}` substitution) are recorded shape-per-version
rather than asserted single-shape.

Ask: rule whether the oracle should resolve the SAME npm the live gate
resolves (e.g. run its probes through the shim / an operator-shell-shaped
PATH), or whether attesting the harness-PATH npm is acceptable as long as the
target is printed. Related question, wider than the suite: is `/usr/bin/npm`
ever what the gate resolves in a real operator shell (e.g. a shell without
mise activation), and if so, is npm 10.9.8 inside the supported set — repo
docs currently treat npm 12 as the only supported npm.
