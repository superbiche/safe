# Install suite assumes its parent is outside no-new-privs

Date: 2026-09-12
Source: release v1.61.0 / PR #144
Affects: tests/install/run.sh, case_doctor_podman_probe_skips_exec_under_no_new_privs

The case first verifies explicit setpriv --no-new-privs handling, then runs the
same doctor command without setpriv and expects a podman version probe. If the
parent agent already inherits NoNewPrivs=1, omitting setpriv cannot remove it.
Safe correctly reports podman present/unprobed, but the latter assertion fails.
This forced an operator terminal run for the release: operator supplied 195/195
passes; agent environment had 194/195 with only this case failing.

Suggested fix: make environment assumptions explicit in the test harness, preserve
both sandboxed and unsandboxed verification in an appropriate execution environment,
and report unavailable coverage honestly. Do not change Safe's production probe
behavior or bypass no-new-privs. Avoid requiring manual operator test runs for
routine releases. The user specifically challenged why this was necessary.

Evidence: tmp/audit-report/release-gates.log; operator's full passing output in
Codex thread 01a0957f-77f7-7450-bb17-116c11fbd87e.
