# Scanner-batch test inherits the host scanner override

**Date:** 2026-09-12
**Source:** safe audit-report task
**Affects:** tests/audit/scanner_batch.sh, full-suite hermeticity

With AUBE_SECURITY_SCANNER inherited as /home/michel/.config/safe/scanner.mjs,
case_gate_injects_scanner_env (around lines 619–627) fails its custom-directory
and no-file assertions: production correctly preserves caller overrides, while
those two test commands assume the variable is absent. The explicit caller-wins
case succeeds.

Observed twice on c232ca1: 33 passed, 1 failed. Running
`env -u AUBE_SECURITY_SCANNER bash tests/audit/scanner_batch.sh` passes 34/34.
No production source or configuration change was needed.

Suggested action: make the two absence-dependent test subprocesses explicitly
unset AUBE_SECURITY_SCANNER, retaining the explicit caller-wins case. This is
outside the reporting patch; do not change gate override behavior.

Evidence: tmp/audit-report/scanner-batch-retry.log and
scanner-batch-clean-env.log; initial full run gates.log.
