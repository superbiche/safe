# Gate repo-audit intermittently claims syft missing under parallel run-all

Captured 2026-08-30 (#206 slice, review-chain verify suite).

During the `safe-tuf-serve-mirror-cage` chain close, the first `tests/run-all.sh`
run at 3173d22 failed 1/25: `tests/audit/socket_tier.sh` could not build the
safe-core test binary because the live gate's repo-audit refused in non-TTY mode
with "rainbow missing required scanners: syft" — while syft IS present on the
host at `/home/michel/go/bin/syft`. Standalone re-run of the suite: 109/109;
full aggregate re-run: 25/25. Evidence: `verify-suite-full.log` /
`verify-suite-run2.log` in `~/.liaison/reviews/2026-08-30-safe-tuf-serve-mirror-cage/`.
Same session also saw `safe install: scanner failure (govulncheck)` noise on
gated `go test` builds.

Ask: diagnose scanner discovery under run-all's parallel/non-interactive
environment (PATH visibility of `~/go/bin`? contention on the scanner probe?)
— an audit-infrastructure failure must read as breakage-to-fix, and a flaky
1-in-25 suite failure will erode trust in the belt.

## Additional instances (2026-08-31, #244 slice)

Four more occurrences during the `safe-lockdiff-config-mirror` chain, all the
same shape (a suite's own `go build` preflight through the live gate loses
scanner discovery under 25-suite contention, fails in ~1s before any case
runs, passes solo immediately after):

- `tests/audit/socket_tier.sh` — "missing required scanners: osv-scanner"
  (orchestrator run at ab9190f); solo rerun 109/109.
- `tests/install/run.sh` — same osv-scanner refusal (orchestrator run at
  198f998); solo rerun 188/188.
- `tests/install/run.sh` — syft variant (implementer run, r1 fix batch);
  solo rerun clean.
- `tests/audit/check_version_aware.sh` — osv-scanner variant (implementer
  run, r4 restructure batch); solo rerun 269/269.

The failing scanner name varies (syft, osv-scanner), the surface varies
(three different suites), the class is constant: discovery-under-contention,
never a real missing scanner. Frequency in this slice: 4 first-attempt
failures across ~8 full run-all executions.
