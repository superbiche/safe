# repo-audit classifies a clean osv-scanner run as failed (coverage silently degraded)

**Date:** 2026-08-13
**Source:** liaison (memory-sync-mcp run prep)
**Affects:** safe repo-audit / rainbow scanner wrapper

## Observed

During the `go test` repo-audit hook in `~/dev/personal/memory-sync-mcp`
(osv-scanner 2.3.8, osv-scalibr 0.4.5):

- `rainbow: continuing without govulncheck; their coverage is reported as not run`
- `osv-scanner failed; details: /tmp/tmp.*/osv.json.stderr`
- Yet the captured stderr shows a NORMAL scan: `Scanned
  .../deploy/package-lock.json file and found 446 packages ... End status: 0
  dirs visited, 2 inodes visited, 1 Extract calls, 27ms elapsed` — clean
  completion, packages found.

`safe doctor` reports no missing prerequisites. Reproducible on every `go
test` in that repo.

## Why it matters

Two of the audit's evidence tiers (osv-scanner, govulncheck) silently degrade
while the audit line still prints "finished project" — the operator reads
green coverage that is not there. Likely an output/exit-format change in
osv-scanner 2.3.x that the rainbow wrapper's success detection predates.

## Suggested action

Reproduce with the wrapper's own invocation against osv-scanner 2.3.8; fix
the success-detection (exit code vs stderr shape); consider a doctor check
asserting the wrapper can parse the INSTALLED scanner version's output, so a
scanner upgrade cannot silently strip a tier again. Also check why
govulncheck is skipped on a Go repo — that tier is the more relevant one
there.
