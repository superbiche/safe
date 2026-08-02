# osv-scanner failing + govulncheck missing on rainbow — Go audit coverage is a hole

**Date:** 2026-08-02
**Source:** memoire (derive near-dup slice, repeated `go build`/`go test` runs)
**Affects:** safe — audit scanner wiring on rainbow

## Observed
Every safe-gated `go` invocation in the memoire repo printed:
- `safe install: scanner failure (osv-scanner); that coverage is missing — safe doctor`
- `safe audit: rainbow missing project audit tools for discovered ecosystems: govulncheck`
One non-interactive `go build ./...` was BLOCKED outright (exit 102,
fail-closed because the scan could not complete headless); subsequent
invocations proceeded on WARN with incomplete coverage. One scan also
reported `+1 new CVEs (GO-2026-5970)` and a later run mentioned a HIGH —
unreviewed because the scan pipeline itself is degraded.

## Why it matters
Per my-safe-gate, scanner failure is escalate-immediately territory: the
scoring wiring is broken, so Go-ecosystem CVE verdicts on rainbow are
running blind, and fail-closed blocks bite headless sessions
mid-verification. The workaround (route builds through `make`) hides the
gap rather than fixing it.

## Suggested action
Run `safe doctor` interactively on rainbow; repair or reinstall
osv-scanner; install govulncheck after verification (the refusal itself
prints the suggested `go install golang.org/x/vuln/cmd/govulncheck@latest`
— pin per safe policy, never @latest in the manifest); then re-run
`safe audit scan --machine rainbow` and review GO-2026-5970 and the
reported HIGH with real coverage.
