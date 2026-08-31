# Ecosystem audit records govulncheck as error while reporting exit 0

Captured 2026-08-31 (gofmt-drift slice, seen on a solo gated `go` run — no
parallel contention involved).

A repo-audit through the live 1.54.0 gate printed, in ECOSYSTEM AUDITS:

    govulncheck: error (govulncheck failed (exit 0))

and the gate then warned `safe install: scanner failure (govulncheck); that
coverage is missing`. The parenthetical contradicts itself: an exit-0
govulncheck being recorded as *failed* means the audit lane is misreading the
scanner's result (wrong success predicate, output-parse failure, or a
misattributed status), not that the scanner broke. The same noise was
mentioned in passing in the (now closed) 2026-08-30 contention note, but this
occurrence was solo, so it is not a contention artifact.

Ask: diagnose how the govulncheck ecosystem-audit lane classifies results —
reproduce with a Go project, find why exit 0 reads as failure, and fix the
predicate so govulncheck coverage stops being reported missing when the
scanner ran fine. Standing ruling applies: audit-infrastructure failure must
read as breakage-to-fix — but a *healthy* run misread as breakage is the
inverse defect and equally trust-eroding.
