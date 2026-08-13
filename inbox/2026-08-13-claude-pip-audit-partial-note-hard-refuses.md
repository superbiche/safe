# pip-audit partial coverage hard-refuses the install, because its note says "failed"

**Date:** 2026-08-13
**Source:** claude-code (sibling sweep while closing PR #80's review F1)
**Affects:** `bin/safe-audit` pip-audit normalizer ↔ `bin/safe` install gate

## Observed

`run_pip_audit_dir` keeps what the surviving targets found when one pip-audit
invocation fails, and marks the record `partial`:

```
audit_status="partial"
partial_note="pip-audit failed for: ${failed[*]}"
```

The comment directly above states the intent — "One target failing must not
erase what another target FOUND": counts are real but incomplete, so the
verdict is WARN and the operator can accept it.

The install gate then reads that note:

```
def broken: (.status // "ok") as $s
  | ($s == "error") or (($s != "ok") and (((.note // "") | test("fail|error"; "i"))));
```

`partial` is not `ok`, and the note contains the literal word `failed`, so the
gate classifies the scanner as broken and refuses with exit 100 — which
`--yes` may not accept. The partial-coverage path the normalizer builds is
therefore unreachable at the surface that matters.

## Why it matters

Same defect class as PR #80's F1: **a non-error tool status whose free-form
note is read by a policy predicate.** F1 was the version I introduced (paths
interpolated into a note, so a project under `error-pages/` refused); this one
is pre-existing and was found by the sibling sweep that F1's closure required.

The difference is that F1 was unambiguously wrong — a directory name is not
evidence about a scanner. Here the wording is accurate: a pip-audit target
really did fail. So the question is not "fix the string" but **what should a
partly-failed pip-audit do at the install gate**, and that is a policy call.

## Suggested action

Needs an operator ruling before code. Three shapes:

1. **Honour the normalizer's stated intent** — `partial` is coverage loss, not
   breakage: WARN, disclose in `not run:`, acceptable under `--yes`. Requires
   the gate to stop deriving "broken" from prose for non-error statuses.
2. **Keep the refusal and make it deliberate** — a failed pip-audit target IS
   broken infrastructure; then the normalizer's comment is wrong and should
   say so, and `partial` should be reserved for losses that do not refuse.
3. **Split the signal structurally** — carry a boolean the gate reads instead
   of regex-matching a human-facing note, which retires the whole defect class
   rather than this instance. Larger, and it touches every scanner record.

Option 3 is what would have prevented both F1 and this one, but it is a
contract change to the result document, not a fix.

Chain reference: `~/.liaison/reviews/2026-08-13-safe-osv-lockfile-coverage/`
(`FINDINGS-r1-sweep.md`, N1). Also parked in the Semaphore audit lane; this
note is the repo-side copy so the ruling happens where the code lives.

Reproduction: a project declaring two pip-audit targets where one invocation
fails and the other succeeds.
`tests/audit/ecosystem_audits.sh:case_pip_audit_partial_failure_keeps_what_was_found`
already builds that state and asserts the counts survive — what is unasserted
is the gate's reaction to the resulting note.
