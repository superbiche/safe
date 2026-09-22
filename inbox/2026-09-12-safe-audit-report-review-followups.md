# Follow-ups from audit report review

**Date:** 2026-09-12
**Source:** safe report changes c232ca1 / 696170c
**Affects:** pre-existing audit severity normalization and terminal rendering

Independent GLM Flash review passed with two minor findings. The wording finding
was corrected in 696170c. These remaining items need separate triage:

- **Empty OSV database severity:** an advisory with database_specific.severity=""
  and severity[0].score="9.8" produces critical=0 and verdict=GO while normalized
  severity is 9.8. Both main and candidate reproduce this; new reporting makes
  the existing disagreement visible by printing the critical advisory. Aligning
  counts and normalized severity changes verdict behavior and needs its own
  policy/test slice. Curated OSV data is expected to use a word or omit the field;
  the reported opencode scan does not contain this malformed input.
- **Ecosystem stderr notes:** existing note rendering does not strip terminal
  control characters; the newly added advisory renderer does. Consider applying
  equivalent one-line sanitization to notes in a separate reporting fix.
- **Numeric severity parsing:** severity_from_osv_entry uses substring heuristics
  such as *9.*; exact numeric parsing would be a separate severity-policy change.

Reproduction: tmp/audit-report/reproduce-f1.sh; f1-base.json and f1-current.json
show identical GO/zero counts and normalized severity 9.8. Review:
/home/michel/.liaison/reviews/2026-09-12-safe-audit-reporting/FINDINGS-r1.md.
No verdict, override or gate configuration changes were made in this task.
