# Medium advisory blocked Encre frozen-lock dependency restore

Observed in Encre graph task398: pnpm install --frozen-lockfile in apps/web refused exit102 for devalue@5.9.2, Medium GHSA-4q55-j62x-fr9h. Required web gates remain blocked; no agent bypass or policy mutation performed. Audit evidence: /home/michel/.local/share/safe/audit/results/rainbow/2026-10-12-scan.json (mutable historical receipt path; verify exact offending install evidence before implementation).

Operator ruling 2026-10-12: vulnerability severity below High/Critical should inform but not block installation. Please reconcile advisory severity classification and package-manager gating so Low/Medium advisory findings do not require operator confirmation solely because of that severity. Preserve separate malware/blocklist, critical behavioral signals, audit-infrastructure failures and explicit trust boundaries; do not infer this ruling waives those independent controls. Add focused gate tests and update owning policy/contract after independent review.

This is a cross-project policy-change request, not an assertion the advisory is false or fixed. Current Encre refusal stays in force until operator confirmation or reviewed Safe implementation. No Safe enforcement/config changes authorized in this capture task.
