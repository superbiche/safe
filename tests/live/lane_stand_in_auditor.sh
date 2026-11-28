#!/usr/bin/env bash
if [[ "${1:-}" == "scanner-batch" ]]; then
  jq -c --arg adv "${LIVE_ADVISORY_NAME:-}" --arg mal "${LIVE_MALWARE_NAME:-}" '{schema_version: 1, policy: {block_severities: ["critical"]},
          identities: [.packages[] | {name, version, coverage: "complete", gap: "",
            advisories: (if .name == $mal then [{id: "MAL-live-0001", severity: "critical", malware: true}]
                         elif .name == $adv then [{id: "GHSA-live-0001", severity: "critical", malware: false}] else [] end)}],
          blocklist: []}'
  exit 0
fi
# The lane's read-only door into the operator's stores: no standing acceptance applies.
if [[ "${1:-}" == "lane-revoke" ]]; then cat >/dev/null; printf '{"revoked":[]}\n'; exit 0; fi
if [[ "${1:-}" == "lane-acceptances" ]]; then cat >/dev/null; printf '{"schema_version":1,"acceptances":[]}\n'; exit 0; fi
# Socket's facts on the named roots (package-audit --evidence-only): a fixture, because no Socket credential is
# available to a live run; every named root scores clear and no block is cached.
if [[ "${1:-}" == "package-audit" && "$*" == *"--evidence-only"* ]]; then
  jq -c '{schema_version: 1, roots: [.roots[] | {name, version, outcome: "clear", gate_exit: 0, line: "PASS (score=95)", causes: [], cached: false}], cached_blocks: [], cache_gap: ""}'
  exit 0
fi
# The whole-project scan, as the lane runs it after a publication (`repo-audit . --deps-only --result-out <file>`): it writes a result
# document like the real auditor's, with what the scenario asks for (a critical finding in another ecosystem, scanners that are not ok, a
# failing scan); without a result file asked for it writes none.
if [[ "${1:-}" == "repo-audit" ]]; then
  result_out=""; prev=""
  for arg in "$@"; do [[ "${prev}" == "--result-out" ]] && result_out="${arg}"; prev="${arg}"; done
  [[ "${LIVE_SCAN_EXIT:-0}" == 0 ]] || exit "${LIVE_SCAN_EXIT}"
  [[ -z "${result_out}" ]] || jq -n --argjson py "${LIVE_SCAN_PYTHON_CRITICAL:-0}" --argjson partial "${LIVE_SCAN_PARTIAL:-0}" \
    '{verdict: "GO", cve_scan: {critical: $py, high: 0, medium: 0, low: 0, findings: []}, audit_totals: {critical: $py, by_ecosystem: (if $py > 0 then {python: {critical: $py}} else {} end)},
      tool_status: (if $partial == 1 then {"osv-scanner": {status: "partial", note: "could not read a lockfile"}, syft: {status: "skipped", note: "unavailable"}, grype: {status: "ok", note: null}} else {grype: {status: "ok", note: null}} end),
      ecosystem_audits: []}' > "${result_out}"
  exit 0
fi
exit 0
