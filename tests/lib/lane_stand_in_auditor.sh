#!/usr/bin/env bash
# The live binding suite's stand-in for the auditor (scenarios A to J). It answers every entry it stands for with the members and types of the
# REAL answers: tests/contract/lane_auditor.sh holds it to tests/lib/lane_auditor_shapes.json, which that suite generates from the real entries.
if [[ "${1:-}" == "scanner-batch" ]]; then
  jq -c --arg adv "${LIVE_ADVISORY_NAME:-}" --arg mal "${LIVE_MALWARE_NAME:-}" --arg blocked "${LIVE_BLOCKLISTED:-}" '{schema_version: 1, policy: {block_severities: ["critical"]},
          identities: [.packages[] | {name, version, coverage: "complete", gap: "",
            advisories: (if .name == $mal then [{id: "MAL-live-0001", severity: "critical", malware: true}]
                         elif .name == $adv then [{id: "GHSA-live-0001", severity: "critical", malware: false}] else [] end)}],
          blocklist: (if $blocked == "" then [] else [{name: $blocked, reason: "blocklisted for the scenario"}] end)}'
  exit 0
fi
# The lane's doors into the operator's stores: no standing acceptance applies and no receipt is revoked, unless the scenario names one.
if [[ "${1:-}" == "lane-revoke" ]]; then
  jq -c --arg revoked "${LIVE_REVOKED:-}" '{revoked: [.identities[] | select(.name == $revoked) | {name, version}]}'
  exit 0
fi
if [[ "${1:-}" == "lane-acceptances" ]]; then
  jq -c --arg accepted "${LIVE_ACCEPTED:-}" '{schema_version: 1, acceptances: [.candidates[] | select(.name == $accepted) | {kind: "local_tolerance", name, version, host, advisories: [], causes: ["socket_low_score"]}]}'
  exit 0
fi
# Socket's facts on the named roots (package-audit --evidence-only): a fixture, because no Socket credential is available to a live run; every named
# root scores clear, and no block is cached unless the scenario names one.
if [[ "${1:-}" == "package-audit" && "$*" == *"--evidence-only"* ]]; then
  jq -c --arg blocked "${LIVE_SOCKET_BLOCKED:-}" '{schema_version: 1,
      roots: [.roots[] | {name, version, outcome: "clear", gate_exit: 0, line: "PASS (score=95)", causes: [], cached: false}],
      cached_blocks: [.cached[] | select(.name == $blocked) | {name, version, line: "BLOCK (critical supply-chain-risk alert)"}], cache_gap: ""}'
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
    '{machine: "local", date: "2026-11-28", timestamp: "2026-11-28T00:00:00+00:00", target: ".", strategy: "local-direct", scan_mode: "deps", sbom: "/dev/null",
      summary: {packages_total: 0, ecosystems: {npm: 0, python: 0, php: 0, rust: 0, go: 0}},
      cve_scan: {critical: $py, high: 0, medium: 0, low: 0, findings: []},
      audit_totals: {critical: $py, high: 0, medium: 0, low: 0, unknown: 0, cve_scan: {critical: $py, high: 0, medium: 0, low: 0}, ecosystem: [],
                     by_ecosystem: (if $py > 0 then {python: {critical: $py, high: 0, medium: 0, low: 0, unknown: 0}} else {} end), deduplicated: false},
      tool_status: (if $partial == 1 then {"osv-scanner": {status: "partial", note: "could not read a lockfile"}, syft: {status: "skipped", note: "unavailable"}, grype: {status: "ok", note: null}}
                    else {"osv-scanner": {status: "ok", note: null}, syft: {status: "ok", note: null}, grype: {status: "ok", note: null}} end),
      ecosystem_audits: [{scanner: "npm-audit", status: "ok", total: 0, critical: 0, high: 0, medium: 0, low: 0, unknown: 0, note: null, root: "."}],
      source_scan: {status: "skipped", note: "source scan disabled in deps-only mode", scanned_files: 0, total: 0, findings: []},
      verdict: "GO", delta: {previous_scan: null, packages_added: 0, packages_removed: 0, new_cves: []}}' > "${result_out}"
  exit 0
fi
exit 0
