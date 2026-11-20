package projectlane

import (
	"strings"
	"testing"
)

const validEvidence = `{
  "schema_version": 1,
  "policy": {"block_severities": ["critical"]},
  "identities": [
    {"name": "p", "version": "1.0.0", "coverage": "complete", "gap": "",
     "advisories": [{"id": "GHSA-abcd-0001", "severity": "high", "malware": false},
                    {"id": "MAL-2026-1", "severity": "critical", "malware": true}]},
    {"name": "q", "version": "2.0.0", "coverage": "missing", "gap": "OSV batch query failed", "advisories": []}
  ],
  "blocklist": [{"name": "evil", "reason": "operator blocklist"}]
}`

const validAcceptances = `{
  "schema_version": 1,
  "acceptances": [
    {"kind": "local_exact_approval", "name": "p", "version": "1.0.0", "host": "registry.npmjs.org", "advisories": [], "causes": []},
    {"kind": "followed_advisory_override", "name": "p", "version": "1.0.0", "host": "registry.npmjs.org", "advisories": ["GHSA-abcd-0001"], "causes": []}
  ]
}`

func TestReadEvidenceAcceptsAValidDocument(t *testing.T) {
	evidence, err := ReadEvidence([]byte(validEvidence))
	if err != nil {
		t.Fatalf("ReadEvidence() error = %v", err)
	}
	if len(evidence.Identities) != 2 || len(evidence.Identities[0].Advisories) != 2 ||
		evidence.Blocklist[0].Name != "evil" || evidence.Policy.BlockSeverities[0] != "critical" {
		t.Fatalf("evidence = %+v", evidence)
	}
}

func TestReadEvidenceRefuses(t *testing.T) {
	replace := func(old, new string) string {
		if !strings.Contains(validEvidence, old) {
			t.Fatalf("fixture lacks %q", old)
		}
		return strings.Replace(validEvidence, old, new, 1)
	}
	cases := map[string]string{
		"not JSON":                                    `nope`,
		"not an object":                               `[]`,
		"empty":                                       ``,
		"two documents":                               validEvidence + validEvidence,
		"unknown schema version":                      replace(`"schema_version": 1`, `"schema_version": 2`),
		"missing schema version":                      replace(`"schema_version": 1,`, ``),
		"unknown top-level member":                    replace(`"blocklist"`, `"extra": 1, "blocklist"`),
		"unknown identity member":                     replace(`"coverage": "complete"`, `"coverage": "complete", "published": "2026-01-01"`),
		"repeated member":                             replace(`"schema_version": 1,`, `"schema_version": 1, "schema_version": 1,`),
		"repeated member, folded":                     replace(`"schema_version": 1,`, `"schema_version": 1, "Schema_Version": 1,`),
		"missing identities":                          strings.Replace(validEvidence, `"identities"`, `"identitiez"`, 1),
		"null blocklist":                              replace(`"blocklist": [{"name": "evil", "reason": "operator blocklist"}]`, `"blocklist": null`),
		"missing policy list":                         replace(`"block_severities": ["critical"]`, `"x": []`),
		"unknown severity in policy":                  replace(`"block_severities": ["critical"]`, `"block_severities": ["catastrophic"]`),
		"missing advisories list":                     replace(`"gap": "OSV batch query failed", "advisories": []`, `"gap": "OSV batch query failed"`),
		"unknown coverage":                            replace(`"coverage": "complete"`, `"coverage": "partial"`),
		"complete coverage with gap":                  replace(`"coverage": "complete", "gap": ""`, `"coverage": "complete", "gap": "x"`),
		"missing coverage no gap":                     replace(`"gap": "OSV batch query failed"`, `"gap": ""`),
		"duplicate identity":                          replace(`{"name": "q", "version": "2.0.0"`, `{"name": "p", "version": "1.0.0"`),
		"duplicate advisory":                          replace(`"id": "MAL-2026-1"`, `"id": "GHSA-abcd-0001"`),
		"malformed advisory id":                       replace(`GHSA-abcd-0001", "severity": "high"`, `GHSA abcd", "severity": "high"`),
		"unknown advisory severity":                   replace(`"severity": "high"`, `"severity": "scary"`),
		"malware flag on a GHSA":                      replace(`"severity": "high", "malware": false`, `"severity": "high", "malware": true`),
		"MAL record not flagged":                      replace(`"malware": true`, `"malware": false`),
		"blocklist without a name":                    replace(`{"name": "evil"`, `{"name": ""`),
		"acceptances inside the evidence document":    replace(`"blocklist"`, `"acceptances": [], "blocklist"`),
		"acceptances smuggled with a repeated member": replace(`"blocklist"`, `"acceptances": [], "acceptances": [], "blocklist"`),
	}
	for name, document := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ReadEvidence([]byte(document)); err == nil {
				t.Fatal("ReadEvidence() error = nil, want an error")
			}
		})
	}
}

func TestReadAcceptances(t *testing.T) {
	acceptances, err := ReadAcceptances([]byte(validAcceptances))
	if err != nil || len(acceptances) != 2 || acceptances[1].Advisories[0] != "GHSA-abcd-0001" {
		t.Fatalf("ReadAcceptances() = %+v, %v", acceptances, err)
	}
	if empty, err := ReadAcceptances([]byte(`{"schema_version":1,"acceptances":[]}`)); err != nil || len(empty) != 0 {
		t.Fatalf("an empty list is a valid document: %+v, %v", empty, err)
	}
	replace := func(old, new string) string {
		if !strings.Contains(validAcceptances, old) {
			t.Fatalf("fixture lacks %q", old)
		}
		return strings.Replace(validAcceptances, old, new, 1)
	}
	cases := map[string]string{
		"not JSON":                    `nope`,
		"two documents":               validAcceptances + validAcceptances,
		"unknown schema version":      replace(`"schema_version": 1`, `"schema_version": 2`),
		"missing schema version":      replace(`"schema_version": 1,`, ``),
		"unknown top-level member":    replace(`"acceptances"`, `"extra": 1, "acceptances"`),
		"repeated member":             replace(`"schema_version": 1,`, `"schema_version": 1, "schema_version": 1,`),
		"null list":                   `{"schema_version":1,"acceptances":null}`,
		"unknown acceptance member":   replace(`"kind": "local_exact_approval"`, `"kind": "local_exact_approval", "reason": "x"`),
		"unknown acceptance kind":     replace(`"local_exact_approval"`, `"trust_me"`),
		"override without advisories": replace(`"advisories": ["GHSA-abcd-0001"]`, `"advisories": []`),
		"approval listing advisories": replace(`"host": "registry.npmjs.org", "advisories": []`, `"host": "registry.npmjs.org", "advisories": ["GHSA-abcd-0001"]`),
		"acceptance without host":     replace(`"host": "registry.npmjs.org", "advisories": []`, `"host": "", "advisories": []`),
		"malformed advisory id":       replace(`GHSA-abcd-0001"]`, `GHSA abcd"]`),
	}
	for name, document := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ReadAcceptances([]byte(document)); err == nil {
				t.Fatal("ReadAcceptances() error = nil, want an error")
			}
		})
	}
}
