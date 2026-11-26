package projectlane

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strings"

	"github.com/superbiche/safe/internal/strictjson"
)

// The project scan, as a report (ticket 1639). The scan is today's `safe audit repo-audit . --deps-only`; its result document is read
// here and never its output. The reading follows the gate's own (lib/gate-lib.sh, safe_gate_scan_project): the verdict is the document's
// audit totals, the critical findings are counted per ecosystem from `by_ecosystem`, and a scanner has a coverage failure when its status
// is "error", or is not "ok" and its note says it failed. What differs is what is kept: only counts, ecosystem names of the known set,
// and scanner names that read as names. Nothing the scan or its tools wrote as free text is kept.

// ScanEcosystems is the scan's known set, as `by_ecosystem` names it.
var ScanEcosystems = []string{"composer", "go", "npm", "python", "rust"}

var scannerName = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,31}$`)

const maxScanFailures = 20

// ScanSummary is what a scan result says that a report may keep.
type ScanSummary struct {
	SchemaVersion int `json:"schema_version"`
	// CriticalTotal is the scan's own total of critical findings.
	CriticalTotal int `json:"critical_total"`
	// Critical is the count per ecosystem of the known set (only those above zero).
	Critical map[string]int `json:"critical"`
	// Unattributed are the critical findings not attributed to an ecosystem of the known set: those of any other key, or all of them
	// when the document has no breakdown, or one that does not add up to the total.
	Unattributed int `json:"unattributed"`
	// CoverageFailures are the scanners that did not run to completion, as names; CoverageOther counts those whose name does not read
	// as one (or that do not fit the bound).
	CoverageFailures []string `json:"coverage_failures"`
	CoverageOther    int      `json:"coverage_other"`
}

// ErrNoVerdict: the document is not one that carries a verdict.
var ErrNoVerdict = errors.New("the scan result carries no verdict")

type ecosystemCounts struct {
	Critical *json.Number `json:"critical"`
}

// ReadScanSummary reads a scan result document.
func ReadScanSummary(raw []byte) (ScanSummary, error) {
	summary := ScanSummary{SchemaVersion: 1, Critical: map[string]int{}, CoverageFailures: []string{}}
	members, err := strictjson.ParseObject(raw)
	if err != nil {
		return summary, ErrNoVerdict
	}
	total, ok := criticalTotal(members)
	if !ok {
		return summary, ErrNoVerdict
	}
	summary.CriticalTotal = total
	known := map[string]bool{}
	for _, name := range ScanEcosystems {
		known[name] = true
	}
	breakdown, consistent := breakdownOf(members, total)
	if !consistent {
		summary.Unattributed = total
	} else {
		for name, count := range breakdown {
			switch {
			case count == 0:
			case known[name]:
				summary.Critical[name] = count
			default:
				summary.Unattributed += count
			}
		}
	}
	names := map[string]bool{}
	other := 0
	note := func(name string) {
		if scannerName.MatchString(name) {
			names[name] = true
		} else {
			other++
		}
	}
	var status map[string]json.RawMessage
	if json.Unmarshal(members["tool_status"], &status) == nil {
		for name, value := range status {
			if scanBroken(value) {
				note(name)
			}
		}
	}
	var audits []json.RawMessage
	if json.Unmarshal(members["ecosystem_audits"], &audits) == nil {
		for _, value := range audits {
			if !scanBroken(value) {
				continue
			}
			var named struct {
				Scanner string `json:"scanner"`
			}
			if json.Unmarshal(value, &named) != nil || named.Scanner == "" {
				note("unknown")
				continue
			}
			note(named.Scanner)
		}
	}
	for name := range names {
		summary.CoverageFailures = append(summary.CoverageFailures, name)
	}
	sort.Strings(summary.CoverageFailures)
	if len(summary.CoverageFailures) > maxScanFailures {
		other += len(summary.CoverageFailures) - maxScanFailures
		summary.CoverageFailures = summary.CoverageFailures[:maxScanFailures]
	}
	summary.CoverageOther = other
	return summary, nil
}

// criticalTotal is the gate's own reading: audit_totals.critical, else cve_scan.critical, and it must be a number.
func criticalTotal(members map[string]json.RawMessage) (int, bool) {
	for _, path := range [][]string{{"audit_totals", "critical"}, {"cve_scan", "critical"}} {
		raw, ok := members[path[0]]
		if !ok {
			continue
		}
		var inner map[string]json.RawMessage
		if json.Unmarshal(raw, &inner) != nil {
			continue
		}
		var n int
		if value := bytes.TrimSpace(inner[path[1]]); len(value) > 0 && string(value) != "null" && json.Unmarshal(value, &n) == nil && n >= 0 {
			return n, true
		}
	}
	return 0, false
}

// breakdownOf is audit_totals.by_ecosystem when it is an object whose critical counts add up to the total.
func breakdownOf(members map[string]json.RawMessage, total int) (map[string]int, bool) {
	var totals map[string]json.RawMessage
	if json.Unmarshal(members["audit_totals"], &totals) != nil {
		return nil, false
	}
	var by map[string]json.RawMessage
	if json.Unmarshal(totals["by_ecosystem"], &by) != nil || by == nil {
		return nil, false
	}
	counts := map[string]int{}
	sum := 0
	for name, raw := range by {
		var entry struct {
			Critical int `json:"critical"`
		}
		if json.Unmarshal(raw, &entry) != nil || entry.Critical < 0 {
			return nil, false
		}
		counts[name] = entry.Critical
		sum += entry.Critical
	}
	return counts, sum == total
}

// scanBroken is the gate's predicate: status "error", or a status that is not "ok" whose note says it failed or errored.
func scanBroken(raw json.RawMessage) bool {
	var entry struct {
		Status string `json:"status"`
		Note   string `json:"note"`
	}
	if json.Unmarshal(raw, &entry) != nil {
		return false
	}
	status := entry.Status
	if status == "" {
		status = "ok"
	}
	if status == "error" {
		return true
	}
	if status == "ok" {
		return false
	}
	text := strings.ToLower(entry.Note)
	return strings.Contains(text, "fail") || strings.Contains(text, "error")
}
