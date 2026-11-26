package projectlane

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
	"sort"

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
	// CoverageGaps are the scanners whose status is not "ok" (the producer's own rule: bin/safe-audit treats every scanner whose status is
	// not ok as a gap), as the scanner's name and the status WORD, from the closed list ScanStatuses. No note is read. CoverageOther
	// counts a gap whose name does not read as one, whose status is another word, or that does not fit the bound. CoverageUnreadable is
	// true when a coverage section is there and cannot be read: that is not zero gaps.
	CoverageGaps       []ScanGap `json:"coverage_gaps"`
	CoverageOther      int       `json:"coverage_other"`
	CoverageUnreadable bool      `json:"coverage_unreadable"`
}

// ScanGap is a scanner that did not give its whole coverage.
type ScanGap struct {
	Scanner string `json:"scanner"`
	Status  string `json:"status"`
}

// ScanStatuses is the closed list of the producer's non-ok statuses.
var ScanStatuses = map[string]bool{"partial": true, "skipped": true, "unavailable": true, "error": true}

// ErrNoVerdict: the document is not one that carries a verdict.
var ErrNoVerdict = errors.New("the scan result carries no verdict")

// ReadScanSummary reads a scan result document.
func ReadScanSummary(raw []byte) (ScanSummary, error) {
	summary := ScanSummary{SchemaVersion: 1, Critical: map[string]int{}, CoverageGaps: []ScanGap{}}
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
	gaps := map[ScanGap]bool{}
	other := 0
	note := func(name, status string) {
		switch {
		case scannerName.MatchString(name) && ScanStatuses[status]:
			gaps[ScanGap{Scanner: name, Status: status}] = true
		default:
			other++
		}
	}
	// status reads a scanner's status word the producer's way: absent is ok; present and not a string is unreadable.
	status := func(raw json.RawMessage) (word string, readable bool) {
		var entry map[string]json.RawMessage
		if json.Unmarshal(raw, &entry) != nil || entry == nil {
			return "", false
		}
		value, present := entry["status"]
		if !present {
			return "ok", true
		}
		if json.Unmarshal(value, &word) != nil {
			return "", false
		}
		return word, true
	}
	if raw, present := members["tool_status"]; present {
		var tools map[string]json.RawMessage
		if json.Unmarshal(raw, &tools) != nil || tools == nil {
			summary.CoverageUnreadable = true
		}
		for name, value := range tools {
			word, readable := status(value)
			switch {
			case !readable:
				summary.CoverageUnreadable = true
			case word != "ok":
				note(name, word)
			}
		}
	}
	if raw, present := members["ecosystem_audits"]; present {
		var audits []json.RawMessage
		if json.Unmarshal(raw, &audits) != nil || audits == nil {
			summary.CoverageUnreadable = true
		}
		for _, value := range audits {
			word, readable := status(value)
			if !readable {
				summary.CoverageUnreadable = true
				continue
			}
			if word == "ok" {
				continue
			}
			var named struct {
				Scanner string `json:"scanner"`
			}
			_ = json.Unmarshal(value, &named)
			note(named.Scanner, word)
		}
	}
	for gap := range gaps {
		summary.CoverageGaps = append(summary.CoverageGaps, gap)
	}
	sort.Slice(summary.CoverageGaps, func(i, j int) bool {
		a, b := summary.CoverageGaps[i], summary.CoverageGaps[j]
		if a.Scanner != b.Scanner {
			return a.Scanner < b.Scanner
		}
		return a.Status < b.Status
	})
	if len(summary.CoverageGaps) > maxScanFailures {
		other += len(summary.CoverageGaps) - maxScanFailures
		summary.CoverageGaps = summary.CoverageGaps[:maxScanFailures]
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
