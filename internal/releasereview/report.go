package releasereview

import (
	"encoding/json"
	"fmt"
)

// Severity is a verdict, ordered so that worse compares greater.
//
// BLOCK dominates ERROR deliberately. Both fail closed, but they are different
// signals with different recovery paths: ERROR says the review could not run,
// ERROR must never read as a finding about the release, and a real malice
// signal must never be downgraded to "our tooling broke".
type Severity int

// Verdict levels, ordered by severity.
const (
	GO Severity = iota
	WARN
	ERROR
	BLOCK
)

func (s Severity) String() string {
	switch s {
	case BLOCK:
		return "BLOCK"
	case ERROR:
		return "ERROR"
	case WARN:
		return "WARN"
	case GO:
		return "GO"
	}
	return fmt.Sprintf("Severity(%d)", int(s))
}

// MarshalJSON writes the verdict name; the numeric ordering is internal.
func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// ExitCode is the process exit code a top-level verdict maps to. ERROR is 30,
// the audit-infrastructure-breakage code the bash lanes already use, so a
// consumer can tell a broken review from a refused release by exit code alone.
func (s Severity) ExitCode() int {
	switch s {
	case WARN:
		return 10
	case BLOCK:
		return 20
	case ERROR:
		return 30
	default:
		return 0
	}
}

// worst returns the more severe of two verdicts.
func worst(a, b Severity) Severity {
	if b > a {
		return b
	}
	return a
}

// capAdvisory is the advisory cap: an advisory check may warn but never
// decides the run. Applied only at top-level aggregation, so the check's own
// entry in the report still carries what it actually found.
func (s Severity) capAdvisory() Severity {
	if s > WARN {
		return WARN
	}
	return s
}

// Report is one release review, schema_version 1.
type Report struct {
	SchemaVersion int           `json:"schema_version"`
	Subject       Subject       `json:"subject"`
	Verdict       Severity      `json:"verdict"`
	Checks        []CheckResult `json:"checks"`
}

// CheckResult is one enabled check's own, uncapped result.
type CheckResult struct {
	ID       string   `json:"id"`
	Advisory bool     `json:"advisory"`
	Verdict  Severity `json:"verdict"`
	Reasons  []Reason `json:"reasons"`
}

// Reason is one occurrence a check found. Code is scoped to the check that
// emitted it, so the stable key is the pair (check id, code).
type Reason struct {
	Code    string            `json:"code"`
	Message string            `json:"message"`
	Data    map[string]string `json:"data,omitempty"`
}

// bump raises the check's verdict; nothing ever lowers it.
func (r *CheckResult) bump(severity Severity) {
	r.Verdict = worst(r.Verdict, severity)
}

func (r *CheckResult) add(severity Severity, code, message string, data map[string]string) {
	r.bump(severity)
	r.Reasons = append(r.Reasons, Reason{Code: code, Message: message, Data: data})
}

// Review runs the spec's enabled checks and aggregates one verdict.
//
// The spec reaching here is a validated one, which is what makes the switch
// below total: an enabled check with no arm cannot occur unless validation and
// the check registry disagree, and that disagreement is reported as ERROR
// rather than passing as a check that found nothing.
//
// One computation is hoisted out of the loop: whether cosign vouched for an
// artifact is what tells the checksum check apart a digest that was verified
// from a digest that was merely matched, so the signature check runs before the
// report is assembled. Assembly itself stays strictly in checkOrder — only the
// order in which results are computed moves.
func Review(spec Spec) Report {
	report := Report{
		SchemaVersion: 1,
		Subject:       spec.Subject,
		Checks:        []CheckResult{},
	}

	enabled := spec.enabledChecks()

	var signatureResult CheckResult
	var verified map[int]bool
	for _, check := range enabled {
		if check.ID == CheckSignature {
			signatureResult, verified = signature(spec)
		}
	}

	verdict := GO
	for _, check := range enabled {
		var result CheckResult
		switch check.ID {
		case CheckChecksum:
			result = checksum(spec, verified)
		case CheckSignature:
			result = signatureResult
		case CheckTUF:
			result = tuf(spec)
		case CheckExec:
			result = sandboxExec(spec)
		default:
			result = CheckResult{Reasons: []Reason{}}
			result.add(ERROR, "check_not_implemented",
				fmt.Sprintf("check %q is enabled but this build has no implementation for it", check.ID), nil)
		}
		result.ID = check.ID
		result.Advisory = check.Advisory

		effective := result.Verdict
		if check.Advisory {
			effective = effective.capAdvisory()
		}
		verdict = worst(verdict, effective)
		report.Checks = append(report.Checks, result)
	}
	report.Verdict = verdict
	return report
}
