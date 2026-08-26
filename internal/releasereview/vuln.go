package releasereview

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type githubAdvisory struct {
	GHSAID          string `json:"ghsa_id"`
	CVEID           string `json:"cve_id"`
	Severity        string `json:"severity"`
	Vulnerabilities []struct {
		VulnerableVersionRange string `json:"vulnerable_version_range"`
		PatchedVersions        string `json:"patched_versions"`
	} `json:"vulnerabilities"`
}

// vuln matches the release's version against the repository's own published
// security advisories.
//
// This is the one lane with a genuine WARN tier. An advisory of low or moderate
// severity that affects this version is a real observation a consumer should
// see, but it is not by itself a reason to refuse a release — unlike a high or
// critical one, which is. What cannot be mapped at all is BLOCK: an advisory
// whose affected range this build cannot parse might or might not cover the
// version, and "might" fails closed.
func vuln(spec Spec) CheckResult {
	result := CheckResult{Reasons: []Reason{}}
	client := newGitHubClient()
	repo := spec.Subject.Repo
	// version is the subject's GitHub tag, echoed verbatim into every reason so
	// the report names what the caller passed. comparable is that tag reduced to
	// the version core the advisory ranges are compared against — the tag may
	// carry a `rust-v`-style prefix the semver comparison cannot read.
	version := spec.Subject.Version
	comparable := comparableVersion(version)

	var advisories []githubAdvisory
	capped, err := client.getPaged(fmt.Sprintf("/repos/%s/security-advisories?per_page=100", repo), func(page json.RawMessage) *githubError {
		var batch []githubAdvisory
		if decodeErr := json.Unmarshal(page, &batch); decodeErr != nil {
			return &githubError{message: fmt.Sprintf("GitHub's advisory listing is not an array of advisories: %v", decodeErr)}
		}
		advisories = append(advisories, batch...)
		return nil
	})
	if err != nil {
		if err.notFound {
			// A repository with no advisories answers 200 with an empty array,
			// so a 404 is not "nothing published" — it is the repository itself
			// not being visible, which is evidence about the subject.
			result.add(BLOCK, "advisory_feed_missing",
				fmt.Sprintf("GitHub publishes no advisory feed for %s — either the repository does not exist, or it is private and no GITHUB_TOKEN was set (GitHub answers 404, not 403, for a read it will not authorize)", repo),
				map[string]string{"repo": repo})
			return result
		}
		result.add(ERROR, "advisory_feed_unavailable",
			fmt.Sprintf("could not read the advisory feed for %s, so no advisory was checked against %s — audit-infrastructure breakage, not a finding about the release: %s", repo, version, err.message),
			map[string]string{"repo": repo})
		return result
	}
	if capped {
		// Unlike the release history, there is no early answer here: an
		// advisory this check never read is an advisory it cannot rule out.
		result.add(ERROR, "advisory_feed_truncated",
			fmt.Sprintf("the advisory feed for %s was longer than the %d pages this check reads, so an advisory affecting %s may not have been seen", repo, githubMaxPages, version),
			map[string]string{"repo": repo, "pages": strconv.Itoa(githubMaxPages), "advisories_read": strconv.Itoa(len(advisories))})
		return result
	}

	for _, advisory := range advisories {
		matched, ambiguous := matchAdvisory(advisory, comparable)
		identifier := advisory.GHSAID
		if identifier == "" {
			identifier = "an advisory with no GHSA id"
		}

		if ambiguous {
			result.add(BLOCK, "version_mapping_ambiguous",
				fmt.Sprintf("%s names no affected version range this check can read, so whether it covers %s is unknown", identifier, version),
				map[string]string{"advisory": identifier, "version": version})
		}
		if !matched {
			continue
		}

		severity := advisory.Severity
		if severity == "" {
			severity = "unknown"
		}
		data := map[string]string{"advisory": identifier, "severity": severity}
		if advisory.CVEID != "" {
			data["cve"] = advisory.CVEID
		}
		if isHighOrCritical(severity) {
			result.add(BLOCK, "known_advisory_high_severity",
				fmt.Sprintf("%s affects %s with severity %s", identifier, version, severity), data)
		} else {
			result.add(WARN, "known_advisory",
				fmt.Sprintf("%s affects %s with severity %s", identifier, version, severity), data)
		}
	}
	return result
}

// matchAdvisory decides whether one advisory covers the version.
//
// Entries are read in order and the first match wins, so an unreadable entry
// listed after a matching one does not make a decided advisory ambiguous. An
// advisory that names nothing this check can rule out — no vulnerabilities
// entries at all, or entries none of which the range OR its patched-version
// fallback could decide — is ambiguous: it is a published advisory against this
// repository that this check cannot place.
func matchAdvisory(advisory githubAdvisory, version string) (matched, ambiguous bool) {
	decided := 0
	for _, vulnerability := range advisory.Vulnerabilities {
		switch entryVerdict(version, vulnerability.VulnerableVersionRange, vulnerability.PatchedVersions) {
		case rangeMatches:
			return true, ambiguous
		case rangeExcludes:
			decided++
		case rangeAmbiguous:
			ambiguous = true
		}
	}
	// No entry decided either way and none was ambiguous means the advisory
	// carried no vulnerabilities entries at all — still nothing this check can
	// rule out.
	if decided == 0 && !ambiguous {
		ambiguous = true
	}
	return false, ambiguous
}

// entryVerdict decides one vulnerability entry.
//
// The vulnerable_version_range is authoritative whenever this build can read
// it. Only when the range is unreadable — empty, a disjunction, or a syntax the
// grammar rejects — is the entry's patched_versions consulted: the version a
// fix first shipped in is a second, independent signal that an unreadable range
// should not by itself sink a release. This ordering is deliberate and ruled:
// patched_versions never overrides a range this check already decided.
func entryVerdict(version, versionRange, patched string) rangeMatch {
	if verdict := versionMatchesRange(version, versionRange); verdict != rangeAmbiguous {
		return verdict
	}
	if verdict, ok := patchedVerdict(version, patched); ok {
		return verdict
	}
	return rangeAmbiguous
}

// patchedVerdict reads patched_versions as the single version a fix first
// shipped in: a candidate at or above it is not affected, below it is.
//
// It resolves only when both sides are real versions. A comma-separated
// patched list names several fixed branches, and which branch a candidate
// belongs to is the package-identity question this build does not yet answer —
// left ambiguous, not guessed. A candidate that does not begin with a digit is
// not a version this check placed (comparableVersion could not isolate one), so
// it is refused rather than let filevercmp's letters-above-digits ordering read
// every such candidate as "at or above the fix" and fail open.
func patchedVerdict(version, patched string) (rangeMatch, bool) {
	patched = strings.Trim(patched, asciiSpace)
	if patched == "" || strings.ContainsRune(patched, ',') {
		return rangeAmbiguous, false
	}
	if version == "" || !isASCIIDigit(version[0]) {
		return rangeAmbiguous, false
	}
	if !constraintBare.MatchString(patched) {
		return rangeAmbiguous, false
	}
	if versionCmp(version, patched) < 0 {
		return rangeMatches, true
	}
	return rangeExcludes, true
}

func isHighOrCritical(severity string) bool {
	switch strings.ToLower(severity) {
	case "high", "critical":
		return true
	}
	return false
}
