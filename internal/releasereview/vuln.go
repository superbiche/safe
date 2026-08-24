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
	version := spec.Subject.Version

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
		matched, ambiguous := matchAdvisory(advisory, version)
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
// Ranges are read in order and the first match wins, so an unreadable range
// listed after a matching one does not make a decided advisory ambiguous. An
// advisory that names no usable range at all — no vulnerabilities entries, or
// entries that all carry an empty range — is ambiguous: it is a published
// advisory against this repository that this check cannot rule out.
func matchAdvisory(advisory githubAdvisory, version string) (matched, ambiguous bool) {
	usable := 0
	for _, vulnerability := range advisory.Vulnerabilities {
		versionRange := vulnerability.VulnerableVersionRange
		if versionRange == "" {
			continue
		}
		usable++
		switch versionMatchesRange(version, versionRange) {
		case rangeMatches:
			return true, ambiguous
		case rangeAmbiguous:
			ambiguous = true
		}
	}
	if usable == 0 {
		ambiguous = true
	}
	return false, ambiguous
}

func isHighOrCritical(severity string) bool {
	switch strings.ToLower(severity) {
	case "high", "critical":
		return true
	}
	return false
}
