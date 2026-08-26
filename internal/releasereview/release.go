package releasereview

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	defaultReleaseMinAgeDays = 3
	// releaseHistoryPageSize keeps a single page of the release listing under the
	// body cap. GitHub returns each release's full body in this listing, and a
	// repository like openai/codex ships hundreds of KB of notes per release — at
	// per_page=100 one page is ~27 MB, far past githubMaxBodyBytes, so the read
	// failed before any pagination logic ran. A small page reads only the newest
	// releases, which is all reviewReleaseHistory needs, and the early stop in
	// getPaged means a recent release is usually resolved from the first page.
	releaseHistoryPageSize = 10
	// releaseHistoryMaxPages bounds the history walk on its own budget rather than
	// the shared githubMaxPages, so shrinking the page size did not also shrink the
	// number of releases a walk can reach. At releaseHistoryPageSize this reads up
	// to ~250 releases — the reach a review of a not-newest release needs — while
	// staying well inside GitHub's 60/hour anonymous request budget (a recent
	// release early-stops in one or two requests; only an old-release review pays
	// the full budget). A review that runs past it reports release_history_*, never
	// deciding on a silently truncated view.
	releaseHistoryMaxPages = 25
	// sameDayLookbehindDays is how far before the release's publication day the
	// same-day-churn walk keeps reading. It bounds the COMMON case, not a proof:
	// GitHub orders this listing by created_at, which is the tagged commit's date,
	// so a release published on the review day but tagging an older commit sorts
	// deep and can be missed. same_day_churn is therefore a best-effort positive
	// detector — it BLOCKs on the same-day siblings it sees, and a sibling that
	// sorts past this lookbehind (or past the page budget) is a known limitation,
	// not a clean bill of health. The residual is attacker-reachable (a re-cut from
	// an old commit) and is carried as a known risk, not closed here; closing it
	// would require reading the whole listing, which repositories like codex make
	// unaffordable.
	sameDayLookbehindDays = 1
	// The bash lane's default, copied verbatim: workflow files, the scripts a
	// release is built and signed by, and the container and build entry points.
	// A change to any of them between two releases is what a supply-chain
	// compromise looks like from the outside.
	defaultHighRiskPathRegex = `(^|/)\.github/workflows/|(^|/)(install|setup|bootstrap|release|publish|sign|cosign|checksum|goreleaser)([^/]*)(\.[^/]+)?$|(^|/)(Dockerfile|Makefile|magefile\.go)$`
)

type githubAsset struct {
	Name string `json:"name"`
}

type githubRelease struct {
	TagName     string        `json:"tag_name"`
	Draft       bool          `json:"draft"`
	Prerelease  bool          `json:"prerelease"`
	PublishedAt string        `json:"published_at"`
	CreatedAt   string        `json:"created_at"`
	Assets      []githubAsset `json:"assets"`
}

type githubRef struct {
	Object struct {
		Type string `json:"type"`
		SHA  string `json:"sha"`
		URL  string `json:"url"`
	} `json:"object"`
}

type githubCompare struct {
	Files []struct {
		Filename string `json:"filename"`
	} `json:"files"`
}

type githubCommit struct {
	Commit struct {
		Verification struct {
			Verified bool   `json:"verified"`
			Reason   string `json:"reason"`
		} `json:"verification"`
	} `json:"commit"`
}

// release judges a GitHub release's own metadata: what channel it was published
// on, how old it is, whether it carries the asset the spec names, whether it
// arrived in a burst of same-day releases, what changed since its predecessor,
// and whether the commit its tag points at is signed.
//
// Every one of those is a fact about the release, so every adverse answer is
// BLOCK. The one thing this check can report that is not about the release is a
// GitHub it could not reach, which is ERROR — see the 404 split below.
//
// Endpoints are queried independently and every answer is reported: a release
// whose asset is missing AND whose commit is unsigned says both, because a
// consumer who fixed only the one the check happened to report first would
// still be refused.
func release(spec Spec) CheckResult {
	result := CheckResult{Reasons: []Reason{}}
	config := spec.Checks.Release
	client := newGitHubClient()
	repo := spec.Subject.Repo
	version := spec.Subject.Version

	publishedAt := reviewReleaseMetadata(&result, client, repo, version, config.Asset)
	previousTag := reviewReleaseHistory(&result, client, repo, version, publishedAt)
	if previousTag != "" {
		reviewReleaseComparison(&result, client, repo, version, previousTag)
	}
	if commit := reviewTagCommit(&result, client, repo, version); commit != "" {
		reviewCommitVerification(&result, client, repo, commit, config.AllowUnsignedCommit)
	}
	return result
}

// reviewReleaseMetadata reads the release itself and returns its publication
// timestamp, which the history review needs to count same-day siblings.
func reviewReleaseMetadata(result *CheckResult, client *githubClient, repo, version, asset string) string {
	var release githubRelease
	_, err := client.get(fmt.Sprintf("/repos/%s/releases/tags/%s", repo, url.PathEscape(version)), &release)
	if err != nil {
		recordGitHubFailure(result, err, "the release metadata", "release_missing",
			fmt.Sprintf("GitHub has no release %s in %s — either the tag is not published, or the repository is private and no GITHUB_TOKEN was set (GitHub answers 404, not 403, for a read it will not authorize)", version, repo),
			map[string]string{"repo": repo, "version": version})
		return ""
	}

	if release.Draft || release.Prerelease {
		result.add(BLOCK, "release_channel",
			fmt.Sprintf("release %s is published as draft=%t prerelease=%t, which is not a channel a release review accepts", version, release.Draft, release.Prerelease),
			map[string]string{"draft": strconv.FormatBool(release.Draft), "prerelease": strconv.FormatBool(release.Prerelease)})
	}

	publishedAt := release.PublishedAt
	if publishedAt == "" {
		publishedAt = release.CreatedAt
	}
	minimum := releaseMinAgeDays()
	switch age, known := releaseAgeDays(publishedAt); {
	case !known:
		result.add(BLOCK, "release_age_unknown",
			"GitHub's metadata carries no publication timestamp this check can read, so the release's age — the one signal that a compromised release has not had time to be noticed — is unknown",
			nil)
	case age < minimum:
		result.add(BLOCK, "release_too_new",
			fmt.Sprintf("release %s is %dd old, below the %dd minimum", version, age, minimum),
			map[string]string{"age_days": strconv.Itoa(age), "minimum_days": strconv.Itoa(minimum), "published_at": publishedAt})
	}

	if !carriesAsset(release, asset) {
		result.add(BLOCK, "asset_missing",
			fmt.Sprintf("release %s carries no asset named %s", version, asset),
			map[string]string{"asset": asset})
	}
	return publishedAt
}

func carriesAsset(release githubRelease, asset string) bool {
	for _, candidate := range release.Assets {
		if candidate.Name == asset {
			return true
		}
	}
	return false
}

// reviewReleaseHistory counts same-day releases and resolves the tag published
// before this one, which is what the comparison below is taken against.
func reviewReleaseHistory(result *CheckResult, client *githubClient, repo, version, publishedAt string) string {
	var history []githubRelease
	capped, err := client.getPaged(fmt.Sprintf("/repos/%s/releases?per_page=%d", repo, releaseHistoryPageSize), releaseHistoryMaxPages, func(page json.RawMessage) (bool, *githubError) {
		var releases []githubRelease
		if decodeErr := json.Unmarshal(page, &releases); decodeErr != nil {
			return false, &githubError{message: fmt.Sprintf("GitHub's release listing is not an array of releases: %v", decodeErr)}
		}
		history = append(history, releases...)
		return historyWalkSatisfied(history, version, publishedAt), nil
	})
	if err != nil {
		recordGitHubFailure(result, err, "the release history", "release_history_missing",
			fmt.Sprintf("GitHub publishes no release history for %s — either the repository does not exist, or it is private and no GITHUB_TOKEN was set", repo),
			map[string]string{"repo": repo})
		return ""
	}

	if publishedDay := publicationDay(publishedAt); publishedDay != "" {
		if count := sameDayReleaseCount(history, publishedDay); count > 1 {
			result.add(BLOCK, "same_day_churn",
				fmt.Sprintf("%d non-draft releases were published on %s; a release re-cut the same day is how a swapped artifact is slipped past a review that already ran", count, publishedDay),
				map[string]string{"count": strconv.Itoa(count), "published_day": publishedDay})
		}
	}

	previousTag := previousReleaseTag(history, version)
	switch {
	case previousTag != "":
		if capped {
			// The predecessor — the one fact this branch needs complete — was
			// resolved before the cap. The same-day count over the truncated tail
			// is necessarily incomplete, which is exactly why the capped run is
			// recorded rather than passed silently (the producer keeps this at
			// WARN); same_day_churn stays a best-effort positive detector.
			result.add(GO, "release_history_capped",
				fmt.Sprintf("the release history was longer than the %d pages this check reads; the previous release was resolved before the cap, so nothing was decided on the truncated part", releaseHistoryMaxPages),
				map[string]string{"pages": strconv.Itoa(releaseHistoryMaxPages), "releases_read": strconv.Itoa(len(history))})
		}
	case capped:
		// The cap, not the repository, is why there is no answer. That is this
		// review failing to run, not evidence about the release.
		result.add(ERROR, "release_history_truncated",
			fmt.Sprintf("the release history was longer than the %d pages this check reads and %s was not reached, so its predecessor could not be resolved", releaseHistoryMaxPages, version),
			map[string]string{"pages": strconv.Itoa(releaseHistoryMaxPages), "releases_read": strconv.Itoa(len(history))})
	default:
		result.add(BLOCK, "previous_release_unresolved",
			fmt.Sprintf("no release published before %s could be resolved, so there is nothing to compare it against", version),
			map[string]string{"version": version})
	}
	return previousTag
}

// sameDayReleaseCount counts the non-draft, non-prerelease releases published on
// one day, the day the release under review was published on.
func sameDayReleaseCount(history []githubRelease, publishedDay string) int {
	count := 0
	for _, candidate := range history {
		if candidate.Draft || candidate.Prerelease {
			continue
		}
		if publicationDay(candidate.PublishedAt) == publishedDay {
			count++
		}
	}
	return count
}

// previousReleaseTag returns the tag of the release listed after this one, drafts
// excluded. GitHub lists releases newest first, so "the next one down" is the
// predecessor.
func previousReleaseTag(history []githubRelease, version string) string {
	published := make([]githubRelease, 0, len(history))
	for _, candidate := range history {
		if !candidate.Draft {
			published = append(published, candidate)
		}
	}
	for index, candidate := range published {
		if candidate.TagName == version && index+1 < len(published) {
			return published[index+1].TagName
		}
	}
	return ""
}

// historyWalkSatisfied reports whether the release listing has been read far
// enough to stop the walk: the predecessor is resolved, and the walk has read
// past the release's publication day. It is the getPaged early stop.
//
// This is sound for the predecessor, a fixed fact once found. It is NOT a
// completeness proof for same_day_churn: the listing is ordered by created_at
// (the tagged commit's date), so a same-day-published release built from an older
// commit can sort past the window and go unread — see sameDayLookbehindDays.
// The oldest entry read so far is the last one appended; once its created
// timestamp is a full lookbehind day before the publication day AND its own
// publication timestamp is before that day, the walk stops. Until a publication
// day can be read from the release under review, or until the predecessor is
// resolved, the walk does not stop early and falls through to the page budget —
// the conservative default.
func historyWalkSatisfied(history []githubRelease, version, publishedAt string) bool {
	if len(history) == 0 || previousReleaseTag(history, version) == "" {
		return false
	}
	publishedDay := publicationDay(publishedAt)
	if publishedDay == "" {
		return false
	}
	day, err := time.Parse("2006-01-02", publishedDay)
	if err != nil {
		return false
	}
	oldest := history[len(history)-1]
	createdCutoff := day.AddDate(0, 0, -sameDayLookbehindDays)
	return timestampBefore(oldest.CreatedAt, createdCutoff) &&
		timestampBefore(oldest.PublishedAt, day)
}

// timestampBefore reports whether an RFC 3339 timestamp is strictly before a
// cutoff. An empty or unreadable timestamp returns false: a timestamp that
// cannot be placed is never treated as old enough to stop the walk, so an
// unreadable date keeps the walk reading rather than ending it early.
func timestampBefore(timestamp string, cutoff time.Time) bool {
	parsed, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return false
	}
	return parsed.Before(cutoff)
}

func reviewReleaseComparison(result *CheckResult, client *githubClient, repo, version, previousTag string) {
	pattern, patternErr := highRiskPathPattern()
	if patternErr != nil {
		result.add(ERROR, "high_risk_pattern_invalid",
			fmt.Sprintf("SAFE_AUDIT_GITHUB_HIGH_RISK_PATH_REGEX is not a usable pattern, so no release path could be classified: %v", patternErr),
			map[string]string{"error": patternErr.Error()})
		return
	}

	var comparison githubCompare
	_, err := client.get(fmt.Sprintf("/repos/%s/compare/%s...%s", repo, url.PathEscape(previousTag), url.PathEscape(version)), &comparison)
	if err != nil {
		recordGitHubFailure(result, err, "the comparison against the previous release", "comparison_missing",
			fmt.Sprintf("GitHub cannot compare %s with %s — one of the two tags is not in the repository", previousTag, version),
			map[string]string{"previous_tag": previousTag, "version": version})
		return
	}

	var risky []string
	for _, file := range comparison.Files {
		if pattern.MatchString(file.Filename) {
			risky = append(risky, file.Filename)
		}
	}
	if len(risky) > 0 {
		result.add(BLOCK, "high_risk_paths",
			fmt.Sprintf("%d release-machinery path(s) changed between %s and %s: %s", len(risky), previousTag, version, strings.Join(risky, ", ")),
			map[string]string{
				"previous_tag":  previousTag,
				"paths":         strings.Join(risky, ","),
				"changed_files": strconv.Itoa(len(comparison.Files)),
			})
	}
}

// reviewTagCommit resolves the tag to the commit it names, dereferencing an
// annotated tag object when GitHub returns one.
func reviewTagCommit(result *CheckResult, client *githubClient, repo, version string) string {
	unresolved := func(detail string) {
		result.add(BLOCK, "tag_unresolved",
			fmt.Sprintf("tag %s does not resolve to a commit in %s: %s — a tag that does not name one commit cannot be held to a signature", version, repo, detail),
			map[string]string{"version": version})
	}

	var ref githubRef
	_, err := client.get(fmt.Sprintf("/repos/%s/git/ref/tags/%s", repo, url.PathEscape(version)), &ref)
	if err != nil {
		recordGitHubFailure(result, err, "the tag reference", "tag_unresolved",
			fmt.Sprintf("GitHub has no git tag %s in %s — either the tag was never pushed, or the repository is private and no GITHUB_TOKEN was set", version, repo),
			map[string]string{"version": version})
		return ""
	}

	switch ref.Object.Type {
	case "commit":
		if ref.Object.SHA == "" {
			unresolved("the reference names no commit SHA")
			return ""
		}
		return ref.Object.SHA
	case "tag":
		// An annotated tag is an object of its own; the commit is one hop further.
		if ref.Object.URL == "" {
			unresolved("the annotated tag object carries no address to dereference")
			return ""
		}
		var tag githubRef
		if _, tagErr := client.get(ref.Object.URL, &tag); tagErr != nil {
			recordGitHubFailure(result, tagErr, "the annotated tag object", "tag_unresolved",
				fmt.Sprintf("GitHub does not serve the annotated tag object %s names", version),
				map[string]string{"version": version})
			return ""
		}
		if tag.Object.Type != "commit" || tag.Object.SHA == "" {
			unresolved(fmt.Sprintf("the annotated tag dereferences to a %q, not a commit", tag.Object.Type))
			return ""
		}
		return tag.Object.SHA
	default:
		unresolved(fmt.Sprintf("the reference names a %q", ref.Object.Type))
		return ""
	}
}

func reviewCommitVerification(result *CheckResult, client *githubClient, repo, commit string, allowUnsigned bool) {
	var details githubCommit
	_, err := client.get(fmt.Sprintf("/repos/%s/commits/%s", repo, url.PathEscape(commit)), &details)
	if err != nil {
		recordGitHubFailure(result, err, "the tag commit", "commit_missing",
			fmt.Sprintf("GitHub has no commit %s in %s, although a tag names it", commit, repo),
			map[string]string{"commit": commit})
		return
	}
	if details.Commit.Verification.Verified {
		return
	}
	reason := details.Commit.Verification.Reason
	if reason == "" {
		reason = "unverified"
	}
	// A subject whose upstream does not sign its release tags declares so with
	// allow_unsigned_commit, which the producer sets when the manifest waives
	// commit_unverified because a stronger control — the sigstore workflow
	// attestation that binds the artifact to the tag — covers the same risk. An
	// unsigned commit is then the expected state, not a finding, and is recorded
	// as a GO note that stays in the report rather than a BLOCK the consumer must
	// waive on every review. Only a plain "unsigned" passes: a commit GitHub
	// reports as invalid, bad_email, or signed by an unknown key is anomalous even
	// for a project that never signs, so it still BLOCKs.
	if allowUnsigned && reason == "unsigned" {
		result.add(GO, "commit_unsigned_allowed",
			fmt.Sprintf("the tagged commit %s is unsigned, which the spec accepts for this subject (allow_unsigned_commit)", commit),
			map[string]string{"commit": commit, "reason": reason})
		return
	}
	result.add(BLOCK, "commit_unverified",
		fmt.Sprintf("GitHub does not report the tagged commit %s as signed: %s", commit, reason),
		map[string]string{"commit": commit, "reason": reason})
}

// recordGitHubFailure applies the composite's severity law to a failed request.
//
// A 404 is an answer: GitHub looked, and what the spec named is not there. That
// is evidence about the release, so it BLOCKs under the caller's own code. Any
// other failure — no route to the host, a timeout, a 5xx, a rate limit, a body
// that is not the JSON this check expects — means the review could not run, and
// reporting that as a finding about the release would put "we could not check"
// in the same bucket as "we checked, and it failed".
func recordGitHubFailure(result *CheckResult, err *githubError, endpoint, notFoundCode, notFoundMessage string, data map[string]string) {
	if err.notFound {
		result.add(BLOCK, notFoundCode, notFoundMessage, data)
		return
	}
	result.add(ERROR, "metadata_unavailable",
		fmt.Sprintf("could not read %s from GitHub, so this release was not reviewed — audit-infrastructure breakage, not a finding about the release: %s", endpoint, err.message),
		map[string]string{"endpoint": endpoint})
}

// releaseMinAgeDays resolves the minimum age a release must have. An override
// that is not a usable number falls back to the default rather than refusing:
// the knob tunes a threshold, and a typo in it must not decide a release.
func releaseMinAgeDays() int {
	if raw := os.Getenv("SAFE_AUDIT_GITHUB_RELEASE_MIN_AGE_DAYS"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed >= 0 {
			return parsed
		}
	}
	return defaultReleaseMinAgeDays
}

// releaseAgeDays returns whole days since publication. A release dated in the
// future reads as zero days old, the way the bash lane's clamp does — a clock
// skew must not make a brand-new release look ancient.
func releaseAgeDays(publishedAt string) (int, bool) {
	if publishedAt == "" {
		return 0, false
	}
	published, err := time.Parse(time.RFC3339, publishedAt)
	if err != nil {
		return 0, false
	}
	elapsed := time.Since(published)
	if elapsed < 0 {
		return 0, true
	}
	return int(elapsed / (24 * time.Hour)), true
}

// publicationDay is the calendar day of an ISO 8601 timestamp, the way the bash
// lane took it: the leading YYYY-MM-DD, with no time zone conversion, so two
// releases are same-day exactly when GitHub says they are.
func publicationDay(timestamp string) string {
	if len(timestamp) < 10 {
		return ""
	}
	return timestamp[:10]
}

func highRiskPathPattern() (*regexp.Regexp, error) {
	pattern := os.Getenv("SAFE_AUDIT_GITHUB_HIGH_RISK_PATH_REGEX")
	if pattern == "" {
		pattern = defaultHighRiskPathRegex
	}
	return regexp.Compile(pattern)
}
