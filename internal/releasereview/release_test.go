package releasereview

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

const (
	testRepo    = "example/tool"
	testVersion = "v1.2.3"
	testAsset   = "tool_1.2.3_linux_amd64.tar.gz"

	releasesPath = "/repos/example/tool/releases"
	releasePath  = "/repos/example/tool/releases/tags/v1.2.3"
	comparePath  = "/repos/example/tool/compare/v1.2.2...v1.2.3"
	refPath      = "/repos/example/tool/git/ref/tags/v1.2.3"
	commitPath   = "/repos/example/tool/commits/abc123"
)

func releaseSpec() Spec {
	return Spec{
		SpecVersion: SpecVersion,
		Subject:     Subject{Repo: testRepo, Version: testVersion},
		Artifacts:   []Artifact{{Path: "dist/" + testAsset, AssetName: testAsset}},
		Checks: &Checks{Release: &ReleaseCheck{
			CheckConfig: CheckConfig{Enabled: true},
			Asset:       testAsset,
		}},
	}
}

// daysAgo builds a timestamp relative to the run, never a fixed date. A release
// fixture dated 2026-05-10 is "old enough" today and would still be old enough
// in ten years, so the too-new case has to be computed or it silently stops
// testing anything.
func daysAgo(days int) string {
	return time.Now().Add(-time.Duration(days) * 24 * time.Hour).UTC().Format(time.RFC3339)
}

func releaseBody(publishedAt string, draft, prerelease bool, assets ...string) string {
	names := make([]string, 0, len(assets))
	for _, asset := range assets {
		names = append(names, fmt.Sprintf(`{"name":%q}`, asset))
	}
	return fmt.Sprintf(`{"tag_name":%q,"draft":%t,"prerelease":%t,"published_at":%q,"assets":[%s]}`,
		testVersion, draft, prerelease, publishedAt, strings.Join(names, ","))
}

func releasesBody(entries ...string) string {
	return "[" + strings.Join(entries, ",") + "]"
}

func releaseEntry(tag, publishedAt string, draft, prerelease bool) string {
	return fmt.Sprintf(`{"tag_name":%q,"draft":%t,"prerelease":%t,"published_at":%q}`,
		tag, draft, prerelease, publishedAt)
}

// cleanRelease is a release nothing is wrong with: published a month ago on a
// day of its own, carrying its asset, following a predecessor it changed no
// release machinery against, tagged at a signed commit.
func cleanRelease() map[string]string {
	return map[string]string{
		releasePath: releaseBody(daysAgo(30), false, false, testAsset),
		releasesPath: releasesBody(
			releaseEntry(testVersion, daysAgo(30), false, false),
			releaseEntry("v1.2.2", daysAgo(60), false, false),
		),
		comparePath: `{"files":[{"filename":"cmd/tool/main.go"},{"filename":"README.md"}]}`,
		refPath:     `{"object":{"type":"commit","sha":"abc123"}}`,
		commitPath:  `{"commit":{"verification":{"verified":true,"reason":"valid"}}}`,
	}
}

func hasCode(result CheckResult, code string) bool {
	for _, reason := range result.Reasons {
		if reason.Code == code {
			return true
		}
	}
	return false
}

func reasonWithCode(t *testing.T, result CheckResult, code string) Reason {
	t.Helper()
	for _, reason := range result.Reasons {
		if reason.Code == code {
			return reason
		}
	}
	t.Fatalf("no %s reason in %v", code, codes(result))
	return Reason{}
}

func TestReleaseCleanRunIsGo(t *testing.T) {
	fake := newFakeGitHub(t, routes(cleanRelease()))

	result := release(releaseSpec())
	if result.Verdict != GO || len(result.Reasons) != 0 {
		t.Fatalf("verdict %s with reasons %v, want a clean GO", result.Verdict, codes(result))
	}

	// All five endpoints are consulted, in the order the check reports on them.
	want := []string{releasePath, releasesPath, comparePath, refPath, commitPath}
	got := fake.pathsRequested()
	if len(got) != len(want) {
		t.Fatalf("requested %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("request %d was %s, want %s", i, got[i], want[i])
		}
	}
	// The headers the bash lane sends, and no Authorization when there is no
	// token to send.
	for _, request := range fake.requests {
		if request.accept != "application/vnd.github+json" ||
			request.apiVersion != "2022-11-28" ||
			request.userAgent != "safe-audit" {
			t.Fatalf("unexpected headers on %s: %+v", request.path, request)
		}
		if request.authScheme != "" {
			t.Fatalf("%s carried an Authorization header with no token set", request.path)
		}
	}
}

// The token's only destination is the Authorization header. This asserts the
// header shape and then proves the negative: the credential appears in no URL,
// no query string, and nowhere in the report the check produces.
func TestReleaseSendsTheTokenOnlyInTheAuthorizationHeader(t *testing.T) {
	fake := newFakeGitHub(t, routes(cleanRelease()))
	const token = "ghp-fixture-credential-not-a-real-token"
	t.Setenv("GITHUB_TOKEN", token)

	result := release(releaseSpec())
	if result.Verdict != GO {
		t.Fatalf("verdict %s with reasons %v, want GO", result.Verdict, codes(result))
	}

	for _, request := range fake.requests {
		if request.authScheme != "Bearer" {
			t.Fatalf("%s was sent with auth scheme %q, want Bearer", request.path, request.authScheme)
		}
		if strings.Contains(request.path, token) || strings.Contains(request.rawQuery, token) {
			t.Fatalf("the token reached the request line of %s", request.path)
		}
	}

	report, err := json.Marshal(Review(releaseSpec()))
	if err != nil {
		t.Fatalf("marshal the report: %v", err)
	}
	if strings.Contains(string(report), token) {
		t.Fatal("the token reached the report")
	}
}

func TestReleaseChannelBlocks(t *testing.T) {
	for _, testCase := range []struct {
		name              string
		draft, prerelease bool
	}{
		{"draft", true, false},
		{"prerelease", false, true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			bodies := cleanRelease()
			bodies[releasePath] = releaseBody(daysAgo(30), testCase.draft, testCase.prerelease, testAsset)
			newFakeGitHub(t, routes(bodies))

			result := release(releaseSpec())
			if result.Verdict != BLOCK || !hasCode(result, "release_channel") {
				t.Fatalf("verdict %s with reasons %v, want a release_channel BLOCK", result.Verdict, codes(result))
			}
		})
	}
}

func TestReleaseTooNewBlocks(t *testing.T) {
	bodies := cleanRelease()
	bodies[releasePath] = releaseBody(daysAgo(1), false, false, testAsset)
	newFakeGitHub(t, routes(bodies))

	result := release(releaseSpec())
	if result.Verdict != BLOCK {
		t.Fatalf("verdict %s with reasons %v, want BLOCK", result.Verdict, codes(result))
	}
	reason := reasonWithCode(t, result, "release_too_new")
	if reason.Data["age_days"] != "1" || reason.Data["minimum_days"] != "3" {
		t.Fatalf("unexpected reason data %v", reason.Data)
	}
}

func TestReleaseMinimumAgeIsOverridable(t *testing.T) {
	bodies := cleanRelease()
	bodies[releasePath] = releaseBody(daysAgo(1), false, false, testAsset)
	newFakeGitHub(t, routes(bodies))
	t.Setenv("SAFE_AUDIT_GITHUB_RELEASE_MIN_AGE_DAYS", "1")

	if result := release(releaseSpec()); result.Verdict != GO {
		t.Fatalf("verdict %s with reasons %v, want GO under a lowered minimum", result.Verdict, codes(result))
	}

	// An override that is not a number tunes nothing: the built-in minimum
	// stands rather than a typo deciding a release.
	t.Setenv("SAFE_AUDIT_GITHUB_RELEASE_MIN_AGE_DAYS", "soon")
	if result := release(releaseSpec()); !hasCode(result, "release_too_new") {
		t.Fatalf("reasons %v, want the default minimum to stand", codes(result))
	}
}

// A release whose age cannot be established is blocked, not passed: age is the
// signal that a compromised release has had time to be noticed, and an unknown
// age is not a small one.
func TestReleaseUnknownAgeBlocks(t *testing.T) {
	for _, publishedAt := range []string{"", "last tuesday"} {
		bodies := cleanRelease()
		bodies[releasePath] = releaseBody(publishedAt, false, false, testAsset)
		newFakeGitHub(t, routes(bodies))

		result := release(releaseSpec())
		if result.Verdict != BLOCK || !hasCode(result, "release_age_unknown") {
			t.Fatalf("published_at %q gave verdict %s with reasons %v, want a release_age_unknown BLOCK",
				publishedAt, result.Verdict, codes(result))
		}
	}
}

func TestReleaseMissingAssetBlocks(t *testing.T) {
	bodies := cleanRelease()
	bodies[releasePath] = releaseBody(daysAgo(30), false, false, "some-other-file.tar.gz")
	newFakeGitHub(t, routes(bodies))

	result := release(releaseSpec())
	if result.Verdict != BLOCK {
		t.Fatalf("verdict %s with reasons %v, want BLOCK", result.Verdict, codes(result))
	}
	if reason := reasonWithCode(t, result, "asset_missing"); reason.Data["asset"] != testAsset {
		t.Fatalf("unexpected reason data %v", reason.Data)
	}
}

// A 404 is GitHub answering: the release is not there. That is evidence about
// the release, and the message has to name the other thing a 404 means, because
// GitHub answers 404 rather than 403 for a private repository — a consumer with
// no token would otherwise read "this release does not exist" and believe it.
func TestReleaseNotFoundBlocksAndNamesThePrivateRepoCase(t *testing.T) {
	bodies := cleanRelease()
	delete(bodies, releasePath)
	newFakeGitHub(t, routes(bodies))

	result := release(releaseSpec())
	if result.Verdict != BLOCK {
		t.Fatalf("verdict %s with reasons %v, want BLOCK", result.Verdict, codes(result))
	}
	message := reasonWithCode(t, result, "release_missing").Message
	if !strings.Contains(message, "GITHUB_TOKEN") || !strings.Contains(message, "private") {
		t.Fatalf("message %q does not name the private-repository case", message)
	}
}

// The other half of the split: GitHub failing to answer is the review breaking,
// never a finding about the release. A BLOCK here would put "we could not
// check" in the same bucket as "we checked, and it failed".
func TestReleaseInfrastructureFailuresAreErrors(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		status int
	}{
		{"server error", http.StatusInternalServerError},
		{"rate limited", http.StatusForbidden},
		{"too many requests", http.StatusTooManyRequests},
		{"bad gateway", http.StatusBadGateway},
		{"unauthorized", http.StatusUnauthorized},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			bodies := cleanRelease()
			newFakeGitHub(t, func(writer http.ResponseWriter, request *http.Request) {
				if request.URL.Path == releasePath {
					writer.WriteHeader(testCase.status)
					fmt.Fprint(writer, `{"message":"nope"}`)
					return
				}
				routes(bodies)(writer, request)
			})

			result := release(releaseSpec())
			if result.Verdict != ERROR {
				t.Fatalf("verdict %s with reasons %v, want ERROR", result.Verdict, codes(result))
			}
			if hasCode(result, "release_missing") {
				t.Fatal("an unreachable GitHub was reported as a missing release")
			}
			reason := reasonWithCode(t, result, "metadata_unavailable")
			if !strings.Contains(reason.Message, "audit-infrastructure breakage") {
				t.Fatalf("message %q does not say the review broke", reason.Message)
			}
		})
	}
}

// A dead endpoint — not a slow one, which would take the timeout — is the same
// class: the review could not run.
func TestReleaseTransportFailureIsError(t *testing.T) {
	fake := newFakeGitHub(t, routes(cleanRelease()))
	fake.server.Close()

	result := release(releaseSpec())
	if result.Verdict != ERROR {
		t.Fatalf("verdict %s with reasons %v, want ERROR", result.Verdict, codes(result))
	}
	if hasCode(result, "release_missing") || hasCode(result, "release_history_missing") {
		t.Fatalf("a transport failure was reported as evidence: %v", codes(result))
	}
}

func TestReleaseSameDayChurnBlocks(t *testing.T) {
	published := daysAgo(30)
	bodies := cleanRelease()
	bodies[releasesPath] = releasesBody(
		releaseEntry("v1.2.4", published, false, false),
		releaseEntry(testVersion, published, false, false),
		releaseEntry("v1.2.2", daysAgo(60), false, false),
	)
	bodies[releasePath] = releaseBody(published, false, false, testAsset)
	newFakeGitHub(t, routes(bodies))

	result := release(releaseSpec())
	if result.Verdict != BLOCK {
		t.Fatalf("verdict %s with reasons %v, want BLOCK", result.Verdict, codes(result))
	}
	if reason := reasonWithCode(t, result, "same_day_churn"); reason.Data["count"] != "2" {
		t.Fatalf("unexpected reason data %v", reason.Data)
	}
}

// Drafts do not count toward same-day churn and are not eligible predecessors:
// a draft is not a release anyone could have installed.
func TestReleaseDraftsAreNotHistory(t *testing.T) {
	published := daysAgo(30)
	bodies := cleanRelease()
	bodies[releasesPath] = releasesBody(
		releaseEntry("v1.2.4-draft", published, true, false),
		releaseEntry(testVersion, published, false, false),
		releaseEntry("v1.2.3-abandoned", published, true, false),
		releaseEntry("v1.2.2", daysAgo(60), false, false),
	)
	bodies[releasePath] = releaseBody(published, false, false, testAsset)
	newFakeGitHub(t, routes(bodies))

	if result := release(releaseSpec()); result.Verdict != GO {
		t.Fatalf("verdict %s with reasons %v, want GO", result.Verdict, codes(result))
	}
}

func TestReleaseWithNoPredecessorBlocks(t *testing.T) {
	bodies := cleanRelease()
	bodies[releasesPath] = releasesBody(releaseEntry(testVersion, daysAgo(30), false, false))
	fake := newFakeGitHub(t, routes(bodies))

	result := release(releaseSpec())
	if result.Verdict != BLOCK || !hasCode(result, "previous_release_unresolved") {
		t.Fatalf("verdict %s with reasons %v, want a previous_release_unresolved BLOCK", result.Verdict, codes(result))
	}
	// With no predecessor there is nothing to compare against, so no comparison
	// is attempted — and no comparison failure is invented from one.
	for _, path := range fake.pathsRequested() {
		if strings.Contains(path, "/compare/") {
			t.Fatalf("a comparison was attempted with no predecessor: %s", path)
		}
	}
}

func TestReleaseHighRiskPathsBlock(t *testing.T) {
	bodies := cleanRelease()
	bodies[comparePath] = `{"files":[{"filename":".github/workflows/release.yml"},{"filename":"cmd/tool/main.go"}]}`
	newFakeGitHub(t, routes(bodies))

	result := release(releaseSpec())
	if result.Verdict != BLOCK {
		t.Fatalf("verdict %s with reasons %v, want BLOCK", result.Verdict, codes(result))
	}
	reason := reasonWithCode(t, result, "high_risk_paths")
	if reason.Data["paths"] != ".github/workflows/release.yml" || reason.Data["previous_tag"] != "v1.2.2" {
		t.Fatalf("unexpected reason data %v", reason.Data)
	}
}

// The pattern is a knob, and a knob set to something that will not compile
// means no path was classified at all — which is the review failing to run, not
// a release that changed nothing risky.
func TestReleaseUnusableHighRiskPatternIsError(t *testing.T) {
	newFakeGitHub(t, routes(cleanRelease()))
	t.Setenv("SAFE_AUDIT_GITHUB_HIGH_RISK_PATH_REGEX", "(unclosed")

	result := release(releaseSpec())
	if result.Verdict != ERROR {
		t.Fatalf("verdict %s with reasons %v, want ERROR", result.Verdict, codes(result))
	}
	message := reasonWithCode(t, result, "high_risk_pattern_invalid").Message
	if !strings.Contains(message, "SAFE_AUDIT_GITHUB_HIGH_RISK_PATH_REGEX") {
		t.Fatalf("message %q does not name the variable to fix", message)
	}
}

func TestReleaseUnverifiedCommitBlocks(t *testing.T) {
	bodies := cleanRelease()
	bodies[commitPath] = `{"commit":{"verification":{"verified":false,"reason":"unsigned"}}}`
	newFakeGitHub(t, routes(bodies))

	result := release(releaseSpec())
	if result.Verdict != BLOCK {
		t.Fatalf("verdict %s with reasons %v, want BLOCK", result.Verdict, codes(result))
	}
	if reason := reasonWithCode(t, result, "commit_unverified"); reason.Data["reason"] != "unsigned" {
		t.Fatalf("unexpected reason data %v", reason.Data)
	}
}

// An annotated tag points at a tag object, not at a commit, so the signature
// question is one hop further than the reference.
func TestReleaseAnnotatedTagIsDereferenced(t *testing.T) {
	const tagObjectPath = "/repos/example/tool/git/tags/deadbeef"
	bodies := cleanRelease()
	bodies[tagObjectPath] = `{"object":{"type":"commit","sha":"abc123"}}`

	// The handler reads the map on every request, so the reference body can be
	// filled in once the server has an address — the way GitHub's own object
	// URLs point back at the API.
	fake := newFakeGitHub(t, func(writer http.ResponseWriter, request *http.Request) {
		routes(bodies)(writer, request)
	})
	bodies[refPath] = fmt.Sprintf(`{"object":{"type":"tag","sha":"deadbeef","url":%q}}`,
		fake.server.URL+tagObjectPath)

	if result := release(releaseSpec()); result.Verdict != GO {
		t.Fatalf("verdict %s with reasons %v, want GO", result.Verdict, codes(result))
	}
	if !contains(fake.pathsRequested(), tagObjectPath) {
		t.Fatalf("the annotated tag object was never dereferenced: %v", fake.pathsRequested())
	}
}

func TestReleaseUnresolvableTagBlocks(t *testing.T) {
	for _, testCase := range []struct{ name, body string }{
		{"reference names a tree", `{"object":{"type":"tree","sha":"abc123"}}`},
		{"reference names no sha", `{"object":{"type":"commit","sha":""}}`},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			bodies := cleanRelease()
			bodies[refPath] = testCase.body
			newFakeGitHub(t, routes(bodies))

			result := release(releaseSpec())
			if result.Verdict != BLOCK || !hasCode(result, "tag_unresolved") {
				t.Fatalf("verdict %s with reasons %v, want a tag_unresolved BLOCK", result.Verdict, codes(result))
			}
			// A tag that resolves to nothing has no commit to ask about, so the
			// commit endpoint is not invented.
			if hasCode(result, "commit_unverified") {
				t.Fatal("an unresolved tag still produced a commit finding")
			}
		})
	}
}

// The bash lane read only the first page of the release listing, so on a
// repository with a long history it resolved the wrong predecessor — or none.
// Following the Link header is what fixes that.
func TestReleaseHistoryFollowsPagination(t *testing.T) {
	bodies := cleanRelease()
	bodies[releasesPath] = releasesBody(releaseEntry(testVersion, daysAgo(30), false, false))
	secondPage := releasesBody(releaseEntry("v1.2.2", daysAgo(60), false, false))

	var serverURL string
	fake := newFakeGitHub(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == releasesPath {
			if request.URL.Query().Get("page") == "2" {
				fmt.Fprint(writer, secondPage)
				return
			}
			writer.Header().Set("Link", fmt.Sprintf(`<%s%s?per_page=100&page=2>; rel="next"`,
				serverURL, releasesPath))
			fmt.Fprint(writer, bodies[releasesPath])
			return
		}
		routes(bodies)(writer, request)
	})
	serverURL = fake.server.URL

	result := release(releaseSpec())
	if result.Verdict != GO || len(result.Reasons) != 0 {
		t.Fatalf("verdict %s with reasons %v, want a clean GO across two pages", result.Verdict, codes(result))
	}
	pages := 0
	for _, request := range fake.requests {
		if request.path == releasesPath {
			pages++
		}
	}
	if pages != 2 {
		t.Fatalf("the listing was fetched %d times, want 2", pages)
	}
}

// A listing that never ends must not be walked forever, and the cap must not be
// silent: an answer resolved before the cap says so at GO, and an answer the cap
// prevented is ERROR — the review failing to run, not a release with no history.
func TestReleaseHistoryPageCapIsReported(t *testing.T) {
	for _, testCase := range []struct {
		name         string
		targetOnPage bool
		wantVerdict  Severity
		wantCode     string
	}{
		{"resolved before the cap", true, GO, "release_history_capped"},
		{"cap reached first", false, ERROR, "release_history_truncated"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			bodies := cleanRelease()
			firstPage := releasesBody(
				releaseEntry(testVersion, daysAgo(30), false, false),
				releaseEntry("v1.2.2", daysAgo(60), false, false),
			)

			// Each page carries older releases on days of their own and offers
			// another page, so nothing but the cap can stop the walk. Whether
			// the release under review is on the first page is what separates a
			// cap that changed nothing from one that prevented an answer.
			var serverURL string
			page := 0
			fake := newFakeGitHub(t, func(writer http.ResponseWriter, request *http.Request) {
				if request.URL.Path == releasesPath {
					page++
					writer.Header().Set("Link", fmt.Sprintf(`<%s%s?per_page=100&page=%d>; rel="next"`,
						serverURL, releasesPath, page+1))
					if page == 1 && testCase.targetOnPage {
						fmt.Fprint(writer, firstPage)
						return
					}
					fmt.Fprint(writer, releasesBody(
						releaseEntry(fmt.Sprintf("v0.%d.0", page), daysAgo(90+page), false, false),
					))
					return
				}
				routes(bodies)(writer, request)
			})
			serverURL = fake.server.URL

			result := release(releaseSpec())
			if result.Verdict != testCase.wantVerdict {
				t.Fatalf("verdict %s with reasons %v, want %s", result.Verdict, codes(result), testCase.wantVerdict)
			}
			if !hasCode(result, testCase.wantCode) {
				t.Fatalf("reasons %v, want %s", codes(result), testCase.wantCode)
			}
			// A truncation of this check's own making must not also read as a
			// release with no predecessor.
			if hasCode(result, "previous_release_unresolved") {
				t.Fatal("the page cap was reported as evidence about the release")
			}
			pages := 0
			for _, request := range fake.requests {
				if request.path == releasesPath {
					pages++
				}
			}
			if pages != githubMaxPages {
				t.Fatalf("the listing was fetched %d times, want the %d-page cap", pages, githubMaxPages)
			}
		})
	}
}

// Every endpoint is consulted and every answer reported: a consumer who fixed
// only the failure the check happened to report first would still be refused.
func TestReleaseReportsEveryFailure(t *testing.T) {
	bodies := cleanRelease()
	bodies[releasePath] = releaseBody(daysAgo(1), true, false, "wrong-name.tar.gz")
	bodies[comparePath] = `{"files":[{"filename":"Dockerfile"}]}`
	bodies[commitPath] = `{"commit":{"verification":{"verified":false,"reason":"unsigned"}}}`
	newFakeGitHub(t, routes(bodies))

	result := release(releaseSpec())
	if result.Verdict != BLOCK {
		t.Fatalf("verdict %s, want BLOCK", result.Verdict)
	}
	for _, code := range []string{"release_channel", "release_too_new", "asset_missing", "high_risk_paths", "commit_unverified"} {
		if !hasCode(result, code) {
			t.Fatalf("reasons %v are missing %s", codes(result), code)
		}
	}
}
