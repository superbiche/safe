package releasereview

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

const advisoriesPath = "/repos/example/tool/security-advisories"

func vulnSpec() Spec {
	return Spec{
		SpecVersion: SpecVersion,
		Subject:     Subject{Repo: testRepo, Version: testVersion},
		Artifacts:   []Artifact{{Path: "dist/" + testAsset, AssetName: testAsset}},
		Checks:      &Checks{Vuln: &CheckConfig{Enabled: true}},
	}
}

// advisoryBody builds one GHSA record with the affected ranges given. Passing
// no range at all is how a test says "an advisory that names no versions".
func advisoryBody(id, severity string, ranges ...string) string {
	entries := make([]string, 0, len(ranges))
	for _, versionRange := range ranges {
		entries = append(entries, fmt.Sprintf(`{"package":{"ecosystem":"go","name":"github.com/example/tool"},"vulnerable_version_range":%q}`, versionRange))
	}
	return fmt.Sprintf(`{"ghsa_id":%q,"cve_id":"CVE-2026-0001","severity":%q,"summary":"test advisory","vulnerabilities":[%s]}`,
		id, severity, strings.Join(entries, ","))
}

// advisoryEntry is one (range, patched_versions) pair inside an advisory —
// either field may be empty to say the advisory omitted it.
type advisoryEntry struct {
	versionRange string
	patched      string
}

// advisoryBodyEntries builds a GHSA record from explicit entries, so a test can
// pair an unreadable range with a patched_versions fallback.
func advisoryBodyEntries(id, severity string, entries ...advisoryEntry) string {
	encoded := make([]string, 0, len(entries))
	for _, entry := range entries {
		encoded = append(encoded, fmt.Sprintf(
			`{"package":{"ecosystem":"go","name":"github.com/example/tool"},"vulnerable_version_range":%q,"patched_versions":%q}`,
			entry.versionRange, entry.patched))
	}
	return fmt.Sprintf(`{"ghsa_id":%q,"cve_id":"CVE-2026-0001","severity":%q,"summary":"test advisory","vulnerabilities":[%s]}`,
		id, severity, strings.Join(encoded, ","))
}

func advisoriesFeed(advisories ...string) map[string]string {
	return map[string]string{advisoriesPath: "[" + strings.Join(advisories, ",") + "]"}
}

func vulnSpecVersion(version string) Spec {
	spec := vulnSpec()
	spec.Subject.Version = version
	return spec
}

// A repository with no advisories answers with an empty array, and an empty
// array is a clean answer, not an absent one.
func TestVulnNoAdvisoriesIsGo(t *testing.T) {
	newFakeGitHub(t, routes(advisoriesFeed()))

	result := vuln(vulnSpec())
	if result.Verdict != GO || len(result.Reasons) != 0 {
		t.Fatalf("verdict %s with reasons %v, want a clean GO", result.Verdict, codes(result))
	}
}

func TestVulnAdvisoryThatDoesNotCoverTheVersionIsGo(t *testing.T) {
	newFakeGitHub(t, routes(advisoriesFeed(advisoryBody("GHSA-old", "critical", "<1.0.0"))))

	result := vuln(vulnSpec())
	if result.Verdict != GO || len(result.Reasons) != 0 {
		t.Fatalf("verdict %s with reasons %v, want a clean GO", result.Verdict, codes(result))
	}
}

// The severity split is this lane's own: a low or moderate advisory affecting
// the version is a real observation worth surfacing, but it does not decide a
// release. A high or critical one does.
func TestVulnSeveritySplit(t *testing.T) {
	for _, testCase := range []struct {
		severity string
		want     Severity
		wantCode string
	}{
		{"low", WARN, "known_advisory"},
		{"moderate", WARN, "known_advisory"},
		{"unknown", WARN, "known_advisory"},
		{"high", BLOCK, "known_advisory_high_severity"},
		{"critical", BLOCK, "known_advisory_high_severity"},
		{"CRITICAL", BLOCK, "known_advisory_high_severity"},
	} {
		t.Run(testCase.severity, func(t *testing.T) {
			newFakeGitHub(t, routes(advisoriesFeed(advisoryBody("GHSA-test", testCase.severity, "<v2.0.0"))))

			result := vuln(vulnSpec())
			if result.Verdict != testCase.want {
				t.Fatalf("verdict %s with reasons %v, want %s", result.Verdict, codes(result), testCase.want)
			}
			reason := reasonWithCode(t, result, testCase.wantCode)
			if reason.Data["advisory"] != "GHSA-test" || reason.Data["cve"] != "CVE-2026-0001" {
				t.Fatalf("unexpected reason data %v", reason.Data)
			}
		})
	}
}

// An advisory this check cannot map to the version might or might not cover it,
// and "might" fails closed.
func TestVulnAmbiguousMappingBlocks(t *testing.T) {
	for _, testCase := range []struct {
		name string
		body string
	}{
		{"a range with a disjunction", advisoryBody("GHSA-or", "low", "<1.0.0 || >2.0.0")},
		{"a range this grammar cannot read", advisoryBody("GHSA-grammar", "low", "~>1.2.0")},
		{"no affected versions named at all", advisoryBody("GHSA-empty", "low")},
		// The bash lane skipped empty ranges before matching, so an advisory
		// whose every entry carries one contributed nothing at all — it read as
		// "does not affect this version". Divergence 12 in the ledger.
		{"every named range empty", advisoryBody("GHSA-blank", "low", "", "")},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			newFakeGitHub(t, routes(advisoriesFeed(testCase.body)))

			result := vuln(vulnSpec())
			if result.Verdict != BLOCK {
				t.Fatalf("verdict %s with reasons %v, want BLOCK", result.Verdict, codes(result))
			}
			if !hasCode(result, "version_mapping_ambiguous") {
				t.Fatalf("reasons %v, want version_mapping_ambiguous", codes(result))
			}
		})
	}
}

// When a range is unreadable, the entry's patched_versions is a second signal:
// a candidate at or above the fix version is not affected (GO), one below it is
// (BLOCK). This is what stops an advisory whose only defect is an unparseable
// range from blocking every version forever.
func TestVulnPatchedVersionResolvesAnUnreadableRange(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		patched  string
		want     Severity
		wantCode string
	}{
		{"candidate at or above the fix is not affected", "1.0.0", GO, ""},
		{"candidate below the fix is affected", "2.0.0", BLOCK, "known_advisory_high_severity"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			body := advisoryBodyEntries("GHSA-patched", "high", advisoryEntry{"~>1.2.0", testCase.patched})
			newFakeGitHub(t, routes(advisoriesFeed(body)))

			result := vuln(vulnSpec())
			if result.Verdict != testCase.want {
				t.Fatalf("verdict %s with reasons %v, want %s", result.Verdict, codes(result), testCase.want)
			}
			if hasCode(result, "version_mapping_ambiguous") {
				t.Fatalf("reasons %v: a patched-resolved entry was still reported unmappable", codes(result))
			}
			if testCase.wantCode != "" && !hasCode(result, testCase.wantCode) {
				t.Fatalf("reasons %v are missing %s", codes(result), testCase.wantCode)
			}
		})
	}
}

// The real GHSA-w5fx-fh39-j5rw shape: openai/codex publishes it against its npm
// package (`0.2.0 <= 0.38.0`, an unreadable space-separated compound bound) and
// its VS Code extension (`<= 0.4.11`), each with a patched_versions. Reviewing
// the Rust binary tag rust-v0.149.1, the readable range excludes it and the
// unreadable one is resolved by its fix version — a clean GO, where before the
// unparseable range was a permanent BLOCK.
func TestVulnCodexRustTagIsNotBlockedByItsNpmAdvisory(t *testing.T) {
	body := advisoryBodyEntries("GHSA-w5fx", "high",
		advisoryEntry{"0.2.0 <= 0.38.0", "0.39.0"},
		advisoryEntry{"<= 0.4.11", "0.4.12"},
	)
	newFakeGitHub(t, routes(advisoriesFeed(body)))

	result := vuln(vulnSpecVersion("rust-v0.149.1"))
	if result.Verdict != GO || len(result.Reasons) != 0 {
		t.Fatalf("verdict %s with reasons %v, want a clean GO", result.Verdict, codes(result))
	}
}

// The ruled ordering: a range this build CAN read is authoritative, and
// patched_versions is never consulted for it. Here the range matches (a BLOCK)
// while the patched version, were it consulted, would exclude — the range must
// win. Guards against a drift that lets patched_versions override a decided
// range.
func TestVulnReadableRangeIsNotOverriddenByPatchedVersion(t *testing.T) {
	body := advisoryBodyEntries("GHSA-precedence", "high", advisoryEntry{"<v2.0.0", "1.0.0"})
	newFakeGitHub(t, routes(advisoriesFeed(body)))

	result := vuln(vulnSpec())
	if result.Verdict != BLOCK || !hasCode(result, "known_advisory_high_severity") {
		t.Fatalf("verdict %s with reasons %v, want a BLOCK from the readable range", result.Verdict, codes(result))
	}
}

// The fail-open guard: a subject version whose numeric core cannot be isolated
// (no digit at all) must NOT be resolved by patched_versions — a string
// comparison of a non-version collates letters above digits and would read as
// "at or above the fix", passing a release the check cannot actually place. It
// stays ambiguous and BLOCKs.
func TestVulnDigitlessVersionIsNotResolvedByPatched(t *testing.T) {
	body := advisoryBodyEntries("GHSA-digitless", "high", advisoryEntry{"~>1.2.0", "2.0.0"})
	newFakeGitHub(t, routes(advisoriesFeed(body)))

	result := vuln(vulnSpecVersion("nightly"))
	if result.Verdict != BLOCK || !hasCode(result, "version_mapping_ambiguous") {
		t.Fatalf("verdict %s with reasons %v, want a version_mapping_ambiguous BLOCK", result.Verdict, codes(result))
	}
}

// A comma-separated patched_versions names several fixed branches; which one a
// candidate belongs to is the package-identity question this build does not yet
// answer, so it is left ambiguous rather than guessed.
func TestVulnMultiBranchPatchedStaysAmbiguous(t *testing.T) {
	body := advisoryBodyEntries("GHSA-multi", "high", advisoryEntry{"~>1.2.0", "1.5.0, 2.0.0"})
	newFakeGitHub(t, routes(advisoriesFeed(body)))

	result := vuln(vulnSpec())
	if result.Verdict != BLOCK || !hasCode(result, "version_mapping_ambiguous") {
		t.Fatalf("verdict %s with reasons %v, want a version_mapping_ambiguous BLOCK", result.Verdict, codes(result))
	}
}

// Behavior change from divergence 12: an entry with an empty range used to be
// skipped and, if it was the only one, read as ambiguous. With a patched
// version present it now resolves — an empty range plus a fix version at or
// below the candidate is not affected.
func TestVulnEmptyRangeWithPatchedResolves(t *testing.T) {
	body := advisoryBodyEntries("GHSA-emptypatched", "high", advisoryEntry{"", "1.0.0"})
	newFakeGitHub(t, routes(advisoriesFeed(body)))

	result := vuln(vulnSpec())
	if result.Verdict != GO || len(result.Reasons) != 0 {
		t.Fatalf("verdict %s with reasons %v, want a clean GO", result.Verdict, codes(result))
	}
}

// An unreadable range with no usable patched_versions still fails closed — the
// fallback is a resolver, not a loosening.
func TestVulnUnreadableRangeWithoutPatchedStillBlocks(t *testing.T) {
	body := advisoryBodyEntries("GHSA-nopatched", "low", advisoryEntry{"~>1.2.0", ""})
	newFakeGitHub(t, routes(advisoriesFeed(body)))

	result := vuln(vulnSpec())
	if result.Verdict != BLOCK || !hasCode(result, "version_mapping_ambiguous") {
		t.Fatalf("verdict %s with reasons %v, want a version_mapping_ambiguous BLOCK", result.Verdict, codes(result))
	}
}

// Ranges are read in order and the first match wins, so an unreadable range
// listed after a matching one does not turn a decided advisory into an
// undecided one.
func TestVulnMatchWinsOverALaterUnreadableRange(t *testing.T) {
	newFakeGitHub(t, routes(advisoriesFeed(advisoryBody("GHSA-mixed", "high", "<v2.0.0", "~>9.9.9"))))

	result := vuln(vulnSpec())
	if result.Verdict != BLOCK {
		t.Fatalf("verdict %s, want BLOCK", result.Verdict)
	}
	if hasCode(result, "version_mapping_ambiguous") {
		t.Fatalf("reasons %v: a matched advisory was also reported as unmappable", codes(result))
	}
}

// An unreadable range before a matching one is a different story: it was read,
// it decided nothing, and both facts are reported.
func TestVulnAmbiguityBeforeAMatchIsAlsoReported(t *testing.T) {
	newFakeGitHub(t, routes(advisoriesFeed(advisoryBody("GHSA-both", "low", "~>9.9.9", "<v2.0.0"))))

	result := vuln(vulnSpec())
	if result.Verdict != BLOCK {
		t.Fatalf("verdict %s with reasons %v, want BLOCK", result.Verdict, codes(result))
	}
	for _, code := range []string{"version_mapping_ambiguous", "known_advisory"} {
		if !hasCode(result, code) {
			t.Fatalf("reasons %v are missing %s", codes(result), code)
		}
	}
}

// 404 is evidence about the subject, not about the tooling: the advisories
// endpoint answers 200 with an empty array for a repository that has published
// none, so a 404 means the repository itself is not visible.
func TestVulnFeedNotFoundBlocksAndNamesThePrivateRepoCase(t *testing.T) {
	newFakeGitHub(t, routes(nil))

	result := vuln(vulnSpec())
	if result.Verdict != BLOCK {
		t.Fatalf("verdict %s with reasons %v, want BLOCK", result.Verdict, codes(result))
	}
	message := reasonWithCode(t, result, "advisory_feed_missing").Message
	if !strings.Contains(message, "GITHUB_TOKEN") || !strings.Contains(message, "private") {
		t.Fatalf("message %q does not name the private-repository case", message)
	}
}

func TestVulnFeedInfrastructureFailureIsError(t *testing.T) {
	for _, status := range []int{http.StatusInternalServerError, http.StatusTooManyRequests, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			newFakeGitHub(t, func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(status)
				fmt.Fprint(writer, `{"message":"nope"}`)
			})

			result := vuln(vulnSpec())
			if result.Verdict != ERROR {
				t.Fatalf("verdict %s with reasons %v, want ERROR", result.Verdict, codes(result))
			}
			if hasCode(result, "advisory_feed_missing") {
				t.Fatal("an unreachable feed was reported as a repository with no advisories")
			}
			message := reasonWithCode(t, result, "advisory_feed_unavailable").Message
			if !strings.Contains(message, "audit-infrastructure breakage") {
				t.Fatalf("message %q does not say the review broke", message)
			}
		})
	}
}

func TestVulnFeedFollowsPagination(t *testing.T) {
	var serverURL string
	fake := newFakeGitHub(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != advisoriesPath {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		if request.URL.Query().Get("page") == "2" {
			fmt.Fprint(writer, "["+advisoryBody("GHSA-second-page", "critical", "<v2.0.0")+"]")
			return
		}
		writer.Header().Set("Link", fmt.Sprintf(`<%s%s?per_page=100&page=2>; rel="next"`, serverURL, advisoriesPath))
		fmt.Fprint(writer, "["+advisoryBody("GHSA-first-page", "low", "<1.0.0")+"]")
	})
	serverURL = fake.server.URL

	result := vuln(vulnSpec())
	if result.Verdict != BLOCK {
		t.Fatalf("verdict %s with reasons %v, want BLOCK from the advisory on page 2", result.Verdict, codes(result))
	}
	if reason := reasonWithCode(t, result, "known_advisory_high_severity"); reason.Data["advisory"] != "GHSA-second-page" {
		t.Fatalf("unexpected reason data %v", reason.Data)
	}
}

// Unlike the release history, there is no early answer here: an advisory this
// check never read is an advisory it cannot rule out, so a capped walk is the
// review failing to run rather than a repository with nothing published.
func TestVulnFeedPageCapIsError(t *testing.T) {
	var serverURL string
	fake := newFakeGitHub(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != advisoriesPath {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		writer.Header().Set("Link", fmt.Sprintf(`<%s%s?per_page=100&page=99>; rel="next"`, serverURL, advisoriesPath))
		fmt.Fprint(writer, "[]")
	})
	serverURL = fake.server.URL

	result := vuln(vulnSpec())
	if result.Verdict != ERROR || !hasCode(result, "advisory_feed_truncated") {
		t.Fatalf("verdict %s with reasons %v, want an advisory_feed_truncated ERROR", result.Verdict, codes(result))
	}
	if len(fake.requests) != githubMaxPages {
		t.Fatalf("the feed was fetched %d times, want the %d-page cap", len(fake.requests), githubMaxPages)
	}
}

// The token fence again, on the lane that queries a security feed: the header
// carries it and nothing else does.
func TestVulnSendsTheTokenOnlyInTheAuthorizationHeader(t *testing.T) {
	fake := newFakeGitHub(t, routes(advisoriesFeed()))
	const token = "ghp-fixture-credential-not-a-real-token"
	t.Setenv("GITHUB_TOKEN", token)

	if result := vuln(vulnSpec()); result.Verdict != GO {
		t.Fatalf("verdict %s, want GO", result.Verdict)
	}
	for _, request := range fake.requests {
		if request.authScheme != "Bearer" {
			t.Fatalf("%s was sent with auth scheme %q, want Bearer", request.path, request.authScheme)
		}
		if strings.Contains(request.path, token) || strings.Contains(request.rawQuery, token) {
			t.Fatalf("the token reached the request line of %s", request.path)
		}
	}
}
