package releasereview

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The release and vuln checks are the only ones that reach the network, so
// their tests stand up a real HTTP server and point the checks at it through
// SAFE_AUDIT_GITHUB_API_BASE_URL — the same variable an operator uses to aim
// the checks at a proxy. Nothing here is mocked at the client level: the
// request that goes out is the request GitHub would receive.
//
// Tests using this must not run in parallel: the base URL is process-global.

// recordedRequest is what a test may know about a request the check made.
//
// authScheme deliberately records only the scheme word, never the credential.
// A test that captured the token could print it from a failure message, and a
// failing test's output goes to a log — so the fence that keeps GITHUB_TOKEN
// out of everything but the Authorization header is enforced here too.
type recordedRequest struct {
	path       string
	rawQuery   string
	accept     string
	apiVersion string
	userAgent  string
	authScheme string
}

type fakeGitHub struct {
	server   *httptest.Server
	requests []recordedRequest
}

// newFakeGitHub serves handler and points the checks at it. GITHUB_TOKEN is
// cleared unless a test sets it after this call: a developer's real token must
// never leave the machine because a unit test ran.
func newFakeGitHub(t *testing.T, handler http.HandlerFunc) *fakeGitHub {
	t.Helper()

	fake := &fakeGitHub{}
	fake.server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		scheme := ""
		if authorization := request.Header.Get("Authorization"); authorization != "" {
			scheme, _, _ = strings.Cut(authorization, " ")
		}
		fake.requests = append(fake.requests, recordedRequest{
			path:       request.URL.Path,
			rawQuery:   request.URL.RawQuery,
			accept:     request.Header.Get("Accept"),
			apiVersion: request.Header.Get("X-GitHub-Api-Version"),
			userAgent:  request.Header.Get("User-Agent"),
			authScheme: scheme,
		})
		handler(writer, request)
	}))
	t.Cleanup(fake.server.Close)

	t.Setenv("SAFE_AUDIT_GITHUB_API_BASE_URL", fake.server.URL)
	t.Setenv("GITHUB_TOKEN", "")
	return fake
}

// routes serves a path-to-body map and answers 404 for everything else, the way
// GitHub answers for a release, a tag or a repository it will not show.
func routes(bodies map[string]string) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		body, ok := bodies[request.URL.Path]
		if !ok {
			writer.WriteHeader(http.StatusNotFound)
			fmt.Fprint(writer, `{"message":"Not Found"}`)
			return
		}
		fmt.Fprint(writer, body)
	}
}

func (f *fakeGitHub) pathsRequested() []string {
	paths := make([]string, 0, len(f.requests))
	for _, request := range f.requests {
		paths = append(paths, request.path)
	}
	return paths
}

func TestNextPageURL(t *testing.T) {
	for _, testCase := range []struct {
		name, header, want string
	}{
		{"absent", "", ""},
		{
			"next and last",
			`<https://api.github.com/repositories/1/releases?page=2>; rel="next", <https://api.github.com/repositories/1/releases?page=9>; rel="last"`,
			"https://api.github.com/repositories/1/releases?page=2",
		},
		{
			// The last page carries prev and first but no next, which is what
			// ends a walk.
			"prev and first only",
			`<https://api.github.com/repositories/1/releases?page=8>; rel="prev", <https://api.github.com/repositories/1/releases?page=1>; rel="first"`,
			"",
		},
		{
			"next not first in the header",
			`<https://api.github.com/x?page=1>; rel="first", <https://api.github.com/x?page=3>; rel="next"`,
			"https://api.github.com/x?page=3",
		},
		{"malformed", "not a link header", ""},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := nextPageURL(testCase.header); got != testCase.want {
				t.Fatalf("nextPageURL(%q) = %q, want %q", testCase.header, got, testCase.want)
			}
		})
	}
}

// A response body is read into memory, so an endpoint that streams without end
// must fail the review rather than grow it — the same bound the exec check's
// output capture has, applied to the other place this package reads bytes it
// does not control.
func TestOversizedResponseIsInfrastructureFailure(t *testing.T) {
	fake := newFakeGitHub(t, func(writer http.ResponseWriter, _ *http.Request) {
		flood := strings.Repeat("x", 64<<10)
		for written := 0; written < githubMaxBodyBytes+(1<<20); written += len(flood) {
			fmt.Fprint(writer, flood)
		}
	})

	var body any
	_, err := newGitHubClient().get("/repos/example/tool/releases/tags/v1", &body)
	if err == nil {
		t.Fatal("an unbounded body was accepted")
	}
	if err.notFound {
		t.Fatal("an oversized body was classified as evidence about the release")
	}
	if !strings.Contains(err.message, "exceeded") {
		t.Fatalf("message %q does not say the response was too large", err.message)
	}
	_ = fake
}
