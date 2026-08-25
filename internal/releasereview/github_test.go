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

// GITHUB_TOKEN goes to the base host and nowhere else. get is handed absolute
// URLs taken from response bodies (a Link rel="next" target, an annotated tag
// object's address); a compromised or proxied response naming a foreign host
// must not carry the bearer token there. Two servers on two ports stand in for
// the base and a foreign host — the pin is on scheme+host, and different ports
// are different hosts, so the second server must see no Authorization at all.
//
// Only the auth scheme and a boolean are captured, never the credential: a
// failing test's output goes to a log, and the token must not ride there.
func TestTokenIsPinnedToTheBaseHost(t *testing.T) {
	var baseScheme string
	base := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if authorization := request.Header.Get("Authorization"); authorization != "" {
			baseScheme, _, _ = strings.Cut(authorization, " ")
		}
		fmt.Fprint(writer, `{}`)
	}))
	defer base.Close()

	foreignSawAuth := false
	foreign := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "" {
			foreignSawAuth = true
		}
		fmt.Fprint(writer, `{}`)
	}))
	defer foreign.Close()

	t.Setenv("SAFE_AUDIT_GITHUB_API_BASE_URL", base.URL)
	t.Setenv("GITHUB_TOKEN", "sentinel-not-a-real-token")
	client := newGitHubClient()

	var out any
	if _, err := client.get(base.URL+"/repos/example/tool/releases", &out); err != nil {
		t.Fatalf("the same-host request failed: %s", err.message)
	}
	if _, err := client.get(foreign.URL+"/repos/example/tool/releases", &out); err != nil {
		t.Fatalf("the foreign-host request failed: %s", err.message)
	}

	if baseScheme != "Bearer" {
		t.Fatalf("the base host received auth scheme %q, want Bearer", baseScheme)
	}
	if foreignSawAuth {
		t.Fatal("GITHUB_TOKEN was sent to a host other than the base URL's")
	}
}

// The pin holds across redirects, not only on the first request. Go's default
// policy copies Authorization to a same-host-or-subdomain target by hostname
// alone — keeping it across a port change or an https→http downgrade — so the
// composite installs its own policy that strips the header on any hop the
// direct-URL check would reject. The base redirects to a second server on a
// different port (a foreign origin); the token must not arrive there.
func TestTokenIsStrippedOnAForeignRedirect(t *testing.T) {
	foreignSawAuth := false
	foreign := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "" {
			foreignSawAuth = true
		}
		fmt.Fprint(writer, `{}`)
	}))
	defer foreign.Close()

	base := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, foreign.URL+"/redirected", http.StatusFound)
	}))
	defer base.Close()

	t.Setenv("SAFE_AUDIT_GITHUB_API_BASE_URL", base.URL)
	t.Setenv("GITHUB_TOKEN", "sentinel-not-a-real-token")

	var out any
	if _, err := newGitHubClient().get(base.URL+"/repos/example/tool/releases", &out); err != nil {
		t.Fatalf("the redirected request failed: %s", err.message)
	}
	if foreignSawAuth {
		t.Fatal("GITHUB_TOKEN survived a redirect to a foreign origin")
	}
}

// The other direction: a redirect that stays within the base origin must keep
// the token, or following GitHub's own same-origin redirects would silently drop
// authentication and turn a private resource into a 404 the composite reads as
// evidence.
func TestTokenSurvivesASameOriginRedirect(t *testing.T) {
	var finalScheme string
	sawFinal := false
	base := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/final" {
			sawFinal = true
			if authorization := request.Header.Get("Authorization"); authorization != "" {
				finalScheme, _, _ = strings.Cut(authorization, " ")
			}
			fmt.Fprint(writer, `{}`)
			return
		}
		http.Redirect(writer, request, "/final", http.StatusFound)
	}))
	defer base.Close()

	t.Setenv("SAFE_AUDIT_GITHUB_API_BASE_URL", base.URL)
	t.Setenv("GITHUB_TOKEN", "sentinel-not-a-real-token")

	var out any
	if _, err := newGitHubClient().get(base.URL+"/repos/example/tool/releases", &out); err != nil {
		t.Fatalf("the redirected request failed: %s", err.message)
	}
	if !sawFinal {
		t.Fatal("the same-origin redirect was never followed")
	}
	if finalScheme != "Bearer" {
		t.Fatalf("the same-origin redirect target received auth scheme %q, want Bearer", finalScheme)
	}
}

// The pin compares effective ports, so a base URL and a same-origin target that
// differ only in whether the default port is spelled out still match — otherwise
// a proxy configured with an explicit :443 would lose its token on same-origin
// hops. A genuinely different port stays foreign, and an unparseable target
// withholds the token.
func TestTokenTargetTrustedFoldsDefaultPorts(t *testing.T) {
	for _, testCase := range []struct {
		name, base, target string
		want               bool
	}{
		{"explicit 443 matches implicit https", "https://api.github.com", "https://api.github.com:443/x", true},
		{"implicit https matches explicit 443", "https://api.github.com:443", "https://api.github.com/x", true},
		{"explicit 80 matches implicit http", "http://proxy.internal", "http://proxy.internal:80/x", true},
		{"different port is foreign", "https://api.github.com", "https://api.github.com:8443/x", false},
		{"https to http downgrade is foreign", "https://api.github.com", "http://api.github.com/x", false},
		{"case-insensitive host matches", "https://API.GitHub.com", "https://api.github.com/x", true},
		{"different host is foreign", "https://api.github.com", "https://api.github.com.evil.example/x", false},
		{"userinfo host is foreign", "https://api.github.com", "https://api.github.com@evil.example/x", false},
		{"unparseable target withholds", "https://api.github.com", "https://api.github.com:not-a-port/x", false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			client := &githubClient{baseURL: testCase.base}
			if got := client.tokenTargetTrusted(testCase.target); got != testCase.want {
				t.Fatalf("tokenTargetTrusted(base=%q, %q) = %v, want %v",
					testCase.base, testCase.target, got, testCase.want)
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
