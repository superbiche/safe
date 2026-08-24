package releasereview

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	defaultGitHubAPIBaseURL = "https://api.github.com"
	// Every request carries its own deadline so a hung endpoint cannot hold the
	// whole review open. There is no ambient cancellation here: a review is a
	// one-shot command, and a stuck socket would otherwise wedge it forever.
	githubRequestTimeout = 30 * time.Second
	// A response body is read into memory, so it is bounded like the exec
	// check's capture: a misdirected base URL streaming an endless body must
	// fail the review, not grow it until the OOM killer arrives.
	githubMaxBodyBytes = 8 << 20
	// How many Link rel="next" hops a paginated listing may follow. Hitting it
	// is reported, never silently truncated.
	githubMaxPages = 10
)

// githubError is a failed GitHub request, classified into the only two things a
// failure can mean to this composite.
//
// notFound is EVIDENCE: GitHub answered, and what was asked for is not there.
// Everything else — a transport failure, a timeout, a 5xx, a rate limit, an
// unreadable body — is audit-infrastructure breakage, which must never read as
// a finding about the release.
type githubError struct {
	notFound bool
	message  string
}

// githubClient talks to the GitHub REST API.
//
// GITHUB_TOKEN enters exactly one place: the Authorization header built in
// get. It is never put in a URL, an argument, a reason's data, a report, or an
// error message — including the ones built from a transport error, which carry
// the request URL and nothing else.
type githubClient struct {
	baseURL string
	token   string
	http    *http.Client
}

// newGitHubClient reads its configuration from the environment on every call
// rather than at package init, because the base URL is what points a test — or
// an operator debugging against a proxy — at something other than GitHub.
func newGitHubClient() *githubClient {
	base := os.Getenv("SAFE_AUDIT_GITHUB_API_BASE_URL")
	if base == "" {
		base = defaultGitHubAPIBaseURL
	}
	return &githubClient{
		baseURL: base,
		token:   os.Getenv("GITHUB_TOKEN"),
		http:    &http.Client{Timeout: githubRequestTimeout},
	}
}

// get fetches one API path and decodes the JSON body into out. It returns the
// URL of the next page when the response carries a Link rel="next".
//
// pathOrURL is either a path appended to the base URL or an absolute URL, the
// same as the bash github_api_get, so a paginated listing can follow the
// absolute URLs GitHub puts in its Link header.
func (c *githubClient) get(pathOrURL string, out any) (string, *githubError) {
	url := pathOrURL
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = c.baseURL + pathOrURL
	}

	ctx, cancel := context.WithTimeout(context.Background(), githubRequestTimeout)
	defer cancel()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", &githubError{message: fmt.Sprintf("could not build a request for %s: %v", url, err)}
	}
	// The header set the bash lane sends, and nothing else.
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	request.Header.Set("User-Agent", "safe-audit")
	if c.token != "" {
		request.Header.Set("Authorization", "Bearer "+c.token)
	}

	response, err := c.http.Do(request)
	if err != nil {
		return "", &githubError{message: fmt.Sprintf("GitHub request to %s failed: %v", url, err)}
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, githubMaxBodyBytes+1))
	if err != nil {
		return "", &githubError{message: fmt.Sprintf("could not read GitHub's response from %s: %v", url, err)}
	}
	if len(body) > githubMaxBodyBytes {
		return "", &githubError{message: fmt.Sprintf("GitHub's response from %s exceeded %d bytes", url, githubMaxBodyBytes)}
	}

	if response.StatusCode == http.StatusNotFound {
		return "", &githubError{notFound: true, message: fmt.Sprintf("GitHub answered 404 for %s", url)}
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return "", &githubError{message: fmt.Sprintf("GitHub answered %s for %s", response.Status, url)}
	}

	if err := json.Unmarshal(body, out); err != nil {
		return "", &githubError{message: fmt.Sprintf("GitHub's response from %s is not the JSON this check expects: %v", url, err)}
	}
	return nextPageURL(response.Header.Get("Link")), nil
}

// getPaged walks a listing, appending each page through collect, and reports
// whether the page cap stopped it before the listing ran out.
//
// The bash lane read only the first page of `per_page=100`, so on a repository
// with a long history it computed the previous tag and the same-day count from
// a truncated view. Following the Link header fixes that; the cap is what keeps
// a review of a very long history bounded, and capped is returned so the caller
// can say so rather than quietly deciding on partial data.
func (c *githubClient) getPaged(path string, collect func(page json.RawMessage) *githubError) (capped bool, err *githubError) {
	next := path
	for page := 0; page < githubMaxPages; page++ {
		var raw json.RawMessage
		following, requestErr := c.get(next, &raw)
		if requestErr != nil {
			return false, requestErr
		}
		if collectErr := collect(raw); collectErr != nil {
			return false, collectErr
		}
		if following == "" {
			return false, nil
		}
		next = following
	}
	return true, nil
}

// nextPageURL pulls the rel="next" URL out of a Link header, which looks like
//
//	<https://api.github.com/...&page=2>; rel="next", <...>; rel="last"
func nextPageURL(link string) string {
	for _, section := range strings.Split(link, ",") {
		parts := strings.Split(section, ";")
		if len(parts) < 2 {
			continue
		}
		target := strings.TrimSpace(parts[0])
		if !strings.HasPrefix(target, "<") || !strings.HasSuffix(target, ">") {
			continue
		}
		for _, parameter := range parts[1:] {
			parameter = strings.TrimSpace(parameter)
			if parameter == `rel="next"` || parameter == "rel=next" {
				return target[1 : len(target)-1]
			}
		}
	}
	return ""
}
