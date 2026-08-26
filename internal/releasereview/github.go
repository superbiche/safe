package releasereview

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
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
	// How many HTTP redirects a single request may follow. A custom
	// CheckRedirect replaces Go's default policy, and the default 10-hop cap goes
	// with it, so the same bound is re-imposed here.
	githubMaxRedirects = 10
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
// get, and only when the request targets the base URL's own host (see
// tokenTargetTrusted). It is never put in a URL, an argument, a reason's data, a
// report, or an error message — including the ones built from a transport error,
// which carry the request URL and nothing else.
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
	client := &githubClient{
		baseURL: base,
		token:   os.Getenv("GITHUB_TOKEN"),
	}
	// A custom CheckRedirect replaces Go's default redirect policy, which copies
	// the Authorization header onto a same-host-or-subdomain target by hostname
	// alone — dropping scheme and port, so it is looser than the origin the token
	// is pinned to. The default 10-hop cap goes with the default policy, so it is
	// re-imposed in the callback.
	client.http = &http.Client{
		Timeout:       githubRequestTimeout,
		CheckRedirect: client.stripTokenOnForeignRedirect,
	}
	return client
}

// stripTokenOnForeignRedirect keeps GITHUB_TOKEN pinned to the base origin across
// redirects, not just on the first request.
//
// Go copies the Authorization header onto a redirect whose host equals or is a
// subdomain of the original — and it decides that by hostname alone, so a
// same-host port change, an https→http downgrade, or a subdomain all keep the
// header. The composite pins the token to the whole origin, so the header is
// removed on any hop the direct-URL check would reject. This callback runs after
// Go's own header copy, so deleting the header here is authoritative; nothing
// re-adds it on a later hop.
func (c *githubClient) stripTokenOnForeignRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= githubMaxRedirects {
		return fmt.Errorf("stopped after %d redirects", githubMaxRedirects)
	}
	base, err := neturl.Parse(c.baseURL)
	if err != nil || !sameGitHubOrigin(base, req.URL) {
		req.Header.Del("Authorization")
	}
	return nil
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
	if c.token != "" && c.tokenTargetTrusted(url) {
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

// tokenTargetTrusted reports whether target addresses the same scheme and host
// as the configured base URL — the only place GITHUB_TOKEN may go.
//
// get is handed absolute URLs taken from response bodies: a Link rel="next"
// target, and the annotated tag object's address. A compromised or proxied API
// response must not be able to steer the bearer token at a host of its choosing.
// Go already strips Authorization across a cross-host *redirect*; this closes the
// direct-absolute-URL path, which is not a redirect and which Go does not guard.
//
// On a base URL or a target that will not parse, the token is withheld: a
// destination that cannot be shown to match is not one to trust with a
// credential. The whole-URL parse rejects the userinfo trick
// (https://api.github.com@evil.example), where the host is evil.example.
func (c *githubClient) tokenTargetTrusted(target string) bool {
	base, err := neturl.Parse(c.baseURL)
	if err != nil {
		return false
	}
	destination, err := neturl.Parse(target)
	if err != nil {
		return false
	}
	return sameGitHubOrigin(base, destination)
}

// sameGitHubOrigin reports whether target shares the base URL's origin — scheme,
// host and effective port — the only origin GITHUB_TOKEN is attached to.
//
// The effective port folds a scheme's default (443 for https, 80 for http) into
// the comparison, so an explicit `:443` under https equals its omitted form and
// a same-origin request does not silently lose its token over a port the URL
// merely spelled out; a genuinely different port stays foreign. Host is compared
// case-insensitively. Scheme is matched exactly, so an https→http downgrade of
// the same host is foreign.
func sameGitHubOrigin(base, target *neturl.URL) bool {
	return target.Scheme == base.Scheme &&
		strings.EqualFold(target.Hostname(), base.Hostname()) &&
		effectivePort(target) == effectivePort(base)
}

// effectivePort is the URL's port, or the scheme's default when none is spelled
// out. An unknown scheme has no default, which keeps two unknown-scheme URLs
// comparable only when they carry the same explicit port.
func effectivePort(u *neturl.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	switch u.Scheme {
	case "https":
		return "443"
	case "http":
		return "80"
	default:
		return ""
	}
}

// getPaged walks a listing, appending each page through collect, and reports
// whether the page cap stopped it before the listing ran out.
//
// The bash lane read only the first page of `per_page=100`, so on a repository
// with a long history it computed the previous tag and the same-day count from
// a truncated view. Following the Link header fixes that; the cap is what keeps
// a review of a very long history bounded, and capped is returned so the caller
// can say so rather than quietly deciding on partial data.
//
// collect returns stop=true when it has read as far back as it needs, which ends
// the walk without reading the rest of the listing. That is a caller decision,
// not a page-cap truncation, so capped stays false — but it is not a claim that
// the whole listing was seen: what a stop actually guarantees is the caller's to
// define (for the release history, the predecessor is resolved; the same-day
// count over the unread tail stays best-effort — see historyWalkSatisfied). A
// repository like openai/codex publishes over a thousand releases whose bodies
// are hundreds of KB each; a listing read to its end could neither fit a page
// under the body cap nor finish inside the page budget, so a caller that can act
// on the newest entries stops here instead of walking the whole history.
func (c *githubClient) getPaged(path string, maxPages int, collect func(page json.RawMessage) (stop bool, err *githubError)) (capped bool, err *githubError) {
	next := path
	for page := 0; page < maxPages; page++ {
		var raw json.RawMessage
		following, requestErr := c.get(next, &raw)
		if requestErr != nil {
			return false, requestErr
		}
		stop, collectErr := collect(raw)
		if collectErr != nil {
			return false, collectErr
		}
		if stop {
			return false, nil
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
