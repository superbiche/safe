// Package releases reads when a registry published an exact version. It is the
// publish-time reading of the project lane's cooldown: safe's own reading, kept
// apart from what npm's release-age filter does (the filter is a selection aid on
// the projection's command line; this reading decides).
//
// What a reading is worth rests on three things:
//
//   - the question goes to the registry the artifact is bound to, over a
//     transport the caller does not steer: no proxy and no redirect (a redirect
//     is an error status), and the TLS roots are the system's, never named by the
//     caller's environment (the command clears SSL_CERT_FILE and SSL_CERT_DIR);
//   - the answer must be for the package asked, and complete;
//   - a time is cached only after safe itself read it, in the lane's own store
//     under the checks of the recorded lockfiles (see projectlane.PublishCache).
//
// Exactly one kind of reading is not a failure without a time: the registry
// answered completely for that package and its answer holds no time for the
// version (NoTime). Everything else that leaves a version without a time is a
// Failure: the registry unreachable, an error status, a time limit, a size limit,
// a reading never attempted because the deadline ran out, an answer for another
// package or one that is not a packument. A Failure is missing evidence.
package releases

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Limits of one reading.
const (
	// RequestTimeout bounds one packument request, connection to last byte.
	RequestTimeout = 60 * time.Second
	// MaxPackument is the largest answer read. A packument carries every version's
	// manifest; the largest of the public registry are tens of MiB (measured in
	// docs/configuration.md). An answer above the limit is a Failure, never a gap.
	MaxPackument = 512 << 20
)

// maxPackument is the limit in force (a variable so that a test can lower it).
var maxPackument int64 = MaxPackument

// Query is one exact version whose publish time is wanted, and the registry
// host it was resolved from.
type Query struct {
	Name    string
	Version string
	Host    string
}

// Result is the reading of one query. OK means Published is a publish time the
// registry gave. NoTime means the registry answered completely for the package
// and holds no time for the version. Otherwise Failure says why there is no
// reading.
type Result struct {
	Query
	Published time.Time
	OK        bool
	NoTime    bool
	Failure   string
	Cached    bool
}

// Cache keeps publish times safe itself read, by the source actually asked.
type Cache interface {
	Get(source, name, version string) (time.Time, bool)
	Put(source, name, version string, published time.Time)
}

// Reader reads publish times from registries.
type Reader struct {
	// Client is the HTTP client; nil is NewClient().
	Client *http.Client
	// Cache is consulted before a registry is asked and fed after it answered.
	Cache Cache
	// BaseFor maps a registry host to the base URL its packuments are under.
	// The default is https://<host>.
	BaseFor func(host string) string
	// Parallel bounds the packuments fetched at once (default 8).
	Parallel int
}

// NewClient is the client of a reading: no proxy, no redirect, the system's
// TLS roots, a bounded request.
func NewClient() *http.Client {
	return &http.Client{
		Timeout: RequestTimeout,
		Transport: &http.Transport{
			Proxy:               nil,
			TLSClientConfig:     nil,
			MaxIdleConnsPerHost: 8,
			TLSHandshakeTimeout: 20 * time.Second,
			DisableCompression:  false,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func (r *Reader) client() *http.Client {
	if r.Client != nil {
		return r.Client
	}
	return NewClient()
}

// Source is the registry a host's packuments are asked of: the key of the cache.
func (r *Reader) Source(host string) string {
	if r.BaseFor != nil {
		return strings.TrimRight(r.BaseFor(host), "/")
	}
	return "https://" + strings.ToLower(host)
}

// Read answers every query. Queries of one (host, name) share one packument;
// the packument is fetched only when some version of it is not cached. A query
// whose packument was never asked because ctx ended first is a Failure.
func (r *Reader) Read(ctx context.Context, queries []Query) []Result {
	results := make([]Result, len(queries))
	type group struct{ source, name string }
	pending := map[group][]int{}
	var order []group
	for i, q := range queries {
		results[i] = Result{Query: q}
		source := r.Source(q.Host)
		if r.Cache != nil {
			if t, ok := r.Cache.Get(source, q.Name, q.Version); ok {
				results[i].Published, results[i].OK, results[i].Cached = t, true, true
				continue
			}
		}
		g := group{source, q.Name}
		if _, seen := pending[g]; !seen {
			order = append(order, g)
		}
		pending[g] = append(pending[g], i)
	}
	parallel := r.Parallel
	if parallel < 1 {
		parallel = 8
	}
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, g := range order {
		g, indexes := g, pending[g]
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			mu.Lock()
			for _, i := range indexes {
				results[i].Failure = "not attempted: the time limit ran out before this reading started"
			}
			mu.Unlock()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			times, failure := r.packumentTimes(ctx, g.source, g.name)
			mu.Lock()
			defer mu.Unlock()
			for _, i := range indexes {
				q := queries[i]
				if failure != "" {
					results[i].Failure = failure
					continue
				}
				raw, present := times[q.Version]
				if !present {
					results[i].NoTime = true
					continue
				}
				text, isText := raw.(string)
				t, err := time.Parse(time.RFC3339, text)
				if !isText || err != nil {
					results[i].Failure = "the registry's publish time for this version is not a date"
					continue
				}
				results[i].Published, results[i].OK = t.UTC(), true
				if r.Cache != nil {
					r.Cache.Put(g.source, q.Name, q.Version, t.UTC())
				}
			}
		}()
	}
	wg.Wait()
	return results
}

// countingReader fails once more than limit bytes were asked of it, so that the
// size limit is told apart from a truncated or malformed answer.
type countingReader struct {
	r     io.Reader
	limit int64
	n     int64
	over  bool
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	if c.n > c.limit {
		c.over = true
		return n, errors.New("size limit")
	}
	return n, err
}

// packumentTimes fetches the full packument of one name from one source and
// returns its `time` map. A non-empty failure says why it is not a complete
// answer for that package.
func (r *Reader) packumentTimes(ctx context.Context, source, name string) (map[string]any, string) {
	endpoint := source + "/" + escapeName(name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, "the packument request could not be formed"
	}
	req.Header.Set("Accept", "application/json")
	resp, err := r.client().Do(req)
	if err != nil {
		if ctx.Err() != nil || isTimeout(err) {
			return nil, "the time limit ran out while the registry was asked"
		}
		return nil, "the registry could not be reached"
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Sprintf("the registry answered HTTP %d", resp.StatusCode)
	}
	counter := &countingReader{r: resp.Body, limit: maxPackument}
	var doc struct {
		Name string         `json:"name"`
		Time map[string]any `json:"time"`
	}
	if err := json.NewDecoder(counter).Decode(&doc); err != nil {
		switch {
		case counter.over:
			return nil, fmt.Sprintf("the registry's answer is larger than the %d MiB limit", maxPackument>>20)
		case ctx.Err() != nil || isTimeout(err):
			return nil, "the time limit ran out while the registry's answer was read"
		}
		return nil, "the registry's answer is not a complete packument"
	}
	if counter.over {
		return nil, fmt.Sprintf("the registry's answer is larger than the %d MiB limit", maxPackument>>20)
	}
	if doc.Name != name {
		return nil, "the registry's answer is for another package"
	}
	if doc.Time == nil {
		doc.Time = map[string]any{}
	}
	return doc.Time, ""
}

func isTimeout(err error) bool {
	var timeout interface{ Timeout() bool }
	return errors.As(err, &timeout) && timeout.Timeout()
}

// escapeName is how the registry spells a name in a path: a scoped name keeps
// its `@` and writes its slash as %2F.
func escapeName(name string) string {
	return strings.ReplaceAll(url.PathEscape(name), "%40", "@")
}
