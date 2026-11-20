// Package releases reads when a registry published an exact version. It is the
// publish-time reading of the project lane's cooldown: safe's own reading, kept
// apart from what npm's release-age filter does (the filter is a selection aid on
// the projection's command line; this reading decides).
//
// There is no publish time the lane lets pass unread. A reading accepts ONE
// complete answer: the registry's full metadata document, decoded to its end with
// nothing after it, whose name is the package asked and which lists the version
// asked. The version's time is then its own (`time[version]`); a version the
// document lists without a time of its own is bounded by the document's
// last-modified time (`time.modified`), which no publish time in the document can
// exceed (measured on the public registry: docs/configuration.md). Everything else
// is a Failure, which is missing evidence: the registry unreachable, an error
// status or a redirect, a time or size limit, a reading never attempted, an
// abbreviated or truncated answer, another package's answer, a version the answer
// does not list, a document with no last-modified time.
//
// What a reading is worth rests on three more things:
//
//   - the question goes to the registry the artifact is bound to, over a
//     transport the caller does not steer: no proxy and no redirect (a redirect
//     is an error status), and the TLS roots are the system's, never named by the
//     caller's environment (the command clears SSL_CERT_FILE and SSL_CERT_DIR);
//   - the answer is read as a stream and only the fields the reading needs are
//     kept (the name, the time of each version, the names of the versions), so the
//     size of an answer does not set the memory it takes;
//   - a time is cached only after safe itself read it, in the lane's own store
//     under the checks of the recorded lockfiles (see projectlane.PublishCache).
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
	// MaxPackument is the largest answer read: eight times the largest full document measured on the public
	// registry (31 MiB, `next`; docs/configuration.md). An answer above it is a Failure.
	MaxPackument = 256 << 20
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

// Result is the reading of one query. OK means Published is the version's own
// publish time; with Bounded, the document lists the version without a time of
// its own and Published is the document's last-modified time, an upper bound of
// the version's publish time. Otherwise Failure says why there is no reading.
type Result struct {
	Query
	Published time.Time
	OK        bool
	Bounded   bool
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
			// all the versions asked of this package are answered by one document
			var wanted []string
			for _, i := range indexes {
				wanted = append(wanted, queries[i].Version)
			}
			doc, failure := r.packument(ctx, g.source, g.name, wanted)
			mu.Lock()
			defer mu.Unlock()
			for _, i := range indexes {
				q := queries[i]
				if failure != "" {
					results[i].Failure = failure
					continue
				}
				if !doc.listed[q.Version] {
					results[i].Failure = "the registry's answer does not list this version"
					continue
				}
				if raw, own := doc.times[q.Version]; own {
					t, err := time.Parse(time.RFC3339, raw)
					if err != nil {
						results[i].Failure = "the registry's publish time for this version is not a date"
						continue
					}
					results[i].Published, results[i].OK = t.UTC(), true
					if r.Cache != nil {
						r.Cache.Put(g.source, q.Name, q.Version, t.UTC())
					}
					continue
				}
				if doc.modified == "" {
					results[i].Failure = "the registry's answer lists this version without a time and carries no last-modified time"
					continue
				}
				t, err := time.Parse(time.RFC3339, doc.modified)
				if err != nil {
					results[i].Failure = "the registry's last-modified time is not a date"
					continue
				}
				// the version has no time of its own: the last-modified time bounds it (never cached: it moves)
				results[i].Published, results[i].OK, results[i].Bounded = t.UTC(), true, true
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

// document is what a reading keeps of a packument.
type document struct {
	name     string
	times    map[string]string // the time of each version asked, and nothing else
	listed   map[string]bool   // which of the versions asked the document lists
	modified string            // time.modified
}

// packument fetches the full packument of one name from one source and returns
// what the reading needs of it. A non-empty failure says why it is not one
// complete answer for that package.
func (r *Reader) packument(ctx context.Context, source, name string, wanted []string) (document, string) {
	endpoint := source + "/" + escapeName(name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return document{}, "the packument request could not be formed"
	}
	req.Header.Set("Accept", "application/json")
	resp, err := r.client().Do(req)
	if err != nil {
		if ctx.Err() != nil || isTimeout(err) {
			return document{}, "the time limit ran out while the registry was asked"
		}
		return document{}, "the registry could not be reached"
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return document{}, fmt.Sprintf("the registry answered HTTP %d", resp.StatusCode)
	}
	counter := &countingReader{r: resp.Body, limit: maxPackument}
	doc, err := parsePackument(counter, wanted)
	if err != nil {
		switch {
		case counter.over:
			return document{}, fmt.Sprintf("the registry's answer is larger than the %d MiB limit", maxPackument>>20)
		case ctx.Err() != nil || isTimeout(err):
			return document{}, "the time limit ran out while the registry's answer was read"
		}
		return document{}, "the registry's answer is not one complete full packument (" + err.Error() + ")"
	}
	if doc.name != name {
		return document{}, "the registry's answer is for another package"
	}
	return doc, ""
}

// parsePackument reads one JSON document as a stream, to its end, keeping only
// the name, the time of each version asked, the last-modified time and which of
// the versions asked are listed. A document that repeats one of those members, or
// carries anything after it, is not one complete answer.
func parsePackument(r io.Reader, wanted []string) (document, error) {
	want := map[string]bool{}
	for _, v := range wanted {
		want[v] = true
	}
	doc := document{times: map[string]string{}, listed: map[string]bool{}}
	dec := json.NewDecoder(r)
	if err := expectDelim(dec, '{'); err != nil {
		return doc, err
	}
	seen := map[string]bool{}
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return doc, err
		}
		key, _ := keyToken.(string)
		switch key {
		case "name", "time", "versions":
			if seen[key] {
				return doc, fmt.Errorf("member %q is given twice", key)
			}
			seen[key] = true
		}
		switch key {
		case "name":
			if err := dec.Decode(&doc.name); err != nil {
				return doc, err
			}
		case "time":
			if err := expectDelim(dec, '{'); err != nil {
				return doc, err
			}
			own := map[string]bool{}
			for dec.More() {
				k, err := dec.Token()
				if err != nil {
					return doc, err
				}
				version, _ := k.(string)
				if own[version] {
					return doc, fmt.Errorf("time %q is given twice", version)
				}
				own[version] = true
				if want[version] || version == "modified" {
					value, err := dec.Token()
					if err != nil {
						return doc, err
					}
					text, isText := value.(string)
					if !isText {
						// a value that is not a string is not a time: it stays in the document as text that is not a date
						if d, isDelim := value.(json.Delim); isDelim {
							if err := skipRest(dec, d); err != nil {
								return doc, err
							}
						}
						text = "(not a string)"
					}
					if version == "modified" {
						doc.modified = text
					} else {
						doc.times[version] = text
					}
					continue
				}
				if err := skipValue(dec); err != nil {
					return doc, err
				}
			}
			if err := expectDelim(dec, '}'); err != nil {
				return doc, err
			}
		case "versions":
			if err := expectDelim(dec, '{'); err != nil {
				return doc, err
			}
			listed := map[string]bool{}
			for dec.More() {
				k, err := dec.Token()
				if err != nil {
					return doc, err
				}
				version, _ := k.(string)
				if listed[version] {
					return doc, fmt.Errorf("version %q is listed twice", version)
				}
				listed[version] = true
				if want[version] {
					doc.listed[version] = true
				}
				if err := skipValue(dec); err != nil {
					return doc, err
				}
			}
			if err := expectDelim(dec, '}'); err != nil {
				return doc, err
			}
		default:
			if err := skipValue(dec); err != nil {
				return doc, err
			}
		}
	}
	if err := expectDelim(dec, '}'); err != nil {
		return doc, err
	}
	// nothing may follow the document
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return doc, errors.New("data follows the document")
		}
		return doc, err
	}
	if !seen["name"] || !seen["versions"] {
		return doc, errors.New("the document has no name or no versions (an abbreviated or other answer)")
	}
	return doc, nil
}

func expectDelim(dec *json.Decoder, want json.Delim) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := token.(json.Delim); !ok || d != want {
		return fmt.Errorf("expected %q", string(want))
	}
	return nil
}

// skipValue reads one value (a scalar, or an object or array to its close) and keeps nothing of it.
func skipValue(dec *json.Decoder) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := token.(json.Delim); ok {
		return skipRest(dec, d)
	}
	return nil
}

// skipRest reads the rest of an object or array whose opening delimiter was just read.
func skipRest(dec *json.Decoder, open json.Delim) error {
	depth := 1
	for depth > 0 {
		token, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := token.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
		}
	}
	return nil
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
