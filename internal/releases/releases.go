// Package releases reads when a registry published an exact version, and which
// advisories a version fixes. It is the publish-time reading of the project
// lane's cooldown: safe's own reading, kept apart from what npm's release-age
// filter does (the filter is a selection aid on the projection's command line;
// this reading decides).
//
// A publish time is a fact of one exact version that never changes, so it is
// cached per (host, name, version) once read; a reading that failed is never
// cached, and is reported as unreadable, never as old.
package releases

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// CacheSchema is the version of a cache entry; an entry of another version is
// ignored (re-read), never trusted.
const CacheSchema = 1

// DefaultPackumentTimeout and the size limit bound one packument read.
const (
	DefaultTimeout   = 20 * time.Second
	maxPackumentSize = 128 << 20
	maxOSVPages      = 20
)

// Query is one exact version whose publish time is wanted, and the registry
// host it was resolved from.
type Query struct {
	Name    string
	Version string
	Host    string
}

// Result is the reading of one query. OK means Published is a publish time the
// registry gave; otherwise Gap says why there is none.
type Result struct {
	Query
	Published time.Time
	OK        bool
	Gap       string
	Cached    bool
}

// Reader reads publish times from registries, caching per exact version.
type Reader struct {
	Client *http.Client
	// CacheDir is where positive readings are kept ("" = no cache).
	CacheDir string
	// BaseFor maps a registry host to the base URL its packuments are under.
	// The default is https://<host>.
	BaseFor func(host string) string
	// Parallel bounds the packuments fetched at once.
	Parallel int
}

func (r *Reader) client() *http.Client {
	if r.Client != nil {
		return r.Client
	}
	return &http.Client{Timeout: DefaultTimeout}
}

func (r *Reader) base(host string) string {
	if r.BaseFor != nil {
		return strings.TrimRight(r.BaseFor(host), "/")
	}
	return "https://" + host
}

type cacheEntry struct {
	SchemaVersion int    `json:"schema_version"`
	Host          string `json:"host"`
	Name          string `json:"name"`
	Version       string `json:"version"`
	Published     string `json:"published"`
}

func (r *Reader) cachePath(q Query) string {
	sum := sha256.Sum256([]byte(strings.ToLower(q.Host) + "\x00" + q.Name + "\x00" + q.Version))
	return filepath.Join(r.CacheDir, "v1-"+hex.EncodeToString(sum[:])+".json")
}

func (r *Reader) cached(q Query) (time.Time, bool) {
	if r.CacheDir == "" {
		return time.Time{}, false
	}
	raw, err := os.ReadFile(r.cachePath(q))
	if err != nil {
		return time.Time{}, false
	}
	var entry cacheEntry
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&entry) != nil || entry.SchemaVersion != CacheSchema ||
		!strings.EqualFold(entry.Host, q.Host) || entry.Name != q.Name || entry.Version != q.Version {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, entry.Published)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

func (r *Reader) store(q Query, published time.Time) {
	if r.CacheDir == "" {
		return
	}
	if err := os.MkdirAll(r.CacheDir, 0o700); err != nil {
		return
	}
	raw, err := json.Marshal(cacheEntry{CacheSchema, q.Host, q.Name, q.Version, published.UTC().Format(time.RFC3339)})
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(r.CacheDir, ".entry-*")
	if err != nil {
		return
	}
	name := tmp.Name()
	_, werr := tmp.Write(append(raw, '\n'))
	cerr := tmp.Close()
	if werr != nil || cerr != nil || os.Chmod(name, 0o600) != nil || os.Rename(name, r.cachePath(q)) != nil {
		os.Remove(name)
	}
}

// Read answers every query. Queries of one (host, name) share one packument;
// the packument is fetched only when some version of it is not cached.
func (r *Reader) Read(ctx context.Context, queries []Query) []Result {
	results := make([]Result, len(queries))
	type group struct{ host, name string }
	pending := map[group][]int{}
	for i, q := range queries {
		results[i] = Result{Query: q}
		if t, ok := r.cached(q); ok {
			results[i].Published, results[i].OK, results[i].Cached = t, true, true
			continue
		}
		g := group{strings.ToLower(q.Host), q.Name}
		pending[g] = append(pending[g], i)
	}
	parallel := r.Parallel
	if parallel < 1 {
		parallel = 4
	}
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for g, indexes := range pending {
		g, indexes := g, indexes
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			times, gap := r.packumentTimes(ctx, g.host, g.name)
			mu.Lock()
			defer mu.Unlock()
			for _, i := range indexes {
				q := queries[i]
				if gap != "" {
					results[i].Gap = gap
					continue
				}
				raw, present := times[q.Version]
				if !present {
					results[i].Gap = "the registry's packument has no publish time for this version"
					continue
				}
				t, err := time.Parse(time.RFC3339, raw)
				if err != nil {
					results[i].Gap = "the registry's publish time for this version is not a date"
					continue
				}
				results[i].Published, results[i].OK = t.UTC(), true
				r.store(q, t)
			}
		}()
	}
	wg.Wait()
	return results
}

// packumentTimes fetches the full packument of one name and returns its `time`
// map. A non-empty gap says why it could not be read.
func (r *Reader) packumentTimes(ctx context.Context, host, name string) (map[string]string, string) {
	endpoint := r.base(host) + "/" + escapeName(name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, "the packument request could not be formed"
	}
	req.Header.Set("Accept", "application/json")
	resp, err := r.client().Do(req)
	if err != nil {
		return nil, "the registry could not be reached"
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Sprintf("the registry answered HTTP %d", resp.StatusCode)
	}
	var doc struct {
		Time map[string]any `json:"time"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxPackumentSize)).Decode(&doc); err != nil {
		return nil, "the registry's answer is not a readable packument"
	}
	times := make(map[string]string, len(doc.Time))
	for version, value := range doc.Time {
		if text, ok := value.(string); ok {
			times[version] = text
		}
	}
	return times, ""
}

// escapeName is how the registry spells a name in a path: a scoped name keeps
// its `@` and writes its slash as %2F.
func escapeName(name string) string {
	return strings.ReplaceAll(url.PathEscape(name), "%40", "@")
}

// Remediation reads which advisories the given exact versions of one package
// FIX, from the package-level OSV question (the version-scoped question only
// returns what affects a version, so a release that fixes an advisory returns
// nothing there). An advisory counts only when a range that opened an affected
// interval (an `introduced` event) names the version in a `fixed` event, as the
// auditor's cooldown exemption requires. The map holds an entry for every asked
// version.
func Remediation(ctx context.Context, client *http.Client, osvURL, name string, versions []string) (map[string][]string, error) {
	if client == nil {
		client = &http.Client{Timeout: DefaultTimeout}
	}
	osvURL = strings.TrimRight(osvURL, "/")
	out := make(map[string][]string, len(versions))
	want := make(map[string]struct{}, len(versions))
	for _, v := range versions {
		out[v] = []string{}
		want[v] = struct{}{}
	}
	found := map[string]map[string]struct{}{}
	token := ""
	for page := 0; ; page++ {
		if page >= maxOSVPages {
			return nil, fmt.Errorf("the advisory service paged past %d pages", maxOSVPages)
		}
		body := map[string]any{"package": map[string]string{"name": name, "ecosystem": "npm"}}
		if token != "" {
			body["page_token"] = token
		}
		raw, _ := json.Marshal(body)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, osvURL+"/v1/query", bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("the advisory service could not be reached")
		}
		var doc struct {
			Vulns []struct {
				ID       string `json:"id"`
				Affected []struct {
					Package struct {
						Name      string `json:"name"`
						Ecosystem string `json:"ecosystem"`
					} `json:"package"`
					Ranges []struct {
						Type   string `json:"type"`
						Events []struct {
							Introduced *string `json:"introduced"`
							Fixed      *string `json:"fixed"`
						} `json:"events"`
					} `json:"ranges"`
				} `json:"affected"`
			} `json:"vulns"`
			NextPageToken string `json:"next_page_token"`
		}
		decodeErr := json.NewDecoder(io.LimitReader(resp.Body, maxPackumentSize)).Decode(&doc)
		status := resp.StatusCode
		resp.Body.Close()
		if status != http.StatusOK {
			return nil, fmt.Errorf("the advisory service answered HTTP %d", status)
		}
		if decodeErr != nil {
			return nil, fmt.Errorf("the advisory service's answer is not readable")
		}
		for _, vuln := range doc.Vulns {
			if vuln.ID == "" {
				continue
			}
			for _, affected := range vuln.Affected {
				if affected.Package.Ecosystem != "npm" || affected.Package.Name != name {
					continue
				}
				for _, rng := range affected.Ranges {
					if rng.Type != "SEMVER" && rng.Type != "ECOSYSTEM" {
						continue
					}
					opened := false
					for _, event := range rng.Events {
						if event.Introduced != nil && *event.Introduced != "" {
							opened = true
						}
					}
					if !opened {
						continue
					}
					for _, event := range rng.Events {
						if event.Fixed == nil {
							continue
						}
						if _, asked := want[*event.Fixed]; !asked {
							continue
						}
						if found[*event.Fixed] == nil {
							found[*event.Fixed] = map[string]struct{}{}
						}
						found[*event.Fixed][vuln.ID] = struct{}{}
					}
				}
			}
		}
		if doc.NextPageToken == "" {
			break
		}
		token = doc.NextPageToken
	}
	for version, ids := range found {
		list := make([]string, 0, len(ids))
		for id := range ids {
			list = append(list, id)
		}
		sort.Strings(list)
		out[version] = list
	}
	return out, nil
}
