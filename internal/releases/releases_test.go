package releases

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func packumentServer(t *testing.T, doc map[string]map[string]string, hits *int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			atomic.AddInt32(hits, 1)
		}
		name := strings.TrimPrefix(r.URL.EscapedPath(), "/")
		times, ok := doc[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"name": name, "time": times})
	}))
}

func readerFor(server *httptest.Server, cache string) *Reader {
	return &Reader{Client: server.Client(), CacheDir: cache, BaseFor: func(string) string { return server.URL }}
}

func TestReadsPublishTimePerExactVersionAndCachesIt(t *testing.T) {
	var hits int32
	server := packumentServer(t, map[string]map[string]string{
		"left-pad":    {"1.0.0": "2020-01-02T03:04:05.000Z", "1.1.0": "2026-11-19T10:00:00.000Z"},
		"@scope%2Fpk": {"2.0.0": "2025-05-05T05:05:05.000Z"},
	}, &hits)
	defer server.Close()
	cache := filepath.Join(t.TempDir(), "times")
	reader := readerFor(server, cache)
	queries := []Query{{"left-pad", "1.0.0", "registry.npmjs.org"}, {"left-pad", "1.1.0", "registry.npmjs.org"}, {"@scope/pk", "2.0.0", "registry.npmjs.org"}}
	results := reader.Read(context.Background(), queries)
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("one packument per name expected, got %d fetches", got)
	}
	want := []string{"2020-01-02T03:04:05Z", "2026-11-19T10:00:00Z", "2025-05-05T05:05:05Z"}
	for i, result := range results {
		if !result.OK || result.Published.Format(time.RFC3339) != want[i] || result.Cached {
			t.Fatalf("result %d: %+v", i, result)
		}
	}
	// the second reading comes from the cache, per exact version: no fetch
	again := reader.Read(context.Background(), queries)
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("a cached version was fetched again (%d fetches)", got)
	}
	for i, result := range again {
		if !result.OK || !result.Cached || !result.Published.Equal(results[i].Published) {
			t.Fatalf("cached result %d: %+v", i, result)
		}
	}
	entries, _ := os.ReadDir(cache)
	if len(entries) != 3 {
		t.Fatalf("cache entries: %d", len(entries))
	}
	info, _ := os.Stat(filepath.Join(cache, entries[0].Name()))
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("cache entry mode %v", info.Mode().Perm())
	}
}

func TestAnUnreadableAnswerIsAGapAndIsNeverCached(t *testing.T) {
	server := packumentServer(t, map[string]map[string]string{
		"has-times": {"1.0.0": "2020-01-02T03:04:05.000Z", "1.0.1": "not a date"},
		"no-times":  {},
	}, nil)
	defer server.Close()
	cache := t.TempDir()
	reader := readerFor(server, cache)
	results := reader.Read(context.Background(), []Query{
		{"has-times", "9.9.9", "h"}, // version absent from the map
		{"has-times", "1.0.1", "h"}, // not a date
		{"no-times", "1.0.0", "h"},  // no times at all
		{"not-found", "1.0.0", "h"}, // HTTP 404
	})
	for i, result := range results {
		if result.OK || result.Gap == "" {
			t.Fatalf("result %d must be a gap: %+v", i, result)
		}
	}
	if entries, _ := os.ReadDir(cache); len(entries) != 0 {
		t.Fatalf("a failed reading was cached: %d entries", len(entries))
	}
}

func TestACacheEntryOfAnotherIdentityIsIgnored(t *testing.T) {
	server := packumentServer(t, map[string]map[string]string{"pk": {"1.0.0": "2026-11-19T10:00:00.000Z"}}, nil)
	defer server.Close()
	cache := t.TempDir()
	reader := readerFor(server, cache)
	q := Query{"pk", "1.0.0", "h"}
	// a planted entry that claims another name, one with a bad schema, and garbage
	for _, planted := range []string{
		`{"schema_version":1,"host":"h","name":"other","version":"1.0.0","published":"2000-01-01T00:00:00Z"}`,
		`{"schema_version":2,"host":"h","name":"pk","version":"1.0.0","published":"2000-01-01T00:00:00Z"}`,
		`{"schema_version":1,"host":"h","name":"pk","version":"1.0.0","published":"2000-01-01T00:00:00Z","extra":1}`,
		`not json`,
	} {
		if err := os.WriteFile(reader.cachePath(q), []byte(planted), 0o600); err != nil {
			t.Fatal(err)
		}
		result := reader.Read(context.Background(), []Query{q})[0]
		if !result.OK || result.Cached || result.Published.Year() != 2026 {
			t.Fatalf("planted entry %q was used: %+v", planted, result)
		}
	}
}

func osvServer(t *testing.T, pages []string, seen *[]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		token, _ := body["page_token"].(string)
		*seen = append(*seen, token)
		index := 0
		if token != "" {
			index = 1
		}
		w.Write([]byte(pages[index]))
	}))
}

func TestRemediationReadsFixedEventsOfRangesThatOpenedAnInterval(t *testing.T) {
	var tokens []string
	server := osvServer(t, []string{
		`{"vulns":[{"id":"GHSA-aaaa","affected":[{"package":{"name":"pk","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.1"}]}]}]},
		            {"id":"GHSA-bare","affected":[{"package":{"name":"pk","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"fixed":"1.2.1"}]}]}]},
		            {"id":"GHSA-other","affected":[{"package":{"name":"other","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.1"}]}]}]}],
		  "next_page_token":"p2"}`,
		`{"vulns":[{"id":"GHSA-bbbb","affected":[{"package":{"name":"pk","ecosystem":"npm"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"fixed":"1.2.1"},{"fixed":"1.3.0"}]}]}]}]}`,
	}, &tokens)
	defer server.Close()
	got, err := Remediation(context.Background(), server.Client(), server.URL, "pk", []string{"1.2.1", "1.2.2"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got["1.2.1"], ",") != "GHSA-aaaa,GHSA-bbbb" || len(got["1.2.2"]) != 0 {
		t.Fatalf("remediation %v (a bare fixed token, another package's advisory and an unasked version must not count)", got)
	}
	if len(tokens) != 2 || tokens[0] != "" || tokens[1] != "p2" {
		t.Fatalf("pages followed: %v", tokens)
	}
}

func TestRemediationFailureIsAnErrorNotAnEmptyAnswer(t *testing.T) {
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", 500) }))
	defer failing.Close()
	if _, err := Remediation(context.Background(), failing.Client(), failing.URL, "pk", []string{"1.0.0"}); err == nil {
		t.Fatal("an HTTP error is an error")
	}
	garbled := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("{")) }))
	defer garbled.Close()
	if _, err := Remediation(context.Background(), garbled.Client(), garbled.URL, "pk", []string{"1.0.0"}); err == nil {
		t.Fatal("an unreadable answer is an error")
	}
}
