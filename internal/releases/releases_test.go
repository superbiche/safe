package releases

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// memCache is an in-memory Cache that counts its use.
type memCache struct {
	mu      sync.Mutex
	entries map[string]time.Time
}

func (m *memCache) Get(source, name, version string) (time.Time, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.entries[source+"|"+name+"|"+version]
	return t, ok
}

func (m *memCache) Put(source, name, version string, published time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.entries == nil {
		m.entries = map[string]time.Time{}
	}
	m.entries[source+"|"+name+"|"+version] = published
}

func packumentServer(t *testing.T, doc map[string]map[string]any, hits *int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			atomic.AddInt32(hits, 1)
		}
		name := strings.TrimPrefix(r.URL.EscapedPath(), "/")
		body, ok := doc[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(body)
	}))
}

func readerFor(server *httptest.Server, cache Cache) *Reader {
	// the production client (no proxy, no redirect): the servers of these tests are plain HTTP
	return &Reader{Cache: cache, BaseFor: func(string) string { return server.URL }}
}

func packument(name string, times map[string]string) map[string]any {
	t := map[string]any{}
	for k, v := range times {
		t[k] = v
	}
	return map[string]any{"name": name, "time": t}
}

func TestReadsPublishTimePerExactVersionAndKeepsFractionalSeconds(t *testing.T) {
	var hits int32
	server := packumentServer(t, map[string]map[string]any{
		"left-pad":    packument("left-pad", map[string]string{"1.0.0": "2020-01-02T03:04:05.123Z", "1.1.0": "2026-11-19T10:00:00.000Z"}),
		"@scope%2Fpk": packument("@scope/pk", map[string]string{"2.0.0": "2025-05-05T05:05:05.000Z"}),
	}, &hits)
	defer server.Close()
	cache := &memCache{}
	reader := readerFor(server, cache)
	queries := []Query{{"left-pad", "1.0.0", "registry.npmjs.org"}, {"left-pad", "1.1.0", "registry.npmjs.org"}, {"@scope/pk", "2.0.0", "registry.npmjs.org"}}
	results := reader.Read(context.Background(), queries)
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("one packument per name expected, got %d fetches", got)
	}
	if !results[0].OK || results[0].Published.Nanosecond() != 123_000_000 {
		t.Fatalf("the fractional second was lost: %+v", results[0])
	}
	for i, result := range results {
		if !result.OK || result.Cached {
			t.Fatalf("result %d: %+v", i, result)
		}
	}
	again := reader.Read(context.Background(), queries)
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("a cached version was fetched again (%d fetches)", got)
	}
	for i, result := range again {
		if !result.OK || !result.Cached || !result.Published.Equal(results[i].Published) {
			t.Fatalf("cached result %d: %+v", i, result)
		}
	}
	// the cache is keyed by the source actually asked
	for key := range cache.entries {
		if !strings.HasPrefix(key, server.URL+"|") {
			t.Fatalf("entry key %q does not carry the source asked", key)
		}
	}
}

func TestOnlyACompleteAnswerWithoutATimeIsTheNoTimeGap(t *testing.T) {
	server := packumentServer(t, map[string]map[string]any{
		"has-times": packument("has-times", map[string]string{"1.0.0": "2020-01-02T03:04:05.000Z"}),
		"no-times":  {"name": "no-times"},
	}, nil)
	defer server.Close()
	results := readerFor(server, &memCache{}).Read(context.Background(), []Query{
		{"has-times", "9.9.9", "h"}, // the version is absent from the map
		{"no-times", "1.0.0", "h"},  // no time at all
	})
	for i, result := range results {
		if result.OK || !result.NoTime || result.Failure != "" {
			t.Fatalf("result %d must be the no-time gap: %+v", i, result)
		}
	}
}

func TestEveryOtherCauseIsAFailureNeverAGap(t *testing.T) {
	var redirected int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&redirected, 1)
		json.NewEncoder(w).Encode(packument("moved", map[string]string{"1.0.0": "2020-01-01T00:00:00.000Z"}))
	}))
	defer other.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/error", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", 503) })
	mux.HandleFunc("/moved", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/moved", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/garbled", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"name":"garbled","time":{`)) })
	mux.HandleFunc("/array", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`[1]`)) })
	mux.HandleFunc("/badtime", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(packument("badtime", map[string]string{"1.0.0": "last tuesday"}))
	})
	mux.HandleFunc("/nottext", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"name": "nottext", "time": map[string]any{"1.0.0": 7}})
	})
	// an answer for ANOTHER package that holds a time for the version asked
	mux.HandleFunc("/asked", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(packument("someone-else", map[string]string{"1.0.0": "2000-01-01T00:00:00.000Z"}))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	cache := &memCache{}
	queries := []Query{{"error", "1.0.0", "h"}, {"moved", "1.0.0", "h"}, {"garbled", "1.0.0", "h"}, {"array", "1.0.0", "h"},
		{"badtime", "1.0.0", "h"}, {"nottext", "1.0.0", "h"}, {"asked", "1.0.0", "h"}, {"absent", "1.0.0", "h"}}
	results := readerFor(server, cache).Read(context.Background(), queries)
	for i, result := range results {
		if result.OK || result.NoTime || result.Failure == "" {
			t.Fatalf("%s must be a failure: %+v", queries[i].Name, result)
		}
	}
	if !strings.Contains(results[1].Failure, "HTTP 301") || atomic.LoadInt32(&redirected) != 0 {
		t.Fatalf("a redirect must not be followed (%q, %d hits on the other host)", results[1].Failure, redirected)
	}
	if !strings.Contains(results[6].Failure, "another package") {
		t.Fatalf("another package's answer: %q", results[6].Failure)
	}
	if len(cache.entries) != 0 {
		t.Fatalf("a failed reading was cached: %v", cache.entries)
	}
}

func TestTheSizeLimitIsAFailureNamedAsSuch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"name":"big","time":{"1.0.0":"2020-01-01T00:00:00.000Z"},"filler":"`))
		chunk := strings.Repeat("x", 1<<20)
		for i := 0; i < 3; i++ {
			w.Write([]byte(chunk))
		}
		w.Write([]byte(`"}`))
	}))
	defer server.Close()
	saved := maxPackument
	maxPackument = 2 << 20
	defer func() { maxPackument = saved }()
	result := readerFor(server, &memCache{}).Read(context.Background(), []Query{{"big", "1.0.0", "h"}})[0]
	if result.OK || result.NoTime || !strings.Contains(result.Failure, "limit") {
		t.Fatalf("a valid answer above the limit must be a failure naming the limit: %+v", result)
	}
}

func TestAReadingNeverAttemptedIsAFailure(t *testing.T) {
	server := packumentServer(t, map[string]map[string]any{"a": packument("a", map[string]string{"1.0.0": "2020-01-01T00:00:00.000Z"})}, nil)
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the deadline ran out before anything started
	results := readerFor(server, &memCache{}).Read(ctx, []Query{{"a", "1.0.0", "h"}, {"b", "1.0.0", "h"}})
	for i, result := range results {
		if result.OK || result.NoTime || result.Failure == "" {
			t.Fatalf("result %d must be a failure: %+v", i, result)
		}
	}
	if !strings.Contains(results[1].Failure, "not attempted") && !strings.Contains(results[1].Failure, "time limit") {
		t.Fatalf("failure text: %q", results[1].Failure)
	}
}

func TestTheClientIsNotSteeredByTheCallersEnvironment(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("http_proxy", "http://127.0.0.1:1")
	server := packumentServer(t, map[string]map[string]any{"pk": packument("pk", map[string]string{"1.0.0": "2020-01-01T00:00:00.000Z"})}, nil)
	defer server.Close()
	// the default client: a proxy named by the environment is not used (the server is reached directly)
	reader := &Reader{BaseFor: func(string) string { return server.URL }}
	if result := reader.Read(context.Background(), []Query{{"pk", "1.0.0", "h"}})[0]; !result.OK {
		t.Fatalf("the caller's proxy steered the reading: %+v", result)
	}
	transport := NewClient().Transport.(*http.Transport)
	if transport.Proxy != nil || transport.TLSClientConfig != nil {
		t.Fatal("the transport takes a proxy or a TLS configuration")
	}
}
