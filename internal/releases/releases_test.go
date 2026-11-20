package releases

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"runtime/debug"
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

// packument is a full metadata document: the name, every version listed, a time for those that have one, and the
// last-modified time.
func packument(name string, times map[string]string, listed ...string) map[string]any {
	t := map[string]any{}
	versions := map[string]any{}
	for k, v := range times {
		t[k] = v
		if k != "modified" && k != "created" {
			versions[k] = map[string]any{"name": name, "version": k}
		}
	}
	for _, v := range listed {
		versions[v] = map[string]any{"name": name, "version": v}
	}
	if _, ok := t["modified"]; !ok {
		t["modified"] = "2026-11-18T13:37:02.787Z"
	}
	return map[string]any{"name": name, "time": t, "versions": versions, "dist-tags": map[string]string{"latest": "1.0.0"}}
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
		if !result.OK || result.Bounded || result.Cached {
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
	for key := range cache.entries {
		if !strings.HasPrefix(key, server.URL+"|") {
			t.Fatalf("entry key %q does not carry the source asked", key)
		}
	}
}

// A version the document lists without a time of its own is bounded by the document's last-modified time, and that
// reading is never cached (the last-modified time moves).
func TestAVersionListedWithoutATimeIsBoundedByTheDocumentsLastModifiedTime(t *testing.T) {
	doc := packument("pk", map[string]string{"1.0.0": "2020-01-01T00:00:00.000Z", "modified": "2026-05-06T07:08:09.250Z"}, "2.0.0")
	server := packumentServer(t, map[string]map[string]any{"pk": doc}, nil)
	defer server.Close()
	cache := &memCache{}
	results := readerFor(server, cache).Read(context.Background(), []Query{{"pk", "1.0.0", "h"}, {"pk", "2.0.0", "h"}})
	if !results[0].OK || results[0].Bounded {
		t.Fatalf("a version with a time of its own: %+v", results[0])
	}
	if !results[1].OK || !results[1].Bounded || results[1].Published.Format(time.RFC3339Nano) != "2026-05-06T07:08:09.25Z" {
		t.Fatalf("the bounded reading: %+v", results[1])
	}
	if len(cache.entries) != 1 {
		t.Fatalf("only the version's own time is cached: %v", cache.entries)
	}
}

// Everything but one complete answer for the package that lists the version is a failure: there is no gap that passes.
func TestEveryAnswerThatIsNotOneCompleteListingIsAFailure(t *testing.T) {
	var redirected int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&redirected, 1)
		json.NewEncoder(w).Encode(packument("moved", map[string]string{"1.0.0": "2020-01-01T00:00:00.000Z"}))
	}))
	defer other.Close()
	good := `{"name":"%s","time":{"1.0.0":"2020-01-01T00:00:00.000Z","modified":"2026-01-01T00:00:00.000Z"},"versions":{"1.0.0":{}}}`
	raw := func(name, body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(strings.Replace(body, "%s", name, 1))) }
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/error", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", 503) })
	mux.HandleFunc("/moved", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/moved", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/garbled", raw("garbled", `{"name":"%s","time":{`))
	mux.HandleFunc("/truncated", raw("truncated", `{"name":"%s","time":{"1.0.0":"2020-01-01T00:00:00.000Z","modified":"2026-01-01T00:00:00.000Z"},"versions":{"1.0.0":{}`))
	mux.HandleFunc("/array", raw("array", `[1]`))
	mux.HandleFunc("/trailing", raw("trailing", good+` {"name":"trailing"}`))
	mux.HandleFunc("/trailing-garbage", raw("trailing-garbage", good+`xx`))
	mux.HandleFunc("/dup-name", raw("dup-name", `{"name":"%s","name":"other","time":{"1.0.0":"2020-01-01T00:00:00.000Z","modified":"2026-01-01T00:00:00.000Z"},"versions":{"1.0.0":{}}}`))
	mux.HandleFunc("/dup-time", raw("dup-time", `{"name":"%s","time":{"1.0.0":"2020-01-01T00:00:00.000Z","1.0.0":"2030-01-01T00:00:00.000Z","modified":"2026-01-01T00:00:00.000Z"},"versions":{"1.0.0":{}}}`))
	mux.HandleFunc("/badtime", raw("badtime", `{"name":"%s","time":{"1.0.0":"last tuesday","modified":"2026-01-01T00:00:00.000Z"},"versions":{"1.0.0":{}}}`))
	mux.HandleFunc("/nottext", raw("nottext", `{"name":"%s","time":{"1.0.0":7,"modified":"2026-01-01T00:00:00.000Z"},"versions":{"1.0.0":{}}}`))
	// abbreviated: no time, a top-level modified, the versions
	mux.HandleFunc("/abbreviated", raw("abbreviated", `{"name":"%s","dist-tags":{"latest":"1.0.0"},"modified":"2026-01-01T00:00:00.000Z","versions":{"1.0.0":{}}}`))
	// name only, and a document that does not list the version
	mux.HandleFunc("/nameonly", raw("nameonly", `{"name":"%s"}`))
	mux.HandleFunc("/unlisted", raw("unlisted", `{"name":"%s","time":{"1.0.0":"2020-01-01T00:00:00.000Z","modified":"2026-01-01T00:00:00.000Z"},"versions":{"0.9.0":{}}}`))
	// listed, no time of its own and no last-modified time
	mux.HandleFunc("/nomodified", raw("nomodified", `{"name":"%s","time":{},"versions":{"1.0.0":{}}}`))
	mux.HandleFunc("/badmodified", raw("badmodified", `{"name":"%s","time":{"modified":"soon"},"versions":{"1.0.0":{}}}`))
	// an answer for ANOTHER package that lists the version and holds its time
	mux.HandleFunc("/asked", raw("someone-else", good))
	server := httptest.NewServer(mux)
	defer server.Close()
	cache := &memCache{}
	names := []string{"error", "moved", "garbled", "truncated", "array", "trailing", "trailing-garbage", "dup-name", "dup-time", "badtime", "nottext",
		"abbreviated", "nameonly", "unlisted", "nomodified", "badmodified", "asked", "absent"}
	queries := make([]Query, len(names))
	for i, n := range names {
		queries[i] = Query{n, "1.0.0", "h"}
	}
	results := readerFor(server, cache).Read(context.Background(), queries)
	for i, result := range results {
		if result.OK || result.Failure == "" {
			t.Fatalf("%s must be a failure: %+v", names[i], result)
		}
	}
	if !strings.Contains(results[1].Failure, "HTTP 301") || atomic.LoadInt32(&redirected) != 0 {
		t.Fatalf("a redirect must not be followed (%q, %d hits on the other host)", results[1].Failure, redirected)
	}
	byName := map[string]string{}
	for i, n := range names {
		byName[n] = results[i].Failure
	}
	for name, fragment := range map[string]string{"asked": "another package", "unlisted": "does not list this version", "nameonly": "no name or no versions",
		"nomodified": "no last-modified time", "abbreviated": "no last-modified time"} {
		if !strings.Contains(byName[name], fragment) {
			t.Errorf("%s: failure %q does not say %q", name, byName[name], fragment)
		}
	}
	if len(cache.entries) != 0 {
		t.Fatalf("a failed reading was cached: %v", cache.entries)
	}
}

// The size of an answer does not set the memory a reading takes: a document of well over 100 MiB is read as a stream.
func TestTheMemoryOfAReadingDoesNotGrowWithTheAnswer(t *testing.T) {
	if testing.Short() {
		t.Skip("streams 160 MiB")
	}
	pr, pw := io.Pipe()
	go func() {
		w := bufio.NewWriterSize(pw, 1<<20)
		w.WriteString(`{"name":"big","time":{"1.0.0":"2020-01-01T00:00:00.000Z","modified":"2026-01-01T00:00:00.000Z"},"versions":{`)
		filler := strings.Repeat("x", 4<<10)
		for i := 0; i < 40000; i++ {
			if i > 0 {
				w.WriteString(",")
			}
			fmt.Fprintf(w, `"1.%d.0":{"description":"%s"}`, i, filler)
		}
		w.WriteString(`}}`)
		w.Flush()
		pw.Close()
	}()
	var peak uint64
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		var m runtime.MemStats
		for {
			select {
			case <-stop:
				return
			default:
			}
			runtime.ReadMemStats(&m)
			if m.HeapInuse > peak {
				peak = m.HeapInuse
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	debug.SetGCPercent(20)
	defer debug.SetGCPercent(100)
	counter := &countingReader{r: pr, limit: maxPackument}
	doc, err := parsePackument(counter, []string{"1.0.0"})
	close(stop)
	<-done
	if err != nil || doc.name != "big" || doc.times["1.0.0"] == "" {
		t.Fatalf("%+v %v", doc, err)
	}
	if counter.n < 150<<20 {
		t.Fatalf("the document was only %d bytes", counter.n)
	}
	if peak > 48<<20 {
		t.Fatalf("a %d MiB answer took %d MiB of heap", counter.n>>20, peak>>20)
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
	if result.OK || !strings.Contains(result.Failure, "limit") {
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
		if result.OK || result.Failure == "" {
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
