package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func runWithStdin(stdin string, args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := run(args, strings.NewReader(stdin), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// registryServer serves full metadata documents. Per package: version -> time; the special members "__name" (the
// name the document claims), "__listed" (versions listed with no time of their own, comma separated), "__abbreviated"
// (answer with the abbreviated shape: no time at all) and "__nomodified" shape the document.
func registryServer(t *testing.T, times map[string]map[string]string) *httptest.Server {
	t.Helper()
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.EscapedPath(), "/")
		doc, ok := times[path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		name := strings.ReplaceAll(path, "%2F", "/")
		if other, ok := doc["__name"]; ok {
			name = other
		}
		versions := map[string]any{}
		timeMap := map[string]string{}
		for k, v := range doc {
			if strings.HasPrefix(k, "__") {
				continue
			}
			versions[k] = map[string]any{}
			timeMap[k] = v
		}
		for _, v := range strings.Split(doc["__listed"], ",") {
			if v != "" {
				versions[v] = map[string]any{}
			}
		}
		if _, ok := doc["__nomodified"]; !ok {
			timeMap["modified"] = "2026-11-18T13:37:02.787Z"
		}
		body := map[string]any{"name": name, "time": timeMap, "versions": versions}
		if _, ok := doc["__abbreviated"]; ok {
			body = map[string]any{"name": name, "modified": "2026-11-18T13:37:02.787Z", "versions": versions, "dist-tags": map[string]string{}}
		}
		json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(registry.Close)
	return registry
}

func releasesRequest(t *testing.T, dir string, days int, fix string, roots []string, identities ...string) string {
	t.Helper()
	rootList := []map[string]string{}
	for _, r := range roots {
		at := strings.LastIndex(r, "@")
		rootList = append(rootList, map[string]string{"name": r[:at], "version": r[at+1:]})
	}
	list := []map[string]string{}
	for _, id := range identities {
		at := strings.LastIndex(id, "@")
		list = append(list, map[string]string{"name": id[:at], "version": id[at+1:], "host": "registry.npmjs.org"})
	}
	raw, _ := json.Marshal(map[string]any{
		"schema_version": 1, "policy": map[string]any{"cooldown_days": days, "security_fix": fix}, "roots": rootList, "identities": list,
	})
	path := filepath.Join(dir, "request.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func privateStateDir(t *testing.T) string {
	t.Helper()
	state := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	return state
}

func TestProjectReleasesReadsTimesBoundsAndMissingEvidence(t *testing.T) {
	old := "2020-01-01T00:00:00.123Z"
	registry := registryServer(t, map[string]map[string]string{
		"fixer":    {"1.0.1": time.Now().UTC().Add(-10 * time.Hour).Format("2006-01-02T15:04:05.000Z")},
		"old":      {"1.0.0": old},
		"@s%2Fp":   {"1.0.0": old},
		"listed":   {"__listed": "1.0.0", "9.9.9": old},
		"abbrev":   {"__abbreviated": "1", "1.0.0": old},
		"unlisted": {"9.9.9": old},
		"impostor": {"__name": "someone-else", "1.0.0": old},
	})
	dir := t.TempDir()
	state := privateStateDir(t)
	request := releasesRequest(t, dir, 3, "exempt", []string{"fixer@1.0.1"}, "fixer@1.0.1", "old@1.0.0", "@s/p@1.0.0", "listed@1.0.0", "abbrev@1.0.0", "unlisted@1.0.0", "impostor@1.0.0", "unknown@1.0.0")
	code, stdout, stderr := runLane("project-releases", "--request", request, "--state-dir", state, "--registry-base", registry.URL)
	if code != 0 {
		t.Fatalf("code %d: %s", code, stderr)
	}
	var doc struct {
		Identities []struct {
			Name, Version, Status, Published, Gap string
			Root                                  bool
		}
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for i, id := range doc.Identities {
		got[id.Name+"@"+id.Version] = i
	}
	byName := func(n string) (r struct {
		Name, Version, Status, Published, Gap string
		Root                                  bool
	}) {
		return doc.Identities[got[n]]
	}
	if f := byName("fixer@1.0.1"); f.Status != "read" || !f.Root {
		t.Fatalf("fixer: %+v", f)
	}
	if o := byName("old@1.0.0"); o.Status != "read" || o.Root || o.Published != "2020-01-01T00:00:00.123Z" {
		t.Fatalf("old (the fractional second must survive): %+v", o)
	}
	if s := byName("@s/p@1.0.0"); s.Status != "read" {
		t.Fatalf("scoped: %+v", s)
	}
	if l := byName("listed@1.0.0"); l.Status != "bounded" || l.Published != "2026-11-18T13:37:02.787Z" || l.Gap != "" {
		t.Fatalf("a version listed without a time is bounded by the last-modified time: %+v", l)
	}
	for _, name := range []string{"abbrev@1.0.0", "unlisted@1.0.0", "impostor@1.0.0", "unknown@1.0.0"} {
		if m := byName(name); m.Status != "missing" || m.Gap == "" {
			t.Fatalf("%s must be missing evidence: %+v", name, m)
		}
	}
	if !strings.Contains(byName("impostor@1.0.0").Gap, "another package") {
		t.Fatalf("impostor gap: %q", byName("impostor@1.0.0").Gap)
	}
	// the readings are in the lane's store, in private directories
	if info, err := os.Stat(filepath.Join(state, "publish-times")); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("store: %v %v", info, err)
	}
}

func TestProjectReleasesIgnoresTheCallersTLSAndProxyEnvironment(t *testing.T) {
	registry := registryServer(t, map[string]map[string]string{"old": {"1.0.0": "2020-01-01T00:00:00.000Z"}})
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("http_proxy", "http://127.0.0.1:1")
	t.Setenv("SSL_CERT_FILE", "/nonexistent/ca.pem")
	t.Setenv("SSL_CERT_DIR", "/nonexistent")
	dir := t.TempDir()
	request := releasesRequest(t, dir, 3, "exempt", nil, "old@1.0.0")
	code, stdout, stderr := runLane("project-releases", "--request", request, "--state-dir", privateStateDir(t), "--registry-base", registry.URL)
	if code != 0 || !strings.Contains(stdout, `"status":"read"`) {
		t.Fatalf("code %d stdout %s stderr %s", code, stdout, stderr)
	}
	if os.Getenv("SSL_CERT_FILE") != "" || os.Getenv("SSL_CERT_DIR") != "" {
		t.Fatal("the caller's TLS roots are still named in the environment")
	}
}

func TestProjectReleasesWithCooldownOffReadsNothing(t *testing.T) {
	dir := t.TempDir()
	request := releasesRequest(t, dir, 0, "exempt", nil, "pk@1.0.0")
	// an address nothing listens on: a read would be a gap, so reading nothing is visible
	code, stdout, stderr := runLane("project-releases", "--request", request, "--state-dir", privateStateDir(t), "--registry-base", "http://127.0.0.1:1")
	if code != 0 || !strings.Contains(stdout, `"identities":[]`) {
		t.Fatalf("code %d stdout %s stderr %s", code, stdout, stderr)
	}
}

func TestProjectReleasesFailsOnAnUnreadableRequestAndOnUsage(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte(`{"schema_version":1}`), 0o600)
	if code, _, _ := runLane("project-releases", "--request", bad, "--state-dir", dir); code != 3 {
		t.Fatalf("an unreadable request is exit 3, got %d", code)
	}
	if code, _, _ := runLane("project-releases", "--state-dir", dir); code != 2 {
		t.Fatalf("usage is exit 2, got %d", code)
	}
	if code, _, _ := runLane("project-releases", "--request", filepath.Join(dir, "nope"), "--state-dir", dir); code != 3 {
		t.Fatalf("a missing request is exit 3, got %d", code)
	}
}

func TestProjectRootsKeepsOnlyExactNamedVersions(t *testing.T) {
	code, stdout, _ := runWithStdin("a@1.2.3\x00b@^1.0.0\x00@s/c@2.0.0\x00d\x00e@latest\x00f@npm:g@1.0.0\x00https://x/y.tgz\x00h@1.0.0-rc.1\x00", "project-roots")
	if code != 0 {
		t.Fatal(code)
	}
	var roots []map[string]string
	if err := json.Unmarshal([]byte(stdout), &roots); err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, r := range roots {
		names = append(names, r["name"]+"@"+r["version"])
	}
	if strings.Join(names, " ") != "a@1.2.3 @s/c@2.0.0 h@1.0.0-rc.1" {
		t.Fatalf("roots %v", names)
	}
}

func TestProjectDiffRequestsTheIntroducedPublicIdentitiesForTheCooldown(t *testing.T) {
	dir := t.TempDir()
	baseline := laneLock(t, dir, "base.json", nil, "kept", "1.0.0")
	target := laneLock(t, dir, "target.json", nil, "kept", "1.0.0", "fresh", "2.0.0")
	code, stdout, stderr := runLane("project-diff", "--baseline", baseline, target)
	if code != 0 {
		t.Fatalf("%d %s", code, stderr)
	}
	var out struct {
		CooldownRequest []struct{ Name, Version, Host string } `json:"cooldown_request"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.CooldownRequest) != 1 || out.CooldownRequest[0].Name != "fresh" || out.CooldownRequest[0].Host != "registry.npmjs.org" {
		t.Fatalf("cooldown_request %+v (the baseline's entry must not be asked)", out.CooldownRequest)
	}
}

func TestProjectDecideTakesReleasesAndStopsOnAWait(t *testing.T) {
	dir := t.TempDir()
	target := laneLock(t, dir, "target.json", nil, "fresh", "2.0.0")
	evidence := laneEvidence(t, dir, `{"schema_version":1,"policy":{"block_severities":["critical"]},"identities":[{"name":"fresh","version":"2.0.0","coverage":"complete","gap":"","advisories":[]}],"blocklist":[]}`)
	now := time.Now().UTC()
	releases := filepath.Join(dir, "releases.json")
	doc := `{"schema_version":1,"now":"` + now.Format(time.RFC3339) + `","policy":{"cooldown_days":3,"security_fix":"exempt"},"identities":[
	  {"name":"fresh","version":"2.0.0","host":"registry.npmjs.org","root":false,"status":"read","published":"` + now.Add(-2*time.Hour).Format(time.RFC3339Nano) + `","gap":""}]}`
	os.WriteFile(releases, []byte(doc), 0o600)
	code, stdout, stderr := runLane("project-decide", "--no-baseline", "--evidence", evidence, "--releases", releases, target)
	if code != 100 {
		t.Fatalf("a wait is exit 100, got %d: %s %s", code, stdout, stderr)
	}
	var report struct {
		Outcome  struct{ Class string }
		Cooldown struct {
			Waits []struct{ Name, Version, Installable string }
		}
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatal(err)
	}
	if report.Outcome.Class != "wait" || len(report.Cooldown.Waits) != 1 || report.Cooldown.Waits[0].Installable == "" {
		t.Fatalf("%+v", report)
	}
	// a releases document that cannot be read is exit 3, never a pass
	os.WriteFile(releases, []byte(`{}`), 0o600)
	if code, _, _ := runLane("project-decide", "--no-baseline", "--evidence", evidence, "--releases", releases, target); code != 3 {
		t.Fatalf("unreadable releases: %d", code)
	}
}
