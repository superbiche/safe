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

// registryAndOSV serves packuments (by escaped name) and a package-level OSV answer.
func registryAndOSV(t *testing.T, times map[string]map[string]string, osv string) (*httptest.Server, *httptest.Server) {
	t.Helper()
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc, ok := times[strings.TrimPrefix(r.URL.EscapedPath(), "/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"time": doc})
	}))
	advisories := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(osv)) }))
	t.Cleanup(registry.Close)
	t.Cleanup(advisories.Close)
	return registry, advisories
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

func TestProjectReleasesReadsTimesRootsFixesAndGaps(t *testing.T) {
	young := time.Now().UTC().Add(-10 * time.Hour).Format("2006-01-02T15:04:05.000Z")
	old := "2020-01-01T00:00:00.000Z"
	registry, osv := registryAndOSV(t, map[string]map[string]string{
		"fixer":  {"1.0.1": young},
		"old":    {"1.0.0": old},
		"@s%2Fp": {"1.0.0": old},
	}, `{"vulns":[{"id":"GHSA-fix","affected":[{"package":{"name":"fixer","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.1"}]}]}]}]}`)
	dir := t.TempDir()
	request := releasesRequest(t, dir, 3, "exempt", []string{"fixer@1.0.1"}, "fixer@1.0.1", "old@1.0.0", "@s/p@1.0.0", "missing@1.0.0")
	code, stdout, stderr := runLane("project-releases", "--request", request, "--cache-dir", filepath.Join(dir, "cache"), "--registry-base", registry.URL, "--osv-url", osv.URL)
	if code != 0 {
		t.Fatalf("code %d: %s", code, stderr)
	}
	var doc struct {
		Policy     map[string]any
		Identities []struct {
			Name, Version, Status, Published, Gap string
			Root                                  bool
			Remediates                            []string
		}
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for i, id := range doc.Identities {
		got[id.Name+"@"+id.Version] = i
	}
	fixer := doc.Identities[got["fixer@1.0.1"]]
	if fixer.Status != "read" || !fixer.Root || strings.Join(fixer.Remediates, ",") != "GHSA-fix" {
		t.Fatalf("fixer: %+v", fixer)
	}
	if o := doc.Identities[got["old@1.0.0"]]; o.Status != "read" || o.Root || len(o.Remediates) != 0 {
		t.Fatalf("old: %+v", o)
	}
	if s := doc.Identities[got["@s/p@1.0.0"]]; s.Status != "read" {
		t.Fatalf("scoped: %+v", s)
	}
	if m := doc.Identities[got["missing@1.0.0"]]; m.Status != "unreadable" || m.Gap == "" || m.Published != "" {
		t.Fatalf("missing: %+v", m)
	}
	// the document is what project-decide reads: strictly
	if _, err := os.Stat(filepath.Join(dir, "cache")); err != nil {
		t.Fatalf("no cache directory: %v", err)
	}
}

func TestProjectReleasesWithCooldownOffReadsNothing(t *testing.T) {
	dir := t.TempDir()
	request := releasesRequest(t, dir, 0, "exempt", nil, "pk@1.0.0")
	// an address nothing listens on: a read would be a gap, so reading nothing is visible
	code, stdout, stderr := runLane("project-releases", "--request", request, "--cache-dir", filepath.Join(dir, "cache"), "--registry-base", "http://127.0.0.1:1")
	if code != 0 || !strings.Contains(stdout, `"identities":[]`) {
		t.Fatalf("code %d stdout %s stderr %s", code, stdout, stderr)
	}
}

func TestProjectReleasesFailsOnAnUnreadableRequestAndOnUsage(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte(`{"schema_version":1}`), 0o600)
	if code, _, _ := runLane("project-releases", "--request", bad, "--cache-dir", dir); code != 3 {
		t.Fatalf("an unreadable request is exit 3, got %d", code)
	}
	if code, _, _ := runLane("project-releases", "--cache-dir", dir); code != 2 {
		t.Fatalf("usage is exit 2, got %d", code)
	}
	if code, _, _ := runLane("project-releases", "--request", filepath.Join(dir, "nope"), "--cache-dir", dir); code != 3 {
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
	  {"name":"fresh","version":"2.0.0","host":"registry.npmjs.org","root":false,"status":"read","published":"` + now.Add(-2*time.Hour).Format(time.RFC3339) + `","gap":"","remediates":[],"remediation_gap":""}]}`
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
