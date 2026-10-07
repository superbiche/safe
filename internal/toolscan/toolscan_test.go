package toolscan

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeTools writes stub mise/syft/grype executables driven by files in dir,
// so each test states the scanner outputs it feeds Scan.
type fakeTools struct {
	t   *testing.T
	dir string
}

func newFakeTools(t *testing.T) *fakeTools {
	t.Helper()
	f := &fakeTools{t: t, dir: t.TempDir()}
	f.script("mise", `
case "$2" in
  --installed) cat "$FAKE/installed.json" ;;
  --prunable) cat "$FAKE/prunable.json" ;;
  *) exit 64 ;;
esac`)
	f.script("syft", `
[ "$1" = version ] && { echo '{"version":"1.54.0"}'; exit 0; }
echo "$*" >> "$FAKE/syft.calls"
target=""; out=""
for a in "$@"; do
  case "$a" in
    dir:*) target="${a#dir:}" ;;
    syft-json=*) out="${a#syft-json=}" ;;
  esac
done
[ -f "$target/.fail-syft" ] && { echo "syft exploded" >&2; exit 1; }
cp "$target/sbom.json" "$out"`)
	f.script("grype", `
[ "$1" = version ] && { echo '{"version":"0.120.0"}'; exit 0; }
if [ "$1" = db ] && [ "$2" = update ]; then
  [ -f "$FAKE/db-update-fails" ] && { echo "network down" >&2; exit 1; }
  exit 0
fi
if [ "$1" = db ] && [ "$2" = status ]; then
  cat "$FAKE/db-status.json"; exit 0
fi
echo "GRYPE_DB_AUTO_UPDATE=$GRYPE_DB_AUTO_UPDATE" >> "$FAKE/grype.env"
sbom="${1#sbom:}"
id=$(sed -n 's/.*"id":"\([^"]*\)".*/\1/p' "$sbom")
cat "$FAKE/matches-$id.json"`)
	f.write("db-status.json", `{"built":"2026-10-06T06:32:14Z","valid":true}`)
	f.write("prunable.json", `{}`)
	return f
}

func (f *fakeTools) script(name, body string) {
	f.t.Helper()
	path := filepath.Join(f.dir, name)
	if err := os.WriteFile(path, []byte("#!/usr/bin/env bash\nFAKE="+f.dir+"\n"+body+"\n"), 0o755); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakeTools) write(name, content string) {
	f.t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, name), []byte(content), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

// install creates an install directory whose SBOM has the given artifact
// count and whose grype matches come from matches (a JSON array).
func (f *fakeTools) install(id string, artifacts int, matches string) string {
	f.t.Helper()
	path := filepath.Join(f.dir, "installs", id)
	if err := os.MkdirAll(path, 0o755); err != nil {
		f.t.Fatal(err)
	}
	arts := make([]map[string]string, artifacts)
	for i := range arts {
		arts[i] = map[string]string{"name": "a"}
	}
	raw, _ := json.Marshal(map[string]any{"id": id, "artifacts": arts})
	if err := os.WriteFile(filepath.Join(path, "sbom.json"), raw, 0o644); err != nil {
		f.t.Fatal(err)
	}
	f.write("matches-"+id+".json", `{"matches":`+matches+`}`)
	return path
}

func (f *fakeTools) options() Options {
	return Options{
		Mise:     filepath.Join(f.dir, "mise"),
		Syft:     filepath.Join(f.dir, "syft"),
		Grype:    filepath.Join(f.dir, "grype"),
		Dir:      f.dir,
		CacheDir: filepath.Join(f.dir, "cache"),
		Host:     "testhost",
		Producer: "safe-core test",
		Now:      func() time.Time { return time.Date(2026, 10, 7, 1, 0, 0, 0, time.FixedZone("CEST", 7200)) },
	}
}

func grypeMatch(id, sev, name, version string, fixed ...string) string {
	raw, _ := json.Marshal(map[string]any{
		"vulnerability": map[string]any{"id": id, "severity": sev, "fix": map[string]any{"versions": fixed}},
		"artifact":      map[string]any{"name": name, "version": version},
	})
	return string(raw)
}

func list(items ...string) string { return "[" + strings.Join(items, ",") + "]" }

func installedJSON(entries map[string][][2]string) string {
	m := map[string][]map[string]any{}
	for tool, vs := range entries {
		for _, v := range vs {
			m[tool] = append(m[tool], map[string]any{"version": v[0], "install_path": v[1], "installed": true})
		}
	}
	raw, _ := json.Marshal(m)
	return string(raw)
}

func TestScanKeepsHighAndCriticalPerToolVersion(t *testing.T) {
	f := newFakeTools(t)
	mc := f.install("mc", 3, list(
		grypeMatch("GHSA-crit", "Critical", "golang.org/x/crypto", "v0.40.0", "0.45.0"),
		grypeMatch("GHSA-high", "High", "google.golang.org/grpc", "v1.71.0"),
		grypeMatch("GHSA-high", "High", "google.golang.org/grpc", "v1.71.0"),
		grypeMatch("GHSA-med", "Medium", "golang.org/x/net", "v0.42.0"),
		grypeMatch("CVE-unknown", "Unknown", "x", "1"),
	))
	clean := f.install("task", 2, list(grypeMatch("GHSA-low", "Low", "y", "1")))
	f.write("installed.json", installedJSON(map[string][][2]string{
		"aqua:minio/mc":     {{"RELEASE.2025", mc}},
		"aqua:go-task/task": {{"3.54.0", clean}},
	}))

	r := Scan(context.Background(), f.options())
	if r.Error != nil {
		t.Fatalf("unexpected error: %s", *r.Error)
	}
	if r.Schema != "tool-vulns/1" || r.Host != "testhost" || r.GeneratedAt != "2026-10-06T23:00:00Z" {
		t.Fatalf("header = %q %q %q", r.Schema, r.Host, r.GeneratedAt)
	}
	if len(r.Tools) != 2 {
		t.Fatalf("tools = %+v", r.Tools)
	}
	task, mcTool := r.Tools[0], r.Tools[1]
	if task.Tool != "aqua:go-task/task" || task.Critical != 0 || task.High != 0 || len(task.Advisories) != 0 || task.Components != 2 {
		t.Fatalf("clean tool = %+v", task)
	}
	if mcTool.Critical != 1 || mcTool.High != 1 || len(mcTool.Advisories) != 2 {
		t.Fatalf("mc = %+v", mcTool)
	}
	if a := mcTool.Advisories[0]; a.ID != "GHSA-crit" || a.Component != "golang.org/x/crypto" || len(a.FixedIn) != 1 || a.FixedIn[0] != "0.45.0" {
		t.Fatalf("critical first, with fix: %+v", a)
	}
	if a := mcTool.Advisories[1]; a.FixedIn == nil || len(a.FixedIn) != 0 {
		t.Fatalf("no fix publishes [], not null: %+v", a)
	}
	env, _ := os.ReadFile(filepath.Join(f.dir, "grype.env"))
	if strings.Contains(string(env), "=true") || !strings.Contains(string(env), "GRYPE_DB_AUTO_UPDATE=false") {
		t.Fatalf("per-tool matches must not refresh the database: %q", env)
	}
}

func TestScanExcludesPrunableVersions(t *testing.T) {
	f := newFakeTools(t)
	cur := f.install("node-24", 1, "[]")
	old := f.install("node-16", 1, list(grypeMatch("CVE-old", "Critical", "node", "16.13.0")))
	f.write("installed.json", installedJSON(map[string][][2]string{"node": {{"24.18.1", cur}, {"16.13.0", old}}}))
	f.write("prunable.json", installedJSON(map[string][][2]string{"node": {{"16.13.0", old}}}))

	r := Scan(context.Background(), f.options())
	if r.Error != nil || r.Scope == nil || r.Scope.InScope != 1 || r.Scope.Prunable != 1 {
		t.Fatalf("scope = %+v error = %v", r.Scope, r.Error)
	}
	if len(r.Tools) != 1 || r.Tools[0].Version != "24.18.1" {
		t.Fatalf("tools = %+v", r.Tools)
	}
}

func TestScanListsToolsWithNoComponentsAsUnscanned(t *testing.T) {
	f := newFakeTools(t)
	bw := f.install("bw", 0, "[]")
	f.write("installed.json", installedJSON(map[string][][2]string{"aqua:bitwarden/clients": {{"2026.9.1", bw}}}))

	r := Scan(context.Background(), f.options())
	if len(r.Tools) != 0 || len(r.Unscanned) != 1 || r.Unscanned[0] != "aqua:bitwarden/clients@2026.9.1" {
		t.Fatalf("tools = %+v unscanned = %+v", r.Tools, r.Unscanned)
	}
}

func TestScanCachesSBOMsAndDropsUnusedOnes(t *testing.T) {
	f := newFakeTools(t)
	a := f.install("a", 1, "[]")
	f.write("installed.json", installedJSON(map[string][][2]string{"a": {{"1", a}}}))
	o := f.options()
	stale := filepath.Join(o.CacheDir, "deadbeef.syft.json")
	if err := os.MkdirAll(o.CacheDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stale, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	Scan(context.Background(), o)
	Scan(context.Background(), o)
	calls, _ := os.ReadFile(filepath.Join(f.dir, "syft.calls"))
	if n := strings.Count(string(calls), "\n"); n != 1 {
		t.Fatalf("syft ran %d times for one unchanged directory", n)
	}
	if !strings.Contains(string(calls), "+javascript-package-cataloger") {
		t.Fatalf("syft must catalog installed npm packages: %q", calls)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("an SBOM no install references must be removed")
	}

	// A forced reinstall changes the directory's modification time.
	later := time.Now().Add(time.Hour)
	if err := os.Chtimes(a, later, later); err != nil {
		t.Fatal(err)
	}
	Scan(context.Background(), o)
	calls, _ = os.ReadFile(filepath.Join(f.dir, "syft.calls"))
	if n := strings.Count(string(calls), "\n"); n != 2 {
		t.Fatalf("a reinstalled directory must be inventoried again, syft ran %d times", n)
	}
}

func TestScanRecordsPerToolFailuresWithoutHidingOthers(t *testing.T) {
	f := newFakeTools(t)
	bad := f.install("bad", 1, "[]")
	if err := os.WriteFile(filepath.Join(bad, ".fail-syft"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	good := f.install("good", 1, list(grypeMatch("GHSA-x", "High", "c", "1")))
	f.write("installed.json", installedJSON(map[string][][2]string{"bad": {{"1", bad}}, "good": {{"1", good}}}))

	r := Scan(context.Background(), f.options())
	if r.Error != nil {
		t.Fatalf("one tool failing is not a run failure: %s", *r.Error)
	}
	if len(r.Errors) != 1 || r.Errors[0].Tool != "bad" || r.Errors[0].Stage != "sbom" || !strings.Contains(r.Errors[0].Message, "syft exploded") {
		t.Fatalf("errors = %+v", r.Errors)
	}
	if len(r.Tools) != 1 || r.Tools[0].Tool != "good" || r.Tools[0].High != 1 {
		t.Fatalf("tools = %+v", r.Tools)
	}
}

func TestScanWhereEveryVersionFailsIsAnError(t *testing.T) {
	for _, stage := range []string{"sbom", "match"} {
		t.Run(stage, func(t *testing.T) {
			f := newFakeTools(t)
			a := f.install("a", 1, "[]")
			b := f.install("b", 1, "[]")
			if stage == "sbom" {
				for _, dir := range []string{a, b} {
					if err := os.WriteFile(filepath.Join(dir, ".fail-syft"), nil, 0o644); err != nil {
						t.Fatal(err)
					}
				}
			} else {
				f.write("matches-a.json", "not json")
				f.write("matches-b.json", "not json")
			}
			f.write("installed.json", installedJSON(map[string][][2]string{"a": {{"1", a}}, "b": {{"1", b}}}))

			r := Scan(context.Background(), f.options())
			if r.Error == nil || !strings.Contains(*r.Error, "no tool version could be scanned (2 failed; first: "+stage) {
				t.Fatalf("error = %v", r.Error)
			}
			if r.Tools != nil || r.Unscanned != nil || len(r.Errors) != 2 {
				t.Fatalf("findings must be unknown and failures kept: %+v", r)
			}
		})
	}
}

func TestScanWithOnlyUnscannedVersionsIsNotAnError(t *testing.T) {
	f := newFakeTools(t)
	bw := f.install("bw", 0, "[]")
	f.write("installed.json", installedJSON(map[string][][2]string{"bw": {{"1", bw}}}))

	r := Scan(context.Background(), f.options())
	if r.Error != nil || len(r.Unscanned) != 1 {
		t.Fatalf("report = %+v", r)
	}
}

func TestScanFailedUpdateWithUsableDatabaseStillMatches(t *testing.T) {
	f := newFakeTools(t)
	a := f.install("a", 1, list(grypeMatch("GHSA-x", "High", "c", "1")))
	f.write("installed.json", installedJSON(map[string][][2]string{"a": {{"1", a}}}))
	f.write("db-update-fails", "")

	r := Scan(context.Background(), f.options())
	if r.Error != nil || r.DB.UpdateError == nil || !strings.Contains(*r.DB.UpdateError, "network down") {
		t.Fatalf("db = %+v error = %v", r.DB, r.Error)
	}
	if r.DB.Usable == nil || !*r.DB.Usable || len(r.Tools) != 1 {
		t.Fatalf("a usable cached database still matches: %+v", r)
	}
}

func TestScanUnusableDatabaseIsAnErrorNotACleanReport(t *testing.T) {
	f := newFakeTools(t)
	a := f.install("a", 1, "[]")
	f.write("installed.json", installedJSON(map[string][][2]string{"a": {{"1", a}}}))
	f.write("db-update-fails", "")
	f.write("db-status.json", `{"built":"2026-09-01T00:00:00Z","valid":false}`)

	r := Scan(context.Background(), f.options())
	if r.Error == nil || r.Tools != nil || r.Unscanned != nil {
		t.Fatalf("unusable database must leave findings unknown: %+v", r)
	}
	raw, _ := json.Marshal(r)
	if !strings.Contains(string(raw), `"tools":null`) || !strings.Contains(string(raw), `"usable":false`) {
		t.Fatalf("published shape = %s", raw)
	}
}

func TestScanMissingScannerIsAnError(t *testing.T) {
	f := newFakeTools(t)
	f.write("installed.json", `{}`)
	o := f.options()
	o.Grype = ""

	r := Scan(context.Background(), o)
	if r.Error == nil || !strings.Contains(*r.Error, "grype missing") || r.Scanners.Grype != nil || r.DB.Usable != nil {
		t.Fatalf("report = %+v", r)
	}
}

func TestScanMiseFailureIsAnError(t *testing.T) {
	f := newFakeTools(t)
	r := Scan(context.Background(), f.options()) // no installed.json: mise fails
	if r.Error == nil || r.Scope != nil || r.Tools != nil {
		t.Fatalf("report = %+v", r)
	}
}

func TestPublishIsAtomicAndCompleteJSON(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "tool-vulns", "testhost.json")
	r := Report{Schema: Schema, Host: "testhost", Errors: []ToolErr{}}
	if err := Publish(r, dest); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"schema", "generated_at", "host", "producer", "severity_floor", "scanners", "db", "scope", "tools", "unscanned", "errors", "error"} {
		if _, ok := doc[key]; !ok {
			t.Errorf("published key %q missing", key)
		}
	}
	entries, _ := os.ReadDir(filepath.Dir(dest))
	if len(entries) != 1 {
		t.Fatalf("temporary file left behind: %v", entries)
	}
}
