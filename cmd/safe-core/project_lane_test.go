package main

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func laneIntegrity(seed string) string {
	sum := sha512.Sum512([]byte(seed))
	return "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
}

// laneLock writes a lockfileVersion 3 file with canonical registry entries for
// the name, version pairs; poisoned names get a foreign resolved location.
func laneLock(t *testing.T, dir, file string, poisoned map[string]bool, pairs ...string) string {
	t.Helper()
	packages := map[string]any{"": map[string]any{"name": "root", "version": "1.0.0"}}
	for i := 0; i+1 < len(pairs); i += 2 {
		name, version := pairs[i], pairs[i+1]
		resolved := "https://registry.npmjs.org/" + name + "/-/" + name + "-" + version + ".tgz"
		if poisoned[name] {
			resolved = "https://evil.example/" + name + ".tgz"
		}
		packages["node_modules/"+name] = map[string]any{"version": version, "resolved": resolved, "integrity": laneIntegrity(name + version)}
	}
	data, err := json.Marshal(map[string]any{"lockfileVersion": 3, "packages": packages})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, file)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func laneEvidence(t *testing.T, dir, content string) string {
	t.Helper()
	path := filepath.Join(dir, "evidence.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func runLane(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := run(args, strings.NewReader(""), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

const laneEvidenceDoc = `{"schema_version":1,"policy":{"block_severities":["critical"]},
 "identities":[
  {"name":"p","version":"1.0.0","coverage":"complete","gap":"","advisories":[{"id":"GHSA-a","severity":"critical","malware":false}]},
  {"name":"p","version":"1.1.0","coverage":"complete","gap":"","advisories":[]},
  {"name":"q","version":"1.0.0","coverage":"complete","gap":"","advisories":[{"id":"GHSA-b","severity":"critical","malware":false}]}],
 "blocklist":[]}`

func TestProjectGraphReportsBindability(t *testing.T) {
	dir := t.TempDir()
	lock := laneLock(t, dir, "lock.json", map[string]bool{"bad": true}, "ok", "1.0.0", "bad", "1.0.0")
	code, stdout, stderr := runLane("project-graph", lock)
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	var out struct {
		Graph       struct{ Occurrences []map[string]any }
		Bindability struct {
			Bound   bool
			Unbound []struct{ Path, Reason string }
		}
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Graph.Occurrences) != 2 || out.Bindability.Bound || len(out.Bindability.Unbound) != 1 ||
		out.Bindability.Unbound[0].Path != "node_modules/bad" {
		t.Fatalf("output = %s", stdout)
	}
}

func TestProjectDiffNamesWhatIsIntroduced(t *testing.T) {
	dir := t.TempDir()
	before := laneLock(t, dir, "before.json", nil, "p", "1.0.0")
	after := laneLock(t, dir, "after.json", nil, "p", "1.1.0", "q", "1.0.0")
	code, stdout, stderr := runLane("project-diff", "--baseline", before, after)
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	var out struct {
		Difference struct {
			Introduced []struct{ Name, Version string }
		}
		EvidenceRequest []struct{ Name, Version string } `json:"evidence_request"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Difference.Introduced) != 2 || len(out.EvidenceRequest) != 3 ||
		out.EvidenceRequest[0].Name != "p" || out.EvidenceRequest[0].Version != "1.0.0" ||
		out.EvidenceRequest[2].Name != "q" {
		t.Fatalf("output = %s", stdout)
	}

	code, stdout, _ = runLane("project-diff", "--no-baseline", after)
	if code != 0 || !strings.Contains(stdout, `"version":"1.1.0"`) {
		t.Fatalf("no-baseline: code = %d, stdout = %s", code, stdout)
	}
}

func TestProjectDecideOnTwoLockfilesAndAnEvidenceFile(t *testing.T) {
	dir := t.TempDir()
	before := laneLock(t, dir, "before.json", nil, "p", "1.0.0")
	after := laneLock(t, dir, "after.json", nil, "p", "1.1.0", "q", "1.0.0")
	evidence := laneEvidence(t, dir, laneEvidenceDoc)

	code, stdout, stderr := runLane("project-decide", "--baseline", before, "--evidence", evidence, after)
	if code != 104 {
		t.Fatalf("code = %d, want the outcome's 104, stderr = %s", code, stderr)
	}
	var report struct {
		Advisories struct {
			Fixed      []struct{ Name, ID string }
			Introduced []struct{ Name, ID, Class string }
		}
		Outcome struct {
			Status, Class string
			Exit          int
		}
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Advisories.Fixed) != 1 || report.Advisories.Fixed[0].ID != "GHSA-a" ||
		len(report.Advisories.Introduced) != 1 || report.Advisories.Introduced[0].Name != "q" ||
		report.Outcome.Status != "stopped" || report.Outcome.Class != "blocking_advisory" || report.Outcome.Exit != 104 {
		t.Fatalf("report = %s", stdout)
	}
}

// The exit status of project-decide is its outcome's, and the standing
// acceptances are a second file handed as it is: a clear decision exits 0, an
// outstanding class exits with the class's status, and an acceptance clears a
// class without anything being merged into the evidence document.
func TestProjectDecideExitIsTheOutcomesAndAcceptancesAreSeparate(t *testing.T) {
	dir := t.TempDir()
	clean := laneLock(t, dir, "clean.json", nil, "p", "1.1.0")
	blocked := laneLock(t, dir, "blocked.json", nil, "q", "1.0.0")
	adverse := laneLock(t, dir, "adverse.json", nil, "r", "1.0.0")
	evidence := laneEvidence(t, dir, laneEvidenceDoc)
	adverseEvidence := laneEvidence(t, t.TempDir(), `{"schema_version":1,"policy":{"block_severities":["critical"]},
 "identities":[{"name":"r","version":"1.0.0","coverage":"complete","gap":"","advisories":[{"id":"GHSA-r","severity":"high","malware":false}]}],
 "blocklist":[]}`)
	approval := func(name string) string {
		path := filepath.Join(dir, "acceptances-"+name+".json")
		doc := `{"schema_version":1,"acceptances":[{"kind":"local_exact_approval","name":"` + name + `","version":"1.0.0","host":"registry.npmjs.org","advisories":[],"causes":[]}]}`
		if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	cases := map[string]struct {
		args []string
		code int
	}{
		"clear is 0":                                {[]string{"--no-baseline", "--evidence", evidence, clean}, 0},
		"a blocking advisory is 104":                {[]string{"--no-baseline", "--evidence", evidence, blocked}, 104},
		"an adverse advisory is 100":                {[]string{"--no-baseline", "--evidence", adverseEvidence, adverse}, 100},
		"an acceptance clears the adverse advisory": {[]string{"--no-baseline", "--evidence", adverseEvidence, "--acceptances", approval("r"), adverse}, 0},
		"an acceptance of another artifact is not":  {[]string{"--no-baseline", "--evidence", adverseEvidence, "--acceptances", approval("x"), adverse}, 100},
		"an acceptance clears the blocking one":     {[]string{"--no-baseline", "--evidence", evidence, "--acceptances", approval("q"), blocked}, 0},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := runLane(append([]string{"project-decide"}, tc.args...)...)
			if code != tc.code || !strings.Contains(stdout, `"outcome"`) {
				t.Fatalf("code = %d (want %d), stdout = %s, stderr = %s", code, tc.code, stdout, stderr)
			}
		})
	}
}

func TestProjectDecideRefusesAMalformedAcceptancesOrEvidenceDocument(t *testing.T) {
	dir := t.TempDir()
	lock := laneLock(t, dir, "lock.json", nil, "p", "1.0.0")
	evidence := laneEvidence(t, dir, laneEvidenceDoc)
	write := func(name, doc string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	repeated := write("repeated.json", `{"schema_version":1,"policy":{"block_severities":["critical"]},"identities":[],"blocklist":[],"blocklist":[]}`)
	foreign := write("foreign.json", `{"schema_version":1,"policy":{"block_severities":["critical"]},"identities":[],"blocklist":[],"acceptances":[]}`)
	for name, args := range map[string][]string{
		"an evidence document with a repeated member": {"--evidence", repeated, lock},
		"an evidence document with a foreign member":  {"--evidence", foreign, lock},
		"acceptances with a repeated member":          {"--evidence", evidence, "--acceptances", write("a1.json", `{"schema_version":1,"acceptances":[],"acceptances":[]}`), lock},
		"acceptances with a foreign member":           {"--evidence", evidence, "--acceptances", write("a2.json", `{"schema_version":1,"acceptances":[],"extra":1}`), lock},
		"acceptances that cannot be read":             {"--evidence", evidence, "--acceptances", filepath.Join(dir, "none"), lock},
		"acceptances named twice":                     {"--evidence", evidence, "--acceptances", write("a3.json", `{"schema_version":1,"acceptances":[]}`), "--acceptances", write("a4.json", `{"schema_version":1,"acceptances":[]}`), lock},
	} {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := runLane(append([]string{"project-decide", "--no-baseline"}, args...)...)
			want := 3
			if strings.Contains(name, "twice") {
				want = 2
			}
			if code != want || stdout != "" || stderr == "" {
				t.Fatalf("code = %d (want %d), stdout = %q, stderr = %q", code, want, stdout, stderr)
			}
		})
	}
}

func TestProjectDecideTreatsAnUnreadableBaselineAsMissingEvidence(t *testing.T) {
	dir := t.TempDir()
	after := laneLock(t, dir, "after.json", nil, "p", "1.1.0")
	evidence := laneEvidence(t, dir, laneEvidenceDoc)
	for name, baseline := range map[string]string{"absent": filepath.Join(dir, "absent.json"), "corrupt": func() string {
		path := filepath.Join(dir, "corrupt.json")
		_ = os.WriteFile(path, []byte("{"), 0o600)
		return path
	}()} {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := runLane("project-decide", "--baseline", baseline, "--evidence", evidence, after)
			if code != 102 || !strings.Contains(stdout, `"source":"unreadable"`) || !strings.Contains(stdout, `"class":"missing_evidence"`) {
				t.Fatalf("code = %d, stdout = %s, stderr = %s", code, stdout, stderr)
			}
		})
	}
}

func TestProjectLaneRefusesUnusableInput(t *testing.T) {
	dir := t.TempDir()
	lock := laneLock(t, dir, "lock.json", nil, "p", "1.0.0")
	badEvidence := laneEvidence(t, dir, `{"schema_version":1}`)
	for name, tc := range map[string]struct {
		args []string
		code int
	}{
		"graph without a lockfile":         {[]string{"project-graph"}, 2},
		"graph with a baseline":            {[]string{"project-graph", "--baseline", lock, lock}, 2},
		"diff without a baseline choice":   {[]string{"project-diff", lock}, 2},
		"diff with both baseline choices":  {[]string{"project-diff", "--baseline", lock, "--no-baseline", lock}, 2},
		"decide without evidence":          {[]string{"project-decide", "--no-baseline", lock}, 2},
		"decide with an unknown flag":      {[]string{"project-decide", "--no-baseline", "--evidence", "x", "--quiet", lock}, 2},
		"decide with two targets":          {[]string{"project-decide", "--no-baseline", "--evidence", "x", lock, lock}, 2},
		"decide with incomplete evidence":  {[]string{"project-decide", "--no-baseline", "--evidence", badEvidence, lock}, 3},
		"decide with absent evidence":      {[]string{"project-decide", "--no-baseline", "--evidence", filepath.Join(dir, "none"), lock}, 3},
		"graph on an absent lockfile":      {[]string{"project-graph", filepath.Join(dir, "none")}, 3},
		"diff with an unreadable baseline": {[]string{"project-diff", "--baseline", filepath.Join(dir, "none"), lock}, 3},
		"decide on an unreadable target":   {[]string{"project-decide", "--no-baseline", "--evidence", badEvidence, filepath.Join(dir, "none")}, 3},
	} {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := runLane(tc.args...)
			if code != tc.code || stdout != "" || stderr == "" {
				t.Fatalf("code = %d (want %d), stdout = %q, stderr = %q", code, tc.code, stdout, stderr)
			}
		})
	}
}

func TestRepeatedMembersTellsThreeOutcomesApart(t *testing.T) {
	for name, tc := range map[string]struct {
		document string
		code     int
		stdout   string
	}{
		"clean":                       {`{"results":[{"vulns":[{"id":"A"}]}]}`, 0, "[]\n"},
		"repeated container":          {`{"results":[{"vulns":[{"id":"A"}],"vulns":[]}]}`, 1, `[["results",0,"vulns"]]` + "\n"},
		"repeated scalar":             {`{"id":"A","id":"B"}`, 1, `[["id"]]` + "\n"},
		"repeated in a nested array":  {`{"a":[{"x":1},{"y":2,"y":3}]}`, 1, `[["a",1,"y"]]` + "\n"},
		"case and Case are two":       {`{"case":1,"Case":2}`, 0, "[]\n"},
		"1e400 does not end the walk": {`{"extra":1e400,"results":[{"vulns":[{"id":"TEST-A"}],"vulns":[]},{}]}`, 1, `[["results",0,"vulns"]]` + "\n"},
		"NaN is malformed":            {`{"extra":NaN,"results":[{},{}]}`, 3, ""},
		"not JSON":                    {`{"a":`, 3, ""},
		"two documents":               {`{} {}`, 3, ""},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run([]string{"repeated-members"}, strings.NewReader(tc.document), &stdout, &stderr); got != tc.code || stdout.String() != tc.stdout {
				t.Fatalf("run() = %d, stdout %q; want %d, %q (stderr %q)", got, stdout.String(), tc.code, tc.stdout, stderr.String())
			}
		})
	}
	var stdout, stderr bytes.Buffer
	if got := run([]string{"repeated-members", "x"}, strings.NewReader("{}"), &stdout, &stderr); got != 2 {
		t.Fatalf("run() with an argument = %d, want 2", got)
	}
}

func TestProjectLaneTakesBindingAndPublicEvidenceHostsApart(t *testing.T) {
	dir := t.TempDir()
	packages := map[string]any{"": map[string]any{"name": "root"}, "node_modules/p": map[string]any{
		"version": "1.0.0", "resolved": "https://npm.internal.example/p/-/p-1.0.0.tgz", "integrity": laneIntegrity("p"),
	}}
	data, _ := json.Marshal(map[string]any{"lockfileVersion": 3, "packages": packages})
	lock := filepath.Join(dir, "lock.json")
	if err := os.WriteFile(lock, data, 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runLane("project-diff", "--registry-host", "npm.internal.example", "--no-baseline", lock)
	if code != 0 || !strings.Contains(stdout, `"bound":true`) || !strings.Contains(stdout, `"evidence_request":[]`) {
		t.Fatalf("binding host only: code = %d, stdout = %s, stderr = %s", code, stdout, stderr)
	}
	code, stdout, _ = runLane("project-diff", "--registry-host", "npm.internal.example", "--public-evidence-host", "npm.internal.example", "--no-baseline", lock)
	if code != 0 || !strings.Contains(stdout, `"evidence_request":[{"name":"p","version":"1.0.0"}]`) {
		t.Fatalf("both: code = %d, stdout = %s", code, stdout)
	}
}

// project-graph --project-root judges a link on the path it resolves to; --any-version reads a package
// map whatever version the lockfile declares; without them a version 1 lockfile is unreadable (exit 3).
func TestProjectGraphResolvesLinksAndReadsAnyVersion(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "project")
	if err := os.MkdirAll(filepath.Join(root, "packages"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(base, filepath.Join(root, "packages", "sneaky")); err != nil {
		t.Fatal(err)
	}
	doc := `{"lockfileVersion":1,"packages":{"":{},"node_modules/s":{"resolved":"packages/sneaky","link":true}}}`
	lock := filepath.Join(base, "lock.json")
	if err := os.WriteFile(lock, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := runLane("project-graph", lock); code != 3 {
		t.Fatalf("a version 1 lockfile without --any-version: code = %d, want 3", code)
	}
	code, stdout, stderr := runLane("project-graph", "--any-version", lock)
	if code != 0 || !strings.Contains(stdout, `"bound":true`) {
		t.Fatalf("without a root the target looks inside the project: code = %d, %s %s", code, stdout, stderr)
	}
	code, stdout, stderr = runLane("project-graph", "--any-version", "--project-root", root, lock)
	if code != 0 || !strings.Contains(stdout, `"reason":"link_outside_project"`) || !strings.Contains(stdout, `"bound":false`) {
		t.Fatalf("the physical target leaves the project: code = %d, %s %s", code, stdout, stderr)
	}
}

// project-decide --socket reads the Socket evidence strictly and judges it: a named root that Socket rates adverse is
// policy (100), a document that cannot be read is exit 3 (never "nothing found").
func TestProjectDecideReadsTheSocketEvidence(t *testing.T) {
	dir := t.TempDir()
	after := laneLock(t, dir, "after.json", nil, "p", "1.0.0")
	evidence := laneEvidence(t, dir, `{"schema_version":1,"policy":{"block_severities":["critical"]},"identities":[{"name":"p","version":"1.0.0","coverage":"complete","gap":"","advisories":[]}],"blocklist":[]}`)
	write := func(name, doc string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	adverse := write("adverse.json", `{"schema_version":1,"roots":[{"name":"p","version":"1.0.0","outcome":"adverse","gate_exit":10,"line":"WARN (score=40)","causes":["socket_low_score"],"cached":false}],"cached_blocks":[],"cache_gap":"","untied":[]}`)
	code, stdout, stderr := runLane("project-decide", "--no-baseline", "--evidence", evidence, "--socket", adverse, after)
	if code != 100 || !strings.Contains(stdout, `"class":"socket_root"`) {
		t.Fatalf("adverse: code = %d, stdout = %s, stderr = %s", code, stdout, stderr)
	}
	blocked := write("blocked.json", `{"schema_version":1,"roots":[],"cached_blocks":[{"name":"p","version":"1.0.0","line":"BLOCK (critical supply-chain-risk alert)"}],"cache_gap":"","untied":[]}`)
	code, stdout, _ = runLane("project-decide", "--no-baseline", "--evidence", evidence, "--socket", blocked, after)
	if code != 104 || !strings.Contains(stdout, `"signal":"socket_block"`) {
		t.Fatalf("cached block: code = %d, stdout = %s", code, stdout)
	}
	bad := write("bad.json", `{"schema_version":1,"roots":[],"cached_blocks":[],"cache_gap":"","untied":[],"extra":1}`)
	if code, _, _ = runLane("project-decide", "--no-baseline", "--evidence", evidence, "--socket", bad, after); code != 3 {
		t.Fatalf("a document with an unknown member: code = %d, want 3", code)
	}
	if code, _, _ = runLane("project-decide", "--no-baseline", "--evidence", evidence, "--socket", filepath.Join(dir, "missing.json"), after); code != 3 {
		t.Fatalf("a missing document: code = %d, want 3", code)
	}
}
