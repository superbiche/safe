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
 "blocklist":[],"acceptances":[]}`

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
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
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
			if code != 0 || !strings.Contains(stdout, `"source":"unreadable"`) || !strings.Contains(stdout, `"class":"missing_evidence"`) {
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
