package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/superbiche/safe/internal/releasereview"
)

func writeReviewFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func digestOf(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

// reviewSpec builds a one-artifact checksum spec around real files on disk.
func reviewSpec(t *testing.T, artifact, checksums string) string {
	t.Helper()
	spec := fmt.Sprintf(`{"spec_version": 2,"subject":{"repo":"o/r","version":"v1.2.3"},
	  "artifacts":[{"path":%q,"asset_name":"tool.tar.gz","evidence":{"checksum_file":%q}}],
	  "checks":{"checksum":{"enabled":true}}}`, artifact, checksums)
	return spec
}

func runReview(t *testing.T, spec string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run([]string{"release-review", "--spec", "-"}, strings.NewReader(spec), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// An unsigned artifact whose digest matches still warns: checksum-only
// verification is weaker than the spec's own vocabulary can express as GO.
func TestReleaseReviewWarnsOnChecksumOnlyVerification(t *testing.T) {
	dir := t.TempDir()
	artifact := writeReviewFile(t, dir, "tool.tar.gz", "payload")
	checksums := writeReviewFile(t, dir, "checksums.txt", digestOf("payload")+"  tool.tar.gz\n")

	code, stdout, _ := runReview(t, reviewSpec(t, artifact, checksums))
	if code != 10 {
		t.Fatalf("run() = %d, want 10", code)
	}
	if !strings.Contains(stdout, "checksum_only_verification") {
		t.Fatalf("report does not carry the reason: %s", stdout)
	}
}

// Signature metadata does not lift a checksum-only review: the spec leaves the
// signature check off, so no bundle is opened, and the report is WARN.
func TestReleaseReviewSignedSpecStillWarns(t *testing.T) {
	dir := t.TempDir()
	artifact := writeReviewFile(t, dir, "tool.tar.gz", "payload")
	checksums := writeReviewFile(t, dir, "checksums.txt", digestOf("payload")+"  tool.tar.gz\n")
	spec := fmt.Sprintf(`{"spec_version": 2,"subject":{"repo":"o/r","version":"v1"},
	  "artifacts":[{"path":%q,"asset_name":"tool.tar.gz","evidence":{"checksum_file":%q,
	    "signature":{"bundle":"b","identity":"i","oidc_issuer":"https://example.test"}}}]}`, artifact, checksums)

	code, stdout, stderr := runReview(t, spec)
	if code != 10 {
		t.Fatalf("run() = %d, want 10 (stderr=%q)", code, stderr)
	}

	var report struct {
		SchemaVersion int    `json:"schema_version"`
		Verdict       string `json:"verdict"`
		Subject       struct {
			Repo    string `json:"repo"`
			Version string `json:"version"`
		} `json:"subject"`
		Checks []struct {
			ID       string `json:"id"`
			Advisory bool   `json:"advisory"`
			Verdict  string `json:"verdict"`
			Reasons  []struct {
				Code string `json:"code"`
			} `json:"reasons"`
		} `json:"checks"`
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("report is not JSON: %v (%q)", err, stdout)
	}
	if report.SchemaVersion != 1 || report.Verdict != "WARN" {
		t.Fatalf("unexpected envelope %+v", report)
	}
	if report.Subject.Repo != "o/r" || report.Subject.Version != "v1" {
		t.Fatalf("subject not echoed: %+v", report.Subject)
	}
	if len(report.Checks) != 1 || report.Checks[0].ID != "checksum" ||
		report.Checks[0].Verdict != "WARN" || len(report.Checks[0].Reasons) != 1 ||
		report.Checks[0].Reasons[0].Code != "checksum_only_verification" {
		t.Fatalf("unexpected checks %+v", report.Checks)
	}
}

// failWriter is a stdout that cannot be written to, standing in for a full
// disk or a consumer that closed the pipe.
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("no space left on device") }

// A report that cannot be written is infrastructure breakage (30), not a
// refused spec (3): the review ran and decided.
func TestReleaseReviewWriteFailureIsInfrastructure(t *testing.T) {
	dir := t.TempDir()
	checksums := writeReviewFile(t, dir, "checksums.txt", digestOf("payload")+"  tool.tar.gz\n")
	spec := reviewSpec(t, filepath.Join(dir, "absent.tar.gz"), checksums)

	var stderr bytes.Buffer
	code := run([]string{"release-review", "--spec", "-"}, strings.NewReader(spec), failWriter{}, &stderr)
	if code != 30 {
		t.Fatalf("run() = %d, want 30", code)
	}
	if !strings.Contains(stderr.String(), "audit-infrastructure breakage") {
		t.Fatalf("stderr does not classify the failure: %q", stderr.String())
	}
}

func TestReleaseReviewBLOCK(t *testing.T) {
	dir := t.TempDir()
	artifact := writeReviewFile(t, dir, "tool.tar.gz", "tampered")
	checksums := writeReviewFile(t, dir, "checksums.txt", digestOf("payload")+"  tool.tar.gz\n")

	code, stdout, _ := runReview(t, reviewSpec(t, artifact, checksums))
	if code != 20 {
		t.Fatalf("run() = %d, want 20", code)
	}
	if !strings.Contains(stdout, "digest_mismatch") {
		t.Fatalf("report does not carry the reason: %s", stdout)
	}
}

// A directory where the artifact should be hashes as an I/O failure, which is
// a broken review (exit 30) and not a release finding.
func TestReleaseReviewERROR(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "tool.tar.gz")
	if err := os.Mkdir(artifact, 0o755); err != nil {
		t.Fatal(err)
	}
	checksums := writeReviewFile(t, dir, "checksums.txt", digestOf("payload")+"  tool.tar.gz\n")

	code, stdout, _ := runReview(t, reviewSpec(t, artifact, checksums))
	if code != 30 {
		t.Fatalf("run() = %d, want 30", code)
	}
	if !strings.Contains(stdout, `"verdict":"ERROR"`) {
		t.Fatalf("report is not ERROR: %s", stdout)
	}
}

// safe-audit advertises these two numbers in its capability payload, so what
// this build actually accepts and emits has to be printable rather than
// inferred from a refusal.
func TestReleaseReviewVersions(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"release-review", "--versions"}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("run() = %d, want 0 (stderr: %s)", code, stderr.String())
	}

	var versions map[string]int
	if err := json.Unmarshal(stdout.Bytes(), &versions); err != nil {
		t.Fatalf("output %q is not JSON: %v", stdout.String(), err)
	}
	if versions["spec_version"] != releasereview.SpecVersion ||
		versions["report_schema_version"] != releasereview.ReportSchemaVersion {
		t.Fatalf("printed %v, want the package's own constants", versions)
	}

	// The report the engine emits must actually carry the schema_version it
	// advertises; two constants that agree with each other but not with the
	// output would be a promise nothing keeps.
	dir := t.TempDir()
	artifact := writeReviewFile(t, dir, "tool.tar.gz", "payload")
	checksums := writeReviewFile(t, dir, "checksums.txt", digestOf("payload")+"  tool.tar.gz\n")
	_, report, _ := runReview(t, reviewSpec(t, artifact, checksums))
	var emitted struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal([]byte(report), &emitted); err != nil {
		t.Fatalf("report %q is not JSON: %v", report, err)
	}
	if emitted.SchemaVersion != versions["report_schema_version"] {
		t.Fatalf("report carries schema_version %d, advertised %d", emitted.SchemaVersion, versions["report_schema_version"])
	}
}

func TestReleaseReviewUsage(t *testing.T) {
	cases := [][]string{
		{"release-review"},
		{"release-review", "--spec"},
		{"release-review", "--spec", ""},
		{"release-review", "--specification", "s.json"},
		{"release-review", "--spec", "s.json", "--json"},
		{"release-review", "--versions", "extra"},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run(args, strings.NewReader(""), &stdout, &stderr); got != 2 {
				t.Fatalf("run() = %d, want 2", got)
			}
			if stdout.Len() != 0 || !strings.Contains(stderr.String(), "usage") {
				t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
		})
	}
}

func TestReleaseReviewUnusableSpec(t *testing.T) {
	cases := []struct {
		name    string
		spec    string
		wantSub string
	}{
		{"not JSON", `not json`, "read spec"},
		{"unknown field", `{"spec_version": 2,"subject":{"repo":"o/r","version":"v1"},"artifacts":[{"path":"a"}],"x":1}`, `unknown field "x"`},
		{"release enabled without an asset", `{"spec_version": 2,"subject":{"repo":"o/r","version":"v1"},"artifacts":[{"path":"a"}],"checks":{"release":{"enabled":true}}}`, "checks.release.asset is required"},
		{"no checks enabled", `{"spec_version": 2,"subject":{"repo":"o/r","version":"v1"},"artifacts":[{"path":"a"}],"checks":{}}`, "no checks are enabled"},
		{
			name:    "object appended after the spec",
			spec:    `{"spec_version": 2,"subject":{"repo":"o/r","version":"v1"},"artifacts":[{"path":"a","evidence":{"checksum_file":"c"}}]}{"unknown":true}`,
			wantSub: "exactly one JSON document",
		},
		{
			name:    "spec_version given twice",
			spec:    `{"spec_version":2,"subject":{"repo":"o/r","version":"v1"},"artifacts":[{"path":"a","evidence":{"checksum_file":"c"}}],"spec_version": 2}`,
			wantSub: `"spec_version" is given more than once`,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			code, stdout, stderr := runReview(t, testCase.spec)
			if code != 3 {
				t.Fatalf("run() = %d, want 3", code)
			}
			if stdout != "" {
				t.Fatalf("a refused spec still wrote a report: %q", stdout)
			}
			if !strings.Contains(stderr, testCase.wantSub) {
				t.Fatalf("stderr %q does not contain %q", stderr, testCase.wantSub)
			}
			if lines := strings.Count(strings.TrimSpace(stderr), "\n"); lines != 0 {
				t.Fatalf("refusal is %d lines, want one: %q", lines+1, stderr)
			}
		})
	}
}

func TestReleaseReviewSpecFromFile(t *testing.T) {
	dir := t.TempDir()
	artifact := writeReviewFile(t, dir, "tool.tar.gz", "payload")
	checksums := writeReviewFile(t, dir, "checksums.txt", digestOf("payload")+"  tool.tar.gz\n")
	specPath := writeReviewFile(t, dir, "spec.json", reviewSpec(t, artifact, checksums))

	var stdout, stderr bytes.Buffer
	if got := run([]string{"release-review", "--spec", specPath}, strings.NewReader(""), &stdout, &stderr); got != 10 {
		t.Fatalf("run() = %d, want 10 (stderr=%q)", got, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"schema_version":1`) {
		t.Fatalf("unexpected report %q", stdout.String())
	}
}

// fakeCosignOnPath writes a cosign that verifies one fixed signer and
// materializes a TUF cache from a mirror named by MOCK_COSIGN_BRIDGE_ROOT,
// then points PATH at it alone. Replacing PATH rather than prepending is what
// keeps a real cosign on the developer's machine out of these runs.
func fakeCosignOnPath(t *testing.T) {
	t.Helper()
	bin := t.TempDir()
	for _, helper := range []string{"bash", "cp", "dirname", "jq", "mkdir"} {
		resolved, err := exec.LookPath(helper)
		if err != nil {
			t.Skipf("the fake cosign needs %s on PATH: %v", helper, err)
		}
		if err := os.Symlink(resolved, filepath.Join(bin, helper)); err != nil {
			t.Fatalf("link %s: %v", helper, err)
		}
	}
	script := `#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  verify-blob) printf 'Verified OK\n'; exit 0 ;;
  initialize)
    mirror_path="${MOCK_COSIGN_BRIDGE_ROOT:-}"
    repo_dir="$HOME/.sigstore/root/mock-tuf"
    mkdir -p "$repo_dir/targets"
    cp "$mirror_path/targets.json" "$repo_dir/targets.json"
    while IFS=$'\t' read -r name sha; do
      [[ -n "$name" && -n "$sha" ]] || continue
      cp "$mirror_path/targets/$sha.$name" "$repo_dir/targets/$name"
    done < <(jq -r '.signed.targets | to_entries[] | [.key, .value.hashes.sha256] | @tsv' "$repo_dir/targets.json")
    printf 'Initialized\n'
    ;;
  *) exit 1 ;;
esac
`
	if err := os.WriteFile(filepath.Join(bin, "cosign"), []byte(script), 0o755); err != nil {
		t.Fatalf("write fake cosign: %v", err)
	}
	t.Setenv("PATH", bin)
}

// The first report this CLI can return with exit 0: a digest that matched and a
// signature that verified leaves nothing to warn about.
func TestReleaseReviewVerifiedReleaseExitsZero(t *testing.T) {
	fakeCosignOnPath(t)

	dir := t.TempDir()
	artifact := writeReviewFile(t, dir, "tool.tar.gz", "payload")
	checksums := writeReviewFile(t, dir, "checksums.txt", digestOf("payload")+"  tool.tar.gz\n")
	bundle := writeReviewFile(t, dir, "tool.tar.gz.sigstore", `{"mediaType":"application/vnd.dev.sigstore.bundle+json"}`)

	spec := fmt.Sprintf(`{"spec_version": 2,"subject":{"repo":"o/r","version":"v1"},
	  "artifacts":[{"path":%q,"asset_name":"tool.tar.gz","evidence":{"checksum_file":%q,
	    "signature":{"bundle":%q,"identity":"https://example.test/workflow",
	                 "oidc_issuer":"https://token.actions.githubusercontent.com"}}}],
	  "checks":{"checksum":{"enabled":true},"signature":{"enabled":true}}}`, artifact, checksums, bundle)

	code, stdout, stderr := runReview(t, spec)
	if code != 0 {
		t.Fatalf("run() = %d, want 0 (stderr=%q, report=%s)", code, stderr, stdout)
	}
	if !strings.Contains(stdout, `"verdict":"GO"`) {
		t.Fatalf("report is not GO: %s", stdout)
	}
	if strings.Contains(stdout, "checksum_only_verification") {
		t.Fatalf("a verified signature did not retire the checksum warning: %s", stdout)
	}
}

// A TUF-enabled spec travels the CLI intact, including the two fields
// validation rewrites on the way in (a file:// mirror and a prefixed checksum).
func TestReleaseReviewTUFSpecThroughTheCLI(t *testing.T) {
	fakeCosignOnPath(t)

	mirror := t.TempDir()
	if err := os.Mkdir(filepath.Join(mirror, "targets"), 0o755); err != nil {
		t.Fatal(err)
	}
	const target = "trusted material"
	digest := digestOf(target)
	writeReviewFile(t, filepath.Join(mirror, "targets"), digest+".trusted_root.json", target)
	writeReviewFile(t, mirror, "targets.json",
		fmt.Sprintf(`{"signed":{"targets":{"trusted_root.json":{"hashes":{"sha256":%q},"length":%d}}}}`, digest, len(target)))

	const rootContent = `{"signed":{"_type":"root"}}`
	root := writeReviewFile(t, mirror, "root.json", rootContent)
	local := writeReviewFile(t, t.TempDir(), "trusted_root.json", target)
	t.Setenv("MOCK_COSIGN_BRIDGE_ROOT", mirror)

	spec := fmt.Sprintf(`{"spec_version": 2,"subject":{"repo":"o/r","version":"v1"},
	  "artifacts":[{"path":%q,"asset_name":"root.json"}],
	  "checks":{"tuf":{"enabled":true,"mirror":%q,"root":%q,"root_checksum":%q,
	                   "targets":{"trusted_root.json":%q}}}}`,
		root, "file://"+mirror, root, "sha256:"+strings.ToUpper(digestOf(rootContent)), local)

	code, stdout, stderr := runReview(t, spec)
	if code != 0 {
		t.Fatalf("run() = %d, want 0 (stderr=%q, report=%s)", code, stderr, stdout)
	}
	if !strings.Contains(stdout, `"id":"tuf"`) || !strings.Contains(stdout, `"verdict":"GO"`) {
		t.Fatalf("unexpected report: %s", stdout)
	}
}

func TestReleaseReviewMissingSpecFile(t *testing.T) {
	var stdout, stderr bytes.Buffer
	got := run([]string{"release-review", "--spec", filepath.Join(t.TempDir(), "absent.json")},
		strings.NewReader(""), &stdout, &stderr)
	if got != 3 {
		t.Fatalf("run() = %d, want 3", got)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "read spec") {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}
