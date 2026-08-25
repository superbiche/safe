package releasereview

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The divergence ledger, as in-process goldens.
//
// docs/release-review.md § "Divergences from the bash sub-lanes" records every
// place the composite deliberately behaves differently from the bash
// binary-audit sub-lanes it replaced. While both lanes existed, the parity
// corpus (tests/corpus/run.sh) drove the SAME fixtures through each and diffed
// the two verdicts, so a ledger entry with no corpus case was a claim nothing
// checked. This slice deletes the bash sub-lanes, so there is nothing left to
// diff live — and the corpus with it. These goldens take over its job: one case
// per verdict-affecting ledger entry, driving the COMPOSITE end to end through
// Review() and asserting the top-level verdict the ledger records. A per-check
// unit test elsewhere asserts the same behavior at the check boundary; the
// value here is the AGGREGATE verdict Review() produces, which is the number the
// corpus pinned and no per-check test covers.
//
// Ledger entries 5–9 remove a bash dependency or bound a resource without
// changing a verdict on identical inputs, and entries 14–15 change a request
// property or need a hanging subprocess; none had a corpus pair (the ledger
// says so per entry), so none has a golden here. Their unit coverage lives in
// github_test.go, signature_test.go and exec_test.go.

// reportHasCode reports whether any check in the composite report raised the
// given reason code.
func reportHasCode(report Report, code string) bool {
	for _, check := range report.Checks {
		for _, reason := range check.Reasons {
			if reason.Code == code {
				return true
			}
		}
	}
	return false
}

func ledgerSubject() Subject { return Subject{Repo: "example/tool", Version: "v1.2.3"} }

// Ledger 1 (PARITY in the corpus, kept as a golden because the reason code is
// the divergence): a checksum file with entries but none naming the asset is
// BLOCK by `no_entry_for_artifact`, where the bash lane fell back to the first
// digest and called it a mismatch. Both refuse, so the top-level verdict is the
// same BLOCK — this holds the composite to naming the absent entry, not a
// mislabelled tamper.
func TestLedger01ChecksumNoEntryForArtifactIsBlock(t *testing.T) {
	dir := t.TempDir()
	artifact := writeFile(t, dir, "tool.bin", "release payload")
	checksums := writeFile(t, dir, "checksums.txt",
		sha256Of("other a")+"  other-a.tar.gz\n"+sha256Of("other b")+"  other-b.tar.gz\n")

	spec := Spec{
		SpecVersion: 1,
		Subject:     ledgerSubject(),
		Artifacts: []Artifact{{
			Path: artifact, AssetName: "tool.bin",
			Evidence: Evidence{ChecksumFile: checksums},
		}},
		Checks: &Checks{Checksum: &CheckConfig{Enabled: true}},
	}

	report := Review(spec)
	if report.Verdict != BLOCK {
		t.Fatalf("top-level verdict %s, want BLOCK", report.Verdict)
	}
	if !reportHasCode(report, "no_entry_for_artifact") {
		t.Fatalf("no no_entry_for_artifact reason: %+v", report.Checks)
	}
}

// Ledger 2 (DIVERGENT): cosign is not installed. The composite reports its own
// tooling absent as ERROR, where the bash lane read the missing tool as a
// finding about the release (BLOCK). The checksum check still runs natively and
// only WARNs, so ERROR is the top-level verdict, not a masked BLOCK.
func TestLedger02MissingCosignIsError(t *testing.T) {
	withFakeTools(t) // no cosign on PATH
	dir := t.TempDir()
	artifact := writeFile(t, dir, "tool.tar.gz", "payload")
	bundle := writeFile(t, dir, "tool.tar.gz.sigstore",
		`{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.3"}`)
	checksums := writeFile(t, dir, "checksums.txt", sha256Of("payload")+"  tool.tar.gz\n")

	report := Review(signatureSpec(artifact, bundle, checksums, mockIdentity, mockIssuer))
	if report.Verdict != ERROR {
		t.Fatalf("top-level verdict %s, want ERROR", report.Verdict)
	}
}

// Ledger 3 (DIVERGENT): podman is not installed. The composite reports the
// sandbox review it could not run as ERROR, where the bash lane's WARN
// understated a review that never happened.
func TestLedger03MissingPodmanIsError(t *testing.T) {
	withFakeTools(t) // no podman on PATH
	dir := t.TempDir()
	artifact := writeFile(t, dir, "tool", "#!/bin/sh\nexit 0\n")

	report := Review(execSpec(artifact, nil, 10))
	if report.Verdict != ERROR {
		t.Fatalf("top-level verdict %s, want ERROR", report.Verdict)
	}
}

// Ledger 4 (DIVERGENT): the binary to smoke is not where the spec says. That
// same observation is BLOCK in the checksum check, and one composite must not
// classify one observation two ways — so it is BLOCK by `artifact_missing`,
// where the bash lane read a missing file as WARN.
func TestLedger04MissingExecArtifactIsBlock(t *testing.T) {
	withFakeTools(t, "podman")
	absent := filepath.Join(t.TempDir(), "absent-binary")

	report := Review(execSpec(absent, nil, 10))
	if report.Verdict != BLOCK {
		t.Fatalf("top-level verdict %s, want BLOCK", report.Verdict)
	}
	if !reportHasCode(report, "artifact_missing") {
		t.Fatalf("no artifact_missing reason: %+v", report.Checks)
	}
}

// Ledger 10 (DIVERGENT): GitHub answers 500. The composite reads that as its own
// breakage — ERROR — where the bash lane collapsed every failed request into a
// BLOCK finding about the release. Only a 404 is evidence; everything else is
// the review failing to run.
func TestLedger10GitHubServerErrorIsError(t *testing.T) {
	bodies := cleanRelease()
	newFakeGitHub(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == releasePath {
			writer.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(writer, `{"message":"boom"}`)
			return
		}
		routes(bodies)(writer, request)
	})

	report := Review(releaseSpec())
	if report.Verdict != ERROR {
		t.Fatalf("top-level verdict %s, want ERROR", report.Verdict)
	}
}

// Ledger 11 (DIVERGENT): the release history spans two pages. The composite
// follows the Link rel="next" chain and resolves the predecessor, reaching a
// clean GO, where the bash lane read only the first page and saw no history.
func TestLedger11PaginatedListingIsGo(t *testing.T) {
	bodies := cleanRelease()
	bodies[releasesPath] = releasesBody(releaseEntry(testVersion, daysAgo(30), false, false))
	secondPage := releasesBody(releaseEntry("v1.2.2", daysAgo(60), false, false))

	var serverURL string
	fake := newFakeGitHub(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == releasesPath {
			if request.URL.Query().Get("page") == "2" {
				fmt.Fprint(writer, secondPage)
				return
			}
			writer.Header().Set("Link", fmt.Sprintf(`<%s%s?per_page=100&page=2>; rel="next"`,
				serverURL, releasesPath))
			fmt.Fprint(writer, bodies[releasesPath])
			return
		}
		routes(bodies)(writer, request)
	})
	serverURL = fake.server.URL

	report := Review(releaseSpec())
	if report.Verdict != GO {
		t.Fatalf("top-level verdict %s, want GO: %+v", report.Verdict, report.Checks)
	}
}

// Ledger 12 (DIVERGENT): an advisory affecting the version names a range this
// build cannot read. The composite treats an unreadable range as ambiguous and
// fails closed — BLOCK by `version_mapping_ambiguous` — where the bash lane
// dropped the empty range and reported a clean feed (a fail-open in the one
// check whose whole job is not to miss one).
func TestLedger12BlankAdvisoryRangeIsBlock(t *testing.T) {
	newFakeGitHub(t, routes(advisoriesFeed(advisoryBody("GHSA-blank", "high", ""))))

	report := Review(vulnSpec())
	if report.Verdict != BLOCK {
		t.Fatalf("top-level verdict %s, want BLOCK", report.Verdict)
	}
	if !reportHasCode(report, "version_mapping_ambiguous") {
		t.Fatalf("no version_mapping_ambiguous reason: %+v", report.Checks)
	}
}

// Ledger 13 (DIVERGENT): the exec sandbox runs the binary directly, with no
// shell. The bash lane wrapped it in `sh -c 'exec /artifact/<name> "$@"' sh`,
// splicing a spec-supplied file name into shell program text; an artifact named
// `x|touch PWNED` ran the second half of its own name. This one is asserted on
// the invocation, not the verdict — both lanes ran the binary and came back GO,
// so a verdict comparison would prove nothing. What matters is that the hostile
// name reaches podman as one argv entry with no shell anywhere.
func TestLedger13ExecSandboxDropsTheShell(t *testing.T) {
	withFakeTools(t, "podman")
	dir := t.TempDir()
	const hostile = "x|touch PWNED"
	artifact := writeFile(t, dir, hostile, "#!/bin/sh\nexit 0\n")
	if err := os.Chmod(artifact, 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	argLog := filepath.Join(dir, "podman-args.log")
	t.Setenv("MOCK_PODMAN_LOG", argLog)

	Review(execSpec(artifact, nil, 10))

	logged, err := os.ReadFile(argLog)
	if err != nil {
		t.Fatalf("podman was never invoked: %v", err)
	}
	args := strings.Split(strings.TrimRight(string(logged), "\n"), "\n")

	sawArtifact := false
	for _, arg := range args {
		if arg == "/artifact/"+hostile {
			sawArtifact = true
		}
		if arg == "-c" || arg == "sh" {
			t.Fatalf("a shell reached the sandbox invocation: %q", args)
		}
	}
	if !sawArtifact {
		t.Fatalf("the hostile name was not passed as one argv entry: %q", args)
	}
	for _, marker := range []string{filepath.Join(dir, "PWNED"), "PWNED"} {
		if _, err := os.Stat(marker); err == nil {
			t.Fatalf("the artifact name executed as a command (%s exists)", marker)
		}
	}
}
