package releasereview

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func sha256Of(content string) string {
	digest := sha256.Sum256([]byte(content))
	return hex.EncodeToString(digest[:])
}

// checksumSpec builds a one-artifact spec around the given evidence.
func checksumSpec(artifactPath, assetName, checksumFile string, signed bool) Spec {
	evidence := Evidence{ChecksumFile: checksumFile}
	if signed {
		evidence.Signature = &SignatureEvidence{Bundle: "bundle", Identity: "i", OIDCIssuer: "u"}
	}
	return Spec{
		SpecVersion: 1,
		Subject:     Subject{Repo: "o/r", Version: "v1"},
		Artifacts:   []Artifact{{Path: artifactPath, AssetName: assetName, Evidence: evidence}},
	}
}

func codes(result CheckResult) []string {
	out := make([]string, 0, len(result.Reasons))
	for _, reason := range result.Reasons {
		out = append(out, reason.Code)
	}
	return out
}

func TestChecksumEntryFormats(t *testing.T) {
	const payload = "release payload"
	digest := sha256Of(payload)

	cases := []struct {
		name  string
		lines string
	}{
		{"coreutils two spaces", digest + "  tool.tar.gz\n"},
		{"coreutils single space", digest + " tool.tar.gz\n"},
		{"coreutils tab", digest + "\ttool.tar.gz\n"},
		{"coreutils binary marker", digest + " *tool.tar.gz\n"},
		{"coreutils dot-slash name", digest + "  ./tool.tar.gz\n"},
		{"uppercase hex", strings.ToUpper(digest) + "  tool.tar.gz\n"},
		{"bsd", "SHA256 (tool.tar.gz) = " + digest + "\n"},
		{"bsd without a space", "SHA256(tool.tar.gz)=" + digest + "\n"},
		{"bsd dot-slash name", "SHA256 (./tool.tar.gz) = " + digest + "\n"},
		{"bare digest", digest + "\n"},
		{"crlf line endings", digest + "  tool.tar.gz\r\n"},
		{"named entry among others", "deadbeef not a digest\n" + sha256Of("other") + "  other.tar.gz\n" + digest + "  tool.tar.gz\n"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			dir := t.TempDir()
			artifact := writeFile(t, dir, "tool.tar.gz", payload)
			checksums := writeFile(t, dir, "checksums.txt", testCase.lines)

			result := checksum(checksumSpec(artifact, "tool.tar.gz", checksums, true))
			assertVerified(t, result)
		})
	}
}

// assertVerified pins what a matched digest looks like in this build: WARN
// carrying only checksum_only_verification. No implemented check verifies a
// checksum, so a verified artifact cannot reach GO.
func assertVerified(t *testing.T, result CheckResult) {
	t.Helper()
	if result.Verdict != WARN {
		t.Fatalf("verdict %s with reasons %v, want WARN", result.Verdict, codes(result))
	}
	got := codes(result)
	if len(got) != 1 || got[0] != "checksum_only_verification" {
		t.Fatalf("reasons %v, want [checksum_only_verification]", got)
	}
}

// F1: signature metadata is a claim, not a verification. Present or absent, it
// must not change what the checksum check decides in this build.
func TestSignatureMetadataDoesNotSuppressTheWarning(t *testing.T) {
	dir := t.TempDir()
	artifact := writeFile(t, dir, "tool.tar.gz", "payload")
	checksums := writeFile(t, dir, "checksums.txt", sha256Of("payload")+"  tool.tar.gz\n")

	signed := checksum(checksumSpec(artifact, "tool.tar.gz", checksums, true))
	unsigned := checksum(checksumSpec(artifact, "tool.tar.gz", checksums, false))

	assertVerified(t, signed)
	assertVerified(t, unsigned)
}

// A signature block naming a bundle that does not exist must not lift the
// verdict either — nothing in this build ever opens it.
func TestUnverifiableBundlePathDoesNotLiftTheVerdict(t *testing.T) {
	dir := t.TempDir()
	artifact := writeFile(t, dir, "tool.tar.gz", "payload")
	checksums := writeFile(t, dir, "checksums.txt", sha256Of("payload")+"  tool.tar.gz\n")

	spec := checksumSpec(artifact, "tool.tar.gz", checksums, false)
	spec.Artifacts[0].Evidence.Signature = &SignatureEvidence{
		Bundle:     filepath.Join(dir, "definitely-missing.sigstore"),
		Identity:   "unverified",
		OIDCIssuer: "https://invalid.example",
	}

	assertVerified(t, checksum(spec))
}

func TestChecksumNameMatchingIsCaseSensitive(t *testing.T) {
	dir := t.TempDir()
	artifact := writeFile(t, dir, "Tool.tar.gz", "payload")
	// Two entries so the single-entry fallback cannot answer for the asset.
	checksums := writeFile(t, dir, "checksums.txt",
		sha256Of("payload")+"  tool.tar.gz\n"+sha256Of("other")+"  other.tar.gz\n")

	result := checksum(checksumSpec(artifact, "Tool.tar.gz", checksums, true))
	if result.Verdict != BLOCK || codes(result)[0] != "no_entry_for_artifact" {
		t.Fatalf("verdict %s reasons %v, want BLOCK/no_entry_for_artifact", result.Verdict, codes(result))
	}
}

func TestChecksumSingleEntryFallback(t *testing.T) {
	const payload = "payload"

	t.Run("one unnamed digest answers for the artifact", func(t *testing.T) {
		dir := t.TempDir()
		artifact := writeFile(t, dir, "tool.tar.gz", payload)
		checksums := writeFile(t, dir, "checksums.txt", sha256Of(payload)+"\n")

		assertVerified(t, checksum(checksumSpec(artifact, "tool.tar.gz", checksums, true)))
	})

	t.Run("one entry naming a different asset still answers", func(t *testing.T) {
		dir := t.TempDir()
		artifact := writeFile(t, dir, "tool.tar.gz", payload)
		checksums := writeFile(t, dir, "checksums.txt", sha256Of(payload)+"  release.tar.gz\n")

		assertVerified(t, checksum(checksumSpec(artifact, "tool.tar.gz", checksums, true)))
	})

	t.Run("two entries and no name match is no entry, not a mismatch", func(t *testing.T) {
		dir := t.TempDir()
		artifact := writeFile(t, dir, "tool.tar.gz", payload)
		checksums := writeFile(t, dir, "checksums.txt",
			sha256Of(payload)+"  release.tar.gz\n"+sha256Of("other")+"  other.tar.gz\n")

		result := checksum(checksumSpec(artifact, "tool.tar.gz", checksums, true))
		if result.Verdict != BLOCK {
			t.Fatalf("verdict %s, want BLOCK", result.Verdict)
		}
		if got := codes(result); len(got) != 1 || got[0] != "no_entry_for_artifact" {
			t.Fatalf("reasons %v, want [no_entry_for_artifact]", got)
		}
	})

	t.Run("mixed formats both count as candidates", func(t *testing.T) {
		dir := t.TempDir()
		artifact := writeFile(t, dir, "tool.tar.gz", payload)
		checksums := writeFile(t, dir, "checksums.txt",
			sha256Of(payload)+"\nSHA256 (other.tar.gz) = "+sha256Of("other")+"\n")

		result := checksum(checksumSpec(artifact, "tool.tar.gz", checksums, true))
		if got := codes(result); len(got) != 1 || got[0] != "no_entry_for_artifact" {
			t.Fatalf("reasons %v, want [no_entry_for_artifact]", got)
		}
	})
}

func TestChecksumDigestMismatch(t *testing.T) {
	dir := t.TempDir()
	artifact := writeFile(t, dir, "tool.tar.gz", "tampered payload")
	expected := sha256Of("original payload")
	checksums := writeFile(t, dir, "checksums.txt", expected+"  tool.tar.gz\n")

	result := checksum(checksumSpec(artifact, "tool.tar.gz", checksums, true))
	if result.Verdict != BLOCK {
		t.Fatalf("verdict %s, want BLOCK", result.Verdict)
	}
	reason := result.Reasons[0]
	if reason.Code != "digest_mismatch" {
		t.Fatalf("code %s, want digest_mismatch", reason.Code)
	}
	if reason.Data["expected_sha256"] != expected {
		t.Fatalf("expected_sha256 is %q, want %q", reason.Data["expected_sha256"], expected)
	}
	if reason.Data["actual_sha256"] != sha256Of("tampered payload") {
		t.Fatalf("actual_sha256 is %q", reason.Data["actual_sha256"])
	}
	if reason.Data["artifact"] != "tool.tar.gz" {
		t.Fatalf("artifact is %q", reason.Data["artifact"])
	}
}

func TestChecksumMissingArtifact(t *testing.T) {
	dir := t.TempDir()
	checksums := writeFile(t, dir, "checksums.txt", sha256Of("payload")+"  tool.tar.gz\n")

	result := checksum(checksumSpec(filepath.Join(dir, "absent.tar.gz"), "tool.tar.gz", checksums, true))
	if result.Verdict != BLOCK || codes(result)[0] != "artifact_missing" {
		t.Fatalf("verdict %s reasons %v, want BLOCK/artifact_missing", result.Verdict, codes(result))
	}
}

func TestChecksumMissingChecksumFile(t *testing.T) {
	dir := t.TempDir()
	artifact := writeFile(t, dir, "tool.tar.gz", "payload")

	result := checksum(checksumSpec(artifact, "tool.tar.gz", filepath.Join(dir, "absent.txt"), true))
	if result.Verdict != BLOCK {
		t.Fatalf("verdict %s, want BLOCK", result.Verdict)
	}
	reason := result.Reasons[0]
	if reason.Code != "checksum_file_missing" {
		t.Fatalf("code %s, want checksum_file_missing", reason.Code)
	}
	if reason.Data["checksum_file"] == "" {
		t.Fatal("reason data carries no checksum_file")
	}
}

// An existing file that cannot be read is a broken review, not a finding: a
// directory in the artifact's place hashes as an I/O failure, and reporting
// that as BLOCK would read as tampering.
func TestChecksumUnreadableArtifactIsError(t *testing.T) {
	dir := t.TempDir()
	artifactDir := filepath.Join(dir, "tool.tar.gz")
	if err := os.Mkdir(artifactDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	checksums := writeFile(t, dir, "checksums.txt", sha256Of("payload")+"  tool.tar.gz\n")

	result := checksum(checksumSpec(artifactDir, "tool.tar.gz", checksums, true))
	if result.Verdict != ERROR {
		t.Fatalf("verdict %s, want ERROR", result.Verdict)
	}
	reason := result.Reasons[0]
	if reason.Code != "artifact_unreadable" || reason.Data["error"] == "" {
		t.Fatalf("unexpected reason %+v", reason)
	}
}

func TestChecksumUnreadableChecksumFileIsError(t *testing.T) {
	dir := t.TempDir()
	artifact := writeFile(t, dir, "tool.tar.gz", "payload")
	checksumDir := filepath.Join(dir, "checksums.txt")
	if err := os.Mkdir(checksumDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	result := checksum(checksumSpec(artifact, "tool.tar.gz", checksumDir, true))
	if result.Verdict != ERROR {
		t.Fatalf("verdict %s, want ERROR", result.Verdict)
	}
	reason := result.Reasons[0]
	if reason.Code != "artifact_unreadable" || reason.Data["checksum_file"] != checksumDir {
		t.Fatalf("unexpected reason %+v", reason)
	}
}

func TestChecksumNoEvidenceWarns(t *testing.T) {
	dir := t.TempDir()
	verified := writeFile(t, dir, "tool.tar.gz", "payload")
	checksums := writeFile(t, dir, "checksums.txt", sha256Of("payload")+"  tool.tar.gz\n")
	present := writeFile(t, dir, "extra.tar.gz", "extra payload")

	spec := checksumSpec(verified, "tool.tar.gz", checksums, true)
	spec.Artifacts = append(spec.Artifacts, Artifact{Path: present, AssetName: "extra.tar.gz"})

	result := checksum(spec)
	if result.Verdict != WARN {
		t.Fatalf("verdict %s, want WARN", result.Verdict)
	}
	if !hasReason(result, "no_checksum_evidence", "extra.tar.gz") {
		t.Fatalf("reasons %v, want no_checksum_evidence for extra.tar.gz", codes(result))
	}
}

// F2: an artifact carrying no checksum evidence is still probed for presence.
// The old short-circuit reported only the missing evidence and lost the BLOCK.
func TestChecksumMissingArtifactWithoutEvidenceKeepsBothReasons(t *testing.T) {
	dir := t.TempDir()
	verified := writeFile(t, dir, "tool.tar.gz", "payload")
	checksums := writeFile(t, dir, "checksums.txt", sha256Of("payload")+"  tool.tar.gz\n")

	spec := checksumSpec(verified, "tool.tar.gz", checksums, true)
	spec.Artifacts = append(spec.Artifacts, Artifact{
		Path:      filepath.Join(dir, "absent.tar.gz"),
		AssetName: "absent.tar.gz",
	})

	result := checksum(spec)
	if result.Verdict != BLOCK {
		t.Fatalf("verdict %s with reasons %v, want BLOCK", result.Verdict, codes(result))
	}
	if !hasReason(result, "artifact_missing", "absent.tar.gz") ||
		!hasReason(result, "no_checksum_evidence", "absent.tar.gz") ||
		!hasReason(result, "checksum_only_verification", "tool.tar.gz") {
		t.Fatalf("reasons %v, want all three observations", codes(result))
	}
}

// F2: an unreadable artifact and a missing checksum file are independent
// observations, and BLOCK must win the worst-of over the ERROR.
func TestChecksumUnreadableArtifactAndMissingChecksumFile(t *testing.T) {
	dir := t.TempDir()
	artifactDir := filepath.Join(dir, "tool.tar.gz")
	if err := os.Mkdir(artifactDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	result := checksum(checksumSpec(artifactDir, "tool.tar.gz", filepath.Join(dir, "absent.txt"), true))
	if result.Verdict != BLOCK {
		t.Fatalf("verdict %s with reasons %v, want BLOCK", result.Verdict, codes(result))
	}
	if !hasReason(result, "artifact_unreadable", "tool.tar.gz") ||
		!hasReason(result, "checksum_file_missing", "tool.tar.gz") {
		t.Fatalf("reasons %v, want both observations", codes(result))
	}
}

func hasReason(result CheckResult, code, artifact string) bool {
	for _, reason := range result.Reasons {
		if reason.Code == code && reason.Data["artifact"] == artifact {
			return true
		}
	}
	return false
}

func TestChecksumMultipleArtifacts(t *testing.T) {
	dir := t.TempDir()
	good := writeFile(t, dir, "good.tar.gz", "good payload")
	bad := writeFile(t, dir, "bad.tar.gz", "tampered")
	checksums := writeFile(t, dir, "checksums.txt",
		sha256Of("good payload")+"  good.tar.gz\n"+sha256Of("original")+"  bad.tar.gz\n")

	signature := &SignatureEvidence{Bundle: "b", Identity: "i", OIDCIssuer: "u"}
	spec := Spec{
		SpecVersion: 1,
		Subject:     Subject{Repo: "o/r", Version: "v1"},
		Artifacts: []Artifact{
			{Path: good, AssetName: "good.tar.gz", Evidence: Evidence{ChecksumFile: checksums, Signature: signature}},
			{Path: bad, AssetName: "bad.tar.gz", Evidence: Evidence{ChecksumFile: checksums, Signature: signature}},
		},
	}

	result := checksum(spec)
	if result.Verdict != BLOCK {
		t.Fatalf("verdict %s, want BLOCK", result.Verdict)
	}
	if !hasReason(result, "digest_mismatch", "bad.tar.gz") ||
		!hasReason(result, "checksum_only_verification", "good.tar.gz") {
		t.Fatalf("reasons %v, want each artifact's own observation", codes(result))
	}
}
