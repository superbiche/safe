package releasereview

import (
	"path/filepath"
	"testing"
	"time"
)

// signatureSpec builds a one-artifact spec with both checks enabled, which is
// the shape the suppression cases need.
func signatureSpec(artifact, bundle, checksums, identity, issuer string) Spec {
	return Spec{
		SpecVersion: 1,
		Subject:     Subject{Repo: "o/r", Version: "v1.2.3"},
		Artifacts: []Artifact{{
			Path:      artifact,
			AssetName: "tool.tar.gz",
			Evidence: Evidence{
				ChecksumFile: checksums,
				Signature:    &SignatureEvidence{Bundle: bundle, Identity: identity, OIDCIssuer: issuer},
			},
		}},
		Checks: &Checks{
			Checksum:  &CheckConfig{Enabled: true},
			Signature: &CheckConfig{Enabled: true},
		},
	}
}

// signatureFixture writes an artifact, a matching checksum file and a valid
// JSON bundle, and puts the fake cosign on PATH.
func signatureFixture(t *testing.T) (artifact, bundle, checksums string) {
	t.Helper()
	withFakeTools(t, "cosign")
	t.Setenv("MOCK_COSIGN_IDENTITY", mockIdentity)
	t.Setenv("MOCK_COSIGN_ISSUER", mockIssuer)

	dir := t.TempDir()
	artifact = writeFile(t, dir, "tool.tar.gz", "payload")
	bundle = writeFile(t, dir, "tool.tar.gz.sigstore", `{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.3"}`)
	checksums = writeFile(t, dir, "checksums.txt", sha256Of("payload")+"  tool.tar.gz\n")
	return artifact, bundle, checksums
}

// The flagship case for this slice: a signature the policy accepts retires
// checksum_only_verification and makes a top-level GO reachable for the first
// time. Everything else about the composite is unchanged, which is why the
// whole report is asserted rather than only the signature check.
func TestVerifiedSignatureSuppressesTheChecksumWarningAndReachesGO(t *testing.T) {
	artifact, bundle, checksums := signatureFixture(t)

	report := Review(signatureSpec(artifact, bundle, checksums, mockIdentity, mockIssuer))
	if report.Verdict != GO {
		t.Fatalf("top-level verdict %s, want GO: %+v", report.Verdict, report.Checks)
	}
	if len(report.Checks) != 2 {
		t.Fatalf("report carries %d checks, want checksum and signature", len(report.Checks))
	}
	if report.Checks[0].ID != CheckChecksum || len(report.Checks[0].Reasons) != 0 {
		t.Fatalf("checksum check is not clean: %+v", report.Checks[0])
	}
	if report.Checks[1].ID != CheckSignature || len(report.Checks[1].Reasons) != 0 {
		t.Fatalf("signature check is not clean: %+v", report.Checks[1])
	}
}

// Advisory caps what a check contributes to the top level, not what it
// observed. A verification that happened is verification, so the checksum
// warning stays retired.
func TestAdvisorySignatureThatVerifiedStillSuppresses(t *testing.T) {
	artifact, bundle, checksums := signatureFixture(t)

	spec := signatureSpec(artifact, bundle, checksums, mockIdentity, mockIssuer)
	spec.Checks.Signature.Advisory = true

	report := Review(spec)
	if report.Verdict != GO {
		t.Fatalf("top-level verdict %s, want GO: %+v", report.Verdict, report.Checks)
	}
	for _, check := range report.Checks {
		if len(check.Reasons) != 0 {
			t.Fatalf("check %s carries %v", check.ID, codes(check))
		}
	}
}

// An advisory signature check that failed caps at WARN, and because nothing
// vouched for the artifact the checksum warning is back.
func TestAdvisorySignatureThatFailedCapsAtWarn(t *testing.T) {
	artifact, bundle, checksums := signatureFixture(t)
	t.Setenv("MOCK_COSIGN_BUNDLE_MODE", "fail")

	spec := signatureSpec(artifact, bundle, checksums, mockIdentity, mockIssuer)
	spec.Checks.Signature.Advisory = true

	report := Review(spec)
	if report.Verdict != WARN {
		t.Fatalf("top-level verdict %s, want WARN (advisory cap)", report.Verdict)
	}
	if report.Checks[1].Verdict != BLOCK {
		t.Fatalf("the signature check's own verdict is %s, want an uncapped BLOCK", report.Checks[1].Verdict)
	}
	if !hasReason(report.Checks[0], "checksum_only_verification", "tool.tar.gz") {
		t.Fatalf("checksum reasons %v, want the warning back", codes(report.Checks[0]))
	}
}

func TestSignatureIdentityMismatch(t *testing.T) {
	artifact, bundle, checksums := signatureFixture(t)

	result, verified := signature(signatureSpec(artifact, bundle, checksums, "https://example.test/not-the-signer", mockIssuer))
	if result.Verdict != BLOCK {
		t.Fatalf("verdict %s, want BLOCK", result.Verdict)
	}
	if got := codes(result); len(got) != 1 || got[0] != "identity_mismatch" {
		t.Fatalf("reasons %v, want [identity_mismatch]", got)
	}
	if result.Reasons[0].Data["expected_identity"] != "https://example.test/not-the-signer" {
		t.Fatalf("reason data %v carries no expected identity", result.Reasons[0].Data)
	}
	if len(verified) != 0 {
		t.Fatalf("a policy failure still marked %v verified", verified)
	}
}

func TestSignatureIssuerMismatch(t *testing.T) {
	artifact, bundle, checksums := signatureFixture(t)

	result, _ := signature(signatureSpec(artifact, bundle, checksums, mockIdentity, "https://accounts.example/not-the-issuer"))
	if got := codes(result); len(got) != 1 || got[0] != "issuer_mismatch" {
		t.Fatalf("reasons %v, want [issuer_mismatch]", got)
	}
	if result.Reasons[0].Data["expected_oidc_issuer"] != "https://accounts.example/not-the-issuer" {
		t.Fatalf("reason data %v carries no expected issuer", result.Reasons[0].Data)
	}
}

// Both halves of the policy being wrong is two findings, not one: a consumer
// fixing only the identity would still be refused.
func TestSignatureIdentityAndIssuerMismatchAreBothReported(t *testing.T) {
	artifact, bundle, checksums := signatureFixture(t)

	result, _ := signature(signatureSpec(artifact, bundle, checksums, "https://example.test/wrong", "https://accounts.example/wrong"))
	if got := codes(result); len(got) != 2 || got[0] != "identity_mismatch" || got[1] != "issuer_mismatch" {
		t.Fatalf("reasons %v, want both mismatches", got)
	}
}

// The cascade's invariant: an artifact the policy did not verify always leaves
// a reason behind. Without it, a bundle whose halves each verify alone while
// the combined policy does not would report a clean check for an artifact that
// was never verified — top-level GO on a signature-only spec.
func TestUnverifiedArtifactAlwaysCarriesAReason(t *testing.T) {
	artifact, bundle, checksums := signatureFixture(t)

	// The fake accepts either half on its own but rejects them together, which
	// is the shape a multi-signature bundle can produce.
	t.Setenv("MOCK_COSIGN_SPLIT_POLICY", "1")

	spec := signatureSpec(artifact, bundle, checksums, mockIdentity, mockIssuer)
	spec.Checks.Checksum = nil

	result, verified := signature(spec)
	if len(verified) != 0 {
		t.Fatalf("a failed main verification marked %v verified", verified)
	}
	if result.Verdict != BLOCK || len(result.Reasons) == 0 {
		t.Fatalf("verdict %s with reasons %v, want a BLOCK that says why", result.Verdict, codes(result))
	}
	if got := codes(result); len(got) != 2 || got[0] != "identity_mismatch" || got[1] != "issuer_mismatch" {
		t.Fatalf("reasons %v, want both halves named when neither is the sole culprit", got)
	}
}

// A bundle nothing can verify is a signature failure, not a policy mismatch:
// the identity probes would only restate an answer cosign already gave.
func TestSignatureFailureCarriesTheToolsFirstLine(t *testing.T) {
	artifact, bundle, checksums := signatureFixture(t)
	t.Setenv("MOCK_COSIGN_BUNDLE_MODE", "fail")

	result, _ := signature(signatureSpec(artifact, bundle, checksums, mockIdentity, mockIssuer))
	if got := codes(result); len(got) != 1 || got[0] != "signature_failure" {
		t.Fatalf("reasons %v, want [signature_failure]", got)
	}
	if result.Reasons[0].Message != "bundle verification failed" {
		t.Fatalf("message %q does not summarize the tool's output", result.Reasons[0].Message)
	}
}

func TestSignatureBundleProblems(t *testing.T) {
	t.Run("missing bundle blocks", func(t *testing.T) {
		artifact, bundle, checksums := signatureFixture(t)
		spec := signatureSpec(artifact, filepath.Join(filepath.Dir(bundle), "absent.sigstore"), checksums, mockIdentity, mockIssuer)

		result, _ := signature(spec)
		if result.Verdict != BLOCK || codes(result)[0] != "bundle_missing" {
			t.Fatalf("verdict %s reasons %v, want BLOCK/bundle_missing", result.Verdict, codes(result))
		}
	})

	t.Run("a bundle that is not JSON blocks before cosign runs", func(t *testing.T) {
		artifact, _, checksums := signatureFixture(t)
		bundle := writeFile(t, filepath.Dir(artifact), "broken.sigstore", "this is not a bundle")

		result, _ := signature(signatureSpec(artifact, bundle, checksums, mockIdentity, mockIssuer))
		if result.Verdict != BLOCK || codes(result)[0] != "bundle_invalid" {
			t.Fatalf("verdict %s reasons %v, want BLOCK/bundle_invalid", result.Verdict, codes(result))
		}
	})

	t.Run("a directory in the bundle's place is a broken review", func(t *testing.T) {
		artifact, bundle, checksums := signatureFixture(t)
		bundleDir := filepath.Join(filepath.Dir(bundle), "adirectory.sigstore")
		mkdir(t, bundleDir)

		result, _ := signature(signatureSpec(artifact, bundleDir, checksums, mockIdentity, mockIssuer))
		if result.Verdict != ERROR || codes(result)[0] != "bundle_unreadable" {
			t.Fatalf("verdict %s reasons %v, want ERROR/bundle_unreadable", result.Verdict, codes(result))
		}
	})
}

// Collect-all: the artifact and its bundle are independent inputs, and a report
// that stopped at the first missing one would hide the other.
func TestSignatureMissingArtifactAndBundleAreBothReported(t *testing.T) {
	artifact, _, checksums := signatureFixture(t)
	dir := filepath.Dir(artifact)

	spec := signatureSpec(filepath.Join(dir, "absent.tar.gz"), filepath.Join(dir, "absent.sigstore"), checksums, mockIdentity, mockIssuer)

	result, _ := signature(spec)
	if !hasReason(result, "artifact_missing", "tool.tar.gz") || !hasReason(result, "bundle_missing", "tool.tar.gz") {
		t.Fatalf("reasons %v, want both observations", codes(result))
	}
}

// An artifact carrying no bundle warns, and does so without disturbing a
// sibling the policy did vouch for.
func TestSignatureNoEvidenceWarnsBesideAVerifiedSibling(t *testing.T) {
	artifact, bundle, checksums := signatureFixture(t)
	unsigned := writeFile(t, filepath.Dir(artifact), "extra.tar.gz", "extra payload")

	spec := signatureSpec(artifact, bundle, checksums, mockIdentity, mockIssuer)
	spec.Artifacts = append(spec.Artifacts, Artifact{Path: unsigned, AssetName: "extra.tar.gz"})

	result, verified := signature(spec)
	if result.Verdict != WARN {
		t.Fatalf("verdict %s with reasons %v, want WARN", result.Verdict, codes(result))
	}
	if got := codes(result); len(got) != 1 || got[0] != "no_signature_evidence" {
		t.Fatalf("reasons %v, want only the unsigned artifact to warn", got)
	}
	if !verified[0] || verified[1] {
		t.Fatalf("verified set %v, want the signed artifact only", verified)
	}
}

// A missing cosign is the review's own tooling absent, so it is ERROR with a
// recovery — never a BLOCK that would read as a finding about the release. The
// file probes still run, because whether the artifact and bundle are on disk
// does not depend on cosign.
func TestSignatureMissingCosignIsErrorAndStillProbesFiles(t *testing.T) {
	withFakeTools(t)
	dir := t.TempDir()
	artifact := writeFile(t, dir, "tool.tar.gz", "payload")
	checksums := writeFile(t, dir, "checksums.txt", sha256Of("payload")+"  tool.tar.gz\n")

	spec := signatureSpec(artifact, filepath.Join(dir, "absent.sigstore"), checksums, mockIdentity, mockIssuer)

	result, verified := signature(spec)
	if result.Verdict != BLOCK {
		t.Fatalf("verdict %s, want BLOCK (the missing bundle outranks the ERROR)", result.Verdict)
	}
	got := codes(result)
	if len(got) != 2 || got[0] != "tool_missing" || got[1] != "bundle_missing" {
		t.Fatalf("reasons %v, want the tool once and the file probe kept", got)
	}
	if len(verified) != 0 {
		t.Fatalf("nothing can be verified without cosign, got %v", verified)
	}
}

// The tool is missing once for the whole check, not once per artifact:
// repeating it would bury the per-artifact findings underneath it.
func TestSignatureToolMissingIsReportedOnce(t *testing.T) {
	withFakeTools(t)
	dir := t.TempDir()
	first := writeFile(t, dir, "a.tar.gz", "a")
	second := writeFile(t, dir, "b.tar.gz", "b")
	bundle := writeFile(t, dir, "b.sigstore", `{}`)

	spec := Spec{
		SpecVersion: 1,
		Subject:     Subject{Repo: "o/r", Version: "v1"},
		Artifacts: []Artifact{
			{Path: first, AssetName: "a.tar.gz", Evidence: Evidence{Signature: &SignatureEvidence{Bundle: bundle, Identity: "i", OIDCIssuer: "u"}}},
			{Path: second, AssetName: "b.tar.gz", Evidence: Evidence{Signature: &SignatureEvidence{Bundle: bundle, Identity: "i", OIDCIssuer: "u"}}},
		},
	}

	result, _ := signature(spec)
	occurrences := 0
	for _, code := range codes(result) {
		if code == "tool_missing" {
			occurrences++
		}
	}
	if occurrences != 1 {
		t.Fatalf("tool_missing appears %d times in %v, want once", occurrences, codes(result))
	}
}

// The identity policy travels as a regexp when the spec names one, and the
// probe that classifies a failure must use the same form — otherwise a
// regexp-mode policy failure would degrade to a blanket signature failure.
func TestSignatureIdentityRegexpPolicy(t *testing.T) {
	artifact, bundle, checksums := signatureFixture(t)

	spec := signatureSpec(artifact, bundle, checksums, "", mockIssuer)
	spec.Artifacts[0].Evidence.Signature.IdentityRegexp = `^https://github\.com/example/tool/.*@refs/tags/v1\.2\.3$`

	result, verified := signature(spec)
	if result.Verdict != GO || len(result.Reasons) != 0 {
		t.Fatalf("verdict %s reasons %v, want a clean GO", result.Verdict, codes(result))
	}
	if !verified[0] {
		t.Fatal("a matching identity regexp did not verify the artifact")
	}

	spec.Artifacts[0].Evidence.Signature.IdentityRegexp = `^https://github\.com/somebody-else/.*$`
	mismatch, _ := signature(spec)
	if got := codes(mismatch); len(got) != 1 || got[0] != "identity_mismatch" {
		t.Fatalf("reasons %v, want [identity_mismatch]", got)
	}
	if mismatch.Reasons[0].Data["expected_identity_regexp"] == "" {
		t.Fatalf("reason data %v carries no expected identity regexp", mismatch.Reasons[0].Data)
	}
}

// A cosign that runs past its deadline is the review's own tooling failing to
// answer, not the signature failing to verify: it must read ERROR
// (verification_timeout), never a BLOCK that would call a hung network fetch a
// finding about the release.
func TestSignatureVerificationTimeoutIsErrorNotBlock(t *testing.T) {
	artifact, bundle, checksums := signatureFixture(t)
	lowerCosignTimeout(t, 200*time.Millisecond)
	t.Setenv("MOCK_COSIGN_SLEEP", "5")

	result, verified := signature(signatureSpec(artifact, bundle, checksums, mockIdentity, mockIssuer))
	if result.Verdict != ERROR {
		t.Fatalf("verdict %s, want ERROR: %v", result.Verdict, codes(result))
	}
	if got := codes(result); len(got) != 1 || got[0] != "verification_timeout" {
		t.Fatalf("reasons %v, want [verification_timeout]", got)
	}
	if len(verified) != 0 {
		t.Fatalf("a timed-out verification still marked %v verified", verified)
	}
}

// A cosign that exits but leaves a child holding its output pipe is os/exec
// stalling on I/O (exec.ErrWaitDelay), not a signature that failed to verify. It
// must read ERROR (verification_timeout), never a BLOCK — the same infrastructure
// classification a context-deadline timeout gets.
func TestSignaturePipeStallIsErrorNotBlock(t *testing.T) {
	artifact, bundle, checksums := signatureFixture(t)
	lowerCosignKillDelay(t, 200*time.Millisecond)
	t.Setenv("MOCK_COSIGN_ORPHAN", "2")

	result, verified := signature(signatureSpec(artifact, bundle, checksums, mockIdentity, mockIssuer))
	if result.Verdict != ERROR {
		t.Fatalf("verdict %s, want ERROR: %v", result.Verdict, codes(result))
	}
	if got := codes(result); len(got) != 1 || got[0] != "verification_timeout" {
		t.Fatalf("reasons %v, want [verification_timeout]", got)
	}
	if len(verified) != 0 {
		t.Fatalf("a stalled verification still marked %v verified", verified)
	}
}

// When the identity probe times out, the issuer probe is not launched: a tool
// that just failed to answer cannot be re-probed, and the report is already
// ERROR. The split-policy fake makes the main verification fail and the
// permissive re-probe pass, so the cascade reaches the identity probe — the third
// verify-blob — and hanging exactly that one must leave the fourth call unmade.
func TestSignatureIdentityTimeoutDoesNotLaunchIssuerProbe(t *testing.T) {
	artifact, bundle, checksums := signatureFixture(t)
	t.Setenv("MOCK_COSIGN_SPLIT_POLICY", "1")
	callLog := writeFile(t, t.TempDir(), "calls", "")
	t.Setenv("MOCK_COSIGN_CALL_LOG", callLog)
	t.Setenv("MOCK_COSIGN_SLEEP_ON_CALL", "3")
	t.Setenv("MOCK_COSIGN_SLEEP", "5")
	lowerCosignTimeout(t, 200*time.Millisecond)

	result, _ := signature(signatureSpec(artifact, bundle, checksums, mockIdentity, mockIssuer))
	if result.Verdict != ERROR {
		t.Fatalf("verdict %s, want ERROR: %v", result.Verdict, codes(result))
	}
	if got := codes(result); len(got) != 1 || got[0] != "verification_timeout" {
		t.Fatalf("reasons %v, want [verification_timeout]", got)
	}
	if calls := countLines(t, callLog); calls != 3 {
		t.Fatalf("cosign verify-blob was invoked %d times, want 3 — the issuer probe must not launch", calls)
	}
}

func TestFirstLineSummaryIsBounded(t *testing.T) {
	long := ""
	for range 400 {
		long += "x"
	}
	if got := firstLineSummary("\n\n  "+long+"\nsecond line\n", 240); len([]rune(got)) != 240 {
		t.Fatalf("summary is %d runes, want 240", len([]rune(got)))
	}
	if got := firstLineSummary("\n\nfirst\nsecond\n", 240); got != "first" {
		t.Fatalf("summary %q, want the first non-empty line", got)
	}
	if got := firstLineSummary("   \n\n", 240); got != "" {
		t.Fatalf("summary %q, want empty", got)
	}
}
