package releasereview

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"strings"
)

// signature verifies each artifact's Sigstore bundle with cosign and reports
// which artifacts a signer policy actually vouched for.
//
// The returned map holds the indices cosign verified, keyed by index because a
// spec may repeat an asset name or a path. It is what lets the checksum check
// tell a verified digest from a merely matched one.
//
// Severity here follows the composite's model rather than the bash lane's: a
// missing cosign is ERROR, because audit infrastructure that is not installed
// must read as breakage with a recovery path and never as a finding about the
// release. Missing or malformed release material stays BLOCK.
func signature(spec Spec) (CheckResult, map[int]bool) {
	result := CheckResult{Reasons: []Reason{}}
	verified := make(map[int]bool)

	_, cosignErr := exec.LookPath("cosign")
	cosignAvailable := cosignErr == nil

	// Reported once for the check rather than once per artifact: the tool is
	// missing for the whole run, and repeating it per artifact would bury the
	// per-artifact findings that are still collected below.
	if !cosignAvailable && spec.anySignatureEvidence() {
		result.add(ERROR, "tool_missing",
			"cosign is required to verify signatures — install cosign", nil)
	}

	for index, artifact := range spec.Artifacts {
		name := artifact.AssetName
		data := map[string]string{"artifact": name}

		// The artifact's own presence is a fact about the release whether or not
		// a bundle accompanies it, so it is probed before the evidence is.
		artifactProbe, artifactErr := probeRegularFile(artifact.Path)
		switch artifactProbe {
		case fileAbsent:
			result.add(BLOCK, "artifact_missing",
				fmt.Sprintf("artifact %s is not at %s", name, artifact.Path), data)
		case fileUnusable:
			result.add(ERROR, "artifact_unreadable",
				fmt.Sprintf("could not read artifact %s", name),
				map[string]string{"artifact": name, "error": artifactErr})
		}

		evidence := artifact.Evidence.Signature
		if evidence == nil {
			result.add(WARN, "no_signature_evidence",
				fmt.Sprintf("no signature evidence was provided for %s", name), data)
			continue
		}

		blobPath, evidenceArgs, evidenceUsable := signatureInputs(&result, artifact, evidence)

		if artifactProbe != fileOK || !evidenceUsable || !cosignAvailable {
			continue
		}
		if verifyArtifact(&result, name, blobPath, evidenceArgs, evidence) {
			verified[index] = true
		}
	}

	return result, verified
}

// signatureInputs probes one artifact's signature evidence and returns what
// cosign will verify: the blob to check and the cosign flags that carry the
// evidence. usable is false when a reason was added and verification must not
// run.
//
// The two modes probe different files. A Sigstore bundle is a JSON document
// that signs the artifact, so it is read and its JSON validity is a fact about
// the evidence, and the blob cosign checks is the artifact. A detached
// certificate and signature are opaque text — cosign, not this package, parses
// them — that sign the artifact's checksum file, so only their presence and
// readability are checked here and the blob is that checksum file. A detached
// blob that is missing is left to the checksum check, which owns that finding;
// verification is skipped rather than reported a second time.
func signatureInputs(result *CheckResult, artifact Artifact, evidence *SignatureEvidence) (blobPath string, evidenceArgs []string, usable bool) {
	name := artifact.AssetName

	if evidence.isDetached() {
		certOK := probeEvidenceFile(result, name, "certificate", evidence.Certificate)
		sigOK := probeEvidenceFile(result, name, "signature", evidence.Signature)
		if !certOK || !sigOK {
			return "", nil, false
		}
		// The detached pair signs the checksum file, so cosign reads it as the
		// blob. It is read here for the same reason the cert and signature are:
		// a stat-only check would let an unreadable blob reach cosign and fail as
		// a BLOCK. A missing or unreadable blob is the checksum check's finding,
		// so no reason is added here — verification is simply skipped.
		if _, readErr := os.ReadFile(artifact.Evidence.ChecksumFile); readErr != nil {
			return "", nil, false
		}
		return artifact.Evidence.ChecksumFile,
			[]string{"--certificate", evidence.Certificate, "--signature", evidence.Signature},
			true
	}

	bundleData := map[string]string{"artifact": name, "bundle": evidence.Bundle}
	bundleProbe, bundleErr := probeRegularFile(evidence.Bundle)
	switch bundleProbe {
	case fileAbsent:
		result.add(BLOCK, "bundle_missing",
			fmt.Sprintf("signature bundle for %s is not at %s", name, evidence.Bundle), bundleData)
		return "", nil, false
	case fileUnusable:
		result.add(ERROR, "bundle_unreadable",
			fmt.Sprintf("could not read the signature bundle for %s", name),
			map[string]string{"artifact": name, "bundle": evidence.Bundle, "error": bundleErr})
		return "", nil, false
	}
	// Parsed natively rather than by shelling out to jq the way the bash lane
	// does: a bundle that is not JSON cannot be a bundle, and the finding is the
	// same without the dependency.
	content, readErr := os.ReadFile(evidence.Bundle)
	switch {
	case readErr != nil:
		result.add(ERROR, "bundle_unreadable",
			fmt.Sprintf("could not read the signature bundle for %s", name),
			map[string]string{"artifact": name, "bundle": evidence.Bundle, "error": readErr.Error()})
		return "", nil, false
	case !json.Valid(content):
		result.add(BLOCK, "bundle_invalid",
			fmt.Sprintf("signature bundle for %s is not valid JSON", name), bundleData)
		return "", nil, false
	}
	return artifact.Path,
		[]string{"--bundle", evidence.Bundle, "--new-bundle-format=true"},
		true
}

// probeEvidenceFile checks that one detached evidence file exists and is
// readable, adding a mode-appropriate reason when it is not. The codes mirror
// the bundle path's split: an absent file is evidence about the release
// (BLOCK), a present file that cannot be read is a broken review (ERROR).
//
// The read is not skippable. os.Stat succeeding does not mean os.ReadFile will:
// a file that stats but cannot be read (permissions, a mid-review I/O error)
// would otherwise reach cosign, whose local-I/O failure the cascade would
// misclassify as a signature_failure BLOCK — reporting review breakage as
// release malice. Reading the file here keeps that an ERROR. The bytes are
// discarded; cosign, not this package, parses the certificate and signature.
func probeEvidenceFile(result *CheckResult, name, kind, path string) bool {
	probe, err := probeRegularFile(path)
	switch probe {
	case fileAbsent:
		result.add(BLOCK, kind+"_missing",
			fmt.Sprintf("signature %s for %s is not at %s", kind, name, path),
			map[string]string{"artifact": name, kind: path})
		return false
	case fileUnusable:
		result.add(ERROR, kind+"_unreadable",
			fmt.Sprintf("could not read the signature %s for %s", kind, name),
			map[string]string{"artifact": name, kind: path, "error": err})
		return false
	}
	if _, readErr := os.ReadFile(path); readErr != nil {
		result.add(ERROR, kind+"_unreadable",
			fmt.Sprintf("could not read the signature %s for %s", kind, name),
			map[string]string{"artifact": name, kind: path, "error": readErr.Error()})
		return false
	}
	return true
}

// verifyArtifact runs the cosign cascade for one artifact and reports whether
// the signer policy was satisfied. blobPath and evidenceArgs come from
// signatureInputs and already encode which mode — bundle or detached — this
// artifact carries; the cascade below is identical for both.
//
// The cascade is a direct port of the bash lane. A failed verification is only
// half an answer: whether the signature is unverifiable at all, or verifiable
// but signed by the wrong identity or the wrong issuer, are three different
// findings with three different follow-ups, so a failure is re-probed with
// wildcards until the report can say which one it was.
//
// Three outcomes, not two, at every probe. cosign that answers "yes" is a
// verification; cosign that answers "no" is a finding to narrow; cosign that
// could not answer — a deadline, or a trust bootstrap that could not reach the
// Sigstore TUF repository or Rekor — is audit-infrastructure breakage that
// stops the cascade with an ERROR, never a BLOCK. The distinction matters most
// on the detached path, whose verification needs a live Rekor lookup a bundle
// carries with it: a Rekor outage there must read as breakage-to-retry, not as
// a release signed by the wrong key.
func verifyArtifact(result *CheckResult, name, blobPath string, evidenceArgs []string, evidence *SignatureEvidence) bool {
	identityPolicy := []string{"--certificate-identity", evidence.Identity}
	identityData := map[string]string{"artifact": name, "expected_identity": evidence.Identity}
	if evidence.Identity == "" {
		identityPolicy = []string{"--certificate-identity-regexp", evidence.IdentityRegexp}
		identityData = map[string]string{"artifact": name, "expected_identity_regexp": evidence.IdentityRegexp}
	}

	reportInfra := func(pr probeOutcome) {
		if pr.timedOut {
			result.add(ERROR, "verification_timeout",
				fmt.Sprintf("cosign did not finish verifying %s within %s", name, cosignSubprocessTimeout),
				map[string]string{"artifact": name})
			return
		}
		result.add(ERROR, "verification_infrastructure_unavailable",
			fmt.Sprintf("cosign could not verify %s because its trust bootstrap (Sigstore TUF or the Rekor transparency log) was unreachable — audit-infrastructure breakage, not a finding about the release; retry once connectivity returns", name),
			map[string]string{"artifact": name, "detail": cosignSummary(pr.output, "cosign trust bootstrap unreachable")})
	}
	run := func(policy []string) probeOutcome {
		output, timedOut, err := cosignVerifyBlob(blobPath, evidenceArgs, policy)
		return probeOutcome{output: output, timedOut: timedOut, outcome: classifyCosign(timedOut, err, output)}
	}

	main := run(append(identityPolicy, "--certificate-oidc-issuer", evidence.OIDCIssuer))
	switch main.outcome {
	case cosignVerified:
		return true
	case cosignInfra:
		reportInfra(main)
		return false
	}

	any := run([]string{"--certificate-identity-regexp", ".*", "--certificate-oidc-issuer-regexp", ".*"})
	switch any.outcome {
	case cosignInfra:
		reportInfra(any)
		return false
	case cosignRejected:
		// Nothing about the signature verifies, so the identity probes below
		// would only restate that.
		result.add(BLOCK, "signature_failure",
			cosignSummary(main.output, fmt.Sprintf("cosign could not verify %s", name)),
			map[string]string{"artifact": name})
		return false
	}

	identity := run(append(identityPolicy, "--certificate-oidc-issuer-regexp", ".*"))
	if identity.outcome == cosignInfra {
		// The issuer probe is not launched: a tool that just failed to answer
		// cannot be re-probed into one, and starting it would only hold the
		// review for another deadline without changing the ERROR.
		reportInfra(identity)
		return false
	}
	issuer := run([]string{"--certificate-identity-regexp", ".*", "--certificate-oidc-issuer", evidence.OIDCIssuer})
	if issuer.outcome == cosignInfra {
		reportInfra(issuer)
		return false
	}

	identityMismatch := func() {
		result.add(BLOCK, "identity_mismatch",
			fmt.Sprintf("the signature for %s is signed by an identity the policy does not allow", name),
			identityData)
	}
	issuerMismatch := func() {
		result.add(BLOCK, "issuer_mismatch",
			fmt.Sprintf("the signature for %s is signed under an OIDC issuer the policy does not allow", name),
			map[string]string{"artifact": name, "expected_oidc_issuer": evidence.OIDCIssuer})
	}

	switch {
	case identity.outcome == cosignRejected && issuer.outcome != cosignRejected:
		identityMismatch()
	case identity.outcome != cosignRejected && issuer.outcome == cosignRejected:
		issuerMismatch()
	default:
		// Both probes failed, or — a shape a multi-signature bundle can produce
		// — each half verified alone while the combined policy did not. Neither
		// narrows the failure to one culprit, so both are reported. The default
		// arm must add something: returning "not verified" with no reason would
		// let a failed verification aggregate as a clean check.
		identityMismatch()
		issuerMismatch()
	}
	return false
}

// cosignVerifyBlob runs one cosign verify-blob probe. evidenceArgs carries the
// mode — `--bundle …` or `--certificate … --signature …` — and blobPath is the
// file that evidence signs.
func cosignVerifyBlob(blobPath string, evidenceArgs, policy []string) (output string, timedOut bool, err error) {
	args := append([]string{"verify-blob"}, evidenceArgs...)
	args = append(args, policy...)
	args = append(args, blobPath)
	return cosignRun(nil, args...)
}

// fileProbe classifies one input path.
//
// The split is the one checksum.go already draws: a path that is absent is
// evidence about the release, while a path that exists and cannot be used is a
// broken review. Reporting a permission problem or a directory in an artifact's
// place as a missing artifact would be a false malice signal.
type fileProbe int

const (
	fileOK fileProbe = iota
	fileAbsent
	fileUnusable
)

func probeRegularFile(path string) (fileProbe, string) {
	info, err := os.Stat(path)
	switch {
	case err == nil && info.Mode().IsRegular():
		return fileOK, ""
	case errors.Is(err, fs.ErrNotExist):
		return fileAbsent, ""
	case err != nil:
		return fileUnusable, err.Error()
	default:
		return fileUnusable, "not a regular file"
	}
}

// firstLineSummary reduces subprocess output to one bounded line. Tool output
// is unbounded and attacker-influenced; a reason message is neither.
func firstLineSummary(text string, max int) string {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" {
			continue
		}
		if runes := []rune(line); len(runes) > max {
			return string(runes[:max])
		}
		return line
	}
	return ""
}

// summaryOr is firstLineSummary with a fallback, so a tool that failed silently
// still produces a message a consumer can act on.
func summaryOr(text, fallback string) string {
	if summary := firstLineSummary(text, 240); summary != "" {
		return summary
	}
	return fallback
}

// cosignSummary reduces cosign's combined output to the line worth reporting.
// Current cosign prints a deprecation notice for the detached
// `--certificate`/`--signature` flags BEFORE the real result, so the naive
// first line of a detached failure is "Flag --certificate has been
// deprecated…", not the failure — misleading text on a verdict-bearing reason.
// The deprecation lines are dropped, an `Error:`-prefixed line is preferred
// when present, and the fallback covers a run that said nothing usable.
func cosignSummary(output, fallback string) string {
	firstUsable := ""
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if trimmed == "" || strings.HasPrefix(trimmed, "Flag --") || strings.Contains(trimmed, "has been deprecated") {
			continue
		}
		if rest := strings.TrimPrefix(trimmed, "Error: "); rest != trimmed {
			return summaryOr(rest, fallback)
		}
		if firstUsable == "" {
			firstUsable = trimmed
		}
	}
	return summaryOr(firstUsable, fallback)
}
