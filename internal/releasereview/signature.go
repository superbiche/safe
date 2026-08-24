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
			"cosign is required to verify Sigstore bundles — install cosign", nil)
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
				fmt.Sprintf("no signature bundle was provided for %s", name), data)
			continue
		}

		bundleData := map[string]string{"artifact": name, "bundle": evidence.Bundle}
		bundleUsable := false
		bundleProbe, bundleErr := probeRegularFile(evidence.Bundle)
		switch bundleProbe {
		case fileAbsent:
			result.add(BLOCK, "bundle_missing",
				fmt.Sprintf("signature bundle for %s is not at %s", name, evidence.Bundle), bundleData)
		case fileUnusable:
			result.add(ERROR, "bundle_unreadable",
				fmt.Sprintf("could not read the signature bundle for %s", name),
				map[string]string{"artifact": name, "bundle": evidence.Bundle, "error": bundleErr})
		default:
			// Parsed natively rather than by shelling out to jq the way the bash
			// lane does: a bundle that is not JSON cannot be a bundle, and the
			// finding is the same without the dependency.
			content, readErr := os.ReadFile(evidence.Bundle)
			switch {
			case readErr != nil:
				result.add(ERROR, "bundle_unreadable",
					fmt.Sprintf("could not read the signature bundle for %s", name),
					map[string]string{"artifact": name, "bundle": evidence.Bundle, "error": readErr.Error()})
			case !json.Valid(content):
				result.add(BLOCK, "bundle_invalid",
					fmt.Sprintf("signature bundle for %s is not valid JSON", name), bundleData)
			default:
				bundleUsable = true
			}
		}

		if artifactProbe != fileOK || !bundleUsable || !cosignAvailable {
			continue
		}
		if verifyArtifact(&result, artifact, evidence) {
			verified[index] = true
		}
	}

	return result, verified
}

// verifyArtifact runs the cosign cascade for one artifact and reports whether
// the signer policy was satisfied.
//
// The cascade is a direct port of the bash lane. A failed verification is only
// half an answer: whether the bundle is unverifiable at all, or verifiable but
// signed by the wrong identity or the wrong issuer, are three different
// findings with three different follow-ups, so a failure is re-probed with
// wildcards until the report can say which one it was.
func verifyArtifact(result *CheckResult, artifact Artifact, evidence *SignatureEvidence) bool {
	name := artifact.AssetName
	identityPolicy := []string{"--certificate-identity", evidence.Identity}
	identityData := map[string]string{"artifact": name, "expected_identity": evidence.Identity}
	if evidence.Identity == "" {
		identityPolicy = []string{"--certificate-identity-regexp", evidence.IdentityRegexp}
		identityData = map[string]string{"artifact": name, "expected_identity_regexp": evidence.IdentityRegexp}
	}

	mainOutput, mainErr := cosignVerifyBlob(artifact.Path, evidence.Bundle,
		append(identityPolicy, "--certificate-oidc-issuer", evidence.OIDCIssuer))
	if mainErr == nil {
		return true
	}

	if _, anyErr := cosignVerifyBlob(artifact.Path, evidence.Bundle, []string{
		"--certificate-identity-regexp", ".*",
		"--certificate-oidc-issuer-regexp", ".*",
	}); anyErr != nil {
		// Nothing about the bundle verifies, so the identity probes below would
		// only restate that.
		result.add(BLOCK, "signature_failure",
			summaryOr(mainOutput, fmt.Sprintf("cosign could not verify %s against its bundle", name)),
			map[string]string{"artifact": name})
		return false
	}

	_, identityErr := cosignVerifyBlob(artifact.Path, evidence.Bundle,
		append(identityPolicy, "--certificate-oidc-issuer-regexp", ".*"))
	_, issuerErr := cosignVerifyBlob(artifact.Path, evidence.Bundle, []string{
		"--certificate-identity-regexp", ".*",
		"--certificate-oidc-issuer", evidence.OIDCIssuer,
	})

	identityMismatch := func() {
		result.add(BLOCK, "identity_mismatch",
			fmt.Sprintf("the bundle for %s is signed by an identity the policy does not allow", name),
			identityData)
	}
	issuerMismatch := func() {
		result.add(BLOCK, "issuer_mismatch",
			fmt.Sprintf("the bundle for %s is signed under an OIDC issuer the policy does not allow", name),
			map[string]string{"artifact": name, "expected_oidc_issuer": evidence.OIDCIssuer})
	}

	switch {
	case identityErr != nil && issuerErr == nil:
		identityMismatch()
	case identityErr == nil && issuerErr != nil:
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

func cosignVerifyBlob(artifact, bundle string, policy []string) (string, error) {
	args := append([]string{"verify-blob", "--bundle", bundle, "--new-bundle-format=true"}, policy...)
	args = append(args, artifact)
	output, err := exec.Command("cosign", args...).CombinedOutput()
	return string(output), err
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
