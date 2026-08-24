// Package releasereview reviews one distributed release against a spec and
// emits a single report.
//
// The spec schema names all six checks the composite will ever run, but a
// given build implements only a subset. Enabling a check this build cannot run
// is refused at validation rather than reported as a verdict: a stale safe
// fails fast at the spec instead of returning a report whose missing checks a
// consumer would have to notice on its own.
//
// Nothing here fetches anything. Every artifact and every piece of evidence is
// a path the caller already placed on disk, which is what keeps this package
// stdlib-only and its review reproducible.
package releasereview

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

// Check identifiers, in the fixed order they appear in a report.
const (
	CheckChecksum  = "checksum"
	CheckSignature = "signature"
	CheckRelease   = "release"
	CheckVuln      = "vuln"
	CheckTUF       = "tuf"
	CheckExec      = "exec"
)

// checkOrder is the report's fixed check order; the enabled subset keeps it.
var checkOrder = []string{CheckChecksum, CheckSignature, CheckRelease, CheckVuln, CheckTUF, CheckExec}

// implementedChecks lists the checks this build can actually run, in
// checkOrder. Everything else is schema-only.
var implementedChecks = []string{CheckChecksum}

// Spec is a release review request, schema spec_version 1.
type Spec struct {
	SpecVersion int        `json:"spec_version"`
	Subject     Subject    `json:"subject"`
	Artifacts   []Artifact `json:"artifacts"`
	Checks      *Checks    `json:"checks"`
}

// Subject names the release under review. It is echoed into the report so a
// stored report identifies itself without its spec.
type Subject struct {
	Repo    string `json:"repo"`
	Version string `json:"version"`
}

// Artifact is one distributed file. Path is resolved against the process
// working directory; AssetName is the name checks match on, defaulting to the
// path's base.
type Artifact struct {
	Path      string   `json:"path"`
	AssetName string   `json:"asset_name"`
	Evidence  Evidence `json:"evidence"`
}

// Evidence is what the caller collected about one artifact. Every field is
// optional: an artifact may carry none, and what a check makes of that absence
// is the check's decision, not the schema's.
type Evidence struct {
	ChecksumFile string             `json:"checksum_file"`
	Signature    *SignatureEvidence `json:"signature"`
}

// SignatureEvidence is a Sigstore bundle plus the identity policy it must
// satisfy. Validated even though no build verifies bundles yet — the schema is
// contract from day one, so a spec written today stays valid when the check
// lands.
type SignatureEvidence struct {
	Bundle         string `json:"bundle"`
	Identity       string `json:"identity"`
	IdentityRegexp string `json:"identity_regexp"`
	OIDCIssuer     string `json:"oidc_issuer"`
}

// Checks selects which checks run. An omitted block is a disabled check; an
// omitted Checks object is the default spec: checksum only.
type Checks struct {
	Checksum  *CheckConfig `json:"checksum"`
	Signature *CheckConfig `json:"signature"`
	Release   *CheckConfig `json:"release"`
	Vuln      *CheckConfig `json:"vuln"`
	TUF       *TUFCheck    `json:"tuf"`
	Exec      *ExecCheck   `json:"exec"`
}

// CheckConfig is the shape every check block shares. Advisory does not change
// what a check decides, only how much of its verdict reaches the top level.
type CheckConfig struct {
	Enabled  bool `json:"enabled"`
	Advisory bool `json:"advisory"`
}

// TUFCheck configures the TUF bootstrap check.
type TUFCheck struct {
	CheckConfig
	Mirror       string            `json:"mirror"`
	Root         string            `json:"root"`
	RootChecksum string            `json:"root_checksum"`
	Targets      map[string]string `json:"targets"`
}

// ExecCheck configures the networkless execution check.
type ExecCheck struct {
	CheckConfig
	Artifact       string   `json:"artifact"`
	Args           []string `json:"args"`
	TimeoutSeconds int      `json:"timeout_seconds"`
}

// setting is one enabled check, resolved from the spec.
type setting struct {
	ID       string
	Advisory bool
}

// Decode reads a spec and validates it. Unknown fields anywhere in the
// document are a refusal: the spec is the one place a consumer and a safe
// build can disagree about vocabulary, and disagreeing there is cheaper than
// disagreeing about a report.
func Decode(r io.Reader) (Spec, error) {
	var spec Spec
	decoder := json.NewDecoder(r)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&spec); err != nil {
		return Spec{}, fmt.Errorf("read spec: %w", err)
	}
	if err := spec.normalize(); err != nil {
		return Spec{}, err
	}
	return spec, nil
}

// normalize validates the spec and fills the defaults the schema documents.
func (s *Spec) normalize() error {
	if s.SpecVersion != 1 {
		return fmt.Errorf("spec_version must be 1 (got %d)", s.SpecVersion)
	}
	if s.Subject.Repo == "" {
		return fmt.Errorf("subject.repo is required")
	}
	if s.Subject.Version == "" {
		return fmt.Errorf("subject.version is required")
	}
	if len(s.Artifacts) == 0 {
		return fmt.Errorf("artifacts must contain at least one entry")
	}
	for i := range s.Artifacts {
		artifact := &s.Artifacts[i]
		if artifact.Path == "" {
			return fmt.Errorf("artifacts[%d].path is required", i)
		}
		if artifact.AssetName == "" {
			artifact.AssetName = filepath.Base(artifact.Path)
		}
		if err := validateSignature(i, artifact.Evidence.Signature); err != nil {
			return err
		}
	}
	return s.validateChecks()
}

func validateSignature(index int, signature *SignatureEvidence) error {
	if signature == nil {
		return nil
	}
	if signature.Bundle == "" {
		return fmt.Errorf("artifacts[%d].evidence.signature.bundle is required", index)
	}
	if signature.OIDCIssuer == "" {
		return fmt.Errorf("artifacts[%d].evidence.signature.oidc_issuer is required", index)
	}
	switch {
	case signature.Identity != "" && signature.IdentityRegexp != "":
		return fmt.Errorf("artifacts[%d].evidence.signature: identity and identity_regexp are mutually exclusive", index)
	case signature.Identity == "" && signature.IdentityRegexp == "":
		return fmt.Errorf("artifacts[%d].evidence.signature: one of identity or identity_regexp is required", index)
	}
	return nil
}

func (s *Spec) validateChecks() error {
	enabled := s.enabledChecks()

	// Refused in checkOrder so the refusal line is deterministic when a spec
	// enables several checks this build does not implement.
	for _, check := range enabled {
		if !isImplemented(check.ID) {
			return fmt.Errorf("check %q is not implemented by this build (implements: %s) — upgrade safe or disable the check",
				check.ID, strings.Join(implementedChecks, ", "))
		}
	}

	// A review that runs no check decides nothing, and a GO carrying no
	// evidence is exactly the silent pass this gate exists to prevent.
	if len(enabled) == 0 {
		return fmt.Errorf("no checks are enabled — a review with no checks decides nothing")
	}

	for _, check := range enabled {
		if check.ID != CheckChecksum {
			continue
		}
		if !s.anyChecksumEvidence() {
			return fmt.Errorf("check %q is enabled but no artifact carries evidence.checksum_file", CheckChecksum)
		}
	}
	return nil
}

func (s *Spec) anyChecksumEvidence() bool {
	for _, artifact := range s.Artifacts {
		if artifact.Evidence.ChecksumFile != "" {
			return true
		}
	}
	return false
}

// enabledChecks resolves the spec's check selection into checkOrder.
func (s *Spec) enabledChecks() []setting {
	configs := s.checkConfigs()
	enabled := make([]setting, 0, len(checkOrder))
	for _, id := range checkOrder {
		config := configs[id]
		if config == nil || !config.Enabled {
			continue
		}
		enabled = append(enabled, setting{ID: id, Advisory: config.Advisory})
	}
	return enabled
}

func (s *Spec) checkConfigs() map[string]*CheckConfig {
	if s.Checks == nil {
		// The documented default for an omitted checks object: the one check
		// that needs no network and no external tool.
		return map[string]*CheckConfig{CheckChecksum: {Enabled: true}}
	}
	configs := map[string]*CheckConfig{
		CheckChecksum:  s.Checks.Checksum,
		CheckSignature: s.Checks.Signature,
		CheckRelease:   s.Checks.Release,
		CheckVuln:      s.Checks.Vuln,
	}
	if s.Checks.TUF != nil {
		configs[CheckTUF] = &s.Checks.TUF.CheckConfig
	}
	if s.Checks.Exec != nil {
		configs[CheckExec] = &s.Checks.Exec.CheckConfig
	}
	return configs
}

func isImplemented(id string) bool {
	for _, implemented := range implementedChecks {
		if implemented == id {
			return true
		}
	}
	return false
}
