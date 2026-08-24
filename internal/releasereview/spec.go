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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
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
var implementedChecks = []string{CheckChecksum, CheckSignature, CheckTUF, CheckExec}

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

// Decode reads a spec and validates it.
//
// Three shapes are refused before the spec is even looked at, because each one
// means the document does not say one unambiguous thing:
//
//   - unknown fields anywhere — the spec is the one place a consumer and a
//     safe build can disagree about vocabulary, and disagreeing there is
//     cheaper than disagreeing about a report;
//   - anything after the first JSON document — a second object appended to a
//     spec would otherwise be silently ignored;
//   - a repeated member at any depth — JSON decoders keep the last occurrence,
//     so a spec saying both spec_version 2 and spec_version 1 would quietly
//     become whichever the writer put last.
func Decode(r io.Reader) (Spec, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return Spec{}, fmt.Errorf("read spec: %w", err)
	}

	var spec Spec
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&spec); err != nil {
		return Spec{}, fmt.Errorf("read spec: %w", err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Spec{}, fmt.Errorf("read spec: the spec must be exactly one JSON document")
	}
	if err := rejectRepeatedMembers(raw); err != nil {
		return Spec{}, err
	}

	if err := spec.normalize(); err != nil {
		return Spec{}, err
	}
	return spec, nil
}

// rejectRepeatedMembers walks the document's tokens and refuses any object
// that names the same member twice, at any depth.
func rejectRepeatedMembers(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil {
		// Unreachable: the strict decode above already accepted these bytes.
		return nil
	}
	return walkForRepeats(decoder, token, "")
}

func walkForRepeats(decoder *json.Decoder, token json.Token, path string) error {
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}

	switch delim {
	case '{':
		seen := make(map[string]bool)
		for {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil
			}
			if end, ok := keyToken.(json.Delim); ok && end == '}' {
				return nil
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil
			}
			if seen[key] {
				return fmt.Errorf("read spec: %q is given more than once", path+key)
			}
			seen[key] = true

			valueToken, err := decoder.Token()
			if err != nil {
				return nil
			}
			if err := walkForRepeats(decoder, valueToken, path+key+"."); err != nil {
				return err
			}
		}
	case '[':
		for {
			elementToken, err := decoder.Token()
			if err != nil {
				return nil
			}
			if end, ok := elementToken.(json.Delim); ok && end == ']' {
				return nil
			}
			if err := walkForRepeats(decoder, elementToken, path); err != nil {
				return err
			}
		}
	}
	return nil
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

	// Each check's own configuration is validated only when it is enabled. A
	// disabled block is inert — specs routinely carry placeholders in the
	// blocks they turn off, and refusing those would make the schema's own
	// documented example invalid.
	for _, check := range enabled {
		switch check.ID {
		case CheckChecksum:
			if !s.anyChecksumEvidence() {
				return fmt.Errorf("check %q is enabled but no artifact carries evidence.checksum_file", CheckChecksum)
			}
		case CheckSignature:
			if !s.anySignatureEvidence() {
				return fmt.Errorf("check %q is enabled but no artifact carries evidence.signature", CheckSignature)
			}
		case CheckTUF:
			if err := s.Checks.TUF.normalize(); err != nil {
				return err
			}
		case CheckExec:
			if err := s.Checks.Exec.validate(); err != nil {
				return err
			}
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

func (s *Spec) anySignatureEvidence() bool {
	for _, artifact := range s.Artifacts {
		if artifact.Evidence.Signature != nil {
			return true
		}
	}
	return false
}

// normalize validates the TUF block and rewrites the two fields the check
// consumes in a canonical form: the mirror without its file:// prefix and the
// root checksum lowercased and unprefixed.
func (t *TUFCheck) normalize() error {
	if t.Mirror == "" {
		return fmt.Errorf("checks.tuf.mirror is required")
	}
	// Deliberately string semantics rather than URL parsing: the mirror is
	// usually a bare local path, and a path is not a URL to be parsed.
	if strings.Contains(t.Mirror, "://") && !strings.HasPrefix(t.Mirror, "file://") {
		return fmt.Errorf("checks.tuf.mirror only supports local mirror paths or file:// URLs (got %q)", t.Mirror)
	}
	t.Mirror = strings.TrimPrefix(t.Mirror, "file://")
	if t.Mirror == "" {
		return fmt.Errorf("checks.tuf.mirror is required")
	}

	if t.Root == "" {
		return fmt.Errorf("checks.tuf.root is required")
	}
	if t.RootChecksum == "" {
		return fmt.Errorf("checks.tuf.root_checksum is required")
	}
	normalized, ok := normalizeSHA256(t.RootChecksum)
	if !ok {
		return fmt.Errorf("checks.tuf.root_checksum must be a sha256 digest (got %q)", t.RootChecksum)
	}
	t.RootChecksum = normalized

	if len(t.Targets) == 0 {
		return fmt.Errorf("checks.tuf.targets must name at least one trust target")
	}
	// Sorted so the refusal a multi-target spec produces does not depend on
	// Go's map iteration order.
	for _, name := range sortedNames(t.Targets) {
		if name == "" {
			return fmt.Errorf("checks.tuf.targets has an empty target name")
		}
		if t.Targets[name] == "" {
			return fmt.Errorf("checks.tuf.targets[%q] is empty — every trust target needs a local path", name)
		}
	}
	return nil
}

// validate checks the exec block. Artifact is a free path: it is the executable
// to smoke, typically something extracted from a distributed artifact, and it
// need not name an artifacts[] entry.
func (e *ExecCheck) validate() error {
	if e.Artifact == "" {
		return fmt.Errorf("checks.exec.artifact is required")
	}
	if e.TimeoutSeconds < 0 {
		return fmt.Errorf("checks.exec.timeout_seconds must not be negative (got %d)", e.TimeoutSeconds)
	}
	return nil
}

// normalizeSHA256 accepts a digest with an optional sha256: prefix in any case
// and returns it lowercased, or false when it is not 64 hex characters.
func normalizeSHA256(raw string) (string, bool) {
	digest := strings.ToLower(strings.TrimPrefix(raw, "sha256:"))
	if !sha256Hex.MatchString(digest) {
		return "", false
	}
	return digest, true
}

// sortedNames returns a map's keys in sorted order, which is what keeps every
// per-target report line and refusal reproducible byte-for-byte.
func sortedNames(targets map[string]string) []string {
	names := make([]string, 0, len(targets))
	for name := range targets {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
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
