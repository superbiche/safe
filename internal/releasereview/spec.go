// Package releasereview reviews one distributed release against a spec and
// emits a single report.
//
// The spec schema names all six checks the composite will ever run, but a
// given build implements only a subset. Enabling a check this build cannot run
// is refused at validation rather than reported as a verdict: a stale safe
// fails fast at the spec instead of returning a report whose missing checks a
// consumer would have to notice on its own.
//
// Artifacts and their evidence are never fetched: every file a check reads is
// a path the caller already placed on disk. The release and vuln checks do
// reach the network, but only to read GitHub's own metadata about the release —
// its channel, its age, the commit its tag names, the advisories published
// against the repository. Nothing under review is downloaded here, which is
// what keeps this package stdlib-only and its verdicts reproducible from the
// caller's files.
package releasereview

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/superbiche/safe/internal/strictjson"
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
var implementedChecks = []string{CheckChecksum, CheckSignature, CheckRelease, CheckVuln, CheckTUF, CheckExec}

// The two versions this build speaks. They are constants rather than literals
// at their use sites because they are also advertised — `safe-core
// release-review --versions` prints them, and safe-audit's capability payload
// repeats them so a consumer can preflight a spec before writing one.
const (
	// SpecVersion is the only spec_version Decode accepts. It rose to 2 when the
	// signature check learned detached cert+signature evidence: the schema gained
	// optional fields, so a consumer must be able to tell a build that understands
	// them from one that would refuse them as unknown, and the advertised
	// spec_version is that signal.
	SpecVersion = 2
	// ReportSchemaVersion is the schema_version every report carries. Detached
	// evidence added reason codes, not report shape, so it stays 1: a consumer
	// parses reasons by their (check, code) pair and a new code is data, not a
	// schema change.
	ReportSchemaVersion = 1
)

// Spec is a release review request, schema spec_version 2.
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

// SignatureEvidence is either a Sigstore bundle or a detached cert+signature
// pair, plus the identity policy it must satisfy. It is validated whether or
// not the signature check is enabled: the schema is contract, and evidence a
// disabled check would have read still has to mean one thing.
//
// The two modes are mutually exclusive. Bundle names a Sigstore bundle that
// signs the artifact itself and carries its own transparency-log proof.
// Certificate and Signature are a detached pair — the shape a release that
// publishes `<checksums>.pem` and `<checksums>.sig` beside its checksum file
// ships — and they sign the artifact's checksum file, not the artifact: the
// digest match the checksum check already performs is what carries the trust
// the rest of the way to the artifact. Detached verification therefore vouches
// for an artifact only in concert with an enabled checksum check, which
// validateChecks enforces.
type SignatureEvidence struct {
	Bundle         string `json:"bundle"`
	Certificate    string `json:"certificate"`
	Signature      string `json:"signature"`
	Identity       string `json:"identity"`
	IdentityRegexp string `json:"identity_regexp"`
	OIDCIssuer     string `json:"oidc_issuer"`
}

// isDetached reports whether this evidence is a detached cert+signature pair
// rather than a Sigstore bundle. A validated spec guarantees the two are never
// both set, so the absence of a bundle is what names the mode.
func (s *SignatureEvidence) isDetached() bool {
	return s.Bundle == ""
}

// Checks selects which checks run. An omitted block is a disabled check; an
// omitted Checks object is the default spec: checksum only.
type Checks struct {
	Checksum  *CheckConfig  `json:"checksum"`
	Signature *CheckConfig  `json:"signature"`
	Release   *ReleaseCheck `json:"release"`
	Vuln      *VulnCheck    `json:"vuln"`
	TUF       *TUFCheck     `json:"tuf"`
	Exec      *ExecCheck    `json:"exec"`
}

// CheckConfig is the shape every check block shares. Advisory does not change
// what a check decides, only how much of its verdict reaches the top level.
type CheckConfig struct {
	Enabled  bool `json:"enabled"`
	Advisory bool `json:"advisory"`
}

// ReleaseCheck configures the GitHub release-metadata check. Asset is the name
// the release must carry: the check answers whether GitHub's own record of the
// release contains the file the consumer is about to install, so which file
// that is has to be said, not guessed from the artifacts on disk.
type ReleaseCheck struct {
	CheckConfig
	Asset string `json:"asset"`
	// AllowUnsignedCommit accepts a release whose tagged commit GitHub reports as
	// "unsigned" without a BLOCK, recording a visible GO note instead. It is set
	// for a subject whose upstream never signs its tags and whose manifest waives
	// commit_unverified because a stronger control covers the same risk. It
	// narrows to the plain "unsigned" reason only; any other unverified state
	// still BLOCKs.
	AllowUnsignedCommit bool `json:"allow_unsigned_commit"`
}

// VulnCheck configures the advisory check. Packages declares which
// advisory-package identities describe the subject artifact, so an advisory
// GitHub publishes against an adjacent package in the same repository (the npm
// wrapper or a VS Code extension beside a Rust binary) is ruled not-applicable
// instead of matched cross-artifact. GitHub's ecosystem field is free text
// ("vs code"), not an enum, so the identity is declared, never inferred.
type VulnCheck struct {
	CheckConfig
	Packages []AdvisoryPackage `json:"packages"`
}

// AdvisoryPackage is one advisory-package identity: an ecosystem and a package
// name, both as GitHub reports them in an advisory's `vulnerabilities[].package`.
type AdvisoryPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// scoped reports whether the vuln check restricts advisories to declared
// package identities. Presence of the packages key — even as an empty array —
// turns scoping on: an empty scope is the honest assertion "no advisory package
// in this repository tracks the subject artifact" (a Rust binary in a repo that
// publishes only npm/extension advisories). Its ABSENCE is package-blind, the
// pre-scoping default that matches every advisory. This is the ONE place the
// nil-vs-empty distinction is read; never re-derive it from len().
func (v *VulnCheck) scoped() bool { return v.Packages != nil }

// validate rejects a declared identity that names nothing. An empty packages
// array is a valid empty scope; an entry inside it that omits either half is a
// misconfiguration, not an empty scope.
func (v *VulnCheck) validate() error {
	for i, pkg := range v.Packages {
		if strings.Trim(pkg.Ecosystem, asciiSpace) == "" || strings.Trim(pkg.Name, asciiSpace) == "" {
			return fmt.Errorf("checks.vuln.packages[%d]: both ecosystem and name are required", i)
		}
	}
	return nil
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
	if err := strictjson.RejectRepeatedMembers(raw); err != nil {
		return Spec{}, fmt.Errorf("read spec: %w", err)
	}

	if err := spec.normalize(); err != nil {
		return Spec{}, err
	}
	return spec, nil
}

// normalize validates the spec and fills the defaults the schema documents.
func (s *Spec) normalize() error {
	if s.SpecVersion != SpecVersion {
		return fmt.Errorf("spec_version must be %d (got %d)", SpecVersion, s.SpecVersion)
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
	hasBundle := signature.Bundle != ""
	hasCert := signature.Certificate != ""
	hasSig := signature.Signature != ""
	switch {
	case hasBundle && (hasCert || hasSig):
		return fmt.Errorf("artifacts[%d].evidence.signature: a bundle and a detached certificate/signature are mutually exclusive", index)
	case !hasBundle && !hasCert && !hasSig:
		return fmt.Errorf("artifacts[%d].evidence.signature: a bundle, or a detached certificate and signature, is required", index)
	case !hasBundle && !(hasCert && hasSig):
		return fmt.Errorf("artifacts[%d].evidence.signature: detached verification requires both certificate and signature", index)
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
			if err := s.validateDetachedVouching(enabled); err != nil {
				return err
			}
		case CheckRelease:
			if err := s.Checks.Release.validate(); err != nil {
				return err
			}
		case CheckVuln:
			if err := s.Checks.Vuln.validate(); err != nil {
				return err
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

// validateDetachedVouching enforces what detached evidence needs to mean
// anything. A Sigstore bundle signs the artifact, so a bundle that verifies
// vouches for the artifact on its own. A detached certificate and signature
// sign the artifact's checksum file, so their verifying vouches for the
// artifact only by way of the digest the checksum check matches against that
// same file: without an enabled checksum check the artifact's link to the
// signed material is never exercised, and a top-level GO would rest on nothing.
// So a detached artifact must carry a checksum file, and the checksum check
// must be enabled to consume it. Bundle evidence is untouched by this.
func (s *Spec) validateDetachedVouching(enabled []setting) error {
	checksumEnabled := false
	for _, check := range enabled {
		if check.ID == CheckChecksum {
			checksumEnabled = true
			break
		}
	}
	for i := range s.Artifacts {
		artifact := &s.Artifacts[i]
		signature := artifact.Evidence.Signature
		if signature == nil || !signature.isDetached() {
			continue
		}
		if !checksumEnabled {
			return fmt.Errorf("artifacts[%d].evidence.signature is detached (certificate+signature), which signs the checksum file — enable the checksum check so the digest match ties it to the artifact", i)
		}
		if artifact.Evidence.ChecksumFile == "" {
			return fmt.Errorf("artifacts[%d].evidence.signature is detached, which signs the checksum file, but the artifact carries no evidence.checksum_file", i)
		}
	}
	return nil
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
		// The name is joined onto <mirror>/targets and onto the materialized
		// targets dir to build the paths this check hashes. filepath.Join runs
		// Clean, which *resolves* a `..` rather than neutralizing it, so a name
		// escaping its directory could steer those reads at an arbitrary file.
		// TUF names are path-like and legitimately contain `/`, so only the
		// traversal shapes are refused, not every separator.
		if err := rejectUnsafeTargetName(name); err != nil {
			return fmt.Errorf("checks.tuf.targets[%q]: %w", name, err)
		}
		if t.Targets[name] == "" {
			return fmt.Errorf("checks.tuf.targets[%q] is empty — every trust target needs a local path", name)
		}
	}
	return nil
}

// validate checks the release block. The asset name has no default: falling
// back to the first artifact's name would let a spec that names the wrong file
// pass as if it had named the right one.
func (r *ReleaseCheck) validate() error {
	if r.Asset == "" {
		return fmt.Errorf("checks.release.asset is required — name the asset the GitHub release must carry")
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

// rejectUnsafeTargetName refuses a trust target name that would escape the
// directory it is joined into. TUF names may contain `/`, so a name is refused
// only when it is absolute or carries a `..` segment — the shapes that
// filepath.Join's Clean would resolve out of the targets tree.
func rejectUnsafeTargetName(name string) error {
	if filepath.IsAbs(name) {
		return fmt.Errorf("a trust target name must be relative")
	}
	for _, segment := range strings.Split(filepath.ToSlash(name), "/") {
		if segment == ".." {
			return fmt.Errorf("a trust target name must not contain a %q path segment", "..")
		}
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
	}
	if s.Checks.Vuln != nil {
		configs[CheckVuln] = &s.Checks.Vuln.CheckConfig
	}
	if s.Checks.Release != nil {
		configs[CheckRelease] = &s.Checks.Release.CheckConfig
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
