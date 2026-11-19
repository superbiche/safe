package projectlane

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/superbiche/safe/internal/strictjson"
)

// EvidenceSchema is the version of the evidence document this package reads.
// A reader accepts exactly the versions it knows; a field a later ticket adds
// (publish times, named-root evidence, records) arrives with a new version,
// never as a key an older reader would skip.
const EvidenceSchema = 1

// Coverage states of an identity's advisory reading.
const (
	CoverageComplete = "complete"
	CoverageMissing  = "missing"
)

// Acceptance kinds. Each names an authority, not an outcome: which classes an
// authority may clear is the decision's rule (see Decide), never the
// document's.
const (
	AcceptLocalExact       = "local_exact_approval"
	AcceptFollowedGrant    = "followed_grant"
	AcceptFollowedOverride = "followed_advisory_override"
	AcceptFollowedInstall  = "followed_install_allowance"
)

// Severity labels of the existing ladder. "unknown" is the ladder's label for
// a record whose severity cannot be read.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityModerate = "moderate"
	SeverityLow      = "low"
	SeverityUnknown  = "unknown"
)

var advisoryID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// Evidence is the strict, versioned input of the decision: what was read, kept
// apart from what it means. Advisories and coverage are per exact identity;
// the blocklist is per name. Standing acceptances are NOT part of this
// document: they are authorities verified elsewhere (signers, generations and
// ecosystems are checked there, not here) and arrive as their own strict
// document (see ReadAcceptances), so that nobody merges or re-encodes the
// evidence to add them. A document that carries an "acceptances" member is
// refused like any other foreign member.
type Evidence struct {
	SchemaVersion int                `json:"schema_version"`
	Policy        Policy             `json:"policy"`
	Identities    []IdentityEvidence `json:"identities"`
	Blocklist     []BlocklistHit     `json:"blocklist"`
	// Acceptances is set by the caller from the separate acceptances input;
	// the evidence document never carries it.
	Acceptances []Acceptance `json:"-"`
}

// Policy is the operator's install policy the decision applies.
type Policy struct {
	// BlockSeverities are the ladder labels that make an advisory blocking
	// (install.block_severities, critical by default). Malware is never
	// severity policy.
	BlockSeverities []string `json:"block_severities"`
}

// IdentityEvidence is the advisory reading for one exact identity. Coverage
// "missing" with advisories is a partial reading: the hits are validated and
// stand, and the gap says what was not read.
type IdentityEvidence struct {
	Name       string        `json:"name"`
	Version    string        `json:"version"`
	Coverage   string        `json:"coverage"`
	Gap        string        `json:"gap"`
	Advisories []AdvisoryHit `json:"advisories"`
}

// AdvisoryHit is one validated advisory that affects the identity. Malware
// marks OpenSSF MAL-* records, which are malice and never severity policy.
type AdvisoryHit struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Malware  bool   `json:"malware"`
}

// BlocklistHit is an operator blocklist entry that names a package. It is
// keyed by name: the blocklist knows no versions.
type BlocklistHit struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// Acceptance is a standing authority for one exact artifact: name, version and
// the registry host it came from. Advisories is the list a followed advisory
// override covers; it is empty for every other kind.
type Acceptance struct {
	Kind       string   `json:"kind"`
	Name       string   `json:"name"`
	Version    string   `json:"version"`
	Host       string   `json:"host"`
	Advisories []string `json:"advisories"`
}

// ReadEvidence decodes an evidence document strictly: no repeated member, no
// unknown member, every member present (an absent list is not an empty one),
// and every value in its domain. A document that cannot be read is an error,
// never an empty evidence set.
func ReadEvidence(raw []byte) (Evidence, error) {
	if err := strictjson.RejectRepeatedMembers(raw); err != nil {
		return Evidence{}, fmt.Errorf("evidence: %w", err)
	}
	if err := requireShape(raw); err != nil {
		return Evidence{}, fmt.Errorf("evidence: %w", err)
	}
	var evidence Evidence
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&evidence); err != nil {
		return Evidence{}, fmt.Errorf("evidence: %w", err)
	}
	if decoder.More() {
		return Evidence{}, fmt.Errorf("evidence: more than one JSON document")
	}
	if err := evidence.validate(); err != nil {
		return Evidence{}, fmt.Errorf("evidence: %w", err)
	}
	return evidence, nil
}

func requireShape(raw []byte) error {
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil || root == nil {
		return fmt.Errorf("not a JSON object")
	}
	if err := requireKeys(root, "", "schema_version", "policy", "identities", "blocklist"); err != nil {
		return err
	}
	policy, _ := root["policy"].(map[string]any)
	if err := requireKeys(policy, "policy.", "block_severities"); err != nil {
		return err
	}
	if _, ok := policy["block_severities"].([]any); !ok {
		return fmt.Errorf("policy.block_severities must be a list")
	}
	lists := []struct {
		key  string
		keys []string
	}{
		{"identities", []string{"name", "version", "coverage", "gap", "advisories"}},
		{"blocklist", []string{"name", "reason"}},
	}
	for _, list := range lists {
		items, ok := root[list.key].([]any)
		if !ok {
			return fmt.Errorf("%s must be a list", list.key)
		}
		for i, item := range items {
			object, ok := item.(map[string]any)
			if !ok {
				return fmt.Errorf("%s[%d] must be an object", list.key, i)
			}
			prefix := fmt.Sprintf("%s[%d].", list.key, i)
			if err := requireKeys(object, prefix, list.keys...); err != nil {
				return err
			}
			if list.key == "identities" {
				if _, ok := object["advisories"].([]any); !ok {
					return fmt.Errorf("%sadvisories must be a list", prefix)
				}
			}
			if list.key == "identities" {
				for j, hit := range object["advisories"].([]any) {
					hitObject, ok := hit.(map[string]any)
					if !ok {
						return fmt.Errorf("%sadvisories[%d] must be an object", prefix, j)
					}
					if err := requireKeys(hitObject, fmt.Sprintf("%sadvisories[%d].", prefix, j), "id", "severity", "malware"); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// requireKeys demands exactly the schema's members at one object level: every
// listed key present and non-null, and no other key at all. The comparison is
// byte for byte. A reader that skipped a stray key would leave a second
// spelling of a schema field (a case or Unicode fold of it, which the struct
// decoder below would bind to the same field) free to replace the real one.
func requireKeys(object map[string]any, prefix string, keys ...string) error {
	allowed := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		allowed[key] = struct{}{}
		value, present := object[key]
		if !present {
			return fmt.Errorf("field %s%s is missing", prefix, key)
		}
		if value == nil {
			return fmt.Errorf("field %s%s is null", prefix, key)
		}
	}
	for key := range object {
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("field %s%q is not part of the schema", prefix, key)
		}
	}
	return nil
}

func (e Evidence) validate() error {
	if e.SchemaVersion != EvidenceSchema {
		return fmt.Errorf("unsupported schema_version %d (this reader knows %d)", e.SchemaVersion, EvidenceSchema)
	}
	for _, severity := range e.Policy.BlockSeverities {
		if !validSeverity(severity) {
			return fmt.Errorf("policy.block_severities: unknown severity %q", severity)
		}
	}
	seen := map[Identity]struct{}{}
	for i, identity := range e.Identities {
		if identity.Name == "" || identity.Version == "" {
			return fmt.Errorf("identities[%d]: name and version are required", i)
		}
		key := Identity{Name: identity.Name, Version: identity.Version}
		if _, dup := seen[key]; dup {
			return fmt.Errorf("identities[%d]: %s@%s is given more than once", i, key.Name, key.Version)
		}
		seen[key] = struct{}{}
		switch identity.Coverage {
		case CoverageComplete:
			if identity.Gap != "" {
				return fmt.Errorf("identities[%d]: complete coverage cannot carry a gap", i)
			}
		case CoverageMissing:
			if identity.Gap == "" {
				return fmt.Errorf("identities[%d]: missing coverage must say what was not read", i)
			}
		default:
			return fmt.Errorf("identities[%d]: unknown coverage %q", i, identity.Coverage)
		}
		ids := map[string]struct{}{}
		for j, hit := range identity.Advisories {
			if !advisoryID.MatchString(hit.ID) {
				return fmt.Errorf("identities[%d].advisories[%d]: malformed advisory id", i, j)
			}
			if !validSeverity(hit.Severity) {
				return fmt.Errorf("identities[%d].advisories[%d]: unknown severity %q", i, j, hit.Severity)
			}
			if hit.Malware != strings.HasPrefix(hit.ID, "MAL-") {
				return fmt.Errorf("identities[%d].advisories[%d]: malware must be true exactly for MAL- records", i, j)
			}
			if _, dup := ids[hit.ID]; dup {
				return fmt.Errorf("identities[%d]: advisory %s is given more than once", i, hit.ID)
			}
			ids[hit.ID] = struct{}{}
		}
	}
	for i, hit := range e.Blocklist {
		if hit.Name == "" {
			return fmt.Errorf("blocklist[%d]: name is required", i)
		}
	}
	return nil
}

// AcceptancesSchema is the version of the acceptances document.
const AcceptancesSchema = 1

// ReadAcceptances decodes the standing-acceptances document strictly, with the
// same discipline as ReadEvidence: one JSON document, no repeated member, no
// unknown member, every member present, every value in its domain.
func ReadAcceptances(raw []byte) ([]Acceptance, error) {
	if err := strictjson.RejectRepeatedMembers(raw); err != nil {
		return nil, fmt.Errorf("acceptances: %w", err)
	}
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil || root == nil {
		return nil, fmt.Errorf("acceptances: not a JSON object")
	}
	if err := requireKeys(root, "", "schema_version", "acceptances"); err != nil {
		return nil, fmt.Errorf("acceptances: %w", err)
	}
	items, ok := root["acceptances"].([]any)
	if !ok {
		return nil, fmt.Errorf("acceptances: acceptances must be a list")
	}
	for i, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("acceptances: acceptances[%d] must be an object", i)
		}
		if err := requireKeys(object, fmt.Sprintf("acceptances[%d].", i), "kind", "name", "version", "host", "advisories"); err != nil {
			return nil, fmt.Errorf("acceptances: %w", err)
		}
		if _, ok := object["advisories"].([]any); !ok {
			return nil, fmt.Errorf("acceptances: acceptances[%d].advisories must be a list", i)
		}
	}
	var document struct {
		SchemaVersion int          `json:"schema_version"`
		Acceptances   []Acceptance `json:"acceptances"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("acceptances: %w", err)
	}
	if decoder.More() {
		return nil, fmt.Errorf("acceptances: more than one JSON document")
	}
	if document.SchemaVersion != AcceptancesSchema {
		return nil, fmt.Errorf("acceptances: unsupported schema_version %d (this reader knows %d)", document.SchemaVersion, AcceptancesSchema)
	}
	if err := validateAcceptances(document.Acceptances); err != nil {
		return nil, fmt.Errorf("acceptances: %w", err)
	}
	return document.Acceptances, nil
}

func validateAcceptances(acceptances []Acceptance) error {
	for i, acceptance := range acceptances {
		switch acceptance.Kind {
		case AcceptLocalExact, AcceptFollowedGrant, AcceptFollowedInstall:
			if len(acceptance.Advisories) != 0 {
				return fmt.Errorf("acceptances[%d]: %s covers an artifact, not a list of advisories", i, acceptance.Kind)
			}
		case AcceptFollowedOverride:
			if len(acceptance.Advisories) == 0 {
				return fmt.Errorf("acceptances[%d]: %s must list the advisories it covers", i, acceptance.Kind)
			}
			for _, id := range acceptance.Advisories {
				if !advisoryID.MatchString(id) {
					return fmt.Errorf("acceptances[%d]: malformed advisory id", i)
				}
			}
		default:
			return fmt.Errorf("acceptances[%d]: unknown kind %q", i, acceptance.Kind)
		}
		if acceptance.Name == "" || acceptance.Version == "" || acceptance.Host == "" {
			return fmt.Errorf("acceptances[%d]: name, version and host are required", i)
		}
	}
	return nil
}

func validSeverity(severity string) bool {
	switch severity {
	case SeverityCritical, SeverityHigh, SeverityModerate, SeverityLow, SeverityUnknown:
		return true
	}
	return false
}

// sortedIDs returns the sorted ids of a set.
func sortedIDs(set map[string]struct{}) []string {
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
