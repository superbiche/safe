package projectlane

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/superbiche/safe/internal/strictjson"
)

// The advisory-record cache (spec 1625, ticket 1671): what the lane's advisory reader may keep between two commands, and
// the strict reading of every document that crosses its three boundaries (the entry on disk, the two commands' input, the
// reader's reading of the store's reply). The store itself is advisorycache_linux.go.
//
// What the checks hold, and what they do not: an entry is the local user's (owner, mode, no link, a strict document naming
// its own key); that is not proof that the lane wrote it. A process of the same user can write a reading for a non-malware
// advisory, as it can write a publish time. The store can neither create nor hide a membership, a known-malware record or a
// blocklist entry: those are asked of the service and read from the blocklist on every command.
const (
	// AdvisoryCacheSchema is the version of an entry and of the reply.
	AdvisoryCacheSchema = 1
	// AdvisoryMaxAge is how long a reading is trusted at most: one day, a constant (the bound the scan cache sets for a reading).
	AdvisoryMaxAge = 24 * time.Hour
	// AdvisoryCap is the number of entries the store keeps.
	AdvisoryCap = 10000
	// advisoryInputLimit bounds a document read from a stream: a reading of a thousand identities names a few hundred
	// advisories; the bound only keeps a stream that is not one from filling memory.
	AdvisoryInputLimit = 64 << 20
)

// AdvisoryKey names one reading.
type AdvisoryKey struct {
	ID       string `json:"id"`
	Modified string `json:"modified"`
	Package  string `json:"package"`
}

// AdvisoryReading is one stored reading: the classification of the record for the package, or the fact that the record
// is withdrawn (it is then no advisory of anything, and carries no band). Fetched is when the record was fetched, in
// seconds since the epoch.
type AdvisoryReading struct {
	AdvisoryKey
	Severity  string `json:"severity"`
	Withdrawn bool   `json:"withdrawn"`
	Fetched   int64  `json:"fetched"`
}

var keyMembers = []string{"id", "modified", "package"}
var readingMembers = []string{"id", "modified", "package", "severity", "withdrawn", "fetched"}

// A classification safe stores: the four bands. "unknown" (a record that could not be classified) is never stored.
func storableSeverity(severity string) bool {
	switch severity {
	case "critical", "high", "moderate", "low":
		return true
	}
	return false
}

// A key's parts are one printable line: they name a file and are compared as written.
func advisoryKeyOK(key AdvisoryKey) bool {
	for _, part := range []string{key.ID, key.Modified, key.Package} {
		if part == "" || len(part) > 512 || strings.ContainsAny(part, "\x00\n\r") {
			return false
		}
	}
	return true
}

// validReading is what Put stores and what a reply may hold: a key that is one line each, and either a withdrawn record with
// no band or a record with one of the four.
func validReading(reading AdvisoryReading) bool {
	if !advisoryKeyOK(reading.AdvisoryKey) {
		return false
	}
	if reading.Withdrawn {
		return reading.Severity == ""
	}
	return storableSeverity(reading.Severity)
}

// strictObject decodes raw as exactly one JSON object into into: one document (a stray closing delimiter, a second document or
// trailing data is refused), no member named twice, no second spelling of a required name (another case, a Unicode fold), every
// required member present and not null, no member the type does not name. The repository's strict readers do the work.
func strictObject(raw []byte, into any, required ...string) error {
	members, err := strictjson.ParseObject(raw)
	if err != nil {
		return err
	}
	if err := strictjson.RejectVariants(members, required...); err != nil {
		return err
	}
	for _, name := range required {
		value, present := members[name]
		if !present || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("member %q is missing or null", name)
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(into); err != nil {
		return err
	}
	return nil
}

func decodeKeys(raws []json.RawMessage) ([]AdvisoryKey, error) {
	keys := make([]AdvisoryKey, 0, len(raws))
	for _, raw := range raws {
		var key AdvisoryKey
		if err := strictObject(raw, &key, keyMembers...); err != nil {
			return nil, err
		}
		if !advisoryKeyOK(key) {
			return nil, fmt.Errorf("a key that is not one line of text")
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func decodeReadings(raws []json.RawMessage) ([]AdvisoryReading, error) {
	readings := make([]AdvisoryReading, 0, len(raws))
	for _, raw := range raws {
		var reading AdvisoryReading
		if err := strictObject(raw, &reading, readingMembers...); err != nil {
			return nil, err
		}
		readings = append(readings, reading)
	}
	return readings, nil
}

// ParseAdvisoryGetRequest reads the request of project-advisory-get: {"classifier": "…", "keys": [{id, modified, package}…]}.
func ParseAdvisoryGetRequest(raw []byte) (string, []AdvisoryKey, error) {
	var request struct {
		Classifier string            `json:"classifier"`
		Keys       []json.RawMessage `json:"keys"`
	}
	if err := strictObject(raw, &request, "classifier", "keys"); err != nil {
		return "", nil, err
	}
	if request.Classifier == "" || request.Keys == nil {
		return "", nil, fmt.Errorf("a classifier and a list of keys are required")
	}
	keys, err := decodeKeys(request.Keys)
	return request.Classifier, keys, err
}

// ParseAdvisoryPutRequest reads the request of project-advisory-put: {"classifier": "…", "readings": [{id, modified, package,
// severity, withdrawn, fetched}…]}. A reading that is whole but not one safe stores (a band that is not one of the four, a band on a
// withdrawn record) is the writer's to skip; one that is not whole refuses the request.
func ParseAdvisoryPutRequest(raw []byte) (string, []AdvisoryReading, error) {
	var request struct {
		Classifier string            `json:"classifier"`
		Readings   []json.RawMessage `json:"readings"`
	}
	if err := strictObject(raw, &request, "classifier", "readings"); err != nil {
		return "", nil, err
	}
	if request.Classifier == "" || request.Readings == nil {
		return "", nil, fmt.Errorf("a classifier and a list of readings are required")
	}
	readings, err := decodeReadings(request.Readings)
	return request.Classifier, readings, err
}

// CheckAdvisoryReply is the reader's reading of what the store answered: exactly one document of exactly {schema_version, hits},
// every hit whole and of its types, one hit at most for each key asked and none for a key that was not, each a reading safe
// stores, none dated in the future or older than the bound. It returns the readings as {"<id>|<package>": band | "withdrawn"}.
// Anything else is an error: the caller reads nothing from the store.
func CheckAdvisoryReply(raw []byte, asked []AdvisoryKey, now time.Time) (map[string]string, error) {
	var reply struct {
		SchemaVersion int               `json:"schema_version"`
		Hits          []json.RawMessage `json:"hits"`
	}
	if err := strictObject(raw, &reply, "schema_version", "hits"); err != nil {
		return nil, err
	}
	if reply.SchemaVersion != AdvisoryCacheSchema || reply.Hits == nil {
		return nil, fmt.Errorf("not a reply of schema %d", AdvisoryCacheSchema)
	}
	hits, err := decodeReadings(reply.Hits)
	if err != nil {
		return nil, err
	}
	want := make(map[AdvisoryKey]bool, len(asked))
	for _, key := range asked {
		want[key] = true
	}
	seen := make(map[AdvisoryKey]bool, len(hits))
	out := make(map[string]string, len(hits))
	for _, hit := range hits {
		if !want[hit.AdvisoryKey] {
			return nil, fmt.Errorf("a hit for a key nobody asked")
		}
		if seen[hit.AdvisoryKey] {
			return nil, fmt.Errorf("two hits for one key")
		}
		seen[hit.AdvisoryKey] = true
		if !validReading(hit) {
			return nil, fmt.Errorf("a hit that is not a reading safe stores")
		}
		if age := now.Unix() - hit.Fetched; age < 0 || age >= int64(AdvisoryMaxAge/time.Second) {
			return nil, fmt.Errorf("a hit dated in the future or older than the bound")
		}
		state := hit.Severity
		if hit.Withdrawn {
			state = "withdrawn"
		}
		out[hit.ID+"|"+hit.Package] = state
	}
	return out, nil
}

// the writer's own temporary names: ".new-" and 32 lowercase hexadecimal digits. Nothing else is ever removed as a leftover.
var tempNamePattern = regexp.MustCompile(`^\.new-[0-9a-f]{32}$`)

// the names of entries: 64 lowercase hexadecimal digits
var entryNamePattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
