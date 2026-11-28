//go:build linux

package projectlane

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/superbiche/safe/internal/strictjson"
)

// The cache of advisory readings (spec 1625, ticket 1671) holds what safe's
// advisory reader classified of ONE advisory record for ONE queried package, and
// nothing that decides: no verdict, no label the policy applied, no coverage, no
// hit list, no blocklist. Which advisories an identity carries is asked of the
// service on every command; this store only spares re-fetching and re-classifying
// the record behind an advisory the service says has not changed.
//
//	<state>/advisory-records/<sha256 of schema, classifier, id, stamp, package>
//
// The key's stamp is the modification stamp the service gave WITH the membership
// answer (a string, compared as a string: the record's own stamp has another
// precision and is never compared with it). The classifier names the reading's
// rules: a reading made under other rules is another key. An entry is also never
// trusted for more than AdvisoryMaxAge whatever its stamp (the stamp is the
// service's word that nothing changed), nor when it is dated in the future.
//
// The directory chain is held by descriptor, owned by the user, not writable by
// group or others and never a link (the checks the publish-time store uses); an
// entry is a regular file of mode exactly 0600 owned by the user, opened without
// following a link, whose strict document names the key it is stored under.
// An entry that fails any check is IGNORED, never trusted and never an error: the
// record is fetched again. A hit writes nothing. One writer (Put) prunes.
const (
	advisoryDir        = "advisory-records"
	advisoryEntryLimit = 4096
	// AdvisoryCacheSchema is the version of an entry.
	AdvisoryCacheSchema = 1
	// AdvisoryMaxAge is how long a reading is trusted at most: one day, a constant (the bound the scan cache sets for a reading).
	AdvisoryMaxAge = 24 * time.Hour
	// AdvisoryCap is the number of entries the store keeps.
	AdvisoryCap = 10000
	// stale leftovers of an interrupted Put are removed after this long
	advisoryTempAge = 10 * time.Minute
)

// AdvisoryKey names one reading.
type AdvisoryKey struct {
	ID       string `json:"id"`
	Modified string `json:"modified"`
	Package  string `json:"package"`
}

// AdvisoryReading is one stored reading: the classification of the record for the package, or the fact that the record
// is withdrawn (it is then no advisory of anything). Fetched is when the record was fetched, in seconds since the epoch.
type AdvisoryReading struct {
	AdvisoryKey
	Severity  string `json:"severity"`
	Withdrawn bool   `json:"withdrawn"`
	Fetched   int64  `json:"fetched"`
}

// AdvisoryCache is the store below one state directory.
type AdvisoryCache struct{ StateDir string }

type advisoryEntry struct {
	SchemaVersion int    `json:"schema_version"`
	Classifier    string `json:"classifier"`
	ID            string `json:"id"`
	Modified      string `json:"modified"`
	Package       string `json:"package"`
	Severity      string `json:"severity"`
	Withdrawn     bool   `json:"withdrawn"`
	Fetched       int64  `json:"fetched"`
}

func advisoryEntryName(classifier string, key AdvisoryKey) string {
	sum := sha256.Sum256([]byte("1\x00" + classifier + "\x00" + key.ID + "\x00" + key.Modified + "\x00" + key.Package))
	return hex.EncodeToString(sum[:])
}

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

func (c AdvisoryCache) dir(create bool) (*dirHandle, error) {
	if !strings.HasPrefix(c.StateDir, "/") {
		return nil, os.ErrInvalid
	}
	state, err := filepath.EvalSymlinks(c.StateDir)
	if err != nil {
		return nil, err
	}
	root, err := openDirPath(state)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if err := checkPrivate(root, "the state directory"); err != nil {
		return nil, err
	}
	if create {
		return openPrivateChild(root, advisoryDir, "the advisory-record directory")
	}
	handle, err := root.openDirNoFollow(advisoryDir)
	if err != nil {
		return nil, err
	}
	if err := checkPrivate(handle, "the advisory-record directory"); err != nil {
		handle.Close()
		return nil, err
	}
	return handle, nil
}

func (c AdvisoryCache) read(dir *dirHandle, classifier string, key AdvisoryKey, now time.Time) (AdvisoryReading, bool) {
	raw, info, err := dir.readRegular(advisoryEntryName(classifier, key), advisoryEntryLimit)
	if err != nil {
		return AdvisoryReading{}, false
	}
	if !ownedByUs(info) || info.Mode()&(os.ModePerm|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0o600 {
		return AdvisoryReading{}, false
	}
	members, err := strictjson.ParseObject(raw)
	if err != nil || strictjson.RejectVariants(members, "schema_version", "classifier", "id", "modified", "package", "severity", "withdrawn", "fetched") != nil {
		return AdvisoryReading{}, false
	}
	var entry advisoryEntry
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&entry) != nil || decoder.More() || entry.SchemaVersion != AdvisoryCacheSchema || entry.Classifier != classifier ||
		entry.ID != key.ID || entry.Modified != key.Modified || entry.Package != key.Package {
		return AdvisoryReading{}, false
	}
	// what the entry says must be something Put writes: a withdrawn record has no band, any other reading has one
	if entry.Withdrawn == storableSeverity(entry.Severity) {
		return AdvisoryReading{}, false
	}
	if entry.Withdrawn && entry.Severity != "" {
		return AdvisoryReading{}, false
	}
	// one day at most, and never from the future
	age := now.Unix() - entry.Fetched
	if age < 0 || age >= int64(AdvisoryMaxAge/time.Second) {
		return AdvisoryReading{}, false
	}
	return AdvisoryReading{AdvisoryKey: key, Severity: entry.Severity, Withdrawn: entry.Withdrawn, Fetched: entry.Fetched}, true
}

// Get returns the trusted readings among the keys asked, and writes nothing.
func (c AdvisoryCache) Get(classifier string, keys []AdvisoryKey, now time.Time) []AdvisoryReading {
	dir, err := c.dir(false)
	if err != nil {
		return nil
	}
	defer dir.Close()
	var hits []AdvisoryReading
	for _, key := range keys {
		if !advisoryKeyOK(key) {
			continue
		}
		if reading, ok := c.read(dir, classifier, key, now); ok {
			hits = append(hits, reading)
		}
	}
	return hits
}

// Put stores readings the caller fetched and classified, atomically, then prunes. A reading that is not one safe
// stores (a key that is not a line, a band that is not one of the four, a withdrawn record with a band, a fetch time
// in the future or older than the bound) is skipped. A failure is never an error: the record is fetched again.
func (c AdvisoryCache) Put(classifier string, readings []AdvisoryReading, now time.Time) {
	dir, err := c.dir(true)
	if err != nil {
		return
	}
	defer dir.Close()
	for _, reading := range readings {
		if !advisoryKeyOK(reading.AdvisoryKey) || reading.Withdrawn == storableSeverity(reading.Severity) ||
			(reading.Withdrawn && reading.Severity != "") {
			continue
		}
		if age := now.Unix() - reading.Fetched; age < 0 || age >= int64(AdvisoryMaxAge/time.Second) {
			continue
		}
		raw, err := json.Marshal(advisoryEntry{AdvisoryCacheSchema, classifier, reading.ID, reading.Modified, reading.Package,
			reading.Severity, reading.Withdrawn, reading.Fetched})
		if err != nil {
			continue
		}
		random, err := randomName()
		if err != nil {
			continue
		}
		temp := ".new-" + random
		if _, err := dir.createExclusive(temp, append(raw, '\n'), 0o600); err != nil {
			continue
		}
		if err := renameat2(dir, temp, dir, advisoryEntryName(classifier, reading.AdvisoryKey), 0); err != nil {
			_ = dir.remove(temp)
		}
	}
	c.prune(dir, now)
}

// prune keeps the store inside its bound: leftovers of an interrupted Put, entries older than the bound (they can
// never be trusted again), then the oldest entries beyond AdvisoryCap. Only names this store makes are touched.
func (c AdvisoryCache) prune(dir *dirHandle, now time.Time) {
	names, err := dir.names()
	if err != nil {
		return
	}
	type aged struct {
		name  string
		mtime time.Time
	}
	var entries []aged
	for _, name := range names {
		info, err := dir.lstat(name)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		switch {
		case strings.HasPrefix(name, ".new-"):
			if now.Sub(info.ModTime()) > advisoryTempAge {
				_ = dir.remove(name)
			}
		case len(name) == 64 && isHex(name):
			if now.Sub(info.ModTime()) >= AdvisoryMaxAge {
				_ = dir.remove(name)
				continue
			}
			entries = append(entries, aged{name, info.ModTime()})
		}
	}
	if len(entries) <= AdvisoryCap {
		return
	}
	sort.Slice(entries, func(i, j int) bool {
		if !entries[i].mtime.Equal(entries[j].mtime) {
			return entries[i].mtime.Before(entries[j].mtime)
		}
		return entries[i].name < entries[j].name
	})
	for _, entry := range entries[:len(entries)-AdvisoryCap] {
		_ = dir.remove(entry.name)
	}
}

func isHex(s string) bool {
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}
