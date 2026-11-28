//go:build linux

package projectlane

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
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
	// stale leftovers of an interrupted Put are removed after this long
	advisoryTempAge = 10 * time.Minute
)

// advisoryHook is called at the stages of Put ("room" once the room is made, "write" before each entry is written): a seam for the tests, which
// look at the store between the two. It does nothing in the program.
var advisoryHook = func(stage string) {}

// AdvisoryCache is the store below one state directory.
type AdvisoryCache struct{ StateDir string }

type advisoryEntry struct {
	SchemaVersion int    `json:"schema_version"`
	Classifier    string `json:"classifier"`
	AdvisoryKey
	Severity  string `json:"severity"`
	Withdrawn bool   `json:"withdrawn"`
	Fetched   int64  `json:"fetched"`
}

func advisoryEntryName(classifier string, key AdvisoryKey) string {
	sum := sha256.Sum256([]byte("1\x00" + classifier + "\x00" + key.ID + "\x00" + key.Modified + "\x00" + key.Package))
	return hex.EncodeToString(sum[:])
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
	// every member required and of its type, nothing null, one document, no member twice, nothing the entry does not name
	var entry advisoryEntry
	if err := strictObject(raw, &entry, append([]string{"schema_version", "classifier"}, readingMembers...)...); err != nil {
		return AdvisoryReading{}, false
	}
	if entry.SchemaVersion != AdvisoryCacheSchema || entry.Classifier != classifier || entry.AdvisoryKey != key {
		return AdvisoryReading{}, false
	}
	reading := AdvisoryReading{AdvisoryKey: entry.AdvisoryKey, Severity: entry.Severity, Withdrawn: entry.Withdrawn, Fetched: entry.Fetched}
	// what the entry says must be something Put writes: a withdrawn record has no band, any other reading has one
	if !validReading(reading) {
		return AdvisoryReading{}, false
	}
	// one day at most, and never from the future
	if age := now.Unix() - entry.Fetched; age < 0 || age >= int64(AdvisoryMaxAge/time.Second) {
		return AdvisoryReading{}, false
	}
	return reading, true
}

// Get returns the trusted readings among the keys asked (one at most for each distinct key), and writes nothing.
func (c AdvisoryCache) Get(classifier string, keys []AdvisoryKey, now time.Time) []AdvisoryReading {
	dir, err := c.dir(false)
	if err != nil {
		return nil
	}
	defer dir.Close()
	var hits []AdvisoryReading
	asked := make(map[AdvisoryKey]bool, len(keys))
	for _, key := range keys {
		if !advisoryKeyOK(key) || asked[key] {
			continue
		}
		asked[key] = true
		if reading, ok := c.read(dir, classifier, key, now); ok {
			hits = append(hits, reading)
		}
	}
	return hits
}

// Put stores readings the caller fetched and classified, atomically. It makes room FIRST (so that a write that is interrupted
// can not leave the store past its cap), then writes. A reading that is not one safe stores (a key that is not a line, a band
// that is not one of the four, a withdrawn record with a band, a fetch time in the future or older than the bound) is skipped, and
// so is whatever would pass the cap in one request. A failure is never an error: the record is fetched again.
func (c AdvisoryCache) Put(classifier string, readings []AdvisoryReading, now time.Time) {
	var keep []AdvisoryReading
	for _, reading := range readings {
		if !validReading(reading) {
			continue
		}
		if age := now.Unix() - reading.Fetched; age < 0 || age >= int64(AdvisoryMaxAge/time.Second) {
			continue
		}
		if len(keep) == AdvisoryCap {
			break
		}
		keep = append(keep, reading)
	}
	if len(keep) == 0 {
		return
	}
	dir, err := c.dir(true)
	if err != nil {
		return
	}
	defer dir.Close()
	c.makeRoom(dir, len(keep), now)
	advisoryHook("room")
	for _, reading := range keep {
		advisoryHook("write")
		raw, err := json.Marshal(advisoryEntry{AdvisoryCacheSchema, classifier, reading.AdvisoryKey, reading.Severity, reading.Withdrawn, reading.Fetched})
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
}

// makeRoom leaves space for `incoming` entries below the cap, before anything is written: it removes the leftovers of an
// interrupted Put (only names of the writer's own pattern, and only when old), the entries older than the bound (they can never
// be trusted again), then the oldest entries beyond what the cap leaves. Only names this store makes are ever touched.
func (c AdvisoryCache) makeRoom(dir *dirHandle, incoming int, now time.Time) {
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
		switch {
		case tempNamePattern.MatchString(name):
			info, err := dir.lstat(name)
			if err == nil && info.Mode().IsRegular() && now.Sub(info.ModTime()) > advisoryTempAge {
				_ = dir.remove(name)
			}
		case entryNamePattern.MatchString(name):
			info, err := dir.lstat(name)
			if err != nil || !info.Mode().IsRegular() {
				continue
			}
			if now.Sub(info.ModTime()) >= AdvisoryMaxAge {
				_ = dir.remove(name)
				continue
			}
			entries = append(entries, aged{name, info.ModTime()})
		}
	}
	excess := len(entries) + incoming - AdvisoryCap
	if excess <= 0 {
		return
	}
	sort.Slice(entries, func(i, j int) bool {
		if !entries[i].mtime.Equal(entries[j].mtime) {
			return entries[i].mtime.Before(entries[j].mtime)
		}
		return entries[i].name < entries[j].name
	})
	for _, entry := range entries[:excess] {
		_ = dir.remove(entry.name)
	}
}
