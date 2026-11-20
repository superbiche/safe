//go:build linux

package projectlane

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/superbiche/safe/internal/strictjson"
)

// The cache of publish times (spec 1625, Cooldown) holds only what safe itself
// read from the registry it asked: it lives in the lane's own store, under the
// checks the recorded baselines get (their directory chain and their file
// checks, reused here, not written a second time):
//
//	<state>/publish-times/<sha256 of the source asked>/<sha256 of name NUL version>
//
// The chain of directories is held by descriptor, owned by the user, not writable
// by group or others and never a link; an entry is a regular file of mode
// exactly 0600 owned by the user, opened without following a link, whose strict
// document names the same source, name and version it is stored under. An entry
// that fails any check is IGNORED, never trusted and never an error by itself:
// the version is read again. The source is the base URL actually asked, so a
// mirror's reading never shares the canonical registry's key.
const (
	publishTimesDir   = "publish-times"
	publishEntryLimit = 4096
	// PublishCacheSchema is the version of an entry.
	PublishCacheSchema = 1
)

// PublishCache is the store of publish times below one state directory.
type PublishCache struct{ StateDir string }

type publishEntry struct {
	SchemaVersion int    `json:"schema_version"`
	Source        string `json:"source"`
	Name          string `json:"name"`
	Version       string `json:"version"`
	Published     string `json:"published"`
}

func entryName(name, version string) string {
	sum := sha256.Sum256([]byte(name + "\x00" + version))
	return hex.EncodeToString(sum[:])
}

// dir opens the directory of one source's entries through the checked chain.
func (c PublishCache) dir(source string, create bool) (*dirHandle, error) {
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
	open := func(parent *dirHandle, child, what string) (*dirHandle, error) {
		if create {
			return openPrivateChild(parent, child, what)
		}
		handle, err := parent.openDirNoFollow(child)
		if err != nil {
			return nil, err
		}
		if err := checkPrivate(handle, what); err != nil {
			handle.Close()
			return nil, err
		}
		return handle, nil
	}
	sub, err := open(root, publishTimesDir, "the publish-time directory")
	if err != nil {
		return nil, err
	}
	defer sub.Close()
	key := sha256.Sum256([]byte(source))
	return open(sub, hex.EncodeToString(key[:]), "this source's publish-time directory")
}

// Get returns a trusted entry's time, or false when there is none or it is not trusted.
func (c PublishCache) Get(source, name, version string) (time.Time, bool) {
	dir, err := c.dir(source, false)
	if err != nil {
		return time.Time{}, false
	}
	defer dir.Close()
	raw, info, err := dir.readRegular(entryName(name, version), publishEntryLimit)
	if err != nil {
		return time.Time{}, false
	}
	if !ownedByUs(info) || info.Mode()&(os.ModePerm|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0o600 {
		return time.Time{}, false
	}
	// the repository's exact-object validator: exactly one document, no member given twice (compared exactly), no
	// second spelling of a field name; anything else is not an entry safe wrote
	members, err := strictjson.ParseObject(raw)
	if err != nil || strictjson.RejectVariants(members, "schema_version", "source", "name", "version", "published") != nil {
		return time.Time{}, false
	}
	var entry publishEntry
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&entry) != nil || decoder.More() || entry.SchemaVersion != PublishCacheSchema ||
		entry.Source != source || entry.Name != name || entry.Version != version {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, entry.Published)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// Put stores a time safe read, atomically. A failure is not an error: the version is read again next time.
func (c PublishCache) Put(source, name, version string, published time.Time) {
	dir, err := c.dir(source, true)
	if err != nil {
		return
	}
	defer dir.Close()
	raw, err := json.Marshal(publishEntry{PublishCacheSchema, source, name, version, published.UTC().Format(time.RFC3339Nano)})
	if err != nil {
		return
	}
	random, err := randomName()
	if err != nil {
		return
	}
	temp := ".new-" + random
	if _, err := dir.createExclusive(temp, append(raw, '\n'), 0o600); err != nil {
		return
	}
	target := entryName(name, version)
	// an entry already there is replaced by what was just read (renameat2 without NOREPLACE)
	if err := renameat2(dir, temp, dir, target, 0); err != nil {
		_ = dir.remove(temp)
	}
}
