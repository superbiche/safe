//go:build linux

package projectlane

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const cacheSource = "https://registry.npmjs.org"

func privateState(t *testing.T) string {
	t.Helper()
	state := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	return state
}

func entryPath(state, source, name, version string) string {
	sum := sha256.Sum256([]byte(source))
	return filepath.Join(state, publishTimesDir, hex.EncodeToString(sum[:]), entryName(name, version))
}

func TestPublishCacheRoundTripKeepsFractionalSecondsAndPrivateModes(t *testing.T) {
	state := privateState(t)
	cache := PublishCache{StateDir: state}
	published := time.Date(2026, 11, 2, 17, 5, 43, 359_000_000, time.UTC)
	cache.Put(cacheSource, "semver", "7.8.6", published)
	got, ok := cache.Get(cacheSource, "semver", "7.8.6")
	if !ok || !got.Equal(published) {
		t.Fatalf("round trip: %v %v", got, ok)
	}
	info, err := os.Stat(entryPath(state, cacheSource, "semver", "7.8.6"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("entry: %v %v", info, err)
	}
	for _, dir := range []string{filepath.Join(state, publishTimesDir), filepath.Dir(entryPath(state, cacheSource, "semver", "7.8.6"))} {
		if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o700 {
			t.Fatalf("directory %s: %v %v", dir, info, err)
		}
	}
	// another source, another name, another version: no entry
	for _, miss := range []struct{ source, name, version string }{{"http://mirror.example", "semver", "7.8.6"}, {cacheSource, "other", "7.8.6"}, {cacheSource, "semver", "7.8.5"}} {
		if _, ok := cache.Get(miss.source, miss.name, miss.version); ok {
			t.Fatalf("an entry answered for %+v", miss)
		}
	}
}

func TestPublishCacheIgnoresWhatFailsItsChecks(t *testing.T) {
	published := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	plant := func(t *testing.T, state string) string {
		t.Helper()
		PublishCache{StateDir: state}.Put(cacheSource, "pk", "1.0.0", published)
		return entryPath(state, cacheSource, "pk", "1.0.0")
	}
	asked := func(state string) bool {
		_, ok := PublishCache{StateDir: state}.Get(cacheSource, "pk", "1.0.0")
		return ok
	}
	t.Run("a good entry is trusted", func(t *testing.T) {
		state := privateState(t)
		plant(t, state)
		if !asked(state) {
			t.Fatal("a good entry was ignored")
		}
	})
	t.Run("an entry of the wrong mode", func(t *testing.T) {
		for _, mode := range []os.FileMode{0o644, 0o640, 0o660, 0o400, 0o600 | os.ModeSetuid} {
			state := privateState(t)
			path := plant(t, state)
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			if asked(state) {
				t.Fatalf("an entry of mode %v was trusted", mode)
			}
		}
	})
	t.Run("a link in place of an entry", func(t *testing.T) {
		state := privateState(t)
		path := plant(t, state)
		target := filepath.Join(t.TempDir(), "elsewhere")
		raw, _ := os.ReadFile(path)
		os.WriteFile(target, raw, 0o600)
		os.Remove(path)
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if asked(state) {
			t.Fatal("a link was followed")
		}
	})
	t.Run("a directory that is not private", func(t *testing.T) {
		for _, which := range []string{"state", "publish-times", "source"} {
			state := privateState(t)
			path := plant(t, state)
			dirs := map[string]string{"state": state, "publish-times": filepath.Join(state, publishTimesDir), "source": filepath.Dir(path)}
			if err := os.Chmod(dirs[which], 0o770); err != nil {
				t.Fatal(err)
			}
			if asked(state) {
				t.Fatalf("an entry below a group-writable %s directory was trusted", which)
			}
		}
	})
	t.Run("a link in place of a directory", func(t *testing.T) {
		state := privateState(t)
		path := plant(t, state)
		real := filepath.Join(t.TempDir(), "moved")
		if err := os.Rename(filepath.Dir(path), real); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(real, filepath.Dir(path)); err != nil {
			t.Fatal(err)
		}
		if asked(state) {
			t.Fatal("a linked directory was followed")
		}
	})
	t.Run("an entry that names another identity, another source, or has a foreign member", func(t *testing.T) {
		for _, body := range []string{
			`{"schema_version":1,"source":"https://registry.npmjs.org","name":"other","version":"1.0.0","published":"2000-01-01T00:00:00Z"}`,
			`{"schema_version":1,"source":"http://mirror.example","name":"pk","version":"1.0.0","published":"2000-01-01T00:00:00Z"}`,
			`{"schema_version":2,"source":"https://registry.npmjs.org","name":"pk","version":"1.0.0","published":"2000-01-01T00:00:00Z"}`,
			`{"schema_version":1,"source":"https://registry.npmjs.org","name":"pk","version":"1.0.0","published":"2000-01-01T00:00:00Z","x":1}`,
			`{"schema_version":1,"source":"https://registry.npmjs.org","name":"pk","version":"1.0.0","published":"yesterday"}`,
			// repeated members (the second wins in a lenient reader), a second spelling of a field, trailing data
			`{"schema_version":1,"source":"https://registry.npmjs.org","name":"pk","version":"1.0.0","published":"2000-01-01T00:00:00Z","published":"2026-11-19T00:00:00Z"}`,
			`{"schema_version":1,"source":"https://registry.npmjs.org","name":"pk","Name":"pk","version":"1.0.0","published":"2000-01-01T00:00:00Z"}`,
			`{"schema_version":1,"source":"https://registry.npmjs.org","name":"pk","version":"1.0.0","Published":"2000-01-01T00:00:00Z"}`,
			`{"schema_version":1,"source":"https://registry.npmjs.org","name":"pk","version":"1.0.0","published":"2000-01-01T00:00:00Z"} {"x":1}`,
			`{"schema_version":1,"source":"https://registry.npmjs.org","name":"pk","version":"1.0.0","published":"2000-01-01T00:00:00Z"}}`,
			`not json`,
		} {
			state := privateState(t)
			path := plant(t, state)
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if asked(state) {
				t.Fatalf("a bad entry was trusted: %s", body)
			}
		}
	})
	t.Run("a state directory that is not private", func(t *testing.T) {
		state := privateState(t)
		plant(t, state)
		os.Chmod(state, 0o777)
		defer os.Chmod(state, 0o700)
		if asked(state) {
			t.Fatal("a world-writable state directory was trusted")
		}
		// and nothing is written below it
		PublishCache{StateDir: state}.Put(cacheSource, "x", "1.0.0", published)
		if _, ok := (PublishCache{StateDir: state}).Get(cacheSource, "x", "1.0.0"); ok {
			t.Fatal("an entry was written below an untrusted state directory")
		}
	})
	t.Run("an ignored entry is replaced by what was read", func(t *testing.T) {
		state := privateState(t)
		path := plant(t, state)
		os.Chmod(path, 0o644)
		PublishCache{StateDir: state}.Put(cacheSource, "pk", "1.0.0", published.Add(time.Hour))
		got, ok := PublishCache{StateDir: state}.Get(cacheSource, "pk", "1.0.0")
		if !ok || !got.Equal(published.Add(time.Hour)) {
			t.Fatalf("the bad entry was not replaced: %v %v", got, ok)
		}
	})
}
