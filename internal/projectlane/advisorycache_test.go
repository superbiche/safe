//go:build linux

package projectlane

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// the entries' modification times are the real clock's: the test's "now" is the real one too
var advisoryNow = time.Now().Truncate(time.Second)

func adv(id, modified, pkg string) AdvisoryKey {
	return AdvisoryKey{ID: id, Modified: modified, Package: pkg}
}

func advReading(key AdvisoryKey, severity string, fetched time.Time) AdvisoryReading {
	return AdvisoryReading{AdvisoryKey: key, Severity: severity, Fetched: fetched.Unix()}
}

func advPath(state, classifier string, key AdvisoryKey) string {
	return filepath.Join(state, advisoryDir, advisoryEntryName(classifier, key))
}

func TestAdvisoryCacheRoundTripAndWhatTheKeyHolds(t *testing.T) {
	state := privateState(t)
	cache := AdvisoryCache{StateDir: state}
	key := adv("GHSA-aaaa", "2026-09-10T03:49:55.225771Z", "left-pad")
	cache.Put("c1", []AdvisoryReading{advReading(key, "high", advisoryNow.Add(-time.Hour))}, advisoryNow)
	hits := cache.Get("c1", []AdvisoryKey{key}, advisoryNow)
	if len(hits) != 1 || hits[0].Severity != "high" || hits[0].Withdrawn || hits[0].Fetched != advisoryNow.Add(-time.Hour).Unix() {
		t.Fatalf("round trip: %+v", hits)
	}
	info, err := os.Stat(advPath(state, "c1", key))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("entry: %v %v", info, err)
	}
	if info, err := os.Stat(filepath.Join(state, advisoryDir)); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("directory: %v %v", info, err)
	}
	// every part of the key matters: another stamp, another package, another advisory, another classifier
	for _, miss := range []struct {
		classifier string
		key        AdvisoryKey
	}{
		{"c1", adv("GHSA-aaaa", "2026-09-10T03:49:55.225772Z", "left-pad")},
		{"c1", adv("GHSA-aaaa", "2026-09-10T03:49:55.225771Z", "other")},
		{"c1", adv("GHSA-bbbb", "2026-09-10T03:49:55.225771Z", "left-pad")},
		{"c2", key},
	} {
		if got := cache.Get(miss.classifier, []AdvisoryKey{miss.key}, advisoryNow); len(got) != 0 {
			t.Fatalf("an entry answered for %+v", miss)
		}
	}
	// a withdrawn record is stored as that fact, with no band
	wkey := adv("GHSA-wwww", "2026-01-01T00:00:00Z", "left-pad")
	cache.Put("c1", []AdvisoryReading{{AdvisoryKey: wkey, Withdrawn: true, Fetched: advisoryNow.Unix()}}, advisoryNow)
	if got := cache.Get("c1", []AdvisoryKey{wkey}, advisoryNow); len(got) != 1 || !got[0].Withdrawn || got[0].Severity != "" {
		t.Fatalf("withdrawn: %+v", got)
	}
}

func TestAdvisoryCacheTrustsAnEntryForADayAtMostAndNeverFromTheFuture(t *testing.T) {
	key := adv("GHSA-aaaa", "s", "p")
	for _, tc := range []struct {
		name    string
		fetched time.Time
		now     time.Time
		hit     bool
	}{
		{"fresh", advisoryNow.Add(-time.Minute), advisoryNow, true},
		{"one second inside the day", advisoryNow.Add(-AdvisoryMaxAge + time.Second), advisoryNow, true},
		{"exactly a day", advisoryNow.Add(-AdvisoryMaxAge), advisoryNow, false},
		{"older than a day", advisoryNow.Add(-AdvisoryMaxAge - time.Hour), advisoryNow, false},
		{"dated in the future", advisoryNow.Add(time.Minute), advisoryNow, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := privateState(t)
			cache := AdvisoryCache{StateDir: state}
			// written when it was fetched, read at tc.now
			cache.Put("c", []AdvisoryReading{advReading(key, "low", tc.fetched)}, tc.fetched)
			if tc.fetched.After(tc.now) {
				// Put refuses a reading from the future; plant the file the way a forger would
				cache.Put("c", []AdvisoryReading{advReading(key, "low", tc.now)}, tc.now)
				path := advPath(state, "c", key)
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				forged := []byte(replaceOnce(string(raw), fmt.Sprintf(`"fetched":%d`, tc.now.Unix()), fmt.Sprintf(`"fetched":%d`, tc.fetched.Unix())))
				if err := os.WriteFile(path, forged, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			got := cache.Get("c", []AdvisoryKey{key}, tc.now)
			if (len(got) == 1) != tc.hit {
				t.Fatalf("hit=%v, want %v", len(got) == 1, tc.hit)
			}
		})
	}
}

func replaceOnce(s, old, repl string) string {
	for i := 0; i+len(old) <= len(s); i++ {
		if s[i:i+len(old)] == old {
			return s[:i] + repl + s[i+len(old):]
		}
	}
	return s
}

func TestAdvisoryCacheIgnoresWhatFailsItsChecks(t *testing.T) {
	key := adv("GHSA-aaaa", "stamp", "pkg")
	plant := func(t *testing.T) (string, string) {
		t.Helper()
		state := privateState(t)
		AdvisoryCache{StateDir: state}.Put("c", []AdvisoryReading{advReading(key, "critical", advisoryNow)}, advisoryNow)
		return state, advPath(state, "c", key)
	}
	asked := func(state string) bool {
		return len(AdvisoryCache{StateDir: state}.Get("c", []AdvisoryKey{key}, advisoryNow)) == 1
	}
	if state, _ := plant(t); !asked(state) {
		t.Fatal("a good entry was ignored")
	}
	for _, mode := range []os.FileMode{0o644, 0o640, 0o660, 0o400, 0o600 | os.ModeSetuid} {
		state, path := plant(t)
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if asked(state) {
			t.Fatalf("an entry of mode %v was trusted", mode)
		}
	}
	rewrite := func(content string) bool {
		state, path := plant(t)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return asked(state)
	}
	good := func(extra string) string {
		return fmt.Sprintf(`{"schema_version":1,"classifier":"c","id":"GHSA-aaaa","modified":"stamp","package":"pkg","severity":"critical","withdrawn":false,"fetched":%d%s}`, advisoryNow.Unix(), extra)
	}
	if !rewrite(good("")) {
		t.Fatal("the reference document was ignored")
	}
	for name, content := range map[string]string{
		"empty":                          "",
		"corrupt":                        "{not json",
		"a second document":              good("") + good(""),
		"an unknown member":              good(`,"extra":1`),
		"a repeated member":              good(`,"severity":"low"`),
		"another schema":                 fmt.Sprintf(`{"schema_version":2,"classifier":"c","id":"GHSA-aaaa","modified":"stamp","package":"pkg","severity":"critical","withdrawn":false,"fetched":%d}`, advisoryNow.Unix()),
		"another advisory":               fmt.Sprintf(`{"schema_version":1,"classifier":"c","id":"GHSA-zzzz","modified":"stamp","package":"pkg","severity":"critical","withdrawn":false,"fetched":%d}`, advisoryNow.Unix()),
		"another stamp":                  fmt.Sprintf(`{"schema_version":1,"classifier":"c","id":"GHSA-aaaa","modified":"other","package":"pkg","severity":"critical","withdrawn":false,"fetched":%d}`, advisoryNow.Unix()),
		"another classifier":             fmt.Sprintf(`{"schema_version":1,"classifier":"d","id":"GHSA-aaaa","modified":"stamp","package":"pkg","severity":"critical","withdrawn":false,"fetched":%d}`, advisoryNow.Unix()),
		"a band safe never writes":       fmt.Sprintf(`{"schema_version":1,"classifier":"c","id":"GHSA-aaaa","modified":"stamp","package":"pkg","severity":"unknown","withdrawn":false,"fetched":%d}`, advisoryNow.Unix()),
		"a withdrawn record with a band": fmt.Sprintf(`{"schema_version":1,"classifier":"c","id":"GHSA-aaaa","modified":"stamp","package":"pkg","severity":"critical","withdrawn":true,"fetched":%d}`, advisoryNow.Unix()),
		"no fetch time":                  `{"schema_version":1,"classifier":"c","id":"GHSA-aaaa","modified":"stamp","package":"pkg","severity":"critical","withdrawn":false}`,
	} {
		if rewrite(content) {
			t.Fatalf("%s: trusted", name)
		}
	}
	t.Run("a link in place of the entry", func(t *testing.T) {
		state, path := plant(t)
		target := filepath.Join(t.TempDir(), "elsewhere")
		raw, _ := os.ReadFile(path)
		_ = os.WriteFile(target, raw, 0o600)
		_ = os.Remove(path)
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if asked(state) {
			t.Fatal("a linked entry was trusted")
		}
	})
	t.Run("an entry that is a directory", func(t *testing.T) {
		state, path := plant(t)
		_ = os.Remove(path)
		_ = os.Mkdir(path, 0o700)
		if asked(state) {
			t.Fatal("a directory was trusted")
		}
	})
	t.Run("a directory writable by others", func(t *testing.T) {
		state, _ := plant(t)
		if err := os.Chmod(filepath.Join(state, advisoryDir), 0o770); err != nil {
			t.Fatal(err)
		}
		if asked(state) {
			t.Fatal("a group-writable directory was trusted")
		}
	})
	t.Run("a linked directory", func(t *testing.T) {
		state, _ := plant(t)
		real := filepath.Join(state, advisoryDir)
		moved := filepath.Join(state, "moved")
		if err := os.Rename(real, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(moved, real); err != nil {
			t.Fatal(err)
		}
		if asked(state) {
			t.Fatal("a linked directory was trusted")
		}
	})
	t.Run("a state directory that is open to others", func(t *testing.T) {
		state, _ := plant(t)
		if err := os.Chmod(state, 0o777); err != nil {
			t.Fatal(err)
		}
		if asked(state) {
			t.Fatal("an open state directory was trusted")
		}
	})
	t.Run("no state directory", func(t *testing.T) {
		if got := (AdvisoryCache{}).Get("c", []AdvisoryKey{key}, advisoryNow); len(got) != 0 {
			t.Fatal("an answer without a store")
		}
		if got := (AdvisoryCache{StateDir: "relative"}).Get("c", []AdvisoryKey{key}, advisoryNow); len(got) != 0 {
			t.Fatal("an answer for a relative path")
		}
	})
}

func TestAdvisoryCachePutStoresNothingItShouldNot(t *testing.T) {
	state := privateState(t)
	cache := AdvisoryCache{StateDir: state}
	key := func(n string) AdvisoryKey { return adv("GHSA-"+n, "s", "p") }
	cache.Put("c", []AdvisoryReading{
		advReading(key("unknown"), "unknown", advisoryNow),
		advReading(key("empty"), "", advisoryNow),
		advReading(key("future"), "low", advisoryNow.Add(time.Second)),
		advReading(key("old"), "low", advisoryNow.Add(-AdvisoryMaxAge)),
		{AdvisoryKey: key("withdrawnband"), Severity: "high", Withdrawn: true, Fetched: advisoryNow.Unix()},
		advReading(adv("", "s", "p"), "low", advisoryNow),
		advReading(adv("GHSA-x", "line\nbreak", "p"), "low", advisoryNow),
		advReading(key("good"), "low", advisoryNow),
	}, advisoryNow)
	names, err := os.ReadDir(filepath.Join(state, advisoryDir))
	if err != nil || len(names) != 1 {
		t.Fatalf("stored %d entries (%v), want only the good one", len(names), err)
	}
}

func TestAdvisoryCacheAHitWritesNothing(t *testing.T) {
	state := privateState(t)
	cache := AdvisoryCache{StateDir: state}
	key := adv("GHSA-aaaa", "s", "p")
	cache.Put("c", []AdvisoryReading{advReading(key, "low", advisoryNow)}, advisoryNow)
	dir := filepath.Join(state, advisoryDir)
	old := advisoryNow.Add(-time.Hour)
	if err := os.Chtimes(advPath(state, "c", key), old, old); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadDir(dir)
	if len(cache.Get("c", []AdvisoryKey{key}, advisoryNow)) != 1 {
		t.Fatal("no hit")
	}
	after, _ := os.ReadDir(dir)
	info, _ := os.Stat(advPath(state, "c", key))
	if len(before) != len(after) || !info.ModTime().Equal(old) {
		t.Fatalf("a hit changed the store: %d -> %d entries, mtime %v", len(before), len(after), info.ModTime())
	}
}

func TestAdvisoryCacheIsBoundedAndPruned(t *testing.T) {
	state := privateState(t)
	cache := AdvisoryCache{StateDir: state}
	dir := filepath.Join(state, advisoryDir)
	var first []AdvisoryReading
	for i := 0; i < AdvisoryCap; i++ {
		first = append(first, advReading(adv(fmt.Sprintf("GHSA-%05d", i), "s", "p"), "low", advisoryNow))
	}
	cache.Put("c", first, advisoryNow)
	if names, _ := os.ReadDir(dir); len(names) != AdvisoryCap {
		t.Fatalf("%d entries after the cap's worth, want %d", len(names), AdvisoryCap)
	}
	// make the oldest one clearly the oldest, then add the 10,001st
	oldest := adv("GHSA-00000", "s", "p")
	when := advisoryNow.Add(-time.Hour)
	if err := os.Chtimes(advPath(state, "c", oldest), when, when); err != nil {
		t.Fatal(err)
	}
	extra := adv("GHSA-extra", "s", "p")
	cache.Put("c", []AdvisoryReading{advReading(extra, "low", advisoryNow)}, advisoryNow)
	if names, _ := os.ReadDir(dir); len(names) != AdvisoryCap {
		t.Fatalf("%d entries after the 10,001st, want %d", len(names), AdvisoryCap)
	}
	if len(cache.Get("c", []AdvisoryKey{oldest}, advisoryNow)) != 0 {
		t.Fatal("the oldest entry survived the 10,001st")
	}
	if len(cache.Get("c", []AdvisoryKey{extra}, advisoryNow)) != 1 {
		t.Fatal("the new entry was pruned")
	}
}

func TestAdvisoryCachePrunesWhatCanNeverBeTrustedAgain(t *testing.T) {
	state := privateState(t)
	cache := AdvisoryCache{StateDir: state}
	dir := filepath.Join(state, advisoryDir)
	stale := adv("GHSA-stale", "s", "p")
	cache.Put("c", []AdvisoryReading{advReading(stale, "low", advisoryNow)}, advisoryNow)
	long := advisoryNow.Add(-2 * AdvisoryMaxAge)
	_ = os.Chtimes(advPath(state, "c", stale), long, long)
	leftover := filepath.Join(dir, ".new-abandoned")
	_ = os.WriteFile(leftover, []byte("x"), 0o600)
	_ = os.Chtimes(leftover, advisoryNow.Add(-time.Hour), advisoryNow.Add(-time.Hour))
	fresh := filepath.Join(dir, ".new-inflight")
	_ = os.WriteFile(fresh, []byte("x"), 0o600)
	_ = os.Chtimes(fresh, advisoryNow, advisoryNow)
	foreign := filepath.Join(dir, "README")
	_ = os.WriteFile(foreign, []byte("not ours"), 0o600)
	_ = os.Chtimes(foreign, long, long)
	cache.Put("c", []AdvisoryReading{advReading(adv("GHSA-new", "s", "p"), "low", advisoryNow)}, advisoryNow)
	for path, want := range map[string]bool{advPath(state, "c", stale): false, leftover: false, fresh: true, foreign: true} {
		_, err := os.Lstat(path)
		if (err == nil) != want {
			t.Fatalf("%s: present=%v, want %v", filepath.Base(path), err == nil, want)
		}
	}
}
