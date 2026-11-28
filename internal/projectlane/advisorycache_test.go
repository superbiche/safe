//go:build linux

package projectlane

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
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

func TestAdvisoryCacheRemovesOnlyWhatItWrote(t *testing.T) {
	state := privateState(t)
	cache := AdvisoryCache{StateDir: state}
	dir := filepath.Join(state, advisoryDir)
	stale := adv("GHSA-stale", "s", "p")
	cache.Put("c", []AdvisoryReading{advReading(stale, "low", advisoryNow)}, advisoryNow)
	long := advisoryNow.Add(-2 * AdvisoryMaxAge)
	_ = os.Chtimes(advPath(state, "c", stale), long, long)
	// the writer's own leftover (".new-" and 32 lowercase hexadecimal digits), aged
	ours := filepath.Join(dir, ".new-0123456789abcdef0123456789abcdef")
	_ = os.WriteFile(ours, []byte("x"), 0o600)
	_ = os.Chtimes(ours, advisoryNow.Add(-time.Hour), advisoryNow.Add(-time.Hour))
	// the writer's own leftover, not aged: an interrupted write that may still be running
	inflight := filepath.Join(dir, ".new-fedcba9876543210fedcba9876543210")
	_ = os.WriteFile(inflight, []byte("x"), 0o600)
	_ = os.Chtimes(inflight, advisoryNow, advisoryNow)
	// names that are not the writer's: a prefix alone, a longer or shorter digest, upper case, a name of another kind, a file that is not ours
	var foreign []string
	for _, name := range []string{".new-abandoned", ".new-0123456789abcdef0123456789abcde", ".new-0123456789abcdef0123456789abcdef0", ".new-0123456789ABCDEF0123456789abcdef", "README", ".new-", "0123456789abcdef"} {
		path := filepath.Join(dir, name)
		_ = os.WriteFile(path, []byte("not ours"), 0o600)
		_ = os.Chtimes(path, long, long)
		foreign = append(foreign, path)
	}
	cache.Put("c", []AdvisoryReading{advReading(adv("GHSA-new", "s", "p"), "low", advisoryNow)}, advisoryNow)
	for path, want := range map[string]bool{advPath(state, "c", stale): false, ours: false, inflight: true} {
		_, err := os.Lstat(path)
		if (err == nil) != want {
			t.Fatalf("%s: present=%v, want %v", filepath.Base(path), err == nil, want)
		}
	}
	for _, path := range foreign {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("%s was removed, it is not the writer's", filepath.Base(path))
		}
	}
}

func TestAdvisoryCacheMakesRoomBeforeItWrites(t *testing.T) {
	state := privateState(t)
	cache := AdvisoryCache{StateDir: state}
	dir := filepath.Join(state, advisoryDir)
	var first []AdvisoryReading
	for i := 0; i < AdvisoryCap; i++ {
		first = append(first, advReading(adv(fmt.Sprintf("GHSA-%05d", i), "s", "p"), "low", advisoryNow))
	}
	cache.Put("c", first, advisoryNow)
	handle, err := cache.dir(false)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	// the room is made by the step before the writes: with the store full and three readings to come, three entries are gone already
	cache.makeRoom(handle, map[string]bool{
		advisoryEntryName("c", adv("GHSA-n1", "s", "p")): true, advisoryEntryName("c", adv("GHSA-n2", "s", "p")): true, advisoryEntryName("c", adv("GHSA-n3", "s", "p")): true,
	}, advisoryNow)
	if names, _ := os.ReadDir(dir); len(names) != AdvisoryCap-3 {
		t.Fatalf("%d entries after making room for three, want %d", len(names), AdvisoryCap-3)
	}
	// a request that alone is larger than the cap stores the cap's worth and no more
	var many []AdvisoryReading
	for i := 0; i < AdvisoryCap+5; i++ {
		many = append(many, advReading(adv(fmt.Sprintf("GHSA-many-%05d", i), "s", "p"), "low", advisoryNow))
	}
	cache.Put("c", many, advisoryNow)
	if names, _ := os.ReadDir(dir); len(names) > AdvisoryCap {
		t.Fatalf("%d entries, past the cap", len(names))
	}
}

func TestAdvisoryCacheIgnoresAnEntryThatIsNotWholeOrNotTyped(t *testing.T) {
	key := adv("GHSA-aaaa", "stamp", "pkg")
	now := advisoryNow.Unix()
	doc := func(withdrawn, severity string) string {
		parts := []string{`"schema_version":1`, `"classifier":"c"`, `"id":"GHSA-aaaa"`, `"modified":"stamp"`, `"package":"pkg"`, fmt.Sprintf(`"fetched":%d`, now)}
		if withdrawn != "-" {
			parts = append(parts, `"withdrawn":`+withdrawn)
		}
		if severity != "-" {
			parts = append(parts, `"severity":`+severity)
		}
		return "{" + joinComma(parts) + "}"
	}
	for name, tc := range map[string]struct {
		content string
		hit     bool
	}{
		"whole, banded":                       {doc("false", `"high"`), true},
		"whole, withdrawn":                    {doc("true", `""`), true},
		"no withdrawn member":                 {doc("-", `"high"`), false},
		"a null withdrawn":                    {doc("null", `"high"`), false},
		"a withdrawn entry with no severity":  {doc("true", "-"), false},
		"a null severity":                     {doc("false", "null"), false},
		"a string withdrawn":                  {doc(`"false"`, `"high"`), false},
		"a case variant of a required member": {`{"schema_version":1,"classifier":"c","id":"GHSA-aaaa","modified":"stamp","package":"pkg","Severity":"high","withdrawn":false,"fetched":` + fmt.Sprint(now) + `}`, false},
		"a stray closing delimiter":           {doc("false", `"high"`) + "}", false},
		"a float fetch time":                  {strings.Replace(doc("false", `"high"`), fmt.Sprint(now), fmt.Sprint(now)+".5", 1), false},
	} {
		state := privateState(t)
		AdvisoryCache{StateDir: state}.Put("c", []AdvisoryReading{advReading(key, "high", advisoryNow)}, advisoryNow)
		if err := os.WriteFile(advPath(state, "c", key), []byte(tc.content), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := len((AdvisoryCache{StateDir: state}).Get("c", []AdvisoryKey{key}, advisoryNow)) == 1; got != tc.hit {
			t.Fatalf("%s: hit=%v, want %v", name, got, tc.hit)
		}
	}
}

func joinComma(parts []string) string {
	out := ""
	for i, part := range parts {
		if i > 0 {
			out += ","
		}
		out += part
	}
	return out
}

func TestAdvisoryCachePutNeverWritesPastTheCap(t *testing.T) {
	state := privateState(t)
	cache := AdvisoryCache{StateDir: state}
	dir := filepath.Join(state, advisoryDir)
	var first []AdvisoryReading
	for i := 0; i < AdvisoryCap; i++ {
		first = append(first, advReading(adv(fmt.Sprintf("GHSA-%05d", i), "s", "p"), "low", advisoryNow))
	}
	cache.Put("c", first, advisoryNow)
	// at every moment a write begins (an interruption there leaves exactly what is on disk), the store holds no more than the cap
	var worst int
	advisoryHook = func(stage string) {
		if stage == "write" {
			if names, _ := os.ReadDir(dir); len(names) > worst {
				worst = len(names)
			}
		}
	}
	defer func() { advisoryHook = func(string) {} }()
	cache.Put("c", []AdvisoryReading{advReading(adv("GHSA-x1", "s", "p"), "low", advisoryNow), advReading(adv("GHSA-x2", "s", "p"), "low", advisoryNow), advReading(adv("GHSA-x3", "s", "p"), "low", advisoryNow)}, advisoryNow)
	if worst > AdvisoryCap {
		t.Fatalf("a write began with %d entries on disk, past the cap of %d", worst, AdvisoryCap)
	}
	if names, _ := os.ReadDir(dir); len(names) != AdvisoryCap {
		t.Fatalf("%d entries at the end, want %d", len(names), AdvisoryCap)
	}
}

// prefill writes n entries the way Put does (the same document, the same name, mode 0600) without its fsync, for the tests that need a store of a size
func prefill(t *testing.T, state, classifier string, from, n int) {
	t.Helper()
	dir := filepath.Join(state, advisoryDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for i := from; i < from+n; i++ {
		key := adv(fmt.Sprintf("GHSA-pre-%06d", i), "s", "p")
		raw, _ := json.Marshal(advisoryEntry{AdvisoryCacheSchema, classifier, key, "low", false, advisoryNow.Unix()})
		if err := os.WriteFile(filepath.Join(dir, advisoryEntryName(classifier, key)), append(raw, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func countEntries(t *testing.T, state string) int {
	t.Helper()
	names, err := os.ReadDir(filepath.Join(state, advisoryDir))
	if err != nil {
		t.Fatal(err)
	}
	return len(names)
}

func fresh(from, n int) []AdvisoryReading {
	var out []AdvisoryReading
	for i := from; i < from+n; i++ {
		out = append(out, advReading(adv(fmt.Sprintf("GHSA-new-%06d", i), "s", "p"), "moderate", advisoryNow))
	}
	return out
}

// Two writers (two projects' commands share the store) took a store of 9,600 to 10,400: one writer at a time, the count, the room and the writes under one lock.
func TestAdvisoryCacheTwoWritersKeepTheCap(t *testing.T) {
	state := privateState(t)
	prefill(t, state, "c", 0, 9600)
	cache := AdvisoryCache{StateDir: state}
	var wg sync.WaitGroup
	for _, start := range []int{0, 400} {
		wg.Add(1)
		go func(start int) {
			defer wg.Done()
			cache.Put("c", fresh(start, 400), advisoryNow)
		}(start)
	}
	wg.Wait()
	if n := countEntries(t, state); n > AdvisoryCap {
		t.Fatalf("%d entries after two writers, past the cap of %d", n, AdvisoryCap)
	}
}

// Refreshing entries that exist takes no room: a full store stays full of what it held, the refreshed ones included.
func TestAdvisoryCacheRefreshingEvictsNothing(t *testing.T) {
	state := privateState(t)
	prefill(t, state, "c", 0, AdvisoryCap)
	cache := AdvisoryCache{StateDir: state}
	var refresh []AdvisoryReading
	for i := 0; i < 400; i++ {
		refresh = append(refresh, advReading(adv(fmt.Sprintf("GHSA-pre-%06d", i), "s", "p"), "high", advisoryNow))
	}
	cache.Put("c", refresh, advisoryNow)
	if n := countEntries(t, state); n != AdvisoryCap {
		t.Fatalf("%d entries after refreshing 400 of a full store, want %d", n, AdvisoryCap)
	}
	for _, reading := range refresh {
		if got := cache.Get("c", []AdvisoryKey{reading.AdvisoryKey}, advisoryNow); len(got) != 1 || got[0].Severity != "high" {
			t.Fatalf("a refreshed reading is not there: %+v", got)
		}
	}
	// a mixed request: 100 refreshed and 100 new on a full store: the new ones take room (the 100 oldest of the OTHERS go), the refreshed ones stay even
	// when they are the oldest of all
	old := advisoryNow.Add(-time.Hour)
	for i := 0; i < 100; i++ {
		_ = os.Chtimes(advPath(state, "c", adv(fmt.Sprintf("GHSA-pre-%06d", i), "s", "p")), old, old)
	}
	cache.Put("c", append(refresh[:100:100], fresh(0, 100)...), advisoryNow)
	if n := countEntries(t, state); n != AdvisoryCap {
		t.Fatalf("%d entries after 100 refreshed and 100 new, want %d", n, AdvisoryCap)
	}
	for _, reading := range refresh[:100] {
		if got := cache.Get("c", []AdvisoryKey{reading.AdvisoryKey}, advisoryNow); len(got) != 1 {
			t.Fatalf("a refreshed reading was evicted by the room its own writer made: %+v", reading.AdvisoryKey)
		}
	}
}

// A writer that cannot take the lock within the bound writes nothing and returns: the command that called it does not fail.
func TestAdvisoryCacheWriterThatCannotLockWritesNothing(t *testing.T) {
	state := privateState(t)
	cache := AdvisoryCache{StateDir: state}
	cache.Put("c", fresh(0, 1), advisoryNow)
	held, err := os.Open(filepath.Join(state, advisoryDir))
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if err := syscall.Flock(int(held.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	old := advisoryLockWait
	advisoryLockWait = 150 * time.Millisecond
	defer func() { advisoryLockWait = old }()
	started := time.Now()
	cache.Put("c", fresh(10, 5), advisoryNow)
	if time.Since(started) > 5*time.Second {
		t.Fatalf("a writer that cannot lock waited %v", time.Since(started))
	}
	if n := countEntries(t, state); n != 1 {
		t.Fatalf("%d entries, the writer without the lock wrote some", n)
	}
	// the lock is not left behind by a writer that had it
	_ = syscall.Flock(int(held.Fd()), syscall.LOCK_UN)
	cache.Put("c", fresh(10, 5), advisoryNow)
	if n := countEntries(t, state); n != 6 {
		t.Fatalf("%d entries after the lock was free, want 6", n)
	}
}
