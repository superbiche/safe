//go:build linux

package projectlane

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func oneShotHome(t *testing.T) (OneShotStore, string) {
	t.Helper()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".config", "safe", "run"), 0o700); err != nil {
		t.Fatal(err)
	}
	return OneShotStore{Home: home}, home
}

func oneShotProject(t *testing.T, name string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	return real
}

func addOne(t *testing.T, store OneShotStore, dir string) {
	t.Helper()
	plans, err := Resolve([]string{dir}, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Add(plans); err != nil {
		t.Fatal(err)
	}
}

func TestOneShotRoundTrip(t *testing.T) {
	store, _ := oneShotHome(t)
	dir := oneShotProject(t, "p")
	if store.Check(dir) != OneShotNotPin {
		t.Fatal("pinned before it was added")
	}
	addOne(t, store, dir)
	if store.Check(dir) != OneShotPinned {
		t.Fatal("not pinned after add")
	}
	rows, err := store.List()
	if err != nil || len(rows) != 1 || rows[0].State != "honoured" {
		t.Fatalf("%+v %v", rows, err)
	}
	removed, err := store.Remove([]string{dir})
	if err != nil || len(removed) != 1 || store.Check(dir) != OneShotNotPin {
		t.Fatalf("%v %v", removed, err)
	}
}

// A directory replaced by another (or by a link) is not honoured; remove works by the exact stored key even when the path is a link now.
func TestOneShotReplacedDirectoryAndRemoveByStoredKey(t *testing.T) {
	store, _ := oneShotHome(t)
	dir := oneShotProject(t, "p")
	addOne(t, store, dir)
	other := oneShotProject(t, "other")
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, dir); err != nil {
		t.Fatal(err)
	}
	if store.Check(dir) != OneShotReplaced {
		t.Fatal("a link in place of the directory was honoured")
	}
	rows, _ := store.List()
	if len(rows) != 1 || rows[0].State != "not honoured (directory replaced)" {
		t.Fatalf("%+v", rows)
	}
	removed, err := store.Remove([]string{dir})
	if err != nil || len(removed) != 1 || removed[0] != dir {
		t.Fatalf("remove by stored key: %v %v", removed, err)
	}
	if rows, _ := store.List(); len(rows) != 0 {
		t.Fatalf("the old key stayed: %+v", rows)
	}
}

// A link anywhere in the chain below the home, a foreign owner, a file others can write: nothing is pinned.
func TestOneShotStoreThatCannotBeTrustedPinsNothing(t *testing.T) {
	store, home := oneShotHome(t)
	dir := oneShotProject(t, "p")
	addOne(t, store, dir)
	run := filepath.Join(home, ".config", "safe", "run")
	file := filepath.Join(run, OneShotStoreFile)
	// group-writable file
	if err := os.Chmod(file, 0o664); err != nil {
		t.Fatal(err)
	}
	if store.Check(dir) != OneShotNotPin {
		t.Fatal("a group-writable store was honoured")
	}
	if _, err := store.List(); err == nil {
		t.Fatal("list did not report an untrusted store")
	}
	if err := os.Chmod(file, 0o600); err != nil {
		t.Fatal(err)
	}
	// foreign owner
	oneShotEUID = func() int { return os.Geteuid() + 1 }
	if store.Check(dir) != OneShotNotPin {
		t.Fatal("a store of another owner was honoured")
	}
	if err := store.Add(nil); err == nil {
		t.Fatal("a writer used a directory of another owner")
	}
	oneShotEUID = os.Geteuid
	if store.Check(dir) != OneShotPinned {
		t.Fatal("control: the trusted store is not honoured")
	}
	// the run directory reached through a link (leading into a checkout)
	checkout := t.TempDir()
	if err := os.MkdirAll(filepath.Join(checkout, "safe"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(home, ".config", "safe"), filepath.Join(checkout, "safe-real")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(checkout, "safe-real"), filepath.Join(home, ".config", "safe")); err != nil {
		t.Fatal(err)
	}
	if store.Check(dir) != OneShotNotPin {
		t.Fatal("a store reached through a link was honoured")
	}
	if err := store.Add(mustResolve(t, dir)); err == nil {
		t.Fatal("a writer followed a link in the chain")
	}
}

func mustResolve(t *testing.T, dir string) []OneShotPlan {
	t.Helper()
	plans, err := Resolve([]string{dir}, true)
	if err != nil {
		t.Fatal(err)
	}
	return plans
}

// The check and the read are on the same file: replacing the run directory between them changes nothing.
func TestOneShotReadsTheFileItChecked(t *testing.T) {
	store, home := oneShotHome(t)
	dir := oneShotProject(t, "p")
	addOne(t, store, dir)
	run := filepath.Join(home, ".config", "safe", "run")
	afterChain = func() {
		afterChain = nil
		_ = os.Rename(run, run+".held")
		_ = os.MkdirAll(run, 0o700)
	}
	defer func() { afterChain = nil }()
	if store.Check(dir) != OneShotPinned {
		t.Fatal("the read followed the replaced pathname instead of the held directory")
	}
}

// Two writers at once: a withdrawal is not undone by an add that read the old document.
func TestOneShotWritersAreSerialised(t *testing.T) {
	store, _ := oneShotHome(t)
	a, b := oneShotProject(t, "a"), oneShotProject(t, "b")
	addOne(t, store, a)
	first := true
	var mu sync.Mutex
	afterRead = func() {
		mu.Lock()
		slow := first
		first = false
		mu.Unlock()
		if slow {
			time.Sleep(200 * time.Millisecond)
		}
	}
	defer func() { afterRead = nil }()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = store.Remove([]string{a}) }()
	go func() { time.Sleep(50 * time.Millisecond); defer wg.Done(); _ = store.Add(mustResolve(t, b)) }()
	wg.Wait()
	rows, err := store.List()
	if err != nil || len(rows) != 1 || rows[0].Path != b {
		t.Fatalf("a withdrawn pin came back, or the add was lost: %+v %v", rows, err)
	}
}

// What is recorded is what was shown: a directory that changed between the question and the commit records nothing; a newline or
// bytes that are not UTF-8 are never recorded; a backslash is just a byte.
func TestOneShotCommitsTheIdentityShownAndKeepsTheBytes(t *testing.T) {
	store, _ := oneShotHome(t)
	dir := oneShotProject(t, "p")
	plans := mustResolve(t, dir)
	plans[0].Inode++
	if err := store.Add(plans); err == nil {
		t.Fatal("a plan whose identity changed was recorded")
	}
	if rows, _ := store.List(); len(rows) != 0 {
		t.Fatal("something was recorded")
	}
	base := t.TempDir()
	// the sibling with the shortened name must never be the one pinned for a name that ends in a newline
	if err := os.MkdirAll(filepath.Join(base, "x\n"), 0o755); err == nil {
		_ = os.WriteFile(filepath.Join(base, "x\n", "package.json"), []byte("{}"), 0o644)
		if _, err := Resolve([]string{filepath.Join(base, "x\n")}, true); err == nil {
			t.Fatal("a name ending in a newline was accepted")
		}
	}
	back := filepath.Join(base, `a\b`)
	if err := os.MkdirAll(back, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(back, "package.json"), []byte("{}"), 0o644)
	addOne(t, store, back)
	rows, _ := store.List()
	if len(rows) != 1 || rows[0].Path != mustResolve(t, back)[0].Path || rows[0].State != "honoured" {
		t.Fatalf("a backslash in a name: %+v", rows)
	}
}
