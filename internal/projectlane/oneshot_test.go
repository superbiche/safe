//go:build linux

package projectlane

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func oneShotHome(t *testing.T) (OneShotStore, string) {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
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

func inDir(t *testing.T, dir string) {
	t.Helper()
	old, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
}

func storeFile(home string) string {
	return filepath.Join(home, ".config", "safe", "run", OneShotStoreFile)
}

func TestOneShotRoundTripAndAncestors(t *testing.T) {
	store, _ := oneShotHome(t)
	root := oneShotProject(t, "root")
	member := filepath.Join(root, "pkg")
	if err := os.MkdirAll(member, 0o755); err != nil {
		t.Fatal(err)
	}
	inDir(t, member)
	if store.CheckHere() != OneShotNotPin {
		t.Fatal("pinned before it was added")
	}
	addOne(t, store, root)
	// the directory the command runs in is below the pin: the first question (data alone) says so
	if store.CheckHere() != OneShotPinned {
		t.Fatal("an ancestor that is a pin was not found")
	}
	// the second question: npm's line must name a stored pin by identity, however the command was typed
	if store.VerifyRoot([]byte(root+"/node_modules\n")) != OneShotPinned {
		t.Fatal("the pinned root's line was not honoured")
	}
	for name, line := range map[string]string{
		"the member (not a pin)": member + "/node_modules\n",
		"a global line":          root + "/lib/node_modules\n",
		"two lines":              root + "/node_modules\n" + root + "/node_modules\n",
		"no node_modules":        root + "\n",
		"a relative line":        "node_modules\n",
		"empty":                  "",
		"a line with a NUL":      root + "/node_modules\x00\n",
	} {
		if store.VerifyRoot([]byte(line)) == OneShotPinned {
			t.Fatalf("%s was honoured", name)
		}
	}
	rows, err := store.List()
	if err != nil || len(rows) != 1 || rows[0].State != "honoured" {
		t.Fatalf("%+v %v", rows, err)
	}
	removed, err := store.Remove([]string{root})
	if err != nil || len(removed) != 1 || store.CheckHere() != OneShotNotPin {
		t.Fatalf("%v %v", removed, err)
	}
}

// A line that names the pinned directory through a link is the same directory (the core opens it, never reads it as text); a line
// that names a replaced directory is not honoured.
func TestOneShotVerifyRootOpensTheDirectory(t *testing.T) {
	store, _ := oneShotHome(t)
	root := oneShotProject(t, "root")
	addOne(t, store, root)
	link := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if store.VerifyRoot([]byte(link+"/node_modules\n")) != OneShotPinned {
		t.Fatal("a link to the pinned directory is the pinned directory")
	}
	other := oneShotProject(t, "other")
	if store.VerifyRoot([]byte(other+"/node_modules\n")) == OneShotPinned {
		t.Fatal("another project was honoured")
	}
	// a replaced directory: same path, another inode
	if err := os.Rename(root, root+".old"); err != nil { // kept alive, so the new directory cannot reuse its inode
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if store.VerifyRoot([]byte(root+"/node_modules\n")) == OneShotPinned {
		t.Fatal("a replaced directory was honoured")
	}
	inDir(t, root)
	if store.CheckHere() != OneShotReplaced {
		t.Fatalf("a replaced directory is not reported: %d", store.CheckHere())
	}
}

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

// `link/..` is the parent of what the link leads to, as the kernel says, never the textual parent of the link.
func TestOneShotOperandsAreResolvedByTheKernel(t *testing.T) {
	store, _ := oneShotHome(t)
	elsewhere := oneShotProject(t, "elsewhere")
	nested := filepath.Join(elsewhere, "inner")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	here := oneShotProject(t, "here")
	if err := os.Symlink(nested, filepath.Join(here, "link")); err != nil {
		t.Fatal(err)
	}
	plans, err := Resolve([]string{here + "/link/.."}, true)
	if err != nil || len(plans) != 1 || plans[0].Path != elsewhere {
		t.Fatalf("link/.. resolved to %+v %v (want %s)", plans, err, elsewhere)
	}
	if err := store.Add(plans); err != nil {
		t.Fatal(err)
	}
	if removed, err := store.Remove([]string{here + "/link/.."}); err != nil || removed[0] != elsewhere {
		t.Fatalf("%v %v", removed, err)
	}
}

func TestOneShotStoreThatCannotBeTrustedPinsNothing(t *testing.T) {
	store, home := oneShotHome(t)
	dir := oneShotProject(t, "p")
	addOne(t, store, dir)
	inDir(t, dir)
	file := storeFile(home)
	for name, mode := range map[string]os.FileMode{"group-writable": 0o664, "world-readable": 0o644} {
		if err := os.Chmod(file, mode); err != nil {
			t.Fatal(err)
		}
		if store.CheckHere() != OneShotNotPin {
			t.Fatalf("a %s store was honoured", name)
		}
		if _, err := store.List(); err == nil {
			t.Fatalf("list did not report a %s store", name)
		}
	}
	if err := os.Chmod(file, 0o600); err != nil {
		t.Fatal(err)
	}
	oneShotEUID = func() int { return os.Geteuid() + 1 }
	if store.CheckHere() != OneShotNotPin {
		t.Fatal("a store of another owner was honoured")
	}
	if err := store.Add(mustResolve(t, dir)); err == nil {
		t.Fatal("a writer used a directory of another owner")
	}
	oneShotEUID = os.Geteuid
	if store.CheckHere() != OneShotPinned {
		t.Fatal("control: the trusted store is not honoured")
	}
	// a hard link to the store file
	if err := os.Link(file, file+".twin"); err != nil {
		t.Fatal(err)
	}
	if store.CheckHere() != OneShotNotPin {
		t.Fatal("a store with a second link was honoured")
	}
	_ = os.Remove(file + ".twin")
	// the run directory reached through a link
	checkout := t.TempDir()
	if err := os.Rename(filepath.Join(home, ".config", "safe"), filepath.Join(checkout, "safe-real")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(checkout, "safe-real"), filepath.Join(home, ".config", "safe")); err != nil {
		t.Fatal(err)
	}
	if store.CheckHere() != OneShotNotPin {
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

// The lock file is checked like the data file.
func TestOneShotLockFileIsChecked(t *testing.T) {
	store, home := oneShotHome(t)
	dir := oneShotProject(t, "p")
	lock := filepath.Join(home, ".config", "safe", "run", oneShotLockFile)
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, lock); err != nil {
		t.Fatal(err)
	}
	if err := store.Add(mustResolve(t, dir)); !errors.Is(err, ErrNotRecorded) {
		t.Fatalf("a lock file that is a link was used: %v", err)
	}
	_ = os.Remove(lock)
	if err := os.WriteFile(lock, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(lock, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := store.Add(mustResolve(t, dir)); !errors.Is(err, ErrNotRecorded) {
		t.Fatalf("a lock file open to others was used: %v", err)
	}
}

// The check and the read are on the same file: replacing the run directory between them changes nothing.
func TestOneShotReadsTheFileItChecked(t *testing.T) {
	store, home := oneShotHome(t)
	dir := oneShotProject(t, "p")
	addOne(t, store, dir)
	inDir(t, dir)
	run := filepath.Join(home, ".config", "safe", "run")
	afterChain = func() {
		afterChain = nil
		_ = os.Rename(run, run+".held")
		_ = os.MkdirAll(run, 0o700)
	}
	defer func() { afterChain = nil }()
	if store.CheckHere() != OneShotPinned {
		t.Fatal("the read followed the replaced pathname instead of the held directory")
	}
}

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

// What is recorded is what was shown; control characters are never recorded.
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
	if len(rows) != 1 || rows[0].State != "honoured" || !strings.HasSuffix(rows[0].Path, `a\b`) {
		t.Fatalf("a backslash in a name: %+v", rows)
	}
}

// One strict document: a repeated member, text after it, an unknown member, a second spelling, a repeated path and the old
// unversioned shape are all refused as a store that cannot be trusted.
func TestOneShotDocumentIsStrict(t *testing.T) {
	store, home := oneShotHome(t)
	dir := oneShotProject(t, "p")
	inDir(t, dir)
	good := `{"schema_version":1,"projects":[{"path":"` + dir + `","dev":1,"inode":2,"added":"x"}]}`
	write := func(content string) {
		if err := os.WriteFile(storeFile(home), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(storeFile(home), 0o600)
	}
	write(good)
	if _, err := store.List(); err != nil {
		t.Fatalf("control: %v", err)
	}
	for name, doc := range map[string]string{
		"a repeated member":         `{"schema_version":1,"schema_version":1,"projects":[]}`,
		"a repeated entry member":   `{"schema_version":1,"projects":[{"path":"/a","path":"/b","dev":1,"inode":2,"added":"x"}]}`,
		"text after the document":   good + "\n{}",
		"an unknown member":         `{"schema_version":1,"projects":[],"extra":1}`,
		"a second spelling":         `{"schema_version":1,"Projects":[]}`,
		"a repeated path":           `{"schema_version":1,"projects":[{"path":"/a","dev":1,"inode":2,"added":"x"},{"path":"/a","dev":1,"inode":3,"added":"y"}]}`,
		"the old unversioned shape": `{"projects":{"/a":{"added":"x","dev":1,"inode":2}}}`,
		"a wrong version":           `{"schema_version":2,"projects":[]}`,
		"a relative path":           `{"schema_version":1,"projects":[{"path":"a","dev":1,"inode":2,"added":"x"}]}`,
	} {
		write(doc)
		if _, err := store.List(); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
	// larger than the limit
	write(`{"schema_version":1,"projects":[],"pad":"` + strings.Repeat("x", OneShotLimit) + `"}`)
	if _, err := store.List(); err == nil {
		t.Fatal("a document over the limit was read")
	}
}

// A result larger than the limit refuses before the rename and keeps the previous document.
func TestOneShotWriterKeepsThePreviousDocumentWhenTheResultIsTooLarge(t *testing.T) {
	store, home := oneShotHome(t)
	base := t.TempDir()
	long := strings.Repeat("d", 200)
	var plans []OneShotPlan
	for i := 0; i < 400; i++ {
		dir := filepath.Join(base, long+strings.Repeat("x", 3), string(rune('a'+i%26)), strings.Repeat("y", i%7), itoa(i))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Skip("cannot build long paths here")
		}
		_ = os.WriteFile(filepath.Join(dir, "package.json"), []byte("{}"), 0o644)
		p, err := Resolve([]string{dir}, true)
		if err != nil {
			t.Skip(err)
		}
		plans = append(plans, p...)
	}
	first := plans[:50]
	if err := store.Add(first); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(storeFile(home))
	err := store.Add(plans)
	if !errors.Is(err, ErrNotRecorded) {
		t.Fatalf("an oversize result was published: %v", err)
	}
	after, _ := os.ReadFile(storeFile(home))
	if string(before) != string(after) {
		t.Fatal("the previous document was not kept")
	}
}

func itoa(i int) string {
	return strings.TrimLeft(strings.Replace(strings.Repeat("0", 4)+string(rune('0'+i%10)), "0", "", 0), "")
}

// A failed directory sync after the rename is told apart: the change is visible, durability is uncertain.
func TestOneShotFailureAfterTheRenameIsToldApart(t *testing.T) {
	store, _ := oneShotHome(t)
	dir := oneShotProject(t, "p")
	err := store.Add(mustResolve(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	// after the rename: the directory sync fails: visible, durability uncertain, and told apart from "not recorded"
	other := oneShotProject(t, "after")
	dirSync = func(*dirHandle) error { return errors.New("sync failed") }
	err = store.Add(mustResolve(t, other))
	dirSync = func(d *dirHandle) error { return d.f.Sync() }
	if !errors.Is(err, ErrDurabilityUncertain) || errors.Is(err, ErrNotRecorded) {
		t.Fatalf("a failed sync after the rename: %v", err)
	}
	if rows, _ := store.List(); len(rows) != 2 {
		t.Fatalf("the change is visible after the rename: %+v", rows)
	}
	// before the rename: a failure says NOT recorded and changes nothing
	store2, home2 := oneShotHome(t)
	if err := os.Chmod(filepath.Join(home2, ".config", "safe", "run"), 0o500); err != nil {
		t.Fatal(err)
	}
	if err := store2.Add(mustResolve(t, dir)); !errors.Is(err, ErrNotRecorded) || errors.Is(err, ErrDurabilityUncertain) {
		t.Fatalf("a write that could not start: %v", err)
	}
	_ = os.Chmod(filepath.Join(home2, ".config", "safe", "run"), 0o700)
	if rows, _ := store2.List(); len(rows) != 0 {
		t.Fatal("something was recorded")
	}
}

// The staged file is created with its final mode: never wider, even under a permissive mask.
func TestOneShotStagedFileIsNeverWiderThanItsFinalMode(t *testing.T) {
	_, home := oneShotHome(t)
	run := filepath.Join(home, ".config", "safe", "run")
	handle, err := openDirPath(run)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	old := syscallUmask(0)
	defer syscallUmask(old)
	if _, err := handle.createExclusiveMode("staged", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(run, "staged"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", info.Mode(), err)
	}
}

func syscallUmask(mask int) int { return umaskCall(mask) }

// The FILE's owner is checked on its own (the directories above it are the user's).
func TestOneShotStoreFileOfAnotherOwnerIsRefused(t *testing.T) {
	store, _ := oneShotHome(t)
	dir := oneShotProject(t, "p")
	addOne(t, store, dir)
	inDir(t, dir)
	afterChain = func() { afterChain = nil; oneShotEUID = func() int { return os.Geteuid() + 1 } }
	defer func() { afterChain = nil; oneShotEUID = os.Geteuid }()
	if store.CheckHere() != OneShotNotPin {
		t.Fatal("a store file of another owner was honoured")
	}
}

// Every directory of the chain is closed to group and others, one by one.
func TestOneShotEveryDirectoryOfTheChainMustBeClosedToOthers(t *testing.T) {
	store, home := oneShotHome(t)
	dir := oneShotProject(t, "p")
	addOne(t, store, dir)
	inDir(t, dir)
	for _, rel := range []string{"", ".config", ".config/safe", ".config/safe/run"} {
		path := filepath.Join(home, rel)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o775); err != nil {
			t.Fatal(err)
		}
		if store.CheckHere() != OneShotNotPin {
			t.Fatalf("the store was honoured with %q writable by group", rel)
		}
		if err := os.Chmod(path, info.Mode().Perm()); err != nil {
			t.Fatal(err)
		}
	}
	if store.CheckHere() != OneShotPinned {
		t.Fatal("control")
	}
}
