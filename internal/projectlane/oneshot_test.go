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

// verify puts npm's two answers (its prefix and its root, each one line) to the store.
func verify(store OneShotStore, prefix, root string) int {
	return store.VerifyAnswer([]byte(prefix+"\n"), []byte(root+"\n"))
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
	// the second question: npm's prefix and root must name a stored pin by identity, however the command was typed
	if verify(store, root, root+"/node_modules") != OneShotPinned {
		t.Fatal("the pinned root's answer was not honoured")
	}
	for name, answer := range map[string][2]string{
		"the member (not a pin)":              {member + "\n", member + "/node_modules\n"},
		"a global answer":                     {root + "\n", root + "/lib/node_modules\n"},
		"two root lines":                      {root + "\n", root + "/node_modules\n" + root + "/node_modules\n"},
		"two prefix lines":                    {root + "\n" + root + "\n", root + "/node_modules\n"},
		"a root that is not under the prefix": {root + "\n", member + "/node_modules\n"},
		"no node_modules":                     {root + "\n", root + "\n"},
		"a relative line":                     {"root\n", "node_modules\n"},
		"empty":                               {"", ""},
		"no final newline":                    {root, root + "/node_modules"},
		"a line with a NUL":                   {root + "\n", root + "/node_modules\x00\n"},
	} {
		if store.VerifyAnswer([]byte(answer[0]), []byte(answer[1])) == OneShotPinned {
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
	if verify(store, link, link+"/node_modules") != OneShotPinned {
		t.Fatal("a link to the pinned directory is the pinned directory")
	}
	other := oneShotProject(t, "other")
	if verify(store, other, other+"/node_modules") == OneShotPinned {
		t.Fatal("another project was honoured")
	}
	// a replaced directory: same path, another inode
	if err := os.Rename(root, root+".old"); err != nil { // kept alive, so the new directory cannot reuse its inode
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if verify(store, root, root+"/node_modules") == OneShotPinned {
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
	// a barrier, not sleeps: the withdrawal holds the lock after it read the old document until the other writer is known to be
	// waiting for it (it has started its own change), then both finish
	readOld := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	afterRead = func() {
		once.Do(func() {
			close(readOld)
			<-release
		})
	}
	defer func() { afterRead = nil }()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = store.Remove([]string{a}) }()
	go func() {
		defer wg.Done()
		<-readOld // the withdrawal has read the old document and holds the lock
		close(release)
		_ = store.Add(mustResolve(t, b))
	}()
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
	old := syscallUmask(0) // the most permissive mask: the creating call's own mode is all that limits the file
	defer syscallUmask(old)
	var atCreation os.FileMode
	afterCreateMode = func(file *os.File) {
		info, _ := file.Stat()
		atCreation = info.Mode().Perm()
	}
	defer func() { afterCreateMode = nil }()
	if _, err := handle.createExclusiveMode("staged", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if atCreation != 0o600 {
		t.Fatalf("the staged file existed with mode %v at creation", atCreation)
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

// A project named `lib` under a prefix: its local root and the global root under that prefix are the SAME path. npm's prefix tells
// the mode: in global mode the prefix is the global one and the root is <prefix>/lib/node_modules.
func TestOneShotPrefixTellsTheModeWhenTheRootsCoincide(t *testing.T) {
	store, _ := oneShotHome(t)
	prefix := oneShotProject(t, "prefixdir")
	lib := filepath.Join(prefix, "lib")
	if err := os.MkdirAll(lib, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lib, "package.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	addOne(t, store, prefix) // the prefix itself is pinned; the project lib is NOT
	// global mode (-g --prefix=<prefix>): prefix <prefix>, root <prefix>/lib/node_modules: the root is not under the prefix directly
	if verify(store, prefix, lib+"/node_modules") == OneShotPinned {
		t.Fatal("global mode on a pinned prefix was honoured")
	}
	// local mode in the project lib (lib is pinned): prefix lib, root lib/node_modules
	addOne(t, store, lib)
	if verify(store, lib, lib+"/node_modules") != OneShotPinned {
		t.Fatal("control: the pinned project lib in project mode")
	}
	// the same root with the GLOBAL prefix printed is not it
	if verify(store, prefix, lib+"/node_modules") == OneShotPinned {
		t.Fatal("the coincident root was honoured with another prefix")
	}
}

// A link whose NAME holds a newline and that leads to a pinned directory is not the pinned directory's answer.
func TestOneShotAnAnswerOfMoreThanOneLineIsRefusedBeforeAnyDirectoryIsOpened(t *testing.T) {
	store, _ := oneShotHome(t)
	dir := oneShotProject(t, "p")
	addOne(t, store, dir)
	base := t.TempDir()
	if err := os.Symlink(dir, base+"/a\nb"); err != nil {
		t.Skip("no newline names here")
	}
	if verify(store, base+"/a\nb", base+"/a\nb/node_modules") == OneShotPinned {
		t.Fatal("a name that holds a newline reached a pinned directory")
	}
	if store.VerifyAnswer([]byte(base+"/a\nb\n"), []byte(base+"/a\nb/node_modules\n")) == OneShotPinned {
		t.Fatal("two lines were read as one")
	}
}

// The tree written must be inside the pinned directory: a node_modules that is a link is not it.
func TestOneShotAPinWhoseNodeModulesIsALinkIsNotHonoured(t *testing.T) {
	store, _ := oneShotHome(t)
	dir := oneShotProject(t, "p")
	addOne(t, store, dir)
	if verify(store, dir, dir+"/node_modules") != OneShotPinned {
		t.Fatal("control: no node_modules yet")
	}
	if err := os.MkdirAll(dir+"/node_modules", 0o755); err != nil {
		t.Fatal(err)
	}
	if verify(store, dir, dir+"/node_modules") != OneShotPinned {
		t.Fatal("control: a node_modules directory")
	}
	if err := os.Remove(dir + "/node_modules"); err != nil {
		t.Fatal(err)
	}
	elsewhere := t.TempDir()
	if err := os.Symlink(elsewhere, dir+"/node_modules"); err != nil {
		t.Fatal(err)
	}
	if verify(store, dir, dir+"/node_modules") == OneShotPinned {
		t.Fatal("a node_modules that leads outside the pinned directory was honoured")
	}
}

// Every member of the schema, with its type, before a row is used.
func TestOneShotARowWithMembersMissingOrOfTheWrongTypeIsNotAStore(t *testing.T) {
	store, home := oneShotHome(t)
	dir := oneShotProject(t, "p")
	inDir(t, dir)
	write := func(content string) {
		if err := os.WriteFile(storeFile(home), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(storeFile(home), 0o600)
	}
	for name, doc := range map[string]string{
		"only a path":     `{"schema_version":1,"projects":[{"path":"` + dir + `"}]}`,
		"no inode":        `{"schema_version":1,"projects":[{"path":"` + dir + `","dev":1,"added":"x"}]}`,
		"a string device": `{"schema_version":1,"projects":[{"path":"` + dir + `","dev":"1","inode":2,"added":"x"}]}`,
		"a numeric path":  `{"schema_version":1,"projects":[{"path":5,"dev":1,"inode":2,"added":"x"}]}`,
		"no version":      `{"projects":[]}`,
		"no projects":     `{"schema_version":1}`,
	} {
		write(doc)
		if _, err := store.List(); err == nil {
			t.Fatalf("%s was listed", name)
		}
		if store.CheckHere() != OneShotNotPin {
			t.Fatalf("%s pinned something", name)
		}
	}
}

// Nothing here blocks: a pinned path that is now a FIFO is told at once, and a directory that can be searched but not read is
// still passed by the ancestor walk.
func TestOneShotNothingBlocksAndASearchOnlyDirectoryIsPassed(t *testing.T) {
	store, _ := oneShotHome(t)
	dir := oneShotProject(t, "p")
	addOne(t, store, dir)
	if err := os.Rename(dir, dir+".gone"); err != nil {
		t.Fatal(err)
	}
	if err := syscallMkfifo(dir); err != nil {
		t.Skip("no fifo here")
	}
	done := make(chan []OneShotRow, 1)
	go func() { rows, _ := store.List(); done <- rows }()
	select {
	case rows := <-done:
		if len(rows) != 1 || rows[0].State == "honoured" {
			t.Fatalf("%+v", rows)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("list blocked on a FIFO in place of a pinned directory")
	}
	// search-only ancestor: x without r
	root := oneShotProject(t, "root")
	addOne(t, store, root)
	inner := filepath.Join(root, "inner")
	if err := os.MkdirAll(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o311); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(root, 0o755)
	inDir(t, inner)
	if store.CheckHere() != OneShotPinned {
		t.Fatal("a pinned ancestor the operator can search but not read was not passed")
	}
}

// What was shown is what is removed: when the stored entry changed between the two steps, nothing is removed.
func TestOneShotRemovalCommitsWhatWasShown(t *testing.T) {
	store, _ := oneShotHome(t)
	dir := oneShotProject(t, "p")
	addOne(t, store, dir)
	shown, err := store.ShowRemoval([]string{dir})
	if err != nil || len(shown) != 1 {
		t.Fatalf("%v %v", shown, err)
	}
	// the decision changes between the two steps, under the SAME key: another writer withdraws the project, the directory is
	// replaced by another one at the same path (kept alive beside it, so the inode differs), and it is pinned again
	if _, err := store.Remove([]string{dir}); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(dir, dir+".moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := store.Add(mustResolve(t, dir)); err != nil {
		t.Fatal(err)
	}
	rows, _ := store.List()
	before := len(rows)
	if err := store.RemoveEntries(shown); err == nil || !strings.Contains(err.Error(), "decision changed") {
		t.Fatalf("a changed decision was removed: %v", err)
	}
	if rows, _ := store.List(); len(rows) != before {
		t.Fatal("something was removed although the decision changed")
	}
	// exact-key withdrawal of a gone directory keeps working
	gone := oneShotProject(t, "gone")
	addOne(t, store, gone)
	if err := os.RemoveAll(gone); err != nil {
		t.Fatal(err)
	}
	if removed, err := store.Remove([]string{gone}); err != nil || len(removed) != 1 {
		t.Fatalf("a gone directory: %v %v", removed, err)
	}
}
