//go:build linux

package projectlane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// Scenarios of the critical review of pull request 223, one per finding, each
// written against the API both heads share (this file is run unchanged against
// 99fc578 to show it fails there; see the pull request). They build their own
// small fixtures.

type rsProject struct {
	t        *testing.T
	dir      string
	lockfile []byte
	manifest []byte
	lock     *os.File
	req      BindRequest
	mark     string
}

func rsDigest(content string) string {
	sum := sha256.Sum256([]byte(content))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func rsDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func rsPut(t *testing.T, name, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(name, mode); err != nil {
		t.Fatal(err)
	}
}

func rsLock(packages map[string]any) []byte {
	all := map[string]any{"": map[string]any{"name": "root"}}
	for key, value := range packages {
		all[key] = value
	}
	raw, _ := json.Marshal(map[string]any{"lockfileVersion": 3, "packages": all})
	return raw
}

func rsEntry(name, version string) map[string]any {
	sum := sha256.Sum256([]byte(name + version))
	return map[string]any{
		"version":   version,
		"resolved":  "https://registry.npmjs.org/" + name + "/-/" + name + "-" + version + ".tgz",
		"integrity": "sha512-" + hex.EncodeToString(sum[:]) + hex.EncodeToString(sum[:]),
	}
}

func rsInstall(t *testing.T, root, path, name, version string) {
	t.Helper()
	manifest, _ := json.Marshal(map[string]string{"name": name, "version": version})
	rsPut(t, filepath.Join(root, path, "package.json"), string(manifest), 0o644)
}

// rsNew builds a project with an old tree and a request whose fake install
// copies a tree built from the judged lockfile (package a, 1.0.0).
func rsNew(t *testing.T) *rsProject {
	t.Helper()
	p := &rsProject{t: t, dir: rsDir(t), mark: filepath.Join(rsDir(t), "ran")}
	rsPut(t, filepath.Join(p.dir, "package.json"), `{"name":"root"}`, 0o640)
	rsPut(t, filepath.Join(p.dir, "package-lock.json"), `{"lockfileVersion":3,"packages":{"":{"name":"root"}}}`, 0o600)
	rsPut(t, filepath.Join(p.dir, "node_modules/old/package.json"), `{"name":"old","version":"1.0.0"}`, 0o644)
	rsPut(t, filepath.Join(p.dir, "node_modules/old/data"), "old tree", 0o644)

	src := rsDir(t)
	rsInstall(t, src, "node_modules/a", "a", "1.0.0")
	p.lockfile = rsLock(map[string]any{"node_modules/a": rsEntry("a", "1.0.0")})
	p.manifest = []byte(`{"name":"root","dependencies":{"a":"1.0.0"}}`)

	var err error
	if p.lock, err = os.Open(p.dir); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(p.lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.lock.Close() })
	p.req = BindRequest{
		Project: p.dir,
		Publish: []File{{Rel: "package.json", Content: p.manifest}, {Rel: "package-lock.json", Content: p.lockfile}},
		Live: map[string]string{
			"package.json": rsDigest(`{"name":"root"}`), "npm-shrinkwrap.json": "absent",
			"package-lock.json": rsDigest(`{"lockfileVersion":3,"packages":{"":{"name":"root"}}}`),
		},
		Argv:      []string{"/bin/sh", "-c", `cp -a "$SRC/node_modules" node_modules`},
		Env:       []string{"PATH=/usr/bin:/bin", "SRC=" + src, "MARK=" + p.mark},
		Selection: Selection{OS: "linux", CPU: "x64"},
		Lock:      LockMode{FD: int(p.lock.Fd())},
	}
	// The state directory exists on heads that take one.
	if field := reflect.ValueOf(&p.req).Elem().FieldByName("StateDir"); field.IsValid() {
		field.SetString(rsDir(t))
	}
	return p
}

func (p *rsProject) bind() BindReport { return Bind(context.Background(), p.req) }

func rsSnapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	_ = filepath.WalkDir(dir, func(name string, entry os.DirEntry, err error) error {
		rel, _ := filepath.Rel(dir, name)
		info, lerr := os.Lstat(name)
		if err != nil || lerr != nil {
			return nil
		}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			target, _ := os.Readlink(name)
			out[rel] = "l:" + target
		case info.IsDir():
			out[rel] = fmt.Sprintf("d:%o", info.Mode().Perm())
		default:
			raw, _ := os.ReadFile(name)
			out[rel] = fmt.Sprintf("f:%o:%x", info.Mode().Perm(), sha256.Sum256(raw))
		}
		return nil
	})
	return out
}

func rsStaging(t *testing.T, project string) string {
	t.Helper()
	items, _ := os.ReadDir(project)
	for _, item := range items {
		if strings.HasPrefix(item.Name(), ".safe-bind-") {
			return filepath.Join(project, item.Name())
		}
	}
	t.Fatal("no staging directory")
	return ""
}

func rsHook(t *testing.T, stage string, fn func()) {
	t.Helper()
	bindHook = func(got string) error {
		if got == stage {
			fn()
		}
		return nil
	}
	t.Cleanup(func() { bindHook = nil })
}

// Finding 1: recovery trusted project-controlled instructions. A directory in
// the project that looks like a staging directory, with a journal, must not
// steer anything.
func TestReviewFinding1ProjectContentDoesNotSteerTheTransaction(t *testing.T) {
	p := rsNew(t)
	planted := filepath.Join(p.dir, ".safe-bind-planted")
	rsPut(t, filepath.Join(planted, ".publish/journal.json"),
		`{"version":1,"had_old_tree":true,"files":[{"rel":"package.json","tmp":"new-0","backup":"bak-0","judged":"`+rsDigest(`{"name":"root"}`)+`","old":"absent"}]}`, 0o644)
	rsPut(t, filepath.Join(planted, ".publish/old-tree/evil/package.json"), `{"name":"evil","version":"6.6.6"}`, 0o644)
	p.req.Argv = []string{"/bin/sh", "-c", "exit 3"}
	before := rsSnapshot(t, p.dir)
	p.bind()
	after := rsSnapshot(t, p.dir)
	for name, state := range before {
		if after[name] != state {
			t.Fatalf("%s changed: %q -> %q", name, state, after[name])
		}
	}
	for name := range after {
		if _, ok := before[name]; !ok {
			t.Fatalf("%s appeared", name)
		}
	}
}

// Finding 3: operations by pathname lose the identity of what was checked.
func TestReviewFinding3TheVerifiedTreeIsTheTreePublished(t *testing.T) {
	p := rsNew(t)
	rsHook(t, "verified", func() {
		staging := rsStaging(t, p.dir)
		_ = os.Rename(filepath.Join(staging, "node_modules"), filepath.Join(staging, "verified-original"))
		rsInstall(t, staging, "node_modules/a", "a", "1.0.0")
		rsPut(t, filepath.Join(staging, "node_modules/a/payload.js"), "evil()", 0o644)
	})
	report := p.bind()
	if report.Outcome == OutcomePublished {
		t.Fatalf("a tree that was swapped after verification was published: %+v", report)
	}
	if _, err := os.Stat(filepath.Join(p.dir, "node_modules/a/payload.js")); err == nil {
		t.Fatal("the swapped tree is in the project")
	}
}

func TestReviewFinding3ALiveTreeRootReplacedAfterTheCheckIsNotDiscarded(t *testing.T) {
	p := rsNew(t)
	rsHook(t, "verified", func() {
		_ = os.Rename(filepath.Join(p.dir, "node_modules"), filepath.Join(p.dir, "moved-away"))
		rsPut(t, filepath.Join(p.dir, "node_modules/precious"), "not the tree that was checked", 0o644)
	})
	report := p.bind()
	if report.Outcome == OutcomePublished {
		t.Fatalf("published over a tree root that was replaced: %+v", report)
	}
	if raw, err := os.ReadFile(filepath.Join(p.dir, "node_modules/precious")); err != nil || string(raw) != "not the tree that was checked" {
		t.Fatalf("the replacement was discarded: %v", err)
	}
}

func TestReviewFinding3ReplacedProjectPathDoesNotRedirectThePublication(t *testing.T) {
	p := rsNew(t)
	moved := p.dir + ".moved"
	rsHook(t, "installed", func() {
		if err := os.Rename(p.dir, moved); err != nil {
			t.Error(err)
			return
		}
		if out, err := exec.Command("cp", "-a", moved, p.dir).CombinedOutput(); err != nil {
			t.Errorf("%v %s", err, out)
		}
	})
	t.Cleanup(func() { _ = os.RemoveAll(moved) })
	report := p.bind()
	if report.Outcome != OutcomePublished {
		t.Fatalf("outcome = %s (%s)", report.Outcome, report.Detail)
	}
	if raw, _ := os.ReadFile(filepath.Join(moved, "package.json")); string(raw) != string(p.manifest) {
		t.Fatalf("the locked directory did not get the published manifest: %q", raw)
	}
	if raw, _ := os.ReadFile(filepath.Join(p.dir, "package.json")); string(raw) != `{"name":"root"}` {
		t.Fatalf("a directory that merely took the old path was written: %q", raw)
	}
}

// Finding 4: descriptors above 1023 and processes that leave the process group.
func TestReviewFinding4NoInheritedDescriptorReachesTheChild(t *testing.T) {
	p := rsNew(t)
	const high = 1500
	if err := syscall.Dup3(int(p.lock.Fd()), high, 0); err != nil {
		t.Skipf("no descriptor %d: %v", high, err)
	}
	t.Cleanup(func() { _ = syscall.Close(high) })
	dump := filepath.Join(rsDir(t), "fds")
	p.req.Lock = LockMode{FD: high}
	p.req.Argv = []string{"/bin/sh", "-c", `for fd in /proc/$$/fd/*; do readlink "$fd"; done > "$DUMP"; cp -a "$SRC/node_modules" node_modules`}
	p.req.Env = append(p.req.Env, "DUMP="+dump)
	if report := p.bind(); report.Outcome != OutcomePublished {
		t.Fatalf("outcome = %s (%s)", report.Outcome, report.Detail)
	}
	raw, _ := os.ReadFile(dump)
	if strings.Contains(string(raw), p.dir+"\n") {
		t.Fatalf("the child holds the project directory (the lock) open: %q", raw)
	}
}

func TestReviewFinding4TheInstallsProcessGroupIsGoneBeforeVerification(t *testing.T) {
	p := rsNew(t)
	pidFile := filepath.Join(rsDir(t), "pid")
	// A background process in the install's own process group, still running
	// when the install exits. (A process that leaves the group is outside the
	// stated assumption: the install command is trusted and runs no script.)
	p.req.Argv = []string{"/bin/sh", "-c", `cp -a "$SRC/node_modules" node_modules; sh -c 'echo $$ > "$PIDF"; exec sleep 60' >/dev/null 2>&1 &
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do [ -s "$PIDF" ] && break; sleep 0.05; done`}
	p.req.Env = append(p.req.Env, "PIDF="+pidFile)
	report := p.bind()
	raw, _ := os.ReadFile(pidFile)
	pid, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
	if pid <= 0 {
		t.Fatalf("the background process never wrote its pid (outcome %s)", report.Outcome)
	}
	defer func() { _ = syscall.Kill(pid, syscall.SIGKILL) }()
	if report.Outcome != OutcomePublished {
		t.Fatalf("outcome = %s (%s)", report.Outcome, report.Detail)
	}
	// Bind returned: the group was empty before verification started, so the
	// process is gone, not merely a zombie.
	if err := syscall.Kill(pid, 0); err == nil {
		t.Fatalf("pid %d of the install's process group still exists after the run", pid)
	}
}

// Finding 5: the verifier accepts content it cannot attribute.
func TestReviewFinding5BinEntriesAreAttributed(t *testing.T) {
	root := rsDir(t)
	lock := rsLock(map[string]any{"node_modules/a": rsEntry("a", "1.0.0")})
	rsInstall(t, root, "node_modules/a", "a", "1.0.0")
	if err := os.MkdirAll(filepath.Join(root, "node_modules/.bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../a/bin.js", filepath.Join(root, "node_modules/.bin/a")); err != nil { // dangling, undeclared
		t.Fatal(err)
	}
	report, err := VerifyTree(lock, root, Selection{OS: "linux", CPU: "x64"})
	if err != nil {
		t.Fatal(err)
	}
	if report.Ok {
		t.Fatalf("a dangling .bin link that no lockfile entry declares was accepted: %+v", report)
	}
}

func TestReviewFinding5HiddenRecordOfABundledMemberIsCompared(t *testing.T) {
	root := rsDir(t)
	bundled := map[string]any{"version": "3.0.0", "inBundle": true}
	lock := rsLock(map[string]any{"node_modules/p": rsEntry("p", "1.0.0"), "node_modules/p/node_modules/c": bundled})
	rsInstall(t, root, "node_modules/p", "p", "1.0.0")
	rsInstall(t, root, "node_modules/p/node_modules/c", "c", "3.0.0")
	hidden, _ := json.Marshal(map[string]any{"lockfileVersion": 3, "packages": map[string]any{
		"node_modules/p": rsEntry("p", "1.0.0"),
		"node_modules/p/node_modules/c": map[string]any{"version": "3.0.0", "inBundle": true,
			"resolved": "https://evil.example/c.tgz", "integrity": "sha512-" + strings.Repeat("A", 86) + "=="},
	}})
	rsPut(t, filepath.Join(root, "node_modules/.package-lock.json"), string(hidden), 0o644)
	report, err := VerifyTree(lock, root, Selection{OS: "linux", CPU: "x64"})
	if err != nil {
		t.Fatal(err)
	}
	if report.Ok {
		t.Fatalf("an independent origin recorded for a bundled member was accepted: %+v", report)
	}
}

// Finding 6: a missing required package can count as deselected.
func TestReviewFinding6APresentOptionalParentDoesNotExcuseAMissingChild(t *testing.T) {
	root := rsDir(t)
	native := with(rsEntry("native", "1.0.0"), map[string]any{"optional": true, "os": []string{"win32"}})
	lock := rsLock(map[string]any{
		"node_modules/native":                  native,
		"node_modules/native/node_modules/dep": rsEntry("dep", "1.0.0"),
	})
	rsInstall(t, root, "node_modules/native", "native", "1.0.0")
	report, err := VerifyTree(lock, root, Selection{OS: "linux", CPU: "x64"})
	if err != nil {
		t.Fatal(err)
	}
	if report.Ok {
		t.Fatalf("a required child of a present package was excused: %+v", report)
	}
}

// Finding 7: publication can overwrite an edit or report success with the wrong lockfile.
func TestReviewFinding7AnEditToAPublishedFileIsNotReportedAsPublished(t *testing.T) {
	p := rsNew(t)
	rsHook(t, "publish:file:1", func() {
		rsPut(t, filepath.Join(p.dir, "package.json"), `{"edited":"after it was published"}`, 0o640)
	})
	if report := p.bind(); report.Outcome == OutcomePublished {
		t.Fatalf("published although a published file was edited: %+v", report)
	}
}

// Finding 8: strictness differs between judgement and verification.
func TestReviewFinding8ASecondSpellingOfResolvedIsRefused(t *testing.T) {
	const canonical = "https://registry.npmjs.org/p/-/p-1.0.0.tgz"
	const elsewhere = "https://evil.example/p-1.0.0.tgz"
	for name, entry := range map[string]string{
		"canonical last":  `"resolved":"` + elsewhere + `","Resolved":"` + canonical + `"`,
		"canonical first": `"Resolved":"` + canonical + `","resolved":"` + elsewhere + `"`,
	} {
		t.Run(name, func(t *testing.T) {
			sum := sha256.Sum256([]byte("p"))
			integrity := "sha512-" + hex.EncodeToString(sum[:]) + hex.EncodeToString(sum[:])
			path := filepath.Join(rsDir(t), "package-lock.json")
			doc := `{"lockfileVersion":3,"packages":{"":{"name":"root"},"node_modules/p":{"version":"1.0.0",` + entry + `,"integrity":"` + integrity + `"}}}`
			if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
				t.Fatal(err)
			}
			if graph, err := LoadGraph(path, Hosts{}); err == nil {
				t.Fatalf("the graph was loaded: %+v", graph)
			}
		})
	}
}

func rsTreeWith(t *testing.T, manifest string) (root string, lock []byte) {
	t.Helper()
	root = rsDir(t)
	lock = rsLock(map[string]any{"node_modules/a": rsEntry("a", "1.0.0")})
	rsPut(t, filepath.Join(root, "node_modules/a/package.json"), manifest, 0o644)
	return root, lock
}

func rsRefused(root string, lock []byte) bool {
	report, err := VerifyTree(lock, root, Selection{OS: "linux", CPU: "x64"})
	return err != nil || !report.Ok
}

func TestReviewFinding8AManifestWithASecondSpellingOfNameIsRefused(t *testing.T) {
	root, lock := rsTreeWith(t, `{"name":"evil","Name":"a","version":"1.0.0"}`)
	if !rsRefused(root, lock) {
		t.Fatal("accepted")
	}
}

func TestReviewFinding8AManifestWithAStrayClosingBraceIsRefused(t *testing.T) {
	root, lock := rsTreeWith(t, `{"name":"a","version":"1.0.0"}}`)
	if !rsRefused(root, lock) {
		t.Fatal("accepted")
	}
}

func TestReviewFinding8ALockfileWithAStrayClosingBraceIsRefused(t *testing.T) {
	root, lock := rsTreeWith(t, `{"name":"a","version":"1.0.0"}`)
	if rsRefused(root, lock) {
		t.Fatal("the control tree is refused")
	}
	if !rsRefused(root, append(append([]byte{}, lock...), '}')) {
		t.Fatal("a lockfile with a stray closing brace was accepted")
	}
}

// Modes: a new file honours the creation mask; a set-id destination refuses.
func TestReviewModesANewFileHonoursTheCreationMask(t *testing.T) {
	p := rsNew(t)
	if err := os.Remove(filepath.Join(p.dir, "package-lock.json")); err != nil {
		t.Fatal(err)
	}
	p.req.Live["package-lock.json"] = "absent"
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	if report := p.bind(); report.Outcome != OutcomePublished {
		t.Fatalf("outcome = %s (%s)", report.Outcome, report.Detail)
	}
	info, err := os.Stat(filepath.Join(p.dir, "package-lock.json"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the new lockfile has mode %v (umask 077), want 0600: %v", info.Mode(), err)
	}
}

func TestReviewModesASetIdDestinationRefuses(t *testing.T) {
	p := rsNew(t)
	if err := os.Chmod(filepath.Join(p.dir, "package.json"), os.ModeSetuid|0o755); err != nil {
		t.Fatal(err)
	}
	report := p.bind()
	if report.Outcome == OutcomePublished {
		t.Fatalf("published over a set-id destination: %+v", report)
	}
}

// Round 2 (review of ecedff8). Same rule: only the API both heads share.

func TestReview2Point1ACreatedFileEditedBeforeTheFinalCheckIsNotDeleted(t *testing.T) {
	p := rsNew(t)
	if err := os.Remove(filepath.Join(p.dir, "package-lock.json")); err != nil {
		t.Fatal(err)
	}
	p.req.Live["package-lock.json"] = "absent"
	name := filepath.Join(p.dir, "package-lock.json")
	rsHook(t, "publish:tree", func() {
		_ = os.WriteFile(name, []byte(`{"edited":"after the run created it"}`), 0o644)
	})
	p.bind()
	if raw, err := os.ReadFile(name); err != nil || !strings.Contains(string(raw), "edited") {
		t.Fatalf("the edited file was deleted or reverted: %q %v", raw, err)
	}
}

func TestReview2Point1APermissionTighteningAfterPreparationIsNotLost(t *testing.T) {
	p := rsNew(t)
	name := filepath.Join(p.dir, "package.json")
	rsHook(t, "publish:file:0:before", func() { _ = os.Chmod(name, 0o600) })
	p.bind()
	if info, err := os.Stat(name); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the destination's mode was widened by the publication: %v %v", info, err)
	}
}

func TestReview2Point3ATreeRootThatAppearsDuringTheRunIsNotTakenForTheOldTree(t *testing.T) {
	p := rsNew(t)
	if err := os.RemoveAll(filepath.Join(p.dir, "node_modules")); err != nil {
		t.Fatal(err)
	}
	rsHook(t, "installed", func() {
		rsPut(t, filepath.Join(p.dir, "node_modules/precious"), "mine", 0o644)
	})
	report := p.bind()
	if raw, _ := os.ReadFile(filepath.Join(p.dir, "node_modules/precious")); string(raw) != "mine" || report.Outcome == OutcomePublished {
		t.Fatalf("outcome = %s; the tree that appeared was discarded or published over", report.Outcome)
	}
}

func TestReview2Point3AParentThatDisappearsBeforeTheFinalCheckDoesNotPanic(t *testing.T) {
	p := rsNew(t)
	ws := filepath.Join(p.dir, "ws")
	rsPut(t, filepath.Join(ws, "package.json"), `{"name":"ws"}`, 0o644)
	p.req.Publish = append(p.req.Publish, File{Rel: "ws/package.json", Content: []byte(`{"name":"ws","version":"2"}`)})
	p.req.Live["ws/package.json"] = rsDigest(`{"name":"ws"}`)
	rsHook(t, "publish:tree", func() { _ = os.Rename(ws, ws+".gone") })
	if report := p.bind(); report.Outcome == OutcomePublished {
		t.Fatalf("published although a published file's directory is gone: %+v", report)
	}
}

func TestReview2Point4ACommandLinkIsTheTextNpmWrites(t *testing.T) {
	root := rsDir(t)
	a := with(rsEntry("a", "1.0.0"), map[string]any{"bin": map[string]any{"a": "bin.js"}})
	lock := rsLock(map[string]any{"node_modules/a": a})
	rsInstall(t, root, "node_modules/a", "a", "1.0.0")
	rsPut(t, filepath.Join(root, "node_modules/a/bin.js"), "x", 0o644)
	if err := os.MkdirAll(filepath.Join(root, "node_modules/.bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The cleaned text names the declared file; the text itself does not
	// resolve there ("ghost" does not exist).
	if err := os.Symlink("../ghost/../a/bin.js", filepath.Join(root, "node_modules/.bin/a")); err != nil {
		t.Fatal(err)
	}
	report, err := VerifyTree(lock, root, Selection{OS: "linux", CPU: "x64"})
	if err == nil && report.Ok {
		t.Fatalf("a link whose text is not what npm writes was accepted: %+v", report)
	}
}

func TestReview2Point5ARootEntryAndNullIdentityFieldsAreHeldToTheSameRules(t *testing.T) {
	for name, doc := range map[string]string{
		"a root entry with a second spelling": `{"lockfileVersion":3,"packages":{"":{"name":"root","Name":"x"}}}`,
		"a null resolved":                     `{"lockfileVersion":3,"packages":{"":{"name":"root"},"node_modules/p":{"version":"1.0.0","resolved":null}}}`,
	} {
		path := filepath.Join(rsDir(t), "package-lock.json")
		if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		if graph, err := LoadGraph(path, Hosts{}); err == nil {
			t.Errorf("%s: the graph was loaded: %+v", name, graph)
		}
	}
}

func TestReview2Point6AnInstallThatSelectsNoTreePublishes(t *testing.T) {
	p := rsNew(t)
	if err := os.RemoveAll(filepath.Join(p.dir, "node_modules")); err != nil {
		t.Fatal(err)
	}
	empty := []byte(`{"lockfileVersion":3,"packages":{"":{"name":"root"}}}`)
	p.req.Publish[1].Content = empty
	p.req.Argv = []string{"/bin/sh", "-c", "true"}
	if report := p.bind(); report.Outcome != OutcomePublished {
		t.Fatalf("outcome = %s (%s)", report.Outcome, report.Detail)
	}
}

func TestReview2Point5TheLockfilesNpmWritesAreAccepted(t *testing.T) {
	sel := Selection{OS: "linux", CPU: "x64"}
	for name, build := range map[string]func(root string) []byte{
		"a root dependency that is both dev and peer": func(root string) []byte {
			rsInstall(t, root, "node_modules/x", "x", "1.0.0")
			return rsLock(map[string]any{
				"":               map[string]any{"name": "root", "devDependencies": map[string]any{"x": "1"}, "peerDependencies": map[string]any{"x": "1"}},
				"node_modules/x": with(rsEntry("x", "1.0.0"), map[string]any{"dev": true, "peer": true})})
		},
		"a root dependency that is both dev and production": func(root string) []byte {
			rsInstall(t, root, "node_modules/x", "x", "1.0.0")
			return rsLock(map[string]any{
				"":               map[string]any{"name": "root", "dependencies": map[string]any{"x": "1"}, "devDependencies": map[string]any{"x": "1"}},
				"node_modules/x": rsEntry("x", "1.0.0")})
		},
		"a production package's peer that is also a root dev dependency": func(root string) []byte {
			rsInstall(t, root, "node_modules/app", "app", "1.0.0")
			rsInstall(t, root, "node_modules/shared", "shared", "1.0.0")
			return rsLock(map[string]any{
				"":                    map[string]any{"name": "root", "dependencies": map[string]any{"app": "1"}, "devDependencies": map[string]any{"shared": "1"}},
				"node_modules/app":    with(rsEntry("app", "1.0.0"), map[string]any{"peerDependencies": map[string]any{"shared": "1"}}),
				"node_modules/shared": with(rsEntry("shared", "1.0.0"), map[string]any{"dev": true, "peer": true})})
		},
	} {
		root := rsDir(t)
		lock := build(root)
		report, err := VerifyTree(lock, root, sel)
		if err != nil || !report.Ok {
			t.Errorf("%s: a complete tree was refused: %+v %v", name, report.Problems, err)
		}
	}
}
