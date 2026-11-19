package projectlane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// bindFx is a project with an old tree, judged inputs, and a fake install
// command that builds a given tree (never npm).
type bindFx struct {
	t        *testing.T
	project  string
	src      *treeFx // the tree the fake install produces; judged against src.lockBytes()
	lock     *os.File
	mark     string
	output   bytes.Buffer
	req      BindRequest
	manifest []byte
	lockfile []byte
}

const oldManifest = `{"name":"root","version":"1.0.0","dependencies":{"old":"1.0.0"}}`
const oldLockfile = `{"name":"root","lockfileVersion":3,"packages":{"":{"name":"root"}}}`

func evalDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func put(t *testing.T, name, content string, mode os.FileMode) {
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

func sum(content string) string {
	digest := sha256.Sum256([]byte(content))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func newBindFx(t *testing.T) *bindFx {
	t.Helper()
	f := &bindFx{t: t, project: evalDir(t)}
	put(t, filepath.Join(f.project, "package.json"), oldManifest, 0o640)
	put(t, filepath.Join(f.project, "package-lock.json"), oldLockfile, 0o600)
	put(t, filepath.Join(f.project, ".npmrc"), "ignore-scripts=true\n", 0o600)
	put(t, filepath.Join(f.project, "node_modules/old/package.json"), `{"name":"old","version":"1.0.0"}`, 0o644)
	put(t, filepath.Join(f.project, "node_modules/old/data"), "old tree content", 0o644)

	f.src = newTreeFx(t)
	f.src.pkg("node_modules/a", "a", "1.0.0")
	f.src.pkg("node_modules/@s/b", "@s/b", "2.0.0")
	f.src.pkg("node_modules/a/node_modules/c", "c", "3.0.0")
	f.src.hiddenLockfile(nil)
	f.manifest = []byte(`{"name":"root","version":"1.0.0","dependencies":{"a":"1.0.0","@s/b":"2.0.0"}}`)
	f.lockfile = f.src.lockBytes()
	f.mark = filepath.Join(evalDir(t), "ran")

	var err error
	if f.lock, err = os.Open(f.project); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(f.lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.lock.Close() })

	f.req = BindRequest{
		Project:     f.project,
		Publish:     []File{{Rel: "package.json", Content: f.manifest}, {Rel: "package-lock.json", Content: f.lockfile}},
		Copy:        []File{{Rel: ".npmrc", Content: []byte("ignore-scripts=true\n")}},
		Argv:        []string{"/bin/sh", "-c", `echo ran > "$MARK"; cp -a "$FAKE_TREE/node_modules" node_modules`},
		Env:         []string{"PATH=/usr/bin:/bin", "FAKE_TREE=" + f.src.root, "MARK=" + f.mark},
		Selection:   linuxX64,
		Lock:        LockMode{FD: int(f.lock.Fd())},
		ChildOutput: &f.output,
	}
	f.judge()
	return f
}

// judge records the live digests of the inputs as they are now.
func (f *bindFx) judge() {
	f.req.Live = map[string]string{"npm-shrinkwrap.json": "absent"}
	for _, rel := range []string{"package.json", "package-lock.json", ".npmrc"} {
		raw, err := os.ReadFile(filepath.Join(f.project, rel))
		if err != nil {
			f.req.Live[rel] = "absent"
			continue
		}
		f.req.Live[rel] = sum(string(raw))
	}
}

func (f *bindFx) command(script string) {
	f.req.Argv = []string{"/bin/sh", "-c", script}
}

func (f *bindFx) bind() BindReport {
	f.t.Helper()
	return Bind(context.Background(), f.req)
}

func (f *bindFx) ran() bool {
	_, err := os.Stat(f.mark)
	return err == nil
}

// snapshot is the whole project, byte for byte, modes included.
func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, name)
		info, err := os.Lstat(name)
		if err != nil {
			return err
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
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func sameSnapshot(t *testing.T, before, after map[string]string) {
	t.Helper()
	var diff []string
	for name, state := range before {
		if after[name] != state {
			diff = append(diff, fmt.Sprintf("%s: %q -> %q", name, state, after[name]))
		}
	}
	for name, state := range after {
		if _, ok := before[name]; !ok {
			diff = append(diff, fmt.Sprintf("%s: appeared as %q", name, state))
		}
	}
	sort.Strings(diff)
	if len(diff) > 0 {
		t.Fatalf("the project is not as it was:\n%s", strings.Join(diff, "\n"))
	}
}

func noStaging(t *testing.T, project string) {
	t.Helper()
	items, _ := os.ReadDir(project)
	for _, item := range items {
		if strings.HasPrefix(item.Name(), stagingPrefix) {
			t.Fatalf("staging directory %s is left behind", item.Name())
		}
	}
}

func hookAt(t *testing.T, stage string, fn func() error) {
	t.Helper()
	bindHook = func(got string) error {
		if got == stage {
			return fn()
		}
		return nil
	}
	t.Cleanup(func() { bindHook = nil })
}

func wantOutcome(t *testing.T, report BindReport, outcome string, exit int) {
	t.Helper()
	if report.Outcome != outcome || report.Exit != exit {
		t.Fatalf("outcome = %s/%d (%s: %s), want %s/%d", report.Outcome, report.Exit, report.Reason, report.Detail, outcome, exit)
	}
}

func TestBindPublishesAMatchingTree(t *testing.T) {
	f := newBindFx(t)
	report := f.bind()
	wantOutcome(t, report, OutcomePublished, ExitPublished)
	if !f.ran() || report.Install.ExitCode == nil || *report.Install.ExitCode != 0 || !report.Install.Ran {
		t.Fatalf("install = %+v", report.Install)
	}
	if report.Verification == nil || !report.Verification.Ok || report.Publication.State != PublicationCommitted ||
		!report.Staging.Removed || report.Staging.Path != "" || report.Reason != "" {
		t.Fatalf("report = %+v", report)
	}
	noStaging(t, f.project)

	// The judged files are in place with their original modes.
	for rel, want := range map[string]struct {
		content string
		mode    os.FileMode
	}{
		"package.json":      {string(f.manifest), 0o640},
		"package-lock.json": {string(f.lockfile), 0o600},
	} {
		raw, err := os.ReadFile(filepath.Join(f.project, rel))
		info, _ := os.Lstat(filepath.Join(f.project, rel))
		if err != nil || string(raw) != want.content || info.Mode().Perm() != want.mode || !info.Mode().IsRegular() {
			t.Fatalf("%s: content ok = %v, mode = %v, want %v", rel, string(raw) == want.content, info.Mode(), want.mode)
		}
	}
	// The configuration is copied to staging only: the live file is untouched.
	if raw, _ := os.ReadFile(filepath.Join(f.project, ".npmrc")); string(raw) != "ignore-scripts=true\n" {
		t.Fatalf(".npmrc = %q", raw)
	}
	// The tree in place is the judged one, and the old tree is gone.
	if _, err := os.Stat(filepath.Join(f.project, "node_modules/old")); err == nil {
		t.Fatal("the old tree is still there")
	}
	verified, err := VerifyTree(f.lockfile, f.project, linuxX64)
	if err != nil || !verified.Ok {
		t.Fatalf("the published tree does not verify: %+v, %v", verified, err)
	}
	// The child's output went where it was sent, and the document is strict.
	var decoded BindReport
	raw, _ := json.Marshal(report)
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&decoded); err != nil || decoded.Outcome != OutcomePublished {
		t.Fatalf("document round trip: %v", err)
	}
	for _, member := range []string{"schema_version", "outcome", "exit", "reason", "detail", "project", "selection", "install", "verification", "inputs_changed", "publication", "staging", "recovery", "signal"} {
		var members map[string]json.RawMessage
		_ = json.Unmarshal(raw, &members)
		if _, ok := members[member]; !ok {
			t.Fatalf("the document lacks %q: %s", member, raw)
		}
	}
}

func TestBindCreatesAFileThatDidNotExistWithAReadableMode(t *testing.T) {
	f := newBindFx(t)
	if err := os.Remove(filepath.Join(f.project, "package-lock.json")); err != nil {
		t.Fatal(err)
	}
	f.judge()
	wantOutcome(t, f.bind(), OutcomePublished, ExitPublished)
	info, err := os.Lstat(filepath.Join(f.project, "package-lock.json"))
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("new lockfile: %v, %v", info, err)
	}
}

func TestBindPublishesWhenThereWasNoTreeBefore(t *testing.T) {
	f := newBindFx(t)
	if err := os.RemoveAll(filepath.Join(f.project, "node_modules")); err != nil {
		t.Fatal(err)
	}
	wantOutcome(t, f.bind(), OutcomePublished, ExitPublished)
	if verified, err := VerifyTree(f.lockfile, f.project, linuxX64); err != nil || !verified.Ok {
		t.Fatalf("%+v %v", verified, err)
	}
}

func TestBindRunsTheChildWithTheGivenEnvironmentAndNoDescriptorsOfTheCaller(t *testing.T) {
	t.Setenv("CANARY_FROM_CALLER", "leaked")
	f := newBindFx(t)
	dump := filepath.Join(evalDir(t), "child")
	f.command(`env > "$DUMP.env"; for fd in /proc/$$/fd/*; do readlink "$fd"; done > "$DUMP.fds"; cp -a "$FAKE_TREE/node_modules" node_modules; pwd > "$DUMP.pwd"`)
	f.req.Env = append(f.req.Env, "DUMP="+dump)
	wantOutcome(t, f.bind(), OutcomePublished, ExitPublished)
	env, _ := os.ReadFile(dump + ".env")
	if strings.Contains(string(env), "CANARY_FROM_CALLER") || !strings.Contains(string(env), "FAKE_TREE=") {
		t.Fatalf("child environment = %q", env)
	}
	fds, _ := os.ReadFile(dump + ".fds")
	if strings.Contains(string(fds), f.project+"\n") || strings.Contains(string(fds), f.project+"/\n") {
		t.Fatalf("the child holds the project directory open (the lock): %q", fds)
	}
	pwd, _ := os.ReadFile(dump + ".pwd")
	if !strings.HasPrefix(string(pwd), f.project+"/"+stagingPrefix) {
		t.Fatalf("the child ran in %q, not in staging", pwd)
	}
}

// What the fake install builds, and how the verifier must find it wrong.
func TestBindRefusesATreeThatIsNotTheJudgedOneAndLeavesTheProject(t *testing.T) {
	outside := evalDir(t)
	cases := map[string]struct {
		script string
		want   string // a problem the report must carry
	}{
		"a required entry is missing":                   {`cp -a "$FAKE_TREE/node_modules" node_modules; rm -rf node_modules/@s/b`, TreeMissing},
		"an entry under another name":                   {`cp -a "$FAKE_TREE/node_modules" node_modules; printf '{"name":"evil","version":"2.0.0"}' > node_modules/@s/b/package.json`, TreeWrongName},
		"an entry under another version":                {`cp -a "$FAKE_TREE/node_modules" node_modules; printf '{"name":"a","version":"1.0.1"}' > node_modules/a/package.json`, TreeWrongVersion},
		"an extra entry":                                {`cp -a "$FAKE_TREE/node_modules" node_modules; mkdir node_modules/extra; printf '{"name":"extra","version":"1.0.0"}' > node_modules/extra/package.json`, TreeNotInLockfile},
		"a hidden extra entry":                          {`cp -a "$FAKE_TREE/node_modules" node_modules; mkdir node_modules/.hidden; echo x > node_modules/.hidden/f`, TreeHiddenNotAllowed},
		"a symbolic link where a directory is expected": {`cp -a "$FAKE_TREE/node_modules" node_modules; mv node_modules/a "$OUT/a"; ln -s "$OUT/a" node_modules/a`, TreeSymlink},
		"a path that leaves the tree":                   {`cp -a "$FAKE_TREE/node_modules" node_modules; mkdir -p node_modules/.bin; ln -s ../../../../etc/passwd node_modules/.bin/x`, TreePathOutside},
		"an unreadable hidden lockfile":                 {`cp -a "$FAKE_TREE/node_modules" node_modules; echo '{' > node_modules/.package-lock.json`, TreeHiddenLockfileUnreadable},
		"a hidden lockfile that says something else":    {`cp -a "$FAKE_TREE/node_modules" node_modules; printf '{"lockfileVersion":3,"packages":{}}' > node_modules/.package-lock.json`, TreeHiddenLockfileInconsistent},
		"no tree at all":                                {`true`, TreeMissing},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newBindFx(t)
			f.command(tc.script)
			f.req.Env = append(f.req.Env, "OUT="+outside)
			before := snapshot(t, f.project)
			report := f.bind()
			wantOutcome(t, report, OutcomeVerificationFailed, ExitVerificationFailed)
			found := false
			for _, problem := range report.Verification.Problems {
				found = found || problem.Problem == tc.want
			}
			if !found || report.Publication.State != PublicationNotStarted {
				t.Fatalf("want a %s problem, report = %+v", tc.want, report.Verification)
			}
			sameSnapshot(t, before, snapshot(t, f.project))
			noStaging(t, f.project)
			if !report.Staging.Removed {
				t.Fatalf("staging = %+v", report.Staging)
			}
		})
	}
}

func TestBindRefusesALockfileItCannotAdmitBeforeRunningAnything(t *testing.T) {
	cases := map[string]struct {
		lock   string
		reason string
	}{
		"a lockfile with a link entry": {`{"lockfileVersion":3,"packages":{"":{},"node_modules/l":{"resolved":"packages/l","link":true},"packages/l":{"version":"1.0.0"}}}`, ReasonLinksNotSupported},
		"a key that leaves the tree":   {`{"lockfileVersion":3,"packages":{"":{},"node_modules/../../outside":{"version":"1.0.0"}}}`, ReasonLockfilePathsOutside},
		"a key outside node_modules":   {`{"lockfileVersion":3,"packages":{"":{},"packages/a":{"version":"1.0.0"}}}`, ReasonLockfilePathsOutside},
		"version 1":                    {`{"lockfileVersion":1,"dependencies":{}}`, ReasonLockfileUnreadable},
		"not JSON":                     {`{`, ReasonLockfileUnreadable},
		"a repeated member":            {`{"lockfileVersion":3,"lockfileVersion":3,"packages":{}}`, ReasonLockfileUnreadable},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newBindFx(t)
			f.req.Publish[1].Content = []byte(tc.lock)
			before := snapshot(t, f.project)
			report := f.bind()
			wantOutcome(t, report, OutcomeRefused, ExitRefused)
			if report.Reason != tc.reason || f.ran() || report.Install.Ran {
				t.Fatalf("reason = %s, ran = %v: %s", report.Reason, f.ran(), report.Detail)
			}
			sameSnapshot(t, before, snapshot(t, f.project))
		})
	}
}

func TestBindRefusesARequestThatIsNotWellFormed(t *testing.T) {
	cases := map[string]func(f *bindFx){
		"a relative command":               func(f *bindFx) { f.req.Argv = []string{"npm", "ci"} },
		"no command":                       func(f *bindFx) { f.req.Argv = nil },
		"no environment":                   func(f *bindFx) { f.req.Env = nil },
		"no manifest":                      func(f *bindFx) { f.req.Publish = f.req.Publish[1:] },
		"no lockfile":                      func(f *bindFx) { f.req.Publish = f.req.Publish[:1] },
		"a published file that is neither": func(f *bindFx) { f.req.Publish = append(f.req.Publish, File{Rel: ".npmrc", Content: []byte("x")}) },
		"a path that climbs":               func(f *bindFx) { f.req.Copy = append(f.req.Copy, File{Rel: "../x", Content: []byte("x")}) },
		"an absolute path":                 func(f *bindFx) { f.req.Copy = append(f.req.Copy, File{Rel: "/etc/x", Content: []byte("x")}) },
		"a path into node_modules":         func(f *bindFx) { f.req.Copy = append(f.req.Copy, File{Rel: "node_modules/x", Content: []byte("x")}) },
		"a path into staging": func(f *bindFx) {
			f.req.Copy = append(f.req.Copy, File{Rel: stagingPrefix + "x/y", Content: []byte("x")})
		},
		"a path given twice":               func(f *bindFx) { f.req.Copy = append(f.req.Copy, File{Rel: "package.json", Content: []byte("x")}) },
		"no digest for an input":           func(f *bindFx) { delete(f.req.Live, ".npmrc") },
		"no digest for the competing name": func(f *bindFx) { delete(f.req.Live, "npm-shrinkwrap.json") },
		"a malformed digest":               func(f *bindFx) { f.req.Live["package.json"] = "md5:abc" },
		"an upper case digest": func(f *bindFx) {
			f.req.Live["package.json"] = "sha256:" + strings.ToUpper(strings.TrimPrefix(f.req.Live["package.json"], "sha256:"))
		},
		"a bad selection":                     func(f *bindFx) { f.req.Selection.Omit = []string{"everything"} },
		"a competing lockfile judged present": func(f *bindFx) { f.req.Live["npm-shrinkwrap.json"] = sum("x") },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			f := newBindFx(t)
			edit(f)
			before := snapshot(t, f.project)
			report := f.bind()
			wantOutcome(t, report, OutcomeRefused, ExitRefused)
			if f.ran() {
				t.Fatal("the install command ran")
			}
			sameSnapshot(t, before, snapshot(t, f.project))
		})
	}
}

func TestBindChildFailureLeavesTheProjectUntouched(t *testing.T) {
	cases := map[string]struct {
		script string
		argv0  string
		reason string
		code   int
		signal string
	}{
		"the child exits non-zero": {script: `echo "npm ERR! boom" >&2; mkdir node_modules; exit 7`, reason: ReasonInstallExit, code: 7},
		"the child is killed":      {script: `mkdir node_modules; kill -9 $$`, reason: ReasonInstallSignaled, code: -1, signal: "killed"},
		"the child cannot start":   {argv0: "/nonexistent/npm", reason: ReasonStartFailed, code: -2},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newBindFx(t)
			if tc.script != "" {
				f.command(tc.script)
			}
			if tc.argv0 != "" {
				f.req.Argv = []string{tc.argv0, "ci"}
			}
			before := snapshot(t, f.project)
			report := f.bind()
			wantOutcome(t, report, OutcomeInstallFailed, ExitInstallFailed)
			if report.Reason != tc.reason {
				t.Fatalf("reason = %s", report.Reason)
			}
			switch {
			case tc.code >= 0:
				if report.Install.ExitCode == nil || *report.Install.ExitCode != tc.code || report.Install.Signal != "" {
					t.Fatalf("install = %+v", report.Install)
				}
				if tc.code == 7 && !strings.Contains(f.output.String(), "npm ERR! boom") {
					t.Fatalf("the child's diagnostic was not passed on: %q", f.output.String())
				}
			case tc.code == -1:
				if report.Install.ExitCode != nil || !strings.Contains(strings.ToLower(report.Install.Signal), tc.signal) {
					t.Fatalf("install = %+v", report.Install)
				}
			default:
				if report.Install.Ran {
					t.Fatalf("install = %+v", report.Install)
				}
			}
			sameSnapshot(t, before, snapshot(t, f.project))
			noStaging(t, f.project)
		})
	}
}

// A signal to project-bind at every stage before publication leaves the
// project untouched and no staging directory.
func TestBindSignalAtEachStageBeforePublication(t *testing.T) {
	stages := []string{"admitted", "staged", "installed", "verifying", "verified", "publish:prepared"}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			f := newBindFx(t)
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			hookAt(t, stage, func() error {
				cancel(errors.New("terminated"))
				return nil
			})
			before := snapshot(t, f.project)
			report := Bind(ctx, f.req)
			wantOutcome(t, report, OutcomeInterrupted, ExitInterrupted)
			if report.Signal != "terminated" || report.Reason != ReasonSignal || report.Publication.State != PublicationNotStarted {
				t.Fatalf("report = %+v", report)
			}
			sameSnapshot(t, before, snapshot(t, f.project))
			noStaging(t, f.project)
		})
	}
}

func TestBindSignalWhileTheChildRuns(t *testing.T) {
	f := newBindFx(t)
	pids := filepath.Join(evalDir(t), "pids")
	f.command(`mkdir node_modules; sleep 60 & echo "$$ $!" > "$PIDS"; wait`)
	f.req.Env = append(f.req.Env, "PIDS="+pids)
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	go func() {
		for i := 0; i < 500; i++ {
			if raw, err := os.ReadFile(pids); err == nil && strings.Contains(string(raw), " ") && strings.HasSuffix(string(raw), "\n") {
				cancel(errors.New("interrupt"))
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		cancel(errors.New("never started"))
	}()
	before := snapshot(t, f.project)
	report := Bind(ctx, f.req)
	wantOutcome(t, report, OutcomeInterrupted, ExitInterrupted)
	if report.Signal != "interrupt" || !report.Install.Ran {
		t.Fatalf("report = %+v", report)
	}
	sameSnapshot(t, before, snapshot(t, f.project))
	noStaging(t, f.project)
	// Neither the child nor what it started is left running.
	raw, _ := os.ReadFile(pids)
	for _, field := range strings.Fields(string(raw)) {
		pid, _ := strconv.Atoi(field)
		deadline := time.Now().Add(3 * time.Second)
		for syscall.Kill(pid, 0) == nil && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
		}
		if err := syscall.Kill(pid, 0); err == nil {
			// A zombie that nobody waits for still answers; read its state.
			stat, _ := os.ReadFile("/proc/" + field + "/stat")
			if !strings.Contains(string(stat), ") Z ") {
				t.Fatalf("process %s survived the interruption", field)
			}
		}
	}
}

func TestBindTreeRootThatIsASymbolicLinkRefusesBeforeAnythingRuns(t *testing.T) {
	f := newBindFx(t)
	behind := evalDir(t)
	put(t, filepath.Join(behind, "victim/package.json"), `{"name":"victim","version":"1.0.0"}`, 0o644)
	put(t, filepath.Join(behind, "canary"), "do not touch", 0o644)
	if err := os.RemoveAll(filepath.Join(f.project, "node_modules")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(behind, filepath.Join(f.project, "node_modules")); err != nil {
		t.Fatal(err)
	}
	before, behindBefore := snapshot(t, f.project), snapshot(t, behind)
	report := f.bind()
	wantOutcome(t, report, OutcomeRefused, ExitRefused)
	if report.Reason != ReasonTreeRootSymlink || f.ran() || report.Install.Ran {
		t.Fatalf("report = %+v", report)
	}
	sameSnapshot(t, before, snapshot(t, f.project))
	sameSnapshot(t, behindBefore, snapshot(t, behind))
}

func TestBindTreeRootThatIsNotADirectoryRefuses(t *testing.T) {
	f := newBindFx(t)
	if err := os.RemoveAll(filepath.Join(f.project, "node_modules")); err != nil {
		t.Fatal(err)
	}
	put(t, filepath.Join(f.project, "node_modules"), "a file", 0o644)
	report := f.bind()
	wantOutcome(t, report, OutcomeRefused, ExitRefused)
	if report.Reason != ReasonTreeRootInvalid || f.ran() {
		t.Fatalf("report = %+v", report)
	}
}

func TestBindRefusesInputsThatAreSymbolicLinks(t *testing.T) {
	for _, rel := range []string{"package.json", "package-lock.json", ".npmrc"} {
		t.Run(rel, func(t *testing.T) {
			f := newBindFx(t)
			real := filepath.Join(evalDir(t), "real")
			put(t, real, "content behind a link", 0o644)
			name := filepath.Join(f.project, rel)
			if err := os.Remove(name); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(real, name); err != nil {
				t.Fatal(err)
			}
			f.judge()
			before := snapshot(t, f.project)
			report := f.bind()
			wantOutcome(t, report, OutcomeRefused, ExitRefused)
			if report.Reason != ReasonInputUnsafe || f.ran() {
				t.Fatalf("report = %+v", report)
			}
			sameSnapshot(t, before, snapshot(t, f.project))
			if raw, _ := os.ReadFile(real); string(raw) != "content behind a link" {
				t.Fatal("the file behind the link was written")
			}
		})
	}
}

func TestBindRefusesAnInputBelowASymbolicLinkedDirectory(t *testing.T) {
	f := newBindFx(t)
	behind := evalDir(t)
	put(t, filepath.Join(behind, "package.json"), `{"name":"w","version":"1.0.0"}`, 0o644)
	if err := os.Symlink(behind, filepath.Join(f.project, "ws")); err != nil {
		t.Fatal(err)
	}
	f.req.Publish = append(f.req.Publish, File{Rel: "ws/package.json", Content: []byte(`{"name":"w","version":"2.0.0"}`)})
	f.req.Live["ws/package.json"] = sum(`{"name":"w","version":"1.0.0"}`)
	report := f.bind()
	wantOutcome(t, report, OutcomeRefused, ExitRefused)
	if report.Reason != ReasonInputUnsafe || f.ran() {
		t.Fatalf("report = %+v", report)
	}
	if raw, _ := os.ReadFile(filepath.Join(behind, "package.json")); !strings.Contains(string(raw), "1.0.0") {
		t.Fatal("the file behind the link was written")
	}
}

// Live inputs changed between judgement and publication refuse without
// publishing and without overwriting the change.
func TestBindInputsChangedBeforeTheRunAreRefused(t *testing.T) {
	f := newBindFx(t)
	put(t, filepath.Join(f.project, "package.json"), `{"name":"root","edited":"since judged"}`, 0o640)
	before := snapshot(t, f.project)
	report := f.bind()
	wantOutcome(t, report, OutcomeInputsChanged, ExitInputsChanged)
	if f.ran() || len(report.Changed) != 1 || report.Changed[0].Path != "package.json" || report.Changed[0].Judged == report.Changed[0].Found {
		t.Fatalf("report = %+v", report)
	}
	sameSnapshot(t, before, snapshot(t, f.project))
}

func TestBindInputsChangedBeforePublicationAreNeverOverwritten(t *testing.T) {
	changes := map[string]struct {
		change func(project string)
		path   string
	}{
		"the manifest":                   {func(p string) { put(t, filepath.Join(p, "package.json"), `{"edited":"manifest"}`, 0o640) }, "package.json"},
		"the lockfile":                   {func(p string) { put(t, filepath.Join(p, "package-lock.json"), `{"edited":"lock"}`, 0o600) }, "package-lock.json"},
		"the configuration":              {func(p string) { put(t, filepath.Join(p, ".npmrc"), "registry=https://evil.example/\n", 0o600) }, ".npmrc"},
		"a competing lockfile appearing": {func(p string) { put(t, filepath.Join(p, "npm-shrinkwrap.json"), `{"lockfileVersion":3}`, 0o644) }, "npm-shrinkwrap.json"},
		"the lockfile removed":           {func(p string) { _ = os.Remove(filepath.Join(p, "package-lock.json")) }, "package-lock.json"},
		"the manifest swapped for a link": {func(p string) {
			_ = os.Remove(filepath.Join(p, "package.json"))
			_ = os.Symlink("/etc/hostname", filepath.Join(p, "package.json"))
		}, ""},
		"the tree root swapped for a link": {func(p string) {
			_ = os.RemoveAll(filepath.Join(p, "node_modules"))
			_ = os.Symlink("/", filepath.Join(p, "node_modules"))
		}, ""},
	}
	for name, tc := range changes {
		for _, stage := range []string{"installed", "verified", "publish:prepared"} {
			t.Run(name+" at "+stage, func(t *testing.T) {
				f := newBindFx(t)
				var afterChange map[string]string
				hookAt(t, stage, func() error {
					tc.change(f.project)
					afterChange = snapshot(t, f.project)
					for name := range afterChange {
						if strings.HasPrefix(name, stagingPrefix) {
							delete(afterChange, name)
						}
					}
					return nil
				})
				report := f.bind()
				wantOutcome(t, report, OutcomeInputsChanged, ExitInputsChanged)
				if tc.path != "" {
					found := false
					for _, change := range report.Changed {
						found = found || change.Path == tc.path
					}
					if !found {
						t.Fatalf("changed = %+v", report.Changed)
					}
				}
				if report.Publication.State != PublicationNotStarted {
					t.Fatalf("publication = %+v", report.Publication)
				}
				noStaging(t, f.project)
				// Byte for byte what the change made it: nothing published,
				// nothing overwritten, the old tree where it was.
				sameSnapshot(t, afterChange, snapshot(t, f.project))
				// The project is what the change made it, and nothing of ours.
				after := snapshot(t, f.project)
				for _, rel := range []string{"node_modules/a/package.json", "node_modules/@s"} {
					if _, ok := after[rel]; ok && tc.path != "" && name != "the tree root swapped for a link" {
						t.Fatalf("%s of the new tree was published", rel)
					}
				}
				if tc.path == "package.json" {
					if raw, _ := os.ReadFile(filepath.Join(f.project, "package.json")); !strings.Contains(string(raw), "manifest") {
						t.Fatalf("the edit was overwritten: %q", raw)
					}
				}
				if tc.path == "package-lock.json" && name == "the lockfile" {
					if raw, _ := os.ReadFile(filepath.Join(f.project, "package-lock.json")); !strings.Contains(string(raw), "edited") {
						t.Fatalf("the edit was overwritten: %q", raw)
					}
				}
				if tc.path == ".npmrc" {
					if raw, _ := os.ReadFile(filepath.Join(f.project, ".npmrc")); !strings.Contains(string(raw), "evil") {
						t.Fatalf("the edit was overwritten: %q", raw)
					}
				}
			})
		}
	}
}

func TestBindOldTreeIsKeptWhenInputsChange(t *testing.T) {
	f := newBindFx(t)
	hookAt(t, "verified", func() error {
		put(t, filepath.Join(f.project, "package.json"), `{"edited":true}`, 0o640)
		return nil
	})
	report := f.bind()
	wantOutcome(t, report, OutcomeInputsChanged, ExitInputsChanged)
	if raw, err := os.ReadFile(filepath.Join(f.project, "node_modules/old/data")); err != nil || string(raw) != "old tree content" {
		t.Fatalf("the old tree is gone: %v", err)
	}
}

// An edit that lands during publication, after the last check, survives and
// the publication is undone.
func TestBindAnEditDuringPublicationSurvivesAndPublicationIsUndone(t *testing.T) {
	for _, tc := range []struct{ stage, rel string }{
		{"publish:journaled", "package.json"},
		{"publish:tree_aside", "package-lock.json"},
		{"publish:tree_in", "package.json"},
		{"publish:file:0", "package-lock.json"},
	} {
		t.Run(tc.stage+" "+tc.rel, func(t *testing.T) {
			f := newBindFx(t)
			name := filepath.Join(f.project, tc.rel)
			hookAt(t, tc.stage, func() error {
				// In place, as an editor that truncates and writes would.
				return os.WriteFile(name, []byte(`{"edited":"during publication"}`), 0o640)
			})
			report := f.bind()
			wantOutcome(t, report, OutcomeInputsChanged, ExitInputsChanged)
			if report.Publication.State != PublicationRolledBack {
				t.Fatalf("publication = %+v", report.Publication)
			}
			if raw, _ := os.ReadFile(name); !strings.Contains(string(raw), "during publication") {
				t.Fatalf("the edit was overwritten or reverted: %q", raw)
			}
			if raw, err := os.ReadFile(filepath.Join(f.project, "node_modules/old/data")); err != nil || string(raw) != "old tree content" {
				t.Fatalf("the old tree was not put back: %v", err)
			}
			if _, err := os.Stat(filepath.Join(f.project, "node_modules/a")); err == nil {
				t.Fatal("the new tree is still in place")
			}
			noStaging(t, f.project)
		})
	}
}

// A failure inside publication is undone in process; a crash is undone by the
// next run. At no point is the tree in place anything but the old one, none,
// or the verified one.
func TestBindFailureInsidePublicationIsUndone(t *testing.T) {
	for _, stage := range []string{"publish:journaled", "publish:tree_aside", "publish:tree_in", "publish:file:0", "publish:file:1"} {
		t.Run(stage, func(t *testing.T) {
			f := newBindFx(t)
			hookAt(t, stage, func() error { return errors.New("disk on fire") })
			before := snapshot(t, f.project)
			report := f.bind()
			wantOutcome(t, report, OutcomePublicationFailed, ExitPublicationFailed)
			if report.Publication.State != PublicationRolledBack || len(report.Publication.Conflicts) != 0 {
				t.Fatalf("publication = %+v", report.Publication)
			}
			sameSnapshot(t, before, snapshot(t, f.project))
			noStaging(t, f.project)
		})
	}
}

func TestBindCrashInsidePublicationIsUndoneByTheNextRun(t *testing.T) {
	type state struct {
		treeInPlace string // "old", "none" or "new"
		files       int    // judged files already replaced
	}
	cases := map[string]state{
		"publish:prepared":   {"old", 0},
		"publish:journaled":  {"old", 0},
		"publish:tree_aside": {"none", 0},
		"publish:tree_in":    {"new", 0},
		"publish:file:0":     {"new", 1},
		"publish:file:1":     {"new", 2},
	}
	for stage, want := range cases {
		t.Run(stage, func(t *testing.T) {
			f := newBindFx(t)
			before := snapshot(t, f.project)
			hookAt(t, stage, func() error { return errCrash })
			f.bind()
			bindHook = nil

			// What the interrupted publication left.
			switch want.treeInPlace {
			case "old":
				if raw, err := os.ReadFile(filepath.Join(f.project, "node_modules/old/data")); err != nil || string(raw) != "old tree content" {
					t.Fatalf("expected the old tree: %v", err)
				}
			case "none":
				if _, err := os.Lstat(filepath.Join(f.project, "node_modules")); err == nil {
					t.Fatal("expected no tree in place")
				}
			case "new":
				// Never an unverified tree: what is in place is the judged one.
				if report, err := VerifyTree(f.lockfile, f.project, linuxX64); err != nil || !report.Ok {
					t.Fatalf("the tree in place does not verify: %+v %v", report, err)
				}
			}
			replaced := 0
			for _, rel := range []string{"package.json", "package-lock.json"} {
				raw, _ := os.ReadFile(filepath.Join(f.project, rel))
				if !strings.Contains(string(raw), "old") && !strings.Contains(string(raw), `"packages":{"":{"name":"root"}}`) {
					replaced++
				}
			}
			if replaced != want.files {
				t.Fatalf("replaced files = %d, want %d", replaced, want.files)
			}

			// The next run finds the staging directory and undoes it.
			recovery := Recover(f.project)
			if recovery.Found != 1 || len(recovery.Left) != 0 || len(recovery.Conflict) != 0 {
				t.Fatalf("recovery = %+v", recovery)
			}
			sameSnapshot(t, before, snapshot(t, f.project))
			noStaging(t, f.project)
		})
	}
}

func TestBindNextRunRecoversAndGoesOn(t *testing.T) {
	f := newBindFx(t)
	before := snapshot(t, f.project)
	hookAt(t, "publish:tree_in", func() error { return errCrash })
	f.bind()
	bindHook = nil
	report := f.bind()
	wantOutcome(t, report, OutcomePublished, ExitPublished)
	if report.Recovery.Found != 1 || report.Recovery.Undone != 1 || report.Recovery.Removed != 1 {
		t.Fatalf("recovery = %+v", report.Recovery)
	}
	noStaging(t, f.project)
	_ = before
	if verified, err := VerifyTree(f.lockfile, f.project, linuxX64); err != nil || !verified.Ok {
		t.Fatalf("%+v %v", verified, err)
	}
}

func TestBindCrashAfterTheCommitLeavesGarbageThatIsRemoved(t *testing.T) {
	f := newBindFx(t)
	hookAt(t, "publish:committed", func() error { return errCrash })
	f.bind()
	bindHook = nil
	// The project is final; the staging directory holds the old tree and no
	// journal.
	if verified, err := VerifyTree(f.lockfile, f.project, linuxX64); err != nil || !verified.Ok {
		t.Fatalf("%+v %v", verified, err)
	}
	items, _ := os.ReadDir(f.project)
	staging := ""
	for _, item := range items {
		if strings.HasPrefix(item.Name(), stagingPrefix) {
			staging = item.Name()
		}
	}
	if staging == "" {
		t.Fatal("no staging directory was left")
	}
	recovery := Recover(f.project)
	if recovery.Found != 1 || recovery.Removed != 1 || recovery.Undone != 0 {
		t.Fatalf("recovery = %+v", recovery)
	}
	noStaging(t, f.project)
	if verified, err := VerifyTree(f.lockfile, f.project, linuxX64); err != nil || !verified.Ok {
		t.Fatal("recovery touched a committed project")
	}
}

func TestRecoverKeepsAnEditMadeAfterACrash(t *testing.T) {
	f := newBindFx(t)
	hookAt(t, "publish:file:0", func() error { return errCrash })
	f.bind()
	bindHook = nil
	edited := `{"name":"root","edited":"after the crash"}`
	put(t, filepath.Join(f.project, "package.json"), edited, 0o640)
	recovery := Recover(f.project)
	if len(recovery.Conflict) != 1 || recovery.Conflict[0] != "package.json" || len(recovery.Left) != 0 {
		t.Fatalf("recovery = %+v", recovery)
	}
	if raw, _ := os.ReadFile(filepath.Join(f.project, "package.json")); string(raw) != edited {
		t.Fatalf("the edit was reverted: %q", raw)
	}
	if raw, err := os.ReadFile(filepath.Join(f.project, "node_modules/old/data")); err != nil || string(raw) != "old tree content" {
		t.Fatalf("the old tree was not put back: %v", err)
	}
	noStaging(t, f.project)
}

func TestRecoverNeverFollowsOrDeletesWhatIsNotItsOwn(t *testing.T) {
	f := newBindFx(t)
	behind := evalDir(t)
	put(t, filepath.Join(behind, "keep"), "x", 0o644)
	if err := os.Symlink(behind, filepath.Join(f.project, stagingPrefix+"link")); err != nil {
		t.Fatal(err)
	}
	report := f.bind()
	wantOutcome(t, report, OutcomeRefused, ExitRefused)
	if report.Reason != ReasonRecoveryIncomplete || f.ran() {
		t.Fatalf("report = %+v", report)
	}
	if _, err := os.Stat(filepath.Join(behind, "keep")); err != nil {
		t.Fatal("recovery followed a link")
	}
}

func TestBindPublicationIsDeferredWhenASignalArrivesDuringIt(t *testing.T) {
	f := newBindFx(t)
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	hookAt(t, "publish:tree_in", func() error { cancel(errors.New("terminated")); return nil })
	report := Bind(ctx, f.req)
	wantOutcome(t, report, OutcomePublished, ExitPublished)
	if report.Signal != "terminated" || report.Publication.State != PublicationCommitted {
		t.Fatalf("report = %+v", report)
	}
	if verified, err := VerifyTree(f.lockfile, f.project, linuxX64); err != nil || !verified.Ok {
		t.Fatalf("%+v %v", verified, err)
	}
}

// The lock.
func TestBindRefusesWithoutTheProjectLockHeld(t *testing.T) {
	t.Run("a descriptor on the project that holds no lock", func(t *testing.T) {
		f := newBindFx(t)
		unlocked, err := os.Open(f.project)
		if err != nil {
			t.Fatal(err)
		}
		defer unlocked.Close()
		_ = syscall.Flock(int(f.lock.Fd()), syscall.LOCK_UN)
		f.req.Lock = LockMode{FD: int(unlocked.Fd())}
		before := snapshot(t, f.project)
		report := f.bind()
		wantOutcome(t, report, OutcomeRefused, ExitRefused)
		if report.Reason != ReasonLockNotHeld || f.ran() {
			t.Fatalf("report = %+v", report)
		}
		sameSnapshot(t, before, snapshot(t, f.project))
	})
	t.Run("a shared lock is not exclusive", func(t *testing.T) {
		f := newBindFx(t)
		_ = syscall.Flock(int(f.lock.Fd()), syscall.LOCK_UN)
		if err := syscall.Flock(int(f.lock.Fd()), syscall.LOCK_SH); err != nil {
			t.Fatal(err)
		}
		report := f.bind()
		wantOutcome(t, report, OutcomeRefused, ExitRefused)
		if report.Reason != ReasonLockNotHeld {
			t.Fatalf("report = %+v", report)
		}
	})
	t.Run("a lock held through another descriptor is not the caller's", func(t *testing.T) {
		f := newBindFx(t)
		other, err := os.Open(f.project)
		if err != nil {
			t.Fatal(err)
		}
		defer other.Close()
		f.req.Lock = LockMode{FD: int(other.Fd())}
		report := f.bind() // f.lock holds LOCK_EX, other holds nothing
		wantOutcome(t, report, OutcomeRefused, ExitRefused)
		if report.Reason != ReasonLockNotHeld || f.ran() {
			t.Fatalf("report = %+v", report)
		}
	})
	t.Run("a lock on another directory", func(t *testing.T) {
		f := newBindFx(t)
		elsewhere, err := os.Open(evalDir(t))
		if err != nil {
			t.Fatal(err)
		}
		defer elsewhere.Close()
		_ = syscall.Flock(int(elsewhere.Fd()), syscall.LOCK_EX)
		f.req.Lock = LockMode{FD: int(elsewhere.Fd())}
		report := f.bind()
		wantOutcome(t, report, OutcomeRefused, ExitRefused)
		if report.Reason != ReasonLockNotHeld || f.ran() {
			t.Fatalf("report = %+v", report)
		}
	})
	t.Run("a descriptor that is not a directory", func(t *testing.T) {
		f := newBindFx(t)
		file, err := os.Create(filepath.Join(evalDir(t), "x"))
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_EX)
		f.req.Lock = LockMode{FD: int(file.Fd())}
		report := f.bind()
		if report.Reason != ReasonLockNotHeld || f.ran() {
			t.Fatalf("report = %+v", report)
		}
	})
	t.Run("a descriptor that is not open", func(t *testing.T) {
		f := newBindFx(t)
		f.req.Lock = LockMode{FD: 987}
		report := f.bind()
		if report.Reason != ReasonLockNotHeld || f.ran() {
			t.Fatalf("report = %+v", report)
		}
	})
	t.Run("no descriptor", func(t *testing.T) {
		f := newBindFx(t)
		f.req.Lock = LockMode{FD: -1}
		report := f.bind()
		if report.Reason != ReasonLockNotHeld || f.ran() {
			t.Fatalf("report = %+v", report)
		}
	})
}

func TestBindTakesTheLockItselfOnlyWhenNobodyHoldsIt(t *testing.T) {
	f := newBindFx(t)
	f.req.Lock = LockMode{FD: -1, Take: true}
	// f.lock holds the project: another holder exists, so this refuses.
	report := f.bind()
	wantOutcome(t, report, OutcomeRefused, ExitRefused)
	if report.Reason != ReasonLockBusy || f.ran() {
		t.Fatalf("report = %+v", report)
	}
	// Once released it takes it, runs, and lets it go again.
	_ = syscall.Flock(int(f.lock.Fd()), syscall.LOCK_UN)
	wantOutcome(t, f.bind(), OutcomePublished, ExitPublished)
	probe, _ := os.Open(f.project)
	defer probe.Close()
	if err := syscall.Flock(int(probe.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("the lock was not released: %v", err)
	}
}

func TestBindRefusesAProjectThatIsNotADirectory(t *testing.T) {
	f := newBindFx(t)
	f.req.Project = filepath.Join(f.project, "package.json")
	report := f.bind()
	wantOutcome(t, report, OutcomeRefused, ExitRefused)
	if report.Reason != ReasonProjectInvalid {
		t.Fatalf("report = %+v", report)
	}
	f.req.Project = filepath.Join(f.project, "absent")
	if report := f.bind(); report.Reason != ReasonProjectInvalid {
		t.Fatalf("report = %+v", report)
	}
}

// The verifier standing alone keeps its promises on the published tree too.
func TestBindStagingIsPrivateAndUnpredictable(t *testing.T) {
	f := newBindFx(t)
	var names []string
	hookAt(t, "installed", func() error {
		items, _ := os.ReadDir(f.project)
		for _, item := range items {
			if strings.HasPrefix(item.Name(), stagingPrefix) {
				names = append(names, item.Name())
				info, _ := os.Lstat(filepath.Join(f.project, item.Name()))
				if info.Mode().Perm() != 0o700 || !info.IsDir() {
					t.Errorf("staging mode = %v", info.Mode())
				}
			}
		}
		return nil
	})
	wantOutcome(t, f.bind(), OutcomePublished, ExitPublished)
	if len(names) != 1 || len(names[0]) != len(stagingPrefix)+32 {
		t.Fatalf("staging names = %v", names)
	}
	g := newBindFx(t)
	var other []string
	hookAt(t, "installed", func() error {
		items, _ := os.ReadDir(g.project)
		for _, item := range items {
			if strings.HasPrefix(item.Name(), stagingPrefix) {
				other = append(other, item.Name())
			}
		}
		return nil
	})
	wantOutcome(t, g.bind(), OutcomePublished, ExitPublished)
	if len(other) != 1 || other[0] == names[0] {
		t.Fatalf("staging names repeat: %v %v", names, other)
	}
}

// An old tree with read-only directories (npm writes some) is still removed,
// and the report says so only because it checked.
func TestBindRemovesAnOldTreeWithReadOnlyDirectories(t *testing.T) {
	f := newBindFx(t)
	readOnly := filepath.Join(f.project, "node_modules/old/ro")
	put(t, filepath.Join(readOnly, "file"), "x", 0o444)
	if err := os.Chmod(readOnly, 0o555); err != nil {
		t.Fatal(err)
	}
	report := f.bind()
	wantOutcome(t, report, OutcomePublished, ExitPublished)
	if !report.Staging.Removed {
		t.Fatalf("staging = %+v", report.Staging)
	}
	noStaging(t, f.project)
}
