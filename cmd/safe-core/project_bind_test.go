package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The command is exercised as a real process: the test binary re-executes
// itself as safe-core, so that signals, descriptors and exit statuses are the
// ones a caller sees.
func TestMain(m *testing.M) {
	if os.Getenv("SAFE_CORE_TEST_AS_MAIN") == "1" {
		os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

func safeCore(args ...string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), "SAFE_CORE_TEST_AS_MAIN=1")
	return cmd
}

func digest(content string) string {
	sum := sha256.Sum256([]byte(content))
	return "sha256:" + hex.EncodeToString(sum[:])
}

const (
	bindOldManifest = `{"name":"root","version":"1.0.0"}`
	bindOldLock     = `{"lockfileVersion":3,"packages":{"":{"name":"root"}}}`
	bindNewManifest = `{"name":"root","version":"1.0.0","dependencies":{"a":"1.0.0"}}`
	bindNewLock     = `{"lockfileVersion":3,"packages":{"":{"name":"root"},"node_modules/a":{"version":"1.0.0"}}}`
	buildTree       = `mkdir -p node_modules/a && printf '{"name":"a","version":"1.0.0"}' > node_modules/a/package.json`
)

type bindProject struct {
	t        *testing.T
	project  string
	judged   string
	env      string
	baseArgs []string
}

func newBindProject(t *testing.T) *bindProject {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := &bindProject{t: t, project: filepath.Join(root, "project"), judged: filepath.Join(root, "judged")}
	for _, dir := range []string{p.project, p.judged, filepath.Join(p.project, "node_modules/old")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(name, content string, mode os.FileMode) {
		if err := os.WriteFile(name, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(name, mode)
	}
	write(filepath.Join(p.project, "package.json"), bindOldManifest, 0o640)
	write(filepath.Join(p.project, "package-lock.json"), bindOldLock, 0o600)
	write(filepath.Join(p.project, "node_modules/old/package.json"), `{"name":"old","version":"1.0.0"}`, 0o644)
	write(filepath.Join(p.judged, "package.json"), bindNewManifest, 0o644)
	write(filepath.Join(p.judged, "package-lock.json"), bindNewLock, 0o644)
	p.env = filepath.Join(root, "env")
	write(p.env, "PATH=/usr/bin:/bin\x00MARK="+filepath.Join(root, "mark")+"\x00", 0o600)
	p.baseArgs = []string{
		"project-bind", "--project", p.project,
		"--publish", "package.json=" + filepath.Join(p.judged, "package.json"),
		"--publish", "package-lock.json=" + filepath.Join(p.judged, "package-lock.json"),
		"--live", "package.json=" + digest(bindOldManifest),
		"--live", "package-lock.json=" + digest(bindOldLock),
		"--live", "npm-shrinkwrap.json=absent",
		"--env-file", p.env, "--os", "linux", "--cpu", "x64",
	}
	return p
}

func (p *bindProject) args(extra []string, script string) []string {
	args := append(append([]string{}, p.baseArgs...), extra...)
	return append(args, "--", "/bin/sh", "-c", script)
}

type bound struct {
	Outcome string `json:"outcome"`
	Exit    int    `json:"exit"`
	Reason  string `json:"reason"`
	Signal  string `json:"signal"`
	Staging struct {
		Removed bool `json:"removed"`
	} `json:"staging"`
	Install struct {
		Ran      bool `json:"ran"`
		ExitCode *int `json:"exit_code"`
	} `json:"install"`
	Recovery struct {
		Found, Removed int
	} `json:"recovery"`
}

func decodeBound(t *testing.T, stdout []byte) bound {
	t.Helper()
	var out bound
	if err := json.Unmarshal(stdout, &out); err != nil {
		t.Fatalf("not a document: %v\n%s", err, stdout)
	}
	return out
}

func tree(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	_ = filepath.WalkDir(dir, func(name string, entry fs.DirEntry, err error) error {
		rel, _ := filepath.Rel(dir, name)
		info, lerr := os.Lstat(name)
		if lerr != nil {
			return nil
		}
		raw, _ := os.ReadFile(name)
		out[rel] = info.Mode().String() + ":" + digest(string(raw))
		return nil
	})
	return out
}

func sameTree(t *testing.T, before, after map[string]string) {
	t.Helper()
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

func run3(cmd *exec.Cmd) (bound, int, string) {
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if exit, ok := err.(*exec.ExitError); ok {
		code = exit.ExitCode()
	}
	var out bound
	_ = json.Unmarshal(stdout.Bytes(), &out)
	return out, code, stderr.String()
}

func TestProjectBindPublishesAndReportsOneDocument(t *testing.T) {
	p := newBindProject(t)
	cmd := safeCore(p.args([]string{"--take-lock"}, buildTree)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%v\n%s\n%s", err, stdout.String(), stderr.String())
	}
	out := decodeBound(t, stdout.Bytes())
	if out.Outcome != "published" || out.Exit != 0 || !out.Staging.Removed {
		t.Fatalf("document = %s", stdout.String())
	}
	if strings.Count(strings.TrimSpace(stdout.String()), "\n") != 0 {
		t.Fatalf("stdout is more than one document: %q", stdout.String())
	}
	if raw, _ := os.ReadFile(filepath.Join(p.project, "package.json")); string(raw) != bindNewManifest {
		t.Fatalf("package.json = %q", raw)
	}
	info, _ := os.Stat(filepath.Join(p.project, "package.json"))
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %v", info.Mode())
	}
	if _, err := os.Stat(filepath.Join(p.project, "node_modules/a/package.json")); err != nil {
		t.Fatal(err)
	}
}

// Each outcome has its own status, and the child's status is kept apart.
func TestProjectBindExitStatusesTellTheOutcomesApart(t *testing.T) {
	cases := map[string]struct {
		script  string
		extra   []string
		mutate  func(p *bindProject)
		outcome string
		code    int
	}{
		"published": {script: buildTree, outcome: "published", code: 0},
		"refused before running": {script: buildTree, mutate: func(p *bindProject) {
			_ = os.RemoveAll(filepath.Join(p.project, "node_modules"))
			_ = os.Symlink(t.TempDir(), filepath.Join(p.project, "node_modules"))
		}, outcome: "refused", code: 30},
		"the install failed":  {script: "exit 9", outcome: "install_failed", code: 31},
		"verification failed": {script: "mkdir node_modules", outcome: "verification_failed", code: 32},
		"inputs changed": {script: buildTree, mutate: func(p *bindProject) {
			_ = os.WriteFile(filepath.Join(p.project, "package.json"), []byte(`{"edited":1}`), 0o640)
		}, outcome: "inputs_changed", code: 33},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p := newBindProject(t)
			if tc.mutate != nil {
				tc.mutate(p)
			}
			out, code, stderr := run3(safeCore(p.args(append([]string{"--take-lock"}, tc.extra...), tc.script)...))
			if out.Outcome != tc.outcome || out.Exit != tc.code || code != tc.code {
				t.Fatalf("outcome = %s, document exit = %d, status = %d, want %s/%d\n%s", out.Outcome, out.Exit, code, tc.outcome, tc.code, stderr)
			}
			if tc.outcome == "install_failed" && (out.Install.ExitCode == nil || *out.Install.ExitCode != 9) {
				t.Fatalf("the child's status is not kept: %+v", out.Install)
			}
		})
	}
}

func TestProjectBindUsage(t *testing.T) {
	p := newBindProject(t)
	for name, args := range map[string][]string{
		"no lock choice":            p.args(nil, buildTree),
		"both lock choices":         p.args([]string{"--take-lock", "--lock-fd", "3"}, buildTree),
		"no command":                append(append([]string{}, p.baseArgs...), "--take-lock"),
		"no selection":              {"project-bind", "--project", p.project, "--take-lock", "--env-file", p.env, "--publish", "a=b", "--live", "a=absent", "--", "/bin/true"},
		"a lock descriptor below 3": p.args([]string{"--lock-fd", "1"}, buildTree),
		"an unknown flag":           p.args([]string{"--take-lock", "--force"}, buildTree),
	} {
		t.Run(name, func(t *testing.T) {
			cmd := safeCore(args...)
			var stdout bytes.Buffer
			cmd.Stdout = &stdout
			err := cmd.Run()
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 2 || stdout.Len() != 0 {
				t.Fatalf("err = %v, stdout = %q", err, stdout.String())
			}
		})
	}
}

func TestProjectBindRefusesWithoutTheLockAndAcceptsTheCallersDescriptor(t *testing.T) {
	p := newBindProject(t)
	held, err := os.Open(p.project)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	// The caller opened the directory and did not lock it.
	cmd := safeCore(p.args([]string{"--lock-fd", "3"}, buildTree)...)
	cmd.ExtraFiles = []*os.File{held}
	before := tree(t, p.project)
	out, code, _ := run3(cmd)
	if code != 30 || out.Reason != "lock_not_held" || out.Install.Ran {
		t.Fatalf("code = %d, document = %+v", code, out)
	}
	sameTree(t, before, tree(t, p.project))

	// The caller took the lock and passes the descriptor.
	if err := syscall.Flock(int(held.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	cmd = safeCore(p.args([]string{"--lock-fd", "3"}, buildTree)...)
	cmd.ExtraFiles = []*os.File{held}
	out, code, stderr := run3(cmd)
	if code != 0 || out.Outcome != "published" {
		t.Fatalf("code = %d, document = %+v\n%s", code, out, stderr)
	}
	// The caller still holds its lock afterwards: project-bind does not
	// release what it did not take.
	probe, _ := os.Open(p.project)
	defer probe.Close()
	if err := syscall.Flock(int(probe.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
		t.Fatal("the caller's lock was released by project-bind")
	}
}

// Two lock holders cannot exist: while one process holds the project, a
// second is refused and runs nothing.
func TestProjectBindTwoProcessesCannotHoldTheLock(t *testing.T) {
	p := newBindProject(t)
	release := filepath.Join(t.TempDir(), "release")
	started := filepath.Join(t.TempDir(), "started")
	slow := `touch "$STARTED"; while [ ! -e "$RELEASE" ]; do sleep 0.05; done; ` + buildTree
	envFile := p.env
	raw, _ := os.ReadFile(envFile)
	_ = os.WriteFile(envFile, append(raw, []byte("RELEASE="+release+"\x00STARTED="+started+"\x00")...), 0o600)

	first := safeCore(p.args([]string{"--take-lock"}, slow)...)
	var firstOut bytes.Buffer
	first.Stdout = &firstOut
	if err := first.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for _, err := os.Stat(started); err != nil && time.Now().Before(deadline); _, err = os.Stat(started) {
		time.Sleep(20 * time.Millisecond)
	}

	// A second one, taking the lock itself, is refused while the first runs.
	second, code, _ := run3(safeCore(p.args([]string{"--take-lock"}, buildTree)...))
	if code != 30 || second.Reason != "lock_held_by_another" || second.Install.Ran {
		t.Fatalf("the second holder: code = %d, document = %+v", code, second)
	}
	// And so is one that was handed a descriptor of its own on the project.
	own, _ := os.Open(p.project)
	defer own.Close()
	third := safeCore(p.args([]string{"--lock-fd", "3"}, buildTree)...)
	third.ExtraFiles = []*os.File{own}
	thirdOut, code, _ := run3(third)
	if code != 30 || thirdOut.Reason != "lock_not_held" || thirdOut.Install.Ran {
		t.Fatalf("the third holder: code = %d, document = %+v", code, thirdOut)
	}

	if err := os.WriteFile(release, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := first.Wait(); err != nil {
		t.Fatalf("the first holder: %v\n%s", err, firstOut.String())
	}
	if out := decodeBound(t, firstOut.Bytes()); out.Outcome != "published" {
		t.Fatalf("the first holder: %+v", out)
	}
}

func startSlow(t *testing.T, p *bindProject, extra ...string) (*exec.Cmd, *bytes.Buffer, string) {
	t.Helper()
	dir := t.TempDir()
	pids := filepath.Join(dir, "pids")
	raw, _ := os.ReadFile(p.env)
	_ = os.WriteFile(p.env, append(raw, []byte("PIDS="+pids+"\x00")...), 0o600)
	cmd := safeCore(p.args(append([]string{"--take-lock"}, extra...), `mkdir node_modules; sleep 60 & echo "$$ $!" > "$PIDS"; wait`)...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if raw, err := os.ReadFile(pids); err == nil && strings.HasSuffix(string(raw), "\n") && strings.Contains(string(raw), " ") {
			return cmd, &stdout, pids
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = cmd.Process.Kill()
	t.Fatal("the install command never started")
	return nil, nil, ""
}

func gone(t *testing.T, pids string) {
	t.Helper()
	goneOf(t, pids, 2)
}

// goneOf checks the first n processes of the pid file are not running.
func goneOf(t *testing.T, pids string, n int) {
	t.Helper()
	raw, _ := os.ReadFile(pids)
	fields := strings.Fields(string(raw))
	if len(fields) > n {
		fields = fields[:n]
	}
	for _, field := range fields {
		pid, _ := strconv.Atoi(field)
		deadline := time.Now().Add(5 * time.Second)
		for syscall.Kill(pid, 0) == nil && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
		}
		if syscall.Kill(pid, 0) == nil {
			if stat, _ := os.ReadFile("/proc/" + field + "/stat"); !strings.Contains(string(stat), ") Z ") {
				t.Fatalf("process %s is still running", field)
			}
		}
	}
}

func TestProjectBindSignalsLeaveTheProjectUntouched(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP} {
		t.Run(sig.String(), func(t *testing.T) {
			p := newBindProject(t)
			before := tree(t, p.project)
			cmd, stdout, pids := startSlow(t, p)
			if err := cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			err := cmd.Wait()
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 34 {
				t.Fatalf("err = %v\n%s", err, stdout.String())
			}
			out := decodeBound(t, stdout.Bytes())
			if out.Outcome != "interrupted" || out.Signal == "" || !out.Staging.Removed {
				t.Fatalf("document = %s", stdout.String())
			}
			sameTree(t, before, tree(t, p.project))
			gone(t, pids)
			// The lock went with the process.
			probe, _ := os.Open(p.project)
			defer probe.Close()
			if err := syscall.Flock(int(probe.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
				t.Fatalf("the lock is still held: %v", err)
			}
		})
	}
}

// A SIGKILL cannot be handled: the child dies with the process (the kernel
// sees to it), the staging directory is left, and the next run removes it.
func TestProjectBindKilledLeavesNoRunningChildAndTheNextRunCleansUp(t *testing.T) {
	p := newBindProject(t)
	before := tree(t, p.project)
	cmd, _, pids := startSlow(t, p)
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	// The child dies with project-bind (the kernel sees to it). What the child
	// itself started is not covered by that and is ended by hand here: it can
	// only write into the orphaned staging directory, which the next run
	// removes (documented residual).
	goneOf(t, pids, 1)
	if raw, _ := os.ReadFile(pids); len(strings.Fields(string(raw))) == 2 {
		pid, _ := strconv.Atoi(strings.Fields(string(raw))[1])
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
	// Nothing but the staging directory differs.
	after := tree(t, p.project)
	left := ""
	for name := range after {
		if strings.HasPrefix(name, ".safe-bind-") && !strings.Contains(name, "/") {
			left = name
		}
		if !strings.HasPrefix(name, ".safe-bind-") {
			if before[name] != after[name] {
				t.Fatalf("%s changed", name)
			}
		}
	}
	if left == "" {
		t.Fatal("expected a staging directory after a SIGKILL")
	}
	out, code, stderr := run3(safeCore(p.args([]string{"--take-lock"}, buildTree)...))
	if code != 0 || out.Outcome != "published" || out.Recovery.Found != 1 || out.Recovery.Removed != 1 {
		t.Fatalf("code = %d, document = %+v\n%s", code, out, stderr)
	}
	if _, err := os.Lstat(filepath.Join(p.project, left)); err == nil {
		t.Fatal("the stale staging directory is still there")
	}
}

func TestProjectTreeCommand(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, "lock.json")
	_ = os.WriteFile(lock, []byte(bindNewLock), 0o644)
	good, bad := filepath.Join(dir, "good"), filepath.Join(dir, "bad")
	for _, root := range []string{good, bad} {
		if err := os.MkdirAll(filepath.Join(root, "node_modules/a"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.WriteFile(filepath.Join(good, "node_modules/a/package.json"), []byte(`{"name":"a","version":"1.0.0"}`), 0o644)
	_ = os.WriteFile(filepath.Join(bad, "node_modules/a/package.json"), []byte(`{"name":"a","version":"9.9.9"}`), 0o644)
	links := filepath.Join(dir, "links.json")
	_ = os.WriteFile(links, []byte(`{"lockfileVersion":3,"packages":{"":{},"node_modules/l":{"resolved":"p","link":true}}}`), 0o644)
	selection := []string{"--os", "linux", "--cpu", "x64"}
	for name, tc := range map[string]struct {
		args []string
		code int
		out  string
	}{
		"a tree that matches":           {append(append([]string{"project-tree"}, selection...), lock, good), 0, `"ok":true`},
		"a tree that does not":          {append(append([]string{"project-tree"}, selection...), lock, bad), 32, `"problem":"wrong_version"`},
		"a lockfile with links":         {append(append([]string{"project-tree"}, selection...), links, good), 30, ""},
		"an unreadable lockfile":        {append(append([]string{"project-tree"}, selection...), filepath.Join(dir, "none"), good), 3, ""},
		"a directory that is not there": {append(append([]string{"project-tree"}, selection...), lock, filepath.Join(dir, "none")), 3, ""},
		"no platform":                   {[]string{"project-tree", lock, good}, 2, ""},
		"an unknown flag":               {append(append([]string{"project-tree", "--quick"}, selection...), lock, good), 2, ""},
		"an omit that is not one":       {append(append([]string{"project-tree", "--omit", "all"}, selection...), lock, good), 3, ""},
	} {
		t.Run(name, func(t *testing.T) {
			cmd := safeCore(tc.args...)
			var stdout bytes.Buffer
			cmd.Stdout = &stdout
			err := cmd.Run()
			code := 0
			if exit, ok := err.(*exec.ExitError); ok {
				code = exit.ExitCode()
			}
			if code != tc.code || !strings.Contains(stdout.String(), tc.out) {
				t.Fatalf("code = %d (want %d), stdout = %s", code, tc.code, stdout.String())
			}
		})
	}
}
