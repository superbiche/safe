package releasereview

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func execSpec(artifact string, args []string, timeout int) Spec {
	return Spec{
		SpecVersion: 1,
		Subject:     Subject{Repo: "o/r", Version: "v1"},
		Artifacts:   []Artifact{{Path: artifact, AssetName: filepath.Base(artifact)}},
		Checks: &Checks{Exec: &ExecCheck{
			CheckConfig:    CheckConfig{Enabled: true},
			Artifact:       artifact,
			Args:           args,
			TimeoutSeconds: timeout,
		}},
	}
}

// execFixture writes a runnable file, puts the fake podman on PATH, and returns
// the artifact plus the path the fake logs its arguments to.
func execFixture(t *testing.T) (artifact, argLog string) {
	t.Helper()
	withFakeTools(t, "podman")

	dir := t.TempDir()
	artifact = writeFile(t, dir, "tool", "#!/bin/sh\nexit 0\n")
	argLog = filepath.Join(dir, "podman-args.log")
	t.Setenv("MOCK_PODMAN_LOG", argLog)
	return artifact, argLog
}

func TestExecCleanRunPinsTheSandboxPolicy(t *testing.T) {
	artifact, argLog := execFixture(t)

	result := sandboxExec(execSpec(artifact, []string{"--version"}, 5))
	if result.Verdict != GO || len(result.Reasons) != 0 {
		t.Fatalf("verdict %s with reasons %v, want a clean GO", result.Verdict, codes(result))
	}

	logged, err := os.ReadFile(argLog)
	if err != nil {
		t.Fatalf("read the arg log: %v", err)
	}
	args := strings.Split(strings.TrimRight(string(logged), "\n"), "\n")

	// The sandbox is the whole safety argument for running a stranger's binary,
	// so every flag is pinned rather than spot-checked: a flag lost in a
	// refactor would silently widen what an unreviewed release may do.
	for _, want := range []string{
		"run", "--rm",
		"--network=none",
		"--read-only",
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges",
		"HOME=/tmp/home",
		"XDG_CONFIG_HOME=/tmp/xdg-config",
		"XDG_CACHE_HOME=/tmp/xdg-cache",
		"XDG_STATE_HOME=/tmp/xdg-state",
		"/tmp:rw,size=64m",
		"/work:rw,size=64m",
		"--workdir", "/work",
		filepath.Dir(artifact) + ":/artifact:ro,z",
		defaultExecImage,
		`exec /artifact/tool "$@"`,
		"--version",
	} {
		if !contains(args, want) {
			t.Fatalf("podman was not given %q; got %v", want, args)
		}
	}
	// Only the artifact's own directory is bound, and nothing else is: a
	// project mount would let the binary read the repository it is being
	// audited against.
	for _, arg := range args {
		if strings.Contains(arg, ":/artifact") && !strings.HasPrefix(arg, filepath.Dir(artifact)+":") {
			t.Fatalf("an unexpected bind mount reached podman: %q", arg)
		}
	}
}

// A binary exiting nonzero has told us something worth surfacing but not
// something that decides a release — plenty of tools exit nonzero with no
// arguments — so runtime observations are WARN.
func TestExecNonzeroExitWarns(t *testing.T) {
	artifact, _ := execFixture(t)
	t.Setenv("MOCK_PODMAN_RC", "3")

	result := sandboxExec(execSpec(artifact, nil, 5))
	if result.Verdict != WARN {
		t.Fatalf("verdict %s, want WARN", result.Verdict)
	}
	reason := result.Reasons[0]
	if reason.Code != "runtime_failure" || reason.Data["exit_code"] != "3" {
		t.Fatalf("unexpected reason %+v", reason)
	}
	if !strings.Contains(reason.Data["stdout_summary"], "podman stdout summary") ||
		!strings.Contains(reason.Data["stderr_summary"], "podman stderr summary") {
		t.Fatalf("reason data %v carries no output summaries", reason.Data)
	}
}

// The deadline decides a timeout, never the exit code: a container killed by a
// signal reports -1, and a container that exits 137 on its own is a runtime
// failure this review did not cause.
func TestExecTimeoutWarns(t *testing.T) {
	artifact, _ := execFixture(t)
	t.Setenv("MOCK_PODMAN_SLEEP", "2")

	result := sandboxExec(execSpec(artifact, nil, 1))
	if result.Verdict != WARN {
		t.Fatalf("verdict %s, want WARN", result.Verdict)
	}
	reason := result.Reasons[0]
	if reason.Code != "timeout" || reason.Data["timeout_seconds"] != "1" {
		t.Fatalf("unexpected reason %+v", reason)
	}
}

// The exec artifact is a free path, so the failure is stated in terms of that
// path rather than an asset name the spec never gave it.
func TestExecMissingArtifactBlocks(t *testing.T) {
	artifact, _ := execFixture(t)
	absent := filepath.Join(filepath.Dir(artifact), "absent")

	result := sandboxExec(execSpec(absent, nil, 5))
	if result.Verdict != BLOCK {
		t.Fatalf("verdict %s, want BLOCK", result.Verdict)
	}
	reason := result.Reasons[0]
	if reason.Code != "artifact_missing" || reason.Data["artifact_path"] != absent {
		t.Fatalf("unexpected reason %+v", reason)
	}
}

// A missing podman is the review's own tooling absent, with an install as the
// recovery — never a WARN about how the binary behaved, because it never ran.
func TestExecMissingPodmanIsError(t *testing.T) {
	withFakeTools(t)
	artifact := writeFile(t, t.TempDir(), "tool", "#!/bin/sh\n")

	result := sandboxExec(execSpec(artifact, nil, 5))
	if result.Verdict != ERROR {
		t.Fatalf("verdict %s, want ERROR", result.Verdict)
	}
	if got := codes(result); len(got) != 1 || got[0] != "tool_missing" {
		t.Fatalf("reasons %v, want [tool_missing]", got)
	}
	if !strings.Contains(result.Reasons[0].Message, "install podman") {
		t.Fatalf("message %q carries no recovery", result.Reasons[0].Message)
	}
}

// Collect-all: a missing artifact and a missing podman are independent facts,
// and BLOCK wins the worst-of over the ERROR.
func TestExecMissingArtifactAndPodmanAreBothReported(t *testing.T) {
	withFakeTools(t)

	result := sandboxExec(execSpec(filepath.Join(t.TempDir(), "absent"), nil, 5))
	if result.Verdict != BLOCK {
		t.Fatalf("verdict %s with reasons %v, want BLOCK", result.Verdict, codes(result))
	}
	got := codes(result)
	if len(got) != 2 || got[0] != "artifact_missing" || got[1] != "tool_missing" {
		t.Fatalf("reasons %v, want both observations", got)
	}
}

func TestExecImageIsOverridableByEnvironment(t *testing.T) {
	artifact, argLog := execFixture(t)
	t.Setenv("SAFE_AUDIT_BINARY_IMAGE", "registry.example/custom:1")

	sandboxExec(execSpec(artifact, nil, 5))
	logged, err := os.ReadFile(argLog)
	if err != nil {
		t.Fatalf("read the arg log: %v", err)
	}
	if !strings.Contains(string(logged), "registry.example/custom:1") {
		t.Fatalf("podman was not given the overridden image: %s", logged)
	}
}

// Zero means "unset" in the spec, so an omitted timeout resolves to the
// environment override or the built-in default rather than to an instant
// deadline that would fail every run.
func TestEffectiveExecTimeout(t *testing.T) {
	t.Setenv("SAFE_AUDIT_BINARY_TIMEOUT_SECONDS", "")
	if got := effectiveExecTimeout(0); got != defaultExecTimeoutSeconds {
		t.Fatalf("timeout %d, want the default %d", got, defaultExecTimeoutSeconds)
	}
	if got := effectiveExecTimeout(7); got != 7 {
		t.Fatalf("timeout %d, want the spec's 7", got)
	}

	t.Setenv("SAFE_AUDIT_BINARY_TIMEOUT_SECONDS", "45")
	if got := effectiveExecTimeout(0); got != 45 {
		t.Fatalf("timeout %d, want the environment's 45", got)
	}
	if got := effectiveExecTimeout(7); got != 7 {
		t.Fatalf("timeout %d, want the spec to win over the environment", got)
	}

	t.Setenv("SAFE_AUDIT_BINARY_TIMEOUT_SECONDS", "not-a-number")
	if got := effectiveExecTimeout(0); got != defaultExecTimeoutSeconds {
		t.Fatalf("timeout %d, want an unusable override ignored", got)
	}
}

func TestStdioSummaryIsBounded(t *testing.T) {
	long := strings.Repeat("line\n", 200)
	summary := stdioSummary(long)
	if lines := strings.Count(summary, "\n") + 1; lines > execSummaryMaxLines {
		t.Fatalf("summary carries %d lines, want at most %d", lines, execSummaryMaxLines)
	}

	wide := strings.Repeat("x", 9000)
	if got := stdioSummary(wide); len([]rune(got)) != execSummaryMaxChars {
		t.Fatalf("summary is %d runes, want %d", len([]rune(got)), execSummaryMaxChars)
	}
	if got := stdioSummary(""); got != "" {
		t.Fatalf("summary %q, want empty", got)
	}
}

func contains(haystack []string, needle string) bool {
	for _, entry := range haystack {
		if entry == needle {
			return true
		}
	}
	return false
}
