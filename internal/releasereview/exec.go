package releasereview

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	defaultExecTimeoutSeconds = 20
	defaultExecImage          = "docker.io/library/alpine:3.22"
	execSummaryMaxLines       = 40
	execSummaryMaxChars       = 4000
	// execCaptureCap bounds how much of each output stream is held in memory.
	// The summary needs at most 40 lines / 4000 chars, so 64 KiB is ample
	// headroom while keeping a binary that spews unbounded output from growing
	// safe-core's RSS until the OOM killer takes it mid-review.
	execCaptureCap = 64 << 10
	// Mirrors the bash lane's `timeout --kill-after=5s`: a process that ignores
	// SIGTERM still gets killed rather than holding the review open.
	execKillDelay = 5 * time.Second
)

// boundedBuffer retains only the first execCaptureCap bytes written to it and
// discards the rest. Write always reports full consumption (len(p), nil) so
// os/exec's output-drain goroutine keeps reading and the sandboxed process
// never blocks on a full pipe — the point is to cap the reviewer's memory, not
// to backpressure the audited binary.
type boundedBuffer struct {
	buf       bytes.Buffer
	truncated bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if remaining := execCaptureCap - b.buf.Len(); remaining > 0 {
		if len(p) <= remaining {
			b.buf.Write(p)
		} else {
			b.buf.Write(p[:remaining])
			b.truncated = true
		}
	} else if len(p) > 0 {
		b.truncated = true
	}
	return len(p), nil
}

func (b *boundedBuffer) String() string { return b.buf.String() }

// sandboxExec runs the release's executable under a networkless container and
// reports how it behaved.
//
// Named sandboxExec rather than exec so the package can still import os/exec.
//
// What this check can and cannot say bounds its severity. It observes one run
// of one binary with no network and no project mount: a binary that exits
// nonzero, or hangs, has told us something worth surfacing, but not something
// that decides a release — plenty of tools exit nonzero without arguments.
// Runtime observations are therefore WARN. A missing podman is ERROR: that is
// the review's own tooling absent, with an install as the recovery, and it must
// never read as a finding about the binary.
func sandboxExec(spec Spec) CheckResult {
	result := CheckResult{Reasons: []Reason{}}
	config := spec.Checks.Exec

	timeout := effectiveExecTimeout(config.TimeoutSeconds)
	image := defaultExecImage
	if configured := os.Getenv("SAFE_AUDIT_BINARY_IMAGE"); configured != "" {
		image = configured
	}

	// The artifact here is a free path — typically an executable extracted from
	// a distributed archive — so it is not one of the spec's artifacts[] and
	// carries no asset name. Absent or not a regular file, there is nothing to
	// run and the release cannot be smoked: that is a fact about the release,
	// not about this machine.
	runnable := true
	if probe, _ := probeRegularFile(config.Artifact); probe != fileOK {
		result.add(BLOCK, "artifact_missing",
			fmt.Sprintf("no runnable file at %s", config.Artifact),
			map[string]string{"artifact_path": config.Artifact})
		runnable = false
	}
	if _, err := exec.LookPath("podman"); err != nil {
		result.add(ERROR, "tool_missing",
			"podman is required to run the release binary under a sandbox — install podman", nil)
		runnable = false
	}
	if !runnable {
		return result
	}

	absolute, err := filepath.Abs(config.Artifact)
	if err != nil {
		result.add(ERROR, "artifact_unreadable",
			"could not resolve the artifact path against the working directory",
			map[string]string{"artifact_path": config.Artifact, "error": err.Error()})
		return result
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	command := exec.CommandContext(ctx, "podman", sandboxArgs(absolute, image, config.Args)...)
	// SIGTERM then a kill delay, rather than the immediate SIGKILL
	// CommandContext defaults to: a sandboxed binary gets the same chance to
	// exit cleanly the bash lane gave it.
	command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
	command.WaitDelay = execKillDelay

	var stdout, stderr boundedBuffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	runErr := command.Run()

	// The deadline decides a timeout, not the exit code: a container killed by a
	// signal reports -1, and a container that exits 137 on its own is a runtime
	// failure this review did not cause.
	if ctx.Err() == context.DeadlineExceeded {
		result.add(WARN, "timeout",
			fmt.Sprintf("the binary did not exit within %ds inside the sandbox", timeout),
			map[string]string{"timeout_seconds": strconv.Itoa(timeout)})
		return result
	}
	if runErr == nil {
		return result
	}

	// ProcessState is nil when the process never started at all — podman
	// vanishing between the LookPath above and here, or a fork failure. There is
	// no exit code to report then, and -1 is what Go already uses for "no code".
	exitCode := -1
	if command.ProcessState != nil {
		exitCode = command.ProcessState.ExitCode()
	}

	data := map[string]string{"exit_code": strconv.Itoa(exitCode)}
	if summary := stdioSummary(stdout.String()); summary != "" {
		data["stdout_summary"] = summary
	}
	if summary := stdioSummary(stderr.String()); summary != "" {
		data["stderr_summary"] = summary
	}
	result.add(WARN, "runtime_failure",
		fmt.Sprintf("the binary exited %d inside the sandbox", exitCode), data)
	return result
}

// effectiveExecTimeout resolves the spec's timeout, the environment override,
// and the built-in default in that order. Zero means "unset" in the spec, so a
// caller that omits the field gets the default rather than an instant deadline.
func effectiveExecTimeout(configured int) int {
	if configured > 0 {
		return configured
	}
	if raw := os.Getenv("SAFE_AUDIT_BINARY_TIMEOUT_SECONDS"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			return parsed
		}
	}
	return defaultExecTimeoutSeconds
}

// sandboxArgs builds the podman invocation. The flags are held identical to the
// bash lane's: no network, a read-only bind of only the artifact's directory,
// every capability dropped, no privilege escalation, tmpfs scratch, and HOME
// and the XDG paths pointed at that scratch so a binary that insists on writing
// config still runs.
func sandboxArgs(artifact, image string, args []string) []string {
	command := []string{
		"run", "--rm",
		"--network=none",
		"--read-only",
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges",
		"--env", "HOME=/tmp/home",
		"--env", "XDG_CONFIG_HOME=/tmp/xdg-config",
		"--env", "XDG_CACHE_HOME=/tmp/xdg-cache",
		"--env", "XDG_STATE_HOME=/tmp/xdg-state",
		"--tmpfs", "/tmp:rw,size=64m",
		"--tmpfs", "/work:rw,size=64m",
		"--workdir", "/work",
		"-v", filepath.Dir(artifact) + ":/artifact:ro,z",
		image,
		"sh", "-c", `exec /artifact/` + filepath.Base(artifact) + ` "$@"`, "sh",
	}
	return append(command, args...)
}

// stdioSummary bounds captured output the way the bash lane does: at most 40
// lines and 4000 characters. A report carries a summary, never a binary's
// unbounded output.
func stdioSummary(output string) string {
	if output == "" {
		return ""
	}
	lines := strings.Split(strings.ReplaceAll(output, "\x00", " "), "\n")
	if len(lines) > execSummaryMaxLines {
		lines = lines[:execSummaryMaxLines]
	}
	summary := strings.TrimRight(strings.Join(lines, "\n"), "\n")
	if runes := []rune(summary); len(runes) > execSummaryMaxChars {
		summary = string(runes[:execSummaryMaxChars])
	}
	return summary
}
