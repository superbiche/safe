package releasereview

import (
	"context"
	"os/exec"
	"syscall"
	"time"
)

// cosignSubprocessTimeout bounds every cosign invocation the composite makes.
// A hung cosign — a wedged fetch to a signing-log backend, a process that never
// returns — must not hold the whole review open; the exec check established this
// same context-deadline mechanism, and the signature and tuf checks borrow it
// here. It is a var, not a const, so a test can lower it to drive a real timeout
// instead of waiting out the production value.
var cosignSubprocessTimeout = 2 * time.Minute

// cosignKillDelay mirrors the exec check's kill delay: a cosign that ignores the
// SIGTERM the deadline sends still gets killed rather than wedging the Wait that
// bounds the review.
const cosignKillDelay = 5 * time.Second

// cosignRun runs cosign under a deadline and reports a timeout distinctly from a
// nonzero exit.
//
// The distinction is load-bearing. A cosign that never answers is
// audit-infrastructure breakage — ERROR, with an install-or-retry recovery — and
// must never read as evidence about the release, which is what a BLOCK would say.
// A cosign that answers and rejects is the finding; a cosign that never answers
// is the review failing to run.
//
// env may be nil to inherit the process environment, or a replacement set (tuf's
// scratch HOME). The SIGTERM-then-kill-delay stop is the same graceful shape the
// exec sandbox gives its container, rather than CommandContext's default
// immediate SIGKILL.
func cosignRun(env []string, args ...string) (output string, timedOut bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), cosignSubprocessTimeout)
	defer cancel()

	command := exec.CommandContext(ctx, "cosign", args...)
	if env != nil {
		command.Env = env
	}
	command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
	command.WaitDelay = cosignKillDelay

	out, runErr := command.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return string(out), true, ctx.Err()
	}
	return string(out), false, runErr
}
