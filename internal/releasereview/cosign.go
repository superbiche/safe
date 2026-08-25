package releasereview

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// cosignOutcome is what one cosign probe amounts to. Three answers, not two: a
// probe that verified, a probe that ran and rejected, and a probe that could
// not run at all — the audit-infrastructure-breakage answer that must never be
// read as a verdict about the release.
type cosignOutcome int

const (
	cosignVerified cosignOutcome = iota
	cosignRejected
	cosignInfra
)

// probeOutcome carries one probe's classification alongside the raw output a
// caller needs for its reason message and the timeout flag that tells a
// deadline apart from an unreachable trust root.
type probeOutcome struct {
	output   string
	timedOut bool
	outcome  cosignOutcome
}

// classifyCosign turns a cosign run into one of the three outcomes. A clean
// exit verified. A deadline, or output that names a trust-bootstrap network
// failure, is infrastructure breakage. Everything else — a nonzero exit whose
// output is about the certificate or signature — is a genuine rejection.
func classifyCosign(timedOut bool, err error, output string) cosignOutcome {
	switch {
	case err == nil:
		return cosignVerified
	case timedOut || cosignInfraFailure(output):
		return cosignInfra
	default:
		return cosignRejected
	}
}

// cosignInfraFailure reports whether a failed cosign run failed because its own
// trust bootstrap could not reach the network — the Sigstore TUF repository or
// the Rekor transparency log — rather than because the evidence did not verify.
//
// Detached verification (certificate + signature, no bundle) needs a live Rekor
// lookup and a fetched trusted root; a bundle embeds its inclusion proof and
// only needs the trusted root, which cosign caches. Either way a cold cache
// with no network fails here, and that is audit-infrastructure breakage with a
// retry as its recovery — never a verdict about the release, which a BLOCK
// would wrongly say.
//
// Only cosign's FATAL error line decides this. cosign prints the network
// failure on its `Error:` / `error during command execution:` line; the
// "Could not fetch trusted_root … Continuing with individual targets" line is a
// non-fatal WARNING cosign emits even on runs that go on to verify or reject, so
// matching a bare substring anywhere in combined output would convert a genuine
// rejection that merely printed that warning into an ERROR. Scanning only fatal
// lines also defuses the echo problem: cosign echoes the caller-supplied
// certificate path and the certificate's SAN into its output, so a bare
// substring match could be steered by an evidence path or SAN containing
// `dial tcp`. Fatal lines about the evidence itself — a certificate that would
// not load, or an identity that did not match — are excluded, so what remains is
// the trust-bootstrap network chain and nothing an attacker controls. An
// unrecognized fatal line falls through to the caller's rejection (BLOCK) — the
// fail-closed direction — so a future cosign that rewords the bootstrap strings
// degrades to over-blocking, never to a silent pass. The markers were captured
// from a real offline cosign verify-blob run.
func cosignInfraFailure(output string) bool {
	for _, raw := range strings.Split(output, "\n") {
		line := strings.ToLower(strings.TrimSpace(raw))
		if !strings.HasPrefix(line, "error:") && !strings.HasPrefix(line, "error during command execution:") {
			continue
		}
		// A fatal error about the evidence — a certificate or signature that
		// would not load, or an identity that did not match — is a rejection,
		// not infrastructure, even when the evidence path or SAN it echoes
		// contains a network-shaped substring.
		if strings.Contains(line, "loading cert") ||
			strings.Contains(line, "loading signature") ||
			strings.Contains(line, "none of the expected identities matched") {
			continue
		}
		for _, marker := range []string{
			"tuf refresh failed",
			"getting rekor public keys",
			"tuf remote mirror",
			"network is unreachable",
			"dial tcp",
			"no such host",
			"i/o timeout",
		} {
			if strings.Contains(line, marker) {
				return true
			}
		}
	}
	return false
}

// cosignSubprocessTimeout bounds every cosign invocation the composite makes.
// A hung cosign — a wedged fetch to a signing-log backend, a process that never
// returns — must not hold the whole review open; the exec check established this
// same context-deadline mechanism, and the signature and tuf checks borrow it
// here. It is a var, not a const, so a test can lower it to drive a real timeout
// instead of waiting out the production value.
var cosignSubprocessTimeout = 2 * time.Minute

// cosignKillDelay mirrors the exec check's kill delay: a cosign that ignores the
// SIGTERM the deadline sends still gets killed rather than wedging the Wait that
// bounds the review. It is also the grace Wait gives a descendant that outlives
// cosign while still holding an output pipe. A var, not a const, so a test can
// lower it to drive that pipe-drain path without a real five-second wait.
var cosignKillDelay = 5 * time.Second

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
	// Two shapes are the same "cosign did not answer in bounded time" event. The
	// context deadline firing is the plain timeout. exec.ErrWaitDelay is the
	// subtler one: cosign itself exited, but a descendant it left behind kept an
	// output pipe open past the WaitDelay, so os/exec gave up waiting and closed
	// the pipes. Both are the review stalling on its own tooling, never a verdict
	// about the release — reported the same, as a timeout, so a caller never
	// classifies either as a BLOCK.
	if ctx.Err() == context.DeadlineExceeded || errors.Is(runErr, exec.ErrWaitDelay) {
		return string(out), true, runErr
	}
	return string(out), false, runErr
}
