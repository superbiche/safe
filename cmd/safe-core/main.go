// safe-core contains small, stdlib-only pieces of safe's strangler migration.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/superbiche/safe/internal/lockdiff"
	"github.com/superbiche/safe/internal/releasereview"
	"github.com/superbiche/safe/internal/strictjson"
	"github.com/superbiche/safe/internal/verdict"
)

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 1 && args[0] == "--version" {
		fmt.Fprintln(stdout, version)
		return 0
	}
	if len(args) > 0 && args[0] == "package-verdict" {
		return packageVerdict(args[1:], stdin, stdout, stderr)
	}
	if len(args) > 0 && args[0] == "release-review" {
		return releaseReview(args[1:], stdin, stdout, stderr)
	}
	if len(args) > 0 && args[0] == "reify-candidates" {
		return reifyCandidates(args[1:], stdout, stderr)
	}

	registryHosts, oldLockfile, newLockfile, ok := lockdiffArgs(args)
	if !ok {
		fmt.Fprintln(stderr, "safe-core: usage: safe-core lockdiff [--registry-host <host>]... <old-lockfile> <new-lockfile>")
		fmt.Fprintln(stderr, "safe-core: usage: safe-core reify-candidates [--registry-host <host>]... <lockfile> <project-dir>")
		fmt.Fprintln(stderr, "safe-core: usage: safe-core package-verdict < evidence.json")
		fmt.Fprintln(stderr, "safe-core: usage: safe-core release-review --spec <spec.json|-> | --versions")
		return 2
	}

	oldPackages, err := lockdiff.LoadWithRegistryHosts(oldLockfile, registryHosts)
	if err != nil {
		fmt.Fprintf(stderr, "safe-core: lockdiff: %v\n", err)
		return 3
	}
	newPackages, err := lockdiff.LoadWithRegistryHosts(newLockfile, registryHosts)
	if err != nil {
		fmt.Fprintf(stderr, "safe-core: lockdiff: %v\n", err)
		return 3
	}

	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(lockdiff.Compare(oldPackages, newPackages)); err != nil {
		fmt.Fprintf(stderr, "safe-core: lockdiff: write JSON: %v\n", err)
		return 3
	}
	return 0
}

// packageVerdict decides a verdict from an evidence document on stdin.
//
// Malformed evidence is exit 3, never a verdict: a decision layer that cannot
// read its input has no evidence, and emitting any verdict there — including a
// warning one — would let a serialization bug masquerade as a real check.
func packageVerdict(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "safe-core: usage: safe-core package-verdict < evidence.json")
		return 2
	}

	raw, err := io.ReadAll(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "safe-core: package-verdict: read evidence: %v\n", err)
		return 3
	}
	// A repeated member is refused before anything reads the document: json keeps
	// the last occurrence silently, so two conflicting values for one fact would
	// resolve by byte order — a verdict decided by serialization, which this
	// decision layer must not admit even though its evidence is machine-assembled.
	if err := strictjson.RejectRepeatedMembers(raw); err != nil {
		fmt.Fprintf(stderr, "safe-core: package-verdict: read evidence: %v\n", err)
		return 3
	}
	// Shape first, then decode: the decoder cannot tell an absent adverse fact
	// from a benign zero, so the raw document is checked for every key the
	// decision reads before any of it is turned into typed values.
	if err := verdict.RequireShape(raw); err != nil {
		fmt.Fprintf(stderr, "safe-core: package-verdict: incomplete evidence: %v\n", err)
		return 3
	}

	var evidence verdict.Evidence
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&evidence); err != nil {
		fmt.Fprintf(stderr, "safe-core: package-verdict: read evidence: %v\n", err)
		return 3
	}
	if err := evidence.Validate(); err != nil {
		fmt.Fprintf(stderr, "safe-core: package-verdict: unusable evidence: %v\n", err)
		return 3
	}

	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(verdict.Decide(evidence)); err != nil {
		fmt.Fprintf(stderr, "safe-core: package-verdict: write JSON: %v\n", err)
		return 3
	}
	return 0
}

// releaseReview reviews one release against a spec and prints its report.
//
// An unusable spec is exit 3, never a verdict, for the same reason
// package-verdict refuses malformed evidence: a review that cannot read what
// it was asked to check has decided nothing about the release. Verdicts leave
// through the exit code — 0/10/20 as elsewhere in safe, plus 30 for a review
// that broke, which is audit infrastructure failing and not a release finding.
func releaseReview(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	// The versions this build speaks, printed rather than inferred. safe-audit
	// advertises them in its capability payload, and a capability that promised
	// a schema the engine behind it does not accept would be worse than no
	// capability key at all — so the advertisement is checked against this.
	if len(args) == 1 && args[0] == "--versions" {
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(map[string]int{
			"spec_version":          releasereview.SpecVersion,
			"report_schema_version": releasereview.ReportSchemaVersion,
		}); err != nil {
			fmt.Fprintf(stderr, "safe-core: release-review: write JSON: %v\n", err)
			return 30
		}
		return 0
	}

	if len(args) != 2 || args[0] != "--spec" || args[1] == "" {
		fmt.Fprintln(stderr, "safe-core: usage: safe-core release-review --spec <spec.json|-> | --versions")
		return 2
	}

	source := stdin
	if args[1] != "-" {
		file, err := os.Open(args[1])
		if err != nil {
			fmt.Fprintf(stderr, "safe-core: release-review: read spec: %v\n", err)
			return 3
		}
		defer file.Close()
		source = file
	}

	spec, err := releasereview.Decode(source)
	if err != nil {
		fmt.Fprintf(stderr, "safe-core: release-review: %v\n", err)
		return 3
	}

	report := releasereview.Review(spec)
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(report); err != nil {
		// A report that cannot be written is a broken review, not a refused
		// spec: the review ran, and the failure is a full disk or a closed
		// pipe on the consumer's side.
		fmt.Fprintf(stderr, "safe-core: release-review: write JSON: %v — audit-infrastructure breakage, not a release finding\n", err)
		return 30
	}
	return report.Verdict.ExitCode()
}

// reifyCandidates prints the lockfile artifacts a real install would still
// materialize into a project tree.
//
// A project directory that cannot be read is exit 3, never an empty candidate
// set: an unreadable tree is evidence about the tooling, not about the tree,
// and reporting "nothing to fetch" there would vouch for a projection nobody
// checked. An unreadable single entry inside a readable tree is different —
// that is a candidate, decided in ReifyCandidates.
func reifyCandidates(args []string, stdout, stderr io.Writer) int {
	registryHosts, lockfile, projectDir, ok := reifyCandidatesArgs(args)
	if !ok {
		fmt.Fprintln(stderr, "safe-core: usage: safe-core reify-candidates [--registry-host <host>]... <lockfile> <project-dir>")
		return 2
	}

	info, err := os.Stat(projectDir)
	if err != nil {
		fmt.Fprintf(stderr, "safe-core: reify-candidates: read project directory: %v\n", err)
		return 3
	}
	if !info.IsDir() {
		fmt.Fprintf(stderr, "safe-core: reify-candidates: %q is not a directory\n", projectDir)
		return 3
	}

	entries, err := lockdiff.LoadEntries(lockfile, registryHosts)
	if err != nil {
		fmt.Fprintf(stderr, "safe-core: reify-candidates: %v\n", err)
		return 3
	}

	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(lockdiff.ReifyCandidates(entries, projectDir)); err != nil {
		fmt.Fprintf(stderr, "safe-core: reify-candidates: write JSON: %v\n", err)
		return 3
	}
	return 0
}

func lockdiffArgs(args []string) (registryHosts []string, oldLockfile, newLockfile string, ok bool) {
	if len(args) == 0 || args[0] != "lockdiff" {
		return nil, "", "", false
	}

	lockfiles := make([]string, 0, 2)
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--registry-host":
			if i+1 >= len(args) || args[i+1] == "" {
				return nil, "", "", false
			}
			registryHosts = append(registryHosts, args[i+1])
			i++
		default:
			if len(lockfiles) == 2 || len(args[i]) > 1 && args[i][0] == '-' {
				return nil, "", "", false
			}
			lockfiles = append(lockfiles, args[i])
		}
	}
	if len(lockfiles) != 2 {
		return nil, "", "", false
	}
	return registryHosts, lockfiles[0], lockfiles[1], true
}

// reifyCandidatesArgs parses the subcommand's argv exactly as lockdiffArgs
// parses its own: the same registry-host flag, the same refusal of an unknown
// option, and the same two-positional shape.
func reifyCandidatesArgs(args []string) (registryHosts []string, lockfile, projectDir string, ok bool) {
	positionals := make([]string, 0, 2)
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--registry-host":
			if i+1 >= len(args) || args[i+1] == "" {
				return nil, "", "", false
			}
			registryHosts = append(registryHosts, args[i+1])
			i++
		default:
			if len(positionals) == 2 || len(args[i]) > 1 && args[i][0] == '-' {
				return nil, "", "", false
			}
			positionals = append(positionals, args[i])
		}
	}
	if len(positionals) != 2 || positionals[0] == "" || positionals[1] == "" {
		return nil, "", "", false
	}
	return registryHosts, positionals[0], positionals[1], true
}
