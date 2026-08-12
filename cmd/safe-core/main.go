// safe-core contains small, stdlib-only pieces of safe's strangler migration.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/superbiche/safe/internal/lockdiff"
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

	registryHosts, oldLockfile, newLockfile, ok := lockdiffArgs(args)
	if !ok {
		fmt.Fprintln(stderr, "safe-core: usage: safe-core lockdiff [--registry-host <host>]... <old-lockfile> <new-lockfile>")
		fmt.Fprintln(stderr, "safe-core: usage: safe-core package-verdict < evidence.json")
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
