// safe-core contains small, stdlib-only pieces of safe's strangler migration.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/superbiche/safe/internal/lockdiff"
)

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && args[0] == "--version" {
		fmt.Fprintln(stdout, version)
		return 0
	}
	if len(args) != 3 || args[0] != "lockdiff" {
		fmt.Fprintln(stderr, "safe-core: usage: safe-core lockdiff <old-lockfile> <new-lockfile>")
		return 2
	}

	oldPackages, err := lockdiff.Load(args[1])
	if err != nil {
		fmt.Fprintf(stderr, "safe-core: lockdiff: %v\n", err)
		return 3
	}
	newPackages, err := lockdiff.Load(args[2])
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
