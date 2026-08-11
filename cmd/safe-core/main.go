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
	registryHosts, oldLockfile, newLockfile, ok := lockdiffArgs(args)
	if !ok {
		fmt.Fprintln(stderr, "safe-core: usage: safe-core lockdiff [--registry-host <host>]... <old-lockfile> <new-lockfile>")
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
