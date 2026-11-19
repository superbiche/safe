package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/superbiche/safe/internal/projectlane"
)

// project-tree is the strict tree verifier of the project lane, usable on its
// own: exits 0 when the tree is the judged one, 32 when it is not (the
// document lists the problems), 30 for a lockfile it refuses (link entries,
// flags its own edges contradict), 3 for input that cannot be read and 2 for
// usage.
const projectTreeUsage = "safe-core: usage: safe-core project-tree [--omit dev|optional|peer]... --os <os> --cpu <cpu> [--libc <libc>] <lockfile> <dir-holding-node_modules>"

type projectlaneSelection struct {
	omit         []string
	os, cpu, lib string
}

func (s projectlaneSelection) selection() projectlane.Selection {
	return projectlane.Selection{Omit: s.omit, OS: s.os, CPU: s.cpu, Libc: s.lib}
}

// parseSelectionFlag consumes one selection flag at args[i], reporting the
// index of its last argument.
func parseSelectionFlag(sel *projectlaneSelection, args []string, i int) (int, bool, bool) {
	switch args[i] {
	case "--omit", "--os", "--cpu", "--libc":
		if i+1 >= len(args) || args[i+1] == "" {
			return i, true, false
		}
		value := args[i+1]
		switch args[i] {
		case "--omit":
			sel.omit = append(sel.omit, value)
		case "--os":
			if sel.os != "" {
				return i, true, false
			}
			sel.os = value
		case "--cpu":
			if sel.cpu != "" {
				return i, true, false
			}
			sel.cpu = value
		case "--libc":
			if sel.lib != "" {
				return i, true, false
			}
			sel.lib = value
		}
		return i + 1, true, true
	}
	return i, false, true
}

func projectTree(args []string, stdout, stderr io.Writer) int {
	var sel projectlaneSelection
	var positional []string
	for i := 0; i < len(args); i++ {
		next, handled, ok := parseSelectionFlag(&sel, args, i)
		if handled {
			if !ok {
				fmt.Fprintln(stderr, projectTreeUsage)
				return 2
			}
			i = next
			continue
		}
		if len(args[i]) > 1 && args[i][0] == '-' {
			fmt.Fprintln(stderr, projectTreeUsage)
			return 2
		}
		positional = append(positional, args[i])
	}
	if len(positional) != 2 || sel.os == "" || sel.cpu == "" {
		fmt.Fprintln(stderr, projectTreeUsage)
		return 2
	}
	raw, err := os.ReadFile(positional[0])
	if err != nil {
		fmt.Fprintf(stderr, "safe-core: project-tree: %v\n", err)
		return 3
	}
	report, err := projectlane.VerifyTree(raw, positional[1], sel.selection())
	if err != nil {
		fmt.Fprintf(stderr, "safe-core: project-tree: %v\n", err)
		if errors.Is(err, projectlane.ErrLinkEntries) {
			return projectlane.ExitRefused
		}
		return 3
	}
	if code := printJSON(stdout, "project-tree", stderr, report); code != 0 {
		return code
	}
	if !report.Ok {
		return projectlane.ExitVerificationFailed
	}
	return 0
}
