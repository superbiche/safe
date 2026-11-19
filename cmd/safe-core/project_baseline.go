//go:build linux

package main

import (
	"fmt"
	"io"
	"os"

	"github.com/superbiche/safe/internal/projectlane"
)

// project-baseline reads and writes the lockfile safe stored for a project
// after its own last command judged on complete evidence (see
// internal/projectlane/baseline.go for the format and what protects it).
//
//	safe-core project-baseline read  --state-dir <dir> --project <dir> --name <lockfile> --out <file>
//	safe-core project-baseline write --state-dir <dir> --project <dir> --name <lockfile> --file <file>
//
// exits: 0 done (read: the baseline is in <file>); 4 read: none stored for this
// project; 3 a stored baseline or the state directory cannot be trusted or the
// input cannot be read; 2 usage.
const projectBaselineUsage = "safe-core: usage: safe-core project-baseline (read --out <file> | write --file <file>) --state-dir <dir> --project <dir> --name <lockfile>"

func projectBaseline(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "read" && args[0] != "write") {
		fmt.Fprintln(stderr, projectBaselineUsage)
		return 2
	}
	mode := args[0]
	values := map[string]string{}
	for i := 1; i < len(args); i += 2 {
		switch args[i] {
		case "--state-dir", "--project", "--name", "--out", "--file":
			if i+1 >= len(args) || args[i+1] == "" {
				fmt.Fprintln(stderr, projectBaselineUsage)
				return 2
			}
			if _, dup := values[args[i]]; dup {
				fmt.Fprintln(stderr, projectBaselineUsage)
				return 2
			}
			values[args[i]] = args[i+1]
		default:
			fmt.Fprintln(stderr, projectBaselineUsage)
			return 2
		}
	}
	file := "--out"
	if mode == "write" {
		file = "--file"
	}
	other := "--file"
	if mode == "write" {
		other = "--out"
	}
	if values["--state-dir"] == "" || values["--project"] == "" || values["--name"] == "" || values[file] == "" || values[other] != "" {
		fmt.Fprintln(stderr, projectBaselineUsage)
		return 2
	}
	if mode == "write" {
		info, err := os.Lstat(values["--file"])
		if err != nil || !info.Mode().IsRegular() {
			fmt.Fprintln(stderr, "safe-core: project-baseline: the baseline to store is not a regular file")
			return 3
		}
		content, err := os.ReadFile(values["--file"])
		if err != nil {
			fmt.Fprintf(stderr, "safe-core: project-baseline: %v\n", err)
			return 3
		}
		if err := projectlane.WriteBaseline(values["--state-dir"], values["--project"], values["--name"], content); err != nil {
			fmt.Fprintf(stderr, "safe-core: project-baseline: %v\n", err)
			return 3
		}
		return 0
	}
	content, status, err := projectlane.ReadBaseline(values["--state-dir"], values["--project"], values["--name"])
	if err != nil {
		fmt.Fprintf(stderr, "safe-core: project-baseline: %v\n", err)
		return 3
	}
	if status == projectlane.StoredAbsent {
		return 4
	}
	if err := os.WriteFile(values["--out"], content, 0o600); err != nil {
		fmt.Fprintf(stderr, "safe-core: project-baseline: %v\n", err)
		return 3
	}
	return 0
}
