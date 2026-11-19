//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/superbiche/safe/internal/projectlane"
)

// project-baseline keeps the lockfile safe judged and published last in a project
// (see internal/projectlane/baseline.go for the format, the two states and what
// protects them). The project is the directory a DESCRIPTOR holds (the one the
// gate holds locked), never a pathname:
//
//	safe-core project-baseline read    --project-fd <n> --state-dir <dir> --name <lockfile> --kind current|pending --out <file>
//	safe-core project-baseline write   --project-fd <n> --state-dir <dir> --name <lockfile> --kind current|pending --file <file>
//	safe-core project-baseline confirm --project-fd <n> --state-dir <dir> --name <lockfile>
//	safe-core project-baseline drop    --project-fd <n> --state-dir <dir> --name <lockfile>
//
// confirm makes the pending record the current one; drop removes the pending one.
//
// exits: 0 done (read: the baseline is in <file>); 4 read or confirm: none stored;
// 5 write: this directory's identity (birth time) cannot be established, nothing
// can be stored; 3 a record, the state directory or the identity cannot be trusted
// or an input cannot be read; 2 usage.
const projectBaselineUsage = "safe-core: usage: safe-core project-baseline (read --out <file> | write --file <file> | confirm | drop) --project-fd <n> --state-dir <dir> --name <lockfile> [--kind current|pending]"

func projectBaseline(args []string, stdout, stderr io.Writer) int {
	usage := func() int {
		fmt.Fprintln(stderr, projectBaselineUsage)
		return 2
	}
	if len(args) == 0 {
		return usage()
	}
	mode := args[0]
	if mode != "read" && mode != "write" && mode != "confirm" && mode != "drop" {
		return usage()
	}
	values := map[string]string{}
	for i := 1; i < len(args); i += 2 {
		switch args[i] {
		case "--project-fd", "--state-dir", "--name", "--kind", "--out", "--file":
			if i+1 >= len(args) || args[i+1] == "" {
				return usage()
			}
			if _, dup := values[args[i]]; dup {
				return usage()
			}
			values[args[i]] = args[i+1]
		default:
			return usage()
		}
	}
	allowed := map[string]map[string]bool{
		"read":    {"--project-fd": true, "--state-dir": true, "--name": true, "--kind": true, "--out": true},
		"write":   {"--project-fd": true, "--state-dir": true, "--name": true, "--kind": true, "--file": true},
		"confirm": {"--project-fd": true, "--state-dir": true, "--name": true},
		"drop":    {"--project-fd": true, "--state-dir": true, "--name": true},
	}[mode]
	for key := range values {
		if !allowed[key] {
			return usage()
		}
	}
	required := []string{"--project-fd", "--state-dir", "--name"}
	switch mode {
	case "read":
		required = append(required, "--kind", "--out")
	case "write":
		required = append(required, "--kind", "--file")
	}
	for _, key := range required {
		if values[key] == "" {
			return usage()
		}
	}
	fd, convErr := strconv.Atoi(values["--project-fd"])
	if convErr != nil || fd < 3 {
		return usage()
	}
	kind := projectlane.RecordKind(values["--kind"])
	if values["--kind"] != "" && kind != projectlane.RecordCurrent && kind != projectlane.RecordPending {
		return usage()
	}
	state, name := values["--state-dir"], values["--name"]
	fail := func(err error) int {
		fmt.Fprintf(stderr, "safe-core: project-baseline: %v\n", err)
		return 3
	}
	switch mode {
	case "write":
		info, err := os.Lstat(values["--file"])
		if err != nil || !info.Mode().IsRegular() {
			return fail(errors.New("the baseline to store is not a regular file"))
		}
		content, err := os.ReadFile(values["--file"])
		if err != nil {
			return fail(err)
		}
		if err := projectlane.WriteBaseline(state, fd, name, kind, content); err != nil {
			if errors.Is(err, projectlane.ErrNoIdentity) {
				fmt.Fprintf(stderr, "safe-core: project-baseline: %v\n", err)
				return 5
			}
			return fail(err)
		}
		return 0
	case "confirm":
		status, err := projectlane.ConfirmBaseline(state, fd, name)
		if err != nil {
			return fail(err)
		}
		if status == projectlane.StoredAbsent {
			return 4
		}
		return 0
	case "drop":
		if err := projectlane.DropPending(state, fd, name); err != nil {
			return fail(err)
		}
		return 0
	}
	content, status, err := projectlane.ReadBaseline(state, fd, name, kind)
	if err != nil {
		return fail(err)
	}
	if status == projectlane.StoredAbsent {
		return 4
	}
	if err := os.WriteFile(values["--out"], content, 0o600); err != nil {
		return fail(err)
	}
	return 0
}
