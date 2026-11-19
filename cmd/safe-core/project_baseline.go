//go:build linux

package main

import (
	"fmt"
	"io"
	"os"

	"github.com/superbiche/safe/internal/projectlane"
)

// project-baseline keeps the lockfiles safe judged clear in a project, each under its
// own digest (see internal/projectlane/baseline.go for the layout and what protects it):
//
//	safe-core project-baseline record --state-dir <dir> --project <canonical dir> --name <lockfile> --file <file>
//	safe-core project-baseline read   --state-dir <dir> --project <canonical dir> --name <lockfile> --digest <sha256 hex> [--out <file>]
//
// record exits 0 (stored, or already stored and refreshed), 3 (it cannot be stored: the
// state directory cannot be trusted or written, the input cannot be read), 2 usage.
// read exits 0 (a trusted record is stored under that digest; with --out its bytes are in
// <file>, without it nothing is written: only the match is asked), 4 (none: nothing recorded,
// or what is there is not trusted), 3 (a trusted record's bytes could not be handed over), 2 usage.
// A lockfile is a baseline only when the lockfile on disk is byte-identical to a record: there
// is no "latest". A record that is not trusted (its bytes do not hash to
// its name, not a private regular file, ...) is IGNORED, never an error: it is named on
// stderr ("ignored record ...") and the exit status is the same as if it were not there.
const projectBaselineUsage = "safe-core: usage: safe-core project-baseline (record --file <file> | read --digest <sha256> [--out <file>]) --state-dir <dir> --project <canonical dir> --name <lockfile>"

func projectBaseline(args []string, stdout, stderr io.Writer) int {
	usage := func() int {
		fmt.Fprintln(stderr, projectBaselineUsage)
		return 2
	}
	if len(args) == 0 || (args[0] != "record" && args[0] != "read") {
		return usage()
	}
	mode := args[0]
	values := map[string]string{}
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--state-dir", "--project", "--name", "--digest", "--out", "--file":
			if i+1 >= len(args) || args[i+1] == "" {
				return usage()
			}
			if _, dup := values[args[i]]; dup {
				return usage()
			}
			values[args[i]] = args[i+1]
			i++
		default:
			return usage()
		}
	}
	for _, key := range []string{"--state-dir", "--project", "--name"} {
		if values[key] == "" {
			return usage()
		}
	}
	state, project, name := values["--state-dir"], values["--project"], values["--name"]
	if mode == "record" {
		if values["--file"] == "" || values["--out"] != "" || values["--digest"] != "" {
			return usage()
		}
		info, err := os.Lstat(values["--file"])
		if err != nil || !info.Mode().IsRegular() {
			fmt.Fprintln(stderr, "safe-core: project-baseline: the lockfile to record is not a regular file")
			return 3
		}
		content, err := os.ReadFile(values["--file"])
		if err != nil {
			fmt.Fprintf(stderr, "safe-core: project-baseline: %v\n", err)
			return 3
		}
		if err := projectlane.RecordBaseline(state, project, name, content, projectlane.BaselineKeep); err != nil {
			fmt.Fprintf(stderr, "safe-core: project-baseline: %v\n", err)
			return 3
		}
		return 0
	}
	if values["--digest"] == "" || values["--file"] != "" {
		return usage()
	}
	content, found, ignored, err := projectlane.ReadRecorded(state, project, name, values["--digest"])
	for _, item := range ignored {
		fmt.Fprintf(stderr, "safe-core: project-baseline: ignored record %s: %s\n", item.Digest, item.Why)
	}
	if err != nil {
		fmt.Fprintf(stderr, "safe-core: project-baseline: %v\n", err)
		return 2
	}
	if !found {
		return 4
	}
	if values["--out"] == "" {
		return 0
	}
	if err := os.WriteFile(values["--out"], content, 0o600); err != nil {
		fmt.Fprintf(stderr, "safe-core: project-baseline: %v\n", err)
		return 3
	}
	return 0
}
