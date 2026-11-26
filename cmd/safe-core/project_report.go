package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/superbiche/safe/internal/projectlane"
)

// project-report writes the report document of a lane command (ticket 1639) and checks one. `write` prints ONE closed word on stdout:
// written, written-prune-failed, too-large or failed (the gate calls it only once a decision exists: a decision piece that cannot be read
// is a failure to write, never silence). Exit 0 for the first two, 3 otherwise (too-large included: nothing was written), 2 for usage. `check` is for the tests: it exits 0 for a document in
// its schema and canonical form, 3 otherwise.
const projectReportUsage = "safe-core: usage: safe-core project-report write --data <dir> --project <abs path> --scratch <dir> --verb <verb> --status <n> --version <v> --published <none|tree|lockfile> [--dry-run] [--lock-only] | safe-core project-report check <file>"

const reportPieceLimit = 16 << 20

func readPiece(path string) ([]byte, bool) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, false
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > reportPieceLimit {
		return nil, false
	}
	raw, err := io.ReadAll(io.LimitReader(file, reportPieceLimit+1))
	if err != nil || len(raw) > reportPieceLimit {
		return nil, false
	}
	return raw, true
}

func projectReport(args []string, stdout, stderr io.Writer) int {
	usage := func() int {
		fmt.Fprintln(stderr, projectReportUsage)
		return 2
	}
	if len(args) == 2 && args[0] == "check" {
		raw, ok := readPiece(args[1])
		if !ok || projectlane.CheckReportDocument(raw) != nil {
			fmt.Fprintln(stderr, "safe-core: project-report: the document is not a report of this schema")
			return 3
		}
		return 0
	}
	if len(args) == 0 || args[0] != "write" {
		return usage()
	}
	values := map[string]string{}
	flags := map[string]bool{}
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--dry-run", "--lock-only":
			if flags[args[i]] {
				return usage()
			}
			flags[args[i]] = true
		case "--data", "--project", "--scratch", "--verb", "--status", "--version", "--published":
			if i+1 >= len(args) {
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
	for _, need := range []string{"--data", "--project", "--scratch", "--verb", "--status", "--version", "--published"} {
		if _, ok := values[need]; !ok {
			return usage()
		}
	}
	status, errStatus := strconv.Atoi(values["--status"])
	if errStatus != nil || status < 0 || status > 255 {
		return usage()
	}
	switch values["--published"] {
	case "none", "tree", "lockfile":
	default:
		return usage()
	}
	published := values["--published"]
	if published == "none" {
		published = ""
	}
	fail := func(word string) int {
		fmt.Fprintln(stdout, word)
		return 3
	}
	scratch := values["--scratch"]
	piece := func(name string) []byte {
		raw, _ := readPiece(filepath.Join(scratch, name))
		return raw
	}
	in := projectlane.ReportInputs{Now: time.Now().UTC(), SafeVersion: values["--version"], Verb: values["--verb"], DryRun: flags["--dry-run"],
		PackageLockOnly: flags["--lock-only"], Status: status, Published: published, Report: piece("report.json"), Bind: piece("bind.json"),
		Prompts: piece("prompt-log.tsv"), Scripts: piece("scripts.json"), Scan: piece("scan.json"), Graph: piece("target-graph.json"), Judged: piece("judged.json")}
	if in.Report == nil {
		return fail("failed")
	}
	// a piece present but unreadable is not an absent one: the binder's file that cannot be read is said by the document
	if _, err := os.Lstat(filepath.Join(scratch, "bind.json")); err == nil && in.Bind == nil {
		in.Bind = []byte("{")
	}
	doc, err := projectlane.BuildReportDocument(in)
	if err != nil {
		return fail("failed")
	}
	content, err := projectlane.MarshalReportDocument(doc)
	if err != nil {
		return fail("failed")
	}
	result, err := projectlane.ReportStore{Data: values["--data"]}.Write(values["--project"], content, time.Now().UTC())
	switch {
	case err != nil:
		return fail("failed")
	case result == projectlane.ReportTooLarge:
		return fail("too-large")
	case result == projectlane.ReportPruneFailed:
		fmt.Fprintln(stdout, "written-prune-failed")
	default:
		fmt.Fprintln(stdout, "written")
	}
	return 0
}
