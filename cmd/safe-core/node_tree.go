package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/superbiche/safe/internal/nodetree"
)

const nodeTreeUsage = "safe-core: usage: safe-core node-tree --lockfile <file> --source <dir> --target <dir> --modules <rel-dir>... [--exclude <name>]..."

type repeated []string

func (r *repeated) String() string     { return strings.Join(*r, ",") }
func (r *repeated) Set(v string) error { *r = append(*r, v); return nil }

// nodeTree checks an installed node_modules tree against its lockfile for
// `safe install --reuse`. Problems are data (exit 0); exit 3 means the check
// could not run, which the caller must treat as missing evidence.
func nodeTree(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("node-tree", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var o nodetree.Options
	var modules, exclude repeated
	fs.StringVar(&o.Lockfile, "lockfile", "", "")
	fs.StringVar(&o.Source, "source", "", "")
	fs.StringVar(&o.Target, "target", "", "")
	fs.Var(&modules, "modules", "")
	fs.Var(&exclude, "exclude", "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || o.Lockfile == "" || o.Source == "" || o.Target == "" || len(modules) == 0 {
		fmt.Fprintln(stderr, nodeTreeUsage)
		return 2
	}
	o.Modules, o.Exclude = modules, exclude
	report, err := nodetree.Check(o)
	if err != nil {
		fmt.Fprintf(stderr, "safe-core: node-tree: %v\n", err)
		return 3
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(report); err != nil {
		fmt.Fprintf(stderr, "safe-core: node-tree: write JSON: %v\n", err)
		return 3
	}
	return 0
}
