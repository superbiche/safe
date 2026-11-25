package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"

	"github.com/superbiche/safe/internal/projectlane"
)

// project-scripts reads, from data only, what a lane command put in the project that has install-time scripts (the lane runs none; the
// operator is told which did not run). Exits 0 with the document on stdout, 3 when an input cannot be read, 2 for usage.
const projectScriptsUsage = "safe-core: usage: safe-core project-scripts --lock <judged lockfile> [--tree <node_modules dir>] [--previous <hidden lockfile>] [--all] [--manifest <package.json> --project <dir>] [--limit <n>]"

func projectScripts(args []string, stdout, stderr io.Writer) int {
	usage := func() int {
		fmt.Fprintln(stderr, projectScriptsUsage)
		return 2
	}
	values := map[string]string{}
	req := projectlane.ScriptsRequest{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--all":
			if req.All {
				return usage()
			}
			req.All = true
		case "--lock", "--tree", "--previous", "--manifest", "--project", "--limit":
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
	if values["--lock"] == "" || (values["--manifest"] != "") != (values["--project"] != "") {
		return usage()
	}
	req.TreeRoot = values["--tree"]
	req.RootDir = values["--project"]
	if v, ok := values["--limit"]; ok {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 100000 {
			return usage()
		}
		req.Limit = n
	}
	report, err := projectlane.ReadScriptsFiles(values["--lock"], values["--previous"], values["--manifest"], req)
	if err != nil {
		fmt.Fprintf(stderr, "safe-core: project-scripts: %v\n", err)
		return 3
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		fmt.Fprintf(stderr, "safe-core: project-scripts: %v\n", err)
		return 3
	}
	fmt.Fprintln(stdout, string(encoded))
	return 0
}
