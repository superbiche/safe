package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/superbiche/safe/internal/projectlane"
	"github.com/superbiche/safe/internal/strictjson"
)

// The project-lane subcommands are the judging core as pure commands over
// files: they read lockfiles and an evidence document, touch nothing else, and
// print one JSON document. A person can run them on two lockfiles and an
// evidence file to read what a change would introduce; the gate calls the same
// commands. Exit 0 means a document was written, whatever it says (the
// outcome is IN the document); exit 2 is usage; exit 3 is an input that cannot
// be read, never an empty result.

const (
	projectGraphUsage  = "safe-core: usage: safe-core project-graph [--registry-host <host>]... [--public-evidence-host <host>]... <lockfile>"
	projectDiffUsage   = "safe-core: usage: safe-core project-diff [--registry-host <host>]... [--public-evidence-host <host>]... (--baseline <lockfile> | --no-baseline) <target-lockfile>"
	projectDecideUsage = "safe-core: usage: safe-core project-decide [--registry-host <host>]... [--public-evidence-host <host>]... (--baseline <lockfile> | --no-baseline) --evidence <file> <target-lockfile>"
)

// projectLaneSchema versions the documents the graph and diff commands print.
const projectLaneSchema = 1

type projectArgs struct {
	registryHosts []string
	publicHosts   []string
	baseline      string
	noBaseline    bool
	evidence      string
	target        string
}

// hosts are the two host sets the core takes: where artifacts may be bound
// (--registry-host) and whose artifacts public evidence may speak for
// (--public-evidence-host), each in addition to npm's public registry.
func (p projectArgs) hosts() projectlane.Hosts {
	return projectlane.Hosts{Registry: p.registryHosts, PublicEvidence: p.publicHosts}
}

func parseProjectArgs(args []string, allowBaseline, needEvidence bool) (projectArgs, bool) {
	var parsed projectArgs
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--registry-host", "--public-evidence-host", "--baseline", "--evidence":
			if i+1 >= len(args) || args[i+1] == "" {
				return projectArgs{}, false
			}
			value := args[i+1]
			i++
			switch args[i-1] {
			case "--registry-host":
				parsed.registryHosts = append(parsed.registryHosts, value)
			case "--public-evidence-host":
				parsed.publicHosts = append(parsed.publicHosts, value)
			case "--baseline":
				if !allowBaseline || parsed.baseline != "" {
					return projectArgs{}, false
				}
				parsed.baseline = value
			case "--evidence":
				if !needEvidence || parsed.evidence != "" {
					return projectArgs{}, false
				}
				parsed.evidence = value
			}
		case "--no-baseline":
			if !allowBaseline {
				return projectArgs{}, false
			}
			parsed.noBaseline = true
		default:
			if len(args[i]) > 1 && args[i][0] == '-' || parsed.target != "" {
				return projectArgs{}, false
			}
			parsed.target = args[i]
		}
	}
	if parsed.target == "" {
		return projectArgs{}, false
	}
	if allowBaseline && (parsed.noBaseline == (parsed.baseline != "")) {
		return projectArgs{}, false
	}
	if needEvidence && parsed.evidence == "" {
		return projectArgs{}, false
	}
	return parsed, true
}

func printJSON(stdout io.Writer, name string, stderr io.Writer, document any) int {
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(document); err != nil {
		fmt.Fprintf(stderr, "safe-core: %s: write JSON: %v\n", name, err)
		return 3
	}
	return 0
}

// projectGraph prints the artifact graph of a lockfile and whether safe can
// bind every artifact in it.
func projectGraph(args []string, stdout, stderr io.Writer) int {
	parsed, ok := parseProjectArgs(args, false, false)
	if !ok {
		fmt.Fprintln(stderr, projectGraphUsage)
		return 2
	}
	graph, err := projectlane.LoadGraph(parsed.target, parsed.hosts())
	if err != nil {
		fmt.Fprintf(stderr, "safe-core: project-graph: %v\n", err)
		return 3
	}
	return printJSON(stdout, "project-graph", stderr, struct {
		SchemaVersion int                     `json:"schema_version"`
		Graph         projectlane.Graph       `json:"graph"`
		Bindability   projectlane.Bindability `json:"bindability"`
	}{projectLaneSchema, graph, projectlane.CheckBindable(graph, parsed.registryHosts)})
}

// loadBaseline reads the baseline a command names. An explicit --no-baseline
// is the empty graph; a baseline that was named and cannot be read is returned
// as an error text for the decision to carry as missing evidence, never as an
// empty graph.
func loadBaseline(parsed projectArgs) (graph projectlane.Graph, unreadable string) {
	if parsed.noBaseline {
		return projectlane.Graph{}, ""
	}
	graph, err := projectlane.LoadGraph(parsed.baseline, parsed.hosts())
	if err != nil {
		return projectlane.Graph{}, err.Error()
	}
	return graph, ""
}

// projectDiff prints what the target lockfile introduces over the baseline,
// with the exact public identities an advisory reading must cover.
func projectDiff(args []string, stdout, stderr io.Writer) int {
	parsed, ok := parseProjectArgs(args, true, false)
	if !ok {
		fmt.Fprintln(stderr, projectDiffUsage)
		return 2
	}
	target, err := projectlane.LoadGraph(parsed.target, parsed.hosts())
	if err != nil {
		fmt.Fprintf(stderr, "safe-core: project-diff: %v\n", err)
		return 3
	}
	baseline, unreadable := loadBaseline(parsed)
	if unreadable != "" {
		fmt.Fprintf(stderr, "safe-core: project-diff: baseline: %s\n", unreadable)
		return 3
	}
	union := map[projectlane.Identity]struct{}{}
	for _, identity := range append(baseline.Identities(), target.Identities()...) {
		union[identity] = struct{}{}
	}
	request := make([]projectlane.Identity, 0, len(union))
	for identity := range union {
		request = append(request, identity)
	}
	sort.Slice(request, func(i, j int) bool {
		if request[i].Name != request[j].Name {
			return request[i].Name < request[j].Name
		}
		return request[i].Version < request[j].Version
	})
	return printJSON(stdout, "project-diff", stderr, struct {
		SchemaVersion   int                     `json:"schema_version"`
		Difference      projectlane.Difference  `json:"difference"`
		Bindability     projectlane.Bindability `json:"bindability"`
		EvidenceRequest []projectlane.Identity  `json:"evidence_request"`
	}{projectLaneSchema, projectlane.Diff(baseline, target), projectlane.CheckBindable(target, parsed.registryHosts), request})
}

// projectDecide prints the decision report over two lockfiles and an evidence
// document.
//
// Evidence that cannot be read is exit 3, never a report: a decision over
// evidence nobody could read would vouch for a check that did not happen. A
// baseline that cannot be read is different: it is evidence about the project,
// and the report carries it as missing evidence.
func projectDecide(args []string, stdout, stderr io.Writer) int {
	parsed, ok := parseProjectArgs(args, true, true)
	if !ok {
		fmt.Fprintln(stderr, projectDecideUsage)
		return 2
	}
	raw, err := os.ReadFile(parsed.evidence)
	if err != nil {
		fmt.Fprintf(stderr, "safe-core: project-decide: read evidence: %v\n", err)
		return 3
	}
	evidence, err := projectlane.ReadEvidence(raw)
	if err != nil {
		fmt.Fprintf(stderr, "safe-core: project-decide: %v\n", err)
		return 3
	}
	target, err := projectlane.LoadGraph(parsed.target, parsed.hosts())
	if err != nil {
		fmt.Fprintf(stderr, "safe-core: project-decide: %v\n", err)
		return 3
	}
	baseline, unreadable := loadBaseline(parsed)
	return printJSON(stdout, "project-decide", stderr, projectlane.Decide(projectlane.Input{
		Baseline: baseline, BaselineError: unreadable, HasBaseline: !parsed.noBaseline,
		Target: target, Evidence: evidence, RegistryHosts: parsed.registryHosts,
	}))
}

// repeatedMembers reads one JSON document on stdin and prints, as a JSON
// array, the path of every object member named a second time in its object
// (see strictjson.RepeatedMemberPaths). Exit 0: none found, prints []. Exit 1:
// some found, prints their paths. Exit 3: the input is not one valid JSON
// document, or could not be read to its end. Exit 2: usage. The advisory
// readers of safe audit call it before they trust an OSV answer and treat any
// other status as an unusable checker, never as a clean answer.
func repeatedMembers(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "safe-core: usage: safe-core repeated-members < document.json")
		return 2
	}
	raw, err := io.ReadAll(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "safe-core: repeated-members: read: %v\n", err)
		return 3
	}
	paths, err := strictjson.RepeatedMemberPaths(raw)
	if err != nil {
		fmt.Fprintf(stderr, "safe-core: repeated-members: %v\n", err)
		return 3
	}
	if code := printJSON(stdout, "repeated-members", stderr, paths); code != 0 {
		return code
	}
	if len(paths) > 0 {
		return 1
	}
	return 0
}
