package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/superbiche/safe/internal/projectlane"
)

const (
	projectAdvisoryGetUsage   = "safe-core: usage: safe-core project-advisory-get --state-dir <dir> < request.json"
	projectAdvisoryPutUsage   = "safe-core: usage: safe-core project-advisory-put --state-dir <dir> < readings.json"
	projectAdvisoryCheckUsage = "safe-core: usage: safe-core project-advisory-check --request <the request given to project-advisory-get> < reply.json"
)

// projectAdvisoryGet prints the trusted readings among the keys asked: the advisory reader's one question to the store
// (spec 1625, ticket 1671). It writes nothing. The state directory is an argument, never read from the environment; the
// reader that has none has no cache. A store that cannot be opened or trusted answers no hit, which is a miss. The request is
// read strictly (see projectlane.ParseAdvisoryGetRequest): anything else is exit 3.
func projectAdvisoryGet(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	stateDir, ok := advisoryStateDir(args)
	if !ok {
		fmt.Fprintln(stderr, projectAdvisoryGetUsage)
		return 2
	}
	raw, err := readAdvisoryInput(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "safe-core: project-advisory-get: unreadable request\n")
		return 3
	}
	classifier, keys, err := projectlane.ParseAdvisoryGetRequest(raw)
	if err != nil {
		fmt.Fprintf(stderr, "safe-core: project-advisory-get: unreadable request: %v\n", err)
		return 3
	}
	hits := projectlane.AdvisoryCache{StateDir: stateDir}.Get(classifier, keys, time.Now())
	if hits == nil {
		hits = []projectlane.AdvisoryReading{}
	}
	return printJSON(stdout, "project-advisory-get", stderr, map[string]any{"schema_version": projectlane.AdvisoryCacheSchema, "hits": hits})
}

// projectAdvisoryPut stores readings the reader fetched and classified, after making room. Anything it cannot store is
// skipped silently: the record is fetched again next time. Only an unreadable request is an error.
func projectAdvisoryPut(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	stateDir, ok := advisoryStateDir(args)
	if !ok {
		fmt.Fprintln(stderr, projectAdvisoryPutUsage)
		return 2
	}
	raw, err := readAdvisoryInput(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "safe-core: project-advisory-put: unreadable request\n")
		return 3
	}
	classifier, readings, err := projectlane.ParseAdvisoryPutRequest(raw)
	if err != nil {
		fmt.Fprintf(stderr, "safe-core: project-advisory-put: unreadable request: %v\n", err)
		return 3
	}
	projectlane.AdvisoryCache{StateDir: stateDir}.Put(classifier, readings, time.Now())
	return 0
}

// projectAdvisoryCheck is the reader's reading of a reply of project-advisory-get: the strict check of the reply against the
// request it answers (exactly one envelope, whole typed hits, one hit at most per key asked and none that was not, readings
// safe stores, none from the future or older than the bound). It prints {"<id>|<package>": band | "withdrawn"}, or exits 3
// and prints nothing.
func projectAdvisoryCheck(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) != 2 || args[0] != "--request" || args[1] == "" {
		fmt.Fprintln(stderr, projectAdvisoryCheckUsage)
		return 2
	}
	// the bound is applied while the request is read, never after it is whole in memory
	requestFile, err := os.Open(args[1])
	if err != nil {
		fmt.Fprintf(stderr, "safe-core: project-advisory-check: unreadable request\n")
		return 3
	}
	requestRaw, err := readAdvisoryInput(requestFile)
	requestFile.Close()
	if err != nil {
		fmt.Fprintf(stderr, "safe-core: project-advisory-check: unreadable request\n")
		return 3
	}
	_, keys, err := projectlane.ParseAdvisoryGetRequest(requestRaw)
	if err != nil {
		fmt.Fprintf(stderr, "safe-core: project-advisory-check: unreadable request: %v\n", err)
		return 3
	}
	reply, err := readAdvisoryInput(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "safe-core: project-advisory-check: unreadable reply\n")
		return 3
	}
	readings, err := projectlane.CheckAdvisoryReply(reply, keys, time.Now())
	if err != nil {
		fmt.Fprintf(stderr, "safe-core: project-advisory-check: the reply is refused: %v\n", err)
		return 3
	}
	return printJSON(stdout, "project-advisory-check", stderr, readings)
}

func advisoryStateDir(args []string) (string, bool) {
	if len(args) != 2 || args[0] != "--state-dir" || !strings.HasPrefix(args[1], "/") {
		return "", false
	}
	return args[1], true
}

func readAdvisoryInput(stdin io.Reader) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(stdin, projectlane.AdvisoryInputLimit+1))
	if err != nil || len(raw) > projectlane.AdvisoryInputLimit {
		return nil, fmt.Errorf("unreadable")
	}
	return raw, nil
}
