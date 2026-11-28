package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/superbiche/safe/internal/projectlane"
)

const (
	projectAdvisoryGetUsage = "safe-core: usage: safe-core project-advisory-get --state-dir <dir> < request.json"
	projectAdvisoryPutUsage = "safe-core: usage: safe-core project-advisory-put --state-dir <dir> < readings.json"
	// a reading of a thousand identities names a few hundred advisories; the bound only keeps a stream that is not one from filling memory
	advisoryInputLimit = 64 << 20
)

// projectAdvisoryGet prints the trusted readings among the keys asked: the advisory reader's one question to the store
// (spec 1625, ticket 1671). It writes nothing. The state directory is an argument, never read from the environment; the
// reader that has none has no cache. A store that cannot be opened or trusted answers no hit, which is a miss.
func projectAdvisoryGet(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	stateDir, ok := advisoryStateDir(args)
	if !ok {
		fmt.Fprintln(stderr, projectAdvisoryGetUsage)
		return 2
	}
	var request struct {
		Classifier string                    `json:"classifier"`
		Keys       []projectlane.AdvisoryKey `json:"keys"`
	}
	if err := readAdvisoryDocument(stdin, &request); err != nil || request.Classifier == "" {
		fmt.Fprintf(stderr, "safe-core: project-advisory-get: unreadable request\n")
		return 3
	}
	hits := projectlane.AdvisoryCache{StateDir: stateDir}.Get(request.Classifier, request.Keys, time.Now())
	if hits == nil {
		hits = []projectlane.AdvisoryReading{}
	}
	return printJSON(stdout, "project-advisory-get", stderr, map[string]any{"schema_version": 1, "hits": hits})
}

// projectAdvisoryPut stores readings the reader fetched and classified, then prunes the store. Anything it cannot store is
// skipped silently: the record is fetched again next time. Only an unreadable request is an error.
func projectAdvisoryPut(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	stateDir, ok := advisoryStateDir(args)
	if !ok {
		fmt.Fprintln(stderr, projectAdvisoryPutUsage)
		return 2
	}
	var request struct {
		Classifier string                        `json:"classifier"`
		Readings   []projectlane.AdvisoryReading `json:"readings"`
	}
	if err := readAdvisoryDocument(stdin, &request); err != nil || request.Classifier == "" {
		fmt.Fprintf(stderr, "safe-core: project-advisory-put: unreadable request\n")
		return 3
	}
	projectlane.AdvisoryCache{StateDir: stateDir}.Put(request.Classifier, request.Readings, time.Now())
	return 0
}

func advisoryStateDir(args []string) (string, bool) {
	if len(args) != 2 || args[0] != "--state-dir" || !strings.HasPrefix(args[1], "/") {
		return "", false
	}
	return args[1], true
}

func readAdvisoryDocument(stdin io.Reader, into any) error {
	raw, err := io.ReadAll(io.LimitReader(stdin, advisoryInputLimit+1))
	if err != nil || len(raw) > advisoryInputLimit {
		return fmt.Errorf("unreadable")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(into); err != nil || decoder.More() {
		return fmt.Errorf("unreadable")
	}
	return nil
}
