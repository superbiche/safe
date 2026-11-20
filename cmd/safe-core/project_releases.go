package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/superbiche/safe/internal/projectlane"
	"github.com/superbiche/safe/internal/releases"
)

const (
	projectReleasesUsage = "safe-core: usage: safe-core project-releases --request <file> --state-dir <dir> [--registry-base <url>]"
	projectRootsUsage    = "safe-core: usage: safe-core project-roots < NUL-separated-package-arguments"
	// releasesDeadline bounds all the readings of one command together; a reading still queued when it ends is
	// missing evidence (never a gap). It is set from the measurement of docs/configuration.md: 1,300 identities
	// took 17 s cold, so five minutes is about seventeen times that.
	releasesDeadline = 5 * time.Minute
)

// projectReleases reads the publish time of every identity of a request (the
// cooldown's reading, see projectlane.CooldownCandidates) and prints the
// releases document project-decide judges. A publish time safe read is cached
// per exact version and per source in the lane's own store under --state-dir
// (see projectlane.PublishCache).
//
// --registry-base replaces the registry's address (tests, a mirror); without it a
// packument is read from the host the identity was resolved from. The caller's
// proxy and TLS settings are not used (see package releases). Each identity is in
// the document as read (its own publish time), bounded (one complete answer lists
// the version without a time of its own: the last-modified time stands in) or
// missing (any other reason: missing evidence). Exit 3 is a request that cannot be read.
func projectReleases(args []string, stdout, stderr io.Writer) int {
	var requestFile, stateDir, registryBase string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--request", "--state-dir", "--registry-base":
			if i+1 >= len(args) || args[i+1] == "" {
				fmt.Fprintln(stderr, projectReleasesUsage)
				return 2
			}
			value := args[i+1]
			i++
			switch args[i-1] {
			case "--request":
				requestFile = value
			case "--state-dir":
				stateDir = value
			case "--registry-base":
				registryBase = value
			}
		default:
			fmt.Fprintln(stderr, projectReleasesUsage)
			return 2
		}
	}
	if requestFile == "" || stateDir == "" {
		fmt.Fprintln(stderr, projectReleasesUsage)
		return 2
	}
	raw, err := os.ReadFile(requestFile)
	if err != nil {
		fmt.Fprintf(stderr, "safe-core: project-releases: read request: %v\n", err)
		return 3
	}
	request, err := projectlane.ReadReleaseRequest(raw)
	if err != nil {
		fmt.Fprintf(stderr, "safe-core: project-releases: %v\n", err)
		return 3
	}
	// The TLS roots are the system's: Go reads the roots a caller names with these two variables.
	os.Unsetenv("SSL_CERT_FILE")
	os.Unsetenv("SSL_CERT_DIR")
	document := projectlane.Releases{
		SchemaVersion: projectlane.ReleasesSchema,
		Now:           time.Now().UTC().Format(time.RFC3339Nano),
		Policy:        request.Policy,
		Identities:    []projectlane.ReleaseReading{},
	}
	if request.Policy.CooldownDays > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), releasesDeadline)
		defer cancel()
		reader := &releases.Reader{Parallel: 8, Cache: publishCache(stateDir)}
		if registryBase != "" {
			reader.BaseFor = func(string) string { return registryBase }
		}
		queries := make([]releases.Query, 0, len(request.Identities))
		for _, item := range request.Identities {
			queries = append(queries, releases.Query{Name: item.Name, Version: item.Version, Host: item.Host})
		}
		roots := map[projectlane.Identity]struct{}{}
		for _, root := range request.Roots {
			roots[projectlane.Identity{Name: root.Name, Version: root.Version}] = struct{}{}
		}
		for _, result := range reader.Read(ctx, queries) {
			_, isRoot := roots[projectlane.Identity{Name: result.Name, Version: result.Version}]
			reading := projectlane.ReleaseReading{Name: result.Name, Version: result.Version, Host: result.Host, Root: isRoot}
			switch {
			case result.OK && result.Bounded:
				reading.Status, reading.Published = projectlane.ReadingBounded, result.Published.UTC().Format(time.RFC3339Nano)
			case result.OK:
				reading.Status, reading.Published = projectlane.ReadingRead, result.Published.UTC().Format(time.RFC3339Nano)
			default:
				reading.Status, reading.Gap = projectlane.ReadingMissing, strings.TrimSpace(result.Failure)
				if reading.Gap == "" {
					reading.Gap = "the publish time could not be read"
				}
			}
			document.Identities = append(document.Identities, reading)
		}
		sort.Slice(document.Identities, func(i, j int) bool {
			a, b := document.Identities[i], document.Identities[j]
			if a.Name != b.Name {
				return a.Name < b.Name
			}
			return a.Version < b.Version
		})
	}
	return printJSON(stdout, "project-releases", stderr, document)
}

// projectRoots prints, as a JSON list, the versions the caller named exactly
// among NUL-separated command-line package arguments: `name@x.y.z` and nothing
// else (a range, a tag, an alias, a URL or a path names no exact version).
func projectRoots(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, projectRootsUsage)
		return 2
	}
	raw, err := io.ReadAll(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "safe-core: project-roots: read: %v\n", err)
		return 3
	}
	roots := []projectlane.NamedRoot{}
	for _, text := range strings.Split(strings.TrimSuffix(string(raw), "\x00"), "\x00") {
		if text == "" || !projectlane.ExactArg(text) {
			continue
		}
		_, name, version := projectlane.ClassifyArg(text)
		roots = append(roots, projectlane.NamedRoot{Name: name, Version: version})
	}
	return printJSON(stdout, "project-roots", stderr, roots)
}
