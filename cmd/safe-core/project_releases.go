package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/superbiche/safe/internal/projectlane"
	"github.com/superbiche/safe/internal/releases"
)

const (
	projectReleasesUsage = "safe-core: usage: safe-core project-releases --request <file> --cache-dir <dir> [--registry-base <url>] [--osv-url <url>]"
	projectRootsUsage    = "safe-core: usage: safe-core project-roots < NUL-separated-package-arguments"
	osvDefaultURL        = "https://api.osv.dev"
)

// projectReleases reads the publish time of every identity of a request (the
// cooldown's reading, see projectlane.CooldownCandidates) and prints the
// releases document project-decide judges. Publish times are cached per exact
// version in --cache-dir. For a version the caller named exactly that is inside
// the cooldown, it also reads the advisories the version fixes, for the
// security-fix exemption.
//
// --registry-base and --osv-url replace the registries' addresses (tests, a
// mirror of the public registry); without them a packument is read from the host
// the identity was resolved from. An identity that cannot be read is in the
// document as unreadable, with the gap, never as old; exit 3 is a request that
// cannot be read.
func projectReleases(args []string, stdout, stderr io.Writer) int {
	var requestFile, cacheDir, registryBase, osvURL string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--request", "--cache-dir", "--registry-base", "--osv-url":
			if i+1 >= len(args) || args[i+1] == "" {
				fmt.Fprintln(stderr, projectReleasesUsage)
				return 2
			}
			value := args[i+1]
			i++
			switch args[i-1] {
			case "--request":
				requestFile = value
			case "--cache-dir":
				cacheDir = value
			case "--registry-base":
				registryBase = value
			case "--osv-url":
				osvURL = value
			}
		default:
			fmt.Fprintln(stderr, projectReleasesUsage)
			return 2
		}
	}
	if requestFile == "" || cacheDir == "" {
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
	if osvURL == "" {
		osvURL = osvDefaultURL
	}
	document := projectlane.Releases{
		SchemaVersion: projectlane.ReleasesSchema,
		Now:           time.Now().UTC().Format(time.RFC3339),
		Policy:        request.Policy,
		Identities:    []projectlane.ReleaseReading{},
	}
	if request.Policy.CooldownDays > 0 {
		now := time.Now().UTC()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		reader := &releases.Reader{CacheDir: cacheDir, Parallel: 8}
		if registryBase != "" {
			reader.BaseFor = func(string) string { return registryBase }
		}
		queries := make([]releases.Query, 0, len(request.Identities))
		for _, item := range request.Identities {
			queries = append(queries, releases.Query{Name: item.Name, Version: item.Version, Host: item.Host})
		}
		results := reader.Read(ctx, queries)
		roots := map[projectlane.Identity]struct{}{}
		for _, root := range request.Roots {
			roots[projectlane.Identity{Name: root.Name, Version: root.Version}] = struct{}{}
		}
		// the named roots inside the cooldown: their fixes are read, by name
		youngRoots := map[string][]string{}
		for _, result := range results {
			if _, isRoot := roots[projectlane.Identity{Name: result.Name, Version: result.Version}]; !isRoot || !result.OK {
				continue
			}
			age := int(now.Sub(result.Published) / (24 * time.Hour))
			if age < request.Policy.CooldownDays {
				youngRoots[result.Name] = append(youngRoots[result.Name], result.Version)
			}
		}
		fixes := map[projectlane.Identity][]string{}
		fixGap := map[projectlane.Identity]string{}
		names := make([]string, 0, len(youngRoots))
		for name := range youngRoots {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			versions := youngRoots[name]
			found, err := releases.Remediation(ctx, http.DefaultClient, osvURL, name, versions)
			for _, version := range versions {
				identity := projectlane.Identity{Name: name, Version: version}
				if err != nil {
					fixGap[identity] = err.Error()
					continue
				}
				fixes[identity] = found[version]
			}
		}
		for _, result := range results {
			identity := projectlane.Identity{Name: result.Name, Version: result.Version}
			_, isRoot := roots[identity]
			reading := projectlane.ReleaseReading{
				Name: result.Name, Version: result.Version, Host: result.Host, Root: isRoot,
				Status: projectlane.ReadingUnreadable, Gap: strings.TrimSpace(result.Gap), Remediates: []string{},
			}
			if result.OK {
				reading.Status, reading.Gap, reading.Published = projectlane.ReadingRead, "", result.Published.UTC().Format(time.RFC3339)
				if ids := fixes[identity]; ids != nil {
					reading.Remediates = ids
				}
				reading.RemediationGap = fixGap[identity]
			} else if reading.Gap == "" {
				reading.Gap = "the publish time could not be read"
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
