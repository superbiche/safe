// Package projectlane is the pure judging core of the project lane: the
// artifact graph of an npm lockfile, the check that decides whether safe can
// bind each artifact, the difference between a baseline graph and a target
// graph, and the decision over strict, versioned evidence.
//
// Everything here is a function of files and documents handed in. Nothing
// resolves a version, reads the network or writes state: the gate (bash) and
// the evidence readers (safe audit) sit outside, and this package is the part
// they trust, so identities, bindability and the decision table are decided
// once, here.
//
// Three keys are kept apart on purpose, because later evidence attaches to
// each of them and a reader must never have to guess which one a field names:
//
//   - an ARTIFACT is what npm would fetch: name, version, origin and hash.
//     Two occurrences of the same artifact are the same bytes.
//   - an OCCURRENCE is one lockfile path an artifact is installed at.
//   - an ADVISORY is an OSV id; it is judged per package name, never per
//     artifact (the ruled identity is (package name, advisory id)).
package projectlane

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/superbiche/safe/internal/lockdiff"
)

// Artifact kinds. Registry is the only kind that is bound by its own origin
// and hash; link and bundled are admitted but bound by something else (the
// project, the parent's hash); the rest are never admitted in this slice.
const (
	KindRegistry = "registry"
	KindLink     = "link"
	KindGit      = "git"
	KindFile     = "file"
	KindRemote   = "remote"
	KindUnknown  = "unknown"
)

// Occurrence is one lockfile entry: an artifact at a path.
type Occurrence struct {
	Path string `json:"path"`
	// Name is the identity the advisories and the blocklist are read for: the
	// real registry name when the install path is an alias.
	Name string `json:"name"`
	// Alias is the install-path name when it differs from Name.
	Alias   string `json:"alias,omitempty"`
	Version string `json:"version"`
	// Origin is the resolved location with credentials removed. For a link it
	// is the link's target path.
	Origin     string `json:"origin"`
	Integrity  string `json:"integrity"`
	Kind       string `json:"kind"`
	Optional   bool   `json:"optional"`
	Dev        bool   `json:"dev"`
	Bundled    bool   `json:"bundled"`
	Shrinkwrap bool   `json:"shrinkwrap"`
}

// ArtifactKey identifies the bytes an occurrence stands for. A different
// origin or hash at the same version is a different artifact.
type ArtifactKey struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Origin    string `json:"origin"`
	Integrity string `json:"integrity"`
}

// Identity is the exact public identity advisories are read for.
type Identity struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Key returns the artifact an occurrence installs.
func (o Occurrence) Key() ArtifactKey {
	return ArtifactKey{Name: o.Name, Version: o.Version, Origin: o.Origin, Integrity: o.Integrity}
}

// Identity returns the advisory identity of an occurrence.
func (o Occurrence) Identity() Identity {
	return Identity{Name: o.Name, Version: o.Version}
}

// Public reports whether public advisory evidence speaks for this occurrence:
// registry artifacts, and bundled entries, which are public packages carried
// inside a registry parent. A link, git, file or remote entry is not a public
// identity, and neither is a private-origin artifact's namesake here: the
// private-origin rules are the gate's, and this package never feeds a private
// artifact to a public reading.
func (o Occurrence) Public() bool {
	if o.Kind == KindLink {
		return false
	}
	return o.Kind == KindRegistry || (o.Bundled && o.Kind == KindUnknown)
}

// Graph is the artifact graph of one lockfile: its occurrences sorted by path.
type Graph struct {
	Occurrences []Occurrence `json:"occurrences"`
}

// LoadGraph reads an npm lockfile (version 2 or 3) into its artifact graph.
// registryHosts adds hosts to npm's default registry for the descriptor
// classification, exactly as the other safe-core readers do.
func LoadGraph(lockfile string, registryHosts []string) (Graph, error) {
	records, err := lockdiff.LoadRecords(lockfile, registryHosts)
	if err != nil {
		return Graph{}, err
	}
	return graphFromRecords(records), nil
}

func graphFromRecords(records []lockdiff.Record) Graph {
	graph := Graph{Occurrences: make([]Occurrence, 0, len(records))}
	for _, record := range records {
		if record.Link {
			graph.Occurrences = append(graph.Occurrences, Occurrence{
				Path:   record.Path,
				Name:   packageNameOfPath(record.Path),
				Origin: record.LinkTarget,
				Kind:   KindLink,
			})
			continue
		}
		graph.Occurrences = append(graph.Occurrences, Occurrence{
			Path:       record.Path,
			Name:       record.Name,
			Alias:      record.Alias,
			Version:    record.Version,
			Origin:     stripCredentials(record.Resolved),
			Integrity:  record.Integrity,
			Kind:       record.Source,
			Optional:   record.Optional,
			Dev:        record.Dev,
			Bundled:    record.InBundle,
			Shrinkwrap: record.HasShrinkwrap,
		})
	}
	sort.Slice(graph.Occurrences, func(i, j int) bool {
		return graph.Occurrences[i].Path < graph.Occurrences[j].Path
	})
	return graph
}

func packageNameOfPath(path string) string {
	const marker = "node_modules/"
	if i := strings.LastIndex(path, marker); i >= 0 {
		return path[i+len(marker):]
	}
	return path
}

// stripCredentials removes the userinfo of a URL-shaped descriptor. A
// descriptor that does not parse as a URL with a host is returned as is: it
// carries no userinfo to remove, and scp-like git forms keep their user.
func stripCredentials(resolved string) string {
	if !strings.Contains(resolved, "://") {
		return resolved
	}
	parsed, err := url.Parse(resolved)
	if err != nil || parsed.User == nil {
		return resolved
	}
	parsed.User = nil
	return parsed.String()
}

// Identities returns the distinct public identities of the graph, sorted.
func (g Graph) Identities() []Identity {
	seen := map[Identity]struct{}{}
	for _, occurrence := range g.Occurrences {
		if occurrence.Public() {
			seen[occurrence.Identity()] = struct{}{}
		}
	}
	return sortedIdentities(seen)
}

func sortedIdentities(set map[Identity]struct{}) []Identity {
	identities := make([]Identity, 0, len(set))
	for identity := range set {
		identities = append(identities, identity)
	}
	sort.Slice(identities, func(i, j int) bool {
		if identities[i].Name != identities[j].Name {
			return identities[i].Name < identities[j].Name
		}
		return identities[i].Version < identities[j].Version
	})
	return identities
}

// Names returns the distinct names of the graph's occurrences, sorted.
func (g Graph) Names() []string {
	seen := map[string]struct{}{}
	for _, occurrence := range g.Occurrences {
		seen[occurrence.Name] = struct{}{}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (k ArtifactKey) String() string {
	return fmt.Sprintf("%s@%s", k.Name, k.Version)
}
