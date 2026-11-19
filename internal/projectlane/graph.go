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
	// KindLocal is an in-project package a link entry points at (a workspace
	// member): the target of a link, kept as a record of its own so that a
	// change of its version shows in a difference.
	KindLocal   = "local"
	KindGit     = "git"
	KindFile    = "file"
	KindRemote  = "remote"
	KindUnknown = "unknown"
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
	// is the link's target path, for a local record its own path.
	Origin     string `json:"origin"`
	Integrity  string `json:"integrity"`
	Kind       string `json:"kind"`
	Optional   bool   `json:"optional"`
	Dev        bool   `json:"dev"`
	Bundled    bool   `json:"bundled"`
	Shrinkwrap bool   `json:"shrinkwrap"`
	// Host is the registry host the artifact came from; a bundled entry has
	// its covering artifact's.
	Host string `json:"host"`
	// CoveredBy and Member say which artifact's tarball carries a bundled
	// entry, and where in it: the covering artifact's key and the path of the
	// entry below the covering artifact's own. Both are empty for an artifact
	// that is fetched on its own.
	CoveredBy string `json:"covered_by,omitempty"`
	Member    string `json:"member,omitempty"`
	// Public is whether public advisory evidence speaks for this occurrence
	// (see Hosts.PublicEvidence); a bundled entry follows its covering
	// artifact. It is the only door into the advisory reading and the
	// identity request.
	Public bool `json:"public_evidence"`

	// coverName and coverVersion name the covering artifact of a covered
	// member: the identity a standing acceptance has to match.
	coverName, coverVersion string

	// descriptor is the resolved string as written in the lockfile, before any
	// redaction: binding judges what npm would fetch, not what is reported.
	descriptor string
}

// ArtifactKey identifies the bytes an occurrence stands for. A different
// origin or hash at the same version is a different artifact, and a bundled
// entry is the entry of one covering artifact: the same child identity
// carried by another parent, or by the same parent at another hash, is
// another artifact.
type ArtifactKey struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Origin    string `json:"origin"`
	Integrity string `json:"integrity"`
	CoveredBy string `json:"covered_by,omitempty"`
	Member    string `json:"member,omitempty"`
}

// Identity is the exact public identity advisories are read for.
type Identity struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Key returns the artifact an occurrence installs.
func (o Occurrence) Key() ArtifactKey {
	return ArtifactKey{Name: o.Name, Version: o.Version, Origin: o.Origin, Integrity: o.Integrity, CoveredBy: o.CoveredBy, Member: o.Member}
}

// covered reports whether the occurrence is a member of another artifact's
// tarball: bundled, and with no location of its own. An entry that names its
// own location is fetched on its own, whatever its bundle flag says, and is
// judged on that location.
func (o Occurrence) covered() bool {
	return o.Bundled && o.Kind != KindLink && o.descriptor == ""
}

// Identity returns the advisory identity of an occurrence.
func (o Occurrence) Identity() Identity {
	return Identity{Name: o.Name, Version: o.Version}
}

// Graph is the artifact graph of one lockfile: its occurrences sorted by path.
type Graph struct {
	Occurrences []Occurrence `json:"occurrences"`
}

// Hosts are the two sets of registry hosts the core is given, kept apart
// because they answer different questions. Registry is where an artifact may
// be bound to (the hosts safe expects to fetch tarballs from, adding to npm's
// public registry); PublicEvidence is whose artifacts public advisory evidence
// may speak for (adding to npm's public registry). A trusted private mirror is
// the first without being the second. Which hosts are private is the gate's
// lookup, not this package's.
type Hosts struct {
	Registry       []string
	PublicEvidence []string
}

// LoadGraph reads an npm lockfile (version 2 or 3) into its artifact graph.
func LoadGraph(lockfile string, hosts Hosts) (Graph, error) {
	records, err := lockdiff.LoadRecords(lockfile, hosts.Registry)
	if err != nil {
		return Graph{}, err
	}
	locals, err := lockdiff.LoadLocalPackages(lockfile)
	if err != nil {
		return Graph{}, err
	}
	return graphFromRecords(records, locals, hosts), nil
}

// LoadGraphAnyVersion is LoadGraph for a lockfile whose declared version is not judged: the
// package map is read whatever the version says, so that the safety checks on its entries never
// depend on a declared version.
func LoadGraphAnyVersion(lockfile string, hosts Hosts) (Graph, error) {
	records, err := lockdiff.LoadRecordsAnyVersion(lockfile, hosts.Registry)
	if err != nil {
		return Graph{}, err
	}
	locals, err := lockdiff.LoadLocalPackagesAnyVersion(lockfile)
	if err != nil {
		return Graph{}, err
	}
	return graphFromRecords(records, locals, hosts), nil
}

func graphFromRecords(records []lockdiff.Record, locals []lockdiff.LocalPackage, hosts Hosts) Graph {
	eligible := map[string]struct{}{DefaultRegistryHost: {}}
	for _, host := range hosts.PublicEvidence {
		if host = strings.ToLower(strings.TrimSpace(host)); host != "" {
			eligible[host] = struct{}{}
		}
	}

	graph := Graph{Occurrences: make([]Occurrence, 0, len(records)+len(locals))}
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
		origin := stripCredentials(record.Resolved)
		name, alias := record.Name, record.Alias
		if record.InBundle && record.Resolved == "" && record.DeclaredName != "" && record.DeclaredName != name {
			// A descriptor-less bundled entry is the package it declares to be,
			// mounted under another name: advisories and the blocklist are
			// read for the package, the mount name is the alias.
			name, alias = record.DeclaredName, name
		}
		graph.Occurrences = append(graph.Occurrences, Occurrence{
			Path:       record.Path,
			Name:       name,
			Alias:      alias,
			Version:    record.Version,
			Origin:     origin,
			Integrity:  record.Integrity,
			Kind:       record.Source,
			Optional:   record.Optional,
			Dev:        record.Dev,
			Bundled:    record.InBundle,
			Shrinkwrap: record.HasShrinkwrap,
			Host:       hostOf(origin),
			descriptor: record.Resolved,
		})
	}
	for _, local := range locals {
		graph.Occurrences = append(graph.Occurrences, Occurrence{
			Path: local.Path, Name: local.Name, Version: local.Version, Origin: local.Path, Kind: KindLocal,
		})
	}
	sort.Slice(graph.Occurrences, func(i, j int) bool {
		return graph.Occurrences[i].Path < graph.Occurrences[j].Path
	})

	byPath := make(map[string]int, len(graph.Occurrences))
	for i, occurrence := range graph.Occurrences {
		byPath[occurrence.Path] = i
	}
	for i := range graph.Occurrences {
		occurrence := &graph.Occurrences[i]
		if occurrence.covered() {
			// One covering rule for binding, identity, evidence eligibility and
			// the artifact key: a member with no location of its own is its
			// covering artifact's bytes, so it takes that artifact's host,
			// eligibility and key.
			root, ok := coveringRoot(graph.Occurrences, byPath, occurrence.Path)
			if ok {
				cover := graph.Occurrences[root]
				occurrence.CoveredBy = keyText(cover.Key())
				occurrence.coverName, occurrence.coverVersion = cover.Name, cover.Version
				occurrence.Member = strings.TrimPrefix(occurrence.Path, cover.Path+"/")
				occurrence.Host = cover.Host
				_, occurrence.Public = eligible[cover.Host]
			} else {
				// A bundled entry whose covering artifact is not in the lockfile
				// is unbound anyway; it stays in the evidence request.
				occurrence.Public = true
			}
			continue
		}
		switch {
		case occurrence.Kind == KindRegistry:
			_, occurrence.Public = eligible[occurrence.Host]
		case occurrence.Bundled && occurrence.Kind != KindLink:
			// Names a location that is not a registry's: unbound, but still a
			// public identity whose reading is owed.
			occurrence.Public = true
		}
	}
	return graph
}

// coveringRoot walks up the bundled chain of a path to the first entry that is
// not itself bundled: the artifact whose tarball carries the whole chain.
func coveringRoot(occurrences []Occurrence, byPath map[string]int, path string) (int, bool) {
	for depth := 0; depth < 64; depth++ {
		parent, ok := byPath[bundledParentPath(path)]
		if !ok {
			return 0, false
		}
		if !occurrences[parent].covered() {
			return parent, true
		}
		path = occurrences[parent].Path
	}
	return 0, false
}

func keyText(key ArtifactKey) string {
	return key.Name + "@" + key.Version + "\x00" + key.Origin + "\x00" + key.Integrity
}

func hostOf(origin string) string {
	if strings.HasPrefix(strings.ToLower(origin), DefaultRegistryHost+"/") {
		return DefaultRegistryHost
	}
	if !strings.Contains(origin, "://") {
		return ""
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.Host)
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
		if occurrence.Public {
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
