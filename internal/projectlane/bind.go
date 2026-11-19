package projectlane

import (
	"encoding/base64"
	"net/url"
	"path"
	"sort"
	"strings"
)

// Reasons an occurrence cannot be bound. They are stable identifiers: the gate
// and the report name them, and a later ticket may route on them.
const (
	ReasonKindNotAdmitted    = "kind_not_admitted"
	ReasonIntegrityMissing   = "integrity_missing"
	ReasonIntegrityMalformed = "integrity_malformed"
	ReasonOriginMissing      = "origin_missing"
	ReasonOriginNotCanonical = "origin_not_canonical"
	ReasonOwnShrinkwrap      = "own_shrinkwrap"
	ReasonParentUnbound      = "bundled_parent_unbound"
	ReasonLinkOutsideProject = "link_outside_project"
)

// DefaultRegistryHost is npm's public registry, always an expected host.
const DefaultRegistryHost = "registry.npmjs.org"

// Unbound is an occurrence safe cannot bind, with the reason.
type Unbound struct {
	Path    string `json:"path"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Origin  string `json:"origin"`
	Reason  string `json:"reason"`
}

// Bindability is the verdict over a whole graph. Bound is true only when every
// occurrence is bound: a graph holding one entry safe cannot bind is refused
// as a whole, before anything is written.
type Bindability struct {
	Bound   bool      `json:"bound"`
	Unbound []Unbound `json:"unbound"`
}

// CheckBindable decides, for every occurrence, whether the artifact it names
// is one safe can bind (what can be bound, spec 1625):
//
//   - a registry artifact carries an integrity hash and its resolved location
//     is the canonical tarball of that exact name and version on an expected
//     registry host (the lockfile-lint check against lockfile poisoning);
//   - a bundled entry is covered by its parent's hash, so it is bound exactly
//     when its parent is;
//   - a link is admitted when its target stays inside the project (that the
//     target is a directory with a manifest is the gate's check on the disk);
//   - an artifact that ships its own shrinkwrap is not bound in this slice;
//   - every other kind (git, file, remote, no resolved location) is not
//     admitted.
//
// registryHosts adds expected hosts to npm's public registry. The result is
// deterministic: unbound occurrences are sorted by path.
func CheckBindable(graph Graph, registryHosts []string) Bindability {
	expected := map[string]struct{}{DefaultRegistryHost: {}}
	for _, host := range registryHosts {
		if host = strings.ToLower(strings.TrimSpace(host)); host != "" {
			expected[host] = struct{}{}
		}
	}

	byPath := make(map[string]Occurrence, len(graph.Occurrences))
	for _, occurrence := range graph.Occurrences {
		byPath[occurrence.Path] = occurrence
	}

	memo := map[string]string{}
	var reason func(Occurrence, int) string
	reason = func(occurrence Occurrence, depth int) string {
		if cached, ok := memo[occurrence.Path]; ok {
			return cached
		}
		result := bindReason(occurrence, expected)
		if occurrence.Bundled && occurrence.Kind != KindLink {
			// A bundled entry's bytes ride inside its parent's tarball, so the
			// parent's hash covers them and its own descriptor, which npm
			// often omits, is not the evidence. It still must not claim a
			// shrinkwrap of its own.
			result = ""
			if occurrence.Shrinkwrap {
				result = ReasonOwnShrinkwrap
			} else if parent, ok := byPath[bundledParentPath(occurrence.Path)]; !ok || depth > 64 {
				result = ReasonParentUnbound
			} else if reason(parent, depth+1) != "" {
				result = ReasonParentUnbound
			}
		}
		memo[occurrence.Path] = result
		return result
	}

	out := Bindability{Bound: true, Unbound: []Unbound{}}
	for _, occurrence := range graph.Occurrences {
		if why := reason(occurrence, 0); why != "" {
			out.Bound = false
			out.Unbound = append(out.Unbound, Unbound{
				Path: occurrence.Path, Name: occurrence.Name, Version: occurrence.Version,
				Origin: occurrence.Origin, Reason: why,
			})
		}
	}
	sort.Slice(out.Unbound, func(i, j int) bool { return out.Unbound[i].Path < out.Unbound[j].Path })
	return out
}

func bindReason(occurrence Occurrence, expected map[string]struct{}) string {
	switch occurrence.Kind {
	case KindLink:
		if !linkInsideProject(occurrence.Origin) {
			return ReasonLinkOutsideProject
		}
		return ""
	case KindRegistry:
	default:
		return ReasonKindNotAdmitted
	}
	if occurrence.Shrinkwrap {
		return ReasonOwnShrinkwrap
	}
	if occurrence.Integrity == "" {
		return ReasonIntegrityMissing
	}
	if !validIntegrity(occurrence.Integrity) {
		return ReasonIntegrityMalformed
	}
	if occurrence.Origin == "" {
		return ReasonOriginMissing
	}
	if !canonicalTarball(occurrence.Origin, occurrence.Name, occurrence.Version, expected) {
		return ReasonOriginNotCanonical
	}
	return ""
}

// bundledParentPath names the entry whose tarball carries a bundled entry:
// the path up to its last nested node_modules segment.
func bundledParentPath(entryPath string) string {
	const marker = "/node_modules/"
	if i := strings.LastIndex(entryPath, marker); i >= 0 {
		return entryPath[:i]
	}
	return ""
}

// linkInsideProject accepts a relative, non-escaping link target. An absolute
// target, one that climbs out with "..", or an empty one is outside what the
// project's own tree can vouch for.
func linkInsideProject(target string) bool {
	if target == "" || strings.HasPrefix(target, "/") || strings.Contains(target, "\\") ||
		strings.Contains(target, "://") || strings.HasPrefix(target, "file:") {
		return false
	}
	cleaned := path.Clean(target)
	return cleaned != "." && cleaned != ".." && !strings.HasPrefix(cleaned, "../")
}

// validIntegrity accepts a Subresource Integrity token set: every
// whitespace-separated token is algorithm-base64 with an algorithm npm
// writes, and the digest decodes to that algorithm's length. A hash that is
// present but cannot be compared is not a hash.
func validIntegrity(integrity string) bool {
	tokens := strings.Fields(integrity)
	if len(tokens) == 0 {
		return false
	}
	sizes := map[string]int{"sha1": 20, "sha256": 32, "sha384": 48, "sha512": 64}
	for _, token := range tokens {
		algorithm, digest, ok := strings.Cut(token, "-")
		size, known := sizes[algorithm]
		if !ok || !known {
			return false
		}
		// npm writes the digest with padding; an option suffix (?opt) is part
		// of the SRI grammar but never of npm's, so it is refused.
		decoded, err := base64.StdEncoding.DecodeString(digest)
		if err != nil || len(decoded) != size {
			return false
		}
	}
	return true
}

// canonicalTarball reports whether resolved is exactly the registry tarball
// location of name@version on an expected host:
//
//	https://<host>/<name>/-/<unscoped name>-<version>.tgz
//
// No credentials, query or fragment, and no path prefix: a location that
// differs in any way is not the one the name and version stand for, which is
// how a lockfile poisoned to fetch another package under a familiar name is
// told apart. The host-only default-registry descriptor npm also writes
// ("registry.npmjs.org/...") is read as its https form.
func canonicalTarball(resolved, name, version string, expected map[string]struct{}) bool {
	if strings.HasPrefix(strings.ToLower(resolved), DefaultRegistryHost+"/") {
		resolved = "https://" + resolved
	}
	parsed, err := url.Parse(resolved)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" {
		return false
	}
	if _, ok := expected[strings.ToLower(parsed.Host)]; !ok {
		return false
	}
	unscoped := name
	if i := strings.LastIndex(name, "/"); i >= 0 {
		unscoped = name[i+1:]
	}
	return parsed.Path == "/"+name+"/-/"+unscoped+"-"+version+".tgz"
}
