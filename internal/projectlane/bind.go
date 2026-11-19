package projectlane

import (
	"encoding/base64"
	"path"
	"regexp"
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
	ReasonIdentityInvalid    = "identity_invalid"
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

	byPath := indexByPath(graph)

	memo := map[string]string{}
	var reason func(Occurrence, int) string
	reason = func(occurrence Occurrence, depth int) string {
		if cached, ok := memo[occurrence.Path]; ok {
			return cached
		}
		result := ""
		switch {
		case occurrence.covered():
			// A bundled entry with no location of its own rides inside the
			// tarball of the artifact that covers it, and its parent's hash
			// covers it only when that covering artifact is a registry
			// artifact safe has itself bound. A flag, a link or a chain of
			// flags proves nothing: npm fetches a child it does not find in
			// the bundle from the registry, by name and version.
			result = ReasonParentUnbound
			if !validPackageName(occurrence.Name) {
				result = ReasonIdentityInvalid
			} else if occurrence.Shrinkwrap {
				result = ReasonOwnShrinkwrap
			} else if root, ok := coveringRoot(graph.Occurrences, byPath, occurrence.Path); ok && depth <= 64 {
				cover := graph.Occurrences[root]
				if cover.Kind == KindRegistry && reason(cover, depth+1) == "" {
					result = ""
				}
			}
		default:
			// Everything else, a bundled entry that names a location of its own
			// included, is bound on its own evidence.
			result = bindReason(occurrence, expected)
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

func indexByPath(graph Graph) map[string]int {
	byPath := make(map[string]int, len(graph.Occurrences))
	for i, occurrence := range graph.Occurrences {
		byPath[occurrence.Path] = i
	}
	return byPath
}

func bindReason(occurrence Occurrence, expected map[string]struct{}) string {
	switch occurrence.Kind {
	case KindLink, KindLocal:
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
	if occurrence.descriptor == "" {
		return ReasonOriginMissing
	}
	if !validPackageName(occurrence.Name) || !validVersion(occurrence.Version) {
		return ReasonIdentityInvalid
	}
	if !canonicalTarball(occurrence.descriptor, occurrence.Name, occurrence.Version, expected) {
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

var (
	npmName    = regexp.MustCompile(`^(@[A-Za-z0-9~][A-Za-z0-9._~-]*/)?[A-Za-z0-9~][A-Za-z0-9._~-]*$`)
	semverText = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)` +
		`(-(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?` +
		`(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)
)

// validPackageName and validVersion admit only what can stand in a registry
// URL path as written: an npm name (scoped or not) and an exact semantic
// version. Anything with a character that would need escaping is refused
// before an expected path is ever built from it.
func validPackageName(name string) bool { return len(name) <= 214 && npmName.MatchString(name) }
func validVersion(version string) bool  { return semverText.MatchString(version) }

// ExactVersion reports whether the WHOLE string is an exact semantic version.
func ExactVersion(version string) bool { return validVersion(version) }

// canonicalTarball reports whether resolved, AS WRITTEN in the lockfile, is
// exactly the registry tarball location of name@version on an expected host:
//
//	https://<host>/<name>/-/<unscoped name>-<version>.tgz
//
// String equality on the original descriptor, not on a parsed or decoded copy:
// no percent-encoding (npm requests the escaped path it finds, so a decoded
// match proves nothing about the request), no credentials, query, fragment,
// port, path prefix or host-only descriptor. Credentials are redacted for the
// report in a separate step, which binding never sees.
//
// Documented limit: a descriptor spelled any other way is not bound, even when
// it names the right package on the right host. Refused spellings include no
// scheme ("registry.npmjs.org/..."), another scheme ("http://"), an explicit
// port (":443"), an upper-case host, percent-encoding and credentials. Such an
// entry is not installed by the lane: the gate routes it (the operator's
// deliberate route) instead of normalising it into a match.
func canonicalTarball(resolved, name, version string, expected map[string]struct{}) bool {
	const scheme = "https://"
	if !strings.HasPrefix(resolved, scheme) {
		return false
	}
	host, path, found := strings.Cut(resolved[len(scheme):], "/")
	if !found {
		return false
	}
	if _, ok := expected[host]; !ok {
		return false
	}
	unscoped := name
	if i := strings.LastIndex(name, "/"); i >= 0 {
		unscoped = name[i+1:]
	}
	return path == name+"/-/"+unscoped+"-"+version+".tgz"
}
