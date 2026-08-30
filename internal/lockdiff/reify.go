package lockdiff

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// Candidate is one lockfile artifact a real install would materialize into a
// project tree that does not already carry it. Reason says which state the
// tree is in, so a refusal can name what it saw.
type Candidate struct {
	Path      string `json:"path"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Source    string `json:"source"`
	Integrity string `json:"integrity,omitempty"`
	Reason    string `json:"reason"`
}

// Candidates is the versioned reify-candidate set emitted by
// safe-core reify-candidates.
type Candidates struct {
	Schema     int         `json:"schema"`
	Candidates []Candidate `json:"candidates"`
}

// Candidate reasons.
const (
	ReasonMissing         = "missing"
	ReasonVersionMismatch = "version-mismatch"
	ReasonSymlinked       = "symlinked"
)

// Platform is the target npm resolves os/cpu constraints against. An empty
// field means this machine. Values are npm's own spelling (win32, x64) and
// are used verbatim: they come from npm argv, not from Go's runtime, so
// translating them would corrupt a target the operator stated exactly.
type Platform struct {
	OS  string
	CPU string
}

func (p Platform) effective() Platform {
	if p.OS == "" {
		p.OS = currentOS
	}
	if p.CPU == "" {
		p.CPU = currentCPU
	}
	return p
}

// ReifyCandidates reports the entries a delegated npm run may fetch into
// projectDir. The lock delta cannot see them: a partial tree (a deleted
// node_modules subdirectory, an interrupted install) reifies lockfile entries
// that both lockfiles already agreed on, so an empty delta is not evidence
// that nothing is fetched.
//
// platform is the target npm was told to resolve os/cpu against; a zero value
// means this machine.
//
// The hidden node_modules/.package-lock.json is deliberately never consulted:
// it is stale in exactly the partial states this exists to catch. The tree
// itself is the only honest witness.
func ReifyCandidates(entries []Entry, projectDir string, platform Platform) Candidates {
	result := Candidates{Schema: 1, Candidates: []Candidate{}}
	target := platform.effective()
	probe := newTreeProbe(projectDir)

	for _, entry := range entries {
		// The root project and workspace sources never carry a path key under
		// node_modules, so the loader has already dropped them. Link entries
		// point at operator-authored local content rather than a fetched
		// artifact, and materializing one creates a symlink, not a download.
		if entry.Path == "" || entry.Link {
			continue
		}
		// npm skips an optional dependency whose platform constraints exclude
		// this machine (checkPlatform), so it is deterministically never
		// fetched — fsevents on Linux. Auditing it would refuse installs over
		// a package that was never going to arrive. A NON-optional mismatch is
		// not exempt: npm fails that install outright, and over-auditing a
		// command that cannot succeed costs nothing. devOptional is likewise
		// not exempt — it is reachable as a plain dev dependency.
		if entry.Optional && !platformInstalls(entry.OS, entry.CPU, target) {
			continue
		}

		reason, ok := probe.reason(entry)
		if !ok {
			continue
		}
		result.Candidates = append(result.Candidates, Candidate{
			Path:      entry.Path,
			Name:      entry.Package.Name,
			Version:   entry.Package.Version,
			Source:    entry.Package.Source,
			Integrity: entry.Package.Integrity,
			Reason:    reason,
		})
	}

	sort.Slice(result.Candidates, func(i, j int) bool {
		a, b := result.Candidates[i], result.Candidates[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Version < b.Version
	})
	return result
}

// treeProbe reads one project tree, remembering which path components it has
// already found to be symlinks.
//
// The memo is a single snapshot per run, and that is the point: an lstat cache
// can go stale only if the tree mutates mid-scan, and a scan racing a
// concurrent install has no consistent answer to give whether it re-stats or
// not — one snapshot, one verdict, rather than a verdict assembled from
// several. Its size is bounded by the number of distinct path prefixes in the
// lockfile, and a component that cannot be lstat'd at all is remembered as
// "not a symlink" so the manifest read below decides it (absent or unreadable
// both land on missing, the fail-closed side).
type treeProbe struct {
	root     string
	symlinks map[string]bool
}

func newTreeProbe(projectDir string) *treeProbe {
	return &treeProbe{root: filepath.Clean(projectDir), symlinks: map[string]bool{}}
}

// reason decides whether the tree already carries this entry. Any state it
// cannot read as the locked version — absent directory, unreadable or
// malformed package.json, no version in it — reads as missing: an artifact
// that cannot be shown to be present must be assumed fetchable.
func (p *treeProbe) reason(entry Entry) (string, bool) {
	dir := filepath.Join(p.root, filepath.FromSlash(entry.Path))
	// A lockfile path key is untrusted input. One that escapes the project is
	// never read: it cannot be evidence about this tree, so it counts as
	// missing rather than as a reason to stat an unrelated directory.
	rel, err := filepath.Rel(p.root, dir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return ReasonMissing, true
	}
	// A symlink anywhere on the path is a linked actual node, which npm
	// REPLACES with the projected ordinary package during reify — so a
	// symlink carrying the locked version is a materialization, not evidence
	// of presence (r1 review F1). The manifest is never read through one: what
	// it says describes the link target, not what npm will put there.
	if p.symlinkedPath(entry.Path) {
		return ReasonSymlinked, true
	}

	data, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return ReasonMissing, true
	}
	var manifest struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil || manifest.Version == "" {
		return ReasonMissing, true
	}
	if manifest.Version != entry.Package.Version {
		return ReasonVersionMismatch, true
	}
	return "", false
}

// symlinkedPath reports whether any component of an entry's install path, or
// the entry directory itself, is a symlink. The walk starts at the first
// component, so a symlinked node_modules root — a tmpfs or shared-store
// layout — makes every entry a candidate: over-auditing a whole tree, which
// is the direction this gate errs in. Only ModeSymlink counts; a Windows
// junction is not reliably distinguishable here, and safe targets POSIX.
func (p *treeProbe) symlinkedPath(path string) bool {
	prefix := ""
	for _, component := range strings.Split(path, "/") {
		if component == "" {
			continue
		}
		if prefix == "" {
			prefix = component
		} else {
			prefix += "/" + component
		}

		symlinked, known := p.symlinks[prefix]
		if !known {
			info, err := os.Lstat(filepath.Join(p.root, filepath.FromSlash(prefix)))
			symlinked = err == nil && info.Mode()&os.ModeSymlink != 0
			p.symlinks[prefix] = symlinked
		}
		if symlinked {
			return true
		}
	}
	return false
}

// platformInstalls reports whether npm would install an entry carrying these
// os/cpu constraints against the target platform it was told to resolve for.
func platformInstalls(osList, cpuList []string, target Platform) bool {
	return matchesPlatform(osList, target.OS) && matchesPlatform(cpuList, target.CPU)
}

// matchesPlatform mirrors npm-install-checks' checkList: no constraints match
// everything, a negated entry naming this platform excludes it outright, a
// list carrying any positive entry needs one of them to name this platform,
// and a list of negations none of which match still matches.
func matchesPlatform(list []string, value string) bool {
	if len(list) == 0 {
		return true
	}
	if len(list) == 1 && list[0] == "any" {
		return true
	}

	negated := 0
	match := false
	for _, entry := range list {
		if strings.HasPrefix(entry, "!") {
			negated++
			if value == strings.TrimPrefix(entry, "!") {
				return false
			}
			continue
		}
		if value == entry {
			match = true
		}
	}
	return match || negated == len(list)
}

var (
	currentOS  = npmOS(runtime.GOOS)
	currentCPU = npmCPU(runtime.GOARCH)
)

// npmOS and npmCPU translate Go's platform names into the ones npm reads out
// of process.platform/process.arch and matches os/cpu against. The direction
// of a translation error matters: a name Node spells differently than Go
// would fail a POSITIVE os/cpu constraint here that npm's own check passes,
// and platformInstalls would then EXEMPT an optional entry npm actually
// fetches — an audit silently skipped, not an over-audit. The switches
// therefore cover every platform Node names differently from Go (win32,
// sunos, x64, ia32, ppc64); the fallback is identity, used only where the
// two namespaces genuinely coincide (linux, darwin, arm64, arm, s390x,
// riscv64, loong64, the BSDs).
func npmOS(goos string) string {
	switch goos {
	case "windows":
		return "win32"
	case "solaris":
		return "sunos"
	default:
		return goos
	}
}

func npmCPU(goarch string) string {
	switch goarch {
	case "amd64":
		return "x64"
	case "386":
		return "ia32"
	case "ppc64le":
		// Node reports both powerpc endiannesses as "ppc64".
		return "ppc64"
	default:
		return goarch
	}
}
