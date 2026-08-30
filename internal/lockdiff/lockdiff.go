// Package lockdiff computes the registry-package delta between npm lockfiles.
package lockdiff

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"
	"unicode"
)

// Package identifies one registry package occurrence in an npm lockfile.
type Package struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Source    string `json:"source"`
	Integrity string `json:"integrity,omitempty"`
}

// Change records a package name whose sole old and new occurrences differ.
type Change struct {
	Name      string `json:"name"`
	From      string `json:"from"`
	To        string `json:"to"`
	Source    string `json:"source"`
	Integrity string `json:"integrity,omitempty"`
}

// Diff is the versioned lockfile delta emitted by safe-core lockdiff.
type Diff struct {
	Schema  int       `json:"schema"`
	Added   []Package `json:"added"`
	Removed []Package `json:"removed"`
	Changed []Change  `json:"changed"`
}

// Entry is one .packages occurrence with the install path npm materializes it
// at, plus the fields that decide whether a real install materializes it at
// all. Load drops all of it; the reify lane needs every field to tell an
// artifact the delegated command would fetch from one it never will.
type Entry struct {
	Path     string
	Package  Package
	Link     bool
	Optional bool
	Dev      bool
	OS       []string
	CPU      []string
}

// Load reads package occurrences using npm's default registry host.
func Load(path string) ([]Package, error) {
	return LoadWithRegistryHosts(path, nil)
}

// LoadWithRegistryHosts reads package occurrences from an npm lockfileVersion
// 2 or 3 .packages map. A HTTP(S) descriptor is a registry artifact only when
// its host is npm's default registry or one of registryHosts.
func LoadWithRegistryHosts(path string, registryHosts []string) ([]Package, error) {
	entries, err := LoadEntries(path, registryHosts)
	if err != nil {
		return nil, err
	}

	packages := make([]Package, 0, len(entries))
	for _, entry := range entries {
		if entry.Link {
			continue
		}
		packages = append(packages, entry.Package)
	}
	sort.Slice(packages, func(i, j int) bool {
		return packageLess(packages[i], packages[j])
	})
	return packages, nil
}

// LoadEntries reads the same .packages map as LoadWithRegistryHosts while
// keeping each entry's install path and install-decision fields. Link entries
// are returned carrying nothing but their path: npm never fetches them, so
// they are neither validated nor classified here.
func LoadEntries(path string, registryHosts []string) ([]Entry, error) {
	allowedRegistryHosts := registryHostSet(registryHosts)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	var root map[string]json.RawMessage
	if err := decoder.Decode(&root); err != nil {
		return nil, fmt.Errorf("parse %q: invalid JSON: %w", path, err)
	}
	if root == nil {
		return nil, fmt.Errorf("parse %q: lockfile must be a JSON object", path)
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return nil, fmt.Errorf("parse %q: lockfile contains multiple JSON documents", path)
	} else if err != io.EOF {
		return nil, fmt.Errorf("parse %q: invalid trailing JSON: %w", path, err)
	}

	versionRaw, ok := root["lockfileVersion"]
	if !ok {
		return nil, fmt.Errorf("parse %q: lockfileVersion is required", path)
	}
	var lockfileVersion int64
	if err := json.Unmarshal(versionRaw, &lockfileVersion); err != nil {
		return nil, fmt.Errorf("parse %q: lockfileVersion must be a number", path)
	}
	if lockfileVersion == 1 {
		return nil, fmt.Errorf("parse %q: lockfileVersion 1 is unsupported because it has no .packages map", path)
	}
	if lockfileVersion != 2 && lockfileVersion != 3 {
		return nil, fmt.Errorf("parse %q: unsupported lockfileVersion %d (expected 2 or 3)", path, lockfileVersion)
	}

	packagesRaw, ok := root["packages"]
	if !ok {
		return nil, fmt.Errorf("parse %q: lockfileVersion %d requires a .packages map", path, lockfileVersion)
	}
	var entries map[string]json.RawMessage
	if err := json.Unmarshal(packagesRaw, &entries); err != nil || entries == nil {
		return nil, fmt.Errorf("parse %q: .packages must be a JSON object", path)
	}

	loaded := make([]Entry, 0, len(entries))
	for key, raw := range entries {
		name, include := packageName(key)
		if !include {
			continue
		}

		var entry struct {
			Link      *bool           `json:"link"`
			Optional  *bool           `json:"optional"`
			Dev       *bool           `json:"dev"`
			Name      string          `json:"name"`
			Version   string          `json:"version"`
			Resolved  json.RawMessage `json:"resolved"`
			Integrity json.RawMessage `json:"integrity"`
			OS        json.RawMessage `json:"os"`
			CPU       json.RawMessage `json:"cpu"`
		}
		if err := json.Unmarshal(raw, &entry); err != nil {
			return nil, fmt.Errorf("parse %q: .packages[%q] must be an object", path, key)
		}
		if entry.Link != nil && *entry.Link {
			loaded = append(loaded, Entry{Path: key, Link: true})
			continue
		}
		if entry.Version == "" {
			return nil, fmt.Errorf("parse %q: .packages[%q] is missing a string version", path, key)
		}
		resolved, resolvedPresent, err := optionalString(entry.Resolved)
		if err != nil {
			return nil, fmt.Errorf("parse %q: .packages[%q] resolved must be a string", path, key)
		}
		integrity, integrityPresent, err := optionalString(entry.Integrity)
		if err != nil || (integrityPresent && integrity == "") {
			return nil, fmt.Errorf("parse %q: .packages[%q] integrity must be a non-empty string", path, key)
		}
		source := sourceClass(resolved, resolvedPresent, allowedRegistryHosts)
		// npm records the REAL registry identity in .name when the install
		// path is an alias ("foo": "npm:real-pkg@1"). The audit must vouch
		// for that identity only when the descriptor is a registry artifact.
		// A non-registry descriptor can self-declare a registry name, but that
		// must not make an audit of that namesake vouch for its real source.
		if source == "registry" && entry.Name != "" {
			name = entry.Name
		}
		if err := validatePackageName(name); err != nil {
			return nil, fmt.Errorf("parse %q: .packages[%q] %w", path, key, err)
		}
		if err := validateText("package version", entry.Version); err != nil {
			return nil, fmt.Errorf("parse %q: .packages[%q] %w", path, key, err)
		}
		if integrityPresent {
			if err := validateText("package integrity", integrity); err != nil {
				return nil, fmt.Errorf("parse %q: .packages[%q] %w", path, key, err)
			}
		}
		loaded = append(loaded, Entry{
			Path:     key,
			Package:  Package{Name: name, Version: entry.Version, Source: source, Integrity: integrity},
			Optional: entry.Optional != nil && *entry.Optional,
			Dev:      entry.Dev != nil && *entry.Dev,
			OS:       stringList(entry.OS),
			CPU:      stringList(entry.CPU),
		})
	}

	sort.Slice(loaded, func(i, j int) bool {
		return loaded[i].Path < loaded[j].Path
	})
	return loaded, nil
}

// stringList reads npm's one-or-many spelling for os/cpu. An unreadable value
// reads as absent, which matches every platform: over-auditing an entry the
// real command may skip is the safe direction, and a lockfile shape this
// parser does not recognize must not silently exempt an artifact from audit.
func stringList(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		return many
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return []string{one}
	}
	return nil
}

func packageName(key string) (string, bool) {
	if key == "" || !strings.Contains(key, "node_modules/") {
		return "", false
	}
	name := key[strings.LastIndex(key, "node_modules/")+len("node_modules/"):]
	return name, name != ""
}

func optionalString(raw json.RawMessage) (string, bool, error) {
	if len(raw) == 0 {
		return "", false, nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", false, err
	}
	return value, true, nil
}

func registryHostSet(registryHosts []string) map[string]struct{} {
	hosts := map[string]struct{}{"registry.npmjs.org": {}}
	for _, host := range registryHosts {
		host = strings.ToLower(strings.TrimSpace(host))
		if host != "" {
			hosts[host] = struct{}{}
		}
	}
	return hosts
}

func sourceClass(resolved string, present bool, registryHosts map[string]struct{}) string {
	if !present {
		return "unknown"
	}
	lower := strings.ToLower(resolved)
	switch {
	case strings.HasPrefix(lower, "git+"), strings.HasPrefix(lower, "ssh://"), strings.HasPrefix(lower, "git@"):
		return "git"
	case strings.HasPrefix(lower, "file:"):
		return "file"
	case strings.HasPrefix(lower, "registry.npmjs.org/"):
		// npm's lockfile format accepts this magic host-only default-registry
		// descriptor. It has no URL scheme but remains a registry artifact.
		return "registry"
	case strings.HasPrefix(lower, "http://"), strings.HasPrefix(lower, "https://"):
		parsed, err := url.Parse(resolved)
		if err == nil {
			if _, ok := registryHosts[strings.ToLower(parsed.Host)]; ok {
				return "registry"
			}
		}
		return "remote"
	default:
		// npm also permits hosted and other URL-like descriptors. Until a
		// source-aware audit exists, every non-empty unrecognized descriptor
		// is remote and therefore refused by the gate.
		return "remote"
	}
}

func validateText(label, value string) error {
	if value == "" || strings.IndexFunc(value, func(r rune) bool {
		return unicode.IsControl(r) || unicode.IsSpace(r)
	}) >= 0 {
		return fmt.Errorf("has an invalid %s", label)
	}
	return nil
}

func validatePackageName(value string) error {
	if err := validateText("package name", value); err != nil {
		return err
	}
	if strings.HasPrefix(value, "@") {
		if strings.Count(value, "/") != 1 {
			return fmt.Errorf("has an invalid package name")
		}
	} else if strings.Contains(value, "/") {
		return fmt.Errorf("has an invalid package name")
	}
	return nil
}

// Compare returns a deterministic multiset delta. Identical occurrences are
// removed first; only one residual old and new occurrence for the same name
// is represented as a change. All other multiplicity is explicit additions or
// removals.
func Compare(oldPackages, newPackages []Package) Diff {
	oldCounts := count(oldPackages)
	newCounts := count(newPackages)

	for pair, oldCount := range oldCounts {
		if newCount := newCounts[pair]; newCount > 0 {
			common := min(oldCount, newCount)
			oldCounts[pair] -= common
			newCounts[pair] -= common
		}
	}

	oldByName := byName(oldCounts)
	newByName := byName(newCounts)
	allNames := make(map[string]struct{}, len(oldByName)+len(newByName))
	for name := range oldByName {
		allNames[name] = struct{}{}
	}
	for name := range newByName {
		allNames[name] = struct{}{}
	}

	diff := Diff{Schema: 1, Added: []Package{}, Removed: []Package{}, Changed: []Change{}}
	for name := range allNames {
		oldResidual := oldByName[name]
		newResidual := newByName[name]
		if len(oldResidual) == 1 && len(newResidual) == 1 && oldResidual[0] != newResidual[0] {
			diff.Changed = append(diff.Changed, Change{
				Name: name, From: oldResidual[0].Version, To: newResidual[0].Version,
				Source: newResidual[0].Source, Integrity: newResidual[0].Integrity,
			})
			continue
		}
		diff.Removed = append(diff.Removed, oldResidual...)
		diff.Added = append(diff.Added, newResidual...)
	}

	sort.Slice(diff.Added, func(i, j int) bool {
		return packageLess(diff.Added[i], diff.Added[j])
	})
	sort.Slice(diff.Removed, func(i, j int) bool {
		return packageLess(diff.Removed[i], diff.Removed[j])
	})
	sort.Slice(diff.Changed, func(i, j int) bool {
		if diff.Changed[i].Name != diff.Changed[j].Name {
			return diff.Changed[i].Name < diff.Changed[j].Name
		}
		if diff.Changed[i].From != diff.Changed[j].From {
			return diff.Changed[i].From < diff.Changed[j].From
		}
		return diff.Changed[i].To < diff.Changed[j].To
	})
	return diff
}

func count(packages []Package) map[Package]int {
	counts := make(map[Package]int, len(packages))
	for _, pkg := range packages {
		counts[pkg]++
	}
	return counts
}

func byName(counts map[Package]int) map[string][]Package {
	result := make(map[string][]Package)
	for pkg, occurrences := range counts {
		for range occurrences {
			result[pkg.Name] = append(result[pkg.Name], pkg)
		}
	}
	for name := range result {
		sort.Slice(result[name], func(i, j int) bool {
			return packageLess(result[name][i], result[name][j])
		})
	}
	return result
}

func packageLess(a, b Package) bool {
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	if a.Version != b.Version {
		return a.Version < b.Version
	}
	if a.Source != b.Source {
		return a.Source < b.Source
	}
	return a.Integrity < b.Integrity
}
