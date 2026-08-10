// Package lockdiff computes the registry-package delta between npm lockfiles.
package lockdiff

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"unicode"
)

// Package identifies one registry package occurrence in an npm lockfile.
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Change records a package name whose sole old and new occurrences differ.
type Change struct {
	Name string `json:"name"`
	From string `json:"from"`
	To   string `json:"to"`
}

// Diff is the versioned lockfile delta emitted by safe-core lockdiff.
type Diff struct {
	Schema  int       `json:"schema"`
	Added   []Package `json:"added"`
	Removed []Package `json:"removed"`
	Changed []Change  `json:"changed"`
}

// Load reads registry package occurrences from an npm lockfileVersion 2 or 3
// .packages map.
func Load(path string) ([]Package, error) {
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

	packages := make([]Package, 0, len(entries))
	for key, raw := range entries {
		name, include := packageName(key)
		if !include {
			continue
		}

		var entry struct {
			Link    *bool  `json:"link"`
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		if err := json.Unmarshal(raw, &entry); err != nil {
			return nil, fmt.Errorf("parse %q: .packages[%q] must be an object", path, key)
		}
		if entry.Link != nil && *entry.Link {
			continue
		}
		if entry.Version == "" {
			return nil, fmt.Errorf("parse %q: .packages[%q] is missing a string version", path, key)
		}
		// npm records the REAL registry identity in .name when the install
		// path is an alias ("foo": "npm:real-pkg@1"). The audit must vouch
		// for that identity, never the alias path — a clean verdict for the
		// alias name would vouch for an artifact nobody checked.
		if entry.Name != "" {
			name = entry.Name
		}
		if err := validateValue("package name", name); err != nil {
			return nil, fmt.Errorf("parse %q: .packages[%q] %w", path, key, err)
		}
		if err := validateValue("package version", entry.Version); err != nil {
			return nil, fmt.Errorf("parse %q: .packages[%q] %w", path, key, err)
		}
		packages = append(packages, Package{Name: name, Version: entry.Version})
	}

	sort.Slice(packages, func(i, j int) bool {
		return packageLess(packages[i], packages[j])
	})
	return packages, nil
}

func packageName(key string) (string, bool) {
	if key == "" || !strings.Contains(key, "node_modules/") {
		return "", false
	}
	name := key[strings.LastIndex(key, "node_modules/")+len("node_modules/"):]
	return name, name != ""
}

func validateValue(label, value string) error {
	if value == "" || strings.IndexFunc(value, func(r rune) bool {
		return unicode.IsControl(r) || unicode.IsSpace(r)
	}) >= 0 {
		return fmt.Errorf("has an invalid %s", label)
	}
	if strings.HasPrefix(value, "@") {
		if strings.Count(value, "/") != 1 {
			return fmt.Errorf("has an invalid %s", label)
		}
	} else if strings.Contains(value, "/") {
		return fmt.Errorf("has an invalid %s", label)
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
		if len(oldResidual) == 1 && len(newResidual) == 1 && oldResidual[0].Version != newResidual[0].Version {
			diff.Changed = append(diff.Changed, Change{Name: name, From: oldResidual[0].Version, To: newResidual[0].Version})
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
	return a.Version < b.Version
}
