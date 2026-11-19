package projectlane

import "sort"

// Reasons an artifact is introduced.
const (
	IntroducedNew       = "new"
	IntroducedOrigin    = "origin_changed"
	IntroducedIntegrity = "integrity_changed"
	IntroducedBoth      = "origin_and_integrity_changed"
	// IntroducedCovering is a bundled entry whose own identity is unchanged
	// but whose covering artifact (or place in it) is not.
	IntroducedCovering = "covering_changed"
)

// Introduced is an artifact the target graph has and the baseline does not.
// A same-version artifact whose origin or hash differs from the baseline's is
// introduced too: it is different bytes under a familiar name.
type Introduced struct {
	ArtifactKey
	Reason      string   `json:"reason"`
	Occurrences []string `json:"occurrences"`
}

// Dropped is an artifact the baseline has and the target graph does not.
type Dropped struct {
	ArtifactKey
	Occurrences []string `json:"occurrences"`
}

// NameChange is a package name present on both sides whose set of installed
// artifacts differs.
type NameChange struct {
	Name   string   `json:"name"`
	Before []string `json:"before"`
	After  []string `json:"after"`
}

// Difference is what the target graph introduces over the baseline graph.
// Added and Removed are package names; Changed are names on both sides whose
// artifacts differ; Introduced and Dropped are the artifacts themselves.
type Difference struct {
	Added      []NameSet    `json:"added"`
	Removed    []NameSet    `json:"removed"`
	Changed    []NameChange `json:"changed"`
	Introduced []Introduced `json:"introduced"`
	Dropped    []Dropped    `json:"dropped"`
}

// NameSet is a package name with the versions it is installed at.
type NameSet struct {
	Name     string   `json:"name"`
	Versions []string `json:"versions"`
}

// Diff computes the difference between a baseline graph (possibly empty) and a
// target graph. Both are read as sets of artifacts: an artifact installed at
// more paths on one side is not introduced by that (the advisory report shows
// the change of exposure), but one whose origin or hash changed at the same
// version is.
func Diff(baseline, target Graph) Difference {
	before := artifactPaths(baseline)
	after := artifactPaths(target)

	diff := Difference{
		Added: []NameSet{}, Removed: []NameSet{}, Changed: []NameChange{},
		Introduced: []Introduced{}, Dropped: []Dropped{},
	}

	baselineByIdentity := map[Identity][]ArtifactKey{}
	for _, key := range sortedKeys(before) {
		identity := Identity{Name: key.Name, Version: key.Version}
		baselineByIdentity[identity] = append(baselineByIdentity[identity], key)
	}

	for key, paths := range after {
		if _, present := before[key]; present {
			continue
		}
		reason := IntroducedNew
		for _, old := range baselineByIdentity[Identity{Name: key.Name, Version: key.Version}] {
			originChanged := old.Origin != key.Origin
			integrityChanged := old.Integrity != key.Integrity
			switch {
			case !originChanged && !integrityChanged:
				reason = IntroducedCovering
			case originChanged && integrityChanged:
				reason = IntroducedBoth
			case originChanged:
				reason = IntroducedOrigin
			case integrityChanged:
				reason = IntroducedIntegrity
			}
			break
		}
		diff.Introduced = append(diff.Introduced, Introduced{ArtifactKey: key, Reason: reason, Occurrences: paths})
	}
	for key, paths := range before {
		if _, present := after[key]; !present {
			diff.Dropped = append(diff.Dropped, Dropped{ArtifactKey: key, Occurrences: paths})
		}
	}
	sort.Slice(diff.Introduced, func(i, j int) bool { return keyLess(diff.Introduced[i].ArtifactKey, diff.Introduced[j].ArtifactKey) })
	sort.Slice(diff.Dropped, func(i, j int) bool { return keyLess(diff.Dropped[i].ArtifactKey, diff.Dropped[j].ArtifactKey) })

	beforeNames := versionsByName(baseline)
	afterNames := versionsByName(target)
	for name, now := range afterNames {
		versions := now.versions
		old, present := beforeNames[name]
		switch {
		case !present:
			diff.Added = append(diff.Added, NameSet{Name: name, Versions: versions})
		case !equalStrings(old.versions, versions) || old.signature != now.signature:
			diff.Changed = append(diff.Changed, NameChange{Name: name, Before: old.versions, After: versions})
		}
	}
	for name, old := range beforeNames {
		if _, present := afterNames[name]; !present {
			diff.Removed = append(diff.Removed, NameSet{Name: name, Versions: old.versions})
		}
	}
	sort.Slice(diff.Added, func(i, j int) bool { return diff.Added[i].Name < diff.Added[j].Name })
	sort.Slice(diff.Removed, func(i, j int) bool { return diff.Removed[i].Name < diff.Removed[j].Name })
	sort.Slice(diff.Changed, func(i, j int) bool { return diff.Changed[i].Name < diff.Changed[j].Name })
	return diff
}

// nameVersions is the sorted distinct versions a name is installed at and a
// signature of its artifacts, so a same-version change of origin or hash still
// makes the name changed.
type nameVersions struct {
	versions  []string
	signature string
}

func versionsByName(graph Graph) map[string]nameVersions {
	versions := map[string]map[string]struct{}{}
	keys := map[string][]ArtifactKey{}
	for _, key := range sortedKeys(artifactPaths(graph)) {
		if versions[key.Name] == nil {
			versions[key.Name] = map[string]struct{}{}
		}
		versions[key.Name][key.Version] = struct{}{}
		keys[key.Name] = append(keys[key.Name], key)
	}
	out := make(map[string]nameVersions, len(versions))
	for name, set := range versions {
		list := make([]string, 0, len(set))
		for version := range set {
			list = append(list, version)
		}
		sort.Strings(list)
		signature := ""
		for _, key := range keys[name] {
			signature += key.Version + "\x00" + key.Origin + "\x00" + key.Integrity + "\x00" + key.CoveredBy + "\x00" + key.Member + "\x01"
		}
		out[name] = nameVersions{versions: list, signature: signature}
	}
	return out
}

func artifactPaths(graph Graph) map[ArtifactKey][]string {
	paths := map[ArtifactKey][]string{}
	for _, occurrence := range graph.Occurrences {
		paths[occurrence.Key()] = append(paths[occurrence.Key()], occurrence.Path)
	}
	for key := range paths {
		sort.Strings(paths[key])
	}
	return paths
}

func sortedKeys(paths map[ArtifactKey][]string) []ArtifactKey {
	keys := make([]ArtifactKey, 0, len(paths))
	for key := range paths {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keyLess(keys[i], keys[j]) })
	return keys
}

func keyLess(a, b ArtifactKey) bool {
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	if a.Version != b.Version {
		return a.Version < b.Version
	}
	if a.Origin != b.Origin {
		return a.Origin < b.Origin
	}
	if a.Integrity != b.Integrity {
		return a.Integrity < b.Integrity
	}
	if a.CoveredBy != b.CoveredBy {
		return a.CoveredBy < b.CoveredBy
	}
	return a.Member < b.Member
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
