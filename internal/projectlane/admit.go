package projectlane

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/superbiche/safe/internal/strictjson"
)

// Admission: before npm runs anything, every source the command, the manifest,
// its overrides and the committed lockfile's dependency edges name must be a
// registry package, classified the way npm classifies it (npm-package-arg's
// decision: file, alias, URL, git shorthand, then registry version, range or
// tag). The port is deliberately conservative: it never admits a spelling npm
// would not take for the registry, and refuses some spellings npm would (any
// non-ASCII text, loose semver forms). tests/live/npm_spec_oracle.sh checks it
// against the npm that is installed.

// AdmitSchema is the version of the admission document.
const AdmitSchema = 1

// Spec classes. The registry ones are Version, Range and Tag.
const (
	ClassVersion   = "version"
	ClassRange     = "range"
	ClassTag       = "tag"
	ClassFile      = "file"
	ClassAlias     = "alias"
	ClassGit       = "git"
	ClassRemote    = "remote"
	ClassInvalid   = "invalid"
	maxSafeInteger = 9007199254740991
)

var (
	reURL      = regexp.MustCompile(`(?i)^(?:git[+])?[a-z]+:`)
	reGit      = regexp.MustCompile(`(?i)^[^@]+@[^:.]+\.[^:]+:.+$`)
	reFileType = regexp.MustCompile(`(?i)[.](?:tgz|tar\.gz|tar)$`)
	reFileSpec = regexp.MustCompile(`^(?:[.]|~[/]|[/]|[a-zA-Z]:)`)

	numeric   = `(?:0|[1-9][0-9]*)`
	xIdent    = `(?:` + numeric + `|x|X|\*)`
	preIdent  = `(?:[0-9]*[a-zA-Z-][a-zA-Z0-9-]*|` + numeric + `)`
	preRel    = `(?:-(` + preIdent + `(?:\.` + preIdent + `)*))`
	buildPart = `(?:\+([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*))`
	fullPlain = `v?(` + numeric + `)\.(` + numeric + `)\.(` + numeric + `)` + preRel + `?` + buildPart + `?`
	xPlain    = `(?:v|=)*(` + xIdent + `)(?:\.(` + xIdent + `)(?:\.(` + xIdent + `)(?:` + preRel + `)?` + buildPart + `?)?)?`

	reFull       = regexp.MustCompile(`^` + fullPlain + `$`)
	reComparator = regexp.MustCompile(`^((?:<|>)?=?) ?` + xPlain + `$`)
	reTilde      = regexp.MustCompile(`^(?:~>?)` + xPlain + `$`)
	reCaret      = regexp.MustCompile(`^(?:\^)` + xPlain + `$`)
	reHyphen     = regexp.MustCompile(`^` + xPlain + ` - ` + xPlain + `$`)
	reSpaces     = regexp.MustCompile(`[ \t\n\v\f\r]+`)
	reTrimOp     = regexp.MustCompile(`((?:<|>)=?|=) +`)
	reTrimTilde  = regexp.MustCompile(`(~>?) +`)
	reTrimCaret  = regexp.MustCompile(`(\^) +`)
)

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func trimASCII(s string) string { return strings.Trim(s, " \t\n\v\f\r") }

// withinSafeInteger reports whether every digit run in the text is a number
// semver would accept (at most MAX_SAFE_INTEGER): an oversized component makes
// npm read the spelling as a tag, never as a version or a range.
func withinSafeInteger(s string) bool {
	for _, run := range regexp.MustCompile(`[0-9]+`).FindAllString(s, -1) {
		trimmed := strings.TrimLeft(run, "0")
		if len(trimmed) > 16 {
			return false
		}
		if len(trimmed) == 16 && trimmed > fmt.Sprint(maxSafeInteger) {
			return false
		}
	}
	return true
}

// StrictVersion reports whether the text is a strict semantic version
// (x.y.z[-pre][+build], no prefix, no loose form) within semver's limits.
func StrictVersion(s string) bool {
	return len(s) <= 256 && !strings.HasPrefix(s, "v") && reFull.MatchString(s) && withinSafeInteger(strictComponents(s))
}

// strictComponents is the part of a version whose digit runs are components
// (the prerelease and build identifiers are text).
func strictComponents(s string) string {
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		return s[:i]
	}
	return s
}

// strictRange reports whether the text is a semver range every comparator of
// which parses in the strict grammar (a subset of what npm's loose reader takes).
func strictRange(raw string) bool {
	if len(raw) > 256 || !isASCII(raw) {
		return false
	}
	norm := reSpaces.ReplaceAllString(trimASCII(raw), " ")
	for _, set := range strings.Split(norm, "||") {
		set = trimASCII(set)
		if set == "" {
			continue // the empty set is "any version"
		}
		if reHyphen.MatchString(set) {
			if !withinSafeInteger(set) {
				return false
			}
			continue
		}
		set = reTrimOp.ReplaceAllString(set, "$1")
		set = reTrimTilde.ReplaceAllString(set, "$1")
		set = reTrimCaret.ReplaceAllString(set, "$1")
		for _, comparator := range strings.Split(set, " ") {
			if comparator == "" {
				return false
			}
			if !(reComparator.MatchString(comparator) || reTilde.MatchString(comparator) || reCaret.MatchString(comparator)) {
				return false
			}
			if !withinSafeInteger(comparator) {
				return false
			}
		}
	}
	return true
}

// tagSafe is encodeURIComponent(spec) === spec.
func tagSafe(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("-_.!~*'()", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// ValidPackageName is validate-npm-package-name's validForOldPackages, narrowed
// to ASCII: the whole name, or both halves of a scoped one, must survive
// encodeURIComponent unchanged.
func ValidPackageName(name string) bool {
	if name == "" || len(name) > 214 || !isASCII(name) || name != trimASCII(name) {
		return false
	}
	if name[0] == '.' || name[0] == '_' {
		return false
	}
	switch strings.ToLower(name) {
	case "node_modules", "favicon.ico":
		return false
	}
	if tagSafe(name) {
		return true
	}
	if name[0] == '@' {
		scope, pkg, ok := strings.Cut(name[1:], "/")
		return ok && scope != "" && pkg != "" && !strings.Contains(pkg, "/") && tagSafe(scope) && tagSafe(pkg)
	}
	return false
}

// ClassifySpec classifies the spec part of a dependency (npa.resolve with the
// name already known): file, alias, url or git, or a registry version, range or
// tag. Text npm would reject reads as invalid.
func ClassifySpec(spec string) string {
	if !isASCII(spec) {
		return ClassInvalid
	}
	lower := strings.ToLower(spec)
	if strings.HasPrefix(lower, "file:") || reFileSpec.MatchString(spec) {
		return ClassFile
	}
	if strings.HasPrefix(lower, "npm:") {
		return ClassAlias
	}
	// Hosted-git shorthands, URLs and scp-like git all carry a colon or a slash.
	if reURL.MatchString(spec) {
		if strings.HasPrefix(lower, "http:") || strings.HasPrefix(lower, "https:") {
			return ClassRemote
		}
		return ClassGit
	}
	if strings.Contains(spec, ":") || strings.Contains(spec, "/") {
		return ClassGit
	}
	if reFileType.MatchString(spec) {
		return ClassFile
	}
	trimmed := trimASCII(spec)
	if trimmed == "" {
		return ClassRange
	}
	switch {
	case StrictVersion(trimmed):
		return ClassVersion
	case strictRange(trimmed):
		return ClassRange
	case tagSafe(trimmed):
		return ClassTag
	}
	return ClassInvalid
}

// IsRegistry reports whether a class is one the registry resolves.
func IsRegistry(class string) bool {
	return class == ClassVersion || class == ClassRange || class == ClassTag
}

// ClassifyArg classifies a command-line package argument the way npa(arg)
// reads it. It returns the class, and the name and spec it split into ("" when
// the argument names no package).
func ClassifyArg(arg string) (class, name, spec string) {
	if !isASCII(arg) {
		return ClassInvalid, "", ""
	}
	nameEnds := -1
	if len(arg) > 1 {
		if i := strings.Index(arg[1:], "@"); i >= 0 {
			nameEnds = i + 1
		}
	}
	namePart := arg
	if nameEnds > 0 {
		namePart = arg[:nameEnds]
	}
	switch {
	case reURL.MatchString(arg):
		return ClassifySpec(arg), "", arg
	case reGit.MatchString(arg):
		return ClassGit, "", arg
	case !strings.HasPrefix(namePart, "@") && (strings.Contains(namePart, "/") || reFileType.MatchString(namePart)):
		return ClassifySpec(arg), "", arg
	case nameEnds > 0:
		name, spec = namePart, arg[nameEnds+1:]
		if spec == "" {
			spec = "*"
		}
	default:
		if ValidPackageName(arg) {
			name, spec = arg, "*"
		} else {
			return ClassifySpec(arg), "", arg
		}
	}
	if !ValidPackageName(name) {
		return ClassInvalid, name, spec
	}
	return ClassifySpec(spec), name, spec
}

// ExactArg reports whether a command-line argument is `name@x.y.z` and nothing
// else: a package, a strict exact version.
func ExactArg(arg string) bool {
	class, name, spec := ClassifyArg(arg)
	return class == ClassVersion && name != "" && StrictVersion(spec) && strings.HasSuffix(arg, "@"+spec)
}

// Refusal is one thing admission does not take.
type Refusal struct {
	Where  string `json:"where"`
	Text   string `json:"text"`
	Reason string `json:"reason"`
}

// Admission is the document of project-admit.
type Admission struct {
	SchemaVersion int       `json:"schema_version"`
	Ok            bool      `json:"ok"`
	Refusals      []Refusal `json:"refusals"`
	// Names are the distinct package names the checked inputs carry, which the
	// registry rules were applied to.
	Names []string `json:"names"`
}

// AdmitInput is what one admission reads. Every part is optional.
type AdmitInput struct {
	Args         []string
	ManifestFile string
	LockfileFile string
	ConfigFile   string
}

// CanonicalRegistry is the one registry the lane supports.
const CanonicalRegistry = "https://registry.npmjs.org/"

// Admit checks the command arguments, the manifest (dependency sections and
// typed overrides), the lockfile's dependency edges and the registry rules on
// every package name found.
func Admit(in AdmitInput) (Admission, error) {
	result := Admission{SchemaVersion: AdmitSchema, Refusals: []Refusal{}, Names: []string{}}
	names := map[string]struct{}{}
	refuse := func(where, text, reason string) {
		result.Refusals = append(result.Refusals, Refusal{Where: where, Text: text, Reason: reason})
	}
	addName := func(name string) {
		if name != "" {
			names[name] = struct{}{}
		}
	}

	for i, arg := range in.Args {
		if !ExactArg(arg) {
			refuse(fmt.Sprintf("argument %d", i+1), arg, "not an exact name@version registry spec")
			continue
		}
		_, name, _ := ClassifyArg(arg)
		addName(name)
	}

	if in.ManifestFile != "" {
		raw, err := os.ReadFile(in.ManifestFile)
		if err != nil {
			return result, err
		}
		if err := strictjson.RejectRepeatedMembers(raw); err != nil {
			return result, fmt.Errorf("manifest: %w", err)
		}
		var manifest map[string]json.RawMessage
		if err := json.Unmarshal(raw, &manifest); err != nil || manifest == nil {
			return result, fmt.Errorf("manifest: not a JSON object")
		}
		if value, ok := manifest["workspaces"]; ok && string(value) != "null" {
			refuse("manifest.workspaces", "", "a project with workspaces")
		}
		for _, section := range []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"} {
			value, ok := manifest[section]
			if !ok || string(value) == "null" {
				continue
			}
			var deps map[string]any
			if err := json.Unmarshal(value, &deps); err != nil || deps == nil {
				refuse("manifest."+section, "", "not a map")
				continue
			}
			for _, name := range sortedStringKeys(deps) {
				where := "manifest." + section + "." + name
				text, isString := deps[name].(string)
				if !isString {
					refuse(where, "", "a dependency spec that is not a string")
					continue
				}
				checkDep(where, name, text, refuse, addName)
			}
		}
		if value, ok := manifest["overrides"]; ok && string(value) != "null" {
			var overrides any
			if err := json.Unmarshal(value, &overrides); err != nil {
				return result, fmt.Errorf("manifest: overrides: %w", err)
			}
			walkOverrides("manifest.overrides", overrides, 0, refuse, addName)
		}
	}

	if in.LockfileFile != "" {
		raw, err := os.ReadFile(in.LockfileFile)
		if err != nil {
			return result, err
		}
		var lock struct {
			Packages map[string]struct {
				Name                 string         `json:"name"`
				Dependencies         map[string]any `json:"dependencies"`
				DevDependencies      map[string]any `json:"devDependencies"`
				OptionalDependencies map[string]any `json:"optionalDependencies"`
				PeerDependencies     map[string]any `json:"peerDependencies"`
			} `json:"packages"`
		}
		if err := strictjson.RejectRepeatedMembers(raw); err != nil {
			return result, fmt.Errorf("lockfile: %w", err)
		}
		if err := json.Unmarshal(raw, &lock); err != nil {
			return result, fmt.Errorf("lockfile: %w", err)
		}
		paths := make([]string, 0, len(lock.Packages))
		for path := range lock.Packages {
			paths = append(paths, path)
		}
		sort.Strings(paths)
		for _, path := range paths {
			entry := lock.Packages[path]
			if path != "" {
				name := entry.Name
				if name == "" {
					name = packageNameOfPath(path)
				}
				addName(name)
			}
			for kind, deps := range map[string]map[string]any{"dependencies": entry.Dependencies, "devDependencies": entry.DevDependencies,
				"optionalDependencies": entry.OptionalDependencies, "peerDependencies": entry.PeerDependencies} {
				for _, name := range sortedStringKeys(deps) {
					where := fmt.Sprintf("lockfile[%s].%s.%s", path, kind, name)
					text, isString := deps[name].(string)
					if !isString {
						refuse(where, "", "a dependency spec that is not a string")
						continue
					}
					checkDep(where, name, text, refuse, addName)
				}
			}
		}
	}

	var config map[string]any
	if in.ConfigFile != "" {
		raw, err := os.ReadFile(in.ConfigFile)
		if err != nil {
			return result, err
		}
		if err := json.Unmarshal(raw, &config); err != nil || config == nil {
			return result, fmt.Errorf("configuration: not a JSON object")
		}
		checkRegistries(config, names, refuse)
	}

	for name := range names {
		result.Names = append(result.Names, name)
	}
	sort.Strings(result.Names)
	sort.SliceStable(result.Refusals, func(i, j int) bool { return result.Refusals[i].Where < result.Refusals[j].Where })
	result.Ok = len(result.Refusals) == 0
	return result, nil
}

func sortedStringKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func checkDep(where, name, spec string, refuse func(w, t, r string), addName func(string)) {
	if !ValidPackageName(name) {
		refuse(where, name, "a dependency name that is not a registry package name")
		return
	}
	addName(name)
	if class := ClassifySpec(spec); !IsRegistry(class) {
		refuse(where, spec, "a dependency that is not a registry package ("+class+")")
	}
}

// walkOverrides checks an overrides tree as npm reads it: keys are selectors
// (`name`, `name@range`, `.` inside an object), values are a spec, a `$name`
// reference, or a nested object; anything else is not typed overrides.
func walkOverrides(where string, node any, depth int, refuse func(w, t, r string), addName func(string)) {
	if depth > 32 {
		refuse(where, "", "overrides nested too deeply")
		return
	}
	object, ok := node.(map[string]any)
	if !ok {
		refuse(where, "", "overrides that are not an object")
		return
	}
	for _, key := range sortedStringKeys(object) {
		keyWhere := where + "." + key
		selectorName := ""
		if key != "." {
			sel := key
			rangePart := ""
			hasRange := false
			if i := strings.Index(sel[min(1, len(sel)):], "@"); i >= 0 {
				i++
				sel, rangePart, hasRange = key[:i], key[i+1:], true
			}
			if !ValidPackageName(sel) {
				refuse(keyWhere, key, "an override selector that is not a registry package")
				continue
			}
			if hasRange && !IsRegistry(ClassifySpec(rangePart)) {
				refuse(keyWhere, key, "an override selector whose range is not a registry range")
				continue
			}
			selectorName = sel
			addName(sel)
		}
		switch value := object[key].(type) {
		case string:
			if strings.HasPrefix(value, "$") {
				if !ValidPackageName(value[1:]) {
					refuse(keyWhere, value, "an override reference that is not a package name")
				}
				continue
			}
			if class := ClassifySpec(value); !IsRegistry(class) {
				refuse(keyWhere, value, "an override that is not a registry package ("+class+")")
			}
		case map[string]any:
			_ = selectorName
			walkOverrides(keyWhere, value, depth+1, refuse, addName)
		default:
			refuse(keyWhere, "", "an override that is neither a string nor an object")
		}
	}
}

// pickRegistry is npm-registry-fetch's choice for a package name: the registry
// of its scope, else of the configured default scope, else the default registry.
func pickRegistry(config map[string]any, name string) (registry, scope string) {
	get := func(key string) string {
		if value, ok := config[key].(string); ok {
			return value
		}
		return ""
	}
	if strings.HasPrefix(name, "@") {
		if i := strings.Index(name, "/"); i > 0 {
			scope = name[:i]
		}
		if registry = get(scope + ":registry"); registry != "" {
			return registry, scope
		}
	}
	if def := get("scope"); def != "" {
		def = "@" + strings.TrimPrefix(def, "@")
		if registry = get(def + ":registry"); registry != "" {
			return registry, def
		}
	}
	return get("registry"), scope
}

func canonicalRegistry(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return u.Scheme == "https" && u.Host == "registry.npmjs.org" && u.User == nil && (u.Path == "/" || u.Path == "") &&
		u.RawQuery == "" && u.Fragment == "" && strings.EqualFold(raw, CanonicalRegistry)
}

// checkRegistries decides registries on parsed identities: the default
// registry must be the canonical public one; every package name found picks a
// registry by npm's rule, and that must be canonical too (a scope mapped to the
// canonical registry is accepted; one mapped elsewhere refuses when a package
// of that scope is in the judged graph).
func checkRegistries(config map[string]any, names map[string]struct{}, refuse func(w, t, r string)) {
	registry, _ := config["registry"].(string)
	if !canonicalRegistry(registry) {
		refuse("configuration.registry", registry, "a registry other than the canonical public one over https")
	}
	sorted := make([]string, 0, len(names))
	for name := range names {
		sorted = append(sorted, name)
	}
	sort.Strings(sorted)
	reported := map[string]bool{}
	for _, name := range sorted {
		picked, scope := pickRegistry(config, name)
		if picked == "" || canonicalRegistry(picked) {
			continue
		}
		key := scope
		if key == "" {
			key = "(default scope)"
		}
		if reported[key] {
			continue
		}
		reported[key] = true
		refuse("configuration.registry", picked, "the package "+name+" resolves through a registry other than the canonical public one")
	}
}
