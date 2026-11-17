// Package nodetree checks that an installed node_modules tree is the tree a
// JavaScript lockfile describes, whatever package manager wrote it. It backs
// `safe install --reuse` for Node projects: a reused tree must be the one the
// lockfile pins, never a stale install left in the source checkout.
//
// The installed side is read from the tree itself (every package.json under
// the copied node_modules directories), so the check does not depend on a
// manager's private state file. The expected side is read from the lockfile:
// npm (package-lock.json, npm-shrinkwrap.json), Yarn classic and Berry
// (yarn.lock), pnpm (pnpm-lock.yaml) and bun (bun.lock). The YAML lockfiles
// are machine-written with a fixed shape; they are read line by line, without
// a general YAML parser, which keeps safe-core stdlib-only.
package nodetree

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// Entry is one package the lockfile expects in the installed tree.
type Entry struct {
	Name    string
	Version string
	// Optional: the package may be absent from a complete install (an
	// optional or platform-conditional dependency, or one only optional
	// packages need).
	Optional bool
	// ids are the descriptors this entry resolves ("nopt@npm:^10.0.0"),
	// deps and optDeps the descriptors it depends on; a descriptor no entry
	// claims falls back to every entry of that name.
	ids     []string
	deps    []string
	optDeps []string
}

// Lockfile is the expected side of the check.
type Lockfile struct {
	Format  string
	Entries []Entry
	// roots are the dependencies the lockfile itself records for the
	// project and its workspaces (Yarn Berry workspace entries, bun's
	// workspaces section).
	roots []Root
}

// ErrUnsupported marks a lockfile safe cannot read (bun.lockb is binary).
var ErrUnsupported = errors.New("unsupported lockfile format")

// Load reads the lockfile at file; its base name selects the format.
func Load(file string) (Lockfile, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return Lockfile{}, err
	}
	var lf Lockfile
	switch filepath.Base(file) {
	case "package-lock.json", "npm-shrinkwrap.json":
		lf, err = loadNpm(raw)
	case "yarn.lock":
		if berryHeader(raw) {
			lf, err = loadBerry(raw)
		} else {
			lf, err = loadYarnClassic(raw)
		}
	case "pnpm-lock.yaml":
		lf, err = loadPnpm(raw)
	case "bun.lock":
		lf, err = loadBun(raw)
	default:
		return Lockfile{}, fmt.Errorf("%s: %w", filepath.Base(file), ErrUnsupported)
	}
	if err != nil {
		return Lockfile{}, fmt.Errorf("%s: %w", filepath.Base(file), err)
	}
	return lf, nil
}

// Root is one dependency the project itself declares, as the candidate
// entry identifiers to try in order (a descriptor such as "glob@^10.3.10",
// or a bun.lock package key).
type Root []string

// markRequired decides which entries a complete install must hold, for the
// formats whose lockfile does not record transitive optionality (Yarn and
// bun): an entry is required when the project's own dependencies reach it
// through dependency edges that are neither optional nor leave a
// platform-conditional package. npm and pnpm mark it themselves and are left
// as written.
func (lf *Lockfile) markRequired(roots []Root) {
	if lf.Format == "npm" || lf.Format == "pnpm" {
		return
	}
	entries := lf.Entries
	byID := map[string][]int{}
	byName := map[string][]int{}
	for i, e := range entries {
		for _, id := range e.ids {
			byID[id] = append(byID[id], i)
		}
		byName[e.Name] = append(byName[e.Name], i)
	}
	// A descriptor no entry claims falls back to every entry of its name:
	// over-requiring can only add a finding, never hide one.
	resolve := func(candidates ...string) []int {
		for _, c := range candidates {
			if idx, ok := byID[c]; ok {
				return idx
			}
		}
		if len(candidates) == 0 {
			return nil
		}
		name, _ := splitDescriptor(candidates[len(candidates)-1])
		return byName[name]
	}
	required := make([]bool, len(entries))
	var queue []int
	push := func(idx []int) {
		for _, i := range idx {
			if !required[i] {
				required[i] = true
				queue = append(queue, i)
			}
		}
	}
	if len(roots) == 0 {
		// No manifest to start from: every entry nothing depends on is one.
		depended := make([]bool, len(entries))
		for _, e := range entries {
			for _, d := range append(append([]string{}, e.deps...), e.optDeps...) {
				for _, t := range resolve(d) {
					depended[t] = true
				}
			}
		}
		for i := range entries {
			if !depended[i] {
				push([]int{i})
			}
		}
	}
	for _, r := range roots {
		push(resolve(r...))
	}
	for len(queue) > 0 {
		i := queue[0]
		queue = queue[1:]
		if entries[i].Optional {
			continue
		}
		for _, d := range entries[i].deps {
			push(resolve(d))
		}
	}
	for i := range entries {
		if !required[i] {
			entries[i].Optional = true
		}
	}
}

// --- npm ----------------------------------------------------------------------

type npmPackage struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Link        bool   `json:"link"`
	Optional    bool   `json:"optional"`
	DevOptional bool   `json:"devOptional"`
	InBundle    bool   `json:"inBundle"`
	Bundled     bool   `json:"bundled"`
	// Dependencies is a nested tree in lockfileVersion 1 and a name-to-range
	// map in the packages section of later versions.
	Dependencies json.RawMessage `json:"dependencies"`
}

func loadNpm(raw []byte) (Lockfile, error) {
	var doc struct {
		Packages     map[string]npmPackage `json:"packages"`
		Dependencies map[string]npmPackage `json:"dependencies"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return Lockfile{}, err
	}
	lf := Lockfile{Format: "npm"}
	if doc.Packages != nil {
		for key, p := range doc.Packages {
			i := strings.LastIndex(key, "node_modules/")
			// The root and workspace package folders are the project's
			// own sources, links are not installed copies, and bundled
			// packages ship inside their parent's tarball.
			if i < 0 || p.Link || p.InBundle {
				continue
			}
			name := p.Name
			if name == "" {
				name = key[i+len("node_modules/"):]
			}
			lf.Entries = append(lf.Entries, Entry{Name: name, Version: p.Version, Optional: p.Optional || p.DevOptional})
		}
		return lf, nil
	}
	if doc.Dependencies == nil {
		return Lockfile{}, errors.New("neither packages nor dependencies is present")
	}
	var walk func(map[string]npmPackage, bool)
	walk = func(deps map[string]npmPackage, optional bool) {
		for name, p := range deps {
			if p.Bundled {
				continue
			}
			version := p.Version
			// lockfileVersion 1 records an alias as "npm:real@version".
			if real, ok := strings.CutPrefix(version, "npm:"); ok {
				if at := strings.LastIndex(real, "@"); at > 0 {
					name, version = real[:at], real[at+1:]
				}
			}
			if strings.HasPrefix(version, "file:") {
				continue
			}
			lf.Entries = append(lf.Entries, Entry{Name: name, Version: version, Optional: optional || p.Optional})
			var nested map[string]npmPackage
			if len(p.Dependencies) > 0 {
				_ = json.Unmarshal(p.Dependencies, &nested)
			}
			walk(nested, optional || p.Optional)
		}
	}
	walk(doc.Dependencies, false)
	return lf, nil
}

// --- shared line-oriented helpers ------------------------------------------------

func indentOf(line string) int {
	return len(line) - len(strings.TrimLeft(line, " "))
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '"' && s[len(s)-1] == '"' || s[0] == '\'' && s[len(s)-1] == '\'') {
		return s[1 : len(s)-1]
	}
	return s
}

// splitDescriptor splits "name@range" (name may be scoped) at the separator.
func splitDescriptor(d string) (string, string) {
	d = unquote(d)
	at := strings.Index(d[min(1, len(d)):], "@")
	if at < 0 {
		return d, ""
	}
	at++
	return d[:at], d[at+1:]
}

// headerPatterns splits a lockfile block header ("a@1, \"b@2\":") into patterns.
func headerPatterns(line string) []string {
	line = strings.TrimSuffix(strings.TrimSpace(line), ":")
	var out []string
	// Yarn classic quotes each pattern, Berry the whole list.
	for _, p := range strings.Split(line, ",") {
		if p = strings.Trim(p, "\"' "); p != "" {
			out = append(out, p)
		}
	}
	return out
}

type block struct {
	header string
	lines  []string
}

// blocks splits a lockfile into its top-level entries.
func blocks(raw []byte) []block {
	var out []block
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if indentOf(line) == 0 {
			out = append(out, block{header: line})
			continue
		}
		if len(out) > 0 {
			out[len(out)-1].lines = append(out[len(out)-1].lines, line)
		}
	}
	return out
}

// dependencyDescriptor reads one dependency line of a lockfile entry
// (`name "range"`, `name: "npm:range"`, `'@s/name': 1.0.0(peer)`) as the
// descriptor "name@range" that entry headers and keys are written in.
func dependencyDescriptor(line string) string {
	t := strings.TrimSpace(line)
	var key, value string
	if t != "" && (t[0] == '"' || t[0] == '\'') {
		if j := strings.IndexByte(t[1:], t[0]); j >= 0 {
			key, value = t[1:j+1], t[j+2:]
		}
		value = strings.TrimPrefix(strings.TrimSpace(value), ":")
	} else if k, v, ok := strings.Cut(t, ": "); ok {
		key, value = k, v
	} else if k, ok := strings.CutSuffix(t, ":"); ok {
		key = k
	} else {
		key, value, _ = strings.Cut(t, " ")
	}
	value = unquote(value)
	if i := strings.Index(value, "("); i > 0 {
		value = value[:i]
	}
	return key + "@" + value
}

// section returns the dependency descriptors of a nested mapping field
// ("dependencies:") of a block, at the given field indentation.
func section(lines []string, field string, indent int) []string {
	var out []string
	in := false
	for _, l := range lines {
		ind := indentOf(l)
		if ind <= indent {
			in = ind == indent && strings.TrimSpace(l) == field+":"
			continue
		}
		if in && ind == indent+2 && !strings.HasPrefix(strings.TrimSpace(l), "- ") {
			out = append(out, dependencyDescriptor(l))
		}
	}
	return out
}

// field returns the scalar value of a field at the given indentation.
func field(lines []string, name string, indent int, sep string) (string, bool) {
	prefix := name + sep
	for _, l := range lines {
		if indentOf(l) != indent {
			continue
		}
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), prefix); ok {
			return unquote(v), true
		}
	}
	return "", false
}

// --- Yarn classic ------------------------------------------------------------------

func berryHeader(raw []byte) bool {
	for _, b := range blocks(raw) {
		return strings.HasPrefix(b.header, "__metadata:")
	}
	return false
}

func loadYarnClassic(raw []byte) (Lockfile, error) {
	lf := Lockfile{Format: "yarn-classic"}
	for _, b := range blocks(raw) {
		patterns := headerPatterns(b.header)
		if len(patterns) == 0 {
			continue
		}
		version, ok := field(b.lines, "version", 2, " ")
		if !ok {
			return Lockfile{}, fmt.Errorf("entry %q has no version", patterns[0])
		}
		name, rng := splitDescriptor(patterns[0])
		if real, ok := strings.CutPrefix(rng, "npm:"); ok {
			name, _ = splitDescriptor(real)
		}
		if strings.HasPrefix(rng, "file:") || strings.HasPrefix(rng, "link:") {
			continue
		}
		lf.Entries = append(lf.Entries, Entry{
			Name:    name,
			Version: version,
			ids:     patterns,
			deps:    section(b.lines, "dependencies", 2),
			optDeps: section(b.lines, "optionalDependencies", 2),
		})
	}
	if len(lf.Entries) == 0 && len(bytes.TrimSpace(raw)) > 0 && !onlyComments(raw) {
		return Lockfile{}, errors.New("no entries could be read")
	}
	return lf, nil
}

func onlyComments(raw []byte) bool {
	for _, l := range strings.Split(string(raw), "\n") {
		if t := strings.TrimSpace(l); t != "" && !strings.HasPrefix(t, "#") {
			return false
		}
	}
	return true
}

// --- Yarn Berry ----------------------------------------------------------------------

func loadBerry(raw []byte) (Lockfile, error) {
	lf := Lockfile{Format: "yarn-berry"}
	for _, b := range blocks(raw) {
		if strings.HasPrefix(b.header, "__metadata:") {
			continue
		}
		resolution, ok := field(b.lines, "resolution", 2, ": ")
		if !ok {
			return Lockfile{}, fmt.Errorf("entry %q has no resolution", strings.TrimSpace(b.header))
		}
		// Workspaces, portals and links are the project's own folders; a
		// workspace's dependencies are the project's own.
		if lt, _ := field(b.lines, "linkType", 2, ": "); lt == "soft" {
			if strings.Contains(resolution, "@workspace:") {
				for _, d := range berryDescriptors(section(b.lines, "dependencies", 2)) {
					lf.roots = append(lf.roots, Root{d})
				}
			}
			continue
		}
		version, _ := field(b.lines, "version", 2, ": ")
		name, _ := splitDescriptor(resolution)
		conditions, _ := field(b.lines, "conditions", 2, ": ")
		conditional := conditions != "" && !berryConditionsHold(conditions)
		e := Entry{Name: name, Version: version, Optional: conditional,
			ids:     headerPatterns(b.header),
			optDeps: berryDescriptors(section(b.lines, "optionalDependencies", 2))}
		e.optDeps = append(e.optDeps, berryDescriptors(berryOptionalMeta(b.lines))...)
		// dependenciesMeta marks an optional dependency listed among the
		// regular ones: it is no required edge.
		optional := map[string]bool{}
		for _, d := range e.optDeps {
			optional[d] = true
		}
		for _, d := range berryDescriptors(section(b.lines, "dependencies", 2)) {
			if !optional[d] {
				e.deps = append(e.deps, d)
			}
		}
		lf.Entries = append(lf.Entries, e)
	}
	return lf, nil
}

// berryDescriptors: lockfiles before metadata version 8 write a registry
// dependency without its protocol ("glob: ^10.3.10") while the entry header
// carries it ("glob@npm:^10.3.10").
func berryDescriptors(descs []string) []string {
	for i, d := range descs {
		if name, rng := splitDescriptor(d); rng != "" && !strings.Contains(rng, ":") {
			descs[i] = name + "@npm:" + rng
		}
	}
	return descs
}

// berryOptionalMeta reads `dependenciesMeta: <name>: optional: true`.
func berryOptionalMeta(lines []string) []string {
	ranges := map[string]string{}
	for _, d := range section(lines, "dependencies", 2) {
		name, _ := splitDescriptor(d)
		ranges[name] = d
	}
	var out []string
	in, current := false, ""
	for _, l := range lines {
		ind, t := indentOf(l), strings.TrimSpace(l)
		switch {
		case ind == 2:
			in = t == "dependenciesMeta:"
		case in && ind == 4:
			current = unquote(strings.TrimSuffix(t, ":"))
		case in && ind == 6 && t == "optional: true":
			if d, ok := ranges[current]; ok {
				out = append(out, d)
			} else {
				out = append(out, current+"@")
			}
		}
	}
	return out
}

// --- pnpm --------------------------------------------------------------------------

// pnpmKey reads a package key of any lockfile version:
// "/name/1.0.0_peer" (5), "/name@1.0.0(peer)" (6), "name@1.0.0(peer)" (9).
func pnpmKey(key string) (string, string) {
	key = strings.TrimPrefix(unquote(key), "/")
	if i := strings.Index(key, "("); i >= 0 {
		key = key[:i]
	}
	if name, version := splitDescriptor(key); version != "" && pnpmName.MatchString(name) {
		return name, version
	}
	slash := strings.LastIndex(key, "/")
	if slash < 0 {
		return key, ""
	}
	version := key[slash+1:]
	if u := strings.Index(version, "_"); u >= 0 {
		version = version[:u]
	}
	return key[:slash], version
}

var pnpmName = regexp.MustCompile(`^(@[^/@]+/)?[^/@]+$`)

// pnpmEnvDocument: pnpm 10+ may prepend a YAML document locking its own
// config and package-manager dependencies, which install outside the
// project's node_modules.
var pnpmEnvDocument = regexp.MustCompile(`(?m)^    (configDependencies|packageManagerDependencies):`)

func loadPnpm(raw []byte) (Lockfile, error) {
	lf := Lockfile{Format: "pnpm"}
	var docs [][]byte
	for _, doc := range regexp.MustCompile(`(?m)^---\s*$`).Split(string(raw), -1) {
		if strings.TrimSpace(doc) != "" && !pnpmEnvDocument.MatchString(doc) {
			docs = append(docs, []byte(doc))
		}
	}
	if len(docs) != 1 {
		return Lockfile{}, fmt.Errorf("expected one project document, found %d", len(docs))
	}
	raw = docs[0]
	type acc struct{ Entry }
	byKey := map[string]*acc{}
	var order []string
	sectionName := ""
	var current *acc
	inList := ""
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		ind := indentOf(line)
		switch {
		case ind == 0:
			sectionName = strings.TrimSuffix(t, ":")
			current = nil
		case ind == 2 && (sectionName == "packages" || sectionName == "snapshots"):
			key := strings.TrimSuffix(t, ":")
			if strings.HasSuffix(t, ": {}") {
				key = strings.TrimSuffix(t, ": {}")
			}
			name, version := pnpmKey(key)
			id := name + "@" + version
			if byKey[id] == nil {
				byKey[id] = &acc{Entry: Entry{Name: name, Version: version, ids: []string{id}}}
				order = append(order, id)
			}
			current = byKey[id]
			inList = ""
		case ind == 4 && current != nil:
			inList = ""
			k, v, _ := strings.Cut(t, ":")
			v = strings.TrimSpace(v)
			switch k {
			case "optional":
				if v == "true" {
					current.Optional = true
				}
			case "os", "cpu", "libc":
				// An allowlist, not a mark: the package may be absent only
				// where it does not apply to this machine.
				if !platformAllows(k, inlineList(v)) {
					current.Optional = true
				}
			case "name":
				// Tarball and git packages carry their real name and version.
				if sectionName == "packages" {
					current.Name = unquote(v)
				}
			case "version":
				if sectionName == "packages" {
					current.Version = unquote(v)
				}
			case "dependencies", "optionalDependencies":
				inList = k
			}
		case ind == 6 && current != nil && inList != "":
			if inList == "optionalDependencies" {
				current.optDeps = append(current.optDeps, dependencyDescriptor(t))
			} else {
				current.deps = append(current.deps, dependencyDescriptor(t))
			}
		}
	}
	if err := sc.Err(); err != nil {
		return Lockfile{}, err
	}
	for _, id := range order {
		lf.Entries = append(lf.Entries, byKey[id].Entry)
	}
	return lf, nil
}

// --- bun -----------------------------------------------------------------------------

var trailingComma = regexp.MustCompile(`,(\s*[}\]])`)

func loadBun(raw []byte) (Lockfile, error) {
	var doc struct {
		Workspaces map[string]struct {
			Name            string            `json:"name"`
			Dependencies    map[string]string `json:"dependencies"`
			DevDependencies map[string]string `json:"devDependencies"`
		} `json:"workspaces"`
		Packages map[string][]json.RawMessage `json:"packages"`
	}
	if err := json.Unmarshal(trailingComma.ReplaceAll(raw, []byte("$1")), &doc); err != nil {
		return Lockfile{}, err
	}
	lf := Lockfile{Format: "bun"}
	for _, ws := range doc.Workspaces {
		for _, deps := range []map[string]string{ws.Dependencies, ws.DevDependencies} {
			for name := range deps {
				lf.roots = append(lf.roots, Root{ws.Name + "/" + name, name})
			}
		}
	}
	// A bun.lock key is the package's place in the tree ("a/node_modules/b"
	// written "a/b"); a dependency resolves like Node does, from the
	// dependent's own place up to the top level.
	resolveKey := func(from, dep string) string {
		for k := from; ; {
			if _, ok := doc.Packages[k+"/"+dep]; ok && k != "" {
				return k + "/" + dep
			}
			i := strings.LastIndex(k, "/")
			if i < 0 {
				break
			}
			k = k[:i]
		}
		return dep
	}
	for key, tuple := range doc.Packages {
		if len(tuple) == 0 {
			return Lockfile{}, fmt.Errorf("package %q is empty", key)
		}
		var ident string
		if err := json.Unmarshal(tuple[0], &ident); err != nil {
			return Lockfile{}, fmt.Errorf("package %q: %v", key, err)
		}
		at := strings.LastIndex(ident, "@")
		if at <= 0 {
			return Lockfile{}, fmt.Errorf("package %q: unreadable identity %q", key, ident)
		}
		name, version := ident[:at], ident[at+1:]
		if strings.HasPrefix(version, "workspace:") || strings.HasPrefix(version, "link:") {
			continue
		}
		e := Entry{Name: name, Version: version, ids: []string{key}}
		for _, el := range tuple[1:] {
			var meta struct {
				Dependencies         map[string]string `json:"dependencies"`
				OptionalDependencies map[string]string `json:"optionalDependencies"`
				OS                   json.RawMessage   `json:"os"`
				CPU                  json.RawMessage   `json:"cpu"`
				Optional             bool              `json:"optional"`
			}
			if json.Unmarshal(el, &meta) != nil {
				continue
			}
			e.Optional = e.Optional || meta.Optional ||
				!platformAllows("os", jsonList(meta.OS)) || !platformAllows("cpu", jsonList(meta.CPU))
			for d := range meta.Dependencies {
				e.deps = append(e.deps, resolveKey(key, d))
			}
			for d := range meta.OptionalDependencies {
				e.optDeps = append(e.optDeps, resolveKey(key, d))
			}
		}
		lf.Entries = append(lf.Entries, e)
	}
	return lf, nil
}

// --- platform -------------------------------------------------------------------------

// The machine's identity in npm's terms (process.platform, process.arch).
var (
	hostOS   = map[string]string{"windows": "win32"}[runtime.GOOS]
	hostCPU  = map[string]string{"amd64": "x64", "386": "ia32", "arm64": "arm64", "arm": "arm", "ppc64le": "ppc64", "s390x": "s390x", "riscv64": "riscv64", "loong64": "loong64"}[runtime.GOARCH]
	hostLibc = detectLibc()
)

func init() {
	if hostOS == "" {
		hostOS = runtime.GOOS
	}
	if hostCPU == "" {
		hostCPU = runtime.GOARCH
	}
}

func detectLibc() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	if matches, _ := filepath.Glob("/lib/ld-musl-*"); len(matches) > 0 {
		return "musl"
	}
	return "glibc"
}

// platformAllows evaluates an npm os/cpu/libc allowlist ("darwin",
// "!win32") for this machine. An empty list allows everything.
func platformAllows(kind string, list []string) bool {
	host := map[string]string{"os": hostOS, "cpu": hostCPU, "libc": hostLibc}[kind]
	if len(list) == 0 || host == "" && kind == "libc" {
		return true
	}
	positive, matched := false, false
	for _, v := range list {
		if neg, ok := strings.CutPrefix(v, "!"); ok {
			if neg == host {
				return false
			}
			continue
		}
		positive = true
		if v == host || v == "any" {
			matched = true
		}
	}
	return !positive || matched
}

// berryConditionsHold evaluates Yarn Berry's "os=darwin & cpu=arm64"
// (alternatives joined by "|").
func berryConditionsHold(conditions string) bool {
	for _, alt := range strings.Split(conditions, "|") {
		holds := true
		for _, term := range strings.Split(alt, "&") {
			k, v, ok := strings.Cut(strings.Trim(strings.TrimSpace(term), "()"), "=")
			if ok && !platformAllows(strings.TrimSpace(k), []string{strings.TrimSpace(v)}) {
				holds = false
			}
		}
		if holds {
			return true
		}
	}
	return false
}

// inlineList reads a YAML flow list ("[darwin, linux]") or a scalar.
func inlineList(v string) []string {
	v = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(v), "["), "]")
	var out []string
	for _, item := range strings.Split(v, ",") {
		if item = unquote(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// jsonList reads a bun os/cpu value: a string ("darwin", "none") or a list.
func jsonList(raw json.RawMessage) []string {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		if one == "" || one == "none" {
			return nil
		}
		return []string{one}
	}
	var list []string
	_ = json.Unmarshal(raw, &list)
	return list
}
