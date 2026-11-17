package nodetree

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Options names the tree to check.
type Options struct {
	// Lockfile is the project's lockfile.
	Lockfile string
	// Source is the project directory holding the installed tree to check
	// (the source checkout, or the staged copy laid out like the project).
	Source string
	// Target is the project directory the tree will land in: links that
	// leave node_modules are resolved there.
	Target string
	// Modules are the node_modules directories to check, relative to the
	// project directory ("node_modules", "packages/a/node_modules").
	Modules []string
	// Exclude names top-level entries of every modules directory that are
	// tool caches, never copied and never checked (".cache", ".vite").
	Exclude []string
}

// Report is the outcome of a check. Problems is empty when the installed
// tree is exactly the tree the lockfile describes, and self-contained.
type Report struct {
	Schema    int      `json:"schema"`
	Format    string   `json:"format"`
	Expected  int      `json:"expected"`
	Installed int      `json:"installed"`
	Problems  []string `json:"problems"`
}

// installed is one package folder. store: it sits in an isolated layout's
// virtual store, where pnpm keeps orphans of earlier installs until it
// prunes them; nothing resolves to an orphan, so only a missing package
// there is a finding, never an extra one.
type installed struct {
	name, version string
	store         bool
}

// Check compares the installed tree with the lockfile. An error means the
// check could not run (an unreadable lockfile or tree), never a verdict.
func Check(o Options) (Report, error) {
	var err error
	if o.Source, err = filepath.Abs(o.Source); err != nil {
		return Report{}, err
	}
	if o.Target, err = filepath.Abs(o.Target); err != nil {
		return Report{}, err
	}
	lf, err := Load(o.Lockfile)
	if err != nil {
		return Report{}, err
	}
	roots, err := projectRoots(lf.Format, o.Target, o.Modules)
	if err != nil {
		return Report{}, err
	}
	lf.markRequired(append(roots, lf.roots...))
	r := Report{Schema: 1, Format: lf.Format, Problems: []string{}}
	exclude := map[string]bool{}
	for _, e := range o.Exclude {
		exclude[e] = true
	}

	var found []installed
	for _, rel := range o.Modules {
		dir := filepath.Join(o.Source, rel)
		info, err := os.Lstat(dir)
		if err != nil {
			return Report{}, err
		}
		if !info.IsDir() {
			r.Problems = append(r.Problems, fmt.Sprintf("%s is a symlink or not a directory", rel))
			continue
		}
		pk, problems, err := listPackages(dir, rel, exclude, true, nil, lf.Format != "npm")
		if err != nil {
			return Report{}, err
		}
		found = append(found, pk...)
		r.Problems = append(r.Problems, problems...)
		lp, err := checkLinks(o, rel, exclude, optionalSet(lf.Entries), uniqueEntries(lf.Entries))
		if err != nil {
			return Report{}, err
		}
		r.Problems = append(r.Problems, lp...)
	}
	r.Problems = append(append([]string{}, compare(lf.Entries, found)...), r.Problems...)
	r.Expected = len(uniqueEntries(lf.Entries))
	r.Installed = len(uniqueInstalled(found))
	return r, nil
}

// projectRoots reads the dependencies the project and each of its
// workspaces declare, as the target checkout declares them: the tree is
// checked for the project it will serve, and a staged copy carries no
// manifest of its own. Workspaces come from the root manifest's
// "workspaces" and pnpm-workspace.yaml, and from every folder owning a
// copied modules directory: a hoisted workspace owns none, yet its
// dependencies are required at the root.
func projectRoots(format, project string, modules []string) ([]Root, error) {
	dirs := map[string]bool{".": true}
	for _, rel := range modules {
		dirs[filepath.Dir(rel)] = true
	}
	patterns, err := workspacePatterns(project)
	if err != nil {
		return nil, err
	}
	for _, pattern := range patterns {
		matches, _ := filepath.Glob(filepath.Join(project, pattern))
		for _, m := range matches {
			if fi, err := os.Stat(m); err != nil || !fi.IsDir() {
				continue
			}
			if rel, err := filepath.Rel(project, m); err == nil && !strings.Contains("/"+rel+"/", "/node_modules/") {
				dirs[rel] = true
			}
		}
	}
	var roots []Root
	for dir := range dirs {
		raw, err := os.ReadFile(filepath.Join(project, dir, "package.json"))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var pj struct {
			Name            string            `json:"name"`
			Dependencies    map[string]string `json:"dependencies"`
			DevDependencies map[string]string `json:"devDependencies"`
		}
		if err := json.Unmarshal(raw, &pj); err != nil {
			return nil, fmt.Errorf("%s: %v", filepath.Join(dir, "package.json"), err)
		}
		for _, deps := range []map[string]string{pj.Dependencies, pj.DevDependencies} {
			for name, rng := range deps {
				switch format {
				case "bun":
					roots = append(roots, Root{pj.Name + "/" + name, name})
				case "yarn-berry":
					roots = append(roots, Root{name + "@" + rng, name + "@npm:" + rng})
				default:
					roots = append(roots, Root{name + "@" + rng})
				}
			}
		}
	}
	return roots, nil
}

// workspacePatterns reads the workspace globs of the root manifest
// ("workspaces": [...] or {"packages": [...]}) and of pnpm-workspace.yaml.
// Negated patterns are ignored: over-including a workspace can only add a
// requirement, never hide one.
func workspacePatterns(project string) ([]string, error) {
	var out []string
	raw, err := os.ReadFile(filepath.Join(project, "package.json"))
	if err == nil {
		var pj struct {
			Workspaces json.RawMessage `json:"workspaces"`
		}
		if json.Unmarshal(raw, &pj) == nil && len(pj.Workspaces) > 0 {
			var list []string
			if json.Unmarshal(pj.Workspaces, &list) != nil {
				var obj struct {
					Packages []string `json:"packages"`
				}
				_ = json.Unmarshal(pj.Workspaces, &obj)
				list = obj.Packages
			}
			out = append(out, list...)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if raw, err := os.ReadFile(filepath.Join(project, "pnpm-workspace.yaml")); err == nil {
		in := false
		for _, line := range strings.Split(string(raw), "\n") {
			t := strings.TrimSpace(line)
			if indentOf(line) == 0 {
				in = t == "packages:"
				continue
			}
			if v, ok := strings.CutPrefix(t, "- "); in && ok {
				out = append(out, unquote(v))
			}
		}
	}
	var kept []string
	for _, p := range out {
		if p = strings.TrimSuffix(strings.TrimPrefix(p, "./"), "/"); p != "" && !strings.HasPrefix(p, "!") {
			// filepath.Glob has no "**": every folder under the literal
			// prefix is a candidate; those without a package.json add
			// nothing.
			if i := strings.Index(p, "**"); i >= 0 {
				base := filepath.Join(project, p[:i])
				_ = filepath.WalkDir(base, func(q string, d fs.DirEntry, err error) error {
					if err != nil || !d.IsDir() {
						return nil
					}
					if d.Name() == "node_modules" || strings.HasPrefix(d.Name(), ".") && q != base {
						return filepath.SkipDir
					}
					if rel, err := filepath.Rel(project, q); err == nil {
						kept = append(kept, rel)
					}
					return nil
				})
				continue
			}
			kept = append(kept, p)
		}
	}
	return kept, nil
}

// storeDirs hold the real package folders of isolated layouts
// (node_modules/.pnpm/<id>/node_modules/<name>, and bun's .bun likewise).
var storeDirs = map[string]bool{".pnpm": true, ".bun": true}

// moduleFile: a regular file Node resolves as a module from node_modules
// (require("x") finds node_modules/x, x.js, x.json...). No manager writes a
// file at package position, extensionless ones included.
var moduleFile = map[string]bool{".js": true, ".cjs": true, ".mjs": true, ".json": true, ".node": true}

// listPackages reads the packages of one node_modules directory. skip names
// the bundled dependencies of the package that owns it.
func listPackages(dir, rel string, exclude map[string]bool, top bool, skip map[string]bool, honorBundles bool) ([]installed, []string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}
	var out []installed
	var problems []string
	add := func(pk []installed, pr []string, err error) error {
		out = append(out, pk...)
		problems = append(problems, pr...)
		return err
	}
	for _, e := range entries {
		name := e.Name()
		if top && exclude[name] || skip[name] {
			continue
		}
		switch {
		case e.Type().IsRegular() && !strings.HasPrefix(name, ".") && (moduleFile[filepath.Ext(name)] || filepath.Ext(name) == ""):
			problems = append(problems, fmt.Sprintf("%s is a file module the lockfile does not describe", filepath.Join(rel, name)))
		case storeDirs[name] && e.IsDir():
			ids, err := os.ReadDir(filepath.Join(dir, name))
			if err != nil {
				return nil, nil, err
			}
			for _, id := range ids {
				nm := filepath.Join(dir, name, id.Name(), "node_modules")
				if id.Name() == "node_modules" {
					nm = filepath.Join(dir, name, "node_modules")
				}
				if fi, err := os.Lstat(nm); err != nil || !fi.IsDir() {
					continue
				}
				pk, pr, err := listPackages(nm, filepath.Join(rel, name, id.Name(), "node_modules"), nil, false, nil, honorBundles)
				for i := range pk {
					pk[i].store = true
				}
				if err := add(pk, pr, err); err != nil {
					return nil, nil, err
				}
			}
		case strings.HasPrefix(name, "."):
			// Manager state (.bin, .package-lock.json, .yarn-state.yml...).
		case strings.HasPrefix(name, "@") && e.IsDir():
			scoped, err := os.ReadDir(filepath.Join(dir, name))
			if err != nil {
				return nil, nil, err
			}
			for _, s := range scoped {
				if skip[name+"/"+s.Name()] {
					continue
				}
				if s.Type().IsRegular() && (moduleFile[filepath.Ext(s.Name())] || filepath.Ext(s.Name()) == "") {
					problems = append(problems, fmt.Sprintf("%s is a file module the lockfile does not describe", filepath.Join(rel, name, s.Name())))
					continue
				}
				if err := add(readPackage(filepath.Join(dir, name, s.Name()), filepath.Join(rel, name, s.Name()), s, honorBundles)); err != nil {
					return nil, nil, err
				}
			}
		default:
			if err := add(readPackage(filepath.Join(dir, name), filepath.Join(rel, name), e, honorBundles)); err != nil {
				return nil, nil, err
			}
		}
	}
	return out, problems, nil
}

func readPackage(dir, rel string, e fs.DirEntry, honorBundles bool) ([]installed, []string, error) {
	// A symlink is either an alias to a package counted where it lives, or
	// a link to a workspace folder; checkLinks decides whether it holds.
	if e.Type()&fs.ModeSymlink != 0 || !e.IsDir() {
		return nil, nil, nil
	}
	raw, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, []string{fmt.Sprintf("%s has no package.json", rel)}, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var pj struct {
		Name         string            `json:"name"`
		Version      string            `json:"version"`
		Dependencies map[string]string `json:"dependencies"`
		Bundle       json.RawMessage   `json:"bundleDependencies"`
		Bundled      json.RawMessage   `json:"bundledDependencies"`
	}
	if err := json.Unmarshal(raw, &pj); err != nil {
		return nil, []string{fmt.Sprintf("%s/package.json is not readable JSON", rel)}, nil
	}
	if pj.Name == "" {
		pj.Name = filepath.ToSlash(rel[strings.LastIndex(rel, "node_modules/")+len("node_modules/"):])
	}
	// A git or tarball package may write its version as "v2.8.9".
	pj.Version = strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(pj.Version), "v"), "=")
	out := []installed{{name: pj.Name, version: pj.Version}}
	// Bundled dependencies ship inside the package's own tarball and are
	// not lockfile entries for every manager: those the package names are
	// its own; anything else nested beside them is checked as usual.
	// npm's lockfile pins bundled packages (inBundle) with their versions,
	// so an npm tree checks them like any other; other lockfiles do not
	// record them, and only there are they skipped.
	nested := filepath.Join(dir, "node_modules")
	skip := map[string]bool{}
	if honorBundles {
		skip = bundled(pj.Bundle, pj.Dependencies)
		for name := range bundled(pj.Bundled, pj.Dependencies) {
			skip[name] = true
		}
		bundleClosure(nested, skip)
	}
	if fi, err := os.Lstat(nested); err == nil && fi.IsDir() {
		pk, pr, err := listPackages(nested, filepath.Join(rel, "node_modules"), nil, false, skip, honorBundles)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, pk...)
		return out, pr, nil
	}
	return out, nil, nil
}

// bundleClosure adds to skip the dependencies of bundled packages that the
// tarball hoisted beside them in <nested> (npm marks them inBundle too).
func bundleClosure(nested string, skip map[string]bool) {
	queue := make([]string, 0, len(skip))
	for name := range skip {
		queue = append(queue, name)
	}
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		raw, err := os.ReadFile(filepath.Join(nested, name, "package.json"))
		if err != nil {
			continue
		}
		var pj struct {
			Dependencies         map[string]string `json:"dependencies"`
			OptionalDependencies map[string]string `json:"optionalDependencies"`
		}
		if json.Unmarshal(raw, &pj) != nil {
			continue
		}
		for _, deps := range []map[string]string{pj.Dependencies, pj.OptionalDependencies} {
			for dep := range deps {
				if _, err := os.Lstat(filepath.Join(nested, dep)); err == nil && !skip[dep] {
					skip[dep] = true
					queue = append(queue, dep)
				}
			}
		}
	}
}

// bundled reads a bundleDependencies value: a list of names, or true for
// every dependency.
func bundled(raw json.RawMessage, deps map[string]string) map[string]bool {
	out := map[string]bool{}
	var all bool
	if json.Unmarshal(raw, &all) == nil {
		if all {
			for name := range deps {
				out[name] = true
			}
		}
		return out
	}
	var list []string
	_ = json.Unmarshal(raw, &list)
	for _, name := range list {
		out[name] = true
	}
	return out
}

// checkLinks verifies every symlink under one modules directory as it will
// sit in the target: inside a copied modules directory it travels with the
// copy; inside the project (a workspace package) it must exist there and
// stay there physically; anything else would dangle or reach outside.
func checkLinks(o Options, rel string, exclude map[string]bool, optional, known map[string]bool) ([]string, error) {
	var problems []string
	targetReal, err := filepath.EvalSymlinks(o.Target)
	if err != nil {
		return nil, err
	}
	sourceReal, err := filepath.EvalSymlinks(o.Source)
	if err != nil {
		return nil, err
	}
	inModules := func(p string) bool {
		for _, m := range o.Modules {
			root := filepath.Join(o.Target, m)
			if p == root || strings.HasPrefix(p, root+string(filepath.Separator)) {
				return true
			}
		}
		return false
	}
	root := filepath.Join(o.Source, rel)
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p != root && filepath.Dir(p) == root && exclude[d.Name()] {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink == 0 {
			return nil
		}
		where, _ := filepath.Rel(o.Source, p)
		dest, err := os.Readlink(p)
		if err != nil {
			return err
		}
		if filepath.IsAbs(dest) {
			// Only a system path resolves the same for every checkout, and
			// node-gyp's build-time interpreter link is never loaded at run
			// time; any other absolute link would load code from outside
			// the copied tree, which the baseline cannot see.
			if within(dest, o.Source) || within(dest, o.Target) || within(dest, sourceReal) || within(dest, targetReal) {
				problems = append(problems, fmt.Sprintf("symlink %s -> %s is absolute and points into a checkout", where, dest))
			} else if !systemPath(dest) && !nodeGypInterpreter(where, dest) {
				problems = append(problems, fmt.Sprintf("symlink %s -> %s is absolute and points outside the project", where, dest))
			}
			return nil
		}
		logical := filepath.Join(o.Target, filepath.Dir(where), dest)
		if inModules(logical) {
			// It travels with the copy: it must resolve in the tree copied.
			// An isolated layout links every optional dependency, installed
			// or skipped for this platform: only a link into the virtual
			// store, to a package the lockfile holds as optional, may dangle.
			// pnpm's hidden hoisting folder (.pnpm/node_modules) also keeps
			// links to orphans of earlier installs, which nothing pins.
			resolved := filepath.Join(o.Source, filepath.Dir(where), dest)
			pkg := storePackage(resolved)
			hoistOrphan := pkg != "" && !known[pkg] && inHoistDir(where)
			if _, err := os.Stat(resolved); err != nil && !optional[pkg] && !hoistOrphan {
				problems = append(problems, fmt.Sprintf("symlink %s -> %s dangles in the installed tree", where, dest))
			}
			return nil
		}
		if logical != o.Target && !strings.HasPrefix(logical, o.Target+string(filepath.Separator)) {
			problems = append(problems, fmt.Sprintf("symlink %s -> %s points outside the project", where, dest))
			return nil
		}
		at, _ := filepath.Rel(o.Target, logical)
		physical, err := filepath.EvalSymlinks(logical)
		if err != nil {
			problems = append(problems, fmt.Sprintf("symlink %s -> %s would dangle here (%s is absent)", where, dest, at))
			return nil
		}
		if physical != targetReal && !strings.HasPrefix(physical, targetReal+string(filepath.Separator)) {
			problems = append(problems, fmt.Sprintf("symlink %s -> %s leads outside the project through another link", where, dest))
		}
		return nil
	})
	return problems, err
}

// nodeGypInterpreter: node-gyp links the Python it built with as
// <package>/build/node_gyp_bins/python3; nothing loads it at run time. Only
// that exact link, to a python binary, is exempt.
func nodeGypInterpreter(where, dest string) bool {
	where = filepath.ToSlash(where)
	return strings.HasSuffix(where, "/build/node_gyp_bins/python3") &&
		strings.HasPrefix(filepath.Base(dest), "python")
}

// optionalSet: the name@version of every entry a complete install may lack.
func optionalSet(entries []Entry) map[string]bool {
	required := map[string]bool{}
	for _, e := range entries {
		if !e.Optional {
			required[e.Name+"@"+e.Version] = true
		}
	}
	out := map[string]bool{}
	for _, e := range entries {
		if key := e.Name + "@" + e.Version; e.Optional && !required[key] {
			out[key] = true
		}
	}
	return out
}

// inHoistDir: the link sits in a virtual store's hidden hoisting folder.
func inHoistDir(where string) bool {
	parts := strings.Split(filepath.ToSlash(where), "/")
	for i := 0; i+2 < len(parts); i++ {
		if parts[i] == "node_modules" && storeDirs[parts[i+1]] && parts[i+2] == "node_modules" {
			return true
		}
	}
	return false
}

// storePackage reads the name@version of the virtual-store folder a path
// lies in (node_modules/.pnpm/@scope+name@1.0.0_peer/...); "" when none.
func storePackage(p string) string {
	parts := strings.Split(filepath.ToSlash(p), "/")
	for i := 0; i+2 < len(parts); i++ {
		if parts[i] != "node_modules" || !storeDirs[parts[i+1]] {
			continue
		}
		id := strings.Replace(parts[i+2], "+", "/", 1)
		if j := strings.IndexAny(id, "(_"); j > 0 {
			id = id[:j]
		}
		if name, version := splitDescriptor(id); version != "" {
			return name + "@" + version
		}
	}
	return ""
}

// systemPrefixes hold what the operating system installs, the same for
// every checkout on the machine.
var systemPrefixes = []string{"/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/etc"}

func systemPath(p string) bool {
	for _, prefix := range systemPrefixes {
		if within(p, prefix) {
			return true
		}
	}
	return false
}

func within(p, dir string) bool {
	p, dir = filepath.Clean(p), filepath.Clean(dir)
	return p == dir || strings.HasPrefix(p, dir+string(filepath.Separator))
}

// looseVersion: a lockfile version that is not a registry version (a git
// commit, a tarball URL) is matched by package name only.
func looseVersion(v string) bool {
	return v == "" || strings.ContainsAny(v, ":/#")
}

// compare matches the installed packages with the lockfile, name by name.
// A registry entry is matched by exact version. A loose entry (a git commit,
// a tarball URL) is matched by a copy of its name that no registry entry of
// that name claims, one copy per entry.
func compare(entries []Entry, found []installed) []string {
	type want struct {
		exact    map[string]bool // version -> required
		loose    int
		looseReq int
	}
	byName := map[string]*want{}
	for _, e := range entries {
		w := byName[e.Name]
		if w == nil {
			w = &want{exact: map[string]bool{}}
			byName[e.Name] = w
		}
		if looseVersion(e.Version) {
			w.loose++
			if !e.Optional {
				w.looseReq++
			}
			continue
		}
		w.exact[e.Version] = w.exact[e.Version] || !e.Optional
	}
	// name -> version -> found outside a virtual store
	have := map[string]map[string]bool{}
	for _, f := range found {
		if have[f.name] == nil {
			have[f.name] = map[string]bool{}
		}
		have[f.name][f.version] = have[f.name][f.version] || !f.store
	}
	var missing, extra []string
	for name, w := range byName {
		for version, required := range w.exact {
			if _, ok := have[name][version]; required && !ok {
				missing = append(missing, "missing "+name+"@"+version)
			}
		}
		var spare []string
		for version := range have[name] {
			if _, ok := w.exact[version]; !ok {
				spare = append(spare, version)
			}
		}
		sort.Strings(spare)
		if len(spare) < w.looseReq {
			missing = append(missing, fmt.Sprintf("missing %s (%d non-registry cop%s)", name, w.looseReq-len(spare), map[bool]string{true: "y", false: "ies"}[w.looseReq-len(spare) == 1]))
		}
		for i, version := range spare {
			if i >= w.loose && have[name][version] {
				extra = append(extra, "not in the lockfile: "+name+"@"+version)
			}
		}
	}
	for name, versions := range have {
		if byName[name] != nil {
			continue
		}
		for version, outsideStore := range versions {
			if outsideStore {
				extra = append(extra, "not in the lockfile: "+name+"@"+version)
			}
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return append(missing, extra...)
}

func uniqueEntries(entries []Entry) map[string]bool {
	out := map[string]bool{}
	for _, e := range entries {
		out[e.Name+"@"+e.Version] = true
	}
	return out
}

func uniqueInstalled(found []installed) map[string]bool {
	out := map[string]bool{}
	for _, f := range found {
		out[f.name+"@"+f.version] = true
	}
	return out
}
