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
	lf.markRequired(roots)
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
		pk, problems, err := listPackages(dir, rel, exclude, true)
		if err != nil {
			return Report{}, err
		}
		found = append(found, pk...)
		r.Problems = append(r.Problems, problems...)
		lp, err := checkLinks(o, rel, exclude)
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

// projectRoots reads the dependencies each package folder that owns a
// modules directory declares (the project root, and each workspace), as the
// target checkout declares them: the tree is checked for the project it will
// serve, and a staged copy carries no manifest of its own.
func projectRoots(format, project string, modules []string) ([]Root, error) {
	var roots []Root
	for _, rel := range modules {
		raw, err := os.ReadFile(filepath.Join(project, filepath.Dir(rel), "package.json"))
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
			return nil, fmt.Errorf("%s: %v", filepath.Join(filepath.Dir(rel), "package.json"), err)
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

// storeDirs hold the real package folders of isolated layouts
// (node_modules/.pnpm/<id>/node_modules/<name>, and bun's .bun likewise).
var storeDirs = map[string]bool{".pnpm": true, ".bun": true}

func listPackages(dir, rel string, exclude map[string]bool, top bool) ([]installed, []string, error) {
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
		if top && exclude[name] {
			continue
		}
		switch {
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
				pk, pr, err := listPackages(nm, filepath.Join(rel, name, id.Name(), "node_modules"), nil, false)
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
				if err := add(readPackage(filepath.Join(dir, name, s.Name()), filepath.Join(rel, name, s.Name()), s)); err != nil {
					return nil, nil, err
				}
			}
		default:
			if err := add(readPackage(filepath.Join(dir, name), filepath.Join(rel, name), e)); err != nil {
				return nil, nil, err
			}
		}
	}
	return out, problems, nil
}

func readPackage(dir, rel string, e fs.DirEntry) ([]installed, []string, error) {
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
		Name    string          `json:"name"`
		Version string          `json:"version"`
		Bundle  json.RawMessage `json:"bundleDependencies"`
		Bundled json.RawMessage `json:"bundledDependencies"`
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
	// not lockfile entries for every manager: they belong to the package.
	if bundles(pj.Bundle) || bundles(pj.Bundled) {
		return out, nil, nil
	}
	nested := filepath.Join(dir, "node_modules")
	if fi, err := os.Lstat(nested); err == nil && fi.IsDir() {
		pk, pr, err := listPackages(nested, filepath.Join(rel, "node_modules"), nil, false)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, pk...)
		return out, pr, nil
	}
	return out, nil, nil
}

func bundles(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	return s != "" && s != "null" && s != "false" && s != "[]" && s != "{}"
}

// checkLinks verifies every symlink under one modules directory as it will
// sit in the target: inside a copied modules directory it travels with the
// copy; inside the project (a workspace package) it must exist there and
// stay there physically; anything else would dangle or reach outside.
func checkLinks(o Options, rel string, exclude map[string]bool) ([]string, error) {
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
			// A link to a system path (node-gyp's build/node_gyp_bins/python3
			// -> /usr/bin/python3) resolves the same in every checkout; one
			// into either checkout would share the source's files.
			if within(dest, o.Source) || within(dest, o.Target) || within(dest, sourceReal) || within(dest, targetReal) {
				problems = append(problems, fmt.Sprintf("symlink %s -> %s is absolute and points into a checkout", where, dest))
			}
			return nil
		}
		logical := filepath.Join(o.Target, filepath.Dir(where), dest)
		if inModules(logical) {
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

func within(p, dir string) bool {
	p, dir = filepath.Clean(p), filepath.Clean(dir)
	return p == dir || strings.HasPrefix(p, dir+string(filepath.Separator))
}

// looseVersion: a lockfile version that is not a registry version (a git
// commit, a tarball URL) is matched by package name only.
func looseVersion(v string) bool {
	return v == "" || strings.ContainsAny(v, ":/#")
}

func compare(entries []Entry, found []installed) []string {
	expected := map[string]bool{} // name@version -> required
	loose := map[string]bool{}    // names with a non-registry entry
	names := map[string]bool{}
	for _, e := range entries {
		key := e.Name + "@" + e.Version
		expected[key] = expected[key] || !e.Optional
		names[e.Name] = true
		if looseVersion(e.Version) {
			loose[e.Name] = true
		}
	}
	have := map[string]bool{} // name@version -> outside a virtual store
	haveName := map[string]bool{}
	for _, f := range found {
		key := f.name + "@" + f.version
		have[key] = have[key] || !f.store
		haveName[f.name] = true
	}
	var missing, extra []string
	for key, required := range expected {
		name := key[:strings.LastIndex(key, "@")]
		if _, ok := have[key]; !required || ok || loose[name] && haveName[name] {
			continue
		}
		missing = append(missing, "missing "+key)
	}
	for key, outsideStore := range have {
		if !outsideStore {
			continue
		}
		name := key[:strings.LastIndex(key, "@")]
		if _, ok := expected[key]; ok || names[name] && (loose[name] || looseVersion(key[len(name)+1:])) {
			continue
		}
		extra = append(extra, "not in the lockfile: "+key)
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
