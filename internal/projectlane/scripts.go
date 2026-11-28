package projectlane

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/superbiche/safe/internal/strictjson"
)

// The scripts report (ticket 1638). The lane runs no lifecycle script; this reads, from DATA only, what a command put in the project
// that has install-time scripts, so that the operator is told which ones did not run. Two sources, never npm's messages and never a
// question to npm:
//
//   - the published tree: facts read from each package's own files, a preinstall, install or postinstall script in its package.json and
//     a binding.gyp that is a file as npm sees it (a regular file, a link to one included; a directory of that name is not);
//   - the judged lockfile: `hasInstallScript`, which is all there is when no tree was published (--dry-run, --package-lock-only).
//
// The reader states facts and nothing else. What npm does with them is not its business and no rule here predicts it: not whether a
// binding.gyp is built (gypfile, the scripts beside it), not whether a script runs when the lockfile entry does not declare it, not
// which package a command would introduce under a selection. Every package whose own files hold one of the facts is listed, with
// whether its lockfile entry declares scripts as one more fact. A package whose files cannot be read is listed apart as unread: nothing
// is said about it. The measures that the report's sentences still rest on (what `npm rebuild <path>` and `npm run <event>
// --ignore-scripts` do, on npm 11.20.0 and 12.2.1) are held by the live suite, tests/live/project_lane_no_scripts.sh.
const (
	ScriptsSource = "tree"
	ScriptsLock   = "lockfile"

	scriptsMaxPrevious = 64 << 20
	scriptsMaxLock     = 256 << 20
)

// ScriptPackage is one installed package whose own files hold install-time scripts or a binding.gyp, or that could not be read.
type ScriptPackage struct {
	Path    string `json:"path"`
	Name    string `json:"name"`
	Version string `json:"version"`
	// Host is name@version of the OUTERMOST package that is not itself bundled and supplies the bytes of a bundled member: the artifact
	// that is introduced when the member is, and the one whose install path `npm rebuild` is given (measured: a bundled member is
	// rebuilt through its host's path, also when the host has no script, and not by its own path).
	Host        string   `json:"host,omitempty"`
	RebuildPath string   `json:"rebuild_path"`
	Events      []string `json:"events"`   // of preinstall, install, postinstall, in npm's order, as the package.json holds them (tree source only)
	Gyp         bool     `json:"gyp"`      // a binding.gyp file is there (tree source only)
	Declared    bool     `json:"declared"` // the lockfile entry says hasInstallScript: true
}

// RootScripts is the project's own install-time scripts (the manifest the lane published) and whether a binding.gyp file is in it.
type RootScripts struct {
	Events []string `json:"events"` // of the seven npm runs on a bare install, in npm's order
	Gyp    bool     `json:"gyp"`
}

// ScriptsReport is the document `safe-core project-scripts` prints (schema 3). Packages are those whose own files (or, without a tree,
// whose lockfile entry) hold the facts above; Unread are those whose directory or package.json could not be read. Each list is cut at
// the request's limit and its Total is the true count.
type ScriptsReport struct {
	SchemaVersion int             `json:"schema_version"`
	Source        string          `json:"source"`   // tree or lockfile
	Previous      string          `json:"previous"` // read, none, or unreadable (every package is then counted as introduced)
	Total         int             `json:"total"`
	Packages      []ScriptPackage `json:"packages"`
	UnreadTotal   int             `json:"unread_total"`
	Unread        []ScriptPackage `json:"unread"`
	Root          *RootScripts    `json:"root,omitempty"`
}

// ScriptsRequest is what is read.
type ScriptsRequest struct {
	Lock     []byte
	TreeRoot string // the published node_modules directory; "" reads the lockfile alone
	// Previous is the previous tree's hidden lockfile. nil: there was none, every package is introduced (so for `ci`, which builds a
	// whole new tree, the caller gives none). PreviousUnreadable: there was one that could not be read; every package is introduced
	// and the report says why.
	Previous           []byte
	PreviousUnreadable bool
	RootManifest       []byte // nil: the project's own scripts are not asked for
	RootDir            string
	Limit              int
}

var rootEvents = []string{"preinstall", "install", "postinstall", "prepublish", "preprepare", "prepare", "postprepare"}
var packageEvents = []string{"preinstall", "install", "postinstall"}

// ReadScripts builds the report.
func ReadScripts(req ScriptsRequest) (ScriptsReport, error) {
	report := ScriptsReport{SchemaVersion: 3, Source: ScriptsLock, Previous: "none", Packages: []ScriptPackage{}, Unread: []ScriptPackage{}}
	if req.TreeRoot != "" {
		report.Source = ScriptsSource
	}
	lock, err := parseJudgedLockfile(req.Lock, false)
	if err != nil {
		return report, err
	}
	var previous *judgedLock
	switch {
	case req.PreviousUnreadable:
		report.Previous = "unreadable"
	case req.Previous == nil:
		report.Previous = "none"
	default:
		// the previous tree's own record; anything unreadable about it makes every package new (the larger report, never the smaller)
		// and is said
		if prev, perr := parseJudgedLockfile(req.Previous, true); prev != nil && (perr == nil || errors.Is(perr, ErrLinkEntries)) {
			previous, report.Previous = prev, "read"
		} else {
			report.Previous = "unreadable"
		}
	}
	for _, key := range lock.paths {
		entry := lock.entries[key]
		if !introduced(lock, previous, key) {
			continue
		}
		pkg := ScriptPackage{Path: key, Name: packageNameOfPath(key), Version: printableVersion(entry.Version), Events: []string{}, RebuildPath: key,
			Declared: strings.TrimSpace(string(entry.HasInstallScript)) == "true"}
		if outer, bundled := outermostHost(lock, key); bundled {
			pkg.RebuildPath = outer
			hostVersion := "?"
			if h, ok := lock.entries[outer]; ok {
				hostVersion = printableVersion(h.Version)
			}
			pkg.Host = packageNameOfPath(outer) + "@" + hostVersion
		}
		if req.TreeRoot == "" {
			if pkg.Declared {
				report.Packages = append(report.Packages, pkg)
			}
			continue
		}
		dir, state := chainDir(req.TreeRoot, key)
		if state == chainAbsent {
			continue // not installed (omitted, or another platform's): nothing to say about it
		}
		if state == chainUnusable {
			report.Unread = append(report.Unread, pkg)
			continue
		}
		events, gyp, rerr := packageFacts(dir)
		if rerr != nil {
			report.Unread = append(report.Unread, pkg)
			continue
		}
		if len(events) == 0 && !gyp {
			continue
		}
		pkg.Gyp = gyp
		if events != nil {
			pkg.Events = events
		}
		report.Packages = append(report.Packages, pkg)
	}
	for _, group := range []*[]ScriptPackage{&report.Packages, &report.Unread} {
		sort.Slice(*group, func(i, j int) bool { return (*group)[i].Path < (*group)[j].Path })
	}
	report.Total, report.UnreadTotal = len(report.Packages), len(report.Unread)
	if req.Limit > 0 {
		for _, group := range []*[]ScriptPackage{&report.Packages, &report.Unread} {
			if len(*group) > req.Limit {
				*group = (*group)[:req.Limit]
			}
		}
	}
	if req.RootManifest != nil {
		root, rerr := rootScripts(req.RootManifest, req.RootDir)
		if rerr != nil {
			return report, rerr
		}
		report.Root = &root
	}
	return report, nil
}

// outermostHost returns the install path of the artifact that supplies the bytes of a bundled member: the first ancestor entry that is
// not itself bundled. A member whose entry says it is bundled and has no ancestor entry has no host that can be named (false).
func outermostHost(lock *judgedLock, key string) (string, bool) {
	entry := lock.entries[key]
	if entry == nil || !entry.InBundle {
		return "", false
	}
	outer := parentEntry(key)
	if outer == "" {
		return "", false
	}
	for {
		e, ok := lock.entries[outer]
		if !ok || !e.InBundle || parentEntry(outer) == "" {
			return outer, true
		}
		outer = parentEntry(outer)
	}
}

// sameArtifact: an entry the previous tree's record has at the same path, with the same version, resolved location and integrity.
func sameArtifact(previous *judgedLock, key string, entry *lockEntry) bool {
	old, ok := previous.entries[key]
	return ok && old.Version == entry.Version && old.Resolved == entry.Resolved && old.Integrity == entry.Integrity
}

// introduced: the package at key is new or changed in the tree. A bundled entry has no resolved location and no integrity of its own:
// its bytes come from the tarball of its outermost host, so it is introduced when that host's artifact is, or when its own entry is new
// or changed. Without a previous record everything is introduced.
func introduced(lock *judgedLock, previous *judgedLock, key string) bool {
	if previous == nil {
		return true
	}
	if !sameArtifact(previous, key, lock.entries[key]) {
		return true
	}
	if outer, bundled := outermostHost(lock, key); bundled {
		host, ok := lock.entries[outer]
		return !ok || !sameArtifact(previous, outer, host)
	}
	return false
}

// printableVersion keeps a version that reads as one by the lane's own grammar (the one it admits an entry by: a version the lane installed
// is never shown as unreadable) and shows anything else as unreadable: the lockfile is untrusted text.
func printableVersion(v string) string {
	if validVersion(v) {
		return v
	}
	return "?"
}

type chainResult int

const (
	chainDirectory chainResult = iota
	chainAbsent
	chainUnusable
)

// chainDir resolves an install path below the held node_modules directory one real directory at a time (no link, no file in a
// directory's place); the first absent component makes the package absent, any other surprise makes it unusable.
func chainDir(treeRoot, key string) (string, chainResult) {
	rest, ok := strings.CutPrefix(key, "node_modules/")
	if !ok {
		return "", chainUnusable
	}
	dir := treeRoot
	parts := strings.Split(rest, "/")
	for _, part := range parts {
		// "node_modules" components are real directories like the rest; scoped names are two components
		dir = filepath.Join(dir, part)
		info, err := os.Lstat(dir)
		switch {
		case errors.Is(err, os.ErrNotExist):
			return "", chainAbsent
		case err != nil:
			return "", chainUnusable
		case info.Mode()&os.ModeSymlink != 0 || !info.IsDir():
			return "", chainUnusable
		}
	}
	return dir, chainDirectory
}

// packageFacts reads a package directory: which of preinstall, install and postinstall its package.json holds (a non-empty string), and
// whether a binding.gyp file is there. No more: what npm makes of them is not decided here.
func packageFacts(dir string) (events []string, gyp bool, err error) {
	raw, err := readFileNoFollow(filepath.Join(dir, "package.json"), maxManifestBytes)
	if err != nil {
		return nil, false, err
	}
	members, err := strictjson.ParseObject(raw)
	if err != nil {
		return nil, false, err
	}
	if err := strictjson.RejectVariants(members, "scripts"); err != nil {
		return nil, false, err
	}
	have, err := scriptNames(members["scripts"])
	if err != nil {
		return nil, false, err
	}
	for _, name := range packageEvents {
		if have[name] {
			events = append(events, name)
		}
	}
	return events, bindingGyp(dir), nil
}

func scriptNames(raw json.RawMessage) (map[string]bool, error) {
	have := map[string]bool{}
	if len(raw) == 0 || string(raw) == "null" {
		return have, nil
	}
	scripts, err := strictjson.ParseObject(raw)
	if err != nil {
		return nil, err
	}
	for name, value := range scripts {
		var text string
		if json.Unmarshal(value, &text) == nil && text != "" {
			have[name] = true
		}
	}
	return have, nil
}

// bindingGyp: a binding.gyp as npm sees it, a regular file (a link to one included: Stat follows it); a directory of that name is not.
func bindingGyp(dir string) bool {
	info, err := os.Stat(filepath.Join(dir, "binding.gyp"))
	return err == nil && info.Mode().IsRegular()
}

func rootScripts(manifest []byte, dir string) (RootScripts, error) {
	root := RootScripts{Events: []string{}}
	members, err := strictjson.ParseObject(manifest)
	if err != nil {
		return root, fmt.Errorf("package.json: %w", err)
	}
	if err := strictjson.RejectVariants(members, "scripts"); err != nil {
		return root, fmt.Errorf("package.json: %w", err)
	}
	have, err := scriptNames(members["scripts"])
	if err != nil {
		return root, fmt.Errorf("package.json scripts: %w", err)
	}
	for _, name := range rootEvents {
		if have[name] {
			root.Events = append(root.Events, name)
		}
	}
	root.Gyp = bindingGyp(dir)
	return root, nil
}

// ReadScriptsFiles is ReadScripts for files: the lockfile, the previous tree's hidden lockfile ("" for none) and the manifest ("" for
// none) are read with a bound, never followed through a link.
func ReadScriptsFiles(lockFile, previousFile, manifestFile string, req ScriptsRequest) (ScriptsReport, error) {
	var err error
	if req.Lock, err = readFileNoFollow(lockFile, scriptsMaxLock); err != nil {
		return ScriptsReport{}, fmt.Errorf("lockfile: %w", err)
	}
	if previousFile != "" {
		if raw, perr := readFileNoFollow(previousFile, scriptsMaxPrevious); perr == nil {
			req.Previous = raw
		} else {
			req.PreviousUnreadable = true
		}
	}
	if manifestFile != "" {
		if req.RootManifest, err = readFileNoFollow(manifestFile, maxManifestBytes); err != nil {
			return ScriptsReport{}, fmt.Errorf("package.json: %w", err)
		}
	}
	return ReadScripts(req)
}
