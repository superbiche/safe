package projectlane

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/superbiche/safe/internal/strictjson"
)

// The scripts report (ticket 1638). The lane runs no lifecycle script; this reads, from DATA only, what a command put in the project
// that has install-time scripts, so that the operator is told which ones did not run. Two sources, never npm's messages and never a
// question to npm:
//
//   - the published tree: each package's own package.json (a preinstall, install or postinstall script) and binding.gyp (npm's
//     implicit native build: a binding.gyp FILE, no install and no preinstall script, and gypfile not false, on npm 11.20.0 and 12.2.1);
//   - the judged lockfile: `hasInstallScript`, which is all there is when no tree was published (--dry-run, --package-lock-only).
//
// Where the tree has scripts that the lockfile entry does not declare, npm itself does not run them the way it runs a declared one
// (measured on npm 11.20.0 and 12.2.1, on the tree the binder publishes, with the flag absent): `npm ci` with scripts on runs NOTHING
// for a package whose only install-time script is a script, runs the implicit native build of a package that has a binding.gyp, and
// for a package with a postinstall AND a binding.gyp runs only the native build; `npm rebuild <path>` with scripts on likewise runs
// nothing for the first, the native build for the second, and the native build and the script for the third. Such a package is
// reported apart ("undeclared"), with what npm does about it, and its path is in the printed command only when `npm rebuild` runs
// something for it. A package whose files cannot be read is reported apart ("unread"): nothing is said about its scripts and it has
// no command.
const (
	ScriptsSource = "tree"
	ScriptsLock   = "lockfile"

	scriptsMaxPrevious = 64 << 20
	scriptsMaxLock     = 256 << 20
)

// ScriptPackage is one installed package with install-time scripts, or one that could not be read.
type ScriptPackage struct {
	Path    string `json:"path"`
	Name    string `json:"name"`
	Version string `json:"version"`
	// Host is name@version of the OUTERMOST package that is not itself bundled and supplies the bytes of a bundled member: the artifact
	// that is introduced when the member is, and the one whose install path `npm rebuild` is given (measured: a bundled member is
	// rebuilt through its host's path, also when the host has no script, and not by its own path).
	Host        string   `json:"host,omitempty"`
	RebuildPath string   `json:"rebuild_path"`
	Events      []string `json:"events"` // of preinstall, install, postinstall, in npm's order (tree source only)
	Native      bool     `json:"native"` // the implicit native build
}

// RootScripts is the project's own install-time scripts (the manifest the lane published).
type RootScripts struct {
	Events []string `json:"events"` // of the seven npm runs on a bare install, in npm's order
	Native bool     `json:"native"`
}

// ScriptsReport is the document `safe-core project-scripts` prints (schema 2). Packages are those whose lockfile entry declares
// install scripts and whose files (or, without a tree, whose entry) have them; Undeclared are those whose files have scripts that
// their entry does not declare; Unread are those whose directory or package.json could not be read. Each list is cut at the request's
// limit and its Total is the true count.
type ScriptsReport struct {
	SchemaVersion   int             `json:"schema_version"`
	Source          string          `json:"source"`   // tree or lockfile
	Previous        string          `json:"previous"` // read, none, or unreadable (every package is then counted as introduced)
	Total           int             `json:"total"`
	Packages        []ScriptPackage `json:"packages"`
	UndeclaredTotal int             `json:"undeclared_total"`
	Undeclared      []ScriptPackage `json:"undeclared"`
	UnreadTotal     int             `json:"unread_total"`
	Unread          []ScriptPackage `json:"unread"`
	Root            *RootScripts    `json:"root,omitempty"`
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
	report := ScriptsReport{SchemaVersion: 2, Source: ScriptsLock, Previous: "none", Packages: []ScriptPackage{}, Undeclared: []ScriptPackage{}, Unread: []ScriptPackage{}}
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
		pkg := ScriptPackage{Path: key, Name: packageNameOfPath(key), Version: printableVersion(entry.Version), Events: []string{}, RebuildPath: key}
		if outer, bundled := outermostHost(lock, key); bundled {
			pkg.RebuildPath = outer
			hostVersion := "?"
			if h, ok := lock.entries[outer]; ok {
				hostVersion = printableVersion(h.Version)
			}
			pkg.Host = packageNameOfPath(outer) + "@" + hostVersion
		}
		declared := strings.TrimSpace(string(entry.HasInstallScript)) == "true"
		if req.TreeRoot == "" {
			if declared {
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
		events, native, rerr := packageScripts(dir)
		if rerr != nil {
			report.Unread = append(report.Unread, pkg)
			continue
		}
		if len(events) == 0 && !native {
			continue
		}
		pkg.Native = native
		if events != nil {
			pkg.Events = events
		}
		if declared {
			report.Packages = append(report.Packages, pkg)
		} else {
			report.Undeclared = append(report.Undeclared, pkg)
		}
	}
	for _, group := range []*[]ScriptPackage{&report.Packages, &report.Undeclared, &report.Unread} {
		sort.Slice(*group, func(i, j int) bool { return (*group)[i].Path < (*group)[j].Path })
	}
	report.Total, report.UndeclaredTotal, report.UnreadTotal = len(report.Packages), len(report.Undeclared), len(report.Unread)
	if req.Limit > 0 {
		for _, group := range []*[]ScriptPackage{&report.Packages, &report.Undeclared, &report.Unread} {
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

var plainVersion = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$`)

// printableVersion keeps a version that reads as one and shows anything else as unreadable: the lockfile is untrusted text.
func printableVersion(v string) string {
	if plainVersion.MatchString(v) {
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

// packageScripts reads a package directory: which of preinstall, install and postinstall it declares, and whether npm would build it
// natively on its own.
func packageScripts(dir string) (events []string, native bool, err error) {
	raw, err := readFileNoFollow(filepath.Join(dir, "package.json"), maxManifestBytes)
	if err != nil {
		return nil, false, err
	}
	members, err := strictjson.ParseObject(raw)
	if err != nil {
		return nil, false, err
	}
	if err := strictjson.RejectVariants(members, "scripts", "gypfile"); err != nil {
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
	native = nativeBuild(dir, members, have)
	return events, native, nil
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

// nativeBuild is npm's implicit native build: a binding.gyp in the directory, no install and no preinstall script, and gypfile not
// false (measured on npm 11.20.0 and 12.2.1: postinstall alone still builds; preinstall alone, install alone and gypfile:false do not).
func nativeBuild(dir string, members map[string]json.RawMessage, have map[string]bool) bool {
	if have["install"] || have["preinstall"] {
		return false
	}
	if value, ok := members["gypfile"]; ok && strings.TrimSpace(string(value)) == "false" {
		return false
	}
	// as npm sees it: a regular file, a link to one included (Stat follows it); a directory of that name is no native build
	info, err := os.Stat(filepath.Join(dir, "binding.gyp"))
	return err == nil && info.Mode().IsRegular()
}

func rootScripts(manifest []byte, dir string) (RootScripts, error) {
	root := RootScripts{Events: []string{}}
	members, err := strictjson.ParseObject(manifest)
	if err != nil {
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
	root.Native = nativeBuild(dir, members, have)
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
