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
//     implicit native build: a binding.gyp, no install and no preinstall script, and gypfile not false, on npm 11.20.0 and 12.2.1);
//   - the judged lockfile: `hasInstallScript`, which is all there is when no tree was published (--dry-run, --package-lock-only).
//
// The tree wins where both exist: npm's own install trusts a lockfile that says "no scripts" over what is on disk (measured: a
// lockfile without the flag made `npm ci` skip an install script that `npm rebuild` would run), so a package with scripts on disk that
// its lockfile entry does not declare is listed and marked.
const (
	ScriptsSource = "tree"
	ScriptsLock   = "lockfile"

	scriptsMaxPrevious = 64 << 20
	scriptsMaxLock     = 256 << 20
)

// ScriptPackage is one installed package with install-time scripts.
type ScriptPackage struct {
	Path    string `json:"path"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Host    string `json:"host,omitempty"` // name@version of the package that bundles it, for a bundled member
	// RebuildPath is the install path `npm rebuild` is given for it: its own, or for a bundled member its outermost host's (measured: a
	// bundled member is rebuilt through the host's path, also when the host has no script, and not by its own path).
	RebuildPath string   `json:"rebuild_path"`
	Events      []string `json:"events"` // of preinstall, install, postinstall, in npm's order (tree source only)
	Native      bool     `json:"native"` // the implicit native build
	// Declared is what the lockfile entry says (hasInstallScript: true); false next to Events or Native is a disagreement.
	Declared bool `json:"declared"`
	// Unread: the tree has the directory and its package.json cannot be read as one plain JSON object, so nothing can be said about it.
	Unread bool `json:"unread,omitempty"`
}

// RootScripts is the project's own install-time scripts (the manifest the lane published).
type RootScripts struct {
	Events []string `json:"events"` // of the seven npm runs on a bare install, in npm's order
	Native bool     `json:"native"`
}

// ScriptsReport is the document `safe-core project-scripts` prints.
type ScriptsReport struct {
	SchemaVersion int             `json:"schema_version"`
	Source        string          `json:"source"` // tree or lockfile
	Previous      string          `json:"previous"`
	Total         int             `json:"total"`
	Packages      []ScriptPackage `json:"packages"`
	Root          *RootScripts    `json:"root,omitempty"`
}

// ScriptsRequest is what is read.
type ScriptsRequest struct {
	Lock         []byte
	TreeRoot     string // the published node_modules directory; "" reads the lockfile alone
	Previous     []byte // the previous tree's hidden lockfile, nil when there was none
	All          bool   // every package is introduced (npm ci builds a whole new tree)
	RootManifest []byte // nil: the project's own scripts are not asked for
	RootDir      string
	Limit        int
}

var rootEvents = []string{"preinstall", "install", "postinstall", "prepublish", "preprepare", "prepare", "postprepare"}
var packageEvents = []string{"preinstall", "install", "postinstall"}

// ReadScripts builds the report.
func ReadScripts(req ScriptsRequest) (ScriptsReport, error) {
	report := ScriptsReport{SchemaVersion: 1, Source: ScriptsLock, Previous: "none", Packages: []ScriptPackage{}}
	if req.TreeRoot != "" {
		report.Source = ScriptsSource
	}
	lock, err := parseJudgedLockfile(req.Lock, false)
	if err != nil {
		return report, err
	}
	var previous *judgedLock
	switch {
	case req.All:
		report.Previous = "ignored (every package is new in a tree built by ci)"
	case req.Previous == nil:
		report.Previous = "none"
	default:
		// the previous tree's own record; anything unreadable about it makes every package new (the larger report, never the smaller)
		if prev, perr := parseJudgedLockfile(req.Previous, true); prev != nil && (perr == nil || errors.Is(perr, ErrLinkEntries)) {
			previous, report.Previous = prev, "read"
		} else {
			report.Previous = "unreadable"
		}
	}
	for _, key := range lock.paths {
		entry := lock.entries[key]
		if previous != nil {
			if old, ok := previous.entries[key]; ok && old.Version == entry.Version && old.Resolved == entry.Resolved && old.Integrity == entry.Integrity {
				continue
			}
		}
		pkg := ScriptPackage{Path: key, Name: packageNameOfPath(key), Version: printableVersion(entry.Version), Events: []string{},
			Declared: strings.TrimSpace(string(entry.HasInstallScript)) == "true"}
		pkg.RebuildPath = key
		if entry.InBundle {
			if host := parentEntry(key); host != "" {
				hostVersion := "?"
				if h, ok := lock.entries[host]; ok {
					hostVersion = printableVersion(h.Version)
				}
				pkg.Host = packageNameOfPath(host) + "@" + hostVersion
				outer := host
				for {
					e, ok := lock.entries[outer]
					if !ok || !e.InBundle || parentEntry(outer) == "" {
						break
					}
					outer = parentEntry(outer)
				}
				pkg.RebuildPath = outer
			}
		}
		if req.TreeRoot == "" {
			if !pkg.Declared {
				continue
			}
			report.Packages = append(report.Packages, pkg)
			continue
		}
		dir, state := chainDir(req.TreeRoot, key)
		if state == chainAbsent {
			continue // not installed (omitted, or another platform's): nothing to say about it
		}
		if state == chainUnusable {
			pkg.Unread = true
			report.Packages = append(report.Packages, pkg)
			continue
		}
		events, native, rerr := packageScripts(dir)
		if rerr != nil {
			pkg.Unread = true
			report.Packages = append(report.Packages, pkg)
			continue
		}
		if len(events) == 0 && !native {
			continue
		}
		pkg.Native = native
		if events != nil {
			pkg.Events = events
		}
		report.Packages = append(report.Packages, pkg)
	}
	sort.Slice(report.Packages, func(i, j int) bool { return report.Packages[i].Path < report.Packages[j].Path })
	report.Total = len(report.Packages)
	if req.Limit > 0 && len(report.Packages) > req.Limit {
		report.Packages = report.Packages[:req.Limit]
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
	_, err := os.Lstat(filepath.Join(dir, "binding.gyp"))
	return err == nil
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
		}
	}
	if manifestFile != "" {
		if req.RootManifest, err = readFileNoFollow(manifestFile, maxManifestBytes); err != nil {
			return ScriptsReport{}, fmt.Errorf("package.json: %w", err)
		}
	}
	return ReadScripts(req)
}
