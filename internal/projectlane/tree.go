package projectlane

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/superbiche/safe/internal/strictjson"
)

// TreeSchema is the version of the tree verification document.
const TreeSchema = 1

// Tree problems. They are stable identifiers: the gate and the report name
// them.
const (
	// TreeMissing: a selected lockfile entry has no directory in the tree.
	TreeMissing = "missing"
	// TreeManifestMissing: the directory is there and holds no package.json. A
	// present directory without a manifest is broken, never absent.
	TreeManifestMissing = "manifest_missing"
	// TreeManifestUnusable: the manifest is not a regular file, cannot be read
	// or parsed, or repeats a member.
	TreeManifestUnusable = "manifest_unusable"
	TreeWrongName        = "wrong_name"
	TreeWrongVersion     = "wrong_version"
	// TreeWrongOrigin: npm's hidden lockfile records another resolved
	// location or hash than the judged lockfile.
	TreeWrongOrigin = "wrong_origin"
	// TreeSymlink: a symbolic link where the tree holds a directory or a
	// regular file. Nothing in the tree is followed through one.
	TreeSymlink = "symlink"
	// TreeNotADirectory: something that is not a directory where a package, a
	// scope or the tree root is expected.
	TreeNotADirectory = "not_a_directory"
	TreeUnreadable    = "unreadable"
	// TreeNotInLockfile: an entry of the tree the lockfile does not name.
	TreeNotInLockfile = "not_in_lockfile"
	// TreeHiddenNotAllowed: a hidden entry that is not one npm itself writes.
	TreeHiddenNotAllowed = "hidden_not_allowed"
	// TreePathOutside: a path that does not stay inside the tree: a lockfile
	// key that is not a node_modules chain of package names, or a link of
	// npm's bin directory that points elsewhere.
	TreePathOutside = "path_outside_tree"
	// TreeLockfileIncomplete: a lockfile entry that cannot be verified (no
	// version).
	TreeLockfileIncomplete = "lockfile_entry_incomplete"
	// TreeHiddenLockfileUnreadable and TreeHiddenLockfileInconsistent: npm's
	// own record of the tree (node_modules/.package-lock.json) is present and
	// cannot be read, or does not describe the tree the lockfile does.
	TreeHiddenLockfileUnreadable   = "hidden_lockfile_unreadable"
	TreeHiddenLockfileInconsistent = "hidden_lockfile_inconsistent"
)

// ErrLinkEntries is returned for a lockfile that carries link entries
// (workspace members, in-project links). Links are verified by a later ticket;
// until then a lockfile that has one is refused, never half-verified.
var ErrLinkEntries = errors.New("the lockfile carries link entries, which this verifier does not support")

// Selection is what the command that built the tree selected, as npm's
// effective configuration reports it: the dependency types it omits and the
// platform optional packages are matched against. The verifier derives nothing
// from the environment: a field left empty is not guessed, and what it would
// have deselected is then required to be present (an entry is absent only when
// the selection PROVABLY deselects it).
type Selection struct {
	// Omit is a subset of "dev", "optional", "peer".
	Omit []string `json:"omit"`
	// OS, CPU and Libc are npm's own spelling (linux, x64, glibc). Libc is
	// empty when the machine's C library is not known or not relevant.
	OS   string `json:"os"`
	CPU  string `json:"cpu"`
	Libc string `json:"libc"`
}

// Validate refuses a selection the verifier cannot interpret.
func (s Selection) Validate() error {
	seen := map[string]bool{}
	for _, kind := range s.Omit {
		switch kind {
		case "dev", "optional", "peer":
		default:
			return fmt.Errorf("omit %q is not one of dev, optional, peer", kind)
		}
		if seen[kind] {
			return fmt.Errorf("omit %q is given twice", kind)
		}
		seen[kind] = true
	}
	return nil
}

func (s Selection) omits(kind string) bool {
	for _, k := range s.Omit {
		if k == kind {
			return true
		}
	}
	return false
}

// normalized returns the selection with a sorted, non-nil omit list, as the
// document reports it.
func (s Selection) normalized() Selection {
	omit := append([]string{}, s.Omit...)
	sort.Strings(omit)
	s.Omit = omit
	return s
}

// TreeProblem is one finding of the verification.
type TreeProblem struct {
	Path    string `json:"path"`
	Problem string `json:"problem"`
	// Name and Version are what the lockfile names for the path (empty for an
	// entry the lockfile lacks); FoundName and FoundVersion what the tree holds.
	Name         string `json:"name"`
	Version      string `json:"version"`
	FoundName    string `json:"found_name"`
	FoundVersion string `json:"found_version"`
	Detail       string `json:"detail"`
}

// TreeReport is the verification document: Ok holds only when every selected
// entry is present under its name and version, nothing in the tree is absent
// from the lockfile, every absent entry is one the selection provably
// deselects, and npm's hidden lockfile, when present, describes the same tree.
type TreeReport struct {
	SchemaVersion int           `json:"schema_version"`
	Ok            bool          `json:"ok"`
	Selection     Selection     `json:"selection"`
	Checked       int           `json:"checked"`
	Absent        int           `json:"absent_deselected"`
	Problems      []TreeProblem `json:"problems"`
}

type lockEntry struct {
	Name        string          `json:"name"`
	Version     string          `json:"version"`
	Resolved    string          `json:"resolved"`
	Integrity   string          `json:"integrity"`
	Link        bool            `json:"link"`
	Dev         bool            `json:"dev"`
	Optional    bool            `json:"optional"`
	DevOptional bool            `json:"devOptional"`
	Peer        bool            `json:"peer"`
	OS          json.RawMessage `json:"os"`
	CPU         json.RawMessage `json:"cpu"`
	Libc        json.RawMessage `json:"libc"`

	path         string
	expectedName string
}

// judgedLock is a lockfile read for verification: the entries that stand for
// a directory of the tree, and the keys that cannot.
type judgedLock struct {
	entries map[string]*lockEntry
	paths   []string
	// outside lists the keys that are not a chain of node_modules/<package>
	// segments. They are never joined to a directory.
	outside []string
}

// ParseLockfile reads the lockfile a tree is verified against: strictly (one
// document, no repeated member), version 2 or 3. A lockfile with link entries
// is ErrLinkEntries.
func parseJudgedLockfile(raw []byte) (*judgedLock, error) {
	if err := strictjson.RejectRepeatedMembers(raw); err != nil {
		return nil, fmt.Errorf("lockfile: %w", err)
	}
	var document struct {
		LockfileVersion int                        `json:"lockfileVersion"`
		Packages        map[string]json.RawMessage `json:"packages"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("lockfile: %w", err)
	}
	if decoder.More() {
		return nil, errors.New("lockfile: more than one JSON document")
	}
	if document.LockfileVersion != 2 && document.LockfileVersion != 3 {
		return nil, fmt.Errorf("lockfile: lockfileVersion %d is not 2 or 3", document.LockfileVersion)
	}
	if document.Packages == nil {
		return nil, errors.New("lockfile: no packages member")
	}
	lock := &judgedLock{entries: map[string]*lockEntry{}}
	links := false
	for key, rawEntry := range document.Packages {
		trimmed := bytes.TrimSpace(rawEntry)
		if len(trimmed) == 0 || trimmed[0] != '{' {
			return nil, fmt.Errorf("lockfile: packages[%q] is not an object", key)
		}
		var entry lockEntry
		if err := json.Unmarshal(rawEntry, &entry); err != nil {
			return nil, fmt.Errorf("lockfile: packages[%q]: %w", key, err)
		}
		if entry.Link {
			links = true
		}
		if key == "" {
			continue
		}
		if !validTreeKey(key) {
			lock.outside = append(lock.outside, key)
			continue
		}
		entry.path = key
		entry.expectedName = entry.Name
		if entry.expectedName == "" {
			entry.expectedName = packageNameOfPath(key)
		}
		lock.entries[key] = &entry
		lock.paths = append(lock.paths, key)
	}
	sort.Strings(lock.paths)
	sort.Strings(lock.outside)
	if links {
		return lock, ErrLinkEntries
	}
	return lock, nil
}

// validTreeKey accepts exactly a chain node_modules/<package>[/node_modules/
// <package>]...: no empty, "." or ".." segment, no separator that is not a
// slash, no hidden or non-package name. A key that fails stays out of every
// filesystem join.
func validTreeKey(key string) bool {
	segments := strings.Split(key, "/")
	for i := 0; i < len(segments); {
		if segments[i] != "node_modules" {
			return false
		}
		i++
		if i >= len(segments) {
			return false
		}
		name := segments[i]
		i++
		if strings.HasPrefix(name, "@") {
			if i >= len(segments) {
				return false
			}
			name += "/" + segments[i]
			i++
		}
		if !validPackageName(name) {
			return false
		}
	}
	return true
}

func (e *lockEntry) deselected(sel Selection) bool {
	if e.Dev && sel.omits("dev") {
		return true
	}
	if e.Optional && sel.omits("optional") {
		return true
	}
	if e.DevOptional && sel.omits("dev") && sel.omits("optional") {
		return true
	}
	if e.Peer && sel.omits("peer") {
		return true
	}
	if e.Optional {
		// Platform deselection is provable only against a platform that was
		// stated: an empty field proves nothing, and the entry stays required.
		if sel.OS != "" && !constraintMatches(e.OS, sel.OS) ||
			sel.CPU != "" && !constraintMatches(e.CPU, sel.CPU) ||
			sel.Libc != "" && !constraintMatches(e.Libc, sel.Libc) {
			return true
		}
	}
	return false
}

func stringList(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var list []string
	if json.Unmarshal(raw, &list) == nil {
		return list
	}
	var one string
	if json.Unmarshal(raw, &one) == nil && one != "" {
		return []string{one}
	}
	return nil
}

// constraintMatches mirrors npm-install-checks: no constraint matches
// everything, a negated entry naming the value excludes it outright, a list
// with a positive entry needs one to name the value, a list of negations none
// of which names it matches. A constraint that cannot be read matches (nothing
// is deselected on a constraint the verifier does not understand).
func constraintMatches(raw json.RawMessage, value string) bool {
	list := stringList(raw)
	if len(list) == 0 || len(list) == 1 && list[0] == "any" {
		return true
	}
	negated, match := 0, false
	for _, item := range list {
		if strings.HasPrefix(item, "!") {
			negated++
			if value == strings.TrimPrefix(item, "!") {
				return false
			}
			continue
		}
		if item == value {
			match = true
		}
	}
	return match || negated == len(list)
}

const (
	maxManifestBytes       = 16 << 20
	maxHiddenLockfileBytes = 256 << 20
)

// VerifyTree checks that the node_modules tree directly below treeParent is
// the tree the lockfile describes (spec 1625, Binding), read WITHOUT following
// a symbolic link anywhere:
//
//   - every selected entry is present under its lockfile name and version;
//   - an entry is absent only when the selection provably deselects it (or
//     deselects an ancestor it lives in); a directory that is present without a
//     manifest is broken, not absent;
//   - the tree holds nothing the lockfile lacks, hidden entries included, apart
//     from what npm itself writes (node_modules/.package-lock.json and the
//     .bin directories, whose entries must be links that stay in the tree);
//   - no lockfile key leaves the tree, and none is joined to a path;
//   - npm's hidden lockfile, when present, is readable and records the tree the
//     lockfile describes (an unreadable or inconsistent one is a problem, not
//     a skip).
//
// An error is returned for a lockfile that cannot be read as an input
// (ErrLinkEntries included); everything about the tree is a problem in the
// report.
func VerifyTree(lockfile []byte, treeParent string, selection Selection) (TreeReport, error) {
	if err := selection.Validate(); err != nil {
		return TreeReport{}, fmt.Errorf("selection: %w", err)
	}
	lock, err := parseJudgedLockfile(lockfile)
	if err != nil {
		return TreeReport{}, err
	}
	info, err := os.Lstat(treeParent)
	if err != nil {
		return TreeReport{}, err
	}
	if !info.IsDir() {
		return TreeReport{}, fmt.Errorf("%q is not a directory", treeParent)
	}
	v := &verifier{root: treeParent, lock: lock, sel: selection, seen: map[string]bool{}, present: map[string]bool{}}
	report := TreeReport{SchemaVersion: TreeSchema, Selection: selection.normalized(), Problems: []TreeProblem{}}
	v.report = &report
	v.run()
	sort.SliceStable(report.Problems, func(i, j int) bool {
		a, b := report.Problems[i], report.Problems[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Problem < b.Problem
	})
	report.Ok = len(report.Problems) == 0
	return report, nil
}

type verifier struct {
	root    string
	lock    *judgedLock
	sel     Selection
	report  *TreeReport
	seen    map[string]bool // problem dedup
	present map[string]bool // entry paths found as directories
}

func (v *verifier) problem(p TreeProblem) {
	key := p.Path + "\x00" + p.Problem
	if v.seen[key] {
		return
	}
	v.seen[key] = true
	v.report.Problems = append(v.report.Problems, p)
}

func (v *verifier) abs(rel string) string {
	return filepath.Join(v.root, filepath.FromSlash(rel))
}

func (v *verifier) run() {
	for _, key := range v.lock.outside {
		v.problem(TreeProblem{Path: key, Problem: TreePathOutside, Detail: "lockfile key is not a chain of node_modules/<package> segments"})
	}
	rootState := v.rootState()
	if rootState == stateDirectory {
		for _, key := range v.lock.paths {
			v.checkEntry(v.lock.entries[key])
		}
		v.walk("node_modules")
		v.checkHiddenLockfile()
		return
	}
	if rootState == stateAbsent {
		for _, key := range v.lock.paths {
			entry := v.lock.entries[key]
			if entry.deselected(v.sel) || v.ancestorDeselected(key) {
				v.report.Absent++
				continue
			}
			v.problem(TreeProblem{Path: key, Problem: TreeMissing, Name: entry.expectedName, Version: entry.Version})
		}
	}
	// A root that is a link, a file or unreadable has been reported; nothing
	// below it is read.
}

type pathState int

const (
	stateAbsent pathState = iota
	stateDirectory
	stateReported // a problem was recorded for this path or an ancestor
)

// rootState inspects node_modules itself, reporting a link, a file or an
// unreadable root.
func (v *verifier) rootState() pathState {
	return v.lstatDir("node_modules", false)
}

// lstatDir classifies one path without following a link. A path that is not a
// real directory is reported (unless quiet) under its own name.
func (v *verifier) lstatDir(rel string, quiet bool) pathState {
	info, err := os.Lstat(v.abs(rel))
	switch {
	case errors.Is(err, os.ErrNotExist):
		return stateAbsent
	case err != nil:
		if !quiet {
			v.problem(TreeProblem{Path: rel, Problem: TreeUnreadable, Detail: err.Error()})
		}
		return stateReported
	case info.Mode()&os.ModeSymlink != 0:
		if !quiet {
			v.problem(TreeProblem{Path: rel, Problem: TreeSymlink, Detail: "a symbolic link where a directory is expected"})
		}
		return stateReported
	case !info.IsDir():
		if !quiet {
			v.problem(TreeProblem{Path: rel, Problem: TreeNotADirectory, Detail: "not a directory"})
		}
		return stateReported
	}
	return stateDirectory
}

// chain classifies an entry's path component by component from the tree root,
// so that nothing is read through a link or a file standing in for a
// directory. The first component that is absent makes the whole path absent;
// the first that is a link, a file or unreadable is reported.
func (v *verifier) chain(rel string) pathState {
	parts := strings.Split(rel, "/")
	prefix := ""
	for i, part := range parts {
		if prefix == "" {
			prefix = part
		} else {
			prefix += "/" + part
		}
		if i == 0 {
			continue // node_modules: classified by rootState
		}
		if state := v.lstatDir(prefix, false); state != stateDirectory {
			return state
		}
	}
	return stateDirectory
}

// ancestorDeselected reports whether an entry the path lives inside is
// deselected: what is absent below a deselected, absent package is deselected
// with it.
func (v *verifier) ancestorDeselected(key string) bool {
	for parent := parentEntry(key); parent != ""; parent = parentEntry(parent) {
		if entry, ok := v.lock.entries[parent]; ok && entry.deselected(v.sel) {
			return true
		}
	}
	return false
}

// parentEntry returns the install path of the package whose tree holds the
// given one, or "".
func parentEntry(key string) string {
	const marker = "/node_modules/"
	if i := strings.LastIndex(key, marker); i >= 0 {
		return key[:i]
	}
	return ""
}

func (v *verifier) checkEntry(entry *lockEntry) {
	key := entry.path
	base := TreeProblem{Path: key, Name: entry.expectedName, Version: entry.Version}
	deselected := entry.deselected(v.sel) || v.ancestorDeselected(key)
	state := v.chain(key)
	switch state {
	case stateAbsent:
		if deselected {
			v.report.Absent++
			return
		}
		missing := base
		missing.Problem = TreeMissing
		v.problem(missing)
		return
	case stateReported:
		return
	}
	// Present, deselected or not: it is checked like any entry. Whatever is
	// there is lockfile-named content and must be what the lockfile says.
	v.report.Checked++
	v.present[key] = true
	if entry.Version == "" {
		incomplete := base
		incomplete.Problem = TreeLockfileIncomplete
		incomplete.Detail = "the lockfile entry has no version"
		v.problem(incomplete)
		return
	}
	name, version, problem, detail := v.readManifest(key)
	if problem != "" {
		failed := base
		failed.Problem, failed.Detail = problem, detail
		v.problem(failed)
		return
	}
	base.FoundName, base.FoundVersion = name, version
	if name != entry.expectedName {
		base.Problem = TreeWrongName
		v.problem(base)
		return
	}
	if version != entry.Version {
		base.Problem = TreeWrongVersion
		v.problem(base)
	}
}

// readManifest reads the package.json of a package directory the chain walk
// found real. The manifest is a regular file read without following a link.
func (v *verifier) readManifest(dir string) (name, version, problem, detail string) {
	manifest := dir + "/package.json"
	info, err := os.Lstat(v.abs(manifest))
	if errors.Is(err, os.ErrNotExist) {
		return "", "", TreeManifestMissing, "the directory has no package.json"
	}
	if err != nil {
		return "", "", TreeUnreadable, err.Error()
	}
	if !info.Mode().IsRegular() {
		return "", "", TreeManifestUnusable, "package.json is not a regular file"
	}
	raw, err := readFileNoFollow(v.abs(manifest), maxManifestBytes)
	if err != nil {
		return "", "", TreeManifestUnusable, err.Error()
	}
	if err := strictjson.RejectRepeatedMembers(raw); err != nil {
		return "", "", TreeManifestUnusable, err.Error()
	}
	var declared struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(raw, &declared); err != nil {
		return "", "", TreeManifestUnusable, err.Error()
	}
	return declared.Name, declared.Version, "", ""
}

// readFileNoFollow reads a regular file of at most limit bytes, refusing a
// symbolic link at the final component.
func readFileNoFollow(name string, limit int64) ([]byte, error) {
	file, err := os.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", name)
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", name, limit)
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", name, limit)
	}
	return raw, nil
}

// walk reports what a node_modules directory holds that the lockfile does not
// name. It descends only into directories it found real, never through a link.
func (v *verifier) walk(dir string) {
	items, err := os.ReadDir(v.abs(dir))
	if err != nil {
		v.problem(TreeProblem{Path: dir, Problem: TreeUnreadable, Detail: err.Error()})
		return
	}
	for _, item := range items {
		name := item.Name()
		rel := dir + "/" + name
		switch {
		case strings.HasPrefix(name, "."):
			v.hidden(dir, name, item)
		case strings.HasPrefix(name, "@"):
			v.scope(rel, item)
		default:
			v.packageDir(rel, item)
		}
	}
}

// hidden admits what npm itself writes: the root's hidden lockfile (checked
// on its own) and the .bin directories.
func (v *verifier) hidden(dir, name string, item os.DirEntry) {
	rel := dir + "/" + name
	switch {
	case name == ".package-lock.json" && dir == "node_modules" && item.Type().IsRegular():
		return
	case name == ".bin" && item.IsDir():
		v.checkBin(rel)
		return
	}
	v.problem(TreeProblem{Path: rel, Problem: TreeHiddenNotAllowed, Detail: "a hidden entry npm does not write"})
}

// checkBin accepts npm's .bin directory: links whose target stays inside the
// tree's top node_modules.
func (v *verifier) checkBin(rel string) {
	items, err := os.ReadDir(v.abs(rel))
	if err != nil {
		v.problem(TreeProblem{Path: rel, Problem: TreeUnreadable, Detail: err.Error()})
		return
	}
	for _, item := range items {
		entryRel := rel + "/" + item.Name()
		if item.Type()&os.ModeSymlink == 0 {
			v.problem(TreeProblem{Path: entryRel, Problem: TreeHiddenNotAllowed, Detail: "an entry of .bin that is not a link"})
			continue
		}
		target, err := os.Readlink(v.abs(entryRel))
		if err != nil {
			v.problem(TreeProblem{Path: entryRel, Problem: TreeUnreadable, Detail: err.Error()})
			continue
		}
		resolved := path.Join(rel, target)
		if path.IsAbs(target) || resolved != "node_modules" && !strings.HasPrefix(resolved, "node_modules/") {
			v.problem(TreeProblem{Path: entryRel, Problem: TreePathOutside, Detail: "the link leaves the tree"})
		}
	}
}

func (v *verifier) scope(rel string, item os.DirEntry) {
	if item.Type()&os.ModeSymlink != 0 {
		v.problem(TreeProblem{Path: rel, Problem: TreeSymlink, Detail: "a symbolic link where a scope directory is expected"})
		return
	}
	if !item.IsDir() {
		v.problem(TreeProblem{Path: rel, Problem: TreeNotInLockfile, Detail: "a file where a scope directory would be"})
		return
	}
	known := false
	for _, key := range v.lock.paths {
		if strings.HasPrefix(key, rel+"/") {
			known = true
			break
		}
	}
	if !known {
		v.problem(TreeProblem{Path: rel, Problem: TreeNotInLockfile, Detail: "a scope the lockfile has no package in"})
		return
	}
	children, err := os.ReadDir(v.abs(rel))
	if err != nil {
		v.problem(TreeProblem{Path: rel, Problem: TreeUnreadable, Detail: err.Error()})
		return
	}
	for _, child := range children {
		childRel := rel + "/" + child.Name()
		if strings.HasPrefix(child.Name(), ".") {
			v.problem(TreeProblem{Path: childRel, Problem: TreeHiddenNotAllowed, Detail: "a hidden entry in a scope directory"})
			continue
		}
		v.packageDir(childRel, child)
	}
}

func (v *verifier) packageDir(rel string, item os.DirEntry) {
	entry, known := v.lock.entries[rel]
	if !known {
		v.problem(TreeProblem{Path: rel, Problem: TreeNotInLockfile, Detail: "the lockfile has no entry for it"})
		return
	}
	_ = entry
	if item.Type()&os.ModeSymlink != 0 {
		v.problem(TreeProblem{Path: rel, Problem: TreeSymlink, Detail: "a symbolic link where a package directory is expected"})
		return
	}
	if !item.IsDir() {
		v.problem(TreeProblem{Path: rel, Problem: TreeNotADirectory, Detail: "not a directory"})
		return
	}
	nested := rel + "/node_modules"
	switch v.lstatDir(nested, false) {
	case stateDirectory:
		v.walk(nested)
	}
}

// checkHiddenLockfile compares npm's own record of the tree with the judged
// lockfile when npm wrote one. It is present on every real npm install: one
// that cannot be read, or says something else, is a failure.
func (v *verifier) checkHiddenLockfile() {
	rel := "node_modules/.package-lock.json"
	info, err := os.Lstat(v.abs(rel))
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	fail := func(problem, detail string) {
		v.problem(TreeProblem{Path: rel, Problem: problem, Detail: detail})
	}
	if err != nil {
		fail(TreeHiddenLockfileUnreadable, err.Error())
		return
	}
	if !info.Mode().IsRegular() {
		fail(TreeHiddenLockfileUnreadable, "not a regular file")
		return
	}
	raw, err := readFileNoFollow(v.abs(rel), maxHiddenLockfileBytes)
	if err != nil {
		fail(TreeHiddenLockfileUnreadable, err.Error())
		return
	}
	if err := strictjson.RejectRepeatedMembers(raw); err != nil {
		fail(TreeHiddenLockfileUnreadable, err.Error())
		return
	}
	var hidden struct {
		LockfileVersion int                        `json:"lockfileVersion"`
		Packages        map[string]json.RawMessage `json:"packages"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&hidden); err != nil || decoder.More() {
		fail(TreeHiddenLockfileUnreadable, "not one JSON document")
		return
	}
	if hidden.LockfileVersion < 2 || hidden.Packages == nil {
		fail(TreeHiddenLockfileInconsistent, "no lockfileVersion of 2 or more, or no packages member")
		return
	}
	recorded := map[string]bool{}
	keys := make([]string, 0, len(hidden.Packages))
	for key := range hidden.Packages {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		raw := hidden.Packages[key]
		var record lockEntry
		trimmed := bytes.TrimSpace(raw)
		if len(trimmed) == 0 || trimmed[0] != '{' || json.Unmarshal(raw, &record) != nil {
			fail(TreeHiddenLockfileInconsistent, fmt.Sprintf("record %q is not an object", key))
			continue
		}
		want, ok := v.lock.entries[key]
		switch {
		case !validTreeKey(key):
			v.problem(TreeProblem{Path: key, Problem: TreeHiddenLockfileInconsistent, Detail: "npm's record names a path that is not in the tree"})
			continue
		case !ok:
			v.problem(TreeProblem{Path: key, Problem: TreeHiddenLockfileInconsistent, Detail: "npm's record names an entry the lockfile lacks"})
			continue
		case record.Link:
			v.problem(TreeProblem{Path: key, Problem: TreeHiddenLockfileInconsistent, Name: want.expectedName, Version: want.Version, Detail: "npm recorded a registry entry as a link"})
			continue
		}
		recorded[key] = true
		if !v.present[key] {
			v.problem(TreeProblem{Path: key, Problem: TreeHiddenLockfileInconsistent, Name: want.expectedName, Version: want.Version, Detail: "npm recorded an entry the tree does not hold"})
			continue
		}
		problem := TreeProblem{Path: key, Name: want.expectedName, Version: want.Version, FoundVersion: record.Version}
		switch {
		case record.Version != want.Version:
			problem.Problem = TreeWrongVersion
			problem.Detail = "npm's record says another version"
		case want.Resolved != "" && record.Resolved != want.Resolved:
			problem.Problem = TreeWrongOrigin
			problem.Detail = "npm's record says another resolved location, or none"
		case want.Integrity != "" && record.Integrity != want.Integrity:
			problem.Problem = TreeWrongOrigin
			problem.Detail = "npm's record says another hash, or none"
		default:
			continue
		}
		v.problem(problem)
	}
	for key := range v.present {
		if !recorded[key] {
			entry := v.lock.entries[key]
			v.problem(TreeProblem{Path: key, Problem: TreeHiddenLockfileInconsistent, Name: entry.expectedName, Version: entry.Version, Detail: "the tree holds an entry npm did not record"})
		}
	}
}
