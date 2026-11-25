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

	"github.com/superbiche/safe/internal/lockdiff"
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
	// TreeBinInvalid: an entry of a .bin directory that is not a link to a
	// regular file, inside the tree, of a package whose lockfile entry
	// declares that command under that name.
	TreeBinInvalid                 = "bin_invalid"
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
	// Present are the DIRECT packages (node_modules/<name> at the top level) the verification found in the tree, each
	// checked against its lockfile name and version: what a caller may take as installed, and the only list of it. It is
	// empty when the verification fails.
	Present []TreePresent `json:"present_direct"`
	// Limits says what a passing verification does not attest.
	Limits []string `json:"limits"`
}

// TreePresent is one direct package the verified tree holds.
type TreePresent struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Path    string `json:"path"`
}

// VerifierLimits is the statement carried by every tree report: the verifier
// attests the SET of packages in the tree and their identities (name and
// version, npm's own record of origin and hash); it does not attest the bytes
// of their files. That rests on npm checking each tarball against the hash in
// the lockfile as it extracts it, which the transaction trusts as it trusts
// the install command.
var VerifierLimits = []string{
	"attests the set of packages and their identities, not the bytes of their files",
	"payload integrity rests on npm checking each tarball against the integrity hash of the lockfile",
	"npm's hidden lockfile is read as written by the install command that is trusted to write it",
}

type lockEntry struct {
	Name        string
	Version     string
	Resolved    string
	Integrity   string
	Link        bool
	InBundle    bool
	Dev         bool
	Optional    bool
	DevOptional bool
	Peer        bool
	OS          json.RawMessage
	CPU         json.RawMessage
	Libc        json.RawMessage
	Bin         json.RawMessage

	path         string
	expectedName string
}

// judgedLock is a lockfile read for verification: the entries that stand for
// a directory of the tree, and the keys that cannot.
type judgedLock struct {
	root    lockEntry
	entries map[string]*lockEntry
	paths   []string
	// outside lists the keys that are not a chain of node_modules/<package>
	// segments. They are never joined to a directory.
	outside []string
}

// decodeEntry reads one lockfile (or hidden lockfile) entry by exact,
// case-sensitive member names. A second spelling of a member that matters is an
// error; members that do not matter are ignored in whatever spelling.
func decodeEntry(raw json.RawMessage) (lockEntry, error) {
	var entry lockEntry
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return entry, errors.New("not an object")
	}
	if err := lockdiff.CheckEntry(raw); err != nil {
		return entry, err
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return entry, err
	}
	// A null is not an absent member: npm reads the property as written, and
	// a comparison of "absent against absent" must not be satisfied by it.
	for _, key := range lockdiff.IdentityFields {
		if value, ok := members[key]; ok && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return entry, fmt.Errorf("%s is null", key)
		}
	}
	text := func(key string, into *string) error {
		value, ok := members[key]
		if !ok {
			return nil
		}
		if err := json.Unmarshal(value, into); err != nil {
			return fmt.Errorf("%s is not a string", key)
		}
		return nil
	}
	flag := func(key string, into *bool) error {
		value, ok := members[key]
		if !ok {
			return nil
		}
		if err := json.Unmarshal(value, into); err != nil {
			return fmt.Errorf("%s is not a boolean", key)
		}
		return nil
	}
	for _, step := range []func() error{
		func() error { return text("name", &entry.Name) },
		func() error { return text("version", &entry.Version) },
		func() error { return text("resolved", &entry.Resolved) },
		func() error { return text("integrity", &entry.Integrity) },
		func() error { return flag("link", &entry.Link) },
		func() error { return flag("inBundle", &entry.InBundle) },
		func() error { return flag("dev", &entry.Dev) },
		func() error { return flag("optional", &entry.Optional) },
		func() error { return flag("devOptional", &entry.DevOptional) },
		func() error { return flag("peer", &entry.Peer) },
	} {
		if err := step(); err != nil {
			return entry, err
		}
	}
	entry.OS, entry.CPU, entry.Libc, entry.Bin = members["os"], members["cpu"], members["libc"], members["bin"]
	return entry, nil
}

// ParseLockfile reads the lockfile a tree is verified against: exactly one
// JSON document with exactly named members and no repeated member, version 2
// or 3. A lockfile with link entries is ErrLinkEntries.
func parseJudgedLockfile(raw []byte, anyVersion bool) (*judgedLock, error) {
	if err := strictjson.RejectConflictMarkers(raw); err != nil {
		return nil, fmt.Errorf("lockfile: %w", err)
	}
	root, err := strictjson.ParseObject(raw)
	if err != nil {
		return nil, fmt.Errorf("lockfile: %w", err)
	}
	if err := strictjson.RejectVariants(root, "lockfileVersion", "packages"); err != nil {
		return nil, fmt.Errorf("lockfile: %w", err)
	}
	if !anyVersion {
		var version int
		if err := json.Unmarshal(root["lockfileVersion"], &version); err != nil || (version != 2 && version != 3) {
			return nil, errors.New("lockfile: lockfileVersion is not 2 or 3")
		}
	}
	var packages map[string]json.RawMessage
	if err := json.Unmarshal(root["packages"], &packages); err != nil || packages == nil {
		return nil, errors.New("lockfile: no packages member")
	}
	lock := &judgedLock{entries: map[string]*lockEntry{}}
	links := false
	var undecoded error
	undecodedKey := ""
	for key, rawEntry := range packages {
		entry, err := decodeEntry(rawEntry)
		if err != nil {
			// an entry that does not decode does not end the walk: the keys are still checked, so an unsafe key is never hidden
			// by an unreadable entry (the smallest key's error is the one reported, for a stable message)
			if key != "" && !validTreeKey(key) {
				lock.outside = append(lock.outside, key)
			}
			if undecoded == nil || key < undecodedKey {
				undecoded, undecodedKey = fmt.Errorf("lockfile: packages[%q]: %w", key, err), key
			}
			continue
		}
		if entry.Link {
			links = true
		}
		if key == "" {
			lock.root = entry
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
	if undecoded != nil {
		return lock, undecoded
	}
	if links {
		return lock, ErrLinkEntries
	}
	return lock, nil
}

// AdmitFinding is one reason a lockfile is not admitted.
type AdmitFinding struct{ Reason, Detail string }

// AdmitLockfileFindings is the check made before anything runs, reporting EVERY reason it
// finds, not the first: the lockfile reads strictly, carries no link entries and keeps every
// key inside the tree. A link entry never hides an outside key (or the other way round): a
// router that refuses on any unsafe reason sees them all.
func AdmitLockfileFindings(raw []byte) []AdmitFinding {
	lock, err := parseJudgedLockfile(raw, true)
	var findings []AdmitFinding
	switch {
	case err != nil && !errors.Is(err, ErrLinkEntries):
		findings = append(findings, AdmitFinding{ReasonLockfileUnreadable, err.Error()})
		if lock == nil {
			return findings
		}
	case errors.Is(err, ErrLinkEntries):
		findings = append(findings, AdmitFinding{ReasonLinksNotSupported, err.Error()})
	}
	if len(lock.outside) > 0 {
		findings = append(findings, AdmitFinding{ReasonLockfilePathsOutside, fmt.Sprintf("the lockfile names %q, which is not inside the tree", lock.outside[0])})
	}
	return findings
}

// AdmitLockfile is the first finding of AdmitLockfileFindings, in the order the binder has always
// refused in (a link, then a path outside the tree), or "".
func AdmitLockfile(raw []byte) (reason, detail string) {
	if findings := AdmitLockfileFindings(raw); len(findings) > 0 {
		return findings[0].Reason, findings[0].Detail
	}
	return "", ""
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
	return verifyTree(lockfile, treeParent, "", selection)
}

// VerifyHeldTree verifies a node_modules directory the caller holds open,
// given as the /proc/self/fd path of its descriptor: the object verified is
// that directory, whatever happens to the pathnames above it. Each name below
// it is still resolved by an Lstat per component (no link followed); it is not
// an openat chain.
func VerifyHeldTree(lockfile []byte, treeRoot string, selection Selection) (TreeReport, error) {
	return verifyTree(lockfile, "", treeRoot, selection)
}

func verifyTree(lockfile []byte, treeParent, treeRoot string, selection Selection) (TreeReport, error) {
	if err := selection.Validate(); err != nil {
		return TreeReport{}, fmt.Errorf("selection: %w", err)
	}
	lock, err := parseJudgedLockfile(lockfile, false)
	if err != nil {
		return TreeReport{}, err
	}
	// treeParent is a path the caller trusts (a project directory, or a
	// descriptor path of a directory it holds); everything below it is read
	// without following a link.
	checked := treeParent
	if treeRoot != "" {
		checked = treeRoot
	}
	info, err := os.Stat(checked)
	if err != nil {
		return TreeReport{}, err
	}
	if !info.IsDir() {
		return TreeReport{}, fmt.Errorf("%q is not a directory", checked)
	}
	v := &verifier{root: treeParent, treeRoot: treeRoot, lock: lock, sel: selection, seen: map[string]bool{}, present: map[string]bool{}}
	report := TreeReport{SchemaVersion: TreeSchema, Selection: selection.normalized(), Problems: []TreeProblem{}, Present: []TreePresent{}, Limits: append([]string{}, VerifierLimits...)}
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
	if report.Ok {
		for _, key := range lock.paths {
			entry := lock.entries[key]
			if !v.present[key] || !strings.HasPrefix(key, "node_modules/") || strings.Contains(strings.TrimPrefix(key, "node_modules/"), "node_modules/") {
				continue
			}
			report.Present = append(report.Present, TreePresent{Name: entry.expectedName, Version: entry.Version, Path: key})
		}
	}
	return report, nil
}

type verifier struct {
	// root is the directory that holds node_modules. When treeRoot is set the
	// verifier is anchored on a held descriptor of the node_modules directory
	// itself (a /proc/self/fd path) and every name below it resolves from there.
	root     string
	treeRoot string
	lock     *judgedLock
	sel      Selection
	report   *TreeReport
	seen     map[string]bool // problem dedup
	present  map[string]bool // entry paths found as directories
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
	if v.treeRoot != "" {
		if rel == "node_modules" {
			return v.treeRoot
		}
		if rest, ok := strings.CutPrefix(rel, "node_modules/"); ok {
			return filepath.Join(v.treeRoot, filepath.FromSlash(rest))
		}
	}
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
	if v.treeRoot != "" {
		return stateDirectory // a held directory descriptor: nothing to follow
	}
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

// ancestorDeselected reports whether the occurrence an entry is nested under
// is itself deselected AND absent from the tree: what is missing below a
// package that is there is missing, deselected or not, and an ancestor that is
// absent without being provably deselected is its own problem, never an excuse.
func (v *verifier) ancestorDeselected(key string) bool {
	for parent := parentEntry(key); parent != ""; parent = parentEntry(parent) {
		entry, ok := v.lock.entries[parent]
		if !ok || !entry.deselected(v.sel) {
			continue
		}
		if _, err := os.Lstat(v.abs(parent)); errors.Is(err, os.ErrNotExist) {
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
	// npm's property names are case-sensitive: exact members, no second
	// spelling of the identity, one document.
	members, err := strictjson.ParseObject(raw)
	if err != nil {
		return "", "", TreeManifestUnusable, err.Error()
	}
	if err := strictjson.RejectVariants(members, "name", "version"); err != nil {
		return "", "", TreeManifestUnusable, err.Error()
	}
	for key, into := range map[string]*string{"name": &name, "version": &version} {
		if value, ok := members[key]; ok {
			if err := json.Unmarshal(value, into); err != nil {
				return "", "", TreeManifestUnusable, key + " is not a string"
			}
		}
	}
	return name, version, "", ""
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

// binCommands returns the commands a lockfile entry declares: command name to
// the cleaned path of its file inside the package.
func (e *lockEntry) binCommands() map[string]string {
	commands := map[string]string{}
	clean := func(file string) (string, bool) {
		cleaned := path.Clean(file)
		if path.IsAbs(cleaned) || cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
			return "", false
		}
		for _, segment := range strings.Split(cleaned, "/") {
			if segment == "node_modules" {
				return "", false // another package's territory
			}
		}
		return cleaned, true
	}
	var many map[string]string
	if json.Unmarshal(e.Bin, &many) == nil {
		for command, file := range many {
			if cleaned, ok := clean(file); ok {
				commands[command] = cleaned
			}
		}
		return commands
	}
	var one string
	if json.Unmarshal(e.Bin, &one) == nil {
		if cleaned, ok := clean(one); ok {
			commands[path.Base(e.expectedName)] = cleaned
		}
	}
	return commands
}

// regularFileBeneath checks that rel is a regular file reached through real
// directories only: no component of it, the last included, is a link, and the
// file opens without following one.
func (v *verifier) regularFileBeneath(rel string) string {
	parts := strings.Split(rel, "/")
	for i := 1; i < len(parts); i++ {
		info, err := os.Lstat(v.abs(strings.Join(parts[:i+1], "/")))
		switch {
		case err != nil:
			return "the target does not exist"
		case info.Mode()&os.ModeSymlink != 0:
			return "the target is reached through a link"
		case i < len(parts)-1 && !info.IsDir():
			return "the target is below a file"
		case i == len(parts)-1 && !info.Mode().IsRegular():
			return "the target is not a regular file"
		}
	}
	file, err := os.OpenFile(v.abs(rel), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "the target cannot be opened without following a link: " + err.Error()
	}
	defer file.Close()
	if info, err := file.Stat(); err != nil || !info.Mode().IsRegular() {
		return "the target is not a regular file"
	}
	return ""
}

// checkBin accepts npm's .bin directory entry by entry. Only the links that are
// present are attributed (npm skips a command whose file is missing). Each
// must be a symbolic link whose TEXT is exactly the relative path npm's linker
// writes for a command a package's lockfile entry declares, that is
// "../<package>/<declared file>" (bin-links computes relative(dirname(link),
// resolve(package, file)) from the normalised manifest), and the declared file
// must be a regular file beneath that package directory reached without
// following a link. A link with any other spelling, cancelling or redundant
// components included, a file or directory in .bin, and a link to a command no
// entry declares are failures.
func (v *verifier) checkBin(binRel string) {
	nm := path.Dir(binRel)
	items, err := os.ReadDir(v.abs(binRel))
	if err != nil {
		v.problem(TreeProblem{Path: binRel, Problem: TreeUnreadable, Detail: err.Error()})
		return
	}
	for _, item := range items {
		command := item.Name()
		entryRel := binRel + "/" + command
		bad := func(problem, detail string) {
			v.problem(TreeProblem{Path: entryRel, Problem: problem, Detail: detail})
		}
		if item.Type()&os.ModeSymlink == 0 {
			bad(TreeBinInvalid, "an entry of .bin that is not a link")
			continue
		}
		text, err := os.Readlink(v.abs(entryRel))
		if err != nil {
			bad(TreeUnreadable, err.Error())
			continue
		}
		if cleaned := path.Join(binRel, text); path.IsAbs(text) || !strings.HasPrefix(cleaned, "node_modules/") {
			bad(TreePathOutside, "the link leaves the tree")
			continue
		}
		rest, ok := strings.CutPrefix(text, "../")
		if !ok {
			bad(TreeBinInvalid, "the link is not a relative path to a package beside .bin")
			continue
		}
		segments := strings.Split(rest, "/")
		pkg := segments[0]
		if strings.HasPrefix(pkg, "@") && len(segments) > 1 {
			pkg += "/" + segments[1]
		}
		entry, known := v.lock.entries[nm+"/"+pkg]
		if !known {
			bad(TreeBinInvalid, "the link points into a package the lockfile does not name")
			continue
		}
		declared, ok := entry.binCommands()[command]
		if !ok {
			bad(TreeBinInvalid, "the package's lockfile entry does not declare this command")
			continue
		}
		if text != "../"+pkg+"/"+declared {
			bad(TreeBinInvalid, "the link text is not the path npm writes for the declared command")
			continue
		}
		if detail := v.regularFileBeneath(nm + "/" + pkg + "/" + declared); detail != "" {
			bad(TreeBinInvalid, detail)
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
	if err := strictjson.RejectConflictMarkers(raw); err != nil {
		fail(TreeHiddenLockfileUnreadable, err.Error())
		return
	}
	members, err := strictjson.ParseObject(raw)
	if err != nil {
		fail(TreeHiddenLockfileUnreadable, err.Error())
		return
	}
	if err := strictjson.RejectVariants(members, "lockfileVersion", "packages"); err != nil {
		fail(TreeHiddenLockfileUnreadable, err.Error())
		return
	}
	var hidden struct {
		LockfileVersion int
		Packages        map[string]json.RawMessage
	}
	if err := json.Unmarshal(members["lockfileVersion"], &hidden.LockfileVersion); err != nil {
		hidden.LockfileVersion = 0
	}
	_ = json.Unmarshal(members["packages"], &hidden.Packages)
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
		record, err := decodeEntry(raw)
		if err != nil {
			fail(TreeHiddenLockfileInconsistent, fmt.Sprintf("record %q: %v", key, err))
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
			// npm records an optional entry it did not install for this
			// platform (it marks it ideallyInert). A record of an entry that
			// is absent and provably deselected, by the same rule the tree
			// walk applies, is consistent with the tree; the flag npm wrote
			// is not what excuses it.
			if want.deselected(v.sel) || v.ancestorDeselected(key) {
				continue
			}
			v.problem(TreeProblem{Path: key, Problem: TreeHiddenLockfileInconsistent, Name: want.expectedName, Version: want.Version, Detail: "npm recorded an entry the tree does not hold"})
			continue
		}
		// Every identity field is compared as it is, absent against absent
		// included: a record may not hold an origin or a hash the lockfile
		// does not, nor lack one it does, and a bundled member keeps its
		// bundle flag and its recorded name.
		problem := TreeProblem{Path: key, Name: want.expectedName, Version: want.Version, FoundName: record.Name, FoundVersion: record.Version}
		switch {
		case record.Version != want.Version:
			problem.Problem = TreeWrongVersion
			problem.Detail = "npm's record says another version"
		case record.Name != want.Name:
			problem.Problem = TreeWrongName
			problem.Detail = "npm's record says another package name"
		case record.Resolved != want.Resolved:
			problem.Problem = TreeWrongOrigin
			problem.Detail = "npm's record says another resolved location, or none"
		case record.Integrity != want.Integrity:
			problem.Problem = TreeWrongOrigin
			problem.Detail = "npm's record says another hash, or none"
		case record.InBundle != want.InBundle:
			problem.Problem = TreeWrongOrigin
			problem.Detail = "npm's record says another bundling"
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
