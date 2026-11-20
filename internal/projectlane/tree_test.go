package projectlane

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// treeFx is a lockfile and a tree built from it, edited by each test.
type treeFx struct {
	t    *testing.T
	root string
	lock map[string]map[string]any
}

func newTreeFx(t *testing.T) *treeFx {
	return &treeFx{t: t, root: t.TempDir(), lock: map[string]map[string]any{}}
}

// pkg adds a lockfile entry and installs it: a directory with a manifest of
// the same name and version.
func (f *treeFx) pkg(path, name, version string, members ...map[string]any) *treeFx {
	f.t.Helper()
	f.entry(path, name, version, members...)
	f.install(path, name, version)
	return f
}

// entry adds a lockfile entry only.
func (f *treeFx) entry(path, name, version string, members ...map[string]any) *treeFx {
	e := entry(name, version)
	if name != packageNameOfPath(path) {
		e["name"] = name
	}
	for _, m := range members {
		e = with(e, m)
	}
	f.lock[path] = e
	return f
}

func (f *treeFx) install(path, name, version string) *treeFx {
	f.t.Helper()
	dir := filepath.Join(f.root, filepath.FromSlash(path))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		f.t.Fatal(err)
	}
	manifest, _ := json.Marshal(map[string]string{"name": name, "version": version})
	if err := os.WriteFile(filepath.Join(dir, "package.json"), manifest, 0o644); err != nil {
		f.t.Fatal(err)
	}
	return f
}

func (f *treeFx) write(rel, content string) {
	f.t.Helper()
	name := filepath.Join(f.root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(content), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f *treeFx) symlink(target, rel string) {
	f.t.Helper()
	name := filepath.Join(f.root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Symlink(target, name); err != nil {
		f.t.Fatal(err)
	}
}

func (f *treeFx) lockBytes() []byte {
	all := map[string]any{"": map[string]any{"name": "root", "version": "1.0.0"}}
	for path, e := range f.lock {
		all[path] = e
	}
	raw, err := json.Marshal(map[string]any{"lockfileVersion": 3, "packages": all})
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}

// hiddenLockfile writes the record npm leaves: every installed entry as the
// lockfile has it.
func (f *treeFx) hiddenLockfile(edit func(map[string]any)) {
	f.t.Helper()
	packages := map[string]any{}
	for path, e := range f.lock {
		if path == "" {
			continue // npm's hidden lockfile has no root entry
		}
		if _, err := os.Lstat(filepath.Join(f.root, filepath.FromSlash(path))); err == nil {
			packages[path] = e
		}
	}
	if edit != nil {
		edit(packages)
	}
	raw, _ := json.Marshal(map[string]any{"name": "root", "lockfileVersion": 3, "requires": true, "packages": packages})
	f.write("node_modules/.package-lock.json", string(raw))
}

var linuxX64 = Selection{OS: "linux", CPU: "x64"}

func (f *treeFx) verify(sel Selection) TreeReport {
	f.t.Helper()
	report, err := VerifyTree(f.lockBytes(), f.root, sel)
	if err != nil {
		f.t.Fatalf("VerifyTree() error = %v", err)
	}
	return report
}

func problemsOf(report TreeReport) map[string]string {
	out := map[string]string{}
	for _, problem := range report.Problems {
		if out[problem.Path] != "" {
			out[problem.Path] += "+"
		}
		out[problem.Path] += problem.Problem
	}
	return out
}

func expectProblems(t *testing.T, report TreeReport, want map[string]string) {
	t.Helper()
	got := problemsOf(report)
	if len(got) != len(want) || report.Ok != (len(want) == 0) {
		t.Fatalf("problems = %v (ok=%v), want %v\n%+v", got, report.Ok, want, report.Problems)
	}
	for path, problem := range want {
		if got[path] != problem {
			t.Fatalf("problems = %v, want %v", got, want)
		}
	}
}

func completeTree(t *testing.T) *treeFx {
	f := newTreeFx(t)
	f.pkg("node_modules/a", "a", "1.0.0")
	f.pkg("node_modules/@s/b", "@s/b", "2.0.0")
	f.pkg("node_modules/a/node_modules/c", "c", "3.0.0")
	return f
}

func TestVerifyTreeAcceptsTheCompleteTree(t *testing.T) {
	f := completeTree(t)
	f.lock["node_modules/a"]["bin"] = map[string]any{"a": "./bin.js", "a-alt": "lib/cli.js"}
	f.write("node_modules/a/bin.js", "#!/usr/bin/env node\n")
	f.write("node_modules/a/lib/cli.js", "#!/usr/bin/env node\n")
	f.symlink("../a/bin.js", "node_modules/.bin/a")
	f.symlink("../a/lib/cli.js", "node_modules/.bin/a-alt")
	f.hiddenLockfile(nil)
	report := f.verify(linuxX64)
	expectProblems(t, report, nil)
	if report.Checked != 3 || report.Absent != 0 || report.SchemaVersion != TreeSchema {
		t.Fatalf("report = %+v", report)
	}
	// An alias is checked under its real name.
	g := newTreeFx(t)
	g.pkg("node_modules/alias", "real", "1.0.0")
	expectProblems(t, g.verify(linuxX64), nil)
	// An empty project has an empty tree, or none.
	expectProblems(t, newTreeFx(t).verify(linuxX64), nil)
}

func TestVerifyTreeFindsWhatTheLockfileDoesNotSay(t *testing.T) {
	cases := map[string]struct {
		build func(f *treeFx)
		want  map[string]string
	}{
		"a required entry is missing": {
			func(f *treeFx) { f.entry("node_modules/b", "b", "1.0.0") },
			map[string]string{"node_modules/b": TreeMissing}},
		"an entry under another name": {
			func(f *treeFx) { f.install("node_modules/a", "evil", "1.0.0") },
			map[string]string{"node_modules/a": TreeWrongName}},
		"an entry under another version": {
			func(f *treeFx) { f.install("node_modules/a", "a", "1.0.1") },
			map[string]string{"node_modules/a": TreeWrongVersion}},
		"an extra entry": {
			func(f *treeFx) { f.install("node_modules/extra", "extra", "1.0.0") },
			map[string]string{"node_modules/extra": TreeNotInLockfile}},
		"an extra nested entry": {
			func(f *treeFx) { f.install("node_modules/a/node_modules/deep", "deep", "1.0.0") },
			map[string]string{"node_modules/a/node_modules/deep": TreeNotInLockfile}},
		"an extra directory with no manifest": {
			func(f *treeFx) { _ = os.MkdirAll(filepath.Join(f.root, "node_modules/empty"), 0o755) },
			map[string]string{"node_modules/empty": TreeNotInLockfile}},
		"an extra file": {
			func(f *treeFx) { f.write("node_modules/README", "x") },
			map[string]string{"node_modules/README": TreeNotInLockfile}},
		"an extra scope": {
			func(f *treeFx) { f.install("node_modules/@evil/pkg", "@evil/pkg", "1.0.0") },
			map[string]string{"node_modules/@evil": TreeNotInLockfile}},
		"an extra package in a known scope": {
			func(f *treeFx) { f.install("node_modules/@s/other", "@s/other", "1.0.0") },
			map[string]string{"node_modules/@s/other": TreeNotInLockfile}},
		// Hidden entries are extras, apart from the ones npm itself writes.
		"a hidden package directory": {
			func(f *treeFx) { f.install("node_modules/.hidden", ".hidden", "1.0.0") },
			map[string]string{"node_modules/.hidden": TreeHiddenNotAllowed}},
		"a hidden cache directory": {
			func(f *treeFx) { f.write("node_modules/.cache/x", "x") },
			map[string]string{"node_modules/.cache": TreeHiddenNotAllowed}},
		"a hidden entry in a nested tree": {
			func(f *treeFx) { f.write("node_modules/a/node_modules/.evil/package.json", "{}") },
			map[string]string{"node_modules/a/node_modules/.evil": TreeHiddenNotAllowed}},
		"a hidden entry in a scope": {
			func(f *treeFx) { f.install("node_modules/@s/.sneaky", "x", "1.0.0") },
			map[string]string{"node_modules/@s/.sneaky": TreeHiddenNotAllowed}},
		"a hidden file named like npm's, at another level": {
			func(f *treeFx) { f.write("node_modules/a/node_modules/.package-lock.json", "{}") },
			map[string]string{"node_modules/a/node_modules/.package-lock.json": TreeHiddenNotAllowed}},
		"a .bin entry that is a file": {
			func(f *treeFx) { f.write("node_modules/.bin/tool", "#!/bin/sh") },
			map[string]string{"node_modules/.bin/tool": TreeBinInvalid}},
		"a .bin link that leaves the tree": {
			func(f *treeFx) { f.symlink("../../../etc/passwd", "node_modules/.bin/x") },
			map[string]string{"node_modules/.bin/x": TreePathOutside}},
		"an absolute .bin link": {
			func(f *treeFx) { f.symlink("/etc/passwd", "node_modules/.bin/x") },
			map[string]string{"node_modules/.bin/x": TreePathOutside}},
		// The declaration is there, so these two stop at existence, not at attribution.
		"a dangling .bin link to a declared command": {
			func(f *treeFx) {
				f.lock["node_modules/a"]["bin"] = map[string]any{"a": "bin.js"}
				f.symlink("../a/bin.js", "node_modules/.bin/a")
			},
			map[string]string{"node_modules/.bin/a": TreeBinInvalid}},
		"a .bin link text that cancels a component before it resolves": {
			func(f *treeFx) {
				f.lock["node_modules/a"]["bin"] = map[string]any{"a": "bin.js"}
				f.write("node_modules/a/bin.js", "x")
				f.symlink("../ghost/../a/bin.js", "node_modules/.bin/a")
			},
			map[string]string{"node_modules/.bin/a": TreeBinInvalid}},
		"a .bin link text with a redundant component": {
			func(f *treeFx) {
				f.lock["node_modules/a"]["bin"] = map[string]any{"a": "bin.js"}
				f.write("node_modules/a/bin.js", "x")
				f.symlink("../a/./bin.js", "node_modules/.bin/a")
			},
			map[string]string{"node_modules/.bin/a": TreeBinInvalid}},
		"a .bin link that goes through the nested node_modules of the package": {
			func(f *treeFx) {
				f.lock["node_modules/a"]["bin"] = map[string]any{"c": "node_modules/c/x.js"}
				f.write("node_modules/a/node_modules/c/x.js", "x")
				f.symlink("../a/node_modules/c/x.js", "node_modules/.bin/c")
			},
			map[string]string{"node_modules/.bin/c": TreeBinInvalid}},
		"a nested .bin link to the nested package's own declared command": {
			func(f *treeFx) {
				f.lock["node_modules/a/node_modules/c"]["bin"] = map[string]any{"c": "x.js"}
				f.write("node_modules/a/node_modules/c/x.js", "x")
				f.symlink("../c/x.js", "node_modules/a/node_modules/.bin/c")
			},
			nil},
		"a .bin link to a file the lockfile declares for another command": {
			func(f *treeFx) {
				f.lock["node_modules/a"]["bin"] = map[string]any{"a": "bin.js"}
				f.write("node_modules/a/bin.js", "x")
				f.symlink("../a/bin.js", "node_modules/.bin/other")
			},
			map[string]string{"node_modules/.bin/other": TreeBinInvalid}},
		"a .bin link into a package that declares no commands": {
			func(f *treeFx) {
				f.write("node_modules/a/bin.js", "x")
				f.symlink("../a/bin.js", "node_modules/.bin/a")
			},
			map[string]string{"node_modules/.bin/a": TreeBinInvalid}},
		"a .bin link to a package the lockfile does not name": {
			func(f *treeFx) { f.symlink("../ghost/bin.js", "node_modules/.bin/ghost") },
			map[string]string{"node_modules/.bin/ghost": TreeBinInvalid}},
		"a .bin link to a directory": {
			func(f *treeFx) {
				f.lock["node_modules/a"]["bin"] = map[string]any{"a": "lib"}
				f.write("node_modules/a/lib/x", "x")
				f.symlink("../a/lib", "node_modules/.bin/a")
			},
			map[string]string{"node_modules/.bin/a": TreeBinInvalid}},
		"a .bin link through another link": {
			func(f *treeFx) {
				f.lock["node_modules/a"]["bin"] = map[string]any{"a": "lib/x.js"}
				f.write("elsewhere/x.js", "x")
				f.symlink("../../../elsewhere", "node_modules/a/lib")
				f.symlink("../a/lib/x.js", "node_modules/.bin/a")
			},
			map[string]string{"node_modules/.bin/a": TreeBinInvalid}},
		"a .bin that is a link": {
			func(f *treeFx) { f.symlink("../outside", "node_modules/.bin") },
			map[string]string{"node_modules/.bin": TreeHiddenNotAllowed}},
		// Symbolic links are never followed.
		"a symbolic link where a package directory is expected": {
			func(f *treeFx) {
				_ = os.RemoveAll(filepath.Join(f.root, "node_modules/a/node_modules"))
				_ = os.RemoveAll(filepath.Join(f.root, "node_modules/a"))
				f.install("elsewhere/a", "a", "1.0.0")
				f.symlink("../elsewhere/a", "node_modules/a")
				_ = os.RemoveAll(filepath.Join(f.root, "node_modules/@s"))
				f.install("node_modules/@s/b", "@s/b", "2.0.0")
				f.entry("node_modules/other", "other", "1.0.0")
				f.install("node_modules/other", "other", "1.0.0")
				delete(f.lock, "node_modules/a/node_modules/c")
			},
			map[string]string{"node_modules/a": TreeSymlink}},
		"a symbolic link as a scope directory": {
			func(f *treeFx) {
				_ = os.RemoveAll(filepath.Join(f.root, "node_modules/@s"))
				f.install("elsewhere/@s/b", "@s/b", "2.0.0")
				f.symlink("../elsewhere/@s", "node_modules/@s")
			},
			map[string]string{"node_modules/@s": TreeSymlink}},
		"a symbolic link as a nested node_modules": {
			func(f *treeFx) {
				_ = os.RemoveAll(filepath.Join(f.root, "node_modules/a/node_modules"))
				f.install("elsewhere/c", "c", "3.0.0")
				f.symlink("../../elsewhere", "node_modules/a/node_modules")
			},
			map[string]string{"node_modules/a/node_modules": TreeSymlink}},
		"a manifest that is a symbolic link": {
			func(f *treeFx) {
				f.write("elsewhere/package.json", `{"name":"a","version":"1.0.0"}`)
				_ = os.Remove(filepath.Join(f.root, "node_modules/a/package.json"))
				f.symlink("../../elsewhere/package.json", "node_modules/a/package.json")
			},
			map[string]string{"node_modules/a": TreeManifestUnusable}},
		"a manifest that is a directory": {
			func(f *treeFx) {
				_ = os.Remove(filepath.Join(f.root, "node_modules/a/package.json"))
				_ = os.Mkdir(filepath.Join(f.root, "node_modules/a/package.json"), 0o755)
			},
			map[string]string{"node_modules/a": TreeManifestUnusable}},
		"a manifest that repeats a member": {
			func(f *treeFx) {
				f.write("node_modules/a/package.json", `{"name":"evil","name":"a","version":"1.0.0"}`)
			},
			map[string]string{"node_modules/a": TreeManifestUnusable}},
		"a manifest that is not JSON": {
			func(f *treeFx) { f.write("node_modules/a/package.json", `{`) },
			map[string]string{"node_modules/a": TreeManifestUnusable}},
		// A present directory without a manifest is broken, not absent.
		"a present directory without a manifest": {
			func(f *treeFx) { _ = os.Remove(filepath.Join(f.root, "node_modules/a/package.json")) },
			map[string]string{"node_modules/a": TreeManifestMissing}},
		"a package that is a file": {
			func(f *treeFx) {
				_ = os.RemoveAll(filepath.Join(f.root, "node_modules/a/node_modules"))
				_ = os.RemoveAll(filepath.Join(f.root, "node_modules/a"))
				f.write("node_modules/a", "not a directory")
				delete(f.lock, "node_modules/a/node_modules/c")
			},
			map[string]string{"node_modules/a": TreeNotADirectory}},
		// A path that leaves the tree.
		"a lockfile key that climbs out of the tree": {
			func(f *treeFx) { f.entry("node_modules/../../outside", "outside", "1.0.0") },
			map[string]string{"node_modules/../../outside": TreePathOutside}},
		"a lockfile key with a dot segment": {
			func(f *treeFx) { f.entry("node_modules/./a", "a", "1.0.0") },
			map[string]string{"node_modules/./a": TreePathOutside}},
		"a lockfile key that is absolute": {
			func(f *treeFx) { f.entry("/etc/x", "x", "1.0.0") },
			map[string]string{"/etc/x": TreePathOutside}},
		"a lockfile key that is not under node_modules": {
			func(f *treeFx) { f.entry("packages/a", "pa", "1.0.0") },
			map[string]string{"packages/a": TreePathOutside}},
		"a lockfile key with a parent segment inside a chain": {
			func(f *treeFx) { f.entry("node_modules/a/node_modules/../../../x", "x", "1.0.0") },
			map[string]string{"node_modules/a/node_modules/../../../x": TreePathOutside}},
		"a lockfile entry without a version": {
			func(f *treeFx) { delete(f.lock["node_modules/a"], "version") },
			map[string]string{"node_modules/a": TreeLockfileIncomplete}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := completeTree(t)
			tc.build(f)
			expectProblems(t, f.verify(linuxX64), tc.want)
		})
	}
}

func TestVerifyTreeRootThatIsNotARealDirectory(t *testing.T) {
	f := completeTree(t)
	outside := t.TempDir()
	if err := os.Rename(filepath.Join(f.root, "node_modules"), filepath.Join(outside, "node_modules")); err != nil {
		t.Fatal(err)
	}
	f.symlink(filepath.Join(outside, "node_modules"), "node_modules")
	report := f.verify(linuxX64)
	expectProblems(t, report, map[string]string{"node_modules": TreeSymlink})
	if report.Checked != 0 {
		t.Fatalf("nothing behind the link is read: %+v", report)
	}

	g := newTreeFx(t)
	g.write("node_modules", "a file")
	g.entry("node_modules/a", "a", "1.0.0")
	expectProblems(t, g.verify(linuxX64), map[string]string{"node_modules": TreeNotADirectory})

	// No tree at all is absent, and absent entries are missing.
	h := newTreeFx(t)
	h.entry("node_modules/a", "a", "1.0.0")
	expectProblems(t, h.verify(linuxX64), map[string]string{"node_modules/a": TreeMissing})
}

// An entry is absent only when the given selection provably deselects it.
func TestVerifyTreeAbsenceNeedsAProvableDeselection(t *testing.T) {
	win := func(extra ...map[string]any) []map[string]any {
		return append([]map[string]any{{"optional": true, "os": []string{"win32"}}}, extra...)
	}
	cases := map[string]struct {
		members map[string]any
		sel     Selection
		absent  bool
	}{
		"optional for another os, on the stated os":       {map[string]any{"optional": true, "os": []string{"win32"}}, linuxX64, true},
		"optional for another cpu":                        {map[string]any{"optional": true, "cpu": []string{"arm64"}}, linuxX64, true},
		"optional for this platform is required":          {map[string]any{"optional": true, "os": []string{"linux"}, "cpu": []string{"x64"}}, linuxX64, false},
		"optional with no constraint is required":         {map[string]any{"optional": true}, linuxX64, false},
		"optional negated on this os":                     {map[string]any{"optional": true, "os": []string{"!linux"}}, linuxX64, true},
		"optional negated on another os is required":      {map[string]any{"optional": true, "os": []string{"!win32"}}, linuxX64, false},
		"os not stated: nothing is provable":              {map[string]any{"optional": true, "os": []string{"win32"}}, Selection{CPU: "x64"}, false},
		"cpu not stated: nothing is provable":             {map[string]any{"optional": true, "cpu": []string{"arm64"}}, Selection{OS: "linux"}, false},
		"libc stated and different":                       {map[string]any{"optional": true, "os": []string{"linux"}, "libc": []string{"musl"}}, Selection{OS: "linux", CPU: "x64", Libc: "glibc"}, true},
		"libc stated and equal is required":               {map[string]any{"optional": true, "os": []string{"linux"}, "libc": []string{"glibc"}}, Selection{OS: "linux", CPU: "x64", Libc: "glibc"}, false},
		"libc not stated: nothing is provable":            {map[string]any{"optional": true, "os": []string{"linux"}, "libc": []string{"musl"}}, linuxX64, false},
		"a constraint of another shape proves nothing":    {map[string]any{"optional": true, "os": map[string]any{"x": 1}}, linuxX64, false},
		"required for another os is still required":       {map[string]any{"os": []string{"win32"}}, linuxX64, false},
		"devOptional is not optional for the platform":    {map[string]any{"devOptional": true, "os": []string{"win32"}}, linuxX64, false},
		"optional omitted":                                {map[string]any{"optional": true}, Selection{OS: "linux", CPU: "x64", Omit: []string{"optional"}}, true},
		"optional not omitted when only dev is":           {map[string]any{"optional": true}, Selection{OS: "linux", CPU: "x64", Omit: []string{"dev"}}, false},
		"dev omitted":                                     {map[string]any{"dev": true}, Selection{OS: "linux", CPU: "x64", Omit: []string{"dev"}}, true},
		"dev not omitted":                                 {map[string]any{"dev": true}, linuxX64, false},
		"dev with optional omitted only":                  {map[string]any{"dev": true}, Selection{OS: "linux", CPU: "x64", Omit: []string{"optional"}}, false},
		"devOptional needs both omitted":                  {map[string]any{"devOptional": true}, Selection{OS: "linux", CPU: "x64", Omit: []string{"dev", "optional"}}, true},
		"devOptional with dev omitted only is required":   {map[string]any{"devOptional": true}, Selection{OS: "linux", CPU: "x64", Omit: []string{"dev"}}, false},
		"devOptional with opt omitted only is required":   {map[string]any{"devOptional": true}, Selection{OS: "linux", CPU: "x64", Omit: []string{"optional"}}, false},
		"peer omitted":                                    {map[string]any{"peer": true}, Selection{OS: "linux", CPU: "x64", Omit: []string{"peer"}}, true},
		"peer not omitted":                                {map[string]any{"peer": true}, linuxX64, false},
		"dev and optional flags, only optional omitted":   {map[string]any{"dev": true, "optional": true}, Selection{OS: "linux", CPU: "x64", Omit: []string{"optional"}}, true},
		"an env that would omit dev is not the selection": {map[string]any{"dev": true}, linuxX64, false},
	}
	_ = win
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if strings.Contains(name, "env") {
				t.Setenv("NODE_ENV", "production")
				t.Setenv("npm_config_omit", "dev")
			}
			f := newTreeFx(t)
			f.pkg("node_modules/keep", "keep", "1.0.0")
			f.entry("node_modules/x", "x", "1.0.0", tc.members)
			report := f.verify(tc.sel)
			if tc.absent {
				expectProblems(t, report, nil)
				if report.Absent != 1 {
					t.Fatalf("absent = %d, want 1", report.Absent)
				}
				return
			}
			expectProblems(t, report, map[string]string{"node_modules/x": TreeMissing})
		})
	}
}

func TestVerifyTreeAbsentBelowADeselectedPackage(t *testing.T) {
	f := newTreeFx(t)
	f.pkg("node_modules/keep", "keep", "1.0.0")
	f.entry("node_modules/native", "native", "1.0.0", map[string]any{"optional": true, "os": []string{"win32"}})
	f.entry("node_modules/native/node_modules/inner", "inner", "1.0.0")
	expectProblems(t, f.verify(linuxX64), nil)

	// Below a package that is NOT deselected, a missing child is missing.
	g := newTreeFx(t)
	g.pkg("node_modules/keep", "keep", "1.0.0")
	g.entry("node_modules/keep/node_modules/inner", "inner", "1.0.0")
	expectProblems(t, g.verify(linuxX64), map[string]string{"node_modules/keep/node_modules/inner": TreeMissing})
}

// A deselected entry that is present is verified like any other, and a
// directory that is present without a manifest is broken, not absent.
func TestVerifyTreeDeselectedButPresent(t *testing.T) {
	f := newTreeFx(t)
	f.entry("node_modules/native", "native", "1.0.0", map[string]any{"optional": true, "os": []string{"win32"}})
	f.install("node_modules/native", "native", "9.9.9")
	expectProblems(t, f.verify(linuxX64), map[string]string{"node_modules/native": TreeWrongVersion})

	g := newTreeFx(t)
	g.entry("node_modules/native", "native", "1.0.0", map[string]any{"optional": true, "os": []string{"win32"}})
	if err := os.MkdirAll(filepath.Join(g.root, "node_modules/native"), 0o755); err != nil {
		t.Fatal(err)
	}
	expectProblems(t, g.verify(linuxX64), map[string]string{"node_modules/native": TreeManifestMissing})

	h := newTreeFx(t)
	h.pkg("node_modules/native", "native", "1.0.0", map[string]any{"optional": true, "os": []string{"win32"}})
	expectProblems(t, h.verify(linuxX64), nil)
}

func TestVerifyTreeHiddenLockfile(t *testing.T) {
	cases := map[string]struct {
		edit func(f *treeFx)
		want map[string]string
	}{
		"a consistent record": {func(f *treeFx) { f.hiddenLockfile(nil) }, nil},
		"no record at all":    {func(f *treeFx) {}, nil},
		"unreadable": {func(f *treeFx) { f.write("node_modules/.package-lock.json", `{not json`) },
			map[string]string{"node_modules/.package-lock.json": TreeHiddenLockfileUnreadable}},
		"empty": {func(f *treeFx) { f.write("node_modules/.package-lock.json", ``) },
			map[string]string{"node_modules/.package-lock.json": TreeHiddenLockfileUnreadable}},
		"two documents": {func(f *treeFx) { f.write("node_modules/.package-lock.json", `{"lockfileVersion":3,"packages":{}}{}`) },
			map[string]string{"node_modules/.package-lock.json": TreeHiddenLockfileUnreadable}},
		"a repeated member": {func(f *treeFx) {
			f.write("node_modules/.package-lock.json", `{"lockfileVersion":3,"lockfileVersion":3,"packages":{}}`)
		}, map[string]string{"node_modules/.package-lock.json": TreeHiddenLockfileUnreadable}},
		"a symbolic link": {func(f *treeFx) {
			f.write("elsewhere.json", `{"lockfileVersion":3,"packages":{}}`)
			f.symlink("../elsewhere.json", "node_modules/.package-lock.json")
		}, map[string]string{"node_modules/.package-lock.json": TreeHiddenLockfileUnreadable + "+" + TreeHiddenNotAllowed}},
		"no packages member": {func(f *treeFx) { f.write("node_modules/.package-lock.json", `{"lockfileVersion":3}`) },
			map[string]string{"node_modules/.package-lock.json": TreeHiddenLockfileInconsistent}},
		"no lockfile version": {func(f *treeFx) { f.write("node_modules/.package-lock.json", `{"packages":{}}`) },
			map[string]string{"node_modules/.package-lock.json": TreeHiddenLockfileInconsistent}},
		"another version": {func(f *treeFx) {
			f.hiddenLockfile(func(p map[string]any) {
				p["node_modules/a"] = with(entry("a", "1.0.0"), map[string]any{"version": "1.0.1"})
			})
		}, map[string]string{"node_modules/a": TreeWrongVersion}},
		"another resolved location": {func(f *treeFx) {
			f.hiddenLockfile(func(p map[string]any) {
				p["node_modules/a"] = with(entry("a", "1.0.0"), map[string]any{"resolved": "https://evil.example/a-1.0.0.tgz"})
			})
		}, map[string]string{"node_modules/a": TreeWrongOrigin}},
		"no resolved location": {func(f *treeFx) {
			f.hiddenLockfile(func(p map[string]any) {
				p["node_modules/a"] = with(entry("a", "1.0.0"), map[string]any{"resolved": nil})
			})
		}, map[string]string{"node_modules/a": TreeWrongOrigin}},
		"another hash": {func(f *treeFx) {
			f.hiddenLockfile(func(p map[string]any) {
				p["node_modules/a"] = with(entry("a", "1.0.0"), map[string]any{"integrity": integrityOf("other")})
			})
		}, map[string]string{"node_modules/a": TreeWrongOrigin}},
		"no hash": {func(f *treeFx) {
			f.hiddenLockfile(func(p map[string]any) {
				p["node_modules/a"] = with(entry("a", "1.0.0"), map[string]any{"integrity": nil})
			})
		}, map[string]string{"node_modules/a": TreeWrongOrigin}},
		"no version": {func(f *treeFx) {
			f.hiddenLockfile(func(p map[string]any) {
				p["node_modules/a"] = with(entry("a", "1.0.0"), map[string]any{"version": nil})
			})
		}, map[string]string{"node_modules/a": TreeWrongVersion}},
		"a record the lockfile lacks": {func(f *treeFx) {
			f.hiddenLockfile(func(p map[string]any) { p["node_modules/ghost"] = entry("ghost", "1.0.0") })
		}, map[string]string{"node_modules/ghost": TreeHiddenLockfileInconsistent}},
		"a record of a path outside the tree": {func(f *treeFx) {
			f.hiddenLockfile(func(p map[string]any) { p["../../x"] = entry("x", "1.0.0") })
		}, map[string]string{"../../x": TreeHiddenLockfileInconsistent}},
		"a registry entry recorded as a link": {func(f *treeFx) {
			f.hiddenLockfile(func(p map[string]any) { p["node_modules/a"] = map[string]any{"resolved": "elsewhere", "link": true} })
		}, map[string]string{"node_modules/a": TreeHiddenLockfileInconsistent}},
		"an installed entry npm did not record": {func(f *treeFx) {
			f.hiddenLockfile(func(p map[string]any) { delete(p, "node_modules/a") })
		}, map[string]string{"node_modules/a": TreeHiddenLockfileInconsistent}},
		"a record that is not an object": {func(f *treeFx) {
			f.hiddenLockfile(func(p map[string]any) { p["node_modules/a"] = "x" })
		}, map[string]string{"node_modules/.package-lock.json": TreeHiddenLockfileInconsistent, "node_modules/a": TreeHiddenLockfileInconsistent}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := completeTree(t)
			tc.edit(f)
			expectProblems(t, f.verify(linuxX64), tc.want)
		})
	}
}

func TestVerifyTreeRefusesWhatItCannotRead(t *testing.T) {
	f := completeTree(t)
	good := f.lockBytes()
	f.lock["node_modules/l"] = map[string]any{"resolved": "packages/l", "link": true}
	if _, err := VerifyTree(f.lockBytes(), f.root, linuxX64); !errors.Is(err, ErrLinkEntries) {
		t.Fatalf("a lockfile with a link: error = %v, want ErrLinkEntries", err)
	}
	cases := map[string][]byte{
		"not JSON":                       []byte(`{`),
		"version 1":                      []byte(`{"lockfileVersion":1,"dependencies":{}}`),
		"no packages":                    []byte(`{"lockfileVersion":3}`),
		"a repeated member":              []byte(strings.Replace(string(good), `"lockfileVersion":3`, `"lockfileVersion":3,"lockfileVersion":3`, 1)),
		"two documents":                  append(append([]byte{}, good...), good...),
		"an entry that is not an object": []byte(`{"lockfileVersion":3,"packages":{"node_modules/a":"x"}}`),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyTree(raw, f.root, linuxX64); err == nil {
				t.Fatal("VerifyTree() error = nil")
			}
		})
	}
	if _, err := VerifyTree(good, filepath.Join(f.root, "absent"), linuxX64); err == nil {
		t.Fatal("an absent directory is an error, not an empty tree")
	}
	if _, err := VerifyTree(good, f.root, Selection{Omit: []string{"production"}}); err == nil {
		t.Fatal("an unknown omit is an error")
	}
	if _, err := VerifyTree(good, f.root, Selection{Omit: []string{"dev", "dev"}}); err == nil {
		t.Fatal("a repeated omit is an error")
	}
}

func TestVerifyTreeReadsEachSymlinkedAncestorOnce(t *testing.T) {
	// A symlinked parent of a nested entry reports at the link, once, and the
	// entries below it are not read through it.
	f := completeTree(t)
	outside := t.TempDir()
	f.install("elsewhere/a", "a", "1.0.0")
	if err := os.RemoveAll(filepath.Join(f.root, "node_modules/a")); err != nil {
		t.Fatal(err)
	}
	f.symlink(filepath.Join(f.root, "elsewhere/a"), "node_modules/a")
	_ = outside
	got := problemsOf(f.verify(linuxX64))
	if got["node_modules/a"] != TreeSymlink {
		t.Fatalf("problems = %v", got)
	}
}

// A missing required package is not excused by an ancestor that is only
// deselected: the ancestor has to be absent as well.
func TestVerifyTreePresentDeselectedParentDoesNotExcuseAMissingChild(t *testing.T) {
	f := newTreeFx(t)
	f.pkg("node_modules/native", "native", "1.0.0", map[string]any{"optional": true, "os": []string{"win32"}})
	f.entry("node_modules/native/node_modules/inner", "inner", "1.0.0")
	expectProblems(t, f.verify(linuxX64), map[string]string{"node_modules/native/node_modules/inner": TreeMissing})

	// With the parent absent as well, the child is deselected with it.
	g := newTreeFx(t)
	g.entry("node_modules/native", "native", "1.0.0", map[string]any{"optional": true, "os": []string{"win32"}})
	g.entry("node_modules/native/node_modules/inner", "inner", "1.0.0")
	expectProblems(t, g.verify(linuxX64), nil)

	// A parent that is absent without being deselected is its own problem and
	// excuses nothing below it.
	h := newTreeFx(t)
	h.entry("node_modules/needed", "needed", "1.0.0")
	h.entry("node_modules/needed/node_modules/inner", "inner", "1.0.0")
	expectProblems(t, h.verify(linuxX64), map[string]string{
		"node_modules/needed": TreeMissing, "node_modules/needed/node_modules/inner": TreeMissing})
}

// Installed manifests and the lockfiles are read by exact, case-sensitive
// member names, as one document.
func TestVerifyTreeReadsDocumentsByExactNames(t *testing.T) {
	manifests := map[string]string{
		"a second spelling of name":    `{"name":"a","Name":"evil","version":"1.0.0"}`,
		"the only spelling is wrong":   `{"Name":"a","Version":"1.0.0"}`,
		"a second spelling of version": `{"name":"a","version":"1.0.0","VERSION":"9.9.9"}`,
		"a repeated name":              `{"name":"a","name":"a","version":"1.0.0"}`,
		"a stray closing brace":        `{"name":"a","version":"1.0.0"}}`,
		"a second document":            `{"name":"a","version":"1.0.0"}{"name":"a","version":"1.0.0"}`,
		"a name that is not a string":  `{"name":1,"version":"1.0.0"}`,
	}
	for name, content := range manifests {
		t.Run("manifest "+name, func(t *testing.T) {
			f := completeTree(t)
			f.write("node_modules/a/package.json", content)
			report := f.verify(linuxX64)
			if report.Ok {
				t.Fatalf("accepted: %+v", report)
			}
		})
	}
	// Unrelated members stay allowed, in any spelling.
	f := completeTree(t)
	f.write("node_modules/a/package.json", `{"name":"a","version":"1.0.0","Description":"x","description":"y","scripts":{"Test":"x"}}`)
	expectProblems(t, f.verify(linuxX64), nil)

	lockfiles := map[string]func(raw string) string{
		"a second spelling of resolved": func(raw string) string {
			return strings.Replace(raw, `"resolved":`, `"Resolved":"https://evil.example/a.tgz","resolved":`, 1)
		},
		"a repeated member": func(raw string) string {
			return strings.Replace(raw, `"version":"1.0.0"`, `"version":"1.0.0","version":"1.0.0"`, 1)
		},
		"trailing content": func(raw string) string { return raw + "}" },
	}
	for name, edit := range lockfiles {
		t.Run("lockfile "+name, func(t *testing.T) {
			f := completeTree(t)
			if _, err := VerifyTree([]byte(edit(string(f.lockBytes()))), f.root, linuxX64); err == nil {
				t.Fatal("VerifyTree() error = nil")
			}
		})
	}
}

// The hidden lockfile is compared strictly, bundled entries and names included.
// npm 11 records in its hidden lockfile the optional entries it did not
// install for the platform, marked ideallyInert (seen on a real tree: esbuild's
// platform packages). Such a record is consistent with the tree only when the
// entry is provably deselected; the mark alone excuses nothing.
func TestVerifyTreeHiddenRecordOfADeselectedEntry(t *testing.T) {
	inert := func(members map[string]any) func(map[string]any) {
		return func(packages map[string]any) {
			packages["node_modules/o"] = with(with(entry("o", "1.0.0"), members), map[string]any{"ideallyInert": true})
		}
	}
	t.Run("recorded and deselected by the platform", func(t *testing.T) {
		members := map[string]any{"optional": true, "os": []string{"win32"}}
		f := newTreeFx(t)
		f.pkg("node_modules/p", "p", "1.0.0")
		f.entry("node_modules/o", "o", "1.0.0", members)
		f.hiddenLockfile(inert(members))
		if report := f.verify(linuxX64); !report.Ok {
			t.Fatalf("a recorded, absent and deselected entry must verify: %+v", report.Problems)
		}
	})
	t.Run("recorded as inert but required on this platform", func(t *testing.T) {
		members := map[string]any{"optional": true, "os": []string{"linux"}, "cpu": []string{"x64"}}
		f := newTreeFx(t)
		f.pkg("node_modules/p", "p", "1.0.0")
		f.entry("node_modules/o", "o", "1.0.0", members)
		f.hiddenLockfile(inert(members))
		report := f.verify(linuxX64)
		if report.Ok {
			t.Fatalf("an entry required on this platform is missing, whatever npm recorded")
		}
	})
}

func TestVerifyTreeHiddenLockfileStrictness(t *testing.T) {
	full := func(members map[string]any) map[string]any { return with(entry("c", "3.0.0"), members) }
	bundled := map[string]any{"inBundle": true, "resolved": nil, "integrity": nil}
	cases := map[string]struct {
		lockMembers map[string]any
		record      map[string]any
		want        string
	}{
		"a bundled member recorded as the lockfile has it": {
			bundled, map[string]any{"version": "3.0.0", "inBundle": true}, ""},
		"a bundled member recorded with an independent origin": {
			bundled, map[string]any{"version": "3.0.0", "inBundle": true, "resolved": "https://evil.example/c.tgz", "integrity": integrityOf("evil")},
			TreeWrongOrigin},
		"a record that lacks the origin the lockfile has": {
			nil, map[string]any{"version": "3.0.0"}, TreeWrongOrigin},
		"a record that drops the bundle flag": {
			bundled, map[string]any{"version": "3.0.0"}, TreeWrongOrigin},
		"a record that contradicts the recorded name": {
			map[string]any{"name": "c"}, full(map[string]any{"name": "other"}), TreeWrongName},
		"a record that invents a name": {
			nil, full(map[string]any{"name": "other"}), TreeWrongName},
		"a record that spells resolved twice": {
			nil, full(map[string]any{"Resolved": "https://evil.example/c.tgz"}), TreeHiddenLockfileInconsistent},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newTreeFx(t)
			f.pkg("node_modules/p", "p", "1.0.0")
			f.pkg("node_modules/p/node_modules/c", "c", "3.0.0", tc.lockMembers)
			f.hiddenLockfile(func(packages map[string]any) {
				packages["node_modules/p/node_modules/c"] = tc.record
			})
			report := f.verify(linuxX64)
			if tc.want == "" {
				expectProblems(t, report, nil)
				return
			}
			found := false
			for _, problem := range report.Problems {
				found = found || problem.Problem == tc.want
			}
			if !found {
				t.Fatalf("want %s, problems = %+v", tc.want, report.Problems)
			}
		})
	}
}

func TestVerifyTreeStatesItsLimits(t *testing.T) {
	report := completeTree(t).verify(linuxX64)
	if len(report.Limits) == 0 || !strings.Contains(strings.Join(report.Limits, " "), "not the bytes of their files") {
		t.Fatalf("limits = %v", report.Limits)
	}
}

// Lockfiles npm 11 itself writes for a root dependency that is both dev and
// peer, both dev and production, and a production package's peer that is also a
// root dev dependency, are accepted: the flags are the lockfile's own, absence
// is excused on them and on the platform alone, and a complete tree verifies
// whatever the selection.
func TestVerifyTreeAcceptsTheLockfilesNpmWrites(t *testing.T) {
	shapes := map[string]func(f *treeFx){
		"a root dependency that is both dev and peer": func(f *treeFx) {
			f.lock[""] = map[string]any{"name": "root", "devDependencies": map[string]any{"x": "1"}, "peerDependencies": map[string]any{"x": "1"}}
			f.pkg("node_modules/x", "x", "1.0.0", map[string]any{"dev": true, "peer": true})
		},
		"a root dependency that is both dev and production": func(f *treeFx) {
			f.lock[""] = map[string]any{"name": "root", "dependencies": map[string]any{"x": "1"}, "devDependencies": map[string]any{"x": "1"}}
			f.pkg("node_modules/x", "x", "1.0.0")
		},
		"a production package's peer that is also a root dev dependency": func(f *treeFx) {
			f.lock[""] = map[string]any{"name": "root", "dependencies": map[string]any{"app": "1"}, "devDependencies": map[string]any{"shared": "1"}}
			f.pkg("node_modules/app", "app", "1.0.0", map[string]any{"peerDependencies": map[string]any{"shared": "1"}})
			f.pkg("node_modules/shared", "shared", "1.0.0", map[string]any{"dev": true, "peer": true})
		},
	}
	for name, build := range shapes {
		t.Run(name, func(t *testing.T) {
			f := newTreeFx(t)
			build(f)
			f.hiddenLockfile(nil)
			for _, sel := range []Selection{linuxX64, {OS: "linux", CPU: "x64", Omit: []string{"optional"}}} {
				expectProblems(t, f.verify(sel), nil)
			}
			if reason, detail := AdmitLockfile(f.lockBytes()); reason != "" {
				t.Fatalf("a lockfile npm writes was refused: %s %s", reason, detail)
			}
		})
	}
}

// A lockfile whose flags lie yields an incomplete tree, never a foreign or an
// extra package: the flag excuses an absence (the stated limit) and nothing else.
func TestVerifyTreeTrustsFlagsOnlyForAbsence(t *testing.T) {
	f := newTreeFx(t)
	f.entry("node_modules/liar", "liar", "1.0.0", map[string]any{"dev": true})
	sel := Selection{OS: "linux", CPU: "x64", Omit: []string{"dev"}}
	expectProblems(t, f.verify(sel), nil) // absent, excused by its own flag
	f.install("node_modules/liar", "liar", "1.0.1")
	expectProblems(t, f.verify(sel), map[string]string{"node_modules/liar": TreeWrongVersion})
	g := newTreeFx(t)
	g.install("node_modules/extra", "extra", "1.0.0")
	expectProblems(t, g.verify(sel), map[string]string{"node_modules/extra": TreeNotInLockfile})
}

// With both occurrences present in the lockfile, the nested one is judged on
// its own: the top-level one being deselected and absent excuses nothing below
// or beside it.
func TestVerifyTreeNestedConflictKeepsBothOccurrences(t *testing.T) {
	f := newTreeFx(t)
	f.pkg("node_modules/app", "app", "1.0.0")
	f.entry("node_modules/shared", "shared", "2.0.0", map[string]any{"dev": true})
	f.entry("node_modules/app/node_modules/shared", "shared", "1.0.0")
	sel := Selection{OS: "linux", CPU: "x64", Omit: []string{"dev"}}
	expectProblems(t, f.verify(sel), map[string]string{"node_modules/app/node_modules/shared": TreeMissing})
	f.install("node_modules/app/node_modules/shared", "shared", "1.0.0")
	expectProblems(t, f.verify(sel), nil)
}

// A null is not an absent member, a byte-order mark and merge-conflict markers
// are outside the admitted language.
func TestVerifyTreeRefusesNullsBomAndConflictMarkers(t *testing.T) {
	f := completeTree(t)
	good := string(f.lockBytes())
	for name, doc := range map[string]string{
		"a null resolved":   strings.Replace(good, `"resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz"`, `"resolved":null`, 1),
		"a null version":    strings.Replace(good, `"version":"1.0.0"`, `"version":null`, 1),
		"a null flag":       strings.Replace(good, `"version":"1.0.0"`, `"version":"1.0.0","dev":null`, 1),
		"a byte-order mark": "\xef\xbb\xbf" + good,
		"conflict markers":  strings.Replace(good, `"name":"root"`, `"name":"<<<<<<< ======= >>>>>>>"`, 1),
	} {
		if _, err := VerifyTree([]byte(doc), f.root, linuxX64); err == nil {
			t.Errorf("lockfile with %s was accepted", name)
		}
	}
	// Installed manifests: null and BOM refuse; the hidden lockfile too.
	for name, content := range map[string]string{
		"a null version":    `{"name":"a","version":null}`,
		"a byte-order mark": "\xef\xbb\xbf" + `{"name":"a","version":"1.0.0"}`,
	} {
		g := completeTree(t)
		g.write("node_modules/a/package.json", content)
		if g.verify(linuxX64).Ok {
			t.Errorf("manifest with %s was accepted", name)
		}
	}
	h := completeTree(t)
	h.hiddenLockfile(func(p map[string]any) {
		p["node_modules/a"] = map[string]any{"version": "1.0.0", "resolved": nil, "integrity": nil}
	})
	if h.verify(linuxX64).Ok {
		t.Error("a hidden record with null identity fields was accepted")
	}
	k := completeTree(t)
	k.write("node_modules/.package-lock.json", "\xef\xbb\xbf"+`{"lockfileVersion":3,"packages":{}}`)
	if k.verify(linuxX64).Ok {
		t.Error("a hidden lockfile with a byte-order mark was accepted")
	}
}

// The verifier can walk from a held tree descriptor.
func TestVerifyHeldTree(t *testing.T) {
	f := completeTree(t)
	f.hiddenLockfile(nil)
	handle, err := os.Open(filepath.Join(f.root, "node_modules"))
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	held := "/proc/self/fd/" + strconv.Itoa(int(handle.Fd()))
	report, err := VerifyHeldTree(f.lockBytes(), held, linuxX64)
	if err != nil || !report.Ok || report.Checked != 3 {
		t.Fatalf("report = %+v, %v", report, err)
	}
	f.install("node_modules/extra", "extra", "1.0.0")
	report, _ = VerifyHeldTree(f.lockBytes(), held, linuxX64)
	if report.Ok {
		t.Fatal("an extra entry below the held tree was not found")
	}
}

func TestAdmitLockfileFindingsReportsEveryReason(t *testing.T) {
	both := []byte(`{"lockfileVersion":3,"packages":{"":{},"node_modules/l":{"resolved":"packages/l","link":true},"../outside/pkg":{"version":"1.0.0"}}}`)
	findings := AdmitLockfileFindings(both)
	var reasons []string
	for _, f := range findings {
		reasons = append(reasons, f.Reason)
	}
	if len(reasons) != 2 || reasons[0] != ReasonLinksNotSupported || reasons[1] != ReasonLockfilePathsOutside {
		t.Fatalf("findings = %v", reasons)
	}
	if reason, _ := AdmitLockfile(both); reason != ReasonLinksNotSupported {
		t.Fatalf("the binder's first reason changed: %s", reason)
	}
	if got := AdmitLockfileFindings([]byte(`{"lockfileVersion":3,"packages":{"":{},"node_modules/a":{"version":"1.0.0"}}}`)); len(got) != 0 {
		t.Fatalf("a clean lockfile has findings: %v", got)
	}
	if got := AdmitLockfileFindings([]byte(`{"lockfileVersion":3}`)); len(got) != 1 || got[0].Reason != ReasonLockfileUnreadable {
		t.Fatalf("a lockfile without a package map: %v", got)
	}
}

// The verified tree names the direct packages it holds: what a caller may take as installed. A deselected package that is
// absent is not listed, one nested below another is not direct, and a failing verification lists nothing.
func TestVerifyTreeReportsTheDirectPackagesItHolds(t *testing.T) {
	f := newTreeFx(t)
	f.pkg("node_modules/clean", "clean", "2.0.0")
	f.pkg("node_modules/@s/scoped", "@s/scoped", "1.1.0")
	f.pkg("node_modules/clean/node_modules/nested", "nested", "1.0.0")
	f.entry("node_modules/devonly", "devonly", "3.0.0", map[string]any{"dev": true})
	report := f.verify(Selection{OS: "linux", CPU: "x64", Omit: []string{"dev"}})
	if !report.Ok {
		t.Fatalf("%+v", report.Problems)
	}
	var got []string
	for _, present := range report.Present {
		got = append(got, present.Name+"@"+present.Version+" "+present.Path)
	}
	want := []string{"@s/scoped@1.1.0 node_modules/@s/scoped", "clean@2.0.0 node_modules/clean"}
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("present = %v, want %v", got, want)
	}
	// the same lockfile with the deselected root installed (a stray copy) is verified like any entry, and then it IS held
	f.install("node_modules/devonly", "devonly", "3.0.0")
	if report = f.verify(Selection{OS: "linux", CPU: "x64", Omit: []string{"dev"}}); len(report.Present) != 3 {
		t.Fatalf("%+v", report.Present)
	}
	// a failing verification lists nothing
	g := newTreeFx(t)
	g.entry("node_modules/clean", "clean", "2.0.0")
	if report = g.verify(linuxX64); report.Ok || len(report.Present) != 0 {
		t.Fatalf("%+v", report)
	}
}
