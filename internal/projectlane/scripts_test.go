package projectlane

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"syscall"
	"testing"
)

// lockOf builds a version 3 lockfile from install path -> entry members (JSON text).
func lockOf(entries map[string]string) []byte {
	var b strings.Builder
	b.WriteString(`{"lockfileVersion":3,"packages":{"":{"name":"p","version":"1.0.0"}`)
	for key, body := range entries {
		fmt.Fprintf(&b, `,%q:%s`, key, body)
	}
	b.WriteString(`}}`)
	return []byte(b.String())
}

func entryOf(version string, extra string) string {
	return fmt.Sprintf(`{"version":%q,"resolved":"https://registry.npmjs.org/x/-/x-%s.tgz","integrity":"sha512-AAAA"%s}`, version, version, extra)
}

func writePackage(t *testing.T, tree, rel, manifest string, files ...string) string {
	t.Helper()
	dir := filepath.Join(tree, filepath.FromSlash(rel))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if manifest != "" {
		if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(manifest), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(dir, f), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func pathsOf(r ScriptsReport) []string {
	out := []string{}
	for _, p := range r.Packages {
		out = append(out, p.Path)
	}
	return out
}

// The reader states what is on disk: a package is listed when its own files hold a preinstall, install or postinstall script or a
// binding.gyp file; gypfile, the scripts beside the file and the lockfile flag decide nothing about whether it is listed.
func TestScriptsTreeReadsWhatIsOnDisk(t *testing.T) {
	tree := t.TempDir()
	writePackage(t, tree, "a", `{"scripts":{"preinstall":"x","install":"y","postinstall":"z","test":"t"}}`)
	writePackage(t, tree, "pre-gyp", `{"scripts":{"preinstall":"x"}}`, "binding.gyp")
	writePackage(t, tree, "post-gyp", `{"scripts":{"postinstall":"x"}}`, "binding.gyp")
	writePackage(t, tree, "install-gyp", `{"scripts":{"install":"x"}}`, "binding.gyp")
	writePackage(t, tree, "off-gyp", `{"gypfile":false}`, "binding.gyp") // npm builds it anyway from a lockfile that declares it: listed
	writePackage(t, tree, "plain-gyp", `{}`, "binding.gyp")
	writePackage(t, tree, "prepare-only", `{"scripts":{"prepare":"x","prepublish":"y"}}`) // not install-time of a dependency
	writePackage(t, tree, "empty-script", `{"scripts":{"install":""}}`)                   // an empty script is no script
	writePackage(t, tree, "dir-gyp", `{}`)                                                // a DIRECTORY named binding.gyp is no file
	if err := os.Mkdir(filepath.Join(tree, "dir-gyp", "binding.gyp"), 0o755); err != nil {
		t.Fatal(err)
	}
	writePackage(t, tree, "link-gyp", `{}`, "real.gyp")
	if err := os.Symlink("real.gyp", filepath.Join(tree, "link-gyp", "binding.gyp")); err != nil {
		t.Fatal(err)
	}
	lock := lockOf(map[string]string{
		"node_modules/a": entryOf("1.0.0", `,"hasInstallScript":true`), "node_modules/pre-gyp": entryOf("1.0.0", ""),
		"node_modules/post-gyp": entryOf("1.0.0", ""), "node_modules/install-gyp": entryOf("1.0.0", `,"hasInstallScript":true`), "node_modules/off-gyp": entryOf("1.0.0", `,"hasInstallScript":true`),
		"node_modules/plain-gyp": entryOf("1.0.0", ""), "node_modules/prepare-only": entryOf("1.0.0", ""), "node_modules/empty-script": entryOf("1.0.0", ""),
		"node_modules/dir-gyp": entryOf("1.0.0", ""), "node_modules/link-gyp": entryOf("1.0.0", ""),
		"node_modules/gone": entryOf("1.0.0", `,"hasInstallScript":true`), // omitted: not in the tree
	})
	report, err := ReadScripts(ScriptsRequest{Lock: lock, TreeRoot: tree})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]ScriptPackage{}
	for _, p := range report.Packages {
		got[p.Path] = p
	}
	want := map[string]struct {
		events   []string
		gyp      bool
		declared bool
	}{
		"node_modules/a":           {[]string{"preinstall", "install", "postinstall"}, false, true},
		"node_modules/pre-gyp":     {[]string{"preinstall"}, true, false},
		"node_modules/post-gyp":    {[]string{"postinstall"}, true, false},
		"node_modules/install-gyp": {[]string{"install"}, true, true},
		"node_modules/off-gyp":     {[]string{}, true, true},
		"node_modules/plain-gyp":   {[]string{}, true, false},
		"node_modules/link-gyp":    {[]string{}, true, false}, // a link to a file is a file, as npm sees it
	}
	if len(got) != len(want) || report.Total != len(want) || report.UnreadTotal != 0 || report.Source != ScriptsSource || report.SchemaVersion != 3 {
		t.Fatalf("packages %v unread %v", pathsOf(report), report.UnreadTotal)
	}
	for key, w := range want {
		p, ok := got[key]
		if !ok || !reflect.DeepEqual(p.Events, w.events) || p.Gyp != w.gyp || p.Declared != w.declared {
			t.Fatalf("%s: %+v, want %+v", key, p, w)
		}
	}
}

func TestScriptsLockfileAloneUsesTheDeclaredFlag(t *testing.T) {
	lock := lockOf(map[string]string{"node_modules/a": entryOf("1.0.0", `,"hasInstallScript":true`), "node_modules/b": entryOf("1.0.0", `,"hasInstallScript":false`), "node_modules/c": entryOf("1.0.0", "")})
	report, err := ReadScripts(ScriptsRequest{Lock: lock})
	if err != nil || report.Source != ScriptsLock || !reflect.DeepEqual(pathsOf(report), []string{"node_modules/a"}) {
		t.Fatalf("%+v %v", report, err)
	}
}

func TestScriptsBundledMemberIsNamedWithItsOutermostHostAndRebuiltThroughIt(t *testing.T) {
	tree := t.TempDir()
	writePackage(t, tree, "host", `{}`)
	writePackage(t, tree, "host/node_modules/mid", `{}`)
	writePackage(t, tree, "host/node_modules/mid/node_modules/leaf", `{"scripts":{"postinstall":"x"}}`)
	lock := lockOf(map[string]string{
		"node_modules/host":                                    entryOf("2.0.0", ""),
		"node_modules/host/node_modules/mid":                   entryOf("3.0.0", `,"inBundle":true`),
		"node_modules/host/node_modules/mid/node_modules/leaf": entryOf("4.0.0", `,"inBundle":true,"hasInstallScript":true`),
	})
	report, err := ReadScripts(ScriptsRequest{Lock: lock, TreeRoot: tree})
	if err != nil || len(report.Packages) != 1 {
		t.Fatalf("%+v %v", report, err)
	}
	p := report.Packages[0]
	if p.Name != "leaf" || p.Version != "4.0.0" || p.Host != "host@2.0.0" || p.RebuildPath != "node_modules/host" {
		t.Fatalf("%+v", p)
	}
}

// A bundled entry has no resolved location and no integrity: its bytes come from the tarball of its outermost host. The member is
// introduced when that host's artifact is, whatever its own entry says (the family "a bundled member judged apart from its host").
func TestScriptsBundledMemberIsIntroducedWhenItsHostIs(t *testing.T) {
	tree := t.TempDir()
	writePackage(t, tree, "host", `{}`)
	writePackage(t, tree, "host/node_modules/mid", `{}`)
	writePackage(t, tree, "host/node_modules/mid/node_modules/leaf", `{"scripts":{"postinstall":"x"}}`)
	writePackage(t, tree, "alone/node_modules/leaf2", `{"scripts":{"postinstall":"x"}}`)
	build := func(hostEntry string, mid, leaf string) []byte {
		return lockOf(map[string]string{
			"node_modules/host":                                    hostEntry,
			"node_modules/host/node_modules/mid":                   mid,
			"node_modules/host/node_modules/mid/node_modules/leaf": leaf,
		})
	}
	bundled := func(v string) string { return entryOf(v, `,"inBundle":true`) }
	member := strings.Replace(bundled("1.0.0"), `"resolved":"https://registry.npmjs.org/x/-/x-1.0.0.tgz","integrity":"sha512-AAAA",`, "", 1)
	if member == bundled("1.0.0") {
		member = `{"version":"1.0.0","inBundle":true,"hasInstallScript":true}`
	}
	leaf := `{"version":"1.0.0","inBundle":true,"hasInstallScript":true}`
	mid := `{"version":"1.0.0","inBundle":true}`
	previous := build(entryOf("1.0.0", ""), mid, leaf)
	cases := []struct {
		name string
		lock []byte
		want []string
	}{
		{"host unchanged, members unchanged: nothing", build(entryOf("1.0.0", ""), mid, leaf), nil},
		{"host version changed, member entries identical", build(entryOf("2.0.0", ""), mid, leaf), []string{"node_modules/host/node_modules/mid/node_modules/leaf"}},
		{"host integrity changed at the same version", build(strings.Replace(entryOf("1.0.0", ""), "AAAA", "BBBB", 1), mid, leaf), []string{"node_modules/host/node_modules/mid/node_modules/leaf"}},
		{"host resolved changed at the same version", build(strings.Replace(entryOf("1.0.0", ""), "registry.npmjs.org", "other.example", 1), mid, leaf), []string{"node_modules/host/node_modules/mid/node_modules/leaf"}},
		{"the member's own entry changed under an unchanged host", build(entryOf("1.0.0", ""), mid, `{"version":"1.1.0","inBundle":true,"hasInstallScript":true}`), []string{"node_modules/host/node_modules/mid/node_modules/leaf"}},
	}
	for _, c := range cases {
		report, err := ReadScripts(ScriptsRequest{Lock: c.lock, TreeRoot: tree, Previous: previous})
		got := []string{}
		for _, p := range report.Packages {
			got = append(got, p.Path)
		}
		if err != nil || report.Previous != "read" || !reflect.DeepEqual(got, append([]string{}, c.want...)) {
			t.Fatalf("%s: %v %v (%s)", c.name, got, err, report.Previous)
		}
	}
	// a member whose host is not in the previous record at all is introduced
	report, _ := ReadScripts(ScriptsRequest{Lock: build(entryOf("1.0.0", ""), mid, leaf), TreeRoot: tree, Previous: lockOf(map[string]string{"node_modules/other": entryOf("1.0.0", "")})})
	if len(report.Packages) != 1 {
		t.Fatalf("a member of a new host: %v", pathsOf(report))
	}
}

func TestScriptsIntroducedAgainstThePreviousTree(t *testing.T) {
	tree := t.TempDir()
	for _, n := range []string{"same", "moved", "fresh"} {
		writePackage(t, tree, n, `{"scripts":{"install":"x"}}`)
	}
	lock := lockOf(map[string]string{"node_modules/same": entryOf("1.0.0", `,"hasInstallScript":true`), "node_modules/moved": entryOf("2.0.0", `,"hasInstallScript":true`), "node_modules/fresh": entryOf("1.0.0", `,"hasInstallScript":true`)})
	previous := lockOf(map[string]string{"node_modules/same": entryOf("1.0.0", `,"hasInstallScript":true`), "node_modules/moved": entryOf("1.0.0", `,"hasInstallScript":true`)})
	report, _ := ReadScripts(ScriptsRequest{Lock: lock, TreeRoot: tree, Previous: previous})
	if !reflect.DeepEqual(pathsOf(report), []string{"node_modules/fresh", "node_modules/moved"}) || report.Previous != "read" {
		t.Fatalf("%v %s", pathsOf(report), report.Previous)
	}
	// a changed integrity at the same version is a change
	changed := lockOf(map[string]string{"node_modules/same": strings.Replace(entryOf("1.0.0", `,"hasInstallScript":true`), "AAAA", "BBBB", 1)})
	report, _ = ReadScripts(ScriptsRequest{Lock: lock, TreeRoot: tree, Previous: changed})
	if !reflect.DeepEqual(pathsOf(report), []string{"node_modules/fresh", "node_modules/moved", "node_modules/same"}) {
		t.Fatalf("an integrity that changed was not introduced: %v", pathsOf(report))
	}
	// no previous record (what `ci` is given, since it builds a whole tree) makes everything new; an unreadable one too, and says so
	report, _ = ReadScripts(ScriptsRequest{Lock: lock, TreeRoot: tree})
	if len(report.Packages) != 3 || report.Previous != "none" {
		t.Fatalf("no record: %v %s", pathsOf(report), report.Previous)
	}
	for _, req := range []ScriptsRequest{{Lock: lock, TreeRoot: tree, Previous: []byte("{")}, {Lock: lock, TreeRoot: tree, PreviousUnreadable: true}} {
		report, _ = ReadScripts(req)
		if len(report.Packages) != 3 || report.Previous != "unreadable" {
			t.Fatalf("unreadable previous: %v %s", pathsOf(report), report.Previous)
		}
	}
}

func TestScriptsHostileInputsAreNotTrusted(t *testing.T) {
	tree := t.TempDir()
	// package.json that is a link, a FIFO, duplicated members, not an object; a directory that is a link; a hostile version
	writePackage(t, tree, "linked-manifest", "")
	if err := os.Symlink("/etc/hostname", filepath.Join(tree, "linked-manifest", "package.json")); err != nil {
		t.Fatal(err)
	}
	writePackage(t, tree, "fifo-manifest", "")
	if err := syscall.Mkfifo(filepath.Join(tree, "fifo-manifest", "package.json"), 0o644); err != nil {
		t.Fatal(err)
	}
	writePackage(t, tree, "dup", `{"scripts":{"install":"x"},"scripts":{}}`)
	writePackage(t, tree, "array", `[]`)
	writePackage(t, tree, "target", `{"scripts":{"install":"x"}}`)
	if err := os.Symlink(filepath.Join(tree, "target"), filepath.Join(tree, "link-dir")); err != nil {
		t.Fatal(err)
	}
	writePackage(t, tree, "evil", `{"scripts":{"install":"x"}}`)
	lock := lockOf(map[string]string{
		"node_modules/linked-manifest": entryOf("1.0.0", ""), "node_modules/fifo-manifest": entryOf("1.0.0", ""), "node_modules/dup": entryOf("1.0.0", ""),
		"node_modules/array": entryOf("1.0.0", ""), "node_modules/link-dir": entryOf("1.0.0", ""),
		"node_modules/evil": entryOf("1.0.0\\u001b[31m\\n\\u009b", ""),
	})
	report, err := ReadScripts(ScriptsRequest{Lock: lock, TreeRoot: tree})
	if err != nil {
		t.Fatal(err)
	}
	// a package that cannot be read is never among those that have scripts
	unread := map[string]bool{}
	for _, p := range report.Unread {
		unread[p.Name] = true
		if len(p.Events) != 0 || p.Gyp {
			t.Fatalf("%s was read: %+v", p.Name, p)
		}
	}
	for _, name := range []string{"linked-manifest", "fifo-manifest", "dup", "array", "link-dir"} {
		if !unread[name] {
			t.Fatalf("%s is not among the unread: %v", name, report.Unread)
		}
	}
	if len(report.Packages) != 1 || report.Packages[0].Name != "evil" || report.Packages[0].Version != "?" || report.Packages[0].Declared || report.UnreadTotal != 5 {
		t.Fatalf("packages %+v unread %d", report.Packages, report.UnreadTotal)
	}
}

func TestScriptsLimitKeepsTheTotal(t *testing.T) {
	entries := map[string]string{}
	for i := 0; i < 30; i++ {
		entries[fmt.Sprintf("node_modules/p%02d", i)] = entryOf("1.0.0", `,"hasInstallScript":true`)
	}
	report, _ := ReadScripts(ScriptsRequest{Lock: lockOf(entries), Limit: 25})
	if report.Total != 30 || len(report.Packages) != 25 || report.Packages[0].Path != "node_modules/p00" {
		t.Fatalf("%d %d", report.Total, len(report.Packages))
	}
}

func TestScriptsRootInstallTimeScripts(t *testing.T) {
	dir := t.TempDir()
	manifest := []byte(`{"name":"p","scripts":{"postinstall":"a","prepare":"b","postprepare":"c","test":"d","build":"e"}}`)
	report, err := ReadScripts(ScriptsRequest{Lock: lockOf(nil), RootManifest: manifest, RootDir: dir})
	if err != nil || report.Root == nil || !reflect.DeepEqual(report.Root.Events, []string{"postinstall", "prepare", "postprepare"}) || report.Root.Gyp {
		t.Fatalf("%+v %v", report.Root, err)
	}
	// a binding.gyp file at the root is a fact of the project, whatever scripts it has
	if err := os.WriteFile(filepath.Join(dir, "binding.gyp"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	report, _ = ReadScripts(ScriptsRequest{Lock: lockOf(nil), RootManifest: []byte(`{"name":"p"}`), RootDir: dir})
	if report.Root == nil || !report.Root.Gyp {
		t.Fatalf("%+v", report.Root)
	}
	// a directory of that name is no native build, for the project as for a package
	dirRoot := t.TempDir()
	if err := os.Mkdir(filepath.Join(dirRoot, "binding.gyp"), 0o755); err != nil {
		t.Fatal(err)
	}
	report, _ = ReadScripts(ScriptsRequest{Lock: lockOf(nil), RootManifest: []byte(`{"name":"p"}`), RootDir: dirRoot})
	if report.Root == nil || report.Root.Gyp {
		t.Fatalf("a directory named binding.gyp is a binding.gyp of the project: %+v", report.Root)
	}
	if _, err := ReadScripts(ScriptsRequest{Lock: lockOf(nil), RootManifest: []byte(`{"scripts":{"a":"x","a":"y"}}`), RootDir: dir}); err == nil {
		t.Fatal("a manifest with a repeated member was read")
	}
}

func TestScriptsLinkEntriesAreRefused(t *testing.T) {
	lock := lockOf(map[string]string{"node_modules/l": `{"resolved":"../l","link":true}`})
	if _, err := ReadScripts(ScriptsRequest{Lock: lock}); err == nil {
		t.Fatal("a lockfile with a link entry was read")
	}
}

// The report prints a command line the operator may paste into a shell (npm rebuild ./<install path>). Only an install path of npm's
// own grammar reaches it: a key that carries shell syntax, an option, a traversal or a control character is not a package of the tree
// and names nothing in the report, read from the tree or from the lockfile alone, as a package or as the host of a bundled member.
func TestScriptsOnlyAnInstallPathReachesTheCommandLine(t *testing.T) {
	tree := t.TempDir()
	hostile := []string{"node_modules/x; touch pwned", "node_modules/$(id)", "node_modules/`id`", "node_modules/-rf", "node_modules/a b",
		"node_modules/..", "node_modules/ok/../../y", "node_modules/q'uote", "node_modules/in&ner", "node_modules/@s/x;y", "node_modules/.hidden",
		"node_modules/nl\nline", "node_modules/\x1b[31mred", "node_modules/x|y", "node_modules/x>y", "node_modules/x*", "node_modules/x\\y",
		"node_modules/\"quoted\"", "node_modules/x=y", "node_modules/x#y", "node_modules/{a,b}", "node_modules/x!y"}
	script := `{"scripts":{"install":"x"}}`
	entry := entryOf("1.0.0", `,"hasInstallScript":true`)
	member := entryOf("1.0.0", `,"hasInstallScript":true,"inBundle":true`)
	var b strings.Builder
	b.WriteString(`{"lockfileVersion":3,"packages":{"":{"name":"p","version":"1.0.0"},"node_modules/ok":` + entry + `,"node_modules/@s/ok":` + entry)
	writePackage(t, tree, "ok", script)
	writePackage(t, tree, "@s/ok", script)
	for _, key := range hostile {
		for _, k := range []string{key, key + "/node_modules/member"} {
			quoted, err := json.Marshal(k)
			if err != nil {
				t.Fatal(err)
			}
			body := entry
			if k != key {
				body = member
			}
			fmt.Fprintf(&b, `,%s:%s`, quoted, body)
		}
		// the directory exists where the file system takes the name (never one that leaves the tree)
		if rel := strings.TrimPrefix(key, "node_modules/"); !strings.Contains(rel, "..") {
			dir := filepath.Join(tree, rel)
			if os.MkdirAll(filepath.Join(dir, "node_modules", "member"), 0o755) == nil {
				_ = os.WriteFile(filepath.Join(dir, "package.json"), []byte(script), 0o644)
				_ = os.WriteFile(filepath.Join(dir, "node_modules", "member", "package.json"), []byte(script), 0o644)
			}
		}
	}
	b.WriteString(`}}`)
	lock := []byte(b.String())
	pasted := regexp.MustCompile(`^node_modules/[A-Za-z0-9@~][A-Za-z0-9._~@/-]*$`)
	for _, req := range []ScriptsRequest{{Lock: lock, TreeRoot: tree}, {Lock: lock}} {
		report, err := ReadScripts(req)
		if err != nil {
			t.Fatal(err)
		}
		if got := pathsOf(report); !reflect.DeepEqual(got, []string{"node_modules/@s/ok", "node_modules/ok"}) {
			t.Fatalf("tree %q: a key that is not an install path is in the report: %q", req.TreeRoot, got)
		}
		for _, p := range report.Packages {
			if !pasted.MatchString(p.RebuildPath) || strings.Contains(p.RebuildPath, "..") || p.Host != "" {
				t.Fatalf("tree %q: %+v", req.TreeRoot, p)
			}
		}
	}
}

// A previous record that cannot be read from its file (the reader's own read, not the gate's copy) is said, not taken for none.
func TestScriptsFilesPreviousRecordThatCannotBeReadIsSaid(t *testing.T) {
	dir := t.TempDir()
	lockFile := filepath.Join(dir, "package-lock.json")
	if err := os.WriteFile(lockFile, lockOf(map[string]string{"node_modules/a": entryOf("1.0.0", `,"hasInstallScript":true`)}), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := ReadScriptsFiles(lockFile, filepath.Join(dir, "missing.json"), "", ScriptsRequest{})
	if err != nil || report.Previous != "unreadable" || len(report.Packages) != 1 {
		t.Fatalf("%+v %v", report, err)
	}
	report, err = ReadScriptsFiles(lockFile, "", "", ScriptsRequest{})
	if err != nil || report.Previous != "none" {
		t.Fatalf("%+v %v", report, err)
	}
}
