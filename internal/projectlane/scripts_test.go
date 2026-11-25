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

func TestScriptsTreeReadsWhatIsOnDisk(t *testing.T) {
	tree := t.TempDir()
	writePackage(t, tree, "a", `{"scripts":{"preinstall":"x","install":"y","postinstall":"z","test":"t"}}`)
	writePackage(t, tree, "pre-gyp", `{"scripts":{"preinstall":"x"}}`, "binding.gyp")     // its own preinstall: no implicit build
	writePackage(t, tree, "post-gyp", `{"scripts":{"postinstall":"x"}}`, "binding.gyp")   // postinstall alone still builds
	writePackage(t, tree, "install-gyp", `{"scripts":{"install":"x"}}`, "binding.gyp")    // its own install: no implicit build
	writePackage(t, tree, "off-gyp", `{"gypfile":false}`, "binding.gyp")                  // gypfile false: none
	writePackage(t, tree, "plain-gyp", `{}`, "binding.gyp")                               // the implicit build
	writePackage(t, tree, "prepare-only", `{"scripts":{"prepare":"x","prepublish":"y"}}`) // not install-time of a dependency
	writePackage(t, tree, "empty-script", `{"scripts":{"install":""}}`)                   // an empty script is no script
	lock := lockOf(map[string]string{
		"node_modules/a": entryOf("1.0.0", `,"hasInstallScript":true`), "node_modules/pre-gyp": entryOf("1.0.0", ""),
		"node_modules/post-gyp": entryOf("1.0.0", ""), "node_modules/install-gyp": entryOf("1.0.0", ""), "node_modules/off-gyp": entryOf("1.0.0", ""),
		"node_modules/plain-gyp": entryOf("1.0.0", ""), "node_modules/prepare-only": entryOf("1.0.0", ""), "node_modules/empty-script": entryOf("1.0.0", ""),
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
		native   bool
		declared bool
	}{
		"node_modules/a":           {[]string{"preinstall", "install", "postinstall"}, false, true},
		"node_modules/pre-gyp":     {[]string{"preinstall"}, false, false},
		"node_modules/post-gyp":    {[]string{"postinstall"}, true, false},
		"node_modules/install-gyp": {[]string{"install"}, false, false},
		"node_modules/plain-gyp":   {[]string{}, true, false},
	}
	if len(got) != len(want) || report.Total != len(want) || report.Source != ScriptsSource {
		t.Fatalf("packages %v total %d source %s", pathsOf(report), report.Total, report.Source)
	}
	for key, w := range want {
		p, ok := got[key]
		if !ok || !reflect.DeepEqual(p.Events, w.events) || p.Native != w.native || p.Declared != w.declared {
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

func TestScriptsBundledMemberIsNamedWithItsHostAndRebuiltThroughTheOutermost(t *testing.T) {
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
	if p.Name != "leaf" || p.Version != "4.0.0" || p.Host != "mid@3.0.0" || p.RebuildPath != "node_modules/host" {
		t.Fatalf("%+v", p)
	}
}

func TestScriptsIntroducedAgainstThePreviousTree(t *testing.T) {
	tree := t.TempDir()
	for _, n := range []string{"same", "moved", "fresh"} {
		writePackage(t, tree, n, `{"scripts":{"install":"x"}}`)
	}
	lock := lockOf(map[string]string{"node_modules/same": entryOf("1.0.0", ""), "node_modules/moved": entryOf("2.0.0", ""), "node_modules/fresh": entryOf("1.0.0", "")})
	previous := lockOf(map[string]string{"node_modules/same": entryOf("1.0.0", ""), "node_modules/moved": entryOf("1.0.0", "")})
	report, _ := ReadScripts(ScriptsRequest{Lock: lock, TreeRoot: tree, Previous: previous})
	if !reflect.DeepEqual(pathsOf(report), []string{"node_modules/fresh", "node_modules/moved"}) || report.Previous != "read" {
		t.Fatalf("%v %s", pathsOf(report), report.Previous)
	}
	// a changed integrity at the same version is a change
	changed := lockOf(map[string]string{"node_modules/same": strings.Replace(entryOf("1.0.0", ""), "AAAA", "BBBB", 1)})
	report, _ = ReadScripts(ScriptsRequest{Lock: lock, TreeRoot: tree, Previous: changed})
	if !reflect.DeepEqual(pathsOf(report), []string{"node_modules/fresh", "node_modules/moved", "node_modules/same"}) {
		t.Fatalf("an integrity that changed was not introduced: %v", pathsOf(report))
	}
	// ci builds a whole tree: the previous one is ignored; an unreadable one makes everything new
	report, _ = ReadScripts(ScriptsRequest{Lock: lock, TreeRoot: tree, Previous: previous, All: true})
	if len(report.Packages) != 3 {
		t.Fatalf("ci: %v", pathsOf(report))
	}
	report, _ = ReadScripts(ScriptsRequest{Lock: lock, TreeRoot: tree, Previous: []byte("{not json")})
	if len(report.Packages) != 3 || report.Previous != "unreadable" {
		t.Fatalf("unreadable previous: %v %s", pathsOf(report), report.Previous)
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
	for _, p := range report.Packages {
		switch p.Name {
		case "linked-manifest", "fifo-manifest", "dup", "array", "link-dir":
			if !p.Unread || len(p.Events) != 0 {
				t.Fatalf("%s was read: %+v", p.Name, p)
			}
		case "evil":
			if p.Version != "?" || len(p.Events) != 1 {
				t.Fatalf("a hostile version is printable: %+v", p)
			}
		default:
			t.Fatalf("unexpected %+v", p)
		}
	}
	if len(report.Packages) != 6 {
		t.Fatalf("%v", pathsOf(report))
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
	if err != nil || report.Root == nil || !reflect.DeepEqual(report.Root.Events, []string{"postinstall", "prepare", "postprepare"}) || report.Root.Native {
		t.Fatalf("%+v %v", report.Root, err)
	}
	// a binding.gyp at the root with no install or preinstall script is the implicit native build
	if err := os.WriteFile(filepath.Join(dir, "binding.gyp"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	report, _ = ReadScripts(ScriptsRequest{Lock: lockOf(nil), RootManifest: []byte(`{"name":"p"}`), RootDir: dir})
	if report.Root == nil || !report.Root.Native {
		t.Fatalf("%+v", report.Root)
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
