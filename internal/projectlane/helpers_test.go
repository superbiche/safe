package projectlane

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// integrityOf returns a well-formed sha512 token that is a function of seed, so
// a test can make two artifacts differ in hash only.
func integrityOf(seed string) string {
	sum := sha512.Sum512([]byte(seed))
	return "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
}

func tarball(name, version string) string {
	unscoped := name
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == '/' {
			unscoped = name[i+1:]
			break
		}
	}
	return "https://registry.npmjs.org/" + name + "/-/" + unscoped + "-" + version + ".tgz"
}

// entry is a canonical, bound registry entry unless a test edits it.
func entry(name, version string) map[string]any {
	return map[string]any{
		"version":   version,
		"resolved":  tarball(name, version),
		"integrity": integrityOf(name + "@" + version),
	}
}

// with returns a copy of an entry with the given members set (nil deletes).
func with(base map[string]any, members map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range members {
		if v == nil {
			delete(out, k)
		} else {
			out[k] = v
		}
	}
	return out
}

// writeLock writes a lockfileVersion 3 file from path-keyed entries.
func writeLock(t *testing.T, packages map[string]map[string]any) string {
	t.Helper()
	all := map[string]any{"": map[string]any{"name": "root", "version": "1.0.0"}}
	for path, e := range packages {
		all[path] = e
	}
	data, err := json.Marshal(map[string]any{"lockfileVersion": 3, "packages": all})
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "package-lock.json")
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

func graphOf(t *testing.T, packages map[string]map[string]any) Graph {
	t.Helper()
	graph, err := LoadGraph(writeLock(t, packages), nil)
	if err != nil {
		t.Fatalf("LoadGraph() error = %v", err)
	}
	return graph
}

// pkgs builds path-keyed entries for name@version pairs installed at the top.
func pkgs(pairs ...string) map[string]map[string]any {
	out := map[string]map[string]any{}
	for i := 0; i+1 < len(pairs); i += 2 {
		out["node_modules/"+pairs[i]] = entry(pairs[i], pairs[i+1])
	}
	return out
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
