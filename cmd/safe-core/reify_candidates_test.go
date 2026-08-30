package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeReifyProject(t *testing.T, lockfile string) (dir, lockfilePath string) {
	t.Helper()
	dir = t.TempDir()
	lockfilePath = filepath.Join(dir, "package-lock.json")
	if err := os.WriteFile(lockfilePath, []byte(lockfile), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, lockfilePath
}

func TestReifyCandidatesUsageFailuresWriteNoJSON(t *testing.T) {
	dir, lockfile := writeReifyProject(t, `{"lockfileVersion":3,"packages":{}}`)

	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "no positionals", args: []string{"reify-candidates"}},
		{name: "one positional", args: []string{"reify-candidates", lockfile}},
		{name: "three positionals", args: []string{"reify-candidates", lockfile, dir, dir}},
		{name: "registry host without a value", args: []string{"reify-candidates", "--registry-host", lockfile, dir}},
		{name: "unknown option", args: []string{"reify-candidates", "--tree", lockfile, dir}},
		{name: "os without a value", args: []string{"reify-candidates", lockfile, dir, "--os"}},
		{name: "os with an empty value", args: []string{"reify-candidates", "--os", "", lockfile, dir}},
		{name: "os with an empty glued value", args: []string{"reify-candidates", "--os=", lockfile, dir}},
		{name: "cpu without a value", args: []string{"reify-candidates", lockfile, dir, "--cpu"}},
		{name: "cpu with an empty glued value", args: []string{"reify-candidates", "--cpu=", lockfile, dir}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run(tc.args, strings.NewReader(""), &stdout, &stderr); got != 2 {
				t.Fatalf("run() = %d, want 2", got)
			}
			if stdout.Len() != 0 || !strings.Contains(stderr.String(), "usage: safe-core reify-candidates") {
				t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
		})
	}
}

// An unreadable project directory is exit 3, never an empty candidate set: it
// is breakage in the tooling, and "nothing to fetch" there would vouch for a
// tree nobody read.
func TestReifyCandidatesRefusesAnUnreadableProject(t *testing.T) {
	dir, lockfile := writeReifyProject(t, `{"lockfileVersion":3,"packages":{}}`)

	for _, tc := range []struct {
		name       string
		projectDir string
	}{
		{name: "absent", projectDir: filepath.Join(dir, "absent")},
		{name: "not a directory", projectDir: lockfile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run([]string{"reify-candidates", lockfile, tc.projectDir}, strings.NewReader(""), &stdout, &stderr); got != 3 {
				t.Fatalf("run() = %d, want 3", got)
			}
			if stdout.Len() != 0 || !strings.Contains(stderr.String(), "reify-candidates") {
				t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
		})
	}
}

func TestReifyCandidatesParseFailureWritesNoJSON(t *testing.T) {
	dir, lockfile := writeReifyProject(t, `{"lockfileVersion":1}`)

	var stdout, stderr bytes.Buffer
	if got := run([]string{"reify-candidates", lockfile, dir}, strings.NewReader(""), &stdout, &stderr); got != 3 {
		t.Fatalf("run() = %d, want 3", got)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "lockfileVersion 1") {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestReifyCandidatesWritesOnlyOneJSONDocument(t *testing.T) {
	dir, lockfile := writeReifyProject(t, `{"lockfileVersion":3,"packages":{
	  "":{"name":"reify-test","version":"1.0.0"},
	  "node_modules/present":{"version":"1.0.0"},
	  "node_modules/gone":{"version":"2.0.0","resolved":"https://registry.npmjs.org/gone/-/gone-2.0.0.tgz","integrity":"sha512-gone"}
	}}`)
	present := filepath.Join(dir, "node_modules", "present")
	if err := os.MkdirAll(present, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(present, "package.json"), []byte(`{"version":"1.0.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if got := run([]string{"reify-candidates", lockfile, dir}, strings.NewReader(""), &stdout, &stderr); got != 0 {
		t.Fatalf("run() = %d, stderr=%q", got, stderr.String())
	}
	want := "{\"schema\":1,\"candidates\":[{\"path\":\"node_modules/gone\",\"name\":\"gone\",\"version\":\"2.0.0\",\"source\":\"registry\",\"integrity\":\"sha512-gone\",\"reason\":\"missing\"}]}\n"
	if stdout.String() != want {
		t.Fatalf("stdout=%q, want %q", stdout.String(), want)
	}
}

// The gate forwards npm's own --os/--cpu, so both argv forms must land and
// the last occurrence must win, as npm's config parsing does.
func TestReifyCandidatesTargetPlatformFlags(t *testing.T) {
	dir, lockfile := writeReifyProject(t, `{"lockfileVersion":3,"packages":{
	  "":{"name":"reify-test","version":"1.0.0"},
	  "node_modules/aix-only":{"version":"1.0.0","optional":true,"os":["aix"],"cpu":["ppc64"],"resolved":"https://registry.npmjs.org/aix-only/-/aix-only-1.0.0.tgz","integrity":"sha512-aix"}
	}}`)

	for _, tc := range []struct {
		name  string
		args  []string
		want  string
		empty bool
	}{
		{name: "no override exempts the entry", args: nil, empty: true},
		{name: "glued form", args: []string{"--os=aix", "--cpu=ppc64"}},
		{name: "separate form", args: []string{"--os", "aix", "--cpu", "ppc64"}},
		{name: "last occurrence wins", args: []string{"--os=linux", "--cpu=ppc64", "--os", "aix"}},
		{name: "os alone leaves the cpu constraint unmet", args: []string{"--os=aix"}, empty: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			args := append(append([]string{"reify-candidates"}, tc.args...), lockfile, dir)
			if got := run(args, strings.NewReader(""), &stdout, &stderr); got != 0 {
				t.Fatalf("run() = %d, stderr=%q", got, stderr.String())
			}
			want := "{\"schema\":1,\"candidates\":[]}\n"
			if !tc.empty {
				want = "{\"schema\":1,\"candidates\":[{\"path\":\"node_modules/aix-only\",\"name\":\"aix-only\",\"version\":\"1.0.0\",\"source\":\"registry\",\"integrity\":\"sha512-aix\",\"reason\":\"missing\"}]}\n"
			}
			if stdout.String() != want {
				t.Fatalf("stdout=%q, want %q", stdout.String(), want)
			}
		})
	}
}

// The subcommand carries the same registry-host provenance as lockdiff: the
// gate refuses a non-registry candidate, so a project-private registry must
// classify as one here too.
func TestReifyCandidatesRegistryHostOption(t *testing.T) {
	dir, lockfile := writeReifyProject(t, `{"lockfileVersion":3,"packages":{
	  "":{"name":"reify-test","version":"1.0.0"},
	  "node_modules/alias":{"name":"private-pkg","version":"1.0.0","resolved":"https://registry.example.test/private-pkg/-/private-pkg-1.0.0.tgz"}
	}}`)

	var stdout, stderr bytes.Buffer
	if got := run([]string{"reify-candidates", "--registry-host", "registry.example.test", lockfile, dir}, strings.NewReader(""), &stdout, &stderr); got != 0 {
		t.Fatalf("run() = %d, stderr=%q", got, stderr.String())
	}
	want := "{\"schema\":1,\"candidates\":[{\"path\":\"node_modules/alias\",\"name\":\"private-pkg\",\"version\":\"1.0.0\",\"source\":\"registry\",\"reason\":\"missing\"}]}\n"
	if stdout.String() != want {
		t.Fatalf("stdout=%q, want %q", stdout.String(), want)
	}
}
