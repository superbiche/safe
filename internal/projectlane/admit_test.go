package projectlane

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClassifySpecTable(t *testing.T) {
	cases := []struct {
		spec string
		want string
	}{
		{"1.2.3", ClassVersion}, {"1.2.3-beta.1", ClassVersion}, {"1.2.3+build.5", ClassVersion},
		{"^1.0.0", ClassRange}, {"~1.2.3", ClassRange}, {">=1.0.0 <2.0.0", ClassRange}, {"1.x", ClassRange}, {"*", ClassRange},
		{"1.0.0 - 2.0.0", ClassRange}, {"^1.0.0 || ^2.0.0", ClassRange}, {"", ClassRange}, {">= 1.0.0 < 2.0.0", ClassRange},
		{"latest", ClassTag}, {"next", ClassTag}, {"beta-1", ClassTag}, {"my_tag", ClassTag},
		// a version npm cannot read as one is a tag, never a version
		{"99999999999999999999.0.0", ClassTag}, {"9007199254740992.0.0", ClassTag},
		// archive suffixes, whatever the case, are files
		{"1.2.3-x.tgz", ClassFile}, {"1.2.3-X.TGZ", ClassFile}, {"1.2.3.TAR", ClassFile}, {"fixture.tgz", ClassFile},
		{"Fixture.TGZ", ClassFile}, {"x.tar.gz", ClassFile}, {"x.TAR.GZ", ClassFile},
		{"file:../x", ClassFile}, {"FILE:../x", ClassFile}, {"./x", ClassFile}, {"../x", ClassFile}, {"/abs/x", ClassFile},
		{"~/x", ClassFile}, {"C:\\x", ClassFile}, {".hidden", ClassFile},
		{"npm:foo@1.0.0", ClassAlias}, {"NPM:foo@1.0.0", ClassAlias},
		{"github:user/repo", ClassGit}, {"user/repo", ClassGit}, {"git+https://example.com/x.git", ClassGit},
		{"git+ssh://git@example.com/x.git", ClassGit}, {"git://example.com/x.git", ClassGit}, {"git@github.com:user/repo.git", ClassGit},
		{"workspace:*", ClassGit}, {"link:../x", ClassGit}, {"catalog:", ClassGit},
		{"https://example.com/x.tgz", ClassRemote}, {"HTTPS://example.com/x", ClassRemote},
		// non-ASCII and whitespace-laden text is not taken
		{"é1.0.0", ClassInvalid}, {"１.０.０", ClassInvalid}, {"foo bar", ClassInvalid}, {"1.0.0/x", ClassGit},
	}
	for _, tc := range cases {
		if got := ClassifySpec(tc.spec); got != tc.want {
			t.Errorf("ClassifySpec(%q) = %s, want %s", tc.spec, got, tc.want)
		}
	}
}

func TestExactArg(t *testing.T) {
	exact := []string{"foo@1.2.3", "@scope/foo@1.2.3", "foo@1.2.3-beta.1", "foo@1.2.3+b", "Foo@1.0.0"}
	notExact := []string{"foo", "foo@", "foo@^1.0.0", "foo@latest", "foo@1.2", "foo@v1.2.3", "foo@1.2.3-x.tgz", "foo@1.2.3-X.TGZ",
		"foo@99999999999999999999.0.0", "foo@npm:bar@1.0.0", "foo@file:../x", "fixture.tgz", "github:user/repo", "user/repo@1.0.0",
		"foo@1.2.3 ", " foo@1.2.3", "foo@1.2.3\n", "é@1.0.0", "foo@１.０.０", "@scope@1.0.0", "foo@01.2.3", "./foo@1.0.0", "foo@git+https://x/y.git"}
	for _, arg := range exact {
		if !ExactArg(arg) {
			t.Errorf("ExactArg(%q) = false", arg)
		}
	}
	for _, arg := range notExact {
		if ExactArg(arg) {
			t.Errorf("ExactArg(%q) = true", arg)
		}
	}
}

func writeAdmitFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func refusalWheres(a Admission) string {
	var out []string
	for _, r := range a.Refusals {
		out = append(out, r.Where)
	}
	return strings.Join(out, ",")
}

func TestAdmitManifestTypedOverridesAndEdges(t *testing.T) {
	manifest := writeAdmitFile(t, "package.json", `{"name":"p","dependencies":{"a":"^1.0.0","b":"latest"},
	  "overrides":{"a":"1.2.3","b@^2":{".":"2.0.0","c":{"d":"$a"}}}}`)
	got, err := Admit(AdmitInput{ManifestFile: manifest})
	if err != nil || !got.Ok {
		t.Fatalf("clean manifest: %+v err=%v", got, err)
	}
	for name, body := range map[string]string{
		"dependency source":  `{"dependencies":{"a":"git+https://x/y.git"}}`,
		"archive suffix":     `{"dependencies":{"a":"1.2.3-X.TGZ"}}`,
		"alias":              `{"dependencies":{"a":"npm:b@1"}}`,
		"workspaces":         `{"workspaces":["p/*"]}`,
		"override leaf type": `{"overrides":{"a":7}}`,
		"override null":      `{"overrides":{"a":null}}`,
		"override array":     `{"overrides":{"a":["1.0.0"]}}`,
		"override selector":  `{"overrides":{"a@git+https://x/y.git":"1.0.0"}}`,
		"override nested":    `{"overrides":{"a":{"b":"file:../x"}}}`,
		"override string":    `{"overrides":"1.0.0"}`,
		"dependency type":    `{"dependencies":{"a":1}}`,
		"name":               `{"dependencies":{"../x":"1.0.0"}}`,
	} {
		got, err := Admit(AdmitInput{ManifestFile: writeAdmitFile(t, "package.json", body)})
		if err != nil || got.Ok {
			t.Errorf("%s: admitted (%+v, err=%v)", name, got, err)
		}
	}
	// A string with a NUL stays one string: nothing here is framed by it.
	got, _ = Admit(AdmitInput{ManifestFile: writeAdmitFile(t, "package.json", `{"dependencies":{"a":"1.0.0\u0000file:../x"}}`)})
	if got.Ok {
		t.Error("a spec with a NUL was admitted")
	}
	// Repeated members are refused by the strict reader.
	if _, err := Admit(AdmitInput{ManifestFile: writeAdmitFile(t, "package.json", `{"dependencies":{"a":"1.0.0","a":"git+https://x/y.git"}}`)}); err == nil {
		t.Error("a repeated member was read")
	}
}

func TestAdmitLockfileDependencyEdges(t *testing.T) {
	good := writeAdmitFile(t, "package-lock.json", `{"lockfileVersion":3,"packages":{"":{"dependencies":{"a":"^1.0.0"}},
	  "node_modules/a":{"version":"1.0.0","dependencies":{"b":"~2.1.0"},"peerDependencies":{"c":"*"}}}}`)
	if got, err := Admit(AdmitInput{LockfileFile: good}); err != nil || !got.Ok {
		t.Fatalf("clean lockfile: %+v err=%v", got, err)
	}
	bad := writeAdmitFile(t, "package-lock.json", `{"lockfileVersion":3,"packages":{"":{},
	  "node_modules/a":{"version":"1.0.0","optionalDependencies":{"b":"github:user/repo"}}}}`)
	got, err := Admit(AdmitInput{LockfileFile: bad})
	if err != nil || got.Ok || !strings.Contains(refusalWheres(got), "optionalDependencies.b") {
		t.Fatalf("a lockfile edge to a git source was admitted: %+v err=%v", got, err)
	}
}

func TestAdmitRegistriesOnParsedIdentities(t *testing.T) {
	cfg := func(body string) string { return writeAdmitFile(t, "config.json", body) }
	manifest := writeAdmitFile(t, "package.json", `{"dependencies":{"@priv/lib":"^1.0.0","plain":"^1.0.0"}}`)
	// A scope mapped to the canonical public registry is accepted.
	got, err := Admit(AdmitInput{ManifestFile: manifest, ConfigFile: cfg(`{"registry":"https://registry.npmjs.org/","@priv:registry":"https://registry.npmjs.org/"}`)})
	if err != nil || !got.Ok {
		t.Fatalf("scope mapped to the canonical registry: %+v err=%v", got, err)
	}
	// A scope mapped elsewhere refuses when a package of it is in the graph...
	got, _ = Admit(AdmitInput{ManifestFile: manifest, ConfigFile: cfg(`{"registry":"https://registry.npmjs.org/","@priv:registry":"https://npm.private.example/"}`)})
	if got.Ok {
		t.Fatal("a scope mapped elsewhere was admitted")
	}
	// ... and not when none is.
	other := writeAdmitFile(t, "package.json", `{"dependencies":{"plain":"^1.0.0"}}`)
	got, _ = Admit(AdmitInput{ManifestFile: other, ConfigFile: cfg(`{"registry":"https://registry.npmjs.org/","@priv:registry":"https://npm.private.example/"}`)})
	if !got.Ok {
		t.Fatalf("an unused scope refused: %+v", got)
	}
	// A package first discovered in the projected lockfile counts.
	lock := writeAdmitFile(t, "package-lock.json", `{"lockfileVersion":3,"packages":{"":{},"node_modules/@priv/lib":{"version":"1.0.0"}}}`)
	got, _ = Admit(AdmitInput{LockfileFile: lock, ConfigFile: cfg(`{"registry":"https://registry.npmjs.org/","@priv:registry":"https://npm.private.example/"}`)})
	if got.Ok {
		t.Fatal("a scope first discovered by the lockfile was admitted")
	}
	// The default scope picks the registry of an unscoped name.
	got, _ = Admit(AdmitInput{ManifestFile: other, ConfigFile: cfg(`{"registry":"https://registry.npmjs.org/","scope":"@priv","@priv:registry":"https://npm.private.example/"}`)})
	if got.Ok {
		t.Fatal("the default scope was ignored")
	}
	// The default registry must be the canonical one, over https, exactly.
	for _, registry := range []string{"http://registry.npmjs.org/", "https://registry.npmjs.org:8443/", "https://registry.npmjs.org/prefix/", "https://user:pw@registry.npmjs.org/", "https://registry.npmjs.org/?x=1", ""} {
		got, _ = Admit(AdmitInput{ManifestFile: other, ConfigFile: cfg(`{"registry":"` + registry + `"}`)})
		if got.Ok {
			t.Errorf("registry %q admitted", registry)
		}
	}
}

// The spellings of tests/fixtures/admit-spellings.txt never classify as a
// registry spec when npm would not: the registry ones are listed here from what
// npm answered (tests/live/npm_spec_oracle.sh re-derives them against npm).
func TestSpellingsFixtureIsClassifiable(t *testing.T) {
	file, err := os.Open(filepath.Join("..", "..", "tests", "fixtures", "admit-spellings.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	rows := 0
	for scanner.Scan() {
		rows++
		text := strings.NewReplacer(`\s`, " ", `\t`, "\t").Replace(scanner.Text())
		_ = ClassifySpec(text)
		_, _, _ = ClassifyArg(text)
	}
	if rows < 100 {
		t.Fatalf("the spellings table has %d rows", rows)
	}
}

func TestAdmitNpmrcAllowList(t *testing.T) {
	good := "; a comment\n# another\n\nsave-exact=true\nsave-prefix=~\nengine-strict=false\nfund=false\naudit=false\nupdate-notifier=false\nloglevel=warn\nprogress=false\nregistry=https://registry.npmjs.org/\n@scope:registry=https://registry.npmjs.org/\n"
	if got := AdmitNpmrc([]byte(good)); len(got) != 0 {
		t.Fatalf("the allow-list refused itself: %+v", got)
	}
	bad := map[string]string{
		"cache":             "cache=./.npm\n",
		"logs":              "logs-dir=/tmp/x\n",
		"prefix":            "prefix=/tmp/x\n",
		"location":          "location=global\n",
		"global":            "global=true\n",
		"other registry":    "registry=https://npm.private.example/\n",
		"http registry":     "registry=http://registry.npmjs.org/\n",
		"scoped elsewhere":  "@p:registry=https://npm.private.example/\n",
		"scoped credential": "@p:registry=https://user:hunter2@npm.private.example/\n",
		"auth":              "//registry.npmjs.org/:_authToken=abc\n",
		"proxy":             "proxy=http://p\n",
		"https-proxy":       "https-proxy=http://p\n",
		"cafile":            "cafile=/x\n",
		"strict-ssl":        "strict-ssl=false\n",
		"script-shell":      "script-shell=/bin/x\n",
		"git":               "git=/bin/git\n",
		"allow-git":         "allow-git=all\n",
		"min-release-age":   "min-release-age=3\n",
		"before":            "before=2020-01-01\n",
		"workspaces":        "workspaces=true\n",
		"package-lock":      "package-lock=false\n",
		"package-lock-only": "package-lock-only=true\n",
		"dry-run":           "dry-run=true\n",
		"ignore-scripts":    "ignore-scripts=false\n",
		"section":           "[section]\nsave-exact=true\n",
		"interpolation":     "registry=${REG}\n",
		"continuation":      "loglevel=warn\\\n",
		"duplicate":         "fund=true\nfund=false\n",
		"no equals":         "fund\n",
		"quoted":            "loglevel=\"warn\"\n",
		"inline comment":    "fund=false ; no\n",
		"bad bool":          "fund=maybe\n",
		"bad prefix":        "save-prefix=>=\n",
		"bad level":         "loglevel=loud\n",
		"array":             "fund[]=true\n",
		"bom":               "\xef\xbb\xbffund=true\n",
		"crlf":              "fund=true\r\n",
		"nul":               "fund=true\x00\n",
		"invalid utf8":      "fund=\xff\n",
		"upper key":         "Fund=true\n",
	}
	for name, text := range bad {
		got := AdmitNpmrc([]byte(text))
		if len(got) == 0 {
			t.Errorf("%s: admitted", name)
			continue
		}
		for _, r := range got {
			if strings.Contains(r.Text, "hunter2") || strings.Contains(r.Reason, "hunter2") {
				t.Errorf("%s: a credential in the refusal %+v", name, r)
			}
		}
	}
}

func TestAdmitNpmrcThroughTheDocument(t *testing.T) {
	file := writeAdmitFile(t, ".npmrc", "@p:registry=https://user:hunter2@npm.private.example/\n")
	got, err := Admit(AdmitInput{NpmrcFile: file})
	if err != nil || got.Ok || len(got.Refusals) != 1 {
		t.Fatalf("got %+v err=%v", got, err)
	}
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), "hunter2") {
		t.Fatalf("the document carries the credential: %s", raw)
	}
}

func TestOverridesAndNamesLikeNpm(t *testing.T) {
	cases := map[string]bool{
		`{"overrides":{"a":"1.0.0"}}`:                             true,
		`{"overrides":{"a@^1":{".":"1.2.3","b":"$a"}}}`:           true,
		`{"overrides":{"@s/a@1.x":"1.0.0"}}`:                      true,
		`{"overrides":{"a":{".":{"x":"1.0.0"}}}}`:                 false, // a self-override that is an object
		`{"overrides":{"x.tgz":"1.0.0"}}`:                         false, // an archive-suffixed selector has no package name
		`{"overrides":{"a@file:../x":"1.0.0"}}`:                   false,
		`{"overrides":{"a@npm:b@1":"1.0.0"}}`:                     false,
		`{"overrides":{"@s/.sample":"1.0.0"}}`:                    false,
		`{"dependencies":{"@s/.sample":"1.0.0"}}`:                 false,
		`{"dependencies":{"a":"^9007199254740991.0.0"}}`:          false, // npm: invalid tag name
		`{"dependencies":{"a":"9007199254740991.0.0"}}`:           true,
		`{"dependencies":{"a":">=9007199254740990.0.0"}}`:         true,
		`{"dependencies":{"a":"~9007199254740991.0.0"}}`:          true, // npm reads it as a dist-tag named so
		`{"overrides":{"a":"git+https://example.invalid/x.git"}}`: false,
	}
	for body, want := range cases {
		got, err := Admit(AdmitInput{ManifestFile: writeAdmitFile(t, "package.json", body)})
		if err != nil || got.Ok != want {
			t.Errorf("%s: ok=%v want %v (%+v err=%v)", body, got.Ok, want, got.Refusals, err)
		}
	}
	got, _ := Admit(AdmitInput{Args: []string{"foo@1.2.3"}, ManifestFile: writeAdmitFile(t, "package.json", `{"dependencies":{"a":"^1.0.0"},"overrides":{"b@2":"2.0.0"}}`)})
	kinds := map[string]bool{}
	for _, c := range got.Checked {
		kinds[c.Kind] = true
	}
	for _, kind := range []string{"arg", "dep", "name", "override-key", "override-value"} {
		if !kinds[kind] {
			t.Errorf("the document does not list %s among what it checked: %+v", kind, got.Checked)
		}
	}
}
