package privtrust

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const (
	npmOrigin = "https://git.example.test:8443/api/packages/owner/npm"
	goOrigin  = "https://git.example.test:8443/api/packages/owner/go"
	signerA   = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	signerB   = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
)

func TestCanonicalOrigin(t *testing.T) {
	good := map[string]string{
		"https://Git.Example.Test:8443/api/packages/owner/npm/": npmOrigin,
		"https://git.example.test:443/x":                        "https://git.example.test/x",
		"http://127.0.0.1:9000/reg":                             "http://127.0.0.1:9000/reg",
	}
	for in, want := range good {
		got, err := CanonicalOrigin(in)
		if err != nil || got != want {
			t.Errorf("CanonicalOrigin(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{
		"http://git.example.test/npm", "https://user:tok@git.example.test/npm",
		"https://git.example.test/npm?token=x", "https://git.example.test/a/../b",
		"ftp://git.example.test/", "git.example.test/npm", "",
	} {
		if _, err := CanonicalOrigin(bad); err == nil {
			t.Errorf("CanonicalOrigin(%q) accepted", bad)
		}
	}
}

func TestUnderOriginBoundary(t *testing.T) {
	cases := map[string]bool{
		npmOrigin + "/@scope%2fx/-/x-1.0.0.tgz":                      true,
		"https://tok:x@git.example.test:8443/api/packages/owner/npm": true,
		npmOrigin + "x/evil":                                         false,
		"https://git.example.test/api/packages/owner/npm/x":          false, // port is identity
		"https://registry.npmjs.org/@scope/x/-/x-1.0.0.tgz":          false,
	}
	for u, want := range cases {
		if got := UnderOrigin(u, npmOrigin); got != want {
			t.Errorf("UnderOrigin(%q) = %v, want %v", u, got, want)
		}
	}
}

func TestNamespaces(t *testing.T) {
	if !NamespaceMatches("npm", "@superbiche-private/*", "@superbiche-private/x") ||
		NamespaceMatches("npm", "@superbiche-private/*", "@superbiche-privatex/y") ||
		NamespaceMatches("npm", "@superbiche-private/*", "@superbiche-private/") {
		t.Error("npm scope matching")
	}
	if !NamespaceMatches("go", "superbiche.me", "superbiche.me/caviar") ||
		NamespaceMatches("go", "superbiche.me", "superbiche.meevil/x") {
		t.Error("go prefix matching")
	}
	if !NamespaceMatches("python", "caviar-redact", "Caviar_Redact") {
		t.Error("python normalized matching")
	}
	for eco, bad := range map[string]string{"npm": "superbiche", "go": "superbiche", "python": "caviar*"} {
		if ValidNamespace(eco, bad) == nil {
			t.Errorf("ValidNamespace(%s, %q) accepted", eco, bad)
		}
	}
	if ValidNamespace("go", "*.corp") == nil {
		t.Error("go glob accepted")
	}
	if !NamespacesOverlap("npm", "@s/*", "@s/x") || NamespacesOverlap("npm", "@s/*", "@t/x") ||
		!NamespacesOverlap("go", "a.me", "a.me/x") {
		t.Error("overlap")
	}
}

func TestGoRoute(t *testing.T) {
	ok := func(goproxy, gonoproxy, goprivate string) GoRouteResult {
		return GoRoute("superbiche.me", goOrigin, goproxy, gonoproxy, goprivate)
	}
	if r := ok(goOrigin+",https://proxy.golang.org,direct", "", ""); !r.OK || r.Local || r.Route != goOrigin {
		t.Errorf("good route refused: %+v", r)
	}
	if r := ok("file:///repo/third_party/goproxy,"+goOrigin+",https://proxy.golang.org,direct", "", ""); !r.OK || r.Route != "file:///repo/third_party/goproxy,"+goOrigin {
		t.Errorf("a local file:// source ahead of the origin is a local artifact: %+v", r)
	}
	if r := ok("file:///a|file:///b|"+goOrigin, "", ""); !r.OK {
		t.Errorf("several file:// sources, pipe separators: %+v", r)
	}
	for _, bad := range []string{
		"file:///repo/goproxy,https://proxy.golang.org," + goOrigin,
		"https://proxy.golang.org," + goOrigin,
		"direct," + goOrigin,
		"https://user:tok@evil.example.test/go," + goOrigin,
		"",
	} {
		if r := ok(bad, "", ""); r.OK {
			t.Errorf("GOPROXY=%q accepted: %+v", bad, r)
		}
	}
	if r := ok("https://user:tok@evil.example.test/go", "", ""); r.OK || containsTok(r.Reason) {
		t.Errorf("credentials in the refusal reason: %+v", r)
	}
	if r := ok("https://evil.example.test/go?token=SYNTHQ#frag", "", ""); r.OK || stringsContains(r.Reason, "SYNTHQ") || stringsContains(r.Reason, "frag") {
		t.Errorf("a query credential in the refusal reason: %+v", r)
	}
	if r := ok("file:///repo/goproxy?token=SYNTHQ,"+goOrigin, "", ""); !r.OK || stringsContains(r.Route, "SYNTHQ") {
		t.Errorf("a query credential in the route: %+v", r)
	}
	if r := ok("file:///repo/goproxy,off", "", ""); !r.OK || !r.Local {
		t.Errorf("file:// then off is local-only: %+v", r)
	}
	if r := ok("off", "", ""); !r.OK || !r.Local {
		t.Errorf("off is local-only: %+v", r)
	}
	if r := ok(goOrigin, "", "superbiche.me"); r.OK {
		t.Error("GOPRIVATE direct route accepted")
	}
	if r := ok(goOrigin, "", "superbiche.me/caviar"); r.OK {
		t.Error("GOPRIVATE below the namespace accepted")
	}
	if r := ok(goOrigin, "", "*.me"); r.OK {
		t.Error("GOPRIVATE glob covering the namespace accepted")
	}
	if r := ok(goOrigin, "other.me", "superbiche.me"); !r.OK {
		t.Error("GONOPROXY must override GOPRIVATE")
	}
	if r := ok(goOrigin, "superbiche.meevil", ""); !r.OK {
		t.Error("a pattern for another domain refused")
	}
	if !MatchPrefixPatterns("*.corp.example.com,rsc.io/private", "git.corp.example.com/xyzzy") ||
		!MatchPrefixPatterns("rsc.io/private", "rsc.io/private/quux") ||
		MatchPrefixPatterns("rsc.io/private", "rsc.io/privatex") {
		t.Error("MatchPrefixPatterns")
	}
}

func containsTok(s string) bool { return stringsContains(s, "tok@") }

func stringsContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

type fixture struct {
	dir string
	s   Stores
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	dir := t.TempDir()
	return fixture{dir, Stores{
		Policy:      filepath.Join(dir, "private-registries.json"),
		FollowState: filepath.Join(dir, "private-follow-state.json"), Config: filepath.Join(dir, "config.json")}}
}

func (f fixture) signers(t *testing.T, fprs ...string) {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"follow": map[string]any{"signers": fprs}})
	if err := os.WriteFile(f.s.Config, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f fixture) view(t *testing.T) *View {
	t.Helper()
	v, err := Load(f.s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func npmReg() Registry {
	return Registry{Ecosystem: "npm", Origin: npmOrigin, Namespace: []string{"@p/*"}, Reason: "mine"}
}

func TestMatchAndRegistries(t *testing.T) {
	f := newFixture(t)
	if _, err := AddRegistry(f.s, "p-npm", npmReg()); err != nil {
		t.Fatal(err)
	}
	if _, err := AddRegistry(f.s, "p-npm", npmReg()); err == nil {
		t.Error("duplicate id accepted")
	}
	v := f.view(t)
	m := v.Match("npm", "@p/x")
	if m.Lane != "private" || m.Origin != npmOrigin || len(m.Namespace) != 1 || m.Namespace[0] != "@p/*" {
		t.Errorf("match = %+v", m)
	}
	if v.Match("npm", "@q/x").Lane != "none" || v.Match("go", "@p/x").Lane != "none" {
		t.Error("foreign names matched")
	}
	if regs := v.Registries("npm"); len(regs) != 1 || regs[0].ID != "p-npm" {
		t.Errorf("registries = %+v", regs)
	}
	if regs := v.Registries("go"); len(regs) != 0 {
		t.Errorf("go registries = %+v", regs)
	}
	if err := RemoveRegistry(f.s, "p-npm"); err != nil {
		t.Fatal(err)
	}
	if f.view(t).Match("npm", "@p/x").Lane != "none" {
		t.Error("removed registry still matches")
	}
}

func TestLocalOverlapRefused(t *testing.T) {
	f := newFixture(t)
	if _, err := AddRegistry(f.s, "a", npmReg()); err != nil {
		t.Fatal(err)
	}
	r := npmReg()
	r.Origin = "https://evil.example.test/npm"
	r.Namespace = []string{"@p/x"}
	if _, err := AddRegistry(f.s, "b", r); err == nil {
		t.Error("overlapping namespace with a different origin accepted")
	}
}

func statement(t *testing.T, host, at string, regs map[string]Registry) []byte {
	t.Helper()
	b, err := json.Marshal(Statement{Schema: StatementSchema, Host: host, ExportedAt: at, Registries: regs})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestFollowLifecycle(t *testing.T) {
	f := newFixture(t)
	f.signers(t, signerA)
	st1 := statement(t, "rainbow", "2026-10-10T10:00:00Z", map[string]Registry{"p": npmReg()})
	if r, err := ApplyStatement(f.s.FollowState, "rainbow", signerA, st1, true); err != nil || r.Result != "applied" {
		t.Fatalf("dry run = %+v %v", r, err)
	}
	if _, err := os.Stat(f.s.FollowState); !os.IsNotExist(err) {
		t.Error("dry run wrote the ledger")
	}
	if r, err := ApplyStatement(f.s.FollowState, "rainbow", signerA, st1, false); err != nil || r.Result != "applied" {
		t.Fatalf("apply = %+v %v", r, err)
	}
	m := f.view(t).Match("npm", "@p/x")
	if m.Lane != "private" || m.Sources[0].Host != "rainbow" {
		t.Fatalf("followed match = %+v", m)
	}
	if r, _ := ApplyStatement(f.s.FollowState, "rainbow", signerA, st1, false); r.Result != "current" {
		t.Errorf("same statement = %+v", r)
	}
	collide := statement(t, "rainbow", "2026-10-10T10:00:00Z", map[string]Registry{})
	if r, _ := ApplyStatement(f.s.FollowState, "rainbow", signerA, collide, false); r.Result != "collision" {
		t.Errorf("collision = %+v", r)
	}
	older := statement(t, "rainbow", "2026-10-09T10:00:00Z", map[string]Registry{})
	if r, _ := ApplyStatement(f.s.FollowState, "rainbow", signerA, older, false); r.Result != "older" {
		t.Errorf("older = %+v", r)
	}
	// Signer removal withdraws the followed state at once.
	f.signers(t)
	if m := f.view(t).Match("npm", "@p/x"); m.Lane != "none" {
		t.Errorf("unpinned signer still trusted: %+v", m)
	}
	f.signers(t, signerA)
	// A newer statement without the registry withdraws it (replace, not union).
	newer := statement(t, "rainbow", "2026-10-11T10:00:00Z", map[string]Registry{})
	if r, _ := ApplyStatement(f.s.FollowState, "rainbow", signerA, newer, false); r.Result != "applied" {
		t.Errorf("newer = %+v", r)
	}
	if m := f.view(t).Match("npm", "@p/x"); m.Lane != "none" {
		t.Error("registry removed at origin still matches on follower")
	}
}

func TestFollowConflicts(t *testing.T) {
	f := newFixture(t)
	f.signers(t, signerA, signerB)
	if _, err := ApplyStatement(f.s.FollowState, "rainbow", signerA, statement(t, "rainbow", "2026-10-10T10:00:00Z", map[string]Registry{"p": npmReg()}), false); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyStatement(f.s.FollowState, "tuxedo", signerB, statement(t, "tuxedo", "2026-10-10T10:00:00Z", map[string]Registry{"p2": npmReg()}), false); err != nil {
		t.Fatal(err)
	}
	if m := f.view(t).Match("npm", "@p/x"); m.Lane != "private" {
		t.Fatalf("same origin from two hosts must merge: %+v", m)
	}
	evil := npmReg()
	evil.Origin = "https://evil.example.test/npm"
	if _, err := ApplyStatement(f.s.FollowState, "agent-dev", signerA, statement(t, "agent-dev", "2026-10-10T10:00:00Z", map[string]Registry{"p": evil}), false); err != nil {
		t.Fatal(err)
	}
	if m := f.view(t).Match("npm", "@p/x"); m.Lane != "conflict" || len(m.Origins) != 2 {
		t.Errorf("origin conflict = %+v", m)
	}
	if len(f.view(t).List().Conflicts) == 0 {
		t.Error("List does not report the conflict")
	}
}

func TestStatementValidation(t *testing.T) {
	bad := []byte(`{"schema":"` + StatementSchema + `","host":"tuxedo","exported_at":"2026-10-10T10:00:00Z","registries":{}}`)
	if _, _, err := ParseStatement(bad, "rainbow"); err == nil {
		t.Error("host mismatch accepted")
	}
	extra := []byte(`{"schema":"` + StatementSchema + `","host":"rainbow","exported_at":"2026-10-10T10:00:00Z","registries":{},"auth":"x"}`)
	if _, _, err := ParseStatement(extra, "rainbow"); err == nil {
		t.Error("unknown field accepted")
	}
	old := []byte(`{"schema":"safe-private-registries-export/1","host":"rainbow","exported_at":"2026-10-10T10:00:00Z","registries":{},"pins":{}}`)
	if _, _, err := ParseStatement(old, "rainbow"); err == nil {
		t.Error("a pin-model /1 statement accepted")
	}
	r := npmReg()
	r.Origin = "http://git.example.test/npm"
	st, warns, err := ParseStatement(statement(t, "rainbow", "2026-10-10T10:00:00Z", map[string]Registry{"p": r, "q": npmReg()}), "rainbow")
	if err != nil || len(st.Registries) != 1 || len(warns) != 1 {
		t.Errorf("invalid entry handling: %+v %v %v", st.Registries, warns, err)
	}
}

func TestExportCarriesRegistriesOnly(t *testing.T) {
	f := newFixture(t)
	if _, err := AddRegistry(f.s, "p-npm", npmReg()); err != nil {
		t.Fatal(err)
	}
	st, err := Export(f.s, "rainbow", "2026-10-10T10:00:00Z")
	if err != nil || st.Schema != StatementSchema || len(st.Registries) != 1 {
		t.Fatalf("export = %+v %v", st, err)
	}
	b, _ := json.Marshal(st)
	if stringsContains(string(b), "pin") {
		t.Errorf("export carries pin data: %s", b)
	}
}

func TestMalformedStoresFailClosed(t *testing.T) {
	f := newFixture(t)
	if err := os.WriteFile(f.s.Policy, []byte(`{"schema":"`+PolicySchema+`","registries":{"x":{"ecosystem":"npm","origin":"http://evil/","namespace":["@p/*"]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(f.s); err == nil {
		t.Error("malformed policy loaded")
	}
	if err := os.WriteFile(f.s.Policy, []byte(`{"schema":"`+PolicySchema+`","registries":{},"registries":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(f.s); err == nil {
		t.Error("repeated member accepted")
	}
	if err := os.WriteFile(f.s.Policy, []byte(`{"schema":"safe-private-registries/1","registries":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(f.s); err == nil {
		t.Error("a pin-model /1 policy loaded")
	}
}
