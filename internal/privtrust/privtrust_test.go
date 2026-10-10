package privtrust

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	npmOrigin = "https://git.example.test:8443/api/packages/owner/npm"
	goOrigin  = "https://git.example.test:8443/api/packages/owner/go"
	pyOrigin  = "https://git.example.test:8443/api/packages/owner/pypi"
	signerA   = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	signerB   = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
)

var (
	sriA = "sha512-" + strings.Repeat("A", 86) + "=="
	sriB = "sha512-" + strings.Repeat("B", 86) + "=="
	h1A  = "h1:" + strings.Repeat("a", 43) + "="
	h1B  = "h1:" + strings.Repeat("b", 43) + "="
	shaA = strings.Repeat("a", 64)
	shaB = strings.Repeat("b", 64)
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

func TestNormalizeSRI(t *testing.T) {
	if got, err := NormalizeSRI("sha1-abc " + sriA); err != nil || got != sriA {
		t.Errorf("multi-hash SRI: %q %v", got, err)
	}
	if _, err := NormalizeSRI("sha1-abc"); err == nil {
		t.Error("sha1-only SRI accepted")
	}
	if _, err := NormalizeSRI(sriA + " " + sriB); err == nil {
		t.Error("two distinct sha512 digests accepted (would admit either artifact)")
	}
	if got, err := NormalizeSRI(sriA + " " + sriA + "?opt"); err != nil || got != sriA {
		t.Errorf("a repeated identical digest must normalize: %q %v", got, err)
	}
	if _, err := NormalizeSRI("sha999-zzz " + sriA); err == nil {
		t.Error("unknown algorithm accepted")
	}
}

func TestGoRoute(t *testing.T) {
	if r := GoRoute("superbiche.me/caviar", goOrigin, goOrigin+",https://proxy.golang.org,direct", "", ""); r != "" {
		t.Errorf("good route refused: %s", r)
	}
	if GoRoute("superbiche.me/caviar", goOrigin, goOrigin, "", "superbiche.me") == "" {
		t.Error("GOPRIVATE direct route accepted")
	}
	if GoRoute("superbiche.me/caviar", goOrigin, "https://proxy.golang.org,"+goOrigin, "", "") == "" {
		t.Error("origin not first accepted")
	}
	if GoRoute("superbiche.me/caviar", goOrigin, goOrigin, "other.me", "superbiche.me") != "" {
		t.Error("GONOPROXY must override GOPRIVATE")
	}
	if !MatchPrefixPatterns("*.corp.example.com,rsc.io/private", "git.corp.example.com/xyzzy") ||
		!MatchPrefixPatterns("rsc.io/private", "rsc.io/private/quux") ||
		MatchPrefixPatterns("rsc.io/private", "rsc.io/privatex") {
		t.Error("MatchPrefixPatterns")
	}
}

func TestParseGoSum(t *testing.T) {
	raw := "superbiche.me/caviar v0.2.0 " + h1A + "\nsuperbiche.me/caviar v0.2.0/go.mod " + h1B + "\nexample.com/x v1.0.0/go.mod " + h1A + "\n"
	got, err := ParseGoSum([]byte(raw))
	if err != nil || len(got) != 2 || got[1].H1 != h1A || got[1].Mod != h1B || got[0].H1 != "" {
		t.Fatalf("ParseGoSum = %+v, %v", got, err)
	}
	if _, err := ParseGoSum([]byte("garbage line\n")); err == nil {
		t.Error("malformed go.sum accepted")
	}
}

type fixture struct {
	dir string
	s   Stores
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	dir := t.TempDir()
	return fixture{dir, Stores{
		Policy: filepath.Join(dir, "private-registries.json"), Pins: filepath.Join(dir, "private-pins.json"),
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

func TestMatchAndTOFULifecycle(t *testing.T) {
	f := newFixture(t)
	if _, err := AddRegistry(f.s, "p-npm", npmReg()); err != nil {
		t.Fatal(err)
	}
	if _, err := AddRegistry(f.s, "p-npm", npmReg()); err == nil {
		t.Error("duplicate id accepted")
	}
	v := f.view(t)
	if m := v.Match("npm", "@other/x"); m.Lane != "none" {
		t.Errorf("unrelated name matched: %+v", m)
	}
	m := v.Match("npm", "@p/x")
	if m.Lane != "private" || m.Origin != npmOrigin || m.PinMode != PinModeTOFU {
		t.Fatalf("match = %+v", m)
	}
	obs := &Integrity{SRI: sriA}
	if d := v.Decide(m, "1.0.0", obs, nil); d.Decision != "tofu" {
		t.Fatalf("first decide = %+v", d)
	}
	if _, w, err := WritePin(f.s.Pins, Pin{Ecosystem: "npm", Origin: npmOrigin, Name: "@p/x", Version: "1.0.0", Integrity: *obs}, PinWriteTOFU); err != nil || !w {
		t.Fatal(err)
	}
	// A racing second TOFU writer keeps the first record.
	if p, w, _ := WritePin(f.s.Pins, Pin{Ecosystem: "npm", Origin: npmOrigin, Name: "@p/x", Version: "1.0.0", Integrity: Integrity{SRI: sriB}}, PinWriteTOFU); w || p.Integrity.SRI != sriA {
		t.Error("TOFU overwrote an existing pin")
	}
	v = f.view(t)
	if d := v.Decide(m, "1.0.0", obs, nil); d.Decision != "matched" {
		t.Errorf("second decide = %+v", d)
	}
	if d := v.Decide(m, "1.0.0", &Integrity{SRI: sriB}, nil); d.Decision != "changed" {
		t.Errorf("changed bytes = %+v", d)
	}
	if d := v.Decide(m, "1.0.0", obs, &Integrity{SRI: sriB}); d.Decision != "cross_registry" {
		t.Errorf("observed != fetched = %+v", d)
	}
	if d := v.Decide(m, "^1.0.0", obs, nil); d.Decision != "invalid" {
		t.Errorf("range = %+v", d)
	}
	if _, _, err := WritePin(f.s.Pins, Pin{Ecosystem: "npm", Origin: npmOrigin, Name: "@p/x", Version: "1.0.0", Integrity: Integrity{SRI: sriB}}, PinWriteAdd); err == nil {
		t.Error("operator add over a different pin accepted")
	}
	if _, _, err := WritePin(f.s.Pins, Pin{Ecosystem: "npm", Origin: npmOrigin, Name: "@p/x", Version: "1.0.0"}, PinWriteRevoke); err != nil {
		t.Fatal(err)
	}
	if d := f.view(t).Decide(m, "1.0.0", obs, nil); d.Decision != "revoked" {
		t.Errorf("revoked = %+v", d)
	}
	if _, _, err := WritePin(f.s.Pins, Pin{Ecosystem: "npm", Origin: npmOrigin, Name: "@p/x", Version: "1.0.0", Integrity: *obs}, PinWriteReplace); err != nil {
		t.Fatal(err)
	}
	if d := f.view(t).Decide(m, "1.0.0", obs, nil); d.Decision != "matched" || d.PinnedBy != PinModeOperator {
		t.Errorf("replaced = %+v", d)
	}
	if err := RemoveRegistry(f.s, "p-npm"); err != nil {
		t.Fatal(err)
	}
	if m := f.view(t).Match("npm", "@p/x"); m.Lane != "none" {
		t.Error("removed registry still matches")
	}
}

func TestOperatorPinMode(t *testing.T) {
	f := newFixture(t)
	r := npmReg()
	r.PinMode = PinModeOperator
	if _, err := AddRegistry(f.s, "p", r); err != nil {
		t.Fatal(err)
	}
	v := f.view(t)
	if d := v.Decide(v.Match("npm", "@p/x"), "1.0.0", &Integrity{SRI: sriA}, nil); d.Decision != "missing" {
		t.Errorf("operator mode without pin = %+v", d)
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

func statement(t *testing.T, host, at string, regs map[string]Registry, pins map[string]Pin) []byte {
	t.Helper()
	b, err := json.Marshal(Statement{Schema: StatementSchema, Host: host, ExportedAt: at, Registries: regs, Pins: pins})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func npmPin(sri string) (string, Pin) {
	p := Pin{Ecosystem: "npm", Origin: npmOrigin, Name: "@p/x", Version: "1.0.0", Integrity: Integrity{SRI: sri}, PinnedBy: PinModeOperator}
	return PinKey("npm", npmOrigin, "@p/x", "1.0.0"), p
}

func TestFollowLifecycle(t *testing.T) {
	f := newFixture(t)
	f.signers(t, signerA)
	k, p := npmPin(sriA)
	st1 := statement(t, "rainbow", "2026-10-10T10:00:00Z", map[string]Registry{"p": npmReg()}, map[string]Pin{k: p})
	if r, err := ApplyStatement(f.s.FollowState, "rainbow", signerA, st1, true); err != nil || r.Result != "applied" {
		t.Fatalf("dry run = %+v %v", r, err)
	}
	if _, err := os.Stat(f.s.FollowState); !os.IsNotExist(err) {
		t.Error("dry run wrote the ledger")
	}
	if r, err := ApplyStatement(f.s.FollowState, "rainbow", signerA, st1, false); err != nil || r.Result != "applied" {
		t.Fatalf("apply = %+v %v", r, err)
	}
	v := f.view(t)
	m := v.Match("npm", "@p/x")
	if m.Lane != "private" || m.Sources[0].Host != "rainbow" {
		t.Fatalf("followed match = %+v", m)
	}
	if d := v.Decide(m, "1.0.0", &Integrity{SRI: sriA}, nil); d.Decision != "matched" {
		t.Errorf("followed pin = %+v", d)
	}
	if r, _ := ApplyStatement(f.s.FollowState, "rainbow", signerA, st1, false); r.Result != "current" {
		t.Errorf("same statement = %+v", r)
	}
	collide := statement(t, "rainbow", "2026-10-10T10:00:00Z", map[string]Registry{}, nil)
	if r, _ := ApplyStatement(f.s.FollowState, "rainbow", signerA, collide, false); r.Result != "collision" {
		t.Errorf("collision = %+v", r)
	}
	older := statement(t, "rainbow", "2026-10-09T10:00:00Z", map[string]Registry{}, nil)
	if r, _ := ApplyStatement(f.s.FollowState, "rainbow", signerA, older, false); r.Result != "older" {
		t.Errorf("older = %+v", r)
	}
	// Local TOFU disagreeing with the signed pin: the signed pin decides.
	if _, _, err := WritePin(f.s.Pins, Pin{Ecosystem: "npm", Origin: npmOrigin, Name: "@p/x", Version: "1.0.0", Integrity: Integrity{SRI: sriB}}, PinWriteTOFU); err != nil {
		t.Fatal(err)
	}
	if d := f.view(t).Decide(m, "1.0.0", &Integrity{SRI: sriB}, nil); d.Decision != "changed" {
		t.Errorf("local TOFU vs signed = %+v", d)
	}
	// Signer removal withdraws the followed state at once.
	f.signers(t)
	if m := f.view(t).Match("npm", "@p/x"); m.Lane != "none" {
		t.Errorf("unpinned signer still trusted: %+v", m)
	}
	f.signers(t, signerA)
	// A newer statement without the registry withdraws it (replace, not union).
	newer := statement(t, "rainbow", "2026-10-11T10:00:00Z", map[string]Registry{}, nil)
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
	kA, pA := npmPin(sriA)
	_, pB := npmPin(sriB)
	if _, err := ApplyStatement(f.s.FollowState, "rainbow", signerA, statement(t, "rainbow", "2026-10-10T10:00:00Z", map[string]Registry{"p": npmReg()}, map[string]Pin{kA: pA}), false); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyStatement(f.s.FollowState, "tuxedo", signerB, statement(t, "tuxedo", "2026-10-10T10:00:00Z", map[string]Registry{"p2": npmReg()}, map[string]Pin{kA: pB}), false); err != nil {
		t.Fatal(err)
	}
	v := f.view(t)
	m := v.Match("npm", "@p/x")
	if m.Lane != "private" {
		t.Fatalf("same origin from two hosts must merge: %+v", m)
	}
	if d := v.Decide(m, "1.0.0", &Integrity{SRI: sriA}, nil); d.Decision != "conflict" {
		t.Errorf("two signed pins disagree = %+v", d)
	}
	// A followed registry for the same namespace on another origin conflicts.
	evil := npmReg()
	evil.Origin = "https://evil.example.test/npm"
	if _, err := ApplyStatement(f.s.FollowState, "agent-dev", signerA, statement(t, "agent-dev", "2026-10-10T10:00:00Z", map[string]Registry{"p": evil}, nil), false); err != nil {
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
	bad := []byte(`{"schema":"` + StatementSchema + `","host":"tuxedo","exported_at":"2026-10-10T10:00:00Z","registries":{},"pins":{}}`)
	if _, _, err := ParseStatement(bad, "rainbow"); err == nil {
		t.Error("host mismatch accepted")
	}
	extra := []byte(`{"schema":"` + StatementSchema + `","host":"rainbow","exported_at":"2026-10-10T10:00:00Z","registries":{},"pins":{},"auth":"x"}`)
	if _, _, err := ParseStatement(extra, "rainbow"); err == nil {
		t.Error("unknown field accepted")
	}
	r := npmReg()
	r.Origin = "http://git.example.test/npm"
	st, warns, err := ParseStatement(statement(t, "rainbow", "2026-10-10T10:00:00Z", map[string]Registry{"p": r, "q": npmReg()}, nil), "rainbow")
	if err != nil || len(st.Registries) != 1 || len(warns) != 1 {
		t.Errorf("invalid entry handling: %+v %v %v", st.Registries, warns, err)
	}
}

func TestMalformedStoresFailClosed(t *testing.T) {
	f := newFixture(t)
	if err := os.WriteFile(f.s.Policy, []byte(`{"schema":"`+PolicySchema+`","registries":{"x":{"ecosystem":"npm","origin":"http://evil/","namespace":["@p/*"],"pin_mode":"tofu","cooldown_days":0}}}`), 0o600); err != nil {
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
}

func TestGoAndPythonIntegrity(t *testing.T) {
	if !IntegrityEqual("go", Integrity{H1: h1A, Mod: h1B}, Integrity{Mod: h1B}) ||
		IntegrityEqual("go", Integrity{H1: h1A, Mod: h1B}, Integrity{H1: h1B, Mod: h1B}) {
		t.Error("go comparison")
	}
	if _, _, err := ValidatePin(Pin{Ecosystem: "go", Origin: goOrigin, Name: "superbiche.me/caviar", Version: "v0.2.0", Integrity: Integrity{Mod: h1B}, PinnedBy: "tofu"}); err == nil {
		t.Error("go pin without zip hash accepted")
	}
	a := Integrity{Files: map[string]string{"x-1.whl": shaA, "x-1.tar.gz": "sha256:" + shaB}}
	va, err := ValidateIntegrity("python", a)
	if err != nil {
		t.Fatal(err)
	}
	if IntegrityEqual("python", va, Integrity{Files: map[string]string{"x-1.whl": shaA}}) {
		t.Error("python subset compared equal")
	}
	if _, _, err := ValidatePin(Pin{Ecosystem: "python", Origin: pyOrigin, Name: "Caviar_Redact", Version: "0.2.0", Integrity: va, PinnedBy: "tofu"}); err != nil {
		t.Error(err)
	}
}
