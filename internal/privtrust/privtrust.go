// Package privtrust decides operator-managed trust for owner-controlled
// private package registries: which registry a package name belongs to,
// whether the artifact about to be installed matches the integrity pinned for
// that exact version, and how local and fleet-followed statements combine.
//
// The package reads three stores, all owned by bin/safe-run's trust root:
//
//   - private-registries.json: the local registry policy (operator TTY only);
//   - private-pins.json: per-version artifact integrity, written by the
//     operator or recorded on first use (TOFU) by the install gate;
//   - private-follow-state.json: the last verified signed statement accepted
//     from each fleet origin, honored only while its signer stays pinned.
//
// Nothing here fetches anything or reads a credential: integrity is gathered
// by the ecosystem's own client in bash and handed in.
package privtrust

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/superbiche/safe/internal/strictjson"
)

const (
	PolicySchema    = "safe-private-registries/1"
	PinsSchema      = "safe-private-pins/1"
	StatementSchema = "safe-private-registries-export/1"

	PinModeTOFU     = "tofu"
	PinModeOperator = "operator"

	KindLocal    = "local"
	KindFollowed = "followed"
)

// Registry is one private registry definition.
type Registry struct {
	Ecosystem    string   `json:"ecosystem"`
	Origin       string   `json:"origin"`
	Owner        string   `json:"owner,omitempty"`
	Namespace    []string `json:"namespace"`
	PinMode      string   `json:"pin_mode"`
	CooldownDays int      `json:"cooldown_days"`
	Added        string   `json:"added,omitempty"`
	Reason       string   `json:"reason,omitempty"`
}

// Integrity is the per-ecosystem artifact identity. npm uses the sha512 SRI;
// Go the module zip and go.mod h1 hashes; Python the sha256 of every
// distribution file of the version (pip picks one per platform, so the whole
// set is bound).
type Integrity struct {
	SRI   string            `json:"sri,omitempty"`
	H1    string            `json:"h1,omitempty"`
	Mod   string            `json:"mod,omitempty"`
	Files map[string]string `json:"files,omitempty"`
}

// Pin records the integrity of one exact version served by one origin.
type Pin struct {
	Ecosystem string    `json:"ecosystem"`
	Origin    string    `json:"origin"`
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	Integrity Integrity `json:"integrity"`
	Artifact  string    `json:"artifact,omitempty"`
	PinnedBy  string    `json:"pinned_by"`
	PinnedAt  string    `json:"pinned_at,omitempty"`
	Revoked   bool      `json:"revoked,omitempty"`
}

// Policy is private-registries.json.
type Policy struct {
	Schema     string              `json:"schema"`
	Registries map[string]Registry `json:"registries"`
}

// Pins is private-pins.json.
type Pins struct {
	Schema string         `json:"schema"`
	Pins   map[string]Pin `json:"pins"`
}

// FollowedOrigin is the last accepted signed statement of one fleet origin.
type FollowedOrigin struct {
	Accepted        string              `json:"accepted"`
	StatementSHA256 string              `json:"statement_sha256"`
	Signer          string              `json:"signer"`
	Registries      map[string]Registry `json:"registries"`
	Pins            map[string]Pin      `json:"pins"`
}

// FollowState is private-follow-state.json.
type FollowState struct {
	Origins map[string]FollowedOrigin `json:"origins"`
}

// Statement is the signed document an origin publishes.
type Statement struct {
	Schema     string              `json:"schema"`
	Host       string              `json:"host"`
	ExportedAt string              `json:"exported_at"`
	Registries map[string]Registry `json:"registries"`
	Pins       map[string]Pin      `json:"pins"`
}

var (
	registryIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	npmPartRe    = regexp.MustCompile(`^[a-z0-9~][a-z0-9._~-]*$`)
	pyNameRe     = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$`)
	pyNormRe     = regexp.MustCompile(`[-_.]+`)
	goElemRe     = regexp.MustCompile(`^[A-Za-z0-9._~+-]+$`)
	sha256HexRe  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	h1Re         = regexp.MustCompile(`^h1:[A-Za-z0-9+/]{43}=$`)
	sriSHA512Re  = regexp.MustCompile(`^sha512-[A-Za-z0-9+/]{86}==$`)
	hostRe       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	fileNameRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)
)

// ValidEcosystem reports whether eco is one this package supports.
func ValidEcosystem(eco string) bool {
	switch eco {
	case "npm", "go", "python":
		return true
	}
	return false
}

// ValidRegistryID reports whether id is a well-formed registry id.
func ValidRegistryID(id string) bool { return registryIDRe.MatchString(id) }

// ValidHost reports whether h is a well-formed short hostname.
func ValidHost(h string) bool { return hostRe.MatchString(h) }

// CanonicalOrigin validates a policy origin and returns its canonical form:
// https (http only for a loopback host), lower-case scheme and host, default
// port dropped, no userinfo, query or fragment, no trailing slash, and no
// dot segments.
func CanonicalOrigin(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("origin is not a URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", fmt.Errorf("origin must not carry credentials, a query or a fragment")
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", fmt.Errorf("origin needs a host")
	}
	switch scheme {
	case "https":
	case "http":
		if !isLoopback(host) {
			return "", fmt.Errorf("origin must use https")
		}
	default:
		return "", fmt.Errorf("origin must use https")
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == "." || seg == ".." {
			return "", fmt.Errorf("origin path must not contain dot segments")
		}
	}
	return canonicalJoin(scheme, host, u.Port(), u.EscapedPath()), nil
}

// CanonicalURL is the identity form of an observed URL (a lockfile resolved
// URL, an index URL): credentials, query and fragment dropped, scheme and host
// lower-cased, default port dropped, trailing slashes stripped. It never
// fails open: an unparseable URL returns "".
func CanonicalURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Opaque != "" {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return ""
	}
	return canonicalJoin(scheme, host, u.Port(), u.EscapedPath())
}

func canonicalJoin(scheme, host, port, escapedPath string) string {
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	hostport := host
	if strings.Contains(host, ":") {
		hostport = "[" + host + "]"
	}
	if port != "" {
		hostport += ":" + port
	}
	p := strings.TrimRight(escapedPath, "/")
	return scheme + "://" + hostport + p
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// UnderOrigin reports whether an observed URL lies at or below origin, on a
// path-segment boundary. Both sides are canonicalized; percent-encoding is
// compared case-insensitively only in the host.
func UnderOrigin(observed, origin string) bool {
	o := CanonicalURL(observed)
	base := CanonicalURL(origin)
	if o == "" || base == "" {
		return false
	}
	return o == base || strings.HasPrefix(o, base+"/")
}

// NormalizeName returns the identity form of a package name.
func NormalizeName(eco, name string) string {
	switch eco {
	case "python":
		return strings.ToLower(pyNormRe.ReplaceAllString(name, "-"))
	}
	return name
}

// ValidNamespace validates one namespace entry for an ecosystem:
//
//   - npm: "@scope/*" or an exact scoped name "@scope/name";
//   - go: a literal module path prefix whose first element is a domain
//     ("superbiche.me", "example.com/private"); no globs;
//   - python: one exact distribution name (PyPI has no namespaces, and a
//     prefix pattern would amplify dependency confusion).
func ValidNamespace(eco, ns string) error {
	switch eco {
	case "npm":
		if !strings.HasPrefix(ns, "@") {
			return fmt.Errorf("npm namespace must be a scope: @scope/* or @scope/name")
		}
		scope, rest, ok := strings.Cut(ns[1:], "/")
		if !ok || !npmPartRe.MatchString(scope) || (rest != "*" && !npmPartRe.MatchString(rest)) {
			return fmt.Errorf("npm namespace must be @scope/* or @scope/name")
		}
		return nil
	case "go":
		if strings.ContainsAny(ns, "*?[]\\") {
			return fmt.Errorf("go namespace is a literal module path prefix, not a glob")
		}
		elems := strings.Split(ns, "/")
		for _, e := range elems {
			if e == "" || e == "." || e == ".." || !goElemRe.MatchString(e) {
				return fmt.Errorf("go namespace %q is not a module path prefix", ns)
			}
		}
		if !strings.Contains(elems[0], ".") {
			return fmt.Errorf("go namespace must start with a domain")
		}
		return nil
	case "python":
		if !pyNameRe.MatchString(ns) {
			return fmt.Errorf("python namespace must be one exact distribution name")
		}
		return nil
	}
	return fmt.Errorf("unsupported ecosystem %q", eco)
}

// NamespaceMatches reports whether name belongs to namespace entry ns.
func NamespaceMatches(eco, ns, name string) bool {
	switch eco {
	case "npm":
		if strings.HasSuffix(ns, "/*") {
			return strings.HasPrefix(name, strings.TrimSuffix(ns, "*")) && len(name) > len(ns)-1
		}
		return name == ns
	case "go":
		return name == ns || strings.HasPrefix(name, ns+"/")
	case "python":
		return NormalizeName(eco, name) == NormalizeName(eco, ns)
	}
	return false
}

// NamespacesOverlap reports whether two entries can match a common name.
func NamespacesOverlap(eco, a, b string) bool {
	switch eco {
	case "npm":
		aw, bw := strings.HasSuffix(a, "/*"), strings.HasSuffix(b, "/*")
		switch {
		case aw && bw:
			return a == b
		case aw:
			return NamespaceMatches(eco, a, b)
		case bw:
			return NamespaceMatches(eco, b, a)
		}
		return a == b
	case "go":
		return NamespaceMatches(eco, a, b) || NamespaceMatches(eco, b, a)
	case "python":
		return NormalizeName(eco, a) == NormalizeName(eco, b)
	}
	return false
}

// ValidateRegistry checks a registry definition and returns it canonicalized.
func ValidateRegistry(id string, r Registry) (Registry, error) {
	if !ValidRegistryID(id) {
		return r, fmt.Errorf("registry id %q is invalid (lower-case letters, digits, . _ -)", id)
	}
	if !ValidEcosystem(r.Ecosystem) {
		return r, fmt.Errorf("registry %s: unsupported ecosystem %q (npm, go, python)", id, r.Ecosystem)
	}
	origin, err := CanonicalOrigin(r.Origin)
	if err != nil {
		return r, fmt.Errorf("registry %s: %v", id, err)
	}
	r.Origin = origin
	if len(r.Namespace) == 0 {
		return r, fmt.Errorf("registry %s: at least one namespace entry is required", id)
	}
	seen := map[string]bool{}
	var ns []string
	for _, n := range r.Namespace {
		if err := ValidNamespace(r.Ecosystem, n); err != nil {
			return r, fmt.Errorf("registry %s: %v", id, err)
		}
		if r.Ecosystem == "python" {
			n = NormalizeName("python", n)
		}
		if !seen[n] {
			seen[n] = true
			ns = append(ns, n)
		}
	}
	sort.Strings(ns)
	r.Namespace = ns
	switch r.PinMode {
	case "":
		r.PinMode = PinModeTOFU
	case PinModeTOFU, PinModeOperator:
	default:
		return r, fmt.Errorf("registry %s: pin_mode must be tofu or operator", id)
	}
	if r.CooldownDays < 0 || r.CooldownDays > 365 {
		return r, fmt.Errorf("registry %s: cooldown_days must be 0..365", id)
	}
	return r, nil
}

// ValidateIntegrity checks the integrity shape for an ecosystem.
func ValidateIntegrity(eco string, in Integrity) (Integrity, error) {
	switch eco {
	case "npm":
		sri, err := NormalizeSRI(in.SRI)
		if err != nil {
			return in, err
		}
		return Integrity{SRI: sri}, nil
	case "go":
		// The go.mod hash is always required. The zip hash may be absent only
		// in an observation: go.sum carries just the /go.mod line for a
		// module that is in the build graph but never downloaded. Pins always
		// carry both (ValidatePin).
		if !h1Re.MatchString(in.Mod) || (in.H1 != "" && !h1Re.MatchString(in.H1)) {
			return in, fmt.Errorf("go integrity needs h1: hashes for the module zip and its go.mod")
		}
		return Integrity{H1: in.H1, Mod: in.Mod}, nil
	case "python":
		if len(in.Files) == 0 {
			return in, fmt.Errorf("python integrity needs at least one distribution file sha256")
		}
		files := map[string]string{}
		for f, h := range in.Files {
			h = strings.TrimPrefix(strings.ToLower(h), "sha256:")
			if !fileNameRe.MatchString(f) || !sha256HexRe.MatchString(h) {
				return in, fmt.Errorf("python integrity entry %q is not filename -> sha256", f)
			}
			files[f] = h
		}
		return Integrity{Files: files}, nil
	}
	return in, fmt.Errorf("unsupported ecosystem %q", eco)
}

// NormalizeSRI extracts the sha512 member of an SRI string. A weaker-only SRI
// (sha1 shasum) is not an artifact identity this package accepts.
func NormalizeSRI(sri string) (string, error) {
	for _, tok := range strings.Fields(sri) {
		if i := strings.IndexByte(tok, '?'); i >= 0 {
			tok = tok[:i]
		}
		if sriSHA512Re.MatchString(tok) {
			return tok, nil
		}
	}
	return "", fmt.Errorf("npm integrity needs a sha512 SRI")
}

// IntegrityEqual compares two validated integrities of one ecosystem.
func IntegrityEqual(eco string, a, b Integrity) bool {
	switch eco {
	case "npm":
		return a.SRI != "" && a.SRI == b.SRI
	case "go":
		// A zip hash missing on one side (a go.sum /go.mod-only line) is
		// compared on the go.mod hash alone; present on both, both must match.
		if a.Mod == "" || a.Mod != b.Mod {
			return false
		}
		return a.H1 == "" || b.H1 == "" || a.H1 == b.H1
	case "python":
		if len(a.Files) == 0 || len(a.Files) != len(b.Files) {
			return false
		}
		for f, h := range a.Files {
			if b.Files[f] != h {
				return false
			}
		}
		return true
	}
	return false
}

// PinKey is the ledger key of one identity. It keys on the origin, not the
// registry id, so hosts may name the same registry differently.
func PinKey(eco, origin, name, version string) string {
	return eco + "|" + origin + "|" + NormalizeName(eco, name) + "|" + version
}

// ValidatePin checks a pin and returns it canonicalized together with its key.
func ValidatePin(p Pin) (Pin, string, error) {
	if !ValidEcosystem(p.Ecosystem) {
		return p, "", fmt.Errorf("pin: unsupported ecosystem %q", p.Ecosystem)
	}
	origin, err := CanonicalOrigin(p.Origin)
	if err != nil {
		return p, "", fmt.Errorf("pin %s@%s: %v", p.Name, p.Version, err)
	}
	p.Origin = origin
	if p.Name == "" || strings.ContainsAny(p.Name, " \t\n|") {
		return p, "", fmt.Errorf("pin: invalid name %q", p.Name)
	}
	p.Name = NormalizeName(p.Ecosystem, p.Name)
	if !ExactVersion(p.Ecosystem, p.Version) {
		return p, "", fmt.Errorf("pin %s: %q is not an exact version", p.Name, p.Version)
	}
	switch p.PinnedBy {
	case PinModeTOFU, PinModeOperator:
	default:
		return p, "", fmt.Errorf("pin %s@%s: pinned_by must be tofu or operator", p.Name, p.Version)
	}
	if !p.Revoked {
		in, err := ValidateIntegrity(p.Ecosystem, p.Integrity)
		if err != nil {
			return p, "", fmt.Errorf("pin %s@%s: %v", p.Name, p.Version, err)
		}
		if p.Ecosystem == "go" && in.H1 == "" {
			return p, "", fmt.Errorf("pin %s@%s: go pins need the module zip hash", p.Name, p.Version)
		}
		p.Integrity = in
	} else if in, err := ValidateIntegrity(p.Ecosystem, p.Integrity); err == nil {
		p.Integrity = in
	} else {
		p.Integrity = Integrity{}
	}
	if p.Artifact != "" {
		p.Artifact = CanonicalURL(p.Artifact)
		if p.Ecosystem == "go" {
			p.Artifact = ""
		}
	}
	return p, PinKey(p.Ecosystem, p.Origin, p.Name, p.Version), nil
}

var (
	semverRe = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)
	pep440Re = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*((a|b|rc)[0-9]+)?(\.post[0-9]+)?(\.dev[0-9]+)?(\+[0-9A-Za-z]+([._-][0-9A-Za-z]+)*)?$`)
)

// ExactVersion mirrors bin/safe-audit's version_is_exact for the private
// ecosystems: strict SemVer for npm, v-prefixed SemVer for Go, PEP 440 public
// plus local segments for Python.
func ExactVersion(eco, v string) bool {
	switch eco {
	case "npm":
		return len(v) <= 256 && semverRe.MatchString(v)
	case "go":
		return strings.HasPrefix(v, "v") && semverRe.MatchString(v[1:])
	case "python":
		return pep440Re.MatchString(v)
	}
	return false
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

// ErrMalformed marks a store that exists but cannot be trusted as read.
var ErrMalformed = errors.New("malformed")

func readStrict(file string, v any) (bool, error) {
	raw, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return true, fmt.Errorf("%w: %s: %v", ErrMalformed, file, err)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return false, nil
	}
	if err := strictjson.RejectRepeatedMembers(raw); err != nil {
		return true, fmt.Errorf("%w: %s: %v", ErrMalformed, file, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return true, fmt.Errorf("%w: %s: %v", ErrMalformed, file, err)
	}
	if dec.More() {
		return true, fmt.Errorf("%w: %s: trailing data", ErrMalformed, file)
	}
	return true, nil
}

// LoadPolicy reads the local registry policy. A missing file is empty.
func LoadPolicy(file string) (Policy, error) {
	p := Policy{Schema: PolicySchema, Registries: map[string]Registry{}}
	if file == "" {
		return p, nil
	}
	present, err := readStrict(file, &p)
	if err != nil {
		return p, err
	}
	if !present {
		return Policy{Schema: PolicySchema, Registries: map[string]Registry{}}, nil
	}
	if p.Schema != PolicySchema {
		return p, fmt.Errorf("%w: %s: schema must be %s", ErrMalformed, file, PolicySchema)
	}
	if p.Registries == nil {
		p.Registries = map[string]Registry{}
	}
	for id, r := range p.Registries {
		cr, err := ValidateRegistry(id, r)
		if err != nil {
			return p, fmt.Errorf("%w: %s: %v", ErrMalformed, file, err)
		}
		p.Registries[id] = cr
	}
	if err := checkPolicyOverlap(p.Registries); err != nil {
		return p, fmt.Errorf("%w: %s: %v", ErrMalformed, file, err)
	}
	return p, nil
}

// checkPolicyOverlap refuses two registries of one source whose namespaces
// overlap while their origins differ.
func checkPolicyOverlap(regs map[string]Registry) error {
	ids := sortedKeys(regs)
	for i, a := range ids {
		for _, b := range ids[i+1:] {
			ra, rb := regs[a], regs[b]
			if ra.Ecosystem != rb.Ecosystem || ra.Origin == rb.Origin {
				continue
			}
			for _, na := range ra.Namespace {
				for _, nb := range rb.Namespace {
					if NamespacesOverlap(ra.Ecosystem, na, nb) {
						return fmt.Errorf("registries %s and %s claim overlapping namespaces (%s, %s) with different origins", a, b, na, nb)
					}
				}
			}
		}
	}
	return nil
}

// LoadPins reads the local pin ledger. A missing file is empty.
func LoadPins(file string) (Pins, error) {
	p := Pins{Schema: PinsSchema, Pins: map[string]Pin{}}
	if file == "" {
		return p, nil
	}
	present, err := readStrict(file, &p)
	if err != nil {
		return p, err
	}
	if !present {
		return Pins{Schema: PinsSchema, Pins: map[string]Pin{}}, nil
	}
	if p.Schema != PinsSchema {
		return p, fmt.Errorf("%w: %s: schema must be %s", ErrMalformed, file, PinsSchema)
	}
	if p.Pins == nil {
		p.Pins = map[string]Pin{}
	}
	out := map[string]Pin{}
	for k, pin := range p.Pins {
		cp, key, err := ValidatePin(pin)
		if err != nil || key != k {
			return p, fmt.Errorf("%w: %s: pin %q: invalid or mis-keyed", ErrMalformed, file, k)
		}
		out[key] = cp
	}
	p.Pins = out
	return p, nil
}

// LoadFollowState reads the follower ledger. A missing file is empty.
func LoadFollowState(file string) (FollowState, error) {
	s := FollowState{Origins: map[string]FollowedOrigin{}}
	if file == "" {
		return s, nil
	}
	present, err := readStrict(file, &s)
	if err != nil {
		return s, err
	}
	if !present || s.Origins == nil {
		return FollowState{Origins: map[string]FollowedOrigin{}}, nil
	}
	for host, o := range s.Origins {
		if !ValidHost(host) || o.Accepted == "" || o.Signer == "" {
			return s, fmt.Errorf("%w: %s: origin %q record incomplete", ErrMalformed, file, host)
		}
		if o.Registries == nil {
			o.Registries = map[string]Registry{}
		}
		if o.Pins == nil {
			o.Pins = map[string]Pin{}
		}
		s.Origins[host] = o
	}
	return s, nil
}

// LoadSigners reads follow.signers from the run config, upper-cased. A
// missing config or key is no signers; an invalid value is an error (the
// follow code treats it the same way).
func LoadSigners(configFile string) ([]string, error) {
	if configFile == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(configFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var cfg struct {
		Follow struct {
			Signers []string `json:"signers"`
		} `json:"follow"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("invalid follow.signers")
	}
	fpr := regexp.MustCompile(`^([A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$`)
	var out []string
	for _, s := range cfg.Follow.Signers {
		if !fpr.MatchString(s) {
			return nil, fmt.Errorf("invalid follow.signers")
		}
		out = append(out, strings.ToUpper(s))
	}
	return out, nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ---------------------------------------------------------------------------
// Effective view
// ---------------------------------------------------------------------------

// Source names where a registry or pin came from.
type Source struct {
	Kind       string `json:"kind"`
	RegistryID string `json:"registry_id,omitempty"`
	Host       string `json:"host,omitempty"`
	Signer     string `json:"signer,omitempty"`
	Generation string `json:"generation,omitempty"`
}

type sourcedRegistry struct {
	Registry
	Source Source
}

type sourcedPin struct {
	Pin
	Source Source
}

// View is the union of local state and every followed origin whose signer is
// still pinned. Followed state from an unpinned signer is invisible.
type View struct {
	registries []sourcedRegistry
	pins       map[string][]sourcedPin
}

// Stores bundles the store paths.
type Stores struct {
	Policy      string
	Pins        string
	FollowState string
	Config      string
}

// Load builds the effective view. Any malformed store is an error: the
// caller refuses rather than deciding from partial trust.
func Load(s Stores) (*View, error) {
	pol, err := LoadPolicy(s.Policy)
	if err != nil {
		return nil, err
	}
	pins, err := LoadPins(s.Pins)
	if err != nil {
		return nil, err
	}
	fs, err := LoadFollowState(s.FollowState)
	if err != nil {
		return nil, err
	}
	signers, err := LoadSigners(s.Config)
	if err != nil {
		// Invalid signer config withdraws every followed statement; local
		// trust still applies.
		signers = nil
	}
	return Build(pol, pins, fs, signers), nil
}

// Build assembles a view from already-loaded state.
func Build(pol Policy, pins Pins, fs FollowState, signers []string) *View {
	v := &View{pins: map[string][]sourcedPin{}}
	for _, id := range sortedKeys(pol.Registries) {
		v.registries = append(v.registries, sourcedRegistry{pol.Registries[id], Source{Kind: KindLocal, RegistryID: id}})
	}
	for _, k := range sortedKeys(pins.Pins) {
		v.pins[k] = append(v.pins[k], sourcedPin{pins.Pins[k], Source{Kind: KindLocal}})
	}
	pinned := map[string]bool{}
	for _, s := range signers {
		pinned[strings.ToUpper(s)] = true
	}
	for _, host := range sortedKeys(fs.Origins) {
		o := fs.Origins[host]
		if !pinned[strings.ToUpper(o.Signer)] {
			continue
		}
		src := Source{Kind: KindFollowed, Host: host, Signer: strings.ToUpper(o.Signer), Generation: o.Accepted}
		for _, id := range sortedKeys(o.Registries) {
			r, err := ValidateRegistry(id, o.Registries[id])
			if err != nil {
				continue
			}
			s := src
			s.RegistryID = id
			v.registries = append(v.registries, sourcedRegistry{r, s})
		}
		for _, k := range sortedKeys(o.Pins) {
			p, key, err := ValidatePin(o.Pins[k])
			if err != nil {
				continue
			}
			v.pins[key] = append(v.pins[key], sourcedPin{p, src})
		}
	}
	return v
}

// Match is the registry decision for one package name.
type Match struct {
	Lane         string   `json:"lane"` // none | private | conflict
	Ecosystem    string   `json:"ecosystem"`
	Name         string   `json:"name"`
	Origin       string   `json:"origin,omitempty"`
	Origins      []string `json:"origins,omitempty"`
	RegistryIDs  []string `json:"registry_ids,omitempty"`
	PinMode      string   `json:"pin_mode,omitempty"`
	CooldownDays int      `json:"cooldown_days"`
	Sources      []Source `json:"sources,omitempty"`
}

// Match finds the registry a name belongs to. Several sources agreeing on the
// origin merge (strictest pin mode, longest cooldown); different origins for
// one name are a conflict and never pick a winner.
func (v *View) Match(eco, name string) Match {
	m := Match{Lane: "none", Ecosystem: eco, Name: NormalizeName(eco, name)}
	origins := map[string]bool{}
	ids := map[string]bool{}
	for _, r := range v.registries {
		if r.Ecosystem != eco {
			continue
		}
		hit := false
		for _, ns := range r.Namespace {
			if NamespaceMatches(eco, ns, name) {
				hit = true
				break
			}
		}
		if !hit {
			continue
		}
		origins[r.Origin] = true
		if !ids[r.Source.RegistryID] {
			ids[r.Source.RegistryID] = true
			m.RegistryIDs = append(m.RegistryIDs, r.Source.RegistryID)
		}
		m.Sources = append(m.Sources, r.Source)
		if r.PinMode == PinModeOperator || m.PinMode == "" {
			if m.PinMode != PinModeOperator {
				m.PinMode = r.PinMode
			}
		}
		if r.CooldownDays > m.CooldownDays {
			m.CooldownDays = r.CooldownDays
		}
	}
	switch len(origins) {
	case 0:
		return m
	case 1:
		m.Lane = "private"
		for o := range origins {
			m.Origin = o
		}
	default:
		m.Lane = "conflict"
		m.Origins = sortedKeys(origins)
		m.PinMode = ""
	}
	sort.Strings(m.RegistryIDs)
	return m
}

// Decision is the pin outcome for one exact artifact.
type Decision struct {
	Decision  string     `json:"decision"` // matched | tofu | missing | changed | revoked | conflict | cross_registry | invalid
	Detail    string     `json:"detail,omitempty"`
	Key       string     `json:"key,omitempty"`
	Expected  *Integrity `json:"expected,omitempty"`
	Observed  *Integrity `json:"observed,omitempty"`
	PinnedBy  string     `json:"pinned_by,omitempty"`
	PinSource *Source    `json:"pin_source,omitempty"`
}

// Decide compares the artifact the manager will install (observed) and the
// artifact the policy origin serves (fetched) against the pins for the exact
// identity. fetched may be nil when the observed artifact already comes
// straight from the origin.
func (v *View) Decide(m Match, version string, observed, fetched *Integrity) Decision {
	if m.Lane != "private" {
		return Decision{Decision: "invalid", Detail: "not on the private lane"}
	}
	key := PinKey(m.Ecosystem, m.Origin, m.Name, version)
	d := Decision{Key: key}
	if !ExactVersion(m.Ecosystem, version) {
		d.Decision, d.Detail = "invalid", "not an exact version"
		return d
	}
	if observed == nil {
		d.Decision, d.Detail = "invalid", "no observed integrity"
		return d
	}
	obs, err := ValidateIntegrity(m.Ecosystem, *observed)
	if err != nil {
		d.Decision, d.Detail = "invalid", err.Error()
		return d
	}
	d.Observed = &obs
	if fetched != nil {
		f, err := ValidateIntegrity(m.Ecosystem, *fetched)
		if err != nil {
			d.Decision, d.Detail = "invalid", err.Error()
			return d
		}
		if !IntegrityEqual(m.Ecosystem, obs, f) {
			d.Decision = "cross_registry"
			d.Detail = "the artifact the package manager will install is not the one the private origin serves"
			d.Expected = &f
			return d
		}
	}
	pins := v.pins[key]
	for _, p := range pins {
		if p.Revoked {
			s := p.Source
			d.Decision, d.PinSource = "revoked", &s
			d.Detail = "this exact version was revoked"
			return d
		}
	}
	var followed, localOperator, localTOFU []sourcedPin
	for _, p := range pins {
		switch {
		case p.Source.Kind == KindFollowed:
			followed = append(followed, p)
		case p.PinnedBy == PinModeOperator:
			localOperator = append(localOperator, p)
		default:
			localTOFU = append(localTOFU, p)
		}
	}
	for i := 1; i < len(followed); i++ {
		if !IntegrityEqual(m.Ecosystem, followed[0].Integrity, followed[i].Integrity) {
			d.Decision = "conflict"
			d.Detail = fmt.Sprintf("signed statements from %s and %s pin different bytes", followed[0].Source.Host, followed[i].Source.Host)
			return d
		}
	}
	if len(followed) > 0 && len(localOperator) > 0 && !IntegrityEqual(m.Ecosystem, followed[0].Integrity, localOperator[0].Integrity) {
		d.Decision = "conflict"
		d.Detail = fmt.Sprintf("the local operator pin and the signed statement from %s pin different bytes", followed[0].Source.Host)
		return d
	}
	var auth *sourcedPin
	switch {
	case len(followed) > 0:
		auth = &followed[0]
	case len(localOperator) > 0:
		auth = &localOperator[0]
	case len(localTOFU) > 0:
		auth = &localTOFU[0]
	}
	if auth == nil {
		if m.PinMode == PinModeOperator {
			d.Decision, d.Detail = "missing", "registry requires an operator pin for each version"
			return d
		}
		d.Decision = "tofu"
		return d
	}
	exp := auth.Integrity
	src := auth.Source
	d.Expected, d.PinnedBy, d.PinSource = &exp, auth.PinnedBy, &src
	if IntegrityEqual(m.Ecosystem, obs, exp) {
		d.Decision = "matched"
		return d
	}
	d.Decision = "changed"
	d.Detail = "the artifact differs from the one pinned for this exact version"
	return d
}

// ---------------------------------------------------------------------------
// Go routing
// ---------------------------------------------------------------------------

// MatchPrefixPatterns mirrors cmd/go's module path prefix glob matching for
// GOPRIVATE/GONOPROXY/GONOSUMDB (golang.org/x/mod/module.MatchPrefixPatterns):
// each comma-separated pattern is matched with path.Match against the same
// number of leading path elements of target. safe-core stays stdlib-only.
func MatchPrefixPatterns(globs, target string) bool {
	for globs != "" {
		var glob string
		if i := strings.Index(globs, ","); i >= 0 {
			glob, globs = globs[:i], globs[i+1:]
		} else {
			glob, globs = globs, ""
		}
		glob = strings.TrimSuffix(glob, "/")
		if glob == "" {
			continue
		}
		n := strings.Count(glob, "/")
		prefix := target
		for i := 0; i < len(target); i++ {
			if target[i] == '/' {
				if n == 0 {
					prefix = target[:i]
					break
				}
				n--
			}
		}
		if n > 0 {
			continue
		}
		if ok, _ := path.Match(glob, prefix); ok {
			return true
		}
	}
	return false
}

// GoRoute reports whether `go` would fetch module from origin: GONOPROXY
// (defaulting to GOPRIVATE) must not send it direct, and the first GOPROXY
// entry must be the policy origin. Returns "" when routed through origin.
func GoRoute(module, origin, goproxy, gonoproxy, goprivate string) string {
	noproxy := gonoproxy
	if noproxy == "" {
		noproxy = goprivate
	}
	if MatchPrefixPatterns(noproxy, module) {
		return "GONOPROXY/GOPRIVATE sends this module to its VCS directly, not through the private registry"
	}
	if goproxy == "" {
		goproxy = "https://proxy.golang.org,direct"
	}
	first := goproxy
	if i := strings.IndexAny(first, ",|"); i >= 0 {
		first = first[:i]
	}
	first = strings.TrimSpace(first)
	switch first {
	case "off":
		return "GOPROXY=off: module downloads are disabled"
	case "direct", "":
		return "GOPROXY does not list the private registry first"
	}
	if CanonicalURL(first) == "" || CanonicalURL(first) != CanonicalURL(origin) {
		return "GOPROXY does not list the private registry first"
	}
	return ""
}

// GoSumEntry is one module version's hashes from go.sum.
type GoSumEntry struct {
	Module  string `json:"module"`
	Version string `json:"version"`
	H1      string `json:"h1,omitempty"`
	Mod     string `json:"mod,omitempty"`
}

// ParseGoSum reads go.sum lines into per-version entries, sorted.
func ParseGoSum(raw []byte) ([]GoSumEntry, error) {
	idx := map[string]*GoSumEntry{}
	for n, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) != 3 || !h1Re.MatchString(f[2]) {
			if len(f) == 3 && !strings.HasPrefix(f[2], "h1:") {
				continue // future hash algorithms: not ours to judge
			}
			return nil, fmt.Errorf("go.sum line %d is malformed", n+1)
		}
		mod, ver, isMod := f[0], f[1], false
		if strings.HasSuffix(ver, "/go.mod") {
			ver, isMod = strings.TrimSuffix(ver, "/go.mod"), true
		}
		k := mod + "@" + ver
		e := idx[k]
		if e == nil {
			e = &GoSumEntry{Module: mod, Version: ver}
			idx[k] = e
		}
		if isMod {
			e.Mod = f[2]
		} else {
			e.H1 = f[2]
		}
	}
	out := make([]GoSumEntry, 0, len(idx))
	for _, k := range sortedKeys(idx) {
		out = append(out, *idx[k])
	}
	return out, nil
}
