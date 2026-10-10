// Package privtrust decides operator-managed trust for owner-controlled
// private package registries (trusted origins, operator ruling a37): which
// registry a package name belongs to, whether the package manager would fetch
// it from that registry's origin, and how local and fleet-followed statements
// combine. A name in a registered namespace fetched from its origin is trusted
// like a local artifact; there is no per-version pin or integrity ledger.
//
// The package reads two stores, both owned by bin/safe-run's trust root:
//
//   - private-registries.json: the local registry policy (operator TTY only);
//   - private-follow-state.json: the last verified signed statement accepted
//     from each fleet origin, honored only while its signer stays pinned.
//
// Nothing here fetches anything or reads a credential.
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
	"slices"
	"sort"
	"strings"

	"github.com/superbiche/safe/internal/strictjson"
)

const (
	PolicySchema    = "safe-private-registries/2"
	StatementSchema = "safe-private-registries-export/2"

	KindLocal    = "local"
	KindFollowed = "followed"
)

// Registry is one private registry definition.
type Registry struct {
	Ecosystem string   `json:"ecosystem"`
	Origin    string   `json:"origin"`
	Owner     string   `json:"owner,omitempty"`
	Namespace []string `json:"namespace"`
	Added     string   `json:"added,omitempty"`
	Reason    string   `json:"reason,omitempty"`
}

// Policy is private-registries.json.
type Policy struct {
	Schema     string              `json:"schema"`
	Registries map[string]Registry `json:"registries"`
}

// FollowedOrigin is the last accepted signed statement of one fleet origin.
type FollowedOrigin struct {
	Accepted        string              `json:"accepted"`
	StatementSHA256 string              `json:"statement_sha256"`
	Signer          string              `json:"signer"`
	Registries      map[string]Registry `json:"registries"`
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
}

var (
	registryIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	npmPartRe    = regexp.MustCompile(`^[a-z0-9~][a-z0-9._~-]*$`)
	pyNameRe     = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$`)
	pyNormRe     = regexp.MustCompile(`[-_.]+`)
	goElemRe     = regexp.MustCompile(`^[A-Za-z0-9._~+-]+$`)
	hostRe       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
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
	return r, nil
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

// Source names where a registry came from.
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

// View is the union of local state and every followed origin whose signer is
// still pinned. Followed state from an unpinned signer is invisible.
type View struct {
	registries []sourcedRegistry
}

// Stores bundles the store paths.
type Stores struct {
	Policy      string
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
	return Build(pol, fs, signers), nil
}

// Build assembles a view from already-loaded state.
func Build(pol Policy, fs FollowState, signers []string) *View {
	v := &View{}
	for _, id := range sortedKeys(pol.Registries) {
		v.registries = append(v.registries, sourcedRegistry{pol.Registries[id], Source{Kind: KindLocal, RegistryID: id}})
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
	}
	return v
}

// Match is the registry decision for one package name.
type Match struct {
	Lane        string   `json:"lane"` // none | private | conflict
	Ecosystem   string   `json:"ecosystem"`
	Name        string   `json:"name"`
	Origin      string   `json:"origin,omitempty"`
	Origins     []string `json:"origins,omitempty"`
	RegistryIDs []string `json:"registry_ids,omitempty"`
	Namespace   []string `json:"namespace,omitempty"`
	Sources     []Source `json:"sources,omitempty"`
}

// Match finds the registry a name belongs to. Several sources agreeing on the
// origin merge; different origins for one name are a conflict and never pick
// a winner.
func (v *View) Match(eco, name string) Match {
	m := Match{Lane: "none", Ecosystem: eco, Name: NormalizeName(eco, name)}
	origins := map[string]bool{}
	ids := map[string]bool{}
	for _, r := range v.registries {
		if r.Ecosystem != eco {
			continue
		}
		hit := ""
		for _, ns := range r.Namespace {
			if NamespaceMatches(eco, ns, name) {
				hit = ns
				break
			}
		}
		if hit == "" {
			continue
		}
		if !slices.Contains(m.Namespace, hit) {
			m.Namespace = append(m.Namespace, hit)
		}
		origins[r.Origin] = true
		if !ids[r.Source.RegistryID] {
			ids[r.Source.RegistryID] = true
			m.RegistryIDs = append(m.RegistryIDs, r.Source.RegistryID)
		}
		m.Sources = append(m.Sources, r.Source)
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
	}
	sort.Strings(m.RegistryIDs)
	sort.Strings(m.Namespace)
	return m
}

// Registries returns the effective registries of one ecosystem, in view order
// (local first, then followed origins).
func (v *View) Registries(eco string) []ListEntry {
	var out []ListEntry
	for _, r := range v.registries {
		if r.Ecosystem == eco {
			out = append(out, ListEntry{ID: r.Source.RegistryID, Ecosystem: r.Ecosystem,
				Origin: r.Origin, Namespace: r.Namespace, Source: r.Source})
		}
	}
	return out
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

// GoRouteResult is where `go` would fetch a module path from.
type GoRouteResult struct {
	OK     bool   `json:"ok"`
	Local  bool   `json:"local,omitempty"` // only file:// sources (or none) serve it
	Route  string `json:"route,omitempty"` // the GOPROXY entries up to and including the origin
	Reason string `json:"reason,omitempty"`
}

// GoRoute reports whether `go` would fetch modules under the module path
// prefix ns from origin. GONOPROXY (defaulting to GOPRIVATE) must not send any
// path of ns to its VCS directly. GOPROXY is walked in order: a file:// entry
// is a local source (a local artifact, not a substitution) and the walk
// continues past it, because go falls through when the local tree lacks a
// version; the first other entry must be the origin. A list that ends (or
// reaches off) after only file:// entries is local-only.
func GoRoute(ns, origin, goproxy, gonoproxy, goprivate string) GoRouteResult {
	noproxy := gonoproxy
	if noproxy == "" {
		noproxy = goprivate
	}
	if patternsReach(noproxy, ns) {
		return GoRouteResult{Reason: "GONOPROXY/GOPRIVATE sends " + ns + " modules to their VCS directly, not through the private registry"}
	}
	if strings.TrimSpace(goproxy) == "" {
		goproxy = "https://proxy.golang.org,direct"
	}
	var walked []string
	for _, e := range strings.FieldsFunc(goproxy, func(r rune) bool { return r == ',' || r == '|' }) {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(e), "file://") {
			walked = append(walked, e)
			continue
		}
		if e == "off" {
			return GoRouteResult{OK: true, Local: true, Route: strings.Join(append(walked, "off"), ",")}
		}
		if e == "direct" {
			return GoRouteResult{Reason: "GOPROXY sends " + ns + " modules to their VCS (direct) before the private registry"}
		}
		if c := CanonicalURL(e); c != "" && c == CanonicalURL(origin) {
			return GoRouteResult{OK: true, Route: strings.Join(append(walked, c), ",")}
		}
		return GoRouteResult{Reason: "GOPROXY lists " + redactURL(e) + " ahead of the private registry"}
	}
	return GoRouteResult{OK: true, Local: true, Route: strings.Join(walked, ",")}
}

// patternsReach reports whether any GONOPROXY/GOPRIVATE pattern matches the
// prefix ns itself or some path below it.
func patternsReach(globs, ns string) bool {
	if MatchPrefixPatterns(globs, ns) {
		return true
	}
	nsElems := strings.Split(ns, "/")
	for _, g := range strings.Split(globs, ",") {
		g = strings.TrimSuffix(strings.TrimSpace(g), "/")
		if g == "" {
			continue
		}
		ge := strings.Split(g, "/")
		if len(ge) <= len(nsElems) {
			continue
		}
		reach := true
		for i, e := range nsElems {
			if ok, _ := path.Match(ge[i], e); !ok {
				reach = false
				break
			}
		}
		if reach {
			return true
		}
	}
	return false
}

// redactURL drops any userinfo from a proxy URL before it is printed.
func redactURL(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.User != nil {
		u.User = nil
		return u.String()
	}
	return raw
}
