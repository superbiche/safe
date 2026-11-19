package projectlane

import "testing"

func TestCheckBindable(t *testing.T) {
	cases := []struct {
		name     string
		packages map[string]map[string]any
		hosts    []string
		want     map[string]string // path -> reason, absent = bound
	}{
		{name: "canonical registry entry is bound", packages: pkgs("a", "1.0.0")},
		{name: "scoped canonical entry is bound", packages: map[string]map[string]any{
			"node_modules/@s/p": entry("@s/p", "1.2.3"),
		}},
		{name: "host-only default registry descriptor is not the canonical string", packages: map[string]map[string]any{
			"node_modules/a": with(entry("a", "1.0.0"), map[string]any{"resolved": "registry.npmjs.org/a/-/a-1.0.0.tgz"}),
		}, want: map[string]string{"node_modules/a": ReasonOriginNotCanonical}},
		{name: "poisoned location: encoded scope separator", packages: map[string]map[string]any{
			"node_modules/@test/p": with(entry("@test/p", "1.0.0"), map[string]any{"resolved": "https://registry.npmjs.org/@test%2fp/-/p-1.0.0.tgz"}),
		}, want: map[string]string{"node_modules/@test/p": ReasonOriginNotCanonical}},
		{name: "poisoned location: any percent-encoding", packages: map[string]map[string]any{
			"node_modules/a": with(entry("a", "1.0.0"), map[string]any{"resolved": "https://registry.npmjs.org/%61/-/a-1.0.0.tgz"}),
		}, want: map[string]string{"node_modules/a": ReasonOriginNotCanonical}},
		{name: "poisoned location: canonical string with credentials in front of the expected host", packages: map[string]map[string]any{
			"node_modules/a": with(entry("a", "1.0.0"), map[string]any{"resolved": "https://user:pw@registry.npmjs.org/a/-/a-1.0.0.tgz"}),
		}, want: map[string]string{"node_modules/a": ReasonOriginNotCanonical}},
		{name: "poisoned location: port", packages: map[string]map[string]any{
			"node_modules/a": with(entry("a", "1.0.0"), map[string]any{"resolved": "https://registry.npmjs.org:8443/a/-/a-1.0.0.tgz"}),
		}, want: map[string]string{"node_modules/a": ReasonKindNotAdmitted}},
		{name: "poisoned location: upper-case host is not the written canonical string", packages: map[string]map[string]any{
			"node_modules/a": with(entry("a", "1.0.0"), map[string]any{"resolved": "https://Registry.npmjs.org/a/-/a-1.0.0.tgz"}),
		}, want: map[string]string{"node_modules/a": ReasonOriginNotCanonical}},
		{name: "a version that is not an exact version has no canonical location", packages: map[string]map[string]any{
			"node_modules/a": with(entry("a", "^1.0.0"), map[string]any{"resolved": "https://registry.npmjs.org/a/-/a-^1.0.0.tgz"}),
		}, want: map[string]string{"node_modules/a": ReasonIdentityInvalid}},
		{name: "a name that needs escaping has no canonical location", packages: map[string]map[string]any{
			"node_modules/a!b": with(entry("a!b", "1.0.0"), map[string]any{"resolved": "https://registry.npmjs.org/a!b/-/a!b-1.0.0.tgz"}),
		}, want: map[string]string{"node_modules/a!b": ReasonIdentityInvalid}},
		{name: "prerelease and build versions are canonical as written", packages: map[string]map[string]any{
			"node_modules/a": entry("a", "1.0.0-rc.1+build.5"),
		}},
		{name: "bundled entry that names a location of its own must bind on its own: foreign location", packages: map[string]map[string]any{
			"node_modules/p":                 entry("p", "1.0.0"),
			"node_modules/p/node_modules/in": {"version": "1.0.0", "inBundle": true, "resolved": "https://evil.example/in.tgz", "integrity": integrityOf("in")},
		}, want: map[string]string{"node_modules/p/node_modules/in": ReasonKindNotAdmitted}},
		{name: "bundled entry that names a location of its own must bind on its own: no hash", packages: map[string]map[string]any{
			"node_modules/p":                 entry("p", "1.0.0"),
			"node_modules/p/node_modules/in": with(entry("in", "1.0.0"), map[string]any{"inBundle": true, "integrity": nil}),
		}, want: map[string]string{"node_modules/p/node_modules/in": ReasonIntegrityMissing}},
		{name: "bundled entry that names a canonical location of its own binds on it", packages: map[string]map[string]any{
			"node_modules/p":                 entry("p", "1.0.0"),
			"node_modules/p/node_modules/in": with(entry("in", "1.0.0"), map[string]any{"inBundle": true}),
		}},
		{name: "a chain of bundle flags under a bound registry artifact is covered by it", packages: map[string]map[string]any{
			"node_modules/p":                                 entry("p", "1.0.0"),
			"node_modules/p/node_modules/in":                 {"version": "1.0.0", "inBundle": true},
			"node_modules/p/node_modules/in/node_modules/dd": {"version": "1.0.0", "inBundle": true},
		}},
		{name: "a bundle flag under a link proves no covering tarball", packages: map[string]map[string]any{
			"node_modules/l":                 {"resolved": "packages/l", "link": true},
			"node_modules/l/node_modules/in": {"version": "1.0.0", "inBundle": true},
		}, want: map[string]string{"node_modules/l/node_modules/in": ReasonParentUnbound}},
		{name: "an in-project workspace member the link points at is admitted", packages: map[string]map[string]any{
			"node_modules/ws": {"resolved": "packages/ws", "link": true},
			"packages/ws":     {"name": "ws", "version": "1.0.0"},
		}},
		{name: "alias is bound by its real name", packages: map[string]map[string]any{
			"node_modules/alias": with(entry("real", "1.0.0"), map[string]any{"name": "real"}),
		}},
		{name: "poisoned location: another package's tarball", packages: map[string]map[string]any{
			"node_modules/a": with(entry("a", "1.0.0"), map[string]any{"resolved": tarball("evil", "1.0.0")}),
		}, want: map[string]string{"node_modules/a": ReasonOriginNotCanonical}},
		{name: "poisoned location: another version's tarball", packages: map[string]map[string]any{
			"node_modules/a": with(entry("a", "1.0.0"), map[string]any{"resolved": tarball("a", "1.0.1")}),
		}, want: map[string]string{"node_modules/a": ReasonOriginNotCanonical}},
		{name: "poisoned location: unexpected host", packages: map[string]map[string]any{
			"node_modules/a": with(entry("a", "1.0.0"), map[string]any{"resolved": "https://evil.example/a/-/a-1.0.0.tgz"}),
		}, want: map[string]string{"node_modules/a": ReasonKindNotAdmitted}},
		{name: "poisoned location: look-alike host", packages: map[string]map[string]any{
			"node_modules/a": with(entry("a", "1.0.0"), map[string]any{"resolved": "https://registry.npmjs.org.evil.example/a/-/a-1.0.0.tgz"}),
		}, want: map[string]string{"node_modules/a": ReasonKindNotAdmitted}},
		{name: "poisoned location: userinfo naming the expected host", packages: map[string]map[string]any{
			"node_modules/a": with(entry("a", "1.0.0"), map[string]any{"resolved": "https://registry.npmjs.org@evil.example/a/-/a-1.0.0.tgz"}),
		}, want: map[string]string{"node_modules/a": ReasonKindNotAdmitted}},
		{name: "poisoned location: query string", packages: map[string]map[string]any{
			"node_modules/a": with(entry("a", "1.0.0"), map[string]any{"resolved": tarball("a", "1.0.0") + "?redirect=evil"}),
		}, want: map[string]string{"node_modules/a": ReasonOriginNotCanonical}},
		{name: "poisoned location: plain http", packages: map[string]map[string]any{
			"node_modules/a": with(entry("a", "1.0.0"), map[string]any{"resolved": "http://registry.npmjs.org/a/-/a-1.0.0.tgz"}),
		}, want: map[string]string{"node_modules/a": ReasonOriginNotCanonical}},
		{name: "poisoned location: path prefix", packages: map[string]map[string]any{
			"node_modules/a": with(entry("a", "1.0.0"), map[string]any{"resolved": "https://registry.npmjs.org/x/a/-/a-1.0.0.tgz"}),
		}, want: map[string]string{"node_modules/a": ReasonOriginNotCanonical}},
		{name: "missing hash", packages: map[string]map[string]any{
			"node_modules/a": with(entry("a", "1.0.0"), map[string]any{"integrity": nil}),
		}, want: map[string]string{"node_modules/a": ReasonIntegrityMissing}},
		{name: "malformed hash", packages: map[string]map[string]any{
			"node_modules/a": with(entry("a", "1.0.0"), map[string]any{"integrity": "sha512-nope"}),
		}, want: map[string]string{"node_modules/a": ReasonIntegrityMalformed}},
		{name: "unknown hash algorithm", packages: map[string]map[string]any{
			"node_modules/a": with(entry("a", "1.0.0"), map[string]any{"integrity": "md5-AAAAAAAAAAAAAAAAAAAAAA=="}),
		}, want: map[string]string{"node_modules/a": ReasonIntegrityMalformed}},
		{name: "own shrinkwrap", packages: map[string]map[string]any{
			"node_modules/a": with(entry("a", "1.0.0"), map[string]any{"hasShrinkwrap": true}),
		}, want: map[string]string{"node_modules/a": ReasonOwnShrinkwrap}},
		{name: "no resolved location", packages: map[string]map[string]any{
			"node_modules/a": {"version": "1.0.0", "integrity": integrityOf("a")},
		}, want: map[string]string{"node_modules/a": ReasonKindNotAdmitted}},
		{name: "git source", packages: map[string]map[string]any{
			"node_modules/a": {"version": "1.0.0", "resolved": "git+ssh://git@github.com/x/y.git#abc"},
		}, want: map[string]string{"node_modules/a": ReasonKindNotAdmitted}},
		{name: "file source", packages: map[string]map[string]any{
			"node_modules/a": {"version": "1.0.0", "resolved": "file:../a.tgz"},
		}, want: map[string]string{"node_modules/a": ReasonKindNotAdmitted}},
		{name: "remote tarball", packages: map[string]map[string]any{
			"node_modules/a": {"version": "1.0.0", "resolved": "https://evil.example/a.tgz", "integrity": integrityOf("a")},
		}, want: map[string]string{"node_modules/a": ReasonKindNotAdmitted}},
		{name: "extra expected host", hosts: []string{"npm.internal.example"}, packages: map[string]map[string]any{
			"node_modules/a": with(entry("a", "1.0.0"), map[string]any{"resolved": "https://npm.internal.example/a/-/a-1.0.0.tgz"}),
		}},
		{name: "extra host is not expected unless named", packages: map[string]map[string]any{
			"node_modules/a": with(entry("a", "1.0.0"), map[string]any{"resolved": "https://npm.internal.example/a/-/a-1.0.0.tgz"}),
		}, want: map[string]string{"node_modules/a": ReasonKindNotAdmitted}},
		{name: "in-project link", packages: map[string]map[string]any{
			"node_modules/l": {"resolved": "packages/l", "link": true},
		}},
		{name: "link climbing out of the project", packages: map[string]map[string]any{
			"node_modules/l": {"resolved": "../outside", "link": true},
		}, want: map[string]string{"node_modules/l": ReasonLinkOutsideProject}},
		{name: "link to an absolute path", packages: map[string]map[string]any{
			"node_modules/l": {"resolved": "/etc", "link": true},
		}, want: map[string]string{"node_modules/l": ReasonLinkOutsideProject}},
		{name: "link that cleans out of the project", packages: map[string]map[string]any{
			"node_modules/l": {"resolved": "packages/../../x", "link": true},
		}, want: map[string]string{"node_modules/l": ReasonLinkOutsideProject}},
		{name: "bundled entry is covered by its bound parent", packages: map[string]map[string]any{
			"node_modules/p":                 entry("p", "1.0.0"),
			"node_modules/p/node_modules/in": {"version": "1.0.0", "inBundle": true},
		}},
		{name: "bundled entry of an unbound parent is not bound", packages: map[string]map[string]any{
			"node_modules/p":                 with(entry("p", "1.0.0"), map[string]any{"integrity": nil}),
			"node_modules/p/node_modules/in": {"version": "1.0.0", "inBundle": true},
		}, want: map[string]string{
			"node_modules/p":                 ReasonIntegrityMissing,
			"node_modules/p/node_modules/in": ReasonParentUnbound,
		}},
		{name: "bundled entry without a parent entry", packages: map[string]map[string]any{
			"node_modules/in": {"version": "1.0.0", "inBundle": true},
		}, want: map[string]string{"node_modules/in": ReasonParentUnbound}},
		{name: "bundled entry that carries its own shrinkwrap", packages: map[string]map[string]any{
			"node_modules/p":                 entry("p", "1.0.0"),
			"node_modules/p/node_modules/in": {"version": "1.0.0", "inBundle": true, "hasShrinkwrap": true},
		}, want: map[string]string{"node_modules/p/node_modules/in": ReasonOwnShrinkwrap}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			graph, err := LoadGraph(writeLock(t, tc.packages), Hosts{Registry: tc.hosts})
			if err != nil {
				t.Fatal(err)
			}
			got := CheckBindable(graph, tc.hosts)
			if got.Bound != (len(tc.want) == 0) {
				t.Fatalf("Bound = %v, want %v (unbound: %+v)", got.Bound, len(tc.want) == 0, got.Unbound)
			}
			reasons := map[string]string{}
			for _, unbound := range got.Unbound {
				reasons[unbound.Path] = unbound.Reason
			}
			if len(reasons) != len(tc.want) {
				t.Fatalf("unbound = %v, want %v", reasons, tc.want)
			}
			for path, reason := range tc.want {
				if reasons[path] != reason {
					t.Fatalf("unbound = %v, want %v", reasons, tc.want)
				}
			}
		})
	}
}

func TestCheckBindableEmptyGraphIsBound(t *testing.T) {
	got := CheckBindable(Graph{}, nil)
	if !got.Bound || got.Unbound == nil {
		t.Fatalf("CheckBindable(empty) = %+v, want bound with an empty (non-nil) list", got)
	}
}
