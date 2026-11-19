package strictjson

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRejectRepeatedMembers(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantSub string // "" means the document is accepted
	}{
		{
			name: "flat duplicate",
			raw:  `{"a":1,"a":2}`,
			// path is the bare key at the top level
			wantSub: `"a" is given more than once`,
		},
		{
			name:    "nested duplicate reports the dotted path",
			raw:     `{"outer":{"inner":1,"inner":2}}`,
			wantSub: `"outer.inner" is given more than once`,
		},
		{
			name:    "duplicate inside an array element",
			raw:     `{"list":[{"k":1,"k":2}]}`,
			wantSub: `"list.k" is given more than once`,
		},
		{
			// encoding/json binds both to the same field case-insensitively, so
			// they are a repeat the exact-string compare would have missed.
			name:    "case-folded duplicate (matches the decoder's field folding)",
			raw:     `{"blocklist":1,"Blocklist":2}`,
			wantSub: `"Blocklist" is given more than once`,
		},
		{
			name:    "case-folded duplicate, alias first",
			raw:     `{"Blocklist":1,"blocklist":2}`,
			wantSub: `"blocklist" is given more than once`,
		},
		{
			name: "same key in sibling array elements is not a repeat",
			raw:  `{"list":[{"k":1},{"k":2}]}`,
		},
		{
			name: "same key at different depths is not a repeat",
			raw:  `{"k":{"k":1}}`,
		},
		{
			name: "deeply nested but duplicate-free",
			raw:  `{"a":{"b":{"c":[1,2,{"d":3}]}},"e":4}`,
		},
		{
			name: "malformed JSON is tolerated (caller's decode refuses it)",
			raw:  `{"a":`,
		},
		{
			name: "empty input is tolerated",
			raw:  ``,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := RejectRepeatedMembers([]byte(tc.raw))
			if tc.wantSub == "" {
				if err != nil {
					t.Fatalf("RejectRepeatedMembers(%s) = %v; want nil", tc.raw, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("RejectRepeatedMembers(%s) = nil; want error containing %q", tc.raw, tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("RejectRepeatedMembers(%s) = %q; want substring %q", tc.raw, err.Error(), tc.wantSub)
			}
		})
	}
}

func TestRepeatedMemberPaths(t *testing.T) {
	cases := []struct {
		name     string
		document string
		want     string // JSON of the paths, or "" for an error
	}{
		{"clean", `{"a":[{"b":1}],"c":2}`, `[]`},
		{"top-level scalar", `7`, `[]`},
		{"repeated scalar", `{"id":"A","id":"B"}`, `[["id"]]`},
		{"repeated container beside a populated one", `{"results":[{"vulns":[{"id":"A"}]},{"vulns":[],"vulns":[]}]}`, `[["results",1,"vulns"]]`},
		{"repeated in the envelope", `{"results":[],"results":[]}`, `[["results"]]`},
		{"several, in document order", `{"x":{"y":1,"y":2},"z":[{"q":1,"q":2}],"x":3}`, `[["x","y"],["z",0,"q"],["x"]]`},
		{"names differing only by case are two names", `{"case":1,"Case":2}`, `[]`},
		{"an escaped spelling is the same name", `{"a":1,"a":2}`, `[["a"]]`},
		{"a number no float64 holds is still a number", `{"extra":1e400,"results":[{"v":1,"v":2}]}`, `[["results",0,"v"]]`},
		{"NaN is not JSON", `{"extra":NaN,"results":[]}`, ``},
		{"Infinity is not JSON", `[Infinity]`, ``},
		{"truncated", `{"a":1,"a":`, ``},
		{"empty", ``, ``},
		{"two documents", `{} {}`, ``},
		{"trailing garbage", `{"a":1} x`, ``},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			paths, err := RepeatedMemberPaths([]byte(tc.document))
			if tc.want == "" {
				if err == nil {
					t.Fatalf("RepeatedMemberPaths() = %v, want an error", paths)
				}
				return
			}
			if err != nil {
				t.Fatalf("RepeatedMemberPaths() error = %v", err)
			}
			got, _ := json.Marshal(paths)
			if string(got) != tc.want {
				t.Fatalf("RepeatedMemberPaths() = %s, want %s", got, tc.want)
			}
		})
	}
}
