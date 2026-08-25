package strictjson

import (
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
