package strictjson

import "testing"

func TestExactDocument(t *testing.T) {
	for name, raw := range map[string]string{
		"an object":                  `{"a":1}`,
		"case-distinct names":        `{"Foo":1,"foo":2}`,
		"nested case-distinct names": `{"p":{"node_modules/Foo":{},"node_modules/foo":{}}}`,
	} {
		if err := ExactDocument([]byte(raw)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, raw := range map[string]string{
		"a repeated member":        `{"a":1,"a":2}`,
		"a nested repeated member": `{"p":{"a":1,"a":2}}`,
		"a stray closing brace":    `{"a":1}}`,
		"a second document":        `{"a":1}{"a":1}`,
		"trailing text":            `{"a":1} x`,
		"not JSON":                 `{`,
		"empty":                    ``,
	} {
		if err := ExactDocument([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRejectVariants(t *testing.T) {
	cases := map[string]bool{
		`{"resolved":"a"}`:                         false,
		`{"resolved":"a","Resolved":"b"}`:          true,
		`{"RESOLVED":"b"}`:                         true,
		`{"resolved":"a","funding":1,"Funding":2}`: false,
		"{\"integrity\":1,\"ıntegrity\":2}":        false, // dotless i does not fold to i
		"{\"integrity\":1}":                        false, // an escaped t is just t
		"{\"Key\":1}":                              true,  // Kelvin sign folds to k
	}
	for raw, wantErr := range cases {
		members, err := ParseObject([]byte(raw))
		if err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		err = RejectVariants(members, "resolved", "integrity", "key")
		if (err != nil) != wantErr {
			t.Errorf("%s: err = %v, want error = %v", raw, err, wantErr)
		}
	}
}

func TestRejectConflictMarkers(t *testing.T) {
	for name, raw := range map[string]string{
		"a git conflict":          "<<<<<<< HEAD\n{}\n=======\n{}\n>>>>>>> branch\n",
		"the markers in a string": `{"description":"<<<<<<< ======= >>>>>>>"}`,
	} {
		if RejectConflictMarkers([]byte(raw)) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, raw := range map[string]string{
		"a plain document":        `{"a":1}`,
		"two of the three":        `{"d":"<<<<<<< >>>>>>>"}`,
		"runs that are too short": `{"d":"<<<<<< ====== >>>>>>"}`,
		"base64 padding":          `{"integrity":"sha512-AAAA=="}`,
	} {
		if err := RejectConflictMarkers([]byte(raw)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestExactDocumentRefusesAByteOrderMark(t *testing.T) {
	if err := ExactDocument([]byte("\xef\xbb\xbf{\"a\":1}")); err == nil {
		t.Fatal("a UTF-8 byte-order mark was accepted (npm strips it; this reader refuses it: a compatibility limit)")
	}
}
