package strictjson

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ExactDocument checks that raw is exactly one valid JSON document (trailing
// content of any kind, a stray closing delimiter included, is refused) in which
// no object names the same member twice, compared EXACTLY after unescaping.
//
// It is the document check for npm lockfiles and manifests, whose member names
// are case-sensitive: "Dependencies" and "dependencies" are two members there,
// and a lockfile may hold both node_modules/Foo and node_modules/foo. Unlike
// RejectRepeatedMembers it never folds case, so it cannot refuse a legitimate
// pair of names; the second spellings of the fields that matter are the job of
// RejectVariants.
func ExactDocument(raw []byte) error {
	paths, err := RepeatedMemberPaths(raw)
	if err != nil {
		return err
	}
	if len(paths) > 0 {
		return fmt.Errorf("member %v is given more than once", paths[0])
	}
	return nil
}

// RejectVariants refuses an object that carries a second spelling of one of the
// exact member names: the same name in another case or under any Unicode
// folding (the Kelvin sign for k, the long s for s). encoding/json binds a
// member to a struct field case-insensitively, so a reader that decodes into a
// struct would otherwise let "Resolved" stand in for, or replace, "resolved"
// while npm, which reads exact names, reads the other one.
//
// Only the names given are protected: every other member, spelled any way,
// stays allowed.
func RejectVariants(members map[string]json.RawMessage, exact ...string) error {
	for key := range members {
		for _, name := range exact {
			if key != name && strings.EqualFold(key, name) {
				return fmt.Errorf("member %q is a second spelling of %q", key, name)
			}
		}
	}
	return nil
}

// ParseObject decodes raw as exactly one JSON object whose members are
// exactly named (see ExactDocument) and returns them undecoded.
func ParseObject(raw []byte) (map[string]json.RawMessage, error) {
	if err := ExactDocument(raw); err != nil {
		return nil, err
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil || members == nil {
		return nil, fmt.Errorf("not a JSON object")
	}
	return members, nil
}
