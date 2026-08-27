// Package strictjson holds JSON strictness checks shared by the surfaces that
// decode operator- or machine-supplied documents and must not let a
// serialization quirk change a decision.
//
// It checks ONE thing: that no object names the same member twice, at any
// depth. Encoding/json keeps the last occurrence of a repeated key silently, so
// a document saying both spec_version 3 and spec_version 1 — or two conflicting
// verdict facts — would quietly become whichever the writer put last. That is a
// decision changed by byte order, which no gate may allow.
//
// It is NOT a decoder and does not validate structure: callers must still
// strict-decode the document themselves (the token walk tolerates malformed
// JSON by stopping early rather than erroring, so a caller that skips its own
// decode would accept garbage). The contract is: run RejectRepeatedMembers on
// the raw bytes AND strict-decode them; this package owns only the first half.
package strictjson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// RejectRepeatedMembers walks the document's tokens and refuses any object that
// names the same member twice, at any depth. The returned error names the
// offending path (e.g. `"checks.tuf" is given more than once`); callers wrap it
// with their own context prefix.
func RejectRepeatedMembers(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil {
		// A malformed or empty document has no repeats to find; the caller's
		// own strict decode is what refuses it. See the package contract.
		return nil
	}
	return walkForRepeats(decoder, token, "")
}

func walkForRepeats(decoder *json.Decoder, token json.Token, path string) error {
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}

	switch delim {
	case '{':
		seen := make(map[string]bool)
		for {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil
			}
			if end, ok := keyToken.(json.Delim); ok && end == '}' {
				return nil
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil
			}
			// Fold to the consuming decoder's matching rule before comparing.
			// encoding/json binds an object member to a struct field
			// case-insensitively, so `Blocklist` and `blocklist` decode to the
			// SAME field and the later occurrence silently wins — the exact
			// byte-order-decides-the-value bug an exact-string compare would miss.
			// Members here are ASCII identifiers, for which ToLower is that fold;
			// being no looser than the decoder, it never rejects two members the
			// decoder would keep distinct.
			folded := strings.ToLower(key)
			if seen[folded] {
				return fmt.Errorf("%q is given more than once", path+key)
			}
			seen[folded] = true

			valueToken, err := decoder.Token()
			if err != nil {
				return nil
			}
			if err := walkForRepeats(decoder, valueToken, path+key+"."); err != nil {
				return err
			}
		}
	case '[':
		for {
			elementToken, err := decoder.Token()
			if err != nil {
				return nil
			}
			if end, ok := elementToken.(json.Delim); ok && end == ']' {
				return nil
			}
			if err := walkForRepeats(decoder, elementToken, path); err != nil {
				return err
			}
		}
	}
	return nil
}
