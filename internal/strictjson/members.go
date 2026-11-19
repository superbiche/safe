package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// RepeatedMemberPaths walks one JSON document and returns the path of every
// object member that is named a second time in its object, in document order.
// A path is a list of object member names (strings) and array indexes (ints)
// down to the repeated member.
//
// It is the checker for readers that must tell three outcomes apart, which
// RejectRepeatedMembers cannot: the document was read to its end and holds no
// repeated member (empty result, nil error); it holds some (the paths, nil
// error); it cannot be read as one JSON document, whatever the reason (an
// error, never an empty result). The differences from RejectRepeatedMembers
// are deliberate and local to this function:
//
//   - every token error is returned: a walk that stops early on an error has
//     not seen the rest of the document, and "nothing found" there is false;
//   - numbers are kept as text (json.Number), so a value no float64 can hold
//     (1e400) is still a number, not a failure to read;
//   - member names are compared exactly, after JSON unescaping: "case" and
//     "Case" are two names, as they are to jq, and "a" and "a" are one;
//   - exactly one document: trailing data is an error.
func RepeatedMemberPaths(raw []byte) ([][]any, error) {
	if !json.Valid(raw) {
		return nil, errors.New("not a single valid JSON document")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	found := [][]any{}
	token, err := decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	if err := walkPaths(decoder, token, nil, &found); err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("read: data after the document")
	}
	return found, nil
}

func walkPaths(decoder *json.Decoder, token json.Token, path []any, found *[][]any) error {
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			if end, ok := keyToken.(json.Delim); ok && end == '}' {
				return nil
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object member name is not a string")
			}
			here := append(append([]any{}, path...), key)
			if _, dup := seen[key]; dup {
				*found = append(*found, here)
			}
			seen[key] = struct{}{}
			valueToken, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := walkPaths(decoder, valueToken, here, found); err != nil {
				return err
			}
		}
	case '[':
		for index := 0; ; index++ {
			elementToken, err := decoder.Token()
			if err != nil {
				return err
			}
			if end, ok := elementToken.(json.Delim); ok && end == ']' {
				return nil
			}
			here := append(append([]any{}, path...), index)
			if err := walkPaths(decoder, elementToken, here, found); err != nil {
				return err
			}
		}
	}
	return nil
}
