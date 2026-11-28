//go:build linux

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func advisoryState(t *testing.T) string {
	t.Helper()
	state := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	return state
}

func TestProjectAdvisoryPutThenGet(t *testing.T) {
	state := advisoryState(t)
	now := time.Now().Unix()
	put := fmt.Sprintf(`{"classifier":"c","readings":[{"id":"GHSA-a","modified":"s","package":"p","severity":"high","withdrawn":false,"fetched":%d},{"id":"GHSA-b","modified":"s","package":"p","severity":"unknown","withdrawn":false,"fetched":%d}]}`, now, now)
	if code, out, errText := runWithStdin(put, "project-advisory-put", "--state-dir", state); code != 0 || out != "" {
		t.Fatalf("put: %d %q %q", code, out, errText)
	}
	get := `{"classifier":"c","keys":[{"id":"GHSA-a","modified":"s","package":"p"},{"id":"GHSA-b","modified":"s","package":"p"},{"id":"GHSA-a","modified":"t","package":"p"}]}`
	code, out, errText := runWithStdin(get, "project-advisory-get", "--state-dir", state)
	if code != 0 {
		t.Fatalf("get: %d %q", code, errText)
	}
	var doc struct {
		SchemaVersion int `json:"schema_version"`
		Hits          []struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
		} `json:"hits"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || doc.SchemaVersion != 1 || len(doc.Hits) != 1 || doc.Hits[0].ID != "GHSA-a" || doc.Hits[0].Severity != "high" {
		t.Fatalf("get answered %q (%v)", out, err)
	}
}

func TestProjectAdvisoryWithoutAStateDirectoryThereIsNoCache(t *testing.T) {
	t.Setenv("SAFE_DATA_DIR", advisoryState(t))
	t.Setenv("XDG_STATE_HOME", advisoryState(t))
	for _, args := range [][]string{
		{"project-advisory-get"},
		{"project-advisory-put"},
		{"project-advisory-get", "--state-dir", "relative"},
		{"project-advisory-put", "--state-dir"},
		{"project-advisory-get", "--state-dir", "/x", "extra"},
	} {
		if code, out, _ := runWithStdin(`{"classifier":"c","keys":[],"readings":[]}`, args...); code != 2 || out != "" {
			t.Fatalf("%v: exit %d, output %q", args, code, out)
		}
	}
}

func TestProjectAdvisoryUnreadableRequestsAreErrorsAndAMissingStoreIsAMiss(t *testing.T) {
	state := advisoryState(t)
	for _, in := range []string{"", "{", `{"keys":[]}`, `{"classifier":"c","keys":[],"x":1}`, `{"classifier":"c","keys":[]} {}`} {
		if code, _, _ := runWithStdin(in, "project-advisory-get", "--state-dir", state); code != 3 {
			t.Fatalf("get %q: exit %d, want 3", in, code)
		}
		if code, _, _ := runWithStdin(in, "project-advisory-put", "--state-dir", state); code != 3 {
			t.Fatalf("put %q: exit %d, want 3", in, code)
		}
	}
	// a store that does not exist yet, or a state directory that is not there: no hit, not an error
	code, out, _ := runWithStdin(`{"classifier":"c","keys":[{"id":"a","modified":"s","package":"p"}]}`, "project-advisory-get", "--state-dir", filepath.Join(state, "missing"))
	if code != 0 || out != "{\"hits\":[],\"schema_version\":1}\n" {
		t.Fatalf("missing store: %d %q", code, out)
	}
	// a put that cannot store anything does not fail
	if code, _, _ := runWithStdin(`{"classifier":"c","readings":[{"id":"a","modified":"s","package":"p","severity":"low","withdrawn":false,"fetched":1}]}`, "project-advisory-put", "--state-dir", filepath.Join(state, "missing")); code != 0 {
		t.Fatalf("put into a missing state directory: exit %d", code)
	}
}
