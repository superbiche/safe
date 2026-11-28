package projectlane

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

var wireNow = time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)

const goodKey = `{"id":"GHSA-a","modified":"s","package":"p"}`

func goodHit(fetched int64) string {
	return fmt.Sprintf(`{"id":"GHSA-a","modified":"s","package":"p","severity":"high","withdrawn":false,"fetched":%d}`, fetched)
}

func TestParseAdvisoryGetRequestIsStrict(t *testing.T) {
	for name, tc := range map[string]struct {
		in string
		ok bool
	}{
		"whole":                        {`{"classifier":"c","keys":[` + goodKey + `]}`, true},
		"no keys, an empty list":       {`{"classifier":"c","keys":[]}`, true},
		"no keys member":               {`{"classifier":"c"}`, false},
		"a null keys":                  {`{"classifier":"c","keys":null}`, false},
		"a null classifier":            {`{"classifier":null,"keys":[]}`, false},
		"an empty classifier":          {`{"classifier":"","keys":[]}`, false},
		"a case variant of keys":       {`{"classifier":"c","Keys":[]}`, false},
		"a case variant of classifier": {`{"Classifier":"c","keys":[]}`, false},
		"a repeated member":            {`{"classifier":"c","classifier":"d","keys":[]}`, false},
		"a repeated member in a key":   {`{"classifier":"c","keys":[{"id":"a","id":"b","modified":"s","package":"p"}]}`, false},
		"a stray closing delimiter":    {`{"classifier":"c","keys":[]}}`, false},
		"two documents":                {`{"classifier":"c","keys":[]}{"classifier":"c","keys":[]}`, false},
		"a member too many":            {`{"classifier":"c","keys":[],"x":1}`, false},
		"a key with a member too many": {`{"classifier":"c","keys":[{"id":"a","modified":"s","package":"p","x":1}]}`, false},
		"a key missing a member":       {`{"classifier":"c","keys":[{"id":"a","modified":"s"}]}`, false},
		"a key with a null member":     {`{"classifier":"c","keys":[{"id":"a","modified":null,"package":"p"}]}`, false},
		"a key that is not an object":  {`{"classifier":"c","keys":["a"]}`, false},
		"a key with a newline":         {`{"classifier":"c","keys":[{"id":"a","modified":"s\n","package":"p"}]}`, false},
		"a key with an empty part":     {`{"classifier":"c","keys":[{"id":"a","modified":"","package":"p"}]}`, false},
		"not an object":                {`[]`, false},
		"empty":                        {``, false},
	} {
		_, _, err := ParseAdvisoryGetRequest([]byte(tc.in))
		if (err == nil) != tc.ok {
			t.Fatalf("%s: err=%v, want ok=%v", name, err, tc.ok)
		}
	}
}

func TestParseAdvisoryPutRequestIsStrict(t *testing.T) {
	hit := goodHit(wireNow.Unix())
	for name, tc := range map[string]struct {
		in string
		ok bool
	}{
		"whole":                           {`{"classifier":"c","readings":[` + hit + `]}`, true},
		"an empty list":                   {`{"classifier":"c","readings":[]}`, true},
		"a null list":                     {`{"classifier":"c","readings":null}`, false},
		"no list":                         {`{"classifier":"c"}`, false},
		"a reading without withdrawn":     {`{"classifier":"c","readings":[{"id":"a","modified":"s","package":"p","severity":"high","fetched":1}]}`, false},
		"a reading with a null withdrawn": {`{"classifier":"c","readings":[{"id":"a","modified":"s","package":"p","severity":"high","withdrawn":null,"fetched":1}]}`, false},
		"a reading without severity":      {`{"classifier":"c","readings":[{"id":"a","modified":"s","package":"p","withdrawn":true,"fetched":1}]}`, false},
		"a reading with a float fetch":    {`{"classifier":"c","readings":[{"id":"a","modified":"s","package":"p","severity":"high","withdrawn":false,"fetched":1.5}]}`, false},
		"a case variant of a member":      {`{"classifier":"c","readings":[{"id":"a","modified":"s","package":"p","Severity":"high","withdrawn":false,"fetched":1}]}`, false},
		"a stray closing delimiter":       {`{"classifier":"c","readings":[]}]`, false},
	} {
		_, _, err := ParseAdvisoryPutRequest([]byte(tc.in))
		if (err == nil) != tc.ok {
			t.Fatalf("%s: err=%v, want ok=%v", name, err, tc.ok)
		}
	}
}

func TestCheckAdvisoryReplyIsStrict(t *testing.T) {
	asked := []AdvisoryKey{{ID: "GHSA-a", Modified: "s", Package: "p"}}
	now := wireNow.Unix()
	envelope := func(hits ...string) string {
		return `{"schema_version":1,"hits":[` + strings.Join(hits, ",") + `]}`
	}
	for name, tc := range map[string]struct {
		in string
		ok bool
	}{
		"whole":                        {envelope(goodHit(now)), true},
		"no hit":                       {envelope(), true},
		"two hits for one key":         {envelope(goodHit(now), goodHit(now)), false},
		"two hits, conflicting":        {envelope(goodHit(now), strings.Replace(goodHit(now), "high", "low", 1)), false},
		"a hit nobody asked for":       {envelope(strings.Replace(goodHit(now), `"s"`, `"t"`, 1)), false},
		"two envelopes":                {envelope(goodHit(now)) + envelope(goodHit(now)), false},
		"an extended envelope":         {`{"schema_version":1,"hits":[],"extra":1}`, false},
		"another schema":               {`{"schema_version":2,"hits":[]}`, false},
		"no schema member":             {`{"hits":[]}`, false},
		"null hits":                    {`{"schema_version":1,"hits":null}`, false},
		"a repeated member":            {`{"schema_version":1,"schema_version":1,"hits":[]}`, false},
		"a stray closing delimiter":    {envelope() + `}`, false},
		"a band that is not one":       {envelope(strings.Replace(goodHit(now), "high", "bogus", 1)), false},
		"a withdrawn hit with a band":  {envelope(strings.Replace(goodHit(now), `"withdrawn":false`, `"withdrawn":true`, 1)), false},
		"dated in the future":          {envelope(goodHit(now + 3600)), false},
		"a day old":                    {envelope(goodHit(now - 86400)), false},
		"inside the day":               {envelope(goodHit(now - 86399)), true},
		"a hit with a member too many": {envelope(strings.Replace(goodHit(now), `"fetched"`, `"x":1,"fetched"`, 1)), false},
		"a hit without a member":       {envelope(strings.Replace(goodHit(now), `"withdrawn":false,`, ``, 1)), false},
	} {
		got, err := CheckAdvisoryReply([]byte(tc.in), asked, wireNow)
		if (err == nil) != tc.ok {
			t.Fatalf("%s: err=%v, want ok=%v", name, err, tc.ok)
		}
		if tc.ok && name == "whole" && got["GHSA-a|p"] != "high" {
			t.Fatalf("whole: %v", got)
		}
	}
}
