package projectlane

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// The project's own .npmrc is read by safe, as text, before any npm run, and
// admitted against a short allow-list: npm acts on a project's configuration
// (it creates the cache and log directories, follows a registry, loads a
// certificate) before it can report what the configuration means, and part of
// what it reports is hidden. The reader takes the ini subset npm itself writes,
// one `key=value` per line, with comments and blank lines, and nothing else:
// no section, no interpolation, no continuation, no quoting, no repeated key,
// no byte-order mark, no text it cannot parse.

// npmrcSettings is the allow-list: every setting a project's .npmrc may carry,
// with the values it may hold. Everything else (cache, logs, prefix, location,
// global, any other registry, auth, proxy and certificate settings, script and
// git settings, release-age settings, workspaces, package-lock and dry-run
// switches, ...) refuses.
var npmrcSettings = map[string]func(string) bool{
	"save-exact":    isBool,
	"engine-strict": isBool,
	"fund":          isBool,
	"audit":         isBool,
	"progress":      isBool,
	"save-prefix":   func(v string) bool { return v == "^" || v == "~" || v == "" },
	"loglevel": func(v string) bool {
		switch v {
		case "silent", "error", "warn", "notice", "http", "info", "verbose", "silly":
			return true
		}
		return false
	},
	"registry": func(v string) bool { return v == CanonicalRegistry },
}

var reNpmrcKey = regexp.MustCompile(`^(?:@[A-Za-z0-9][A-Za-z0-9._~-]*:registry|[a-z][a-z0-9-]*)$`)

func isBool(v string) bool { return v == "true" || v == "false" }

// NpmrcAllowList lists the settings (and the scoped-registry form) the reader
// admits, for the documentation and the tests.
func NpmrcAllowList() []string {
	out := make([]string, 0, len(npmrcSettings)+1)
	for key := range npmrcSettings {
		out = append(out, key)
	}
	out = append(out, "@scope:registry")
	return out
}

// AdmitNpmrc reads a project .npmrc and returns what it does not admit. The text
// of a refusal is the setting's name, never its value: a value may be a credential.
func AdmitNpmrc(raw []byte) []Refusal {
	var refusals []Refusal
	refuse := func(line int, text, reason string) {
		refusals = append(refusals, Refusal{Where: fmt.Sprintf(".npmrc line %d", line), Text: text, Reason: reason})
	}
	if bytes.HasPrefix(raw, []byte{0xEF, 0xBB, 0xBF}) {
		return []Refusal{{Where: ".npmrc", Reason: "a byte-order mark"}}
	}
	if !utf8.Valid(raw) || bytes.IndexByte(raw, 0) >= 0 || bytes.IndexByte(raw, '\r') >= 0 {
		return []Refusal{{Where: ".npmrc", Reason: "text that is not plain UTF-8 lines (a NUL, a carriage return or invalid bytes)"}}
	}
	seen := map[string]bool{}
	for i, line := range strings.Split(string(raw), "\n") {
		number := i + 1
		line = strings.Trim(line, " \t")
		if line == "" || line[0] == ';' || line[0] == '#' {
			continue
		}
		if strings.Contains(line, "${") {
			refuse(number, settingName(line), "interpolation")
			continue
		}
		if line[0] == '[' {
			refuse(number, "", "a section")
			continue
		}
		if strings.HasSuffix(line, "\\") {
			refuse(number, settingName(line), "a continuation line")
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			refuse(number, settingName(line), "a line that is not key=value")
			continue
		}
		key, value = strings.Trim(key, " \t"), strings.Trim(value, " \t")
		if !reNpmrcKey.MatchString(key) {
			refuse(number, settingName(key), "a setting that is not on the allow-list")
			continue
		}
		if seen[key] {
			refuse(number, key, "a repeated setting")
			continue
		}
		seen[key] = true
		if strings.ContainsAny(value, ";#\"'") {
			refuse(number, key, "a value with a comment or a quote")
			continue
		}
		check := npmrcSettings[key]
		if strings.HasPrefix(key, "@") {
			check = npmrcSettings["registry"]
		}
		if check == nil {
			refuse(number, key, "a setting that is not on the allow-list")
			continue
		}
		if !check(value) {
			refuse(number, key, "a value that is not on the allow-list for this setting")
		}
	}
	return refusals
}

// settingName is the part of a line that names a setting, bounded, never its value.
func settingName(line string) string {
	key, _, _ := strings.Cut(line, "=")
	key = strings.Trim(key, " \t")
	if len(key) > 64 {
		key = key[:64]
	}
	return key
}
