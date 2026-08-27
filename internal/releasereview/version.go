package releasereview

import (
	"regexp"
	"strings"
)

// Version comparison, ported from the bash lanes' version_cmp /
// version_satisfies_constraint / version_matches_range.
//
// The bash lane compares two versions by feeding them to `sort -V` and looking
// at which one came out first, so the semantics this must reproduce are GNU
// version sort's, not semver's. The two disagree in ways that decide advisory
// matches: `1.2.3-rc1` sorts ABOVE `1.2.3` here, where semver puts a release
// candidate below its release. Everything below is a port of GNU filevercmp
// (what `sort -V` uses), and every case in version_test.go's tables was
// captured by running the bash functions rather than written from memory.

var (
	// The constraint grammar is the bash regexes, character for character. An
	// operator may be followed by whitespace; the right-hand side may not
	// contain whitespace or a comma, because a comma separates constraints.
	constraintWithOperator = regexp.MustCompile(`^(<=|>=|<|>|==|=)[[:space:]]*(v?[0-9][^[:space:],]*)$`)
	constraintBare         = regexp.MustCompile(`^(v?[0-9][^[:space:],]*)$`)

	// compoundBound matches GitHub's space-separated two-sided bound `A <= B`,
	// which means `>= A, <= B`: A the inclusive floor, B the inclusive ceiling.
	// GitHub's canonical form for an interval is the comma-separated `>= A, <= B`,
	// but some advisories store it as this single two-version part — openai/codex's
	// npm range `0.2.0 <= 0.38.0`, whose patched_versions `0.39.0` confirms 0.38.0
	// is the last affected version, so the ceiling is inclusive. Only `<=` is
	// admitted, the sole interior operator seen in real advisory data; any other
	// two-token shape stays ambiguous rather than have a grammar guessed into a
	// gate. Both sides must be versions, so a single-operator constraint (`<= B`,
	// operator first) and a bare version never match this — the addition is purely
	// additive, turning a previously-ambiguous string into a decided one.
	compoundBound = regexp.MustCompile(`^(v?[0-9][^[:space:],]*)[[:space:]]+<=[[:space:]]+(v?[0-9][^[:space:],]*)$`)
)

// rangeMatch is what a version-range comparison concluded. Ambiguous is a third
// answer, not a flavour of "no": a range this build cannot parse says nothing
// about the version, and every caller fails closed on it.
type rangeMatch int

const (
	rangeMatches rangeMatch = iota
	rangeExcludes
	rangeAmbiguous
)

// asciiSpace is bash's [:space:] in the C locale. strings.TrimSpace would also
// trim U+0085 and U+00A0, which the bash lane does not.
const asciiSpace = " \t\n\v\f\r"

// versionMatchesRange reports whether version falls inside an advisory's
// vulnerable_version_range.
//
// Ported quirks, deliberate: `||` anywhere makes the whole range ambiguous
// (the bash lane never learned disjunction), a comma is AND, and an empty
// range is ambiguous while a range of only separators (`,`) matches
// everything — bash's `read -a` yields no fields for the first and empty
// fields for the second, and the empty fields are skipped.
func versionMatchesRange(version, versionRange string) rangeMatch {
	if strings.Contains(versionRange, "||") {
		return rangeAmbiguous
	}
	if versionRange == "" {
		return rangeAmbiguous
	}
	for _, part := range strings.Split(versionRange, ",") {
		part = strings.Trim(part, asciiSpace)
		if part == "" {
			continue
		}
		if got := partSatisfied(version, part); got != rangeMatches {
			return got
		}
	}
	return rangeMatches
}

// partSatisfied evaluates one comma-separated part of a range. Most parts are a
// single constraint; a two-sided `A <= B` bound is expanded into its floor and
// ceiling and both must hold (AND), the same conjunction a comma expresses.
func partSatisfied(version, part string) rangeMatch {
	if match := compoundBound.FindStringSubmatch(part); match != nil {
		if got := versionSatisfiesConstraint(version, ">="+match[1]); got != rangeMatches {
			return got
		}
		return versionSatisfiesConstraint(version, "<="+match[2])
	}
	return versionSatisfiesConstraint(version, part)
}

// placeableTag matches a release tag whose version sits at a STRUCTURAL
// position, capturing that version. The tag as a whole must be one of exactly
// two shapes:
//
//	v?VERSION        the tag is the version, optionally `v`-prefixed (`1.2.3`, `v1.2.3`)
//	<prefix>-vVERSION  a name, then the `-v` separator, then the version (`rust-v0.149.1`, `tool2-v0.5.0`)
//
// VERSION is a dotted numeric version with an optional semver prerelease/build
// suffix. The whole-tag anchoring is what makes this a placement proof rather
// than a guess: a version living in the prefix cannot be mistaken for the
// release, because only the position after a leading `v?` or a `-v` separator is
// read. `platform-6.8-v0` fits neither shape (its release `v0` has no dotted
// version) and is unplaceable; `tool-v0.5.0_linux-6.8` fits neither (the `_linux`
// platform tail breaks the end anchor). A `-v` separated version wins over any
// dotted run in the prefix, so `tool-2.0-v0.5.0` correctly yields `0.5.0`.
var placeableTag = regexp.MustCompile(`^(?:v?|.+-v)([0-9]+(?:\.[0-9]+)+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$`)

// dottedVersionCore matches a bare dotted numeric version, used only to COUNT
// how many appear in a tag. The structural anchor decides WHERE the version is;
// this count rejects a tag that carries a SECOND dotted version anywhere — in
// the prefix, or inside a prerelease/build suffix — because which one is the
// release then cannot be told (`9.9.9-v0.1.0`, `0.1.0+build-v9.9.9`,
// `tool-2.0-v0.5.0`). Together they place only an unambiguous single version.
var dottedVersionCore = regexp.MustCompile(`[0-9]+(?:\.[0-9]+)+`)

// comparableVersion isolates the version core of a release tag so the vuln check
// can compare it against advisory versions, reporting whether the tag names a
// version at a position this build can trust.
//
// subject.version is the GitHub *tag* — the release check looks it up as one
// (`/releases/tags/{version}`), so the producer cannot normalize it there, and a
// tag may carry a project-specific prefix before the semver (openai/codex ships
// the Rust binary as `rust-v0.149.1`). The contract is deliberately strict and
// fail-closed: only the two structural shapes in placeableTag are placed; any
// other tag returns ok=false and is never compared against a range or a patch,
// it is simply ambiguous. This keeps a fabricated or mis-located core from ever
// reaching versionCmp, where it could collate the wrong way and fail open.
func comparableVersion(tag string) (string, bool) {
	match := placeableTag.FindStringSubmatch(tag)
	if match == nil {
		return "", false
	}
	// The anchor placed one version; refuse if a second dotted version lives
	// anywhere else in the tag, so an ambiguous `9.9.9-v0.1.0` or
	// `0.1.0+build-v9.9.9` cannot slip a prefix/suffix version past the anchor.
	if len(dottedVersionCore.FindAllString(tag, -1)) != 1 {
		return "", false
	}
	return match[1], true
}

// versionSatisfiesConstraint evaluates one comparison such as `<2.0.0` or
// `>= 1.0.0`. A bare version is an equality constraint.
func versionSatisfiesConstraint(version, constraint string) rangeMatch {
	constraint = strings.Trim(constraint, asciiSpace)
	if constraint == "" {
		return rangeAmbiguous
	}

	operator, rhs := "", ""
	switch match := constraintWithOperator.FindStringSubmatch(constraint); {
	case match != nil:
		operator, rhs = match[1], match[2]
	default:
		match = constraintBare.FindStringSubmatch(constraint)
		if match == nil {
			return rangeAmbiguous
		}
		operator, rhs = "=", match[1]
	}

	comparison := versionCmp(version, rhs)
	satisfied := false
	switch operator {
	case "<":
		satisfied = comparison < 0
	case "<=":
		satisfied = comparison <= 0
	case ">":
		satisfied = comparison > 0
	case ">=":
		satisfied = comparison >= 0
	case "=", "==":
		satisfied = comparison == 0
	default:
		// Unreachable: the regex above admits no other operator.
		return rangeAmbiguous
	}
	if satisfied {
		return rangeMatches
	}
	return rangeExcludes
}

// versionCmp returns -1, 0 or 1 the way the bash version_cmp does: normalize
// both sides, call them equal when the normalized strings are equal, and
// otherwise ask GNU version sort which one comes first.
//
// The byte-wise tail is not decoration. `sort` falls back to a last-resort
// comparison of the whole line when its key comparison ties, which is why the
// bash lane reports `01.2.3` as lower than `1.2.3` even though version sort
// considers them equal.
func versionCmp(left, right string) int {
	left = semverNormalize(left)
	right = semverNormalize(right)
	if left == right {
		return 0
	}
	if ordering := filevercmp(left, right); ordering != 0 {
		return sign(ordering)
	}
	return sign(strings.Compare(left, right))
}

// semverNormalize drops a leading `v` and any build metadata, so `v1.2.3` and
// `1.2.3+build` are one version.
func semverNormalize(version string) string {
	version = strings.TrimPrefix(version, "v")
	if plus := strings.IndexByte(version, '+'); plus >= 0 {
		version = version[:plus]
	}
	return version
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

// filevercmp is GNU filevercmp: compare the strings with their file suffixes
// cut off, and fall back to comparing them whole when that ties.
func filevercmp(a, b string) int {
	if a == b {
		return 0
	}
	if a == "" {
		return -1
	}
	if b == "" {
		return 1
	}

	// Leading dots sort first, and "." before "..". No version string reaches
	// this shape, but the port is of the whole function, not of the part that
	// happens to be exercised.
	if a[0] == '.' || b[0] == '.' {
		switch {
		case a[0] != '.':
			return 1
		case b[0] != '.':
			return -1
		}
		aDot, bDot := a == ".", b == "."
		if aDot || bDot {
			switch {
			case aDot && bDot:
				return 0
			case aDot:
				return -1
			default:
				return 1
			}
		}
		aDotDot, bDotDot := a == "..", b == ".."
		if aDotDot || bDotDot {
			switch {
			case aDotDot && bDotDot:
				return 0
			case aDotDot:
				return -1
			default:
				return 1
			}
		}
	}

	aPrefix, bPrefix := filePrefixLen(a), filePrefixLen(b)
	if aPrefix == len(a) && bPrefix == len(b) {
		return verrevcmp(a, b)
	}
	if ordering := verrevcmp(a[:aPrefix], b[:bPrefix]); ordering != 0 {
		return ordering
	}
	return verrevcmp(a, b)
}

// filePrefixLen returns the length of the prefix of s that survives cutting a
// trailing file suffix — the longest tail matching the regex
// `(\.[A-Za-z~][A-Za-z0-9~]*)*$`, with gnulib's rule that all of a nonempty s is
// never taken as the suffix. This is a faithful port of gnulib's file_prefixlen
// (lib/filevercmp.c): a FORWARD scan, so a trailing `.` that cannot open a valid
// suffix group (e.g. `1.2.V.`) leaves nothing to cut and the string compares
// whole, and a string that is entirely a would-be suffix (`.tar`) keeps its full
// length rather than cutting to empty. Cutting the suffix before the numbers are
// compared is what makes `1.2.beta` compare below `1.2.1`: the comparison becomes
// `1.2` against `1.2.1`.
func filePrefixLen(s string) int {
	n := len(s)
	prefixLen := 0
	for i := 0; ; {
		if i == n {
			return prefixLen
		}
		i++
		prefixLen = i
		for i+1 < n && s[i] == '.' && (isASCIIAlpha(s[i+1]) || s[i+1] == '~') {
			for i += 2; i < n && (isASCIIAlnum(s[i]) || s[i] == '~'); i++ {
			}
		}
	}
}

// verrevcmp is the Debian-style version comparison at the heart of version
// sort: non-numeric runs compare by the collating order below, numeric runs
// compare as numbers, and a longer number wins outright.
func verrevcmp(a, b string) int {
	aPos, bPos := 0, 0
	for aPos < len(a) || bPos < len(b) {
		firstDiff := 0

		for (aPos < len(a) && !isASCIIDigit(a[aPos])) || (bPos < len(b) && !isASCIIDigit(b[bPos])) {
			aOrder, bOrder := 0, 0
			if aPos < len(a) {
				aOrder = order(a[aPos])
			}
			if bPos < len(b) {
				bOrder = order(b[bPos])
			}
			if aOrder != bOrder {
				return aOrder - bOrder
			}
			aPos++
			bPos++
		}

		for aPos < len(a) && a[aPos] == '0' {
			aPos++
		}
		for bPos < len(b) && b[bPos] == '0' {
			bPos++
		}
		for aPos < len(a) && bPos < len(b) && isASCIIDigit(a[aPos]) && isASCIIDigit(b[bPos]) {
			if firstDiff == 0 {
				firstDiff = int(a[aPos]) - int(b[bPos])
			}
			aPos++
			bPos++
		}
		if aPos < len(a) && isASCIIDigit(a[aPos]) {
			return 1
		}
		if bPos < len(b) && isASCIIDigit(b[bPos]) {
			return -1
		}
		if firstDiff != 0 {
			return firstDiff
		}
	}
	return 0
}

// order is the collating order version sort uses. Digits collate lowest,
// letters by their byte value, `~` below the end of the string — which is what
// sorts `1.0~rc1` under `1.0` — and everything else above every letter.
func order(c byte) int {
	switch {
	case isASCIIDigit(c):
		return 0
	case isASCIIAlpha(c):
		return int(c)
	case c == '~':
		return -1
	default:
		return int(c) + 256
	}
}

func isASCIIDigit(c byte) bool { return c >= '0' && c <= '9' }

func isASCIIAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

func isASCIIAlnum(c byte) bool { return isASCIIDigit(c) || isASCIIAlpha(c) }
