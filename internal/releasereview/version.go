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
		if got := versionSatisfiesConstraint(version, part); got != rangeMatches {
			return got
		}
	}
	return rangeMatches
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
