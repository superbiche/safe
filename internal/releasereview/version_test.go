package releasereview

import "testing"

// Every expectation in this file was CAPTURED, not written: the bash functions
// were sourced out of bin/safe-audit and run on these exact inputs, and their
// output was pasted here. GNU version sort disagrees with semver in ways that
// are easy to get plausibly wrong — a release candidate sorts ABOVE its
// release, `1.2` sorts below `1.2.0`, and a suffix like `.beta` is cut before
// the numbers are compared — so a hand-written table would have pinned the
// port's bugs rather than the bash lane's behavior.

func TestVersionCmpMatchesTheBashLane(t *testing.T) {
	for _, testCase := range []struct {
		left, right string
		want        int
	}{
		{"1.2.3", "1.2.3", 0},
		{"v1.2.3", "1.2.3", 0},
		{"1.2.3", "1.2.4", -1},
		{"1.2.4", "1.2.3", 1},
		{"1.10.0", "1.9.0", 1},
		{"2.0.0", "10.0.0", -1},
		{"1.2.3-rc1", "1.2.3", 1}, // GNU version sort, not semver
		{"1.2.3-rc1", "1.2.3-rc2", -1},
		{"1.2.3-rc10", "1.2.3-rc9", 1},
		{"1.2.3+build", "1.2.3", 0},
		{"1.2", "1.2.0", -1},
		{"1.0.0", "1.0.0.1", -1},
		{"1.2.3-alpha", "1.2.3-beta", -1},
		{"01.2.3", "1.2.3", -1}, // version-equal; sort's last-resort byte order decides
		{"1.2.3a", "1.2.3", 1},
		{"1.2.3.rc1", "1.2.3", 1},
		{"1.2.beta", "1.2.1", -1}, // the file-suffix cut
		{"1.0.tar", "1.0.1", -1},
		{"2.0.beta", "2.0", 1},
		{"1.0~rc1", "1.0", -1}, // `~` collates below end-of-string
		{"3.0.0", "3.0.0-1", -1},
		{"", "1.0.0", -1},
		{"1.0.0", "", 1},
	} {
		if got := versionCmp(testCase.left, testCase.right); got != testCase.want {
			t.Errorf("versionCmp(%q, %q) = %d, want %d (captured from bash version_cmp)",
				testCase.left, testCase.right, got, testCase.want)
		}
	}
}

// The bash return codes map to this package's three answers: 0 is a match, 1 is
// an exclusion, and 2 — an unparseable constraint — is ambiguous, which every
// caller fails closed on.
func TestVersionMatchesRangeMatchesTheBashLane(t *testing.T) {
	for _, testCase := range []struct {
		version, versionRange string
		want                  rangeMatch
	}{
		{"1.2.3", "<2.0.0", rangeMatches},
		{"1.2.3", "<v2.0.0", rangeMatches},
		{"1.2.3", ">=1.0.0, <2.0.0", rangeMatches},
		{"1.2.3", ">=1.0.0,<1.2.0", rangeExcludes},
		{"1.2.3", ">=2.0.0, <3.0.0", rangeExcludes},
		{"1.2.3", "<1.0.0 || >2.0.0", rangeAmbiguous}, // disjunction is never parsed
		{"1.2.3", "", rangeAmbiguous},
		{"1.2.3", " ", rangeMatches}, // one field that trims empty and is skipped
		{"1.2.3", ",", rangeMatches}, // separators only: every field skipped
		{"1.2.3", "<2.0.0,", rangeMatches},
		{"1.2.3", "<2.0.0, invalid", rangeAmbiguous},
		{"1.2.3", "invalid, <2.0.0", rangeAmbiguous},
		{"1.2.3", "= 1.2.3", rangeMatches},
		{"1.2.3", "1.2.3", rangeMatches},
		{"1.2.3", " >= 1.2.0 , <= 1.2.5 ", rangeMatches},
		{"3.0.0", "<v2.0.0", rangeExcludes},
		{"1.2.3-rc1", "<1.2.3", rangeExcludes}, // the rc sorts above the release
		{"1.2.3-rc1", "<2.0.0", rangeMatches},
		{"1.2.3", "~>1.2.0", rangeAmbiguous},
		{"1.2.3", ">= 1.0.0", rangeMatches},
		{"2.0.0", "<2.0.0", rangeExcludes},
		{"1.2.3", "<=1.2.3", rangeMatches},
		{"1.2.3", "> 1.2.3", rangeExcludes},
	} {
		if got := versionMatchesRange(testCase.version, testCase.versionRange); got != testCase.want {
			t.Errorf("versionMatchesRange(%q, %q) = %v, want %v (captured from bash version_matches_range)",
				testCase.version, testCase.versionRange, got, testCase.want)
		}
	}
}
