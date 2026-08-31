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
		// gnulib file_prefixlen is a forward scan: a trailing `.` that cannot
		// open a valid suffix group cuts nothing, and an all-suffix string is
		// never cut to empty. The old backward scan diverged from the bash
		// oracle on these degenerate-but-parseable shapes (round-1 F1).
		{"1.2.3", "1.2.V.", -1}, // `1.2.V.` compares whole; not cut to `1.2`
		{"Xa", "X.V.", -1},
		{".a+0", ".V* z[-_", 1}, // both keep leading `.`; not cut to empty
		{".~9 ", ".b++_.Xa-", -1},
		{"1.2.3", ".a", 1},
		{"1.2.3", ".tar", 1},
		{"X.V.", "X", 1},
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
		// Round-1 F1: the constraint `1.2.V.` passes the bare-version regex, so
		// the fixed forward-scan comparison must reach the bash verdict rather
		// than silently drop the advisory (fail-open). Captured from the oracle.
		{"1.2.3", "<=1.2.V.", rangeMatches},
		{"1.2.3", ">=1.2.V.", rangeExcludes},
		{"1.2.3", "<1.2.V.", rangeMatches},
		{"1.2.3", ">1.2.V.", rangeExcludes},
		{"1.2.3", "=1.2.V.", rangeExcludes},
	} {
		if got := versionMatchesRange(testCase.version, testCase.versionRange); got != testCase.want {
			t.Errorf("versionMatchesRange(%q, %q) = %v, want %v (captured from bash version_matches_range)",
				testCase.version, testCase.versionRange, got, testCase.want)
		}
	}
}

// Item B: GitHub's space-separated two-sided bound `A <= B` means `>= A, <= B`.
// The bash lane never parsed this shape — it flagged it ambiguous — so these are
// a Go-only addition, kept out of the bash-captured table above. The cases are
// grounded in openai/codex's real npm range `0.2.0 <= 0.38.0`, whose
// patched_versions `0.39.0` fixes the inclusive ceiling at 0.38.0. The addition
// is additive-only: it turns a previously-ambiguous string into a decided one
// and never changes what a single-operator or bare constraint already meant.
func TestVersionMatchesRangeCompoundBound(t *testing.T) {
	for _, testCase := range []struct {
		version, versionRange string
		want                  rangeMatch
	}{
		{"0.38.0", "0.2.0 <= 0.38.0", rangeMatches},  // the inclusive ceiling
		{"0.39.0", "0.2.0 <= 0.38.0", rangeExcludes}, // the patched version, above it
		{"0.2.0", "0.2.0 <= 0.38.0", rangeMatches},   // the inclusive floor
		{"0.1.0", "0.2.0 <= 0.38.0", rangeExcludes},  // below the floor
		{"0.30.0", "0.2.0 <= 0.38.0", rangeMatches},
		{"v0.30.0", "0.2.0 <= 0.38.0", rangeMatches},  // v-prefix on the subject
		{"0.30.0", "v0.2.0 <= v0.38.0", rangeMatches}, // v-prefix on both bounds
		{"0.30.0", " 0.2.0 <= 0.38.0 ", rangeMatches}, // surrounding whitespace trims
		{"0.30.0", "0.2.0 < 0.38.0", rangeAmbiguous},  // only `<=` is admitted
		{"0.30.0", "0.2.0 >= 0.38.0", rangeAmbiguous}, // ditto — not guessed
		{"0.30.0", "0.2.0 <= ", rangeAmbiguous},       // missing ceiling
		{"0.30.0", "<= 0.38.0", rangeMatches},         // single constraint, unchanged
		{"0.30.0", "0.2.0", rangeExcludes},            // bare version equality, unchanged
	} {
		if got := versionMatchesRange(testCase.version, testCase.versionRange); got != testCase.want {
			t.Errorf("versionMatchesRange(%q, %q) = %v, want %v",
				testCase.version, testCase.versionRange, got, testCase.want)
		}
	}
}

// --- P2 differential golden (slice #144) ------------------------------------
//
// The two tables below were captured by a systematic differential sweep against
// the bash version oracle (semver_normalize / version_cmp /
// version_satisfies_constraint / version_matches_range in bin/safe-audit) at
// commit 3106d3b, the last commit before this slice deleted that oracle. With
// the bash lane gone there is nothing left to diff live, so its verdicts are
// frozen here as goldens: every row is (input, input, bash-verdict), and the Go
// port must reproduce the bash-verdict forever. The generator was ephemeral
// (scratchpad); the captured table is the artifact, so its reproducibility does
// not depend on the generator surviving.
//
// This is the parked slice-3 P2 residual, resolved by capture-then-delete — the
// same option-2 philosophy the corpus conversion uses.

func TestVersionCmpDifferentialGolden(t *testing.T) {
	for _, testCase := range []struct {
		left, right string
		want        int
	}{
		{"0", "1", -1},
		{"1", "0", 1},
		{"0", "10", -1},
		{"10", "0", 1},
		{"0", "1.2.3", -1},
		{"1.2.3", "0", 1},
		{"1", "2", -1},
		{"2", "1", 1},
		{"1", "1.0", -1},
		{"1.0", "1", 1},
		{"1", "1.2.4", -1},
		{"1.2.4", "1", 1},
		{"2", "10", -1},
		{"10", "2", 1},
		{"2", "1.2", 1},
		{"1.2", "2", -1},
		{"2", "1.10.0", 1},
		{"1.10.0", "2", -1},
		{"10", "1.0", 1},
		{"1.0", "10", -1},
		{"10", "1.2.0", 1},
		{"1.2.0", "10", -1},
		{"10", "1.9.0", 1},
		{"1.9.0", "10", -1},
		{"1.0", "1.2", -1},
		{"1.2", "1.0", 1},
		{"1.0", "1.2.3", -1},
		{"1.2.3", "1.0", 1},
		{"1.0", "2.0.0", -1},
		{"2.0.0", "1.0", 1},
		{"1.2", "1.2.0", -1},
		{"1.2.0", "1.2", 1},
		{"1.2", "1.2.4", -1},
		{"1.2.4", "1.2", 1},
		{"1.2", "10.0.0", -1},
		{"10.0.0", "1.2", 1},
		{"1.2.0", "1.2.3", -1},
		{"1.2.3", "1.2.0", 1},
		{"1.2.0", "1.10.0", -1},
		{"1.10.0", "1.2.0", 1},
		{"1.2.0", "1.0.0.1", 1},
		{"1.0.0.1", "1.2.0", -1},
		{"1.2.3", "1.2.4", -1},
		{"1.2.4", "1.2.3", 1},
		{"1.2.3", "1.9.0", -1},
		{"1.9.0", "1.2.3", 1},
		{"1.2.3", "v1.2.3", 0},
		{"v1.2.3", "1.2.3", 0},
		{"1.2.4", "1.10.0", -1},
		{"1.10.0", "1.2.4", 1},
		{"1.2.4", "2.0.0", -1},
		{"2.0.0", "1.2.4", 1},
		{"1.2.4", "01.2.3", 1},
		{"01.2.3", "1.2.4", -1},
		{"1.10.0", "1.9.0", 1},
		{"1.9.0", "1.10.0", -1},
		{"1.10.0", "10.0.0", -1},
		{"10.0.0", "1.10.0", 1},
		{"1.10.0", "1.2.3+build", 1},
		{"1.2.3+build", "1.10.0", -1},
		{"1.9.0", "2.0.0", -1},
		{"2.0.0", "1.9.0", 1},
		{"1.9.0", "1.0.0.1", 1},
		{"1.0.0.1", "1.9.0", -1},
		{"1.9.0", "1.2.3-rc1", 1},
		{"1.2.3-rc1", "1.9.0", -1},
		{"2.0.0", "10.0.0", -1},
		{"10.0.0", "2.0.0", 1},
		{"2.0.0", "v1.2.3", 1},
		{"v1.2.3", "2.0.0", -1},
		{"2.0.0", "1.2.3-rc2", 1},
		{"1.2.3-rc2", "2.0.0", -1},
		{"10.0.0", "1.0.0.1", 1},
		{"1.0.0.1", "10.0.0", -1},
		{"10.0.0", "01.2.3", 1},
		{"01.2.3", "10.0.0", -1},
		{"10.0.0", "1.2.3-rc9", 1},
		{"1.2.3-rc9", "10.0.0", -1},
		{"1.0.0.1", "v1.2.3", -1},
		{"v1.2.3", "1.0.0.1", 1},
		{"1.0.0.1", "1.2.3+build", -1},
		{"1.2.3+build", "1.0.0.1", 1},
		{"1.0.0.1", "1.2.3-rc10", -1},
		{"1.2.3-rc10", "1.0.0.1", 1},
		{"v1.2.3", "01.2.3", 1},
		{"01.2.3", "v1.2.3", -1},
		{"v1.2.3", "1.2.3-rc1", -1},
		{"1.2.3-rc1", "v1.2.3", 1},
		{"v1.2.3", "1.2.3-alpha", -1},
		{"1.2.3-alpha", "v1.2.3", 1},
		{"01.2.3", "1.2.3+build", -1},
		{"1.2.3+build", "01.2.3", 1},
		{"01.2.3", "1.2.3-rc2", -1},
		{"1.2.3-rc2", "01.2.3", 1},
		{"01.2.3", "1.2.3-beta", -1},
		{"1.2.3-beta", "01.2.3", 1},
		{"1.2.3+build", "1.2.3-rc1", -1},
		{"1.2.3-rc1", "1.2.3+build", 1},
		{"1.2.3+build", "1.2.3-rc9", -1},
		{"1.2.3-rc9", "1.2.3+build", 1},
		{"1.2.3+build", "1.0~rc1", 1},
		{"1.0~rc1", "1.2.3+build", -1},
		{"1.2.3-rc1", "1.2.3-rc2", -1},
		{"1.2.3-rc2", "1.2.3-rc1", 1},
		{"1.2.3-rc1", "1.2.3-rc10", -1},
		{"1.2.3-rc10", "1.2.3-rc1", 1},
		{"1.2.3-rc1", "1.0", 1},
		{"1.0", "1.2.3-rc1", -1},
		{"1.2.3-rc2", "1.2.3-rc9", -1},
		{"1.2.3-rc9", "1.2.3-rc2", 1},
		{"1.2.3-rc2", "1.2.3-alpha", 1},
		{"1.2.3-alpha", "1.2.3-rc2", -1},
		{"1.2.3-rc2", "3.0.0", -1},
		{"3.0.0", "1.2.3-rc2", 1},
		{"1.2.3-rc9", "1.2.3-rc10", -1},
		{"1.2.3-rc10", "1.2.3-rc9", 1},
		{"1.2.3-rc9", "1.2.3-beta", 1},
		{"1.2.3-beta", "1.2.3-rc9", -1},
		{"1.2.3-rc9", "3.0.0-1", -1},
		{"3.0.0-1", "1.2.3-rc9", 1},
		{"1.2.3-rc10", "1.2.3-alpha", 1},
		{"1.2.3-alpha", "1.2.3-rc10", -1},
		{"1.2.3-rc10", "1.0~rc1", 1},
		{"1.0~rc1", "1.2.3-rc10", -1},
		{"1.2.3-rc10", "1.2.3a", 1},
		{"1.2.3a", "1.2.3-rc10", -1},
		{"1.2.3-alpha", "1.2.3-beta", -1},
		{"1.2.3-beta", "1.2.3-alpha", 1},
		{"1.2.3-alpha", "1.0", 1},
		{"1.0", "1.2.3-alpha", -1},
		{"1.2.3-alpha", "1.2.3.rc1", 1},
		{"1.2.3.rc1", "1.2.3-alpha", -1},
		{"1.2.3-beta", "1.0~rc1", 1},
		{"1.0~rc1", "1.2.3-beta", -1},
		{"1.2.3-beta", "3.0.0", -1},
		{"3.0.0", "1.2.3-beta", 1},
		{"1.2.3-beta", "1.2.beta", 1},
		{"1.2.beta", "1.2.3-beta", -1},
		{"1.0~rc1", "1.0", -1},
		{"1.0", "1.0~rc1", 1},
		{"1.0~rc1", "3.0.0-1", -1},
		{"3.0.0-1", "1.0~rc1", 1},
		{"1.0~rc1", "1.2.1", -1},
		{"1.2.1", "1.0~rc1", 1},
		{"1.0", "3.0.0", -1},
		{"3.0.0", "1.0", 1},
		{"1.0", "1.2.3a", -1},
		{"1.2.3a", "1.0", 1},
		{"1.0", "1.0.tar", -1},
		{"1.0.tar", "1.0", 1},
		{"3.0.0", "3.0.0-1", -1},
		{"3.0.0-1", "3.0.0", 1},
		{"3.0.0", "1.2.3.rc1", 1},
		{"1.2.3.rc1", "3.0.0", -1},
		{"3.0.0", "1.0.1", 1},
		{"1.0.1", "3.0.0", -1},
		{"3.0.0-1", "1.2.3a", 1},
		{"1.2.3a", "3.0.0-1", -1},
		{"3.0.0-1", "1.2.beta", 1},
		{"1.2.beta", "3.0.0-1", -1},
		{"3.0.0-1", "2.0.beta", 1},
		{"2.0.beta", "3.0.0-1", -1},
		{"1.2.3a", "1.2.3.rc1", 1},
		{"1.2.3.rc1", "1.2.3a", -1},
		{"1.2.3a", "1.2.1", 1},
		{"1.2.1", "1.2.3a", -1},
		{"1.2.3a", "2.0", -1},
		{"2.0", "1.2.3a", 1},
		{"1.2.3.rc1", "1.2.beta", 1},
		{"1.2.beta", "1.2.3.rc1", -1},
		{"1.2.3.rc1", "1.0.tar", 1},
		{"1.0.tar", "1.2.3.rc1", -1},
		{"1.2.3.rc1", "1.2.V.", -1},
		{"1.2.V.", "1.2.3.rc1", 1},
		{"1.2.beta", "1.2.1", -1},
		{"1.2.1", "1.2.beta", 1},
		{"1.2.beta", "1.0.1", 1},
		{"1.0.1", "1.2.beta", -1},
		{"1.2.beta", "Xa", -1},
		{"Xa", "1.2.beta", 1},
		{"1.2.1", "1.0.tar", 1},
		{"1.0.tar", "1.2.1", -1},
		{"1.2.1", "2.0.beta", -1},
		{"2.0.beta", "1.2.1", 1},
		{"1.2.1", "X.V.", -1},
		{"X.V.", "1.2.1", 1},
		{"1.0.tar", "1.0.1", -1},
		{"1.0.1", "1.0.tar", 1},
		{"1.0.tar", "2.0", -1},
		{"2.0", "1.0.tar", 1},
		{"1.0.tar", "X", -1},
		{"X", "1.0.tar", 1},
		{"1.0.1", "2.0.beta", -1},
		{"2.0.beta", "1.0.1", 1},
		{"1.0.1", "1.2.V.", -1},
		{"1.2.V.", "1.0.1", 1},
		{"2.0.beta", "2.0", 1},
		{"2.0", "2.0.beta", -1},
		{"2.0.beta", "Xa", -1},
		{"Xa", "2.0.beta", 1},
		{"2.0", "1.2.V.", 1},
		{"1.2.V.", "2.0", -1},
		{"2.0", "X.V.", -1},
		{"X.V.", "2.0", 1},
		{"1.2.V.", "Xa", -1},
		{"Xa", "1.2.V.", 1},
		{"1.2.V.", "X", -1},
		{"X", "1.2.V.", 1},
		{"Xa", "X.V.", -1},
		{"X.V.", "Xa", 1},
		{"X.V.", "X", 1},
		{"X", "X.V.", -1},
	} {
		if got := versionCmp(testCase.left, testCase.right); got != testCase.want {
			t.Errorf("versionCmp(%q, %q) = %d, want %d (P2 golden, captured from bash version_cmp)",
				testCase.left, testCase.right, got, testCase.want)
		}
	}
}

func TestVersionMatchesRangeDifferentialGolden(t *testing.T) {
	for _, testCase := range []struct {
		version, versionRange string
		want                  rangeMatch
	}{
		{"1.2.3", "<2.0.0", rangeMatches},
		{"1.2.3", "<=2.0.0", rangeMatches},
		{"1.2.3", ">1.0.0", rangeMatches},
		{"1.2.3", ">=1.2.3", rangeMatches},
		{"1.2.3", "<1.0.0", rangeExcludes},
		{"1.2.3", ">2.0.0", rangeExcludes},
		{"1.2.3", "=1.2.3", rangeMatches},
		{"1.2.3", "==1.2.3", rangeMatches},
		{"1.2.3", "1.2.3", rangeMatches},
		{"1.2.3", "<v2.0.0", rangeMatches},
		{"1.2.3", ">=1.0.0, <2.0.0", rangeMatches},
		{"1.2.3", ">=1.0.0,<1.2.0", rangeExcludes},
		{"1.2.3", ">=2.0.0, <3.0.0", rangeExcludes},
		{"1.2.3", " >= 1.2.0 , <= 1.2.5 ", rangeMatches},
		{"1.2.3", "<2.0.0,", rangeMatches},
		{"1.2.3", "<2.0.0, invalid", rangeAmbiguous},
		{"1.2.3", "invalid, <2.0.0", rangeAmbiguous},
		{"1.2.3", "<1.0.0 || >2.0.0", rangeAmbiguous},
		{"1.2.3", "|| garbage", rangeAmbiguous},
		{"1.2.3", "", rangeAmbiguous},
		{"1.2.3", " ", rangeMatches},
		{"1.2.3", ",", rangeMatches},
		{"1.2.3", "~>1.2.0", rangeAmbiguous},
		{"1.2.3", "= 1.2.3", rangeMatches},
		{"1.2.3", "> 1.2.3", rangeExcludes},
		{"1.2.3", "<=1.2.3", rangeMatches},
		{"2.0.0", "<2.0.0", rangeExcludes},
		{"1.2.3-rc1", "<1.2.3", rangeExcludes},
		{"1.2.3-rc1", "<2.0.0", rangeMatches},
		{"1.2.3", "<=1.2.V.", rangeMatches},
		{"1.2.3", ">=1.2.V.", rangeExcludes},
		{"1.2.3", "<1.2.V.", rangeMatches},
		{"1.2.3", ">1.2.V.", rangeExcludes},
		{"1.2.3", "=1.2.V.", rangeExcludes},
		{"10.0.0", ">=2.0.0", rangeMatches},
		{"0", "<1", rangeMatches},
		{"1.2.0", ">1.2", rangeMatches},
	} {
		if got := versionMatchesRange(testCase.version, testCase.versionRange); got != testCase.want {
			t.Errorf("versionMatchesRange(%q, %q) = %v, want %v (P2 golden, captured from bash version_matches_range)",
				testCase.version, testCase.versionRange, got, testCase.want)
		}
	}
}

func TestComparableVersion(t *testing.T) {
	for _, testCase := range []struct {
		tag       string
		want      string
		placeable bool
	}{
		// Placeable: exactly one dotted version, at a structural position — the
		// whole tag as `v?VERSION`, or the version after a `-v` separator (a name
		// containing a non-dotted digit is fine, `tool2-v0.5.0`).
		{"1.2.3", "1.2.3", true},
		{"v1.2.3", "1.2.3", true},
		{"0.1.0", "0.1.0", true},
		{"rust-v0.149.1", "0.149.1", true},
		{"tool2-v0.5.0", "0.5.0", true},
		{"release-v2.0.0-rc1", "2.0.0-rc1", true},
		// Unplaceable: a SECOND dotted version anywhere makes the placement
		// ambiguous, so the tag fails closed rather than guessing which is the
		// release — whether the second version is in the prefix
		// (`tool-2.0-v0.5.0`, `platform-6.8-v0.1`, `9.9.9-v0.1.0`) or a suffix
		// (`0.1.0+build-v9.9.9`, `v1.2.3-alpha.1.2`, `v1.2.3+linux.6.8`).
		{"tool-2.0-v0.5.0", "", false},
		{"platform-6.8-v0.1", "", false},
		{"9.9.9-v0.1.0", "", false},
		{"0.1.0+build-v9.9.9", "", false},
		{"v1.2.3-alpha.1.2", "", false},
		{"v1.2.3+linux.6.8", "", false},
		// Unplaceable: no version at a structural position at all.
		// `platform-6.8-v0` — the release `v0` has no dotted version.
		// `tool-v0.5.0_linux-6.8` — the `_linux` tail breaks the end anchor.
		// `tool2-0.5.0` / `go1.21.0` — a name glued to a version with no `-v`.
		{"platform-6.8-v0", "", false},
		{"tool-v0.5.0_linux-6.8", "", false},
		{"tool2-0.5.0", "", false},
		{"go1.21.0", "", false},
		{"5abc", "", false},
		{"nightly", "", false},
		{"", "", false},
	} {
		got, ok := comparableVersion(testCase.tag)
		if got != testCase.want || ok != testCase.placeable {
			t.Errorf("comparableVersion(%q) = (%q, %t), want (%q, %t)",
				testCase.tag, got, ok, testCase.want, testCase.placeable)
		}
	}
}
