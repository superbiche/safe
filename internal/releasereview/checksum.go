package releasereview

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"strings"
)

var (
	sha256Hex = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	bsdLine   = regexp.MustCompile(`^SHA256[ \t]*\((.*)\)[ \t]*=[ \t]*([0-9a-fA-F]{64})[ \t]*$`)
)

// checksum verifies each artifact's sha256 against the checksum file the spec
// points at.
//
// The distinction the codes carry: a file that is absent or whose digest
// differs is evidence about the release (BLOCK), while a file that exists and
// cannot be read is a broken review (ERROR). Collapsing the second into the
// first would report a permission problem as a tampered artifact.
//
// Every independent condition is reported, not just the first one found. The
// artifact's own readability and its checksum file's readability are separate
// facts about a release, and a report that stops at whichever failed first
// hides the other — including when the one it hid was the worse of the two.
//
// verified holds the artifact indices an enabled signature check verified. It
// is keyed by index rather than by name or path because a spec may legitimately
// repeat either. A nil map means no signature check ran, in which case a matched
// digest is checksum-only verification and warns unconditionally.
func checksum(spec Spec, verified map[int]bool) CheckResult {
	result := CheckResult{Reasons: []Reason{}}

	for index, artifact := range spec.Artifacts {
		name := artifact.AssetName

		actual, hashErr := sha256File(artifact.Path)
		switch {
		case hashErr == nil:
		case errors.Is(hashErr, fs.ErrNotExist):
			result.add(BLOCK, "artifact_missing",
				fmt.Sprintf("artifact %s is not at %s", name, artifact.Path),
				map[string]string{"artifact": name})
		default:
			result.add(ERROR, "artifact_unreadable",
				fmt.Sprintf("could not hash artifact %s", name),
				map[string]string{"artifact": name, "error": hashErr.Error()})
		}

		if artifact.Evidence.ChecksumFile == "" {
			result.add(WARN, "no_checksum_evidence",
				fmt.Sprintf("no checksum file was provided for %s", name),
				map[string]string{"artifact": name})
			continue
		}

		content, readErr := os.ReadFile(artifact.Evidence.ChecksumFile)
		if readErr != nil {
			if errors.Is(readErr, fs.ErrNotExist) {
				result.add(BLOCK, "checksum_file_missing",
					fmt.Sprintf("checksum file for %s is not at %s", name, artifact.Evidence.ChecksumFile),
					map[string]string{"artifact": name, "checksum_file": artifact.Evidence.ChecksumFile})
			} else {
				result.add(ERROR, "artifact_unreadable",
					fmt.Sprintf("could not read the checksum file for %s", name),
					map[string]string{
						"artifact":      name,
						"checksum_file": artifact.Evidence.ChecksumFile,
						"error":         readErr.Error(),
					})
			}
			continue
		}
		// Whether the checksum file holds an entry for this asset is a fact
		// about the release on its own; only the comparison below needs the
		// artifact's digest.
		expected, ok := expectedDigest(string(content), name)
		if !ok {
			result.add(BLOCK, "no_entry_for_artifact",
				fmt.Sprintf("checksum file contains no usable entry for %s", name),
				map[string]string{"artifact": name, "checksum_file": artifact.Evidence.ChecksumFile})
			continue
		}
		if hashErr != nil {
			continue
		}

		if expected != actual {
			result.add(BLOCK, "digest_mismatch",
				fmt.Sprintf("artifact %s does not match its checksum entry", name),
				map[string]string{
					"artifact":        name,
					"expected_sha256": expected,
					"actual_sha256":   actual,
				})
			continue
		}

		// Suppressed only by a signature check that actually verified this
		// artifact. Spec-level signature metadata is a claim, not verification:
		// were presence of the block enough, a bundle path that does not exist
		// would lift a release to GO. An advisory signature check that verified
		// still suppresses — verification happened, and advisory caps what a
		// check contributes to the top level, not what it observed.
		if verified[index] {
			continue
		}
		result.add(WARN, "checksum_only_verification",
			fmt.Sprintf("%s matched its checksum, but no enabled signature check vouched for it", name),
			map[string]string{"artifact": name})
	}

	return result
}

func sha256File(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	return hashReader(file)
}

// hashReader streams a reader through sha256 and returns the hex digest. The tuf
// check reads its mirror blobs through an *os.Root rather than by path, so the
// hashing is factored out of sha256File to serve both openers.
func hashReader(reader io.Reader) (string, error) {
	digest := sha256.New()
	if _, err := io.Copy(digest, reader); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

// expectedDigest finds the digest a checksum file states for one asset.
//
// Three entry formats are accepted (coreutils, BSD, bare digest). Digests are
// compared lowercased; names are not, because a checksum file distinguishes
// Foo.tar.gz from foo.tar.gz and so must this.
//
// When no entry names the asset, a single-entry file still answers for it —
// one-artifact releases routinely ship a checksum file with no name in it at
// all. A file holding several digests does not: picking one of them would turn
// "this release has no entry for that asset" into "that asset was tampered
// with", two findings with very different follow-ups.
func expectedDigest(content, assetName string) (string, bool) {
	candidates := make([]string, 0, 4)
	wanted := []string{assetName, "./" + assetName}

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSuffix(line, "\r")

		if matches := bsdLine.FindStringSubmatch(line); matches != nil {
			if matchesName(matches[1], wanted) {
				return strings.ToLower(matches[2]), true
			}
			candidates = append(candidates, strings.ToLower(matches[2]))
			continue
		}

		if sha256Hex.MatchString(line) {
			candidates = append(candidates, strings.ToLower(line))
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 || !sha256Hex.MatchString(fields[0]) || !strings.HasPrefix(line, fields[0]) {
			continue
		}
		if matchesName(strings.TrimPrefix(fields[1], "*"), wanted) {
			return strings.ToLower(fields[0]), true
		}
		candidates = append(candidates, strings.ToLower(fields[0]))
	}

	if len(candidates) == 1 {
		return candidates[0], true
	}
	return "", false
}

func matchesName(name string, wanted []string) bool {
	for _, want := range wanted {
		if name == want {
			return true
		}
	}
	return false
}
