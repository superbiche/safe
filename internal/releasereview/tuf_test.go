package releasereview

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const tufRootContent = `{"signed":{"_type":"root","version":1}}`

type mirrorTarget struct {
	name    string
	content string
}

// buildTUFMirror lays out a local TUF mirror the way cosign expects to find
// one: targets.json naming each target by digest and length, and the
// content-addressed blobs beside it under targets/.
func buildTUFMirror(t *testing.T, targets ...mirrorTarget) (mirror, root, rootChecksum string) {
	t.Helper()
	mirror = t.TempDir()
	blobs := mkdir(t, filepath.Join(mirror, "targets"))

	entries := make(map[string]any, len(targets))
	for _, target := range targets {
		digest := sha256Of(target.content)
		entries[target.name] = map[string]any{
			"hashes": map[string]string{"sha256": digest},
			"length": len(target.content),
		}
		writeFile(t, blobs, digest+"."+target.name, target.content)
	}
	metadata, err := json.Marshal(map[string]any{"signed": map[string]any{"targets": entries}})
	if err != nil {
		t.Fatalf("encode targets metadata: %v", err)
	}
	writeFile(t, mirror, "targets.json", string(metadata))

	root = writeFile(t, mirror, "root.json", tufRootContent)
	return mirror, root, sha256Of(tufRootContent)
}

func tufSpec(mirror, root, rootChecksum string, targets map[string]string) Spec {
	return Spec{
		SpecVersion: SpecVersion,
		Subject:     Subject{Repo: "o/r", Version: "v1"},
		Artifacts:   []Artifact{{Path: root, AssetName: "root.json"}},
		Checks: &Checks{TUF: &TUFCheck{
			CheckConfig:  CheckConfig{Enabled: true},
			Mirror:       mirror,
			Root:         root,
			RootChecksum: rootChecksum,
			Targets:      targets,
		}},
	}
}

// tufFixture builds a one-target mirror whose local copy matches, and points
// the fake cosign at it.
func tufFixture(t *testing.T) (spec Spec, mirror, local string) {
	t.Helper()
	withFakeTools(t, "cosign")

	mirror, root, rootChecksum := buildTUFMirror(t, mirrorTarget{name: "trusted_root.json", content: "trust me"})
	t.Setenv("MOCK_COSIGN_BRIDGE_ROOT", mirror)

	local = writeFile(t, t.TempDir(), "trusted_root.json", "trust me")
	return tufSpec(mirror, root, rootChecksum, map[string]string{"trusted_root.json": local}), mirror, local
}

func TestTUFHappyPath(t *testing.T) {
	spec, _, _ := tufFixture(t)

	result := tuf(spec)
	if result.Verdict != GO || len(result.Reasons) != 0 {
		t.Fatalf("verdict %s with reasons %v, want a clean GO", result.Verdict, codes(result))
	}
}

// The pinned root is the whole point of the check: bootstrapping cosign against
// a root that is not the pinned one would perform the very act the pin exists
// to prevent, so nothing downstream runs.
func TestTUFRootChecksumMismatchStopsTheBootstrap(t *testing.T) {
	spec, _, _ := tufFixture(t)
	spec.Checks.TUF.RootChecksum = sha256Of("some other root")

	result := tuf(spec)
	if result.Verdict != BLOCK {
		t.Fatalf("verdict %s, want BLOCK", result.Verdict)
	}
	if got := codes(result); len(got) != 1 || got[0] != "trust_root_mismatch" {
		t.Fatalf("reasons %v, want [trust_root_mismatch]", got)
	}
	reason := result.Reasons[0]
	if reason.Data["expected_root_checksum"] != spec.Checks.TUF.RootChecksum ||
		reason.Data["actual_root_checksum"] != sha256Of(tufRootContent) {
		t.Fatalf("reason data %v does not carry both digests", reason.Data)
	}
}

func TestTUFBootstrapFailureCarriesTheToolsFirstLine(t *testing.T) {
	spec, _, _ := tufFixture(t)
	t.Setenv("MOCK_COSIGN_TUF_MODE", "fail")

	result := tuf(spec)
	if got := codes(result); len(got) != 1 || got[0] != "bootstrap_failure" {
		t.Fatalf("reasons %v, want [bootstrap_failure]", got)
	}
	if result.Reasons[0].Message != "tuf initialize failed" {
		t.Fatalf("message %q does not summarize the tool's output", result.Reasons[0].Message)
	}
}

// A cosign initialize that runs past its deadline is audit-infrastructure
// breakage, not a verdict about the trust material: ERROR (bootstrap_timeout),
// never the BLOCK a genuine initialize rejection produces.
func TestTUFBootstrapTimeoutIsErrorNotBlock(t *testing.T) {
	spec, _, _ := tufFixture(t)
	lowerCosignTimeout(t, 200*time.Millisecond)
	t.Setenv("MOCK_COSIGN_SLEEP", "5")

	result := tuf(spec)
	if result.Verdict != ERROR {
		t.Fatalf("verdict %s, want ERROR: %v", result.Verdict, codes(result))
	}
	if got := codes(result); len(got) != 1 || got[0] != "bootstrap_timeout" {
		t.Fatalf("reasons %v, want [bootstrap_timeout]", got)
	}
}

// A cosign initialize that exits but leaves a child holding its output pipe is
// os/exec stalling on I/O (exec.ErrWaitDelay), not a bootstrap that failed. Like
// the context-deadline timeout, it is ERROR (bootstrap_timeout), never a BLOCK.
func TestTUFBootstrapPipeStallIsErrorNotBlock(t *testing.T) {
	spec, _, _ := tufFixture(t)
	lowerCosignKillDelay(t, 200*time.Millisecond)
	t.Setenv("MOCK_COSIGN_ORPHAN", "2")

	result := tuf(spec)
	if result.Verdict != ERROR {
		t.Fatalf("verdict %s, want ERROR: %v", result.Verdict, codes(result))
	}
	if got := codes(result); len(got) != 1 || got[0] != "bootstrap_timeout" {
		t.Fatalf("reasons %v, want [bootstrap_timeout]", got)
	}
}

// cosign exiting 0 without caching trusted metadata is not a success: there is
// nothing to compare the local material against, and treating that as a pass
// would be the silent GO this gate exists to prevent.
func TestTUFBootstrapWithoutCachedMetadataBlocks(t *testing.T) {
	spec, _, _ := tufFixture(t)
	t.Setenv("MOCK_COSIGN_TUF_MODE", "empty")

	result := tuf(spec)
	if result.Verdict != BLOCK {
		t.Fatalf("verdict %s, want BLOCK", result.Verdict)
	}
	if !strings.Contains(result.Reasons[0].Message, "no trusted targets metadata") {
		t.Fatalf("message %q does not name the missing metadata", result.Reasons[0].Message)
	}
}

func TestTUFTargetNotNamedByTrustedMetadata(t *testing.T) {
	withFakeTools(t, "cosign")
	mirror, root, rootChecksum := buildTUFMirror(t, mirrorTarget{name: "named.json", content: "known"})
	t.Setenv("MOCK_COSIGN_BRIDGE_ROOT", mirror)

	local := writeFile(t, t.TempDir(), "unnamed.json", "unknown")
	result := tuf(tufSpec(mirror, root, rootChecksum, map[string]string{"unnamed.json": local}))

	if got := codes(result); len(got) != 1 || got[0] != "policy_mismatch" {
		t.Fatalf("reasons %v, want [policy_mismatch]", got)
	}
	if result.Reasons[0].Data["target"] != "unnamed.json" {
		t.Fatalf("reason data %v does not name the target", result.Reasons[0].Data)
	}
}

// The digest comes from the trusted metadata and is spliced into the blob path
// <mirror>/targets/<sha>.<name>, where filepath.Join's Clean would resolve a
// `..` out of the targets tree. checkTarget refuses a non-hex digest before it
// builds that path, so a hostile digest cannot steer the read — nor could the
// mismatch branch report the sha256 of an out-of-tree file it hashed.
func TestTUFTrustedMetadataDigestMustBeSHA256(t *testing.T) {
	var metadata tufTargetsMetadata
	if err := json.Unmarshal(
		[]byte(`{"signed":{"targets":{"n":{"hashes":{"sha256":"../../../etc/passwd"},"length":1}}}}`),
		&metadata); err != nil {
		t.Fatalf("fixture metadata did not parse: %v", err)
	}
	config := &TUFCheck{Mirror: t.TempDir(), Targets: map[string]string{"n": "p"}}
	result := CheckResult{Reasons: []Reason{}}

	checkTarget(&result, config, metadata, t.TempDir(), "n", false)

	if got := codes(result); len(got) != 1 || got[0] != "trusted_mirror_target_invalid" {
		t.Fatalf("reasons %v, want [trusted_mirror_target_invalid]", got)
	}
	if !strings.Contains(result.Reasons[0].Message, "is not a sha256") {
		t.Fatalf("message %q, want it to name the non-sha256 digest", result.Reasons[0].Message)
	}
}

func TestTUFMirrorBlobProblems(t *testing.T) {
	t.Run("the blob the metadata names is not in the mirror", func(t *testing.T) {
		spec, mirror, _ := tufFixture(t)
		digest := sha256Of("trust me")
		if err := os.Remove(filepath.Join(mirror, "targets", digest+".trusted_root.json")); err != nil {
			t.Fatalf("remove blob: %v", err)
		}

		result := tuf(spec)
		if got := codes(result); len(got) != 1 || got[0] != "trusted_mirror_target_invalid" {
			t.Fatalf("reasons %v, want [trusted_mirror_target_invalid]", got)
		}
		if result.Reasons[0].Data["mirror_blob_path"] == "" {
			t.Fatalf("reason data %v does not name the blob path", result.Reasons[0].Data)
		}
	})

	// A mirror serving a blob that is not the blob its own trusted metadata
	// describes is the tampered-mirror case, and it is caught before the local
	// material is ever compared against it.
	t.Run("the blob does not hash to what the metadata says", func(t *testing.T) {
		spec, mirror, _ := tufFixture(t)
		digest := sha256Of("trust me")
		writeFile(t, filepath.Join(mirror, "targets"), digest+".trusted_root.json", "substituted content")

		result := tuf(spec)
		if got := codes(result); len(got) != 1 || got[0] != "trusted_mirror_target_invalid" {
			t.Fatalf("reasons %v, want [trusted_mirror_target_invalid]", got)
		}
		reason := result.Reasons[0]
		if reason.Data["trusted_metadata_sha256"] != digest ||
			reason.Data["actual_mirror_blob_sha256"] != sha256Of("substituted content") {
			t.Fatalf("reason data %v does not carry both digests", reason.Data)
		}
	})
}

// Physical containment. The lexical name/digest rules refuse a `..` or absolute
// *spelling*, but a mirror entry can be a symlink, and os.Stat/os.Open follow
// one. A blob symlinked to an out-of-tree file whose content still hashes to the
// trusted digest passes every content check — so only reading the blob through a
// beneath-root cage turns it into a BLOCK. The out-of-tree file carries the
// matching content precisely so a mismatch cannot be what fails the case.
func TestTUFMirrorBlobEscapingTheTargetsTreeIsBlocked(t *testing.T) {
	withFakeTools(t, "cosign")
	const content = "trust me"
	mirror, root, rootChecksum := buildTUFMirror(t, mirrorTarget{name: "trusted_root.json", content: content})
	t.Setenv("MOCK_COSIGN_BRIDGE_ROOT", mirror)

	blob := filepath.Join(mirror, "targets", sha256Of(content)+".trusted_root.json")
	outside := writeFile(t, t.TempDir(), "smuggled", content)
	if err := os.Remove(blob); err != nil {
		t.Fatalf("remove blob: %v", err)
	}
	if err := os.Symlink(outside, blob); err != nil {
		t.Fatalf("symlink blob: %v", err)
	}

	local := writeFile(t, t.TempDir(), "trusted_root.json", content)
	result := tuf(tufSpec(mirror, root, rootChecksum, map[string]string{"trusted_root.json": local}))

	if result.Verdict != BLOCK {
		t.Fatalf("verdict %s, want BLOCK: %v", result.Verdict, codes(result))
	}
	if got := codes(result); len(got) != 1 || got[0] != "trusted_mirror_target_escapes_tree" {
		t.Fatalf("reasons %v, want [trusted_mirror_target_escapes_tree]", got)
	}
	if result.Reasons[0].Data["mirror_blob_path"] == "" {
		t.Fatalf("reason data %v does not name the blob path", result.Reasons[0].Data)
	}
}

// A TUF target name is path-like and may contain `/`, so the blob lives under a
// directory named from the digest and the name's leading segments. An escape can
// therefore hide at a *parent* component, which a final-component O_NOFOLLOW
// would not catch — only whole-path resolution (os.Root) does. Here the
// intermediate directory is the symlink, pointing at an out-of-tree dir that
// holds a matching file.
func TestTUFNestedTargetNameEscapingViaAParentSymlinkIsBlocked(t *testing.T) {
	withFakeTools(t, "cosign")
	const (
		name    = "keys/root.json"
		content = "trust me"
	)
	digest := sha256Of(content)

	mirror := t.TempDir()
	targets := mkdir(t, filepath.Join(mirror, "targets"))
	metadata, err := json.Marshal(map[string]any{"signed": map[string]any{"targets": map[string]any{
		name: map[string]any{"hashes": map[string]string{"sha256": digest}, "length": len(content)},
	}}})
	if err != nil {
		t.Fatalf("encode metadata: %v", err)
	}
	writeFile(t, mirror, "targets.json", string(metadata))
	root := writeFile(t, mirror, "root.json", tufRootContent)
	t.Setenv("MOCK_COSIGN_BRIDGE_ROOT", mirror)

	// The blob for keys/root.json is targets/<digest>.keys/root.json; make the
	// intermediate <digest>.keys a symlink out of the tree.
	outsideDir := t.TempDir()
	writeFile(t, outsideDir, "root.json", content)
	if err := os.Symlink(outsideDir, filepath.Join(targets, digest+".keys")); err != nil {
		t.Fatalf("symlink parent: %v", err)
	}

	local := writeFile(t, t.TempDir(), "root.json", content)
	result := tuf(tufSpec(mirror, root, sha256Of(tufRootContent), map[string]string{name: local}))

	if got := codes(result); len(got) != 1 || got[0] != "trusted_mirror_target_escapes_tree" {
		t.Fatalf("reasons %v (verdict %s), want [trusted_mirror_target_escapes_tree]", got, result.Verdict)
	}
}

// A symlink that stays inside the targets tree is legitimate — mirrors dedup
// content-addressed blobs — so physical containment must resolve it, not reject
// it. Rejecting an in-tree link would be a false positive on a normal mirror.
func TestTUFMirrorBlobInTreeSymlinkStillVerifies(t *testing.T) {
	withFakeTools(t, "cosign")
	const content = "trust me"
	mirror, root, rootChecksum := buildTUFMirror(t, mirrorTarget{name: "trusted_root.json", content: content})
	t.Setenv("MOCK_COSIGN_BRIDGE_ROOT", mirror)

	targets := filepath.Join(mirror, "targets")
	real := writeFile(t, targets, "dedup.blob", content)
	blob := filepath.Join(targets, sha256Of(content)+".trusted_root.json")
	if err := os.Remove(blob); err != nil {
		t.Fatalf("remove blob: %v", err)
	}
	if err := os.Symlink(filepath.Base(real), blob); err != nil {
		t.Fatalf("symlink blob: %v", err)
	}

	local := writeFile(t, t.TempDir(), "trusted_root.json", content)
	result := tuf(tufSpec(mirror, root, rootChecksum, map[string]string{"trusted_root.json": local}))
	if result.Verdict != GO || len(result.Reasons) != 0 {
		t.Fatalf("verdict %s with reasons %v, want a clean GO", result.Verdict, codes(result))
	}
}

// A blob that is a dangling symlink to a name that is not there is absence, not
// an escape: os.Root follows the in-tree link and finds nothing, so it reads as
// the same missing-blob BLOCK a deleted blob produces — never the escape code.
func TestTUFMirrorBlobDanglingSymlinkReadsAsMissing(t *testing.T) {
	withFakeTools(t, "cosign")
	const content = "trust me"
	mirror, root, rootChecksum := buildTUFMirror(t, mirrorTarget{name: "trusted_root.json", content: content})
	t.Setenv("MOCK_COSIGN_BRIDGE_ROOT", mirror)

	blob := filepath.Join(mirror, "targets", sha256Of(content)+".trusted_root.json")
	if err := os.Remove(blob); err != nil {
		t.Fatalf("remove blob: %v", err)
	}
	if err := os.Symlink("absent-sibling", blob); err != nil {
		t.Fatalf("symlink blob: %v", err)
	}

	local := writeFile(t, t.TempDir(), "trusted_root.json", content)
	result := tuf(tufSpec(mirror, root, rootChecksum, map[string]string{"trusted_root.json": local}))
	if got := codes(result); len(got) != 1 || got[0] != "trusted_mirror_target_invalid" {
		t.Fatalf("reasons %v, want [trusted_mirror_target_invalid]", got)
	}
	if !strings.Contains(result.Reasons[0].Message, "missing from the local TUF mirror") {
		t.Fatalf("message %q, want the missing-blob message", result.Reasons[0].Message)
	}
}

// The targets directory itself can be the symlink. os.OpenRoot follows symlinks
// in its own argument, so a `<mirror>/targets` that points out of the mirror
// must be caught by deriving the targets Root from the mirror Root, not by
// opening the joined path — otherwise the cage anchors at the escape destination
// and everything under it reads as contained.
func TestTUFTargetsDirectoryEscapingTheMirrorIsBlocked(t *testing.T) {
	withFakeTools(t, "cosign")
	const content = "trust me"
	mirror, root, rootChecksum := buildTUFMirror(t, mirrorTarget{name: "trusted_root.json", content: content})
	t.Setenv("MOCK_COSIGN_BRIDGE_ROOT", mirror)

	relocated := filepath.Join(t.TempDir(), "smuggled-targets")
	if err := os.Rename(filepath.Join(mirror, "targets"), relocated); err != nil {
		t.Fatalf("relocate targets: %v", err)
	}
	if err := os.Symlink(relocated, filepath.Join(mirror, "targets")); err != nil {
		t.Fatalf("symlink targets: %v", err)
	}

	local := writeFile(t, t.TempDir(), "trusted_root.json", content)
	result := tuf(tufSpec(mirror, root, rootChecksum, map[string]string{"trusted_root.json": local}))
	if got := codes(result); len(got) != 1 || got[0] != "trusted_mirror_target_escapes_tree" {
		t.Fatalf("reasons %v (verdict %s), want [trusted_mirror_target_escapes_tree]", got, result.Verdict)
	}
}

// The escape can be spelled with a relative `..` link, not only an absolute one;
// both leave the targets tree and both must be refused.
func TestTUFMirrorBlobEscapingViaRelativeLinkIsBlocked(t *testing.T) {
	withFakeTools(t, "cosign")
	const content = "trust me"
	mirror, root, rootChecksum := buildTUFMirror(t, mirrorTarget{name: "trusted_root.json", content: content})
	t.Setenv("MOCK_COSIGN_BRIDGE_ROOT", mirror)

	// ../smuggled from the targets tree is <mirror>/smuggled — inside the mirror
	// but outside the targets tree; content matches the digest so only
	// containment can fail the case.
	writeFile(t, mirror, "smuggled", content)
	blob := filepath.Join(mirror, "targets", sha256Of(content)+".trusted_root.json")
	if err := os.Remove(blob); err != nil {
		t.Fatalf("remove blob: %v", err)
	}
	if err := os.Symlink(filepath.Join("..", "smuggled"), blob); err != nil {
		t.Fatalf("symlink blob: %v", err)
	}

	local := writeFile(t, t.TempDir(), "trusted_root.json", content)
	result := tuf(tufSpec(mirror, root, rootChecksum, map[string]string{"trusted_root.json": local}))
	if got := codes(result); len(got) != 1 || got[0] != "trusted_mirror_target_escapes_tree" {
		t.Fatalf("reasons %v (verdict %s), want [trusted_mirror_target_escapes_tree]", got, result.Verdict)
	}
}

// Containment must hold at the READ, not only at the preceding stat: a change
// that kept the stat cage but read the blob (or the trimmed-newline fallback) by
// a path-following opener would escape. These pin both trusted-side reads
// directly, for absolute and relative escapes.
func TestTrustedReadsAreConfinedToTheirRoot(t *testing.T) {
	dir := t.TempDir()
	targets := mkdir(t, filepath.Join(dir, "targets"))
	writeFile(t, dir, "secret", "smuggled")
	if err := os.Symlink(filepath.Join(dir, "secret"), filepath.Join(targets, "abs.link")); err != nil {
		t.Fatalf("abs link: %v", err)
	}
	if err := os.Symlink(filepath.Join("..", "secret"), filepath.Join(targets, "rel.link")); err != nil {
		t.Fatalf("rel link: %v", err)
	}

	root, err := os.OpenRoot(targets)
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	defer root.Close()

	for _, name := range []string{"abs.link", "rel.link"} {
		if _, err := sha256WithinRoot(root, name); err == nil {
			t.Fatalf("sha256WithinRoot(%q) read outside the root", name)
		}
	}

	local := writeFile(t, t.TempDir(), "local", "smuggled\n")
	for _, name := range []string{"abs.link", "rel.link"} {
		if filesMatchAfterTrimmingNewlines(local, trustedCandidate{root: root, name: name}) {
			t.Fatalf("trimmed match read outside the root via %q", name)
		}
	}
}

// A resolution failure that is not a beneath-root violation — here a symlink loop
// (ELOOP) — is a broken mirror, not an escape, and must keep the pre-containment
// missing-blob reason rather than being mislabeled as an escape. This pins the
// positive escape match in isRootEscape against os.Root's other error classes.
func TestTUFNonEscapeMirrorFailureIsNotReportedAsEscape(t *testing.T) {
	withFakeTools(t, "cosign")
	const content = "trust me"
	mirror, root, rootChecksum := buildTUFMirror(t, mirrorTarget{name: "trusted_root.json", content: content})
	t.Setenv("MOCK_COSIGN_BRIDGE_ROOT", mirror)

	blob := filepath.Join(mirror, "targets", sha256Of(content)+".trusted_root.json")
	if err := os.Remove(blob); err != nil {
		t.Fatalf("remove blob: %v", err)
	}
	if err := os.Symlink(filepath.Base(blob), blob); err != nil {
		t.Fatalf("loop link: %v", err)
	}

	local := writeFile(t, t.TempDir(), "trusted_root.json", content)
	result := tuf(tufSpec(mirror, root, rootChecksum, map[string]string{"trusted_root.json": local}))
	if got := codes(result); len(got) != 1 || got[0] != "trusted_mirror_target_invalid" {
		t.Fatalf("reasons %v, want [trusted_mirror_target_invalid] (a symlink loop is not an escape)", got)
	}
}

// A target whose name literally contains the escape sentinel text must not turn
// a plain missing blob into a false escape. os.Root wraps the error in a
// *PathError whose rendered text includes the caller-supplied blob name, so
// isRootEscape compares the unwrapped node, not the rendered path — otherwise a
// missing blob for a target named "path escapes from parent" would be reported
// as an escape that never happened.
func TestTUFTargetNameContainingEscapeTextIsNotAFalseEscape(t *testing.T) {
	withFakeTools(t, "cosign")
	const (
		name    = "path escapes from parent.json"
		content = "trust me"
	)
	mirror, root, rootChecksum := buildTUFMirror(t, mirrorTarget{name: name, content: content})
	t.Setenv("MOCK_COSIGN_BRIDGE_ROOT", mirror)

	if err := os.Remove(filepath.Join(mirror, "targets", sha256Of(content)+"."+name)); err != nil {
		t.Fatalf("remove blob: %v", err)
	}

	local := writeFile(t, t.TempDir(), "local.json", content)
	result := tuf(tufSpec(mirror, root, rootChecksum, map[string]string{name: local}))
	if got := codes(result); len(got) != 1 || got[0] != "trusted_mirror_target_invalid" {
		t.Fatalf("reasons %v, want [trusted_mirror_target_invalid] (missing, not a false escape)", got)
	}
	if !strings.Contains(result.Reasons[0].Message, "missing from the local TUF mirror") {
		t.Fatalf("message %q, want the missing-blob message", result.Reasons[0].Message)
	}
}

func TestTUFLocalTargetMismatch(t *testing.T) {
	spec, _, local := tufFixture(t)
	if err := os.WriteFile(local, []byte("a different key"), 0o644); err != nil {
		t.Fatalf("rewrite local target: %v", err)
	}

	result := tuf(spec)
	if got := codes(result); len(got) != 1 || got[0] != "trust_material_mismatch" {
		t.Fatalf("reasons %v, want [trust_material_mismatch]", got)
	}
	reason := result.Reasons[0]
	if reason.Data["local_sha256"] != sha256Of("a different key") || reason.Data["trusted_sha256"] != sha256Of("trust me") {
		t.Fatalf("reason data %v does not carry both digests", reason.Data)
	}
}

// Text trust material is routinely re-saved with or without a final newline by
// editors and by shell redirection. Refusing a release over that byte would be
// a false positive, so certificates, keys and JSON may match trimmed.
func TestTUFTrimmedNewlineMatch(t *testing.T) {
	t.Run("a .pem target matches with a trailing newline", func(t *testing.T) {
		withFakeTools(t, "cosign")
		mirror, root, rootChecksum := buildTUFMirror(t, mirrorTarget{name: "signing.pem", content: "-----BEGIN CERT-----"})
		t.Setenv("MOCK_COSIGN_BRIDGE_ROOT", mirror)
		local := writeFile(t, t.TempDir(), "signing.pem", "-----BEGIN CERT-----\n")

		result := tuf(tufSpec(mirror, root, rootChecksum, map[string]string{"signing.pem": local}))
		if result.Verdict != GO || len(result.Reasons) != 0 {
			t.Fatalf("verdict %s with reasons %v, want a clean GO", result.Verdict, codes(result))
		}
	})

	// Binary material gets no such latitude: a trailing byte there is a
	// different file, not a different editor.
	t.Run("a binary target does not", func(t *testing.T) {
		withFakeTools(t, "cosign")
		mirror, root, rootChecksum := buildTUFMirror(t, mirrorTarget{name: "tool.bin", content: "binary"})
		t.Setenv("MOCK_COSIGN_BRIDGE_ROOT", mirror)
		local := writeFile(t, t.TempDir(), "tool.bin", "binary\n")

		result := tuf(tufSpec(mirror, root, rootChecksum, map[string]string{"tool.bin": local}))
		if got := codes(result); len(got) != 1 || got[0] != "trust_material_mismatch" {
			t.Fatalf("reasons %v, want [trust_material_mismatch]", got)
		}
	})
}

// Targets live in a map, so without an explicit sort the report's reason order
// would vary run to run — and the slice-3 fixture corpus diffs reports
// byte-for-byte.
func TestTUFTargetsAreReportedInSortedNameOrder(t *testing.T) {
	withFakeTools(t, "cosign")
	mirror, root, rootChecksum := buildTUFMirror(t, mirrorTarget{name: "known.json", content: "known"})
	t.Setenv("MOCK_COSIGN_BRIDGE_ROOT", mirror)

	dir := t.TempDir()
	targets := map[string]string{
		"zzz.json": writeFile(t, dir, "zzz.json", "z"),
		"aaa.json": writeFile(t, dir, "aaa.json", "a"),
		"mmm.json": writeFile(t, dir, "mmm.json", "m"),
	}

	for range 5 {
		result := tuf(tufSpec(mirror, root, rootChecksum, targets))
		var named []string
		for _, reason := range result.Reasons {
			named = append(named, reason.Data["target"])
		}
		if strings.Join(named, ",") != "aaa.json,mmm.json,zzz.json" {
			t.Fatalf("targets reported as %v, want sorted name order", named)
		}
	}
}

// Collect-all: which inputs are missing is one observation, and whether the
// pinned root is the root on disk is another. The second needs nothing but the
// root, so a missing mirror must not suppress it.
func TestTUFMissingInputsStillAnswerTheRootChecksum(t *testing.T) {
	spec, _, _ := tufFixture(t)
	spec.Checks.TUF.Mirror = filepath.Join(t.TempDir(), "absent-mirror")
	spec.Checks.TUF.RootChecksum = sha256Of("some other root")

	result := tuf(spec)
	got := codes(result)
	if len(got) != 2 || got[0] != "trust_input_missing" || got[1] != "trust_root_mismatch" {
		t.Fatalf("reasons %v, want both observations", got)
	}
	if !strings.Contains(result.Reasons[0].Data["missing"], "absent-mirror") {
		t.Fatalf("missing data %q does not name the mirror", result.Reasons[0].Data["missing"])
	}
}

// A target whose local file the caller did not provide still has its
// mirror-side facts checked — those are facts about the mirror — but it is not
// reported a second time for the file already named as a missing input.
func TestTUFMissingLocalTargetIsNotReportedTwice(t *testing.T) {
	withFakeTools(t, "cosign")
	mirror, root, rootChecksum := buildTUFMirror(t, mirrorTarget{name: "known.json", content: "known"})
	t.Setenv("MOCK_COSIGN_BRIDGE_ROOT", mirror)

	absent := filepath.Join(t.TempDir(), "known.json")
	result := tuf(tufSpec(mirror, root, rootChecksum, map[string]string{"known.json": absent}))

	if got := codes(result); len(got) != 1 || got[0] != "trust_input_missing" {
		t.Fatalf("reasons %v, want only the missing input", got)
	}
}

// A missing cosign is the review's own tooling absent, with an install as the
// recovery — never a BLOCK that would read as a finding about the release.
func TestTUFMissingCosignIsError(t *testing.T) {
	withFakeTools(t)
	mirror, root, rootChecksum := buildTUFMirror(t, mirrorTarget{name: "known.json", content: "known"})
	local := writeFile(t, t.TempDir(), "known.json", "known")

	result := tuf(tufSpec(mirror, root, rootChecksum, map[string]string{"known.json": local}))
	if result.Verdict != ERROR {
		t.Fatalf("verdict %s, want ERROR", result.Verdict)
	}
	if got := codes(result); len(got) != 1 || got[0] != "tool_missing" {
		t.Fatalf("reasons %v, want [tool_missing]", got)
	}
	if !strings.Contains(result.Reasons[0].Message, "install cosign") {
		t.Fatalf("message %q carries no recovery", result.Reasons[0].Message)
	}
}

// The loopback bridge replaces the bash lane's spawned python server, and the
// fake cosign reads the mirror directly rather than fetching it — so the bridge
// is exercised here directly instead of being dead code under the mocks.
func TestServeMirrorServesTheDirectoryOverLoopback(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "targets.json", `{"signed":{"targets":{}}}`)

	base, stop, err := serveMirror(dir)
	if err != nil {
		t.Fatalf("serve mirror: %v", err)
	}
	defer stop()

	if !strings.HasPrefix(base, "http://127.0.0.1:") {
		t.Fatalf("mirror served at %q, want a loopback address", base)
	}

	response, err := http.Get(base + "/targets.json")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", response.StatusCode)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != `{"signed":{"targets":{}}}` {
		t.Fatalf("served %q", body)
	}
}

// getMirror fetches one path from a served mirror and returns its status and
// body, so the bridge cases below assert on both without repeating the plumbing.
func getMirror(t *testing.T, base, path string) (int, string) {
	t.Helper()
	response, err := http.Get(base + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read body of %s: %v", path, err)
	}
	return response.StatusCode, string(body)
}

// The bridge is a second sink for the substitution the blob reads are caged
// against: http.Dir follows symlinks, so a mirror entry pointing out of the tree
// would serve out-of-mirror bytes to cosign during bootstrap — content cosign
// then caches as trusted TUF material. Serving through an *os.Root refuses the
// escaping resolution, which the file server reports as 500 rather than 404, so
// the failure is fail-closed (cosign's fetch fails → bootstrap_failure BLOCK)
// and stays distinguishable from a blob that is merely absent.
func TestServeMirrorRefusesAnEscapingSymlink(t *testing.T) {
	const secret = "out-of-mirror-secret"
	dir := t.TempDir()
	outside := writeFile(t, t.TempDir(), "secret.txt", secret)
	targets := mkdir(t, filepath.Join(dir, "targets"))
	if err := os.Symlink(outside, filepath.Join(targets, "evil")); err != nil {
		t.Fatalf("symlink blob: %v", err)
	}

	base, stop, err := serveMirror(dir)
	if err != nil {
		t.Fatalf("serve mirror: %v", err)
	}
	defer stop()

	status, body := getMirror(t, base, "/targets/evil")
	if status != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500", status)
	}
	if strings.Contains(body, secret) {
		t.Fatalf("body %q carries the out-of-mirror content", body)
	}
}

// The escape can hide at a *directory* component of the request path rather than
// at the file it names — the case a check on the final component alone cannot
// catch, since every component up to it looks like an ordinary directory. Only
// whole-path resolution (os.Root) refuses it.
func TestServeMirrorRefusesAnEscapeThroughASymlinkedDirectory(t *testing.T) {
	const secret = "out-of-mirror-secret"
	dir := t.TempDir()
	outsideDir := t.TempDir()
	writeFile(t, outsideDir, "secret.txt", secret)
	if err := os.Symlink(outsideDir, filepath.Join(dir, "link")); err != nil {
		t.Fatalf("symlink directory: %v", err)
	}

	base, stop, err := serveMirror(dir)
	if err != nil {
		t.Fatalf("serve mirror: %v", err)
	}
	defer stop()

	status, body := getMirror(t, base, "/link/secret.txt")
	if status != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500", status)
	}
	if strings.Contains(body, secret) {
		t.Fatalf("body %q carries the out-of-mirror content", body)
	}
}

// Containment, not link-refusal: a mirror that dedups content-addressed blobs
// through in-tree symlinks is a normal mirror, and refusing it would be a false
// positive on the bootstrap path — the same latitude the blob-read cage grants.
func TestServeMirrorServesAnInTreeSymlink(t *testing.T) {
	const content = "deduped blob"
	dir := t.TempDir()
	targets := mkdir(t, filepath.Join(dir, "targets"))
	real := writeFile(t, targets, "real.blob", content)
	if err := os.Symlink(filepath.Base(real), filepath.Join(targets, "dedup.blob")); err != nil {
		t.Fatalf("symlink blob: %v", err)
	}

	base, stop, err := serveMirror(dir)
	if err != nil {
		t.Fatalf("serve mirror: %v", err)
	}
	defer stop()

	status, body := getMirror(t, base, "/targets/dedup.blob")
	if status != http.StatusOK {
		t.Fatalf("status %d, want 200", status)
	}
	if body != content {
		t.Fatalf("served %q, want the linked file's content", body)
	}
}

// The dedup latitude is for RELATIVE links only: os.Root rejects an absolute
// link target outright rather than resolving where it lands, so even an
// absolute link pointing back beneath the mirror refuses like an escape. Pinned
// so the serveMirror comment's claim stays honest — the refusal is fail-closed,
// not a hole (r1 finding F1).
func TestServeMirrorRefusesAnAbsoluteInTreeSymlink(t *testing.T) {
	const content = "in-tree blob behind an absolute link"
	dir := t.TempDir()
	targets := mkdir(t, filepath.Join(dir, "targets"))
	real := writeFile(t, targets, "real.blob", content)
	if err := os.Symlink(real, filepath.Join(targets, "absolute.blob")); err != nil {
		t.Fatalf("symlink blob: %v", err)
	}

	base, stop, err := serveMirror(dir)
	if err != nil {
		t.Fatalf("serve mirror: %v", err)
	}
	defer stop()

	status, body := getMirror(t, base, "/targets/absolute.blob")
	if status != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500", status)
	}
	if body == content {
		t.Fatalf("absolute-target link was served; want refusal")
	}
}

// A link that stays in the tree but names nothing is absence, not an escape: it
// reads as the ordinary 404 a deleted file gives, never the 500 the cage uses.
func TestServeMirrorDanglingInTreeSymlinkIsNotFound(t *testing.T) {
	dir := t.TempDir()
	targets := mkdir(t, filepath.Join(dir, "targets"))
	if err := os.Symlink("absent-sibling", filepath.Join(targets, "dangling.blob")); err != nil {
		t.Fatalf("symlink blob: %v", err)
	}

	base, stop, err := serveMirror(dir)
	if err != nil {
		t.Fatalf("serve mirror: %v", err)
	}
	defer stop()

	if status, _ := getMirror(t, base, "/targets/dangling.blob"); status != http.StatusNotFound {
		t.Fatalf("status %d, want 404", status)
	}
}
