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
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != `{"signed":{"targets":{}}}` {
		t.Fatalf("served %q", body)
	}
}
