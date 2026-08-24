package releasereview

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// tufTargetsMetadata is the slice of TUF targets metadata this check reads. The
// document carries signatures, delegations and expiry that cosign has already
// validated by the time it lands in the trusted cache; what remains to be
// answered here is only whether the local trust material is the material the
// trusted metadata names.
type tufTargetsMetadata struct {
	Signed struct {
		Targets map[string]struct {
			Hashes struct {
				SHA256 string `json:"sha256"`
			} `json:"hashes"`
			Length int64 `json:"length"`
		} `json:"targets"`
	} `json:"signed"`
}

// tuf bootstraps cosign against a pinned root over a local mirror and compares
// the caller's trust material against what the trusted metadata names.
//
// Two Go properties change the shape of this check against the bash lane it
// ports. The mirror is served by the stdlib over loopback instead of a spawned
// python one-liner, and hashing is native, so two "missing tool" failure modes
// the bash lane could report simply do not exist here.
//
// Bootstrapping is the one place a sequential gate is right rather than lazy: a
// root whose checksum does not match is untrusted material, and running
// `cosign initialize` on it would be performing the very act the checksum was
// pinned to prevent.
func tuf(spec Spec) CheckResult {
	result := CheckResult{Reasons: []Reason{}}
	config := spec.Checks.TUF
	names := sortedNames(config.Targets)

	var missing []string
	mirrorInfo, mirrorErr := os.Stat(config.Mirror)
	mirrorPresent := mirrorErr == nil && mirrorInfo.IsDir()
	if !mirrorPresent {
		missing = append(missing, config.Mirror)
	}
	rootPresent := false
	if _, err := os.Stat(config.Root); err == nil {
		rootPresent = true
	} else {
		missing = append(missing, config.Root)
	}
	// Which local targets are present is recorded rather than only counted: a
	// target whose file is absent still has its mirror-side facts checked below,
	// and only the local comparison is skipped.
	targetPresent := make(map[string]bool, len(names))
	for _, name := range names {
		if _, err := os.Stat(config.Targets[name]); err == nil {
			targetPresent[name] = true
		} else {
			missing = append(missing, config.Targets[name])
		}
	}
	if len(missing) > 0 {
		result.add(BLOCK, "trust_input_missing",
			"required local trust material is missing",
			map[string]string{"missing": strings.Join(missing, ", ")})
	}

	// The root's checksum needs nothing but the root, so it is answered even
	// when the mirror or a target is missing: whether the pinned root is the
	// root on disk is the single most load-bearing fact this check reports.
	rootMatched := false
	if rootPresent {
		actual, err := sha256File(config.Root)
		switch {
		case err != nil:
			result.add(ERROR, "trust_root_unreadable",
				"could not hash the trust root",
				map[string]string{"root": config.Root, "error": err.Error()})
		case actual != config.RootChecksum:
			result.add(BLOCK, "trust_root_mismatch",
				"the trust root does not match its pinned checksum",
				map[string]string{
					"root":                   config.Root,
					"expected_root_checksum": config.RootChecksum,
					"actual_root_checksum":   actual,
				})
		default:
			rootMatched = true
		}
	}

	if _, err := exec.LookPath("cosign"); err != nil {
		result.add(ERROR, "tool_missing",
			"cosign is required to bootstrap TUF trust — install cosign", nil)
		return result
	}
	if !mirrorPresent || !rootMatched {
		return result
	}

	metadataPath, targetsDir, cleanup, ok := bootstrap(&result, config)
	defer cleanup()
	if !ok {
		return result
	}

	var metadata tufTargetsMetadata
	content, err := os.ReadFile(metadataPath)
	if err != nil {
		result.add(BLOCK, "bootstrap_failure",
			summaryOr(err.Error(), "cosign cached trusted targets metadata that could not be read"), nil)
		return result
	}
	if err := json.Unmarshal(content, &metadata); err != nil {
		result.add(BLOCK, "bootstrap_failure",
			"cosign cached trusted targets metadata that is not valid TUF targets JSON", nil)
		return result
	}

	for _, name := range names {
		checkTarget(&result, config, metadata, targetsDir, name, targetPresent[name])
	}
	return result
}

// bootstrap serves the mirror over loopback, runs cosign initialize against the
// pinned root, and locates the trusted metadata cosign cached.
//
// The returned paths live inside a scratch cosign home, so the caller owns
// cleanup: the per-target comparisons read the materialized targets out of it
// after this returns. cleanup is never nil.
func bootstrap(result *CheckResult, config *TUFCheck) (metadataPath, targetsDir string, cleanup func(), ok bool) {
	noop := func() {}

	mirrorURL, stop, err := serveMirror(config.Mirror)
	if err != nil {
		result.add(ERROR, "mirror_unserveable",
			"could not serve the local TUF mirror over loopback",
			map[string]string{"mirror": config.Mirror, "error": err.Error()})
		return "", "", noop, false
	}
	defer stop()

	// cosign writes its trusted cache under HOME. A scratch HOME keeps the
	// review from reading — or worse, overwriting — whatever the invoking user
	// has already initialized.
	cosignHome, err := os.MkdirTemp("", "safe-release-review-tuf-")
	if err != nil {
		result.add(ERROR, "scratch_unavailable",
			"could not create a scratch trust cache for cosign",
			map[string]string{"error": err.Error()})
		return "", "", noop, false
	}
	remove := func() { _ = os.RemoveAll(cosignHome) }

	command := exec.Command("cosign", "initialize",
		"--mirror", mirrorURL,
		"--root", config.Root,
		"--root-checksum", "sha256:"+config.RootChecksum)
	// Built from the real environment with HOME replaced: a bare slice would
	// drop PATH, and cosign resolves helpers through it.
	command.Env = envWithHome(cosignHome)
	output, runErr := command.CombinedOutput()
	if runErr != nil {
		result.add(BLOCK, "bootstrap_failure",
			summaryOr(string(output), "cosign failed to initialize against the local TUF mirror"), nil)
		return "", "", remove, false
	}

	metadataPath, found := findTrustedTargetsMetadata(cosignHome)
	if !found {
		result.add(BLOCK, "bootstrap_failure",
			"cosign initialized, but no trusted targets metadata was cached", nil)
		return "", "", remove, false
	}
	// The metadata's own directory is the trusted repository, and cosign
	// materializes the targets it fetched beside it.
	return metadataPath, filepath.Join(filepath.Dir(metadataPath), "targets"), remove, true
}

// serveMirror serves a directory over a loopback-only HTTP listener and returns
// its base URL plus a stop function.
//
// A local directory is what the spec names, but cosign speaks HTTP to a mirror.
// Loopback with an ephemeral port keeps the bridge unreachable from anywhere but
// this process's own host for the few seconds it exists.
func serveMirror(dir string) (string, func(), error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	server := &http.Server{Handler: http.FileServer(http.Dir(dir))}
	go func() { _ = server.Serve(listener) }()
	return "http://" + listener.Addr().String(), func() { _ = server.Close() }, nil
}

// findTrustedTargetsMetadata locates targets.json exactly two levels under the
// cosign home's .sigstore/root, which is where cosign caches the repository it
// bootstrapped. Directory entries are read in sorted order, so a home holding
// more than one repository resolves the same way every run.
func findTrustedTargetsMetadata(cosignHome string) (string, bool) {
	root := filepath.Join(cosignHome, ".sigstore", "root")
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", false
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		candidate := filepath.Join(root, entry.Name(), "targets.json")
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			return candidate, true
		}
	}
	return "", false
}

func envWithHome(home string) []string {
	environment := os.Environ()
	filtered := make([]string, 0, len(environment)+1)
	for _, entry := range environment {
		if strings.HasPrefix(entry, "HOME=") {
			continue
		}
		filtered = append(filtered, entry)
	}
	return append(filtered, "HOME="+home)
}

// trustedCandidate is one copy of a target the local file may legitimately
// match, carried with the digest and size it was accepted on.
type trustedCandidate struct {
	path string
	sha  string
	size int64
}

// checkTarget compares one local trust target against the trusted material.
//
// The mirror-side facts — that the trusted metadata names the target at all,
// and that the mirror's blob is the blob the metadata describes — are facts
// about the mirror, so they are reported even for a target whose local file the
// caller did not provide. Only the last comparison genuinely needs that file,
// and a target already reported as a missing input is not reported twice.
func checkTarget(result *CheckResult, config *TUFCheck, metadata tufTargetsMetadata, targetsDir, name string, localPresent bool) {
	entry, named := metadata.Signed.Targets[name]
	if !named {
		result.add(BLOCK, "policy_mismatch",
			fmt.Sprintf("trusted TUF metadata does not name target %s", name),
			map[string]string{"target": name})
		return
	}

	blobPath := filepath.Join(config.Mirror, "targets", entry.Hashes.SHA256+"."+name)
	blobData := map[string]string{"target": name, "mirror_blob_path": blobPath}
	blobInfo, err := os.Stat(blobPath)
	if err != nil || !blobInfo.Mode().IsRegular() {
		result.add(BLOCK, "trusted_mirror_target_invalid",
			fmt.Sprintf("trusted target %s is missing from the local TUF mirror", name), blobData)
		return
	}
	blobSHA, err := sha256File(blobPath)
	if err != nil || blobSHA != entry.Hashes.SHA256 || blobInfo.Size() != entry.Length {
		result.add(BLOCK, "trusted_mirror_target_invalid",
			fmt.Sprintf("the local TUF mirror's copy of %s does not match trusted metadata", name),
			map[string]string{
				"target":                    name,
				"mirror_blob_path":          blobPath,
				"trusted_metadata_sha256":   entry.Hashes.SHA256,
				"actual_mirror_blob_sha256": blobSHA,
			})
		return
	}

	if !localPresent {
		return
	}
	localPath := config.Targets[name]
	localSHA, err := sha256File(localPath)
	if err != nil {
		result.add(ERROR, "trust_target_unreadable",
			fmt.Sprintf("could not hash local trust target %s", name),
			map[string]string{"target": name, "error": err.Error()})
		return
	}
	localInfo, err := os.Stat(localPath)
	if err != nil {
		result.add(ERROR, "trust_target_unreadable",
			fmt.Sprintf("could not stat local trust target %s", name),
			map[string]string{"target": name, "error": err.Error()})
		return
	}

	// The materialized copy is preferred when cosign produced one that matches
	// the mirror blob, because that is the file a cosign-driven workflow would
	// actually consume; the mirror blob is the fallback. A materialized copy
	// that does not match the blob is not trusted material and is not offered.
	candidates := make([]trustedCandidate, 0, 2)
	materialized := filepath.Join(targetsDir, name)
	if info, err := os.Stat(materialized); err == nil && info.Mode().IsRegular() && info.Size() == blobInfo.Size() {
		if sum, err := sha256File(materialized); err == nil && sum == blobSHA {
			candidates = append(candidates, trustedCandidate{materialized, sum, info.Size()})
		}
	}
	candidates = append(candidates, trustedCandidate{blobPath, blobSHA, blobInfo.Size()})

	trimmedAllowed := trimmedNewlineMatchAllowed(name, localPath)
	for _, candidate := range candidates {
		if localSHA == candidate.sha && localInfo.Size() == candidate.size {
			return
		}
		if trimmedAllowed && filesMatchAfterTrimmingNewlines(localPath, candidate.path) {
			return
		}
	}

	result.add(BLOCK, "trust_material_mismatch",
		fmt.Sprintf("local trust target %s does not match the trusted TUF target", name),
		map[string]string{
			"target":         name,
			"local_sha256":   localSHA,
			"trusted_sha256": blobSHA,
			"trusted_length": strconv.FormatInt(entry.Length, 10),
		})
}

// trimmedNewlineMatchAllowed reports whether a target may match after trailing
// newlines are trimmed. Text trust material — keys, certificates, JSON — is
// routinely re-saved with or without a final newline by editors and by shell
// redirection, and refusing a release over that byte would be a false positive.
// Binary targets get no such latitude.
func trimmedNewlineMatchAllowed(name, path string) bool {
	for _, extension := range []string{".pub", ".pem", ".crt", ".cer", ".json"} {
		if strings.HasSuffix(strings.ToLower(name), extension) ||
			strings.HasSuffix(strings.ToLower(path), extension) {
			return true
		}
	}
	return false
}

func filesMatchAfterTrimmingNewlines(left, right string) bool {
	leftContent, err := os.ReadFile(left)
	if err != nil {
		return false
	}
	rightContent, err := os.ReadFile(right)
	if err != nil {
		return false
	}
	return bytes.Equal(bytes.TrimRight(leftContent, "\r\n"), bytes.TrimRight(rightContent, "\r\n"))
}
