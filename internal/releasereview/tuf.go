package releasereview

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
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

	// The environment is the real one with HOME replaced: a bare slice would drop
	// PATH, and cosign resolves helpers through it. The deadline is cosignRun's,
	// so a hung initialize cannot hold the review open.
	output, timedOut, runErr := cosignRun(envWithHome(cosignHome), "initialize",
		"--mirror", mirrorURL,
		"--root", config.Root,
		"--root-checksum", "sha256:"+config.RootChecksum)
	if timedOut {
		result.add(ERROR, "bootstrap_timeout",
			fmt.Sprintf("cosign did not initialize against the local TUF mirror within %s", cosignSubprocessTimeout), nil)
		return "", "", remove, false
	}
	if runErr != nil {
		result.add(BLOCK, "bootstrap_failure",
			summaryOr(output, "cosign failed to initialize against the local TUF mirror"), nil)
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
//
// The tree is served through an *os.Root rather than http.Dir, which follows
// symlinks: a mirror entry pointing out of the tree would otherwise hand cosign
// out-of-mirror bytes as trusted TUF material, the same substitution the blob
// reads below are caged against. Named failure modes, all observed:
//   - a resolution that leaves the mirror — an escaping symlink at the final
//     component or at any directory component of the request path — fails the
//     open with os.Root's beneath-root violation, which the file server maps to
//     500 rather than 404. cosign's fetch then fails and bootstrap reports
//     bootstrap_failure BLOCK: fail-closed, and distinguishable from a blob that
//     is merely absent.
//   - a dangling in-tree link is absence, not an escape, and reads as 404.
//   - an in-tree symlink is followed and served. Containment is the property,
//     not link-refusal — mirrors legitimately dedup content-addressed blobs
//     through links, the same latitude the hash-read cage grants.
//
// The mirror root itself being a symlink is fine: os.OpenRoot resolves its own
// argument once, and that path is the operator's declaration rather than
// mirror-supplied content. The listener's own error path stays swallowed — a
// failed Serve surfaces as cosign failing to fetch, which is already fail-closed.
func serveMirror(dir string) (string, func(), error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		_ = listener.Close()
		return "", nil, err
	}
	server := &http.Server{Handler: http.FileServer(http.FS(root.FS()))}
	go func() { _ = server.Serve(listener) }()
	// Both halves are closed or the root's descriptor leaks for the life of the
	// review. The server goes first only for tidiness — Close does not drain
	// in-flight handlers, so the ordering guarantees nothing on its own; what
	// makes it safe is that stop runs after cosign has exited, with no request
	// left to serve.
	stop := func() {
		_ = server.Close()
		_ = root.Close()
	}
	return "http://" + listener.Addr().String(), stop, nil
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
// match. It carries the *os.Root the copy lives under and its root-relative
// name so every read of it — the digest above and the trimmed-newline fallback
// below — passes through the same beneath-root enforcement, alongside the digest
// and size it was accepted on.
type trustedCandidate struct {
	root *os.Root
	name string
	sha  string
	size int64
}

// containment is the outcome of resolving a mirror-relative name inside its
// tree: present and contained, absent, or resolving outside the tree.
type containment int

const (
	contained containment = iota
	pathMissing
	pathEscapes
)

// isRootEscape reports whether err is os.Root's beneath-root violation — a name
// whose resolution (a symlink at any component) leaves the root. The stdlib does
// not export the sentinel (os/file.go `errPathEscapes`), so it is matched by its
// message; but only the *unwrapped* node is compared, never the rendered
// *PathError, whose text also carries the caller-supplied path — a target
// legitimately named "path escapes from parent" would otherwise make a plain
// ENOENT look like an escape. The message is stable observable behavior of
// os.Root; the statWithinRoot tests pin it, so a message change surfaces as a
// test failure rather than a silent misclassification. Matching escape
// POSITIVELY, rather than by elimination, also keeps genuine non-escape failures
// — a non-directory component (ENOTDIR), a symlink loop or an over-deep chain
// (ELOOP) — off the escape path, where they would otherwise be reported as an
// escape that never happened.
func isRootEscape(err error) bool {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) && pathErr.Err != nil {
		return pathErr.Err.Error() == "path escapes from parent"
	}
	return false
}

// statWithinRoot stats name inside root and classifies the three outcomes the
// caller reports differently. os.Root refuses any name whose resolution —
// symlinks at the final component or at any parent of a path-like target name
// included — leaves the tree, which is the physical containment the lexical
// name/digest rules cannot provide. Only a beneath-root violation is pathEscapes;
// absence, a dangling in-tree link, a permission error, or any other resolution
// failure is pathMissing, keeping the same missing-blob BLOCK the pre-containment
// code gave an unstattable blob.
func statWithinRoot(root *os.Root, name string) (os.FileInfo, containment) {
	info, err := root.Stat(name)
	switch {
	case err == nil:
		return info, contained
	case isRootEscape(err):
		return nil, pathEscapes
	default:
		return nil, pathMissing
	}
}

// sha256WithinRoot hashes name inside root. os.Root re-enforces containment on
// the Open, so the file hashed is the same contained file statWithinRoot saw —
// the check and the read cannot be split by a symlink swapped in between.
func sha256WithinRoot(root *os.Root, name string) (string, error) {
	file, err := root.Open(name)
	if err != nil {
		return "", err
	}
	defer file.Close()
	return hashReader(file)
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

	// The digest is metadata-supplied and is spliced into the blob's name below,
	// where filepath.Join's Clean would resolve a `..` out of the targets tree —
	// so a non-hex "digest" is refused before it can steer that read (and the
	// mismatch branch could otherwise report the sha256 of an out-of-tree file).
	// The name itself is already refused at spec validation.
	if _, ok := normalizeSHA256(entry.Hashes.SHA256); !ok {
		result.add(BLOCK, "trusted_mirror_target_invalid",
			fmt.Sprintf("trusted metadata's digest for %s is not a sha256", name),
			map[string]string{"target": name, "trusted_metadata_sha256": entry.Hashes.SHA256})
		return
	}

	// Physical containment. The lexical rules above refuse a `..` or absolute
	// *spelling*, but os.Stat/os.Open follow symlinks, so a mirror entry that is
	// a symlink could still steer the hash-read at a file outside the tree. The
	// blob is read through an *os.Root rooted at the mirror's targets directory,
	// which refuses any resolution that leaves it. blobName is a validated digest
	// joined to a spec-validated relative target name.
	blobName := entry.Hashes.SHA256 + "." + name
	blobPath := filepath.Join(config.Mirror, "targets", blobName)
	blobData := map[string]string{"target": name, "mirror_blob_path": blobPath}

	// The mirror is opened as the containment boundary and the targets tree is
	// derived from it, rather than opening <mirror>/targets directly: os.OpenRoot
	// follows symlinks in its own argument, so opening the joined path would
	// follow a `targets` that is itself a symlink out of the mirror and anchor the
	// cage at the escape destination. Deriving the targets Root via Root.OpenRoot
	// refuses a `targets` link that leaves the mirror, while still allowing the
	// operator's declared mirror path to be a symlink (that path is their
	// declaration, not mirror-supplied content).
	mirrorRoot, err := os.OpenRoot(config.Mirror)
	if err != nil {
		result.add(BLOCK, "trusted_mirror_target_invalid",
			fmt.Sprintf("trusted target %s is missing from the local TUF mirror", name), blobData)
		return
	}
	defer mirrorRoot.Close()

	targetsRoot, err := mirrorRoot.OpenRoot("targets")
	if err != nil {
		if isRootEscape(err) {
			result.add(BLOCK, "trusted_mirror_target_escapes_tree",
				fmt.Sprintf("the local TUF mirror's targets directory for %s resolves outside the mirror via a symlink", name),
				blobData)
			return
		}
		// No targets tree to open means the blob it should hold is not there.
		result.add(BLOCK, "trusted_mirror_target_invalid",
			fmt.Sprintf("trusted target %s is missing from the local TUF mirror", name), blobData)
		return
	}
	defer targetsRoot.Close()

	blobInfo, blobContainment := statWithinRoot(targetsRoot, blobName)
	switch {
	case blobContainment == pathEscapes:
		result.add(BLOCK, "trusted_mirror_target_escapes_tree",
			fmt.Sprintf("the local TUF mirror's entry for %s resolves outside the targets tree via a symlink", name),
			blobData)
		return
	case blobContainment == pathMissing, !blobInfo.Mode().IsRegular():
		result.add(BLOCK, "trusted_mirror_target_invalid",
			fmt.Sprintf("trusted target %s is missing from the local TUF mirror", name), blobData)
		return
	}
	blobSHA, err := sha256WithinRoot(targetsRoot, blobName)
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
	// that does not match the blob is not trusted material and is not offered —
	// and, like the blob, it is read through an *os.Root, so an escaping
	// materialized entry is simply not offered rather than hashed out of tree.
	// (That hardening is verdict-invisible: a materialized copy is only ever a
	// candidate when it is byte-identical to the already-contained blob, so it
	// can never change a match outcome — it is defense-in-depth on the read.)
	candidates := make([]trustedCandidate, 0, 2)
	if materializedRoot, err := os.OpenRoot(targetsDir); err == nil {
		defer materializedRoot.Close()
		if info, c := statWithinRoot(materializedRoot, name); c == contained && info.Mode().IsRegular() && info.Size() == blobInfo.Size() {
			if sum, err := sha256WithinRoot(materializedRoot, name); err == nil && sum == blobSHA {
				candidates = append(candidates, trustedCandidate{materializedRoot, name, sum, info.Size()})
			}
		}
	}
	candidates = append(candidates, trustedCandidate{targetsRoot, blobName, blobSHA, blobInfo.Size()})

	trimmedAllowed := trimmedNewlineMatchAllowed(name, localPath)
	for _, candidate := range candidates {
		if localSHA == candidate.sha && localInfo.Size() == candidate.size {
			return
		}
		if trimmedAllowed && filesMatchAfterTrimmingNewlines(localPath, candidate) {
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

// filesMatchAfterTrimmingNewlines compares the caller's local target against a
// trusted candidate, ignoring trailing newlines. The trusted side is read
// through its *os.Root, keeping this fallback read under the same beneath-root
// enforcement as the digest read; the local side is the operator's own declared
// file and is read by path.
func filesMatchAfterTrimmingNewlines(localPath string, trusted trustedCandidate) bool {
	localContent, err := os.ReadFile(localPath)
	if err != nil {
		return false
	}
	trustedContent, err := trusted.root.ReadFile(trusted.name)
	if err != nil {
		return false
	}
	return bytes.Equal(bytes.TrimRight(localContent, "\r\n"), bytes.TrimRight(trustedContent, "\r\n"))
}
