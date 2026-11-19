package projectlane

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"
)

// The binding transaction (spec 1625, Binding): what the project lane judged is
// what lands in node_modules, or nothing does.
//
// The tree is built in a staging directory inside the project, private to the
// user, and published only once it has been verified against the judged
// lockfile. Until publication the project is not touched: a failure, a signal
// or the child's death leaves nothing to restore. Publication is the one
// stretch that is not atomic, and it is journaled so that whatever interrupts
// it leaves a state the next run reads and undoes (see publish).
//
// ORDER OF THE STEPS, and what each failure point leaves on disk:
//
//	 1  check the request, the project directory and the lock   nothing written
//	 2  recover a stale staging directory a killed run left      (see Recover)
//	 3  check the tree root (absent or a real directory) and
//	    the live inputs against the judged digests               nothing written
//	 4  create the staging directory, copy the judged inputs in  staging only
//	 5  run the install command in staging, as a child           staging only
//	 6  verify the staged tree against the judged lockfile       staging only
//	 7  publish (journaled):
//	      a  re-check the live inputs and the tree root; write the replacement
//	         files next to the journal                           staging only
//	      b  write the journal (fsync)                           staging only
//	      c  move the old tree aside, into staging               tree ABSENT, old tree in staging
//	      d  move the staged tree in                             verified tree in place, old inputs
//	      e  for each judged file: link the old one to a backup,
//	         check it is still what was judged, rename the new
//	         one over it                                         verified tree, k files replaced
//	      f  commit: remove the journal                          project is final
//	      g  remove staging (old tree and backups with it)       project is final
//
// Before 7c any failure, signal or kill of the child leaves the project byte
// for byte as it was, and the staging directory is removed. From 7c to 7f a
// failure is undone in process, in reverse, and a crash is undone by the next
// run (Recover): at no point is the tree in place anything but the old tree,
// no tree, or the verified one. A signal received from 7b on is deferred until
// the commit. A SIGKILL of project-bind leaves its staging directory (the
// child dies with it, see the process attributes); the next run removes it.

// Outcomes of a bind and the exit status each is reported with. The statuses
// stay clear of safe's own (0/10-17/20-22/100-104/127): they are safe-core's,
// and the gate maps them.
const (
	BindSchema = 1

	OutcomePublished          = "published"
	OutcomeRefused            = "refused"
	OutcomeInstallFailed      = "install_failed"
	OutcomeVerificationFailed = "verification_failed"
	OutcomeInputsChanged      = "inputs_changed"
	OutcomeInterrupted        = "interrupted"
	OutcomePublicationFailed  = "publication_failed"

	ExitPublished          = 0
	ExitRefused            = 30
	ExitInstallFailed      = 31
	ExitVerificationFailed = 32
	ExitInputsChanged      = 33
	ExitInterrupted        = 34
	ExitPublicationFailed  = 35
)

// Reasons a bind is refused, or fails. Stable identifiers.
const (
	ReasonLockNotHeld          = "lock_not_held"
	ReasonLockBusy             = "lock_held_by_another"
	ReasonProjectInvalid       = "project_invalid"
	ReasonTreeRootSymlink      = "tree_root_symlink"
	ReasonTreeRootInvalid      = "tree_root_invalid"
	ReasonInputUnsafe          = "input_unsafe"
	ReasonRequestInvalid       = "request_invalid"
	ReasonCompetingLockfile    = "competing_lockfile"
	ReasonLockfileUnreadable   = "lockfile_unreadable"
	ReasonLinksNotSupported    = "links_not_supported"
	ReasonLockfilePathsOutside = "lockfile_path_outside_tree"
	ReasonRecoveryIncomplete   = "recovery_incomplete"
	ReasonStagingFailed        = "staging_failed"
	ReasonStartFailed          = "install_start_failed"
	ReasonInstallExit          = "install_exit"
	ReasonInstallSignaled      = "install_signaled"
	ReasonVerification         = "verification_failed"
	ReasonInputsChanged        = "inputs_changed"
	ReasonSignal               = "signal"
	ReasonPublication          = "publication_error"
)

// Publication states.
const (
	PublicationNotStarted = "not_started"
	PublicationCommitted  = "committed"
	PublicationRolledBack = "rolled_back"
	// PublicationIncomplete: the old tree could not be put back. Staging is
	// kept: it holds the old tree, and the next run refuses until it is dealt
	// with.
	PublicationIncomplete = "rollback_incomplete"
)

// File is a judged input: a project-relative path and the bytes judged.
type File struct {
	Rel     string
	Content []byte
}

// LockMode says how the caller's exclusive lock on the project directory is
// proven (see proveLock).
type LockMode struct {
	// FD is a descriptor the caller opened on the project directory and
	// holds LOCK_EX on, inherited by this process. Negative: not given.
	FD int
	// Take makes the transaction take the lock itself, without waiting, and
	// release it on exit. Exactly one of FD (>= 0) and Take is set.
	Take bool
}

// BindRequest is everything the transaction reads.
type BindRequest struct {
	Project string
	// Publish are the judged manifests and the lockfile, replaced at
	// publication (and copied into staging). Rel names must include
	// package.json and package-lock.json.
	Publish []File
	// Copy are judged configuration files copied into staging only.
	Copy []File
	// Live is the digest of every project input as it was when judged:
	// "sha256:<hex>", or "absent". It must name every Publish and Copy path
	// and npm-shrinkwrap.json as absent: the competing lockfile name.
	Live map[string]string
	// Argv is the frozen install command; Argv[0] is an absolute path. Env is
	// the whole environment it runs with (KEY=VALUE); nothing is inherited.
	Argv      []string
	Env       []string
	Selection Selection
	Lock      LockMode
	// ChildOutput receives the child's stdout and stderr.
	ChildOutput io.Writer
}

// InstallReport is what happened to the install command. The child's own
// status is kept apart from the transaction's outcome.
type InstallReport struct {
	Ran        bool   `json:"ran"`
	ExitCode   *int   `json:"exit_code"`
	Signal     string `json:"signal"`
	DurationMS int64  `json:"duration_ms"`
}

// InputChange is one live input that is no longer what was judged.
type InputChange struct {
	Path   string `json:"path"`
	Judged string `json:"judged"`
	Found  string `json:"found"`
}

// PublicationReport says how far publication went.
type PublicationReport struct {
	State string `json:"state"`
	// Published lists the files replaced (only meaningful for "committed").
	Published []string `json:"published"`
	// Conflicts lists files a rollback left alone because they had been
	// changed since the transaction wrote them.
	Conflicts []string `json:"conflicts"`
}

// StagingReport says whether the staging directory is gone.
type StagingReport struct {
	Removed bool `json:"removed"`
	// Path is the directory left behind, "" when removed.
	Path string `json:"path"`
}

// RecoveryReport is what the run found of an earlier, killed run.
type RecoveryReport struct {
	Found    int      `json:"found"`
	Undone   int      `json:"undone"`
	Removed  int      `json:"removed"`
	Conflict []string `json:"conflicts"`
	Left     []string `json:"left"`
}

// BindReport is the document project-bind prints: strict, versioned, and the
// same members always.
type BindReport struct {
	SchemaVersion int               `json:"schema_version"`
	Outcome       string            `json:"outcome"`
	Exit          int               `json:"exit"`
	Reason        string            `json:"reason"`
	Detail        string            `json:"detail"`
	Project       string            `json:"project"`
	Selection     Selection         `json:"selection"`
	Install       InstallReport     `json:"install"`
	Verification  *TreeReport       `json:"verification"`
	Changed       []InputChange     `json:"inputs_changed"`
	Publication   PublicationReport `json:"publication"`
	Staging       StagingReport     `json:"staging"`
	Recovery      RecoveryReport    `json:"recovery"`
	// Signal is the signal that was received, "" if none. With outcome
	// "interrupted" it ended the run; with "published" it arrived during
	// publication and was deferred until the commit.
	Signal string `json:"signal"`
}

const (
	stagingPrefix = ".safe-bind-"
	scratchDir    = ".publish"
	journalName   = "journal.json"
	oldTreeName   = "old-tree"
	maxInputBytes = 256 << 20
)

// errCrash, returned by a test hook, makes the transaction return at once
// without any cleanup, as if the process had been killed there.
var errCrash = errors.New("simulated crash")

// bindHook is called at every stage boundary of a transaction; a non-nil
// error makes the stage fail (errCrash: the process dies there). Tests only.
var bindHook func(stage string) error

func hook(stage string) error {
	if bindHook == nil {
		return nil
	}
	return bindHook(stage)
}

type transaction struct {
	req      BindRequest
	report   BindReport
	project  string
	staging  string
	release  func()
	judged   map[string]File // by Rel, Publish and Copy
	lockfile []byte
	projDev  uint64
	ctx      context.Context
	crashed  bool
	keep     bool // keep staging (old tree inside)
}

func newReport(selection Selection) BindReport {
	return BindReport{
		SchemaVersion: BindSchema,
		Selection:     selection.normalized(),
		Changed:       []InputChange{},
		Publication:   PublicationReport{State: PublicationNotStarted, Published: []string{}, Conflicts: []string{}},
		Recovery:      RecoveryReport{Conflict: []string{}, Left: []string{}},
	}
}

func exitFor(outcome string) int {
	switch outcome {
	case OutcomePublished:
		return ExitPublished
	case OutcomeRefused:
		return ExitRefused
	case OutcomeInstallFailed:
		return ExitInstallFailed
	case OutcomeVerificationFailed:
		return ExitVerificationFailed
	case OutcomeInputsChanged:
		return ExitInputsChanged
	case OutcomeInterrupted:
		return ExitInterrupted
	}
	return ExitPublicationFailed
}

func (t *transaction) end(outcome, reason, detail string) BindReport {
	t.report.Outcome, t.report.Reason, t.report.Detail = outcome, reason, detail
	t.report.Exit = exitFor(outcome)
	return t.report
}

func signalOf(ctx context.Context) string {
	if ctx.Err() == nil {
		return ""
	}
	if cause := context.Cause(ctx); cause != nil && cause != context.Canceled {
		return cause.Error()
	}
	return "canceled"
}

// Bind runs the transaction. ctx is cancelled by the caller on a signal; the
// cause names it. The returned report is complete whatever happened.
func Bind(ctx context.Context, req BindRequest) BindReport {
	t := &transaction{req: req, ctx: ctx, report: newReport(req.Selection), judged: map[string]File{}}
	t.report.Project = req.Project
	report := t.run()
	if !t.crashed {
		t.finish(&report)
	}
	return report
}

// finish removes the staging directory and the lock, and reports what is
// left. It runs after every outcome but a simulated crash.
func (t *transaction) finish(report *BindReport) {
	if t.staging != "" && !t.keep {
		if err := removeTree(t.staging); err != nil || exists(t.staging) {
			report.Staging = StagingReport{Removed: false, Path: t.staging}
		} else {
			report.Staging = StagingReport{Removed: true}
		}
	} else if t.staging != "" {
		report.Staging = StagingReport{Removed: false, Path: t.staging}
	} else {
		report.Staging = StagingReport{Removed: true}
	}
	if t.release != nil {
		t.release()
	}
}

func (t *transaction) refuse(reason, format string, args ...any) BindReport {
	return t.end(OutcomeRefused, reason, fmt.Sprintf(format, args...))
}

func (t *transaction) interrupted() BindReport {
	t.report.Signal = signalOf(t.ctx)
	return t.end(OutcomeInterrupted, ReasonSignal, "interrupted by "+t.report.Signal+"; the project is as it was")
}

func (t *transaction) run() BindReport {
	if report, ok := t.admit(); !ok {
		return report
	}
	if err := hook("admitted"); err != nil {
		return t.hookFailure(err)
	}
	if t.ctx.Err() != nil {
		return t.interrupted()
	}

	// The lock: proven before anything in the project is read or written.
	if err := t.takeLock(); err != nil {
		return t.refuse(err.reason, "%s", err.detail)
	}
	if report, ok := t.recover(); !ok {
		return report
	}
	if report, ok := t.checkProject(); !ok {
		return report
	}

	// Staging.
	if err := t.createStaging(); err != nil {
		return t.refuse(ReasonStagingFailed, "%v", err)
	}
	if err := hook("staged"); err != nil {
		return t.hookFailure(err)
	}
	if t.ctx.Err() != nil {
		return t.interrupted()
	}

	// The install, as a child.
	if report, ok := t.install(); !ok {
		return report
	}
	if err := hook("installed"); err != nil {
		return t.hookFailure(err)
	}
	if t.ctx.Err() != nil {
		return t.interrupted()
	}

	// Verification, against the judged lockfile bytes (not a file the child
	// could have touched).
	if err := hook("verifying"); err != nil {
		return t.hookFailure(err)
	}
	verification, err := VerifyTree(t.lockfile, t.staging, t.req.Selection)
	if err != nil {
		return t.end(OutcomeVerificationFailed, ReasonVerification, "the staged tree could not be verified: "+err.Error())
	}
	t.report.Verification = &verification
	if t.ctx.Err() != nil {
		// A signal during verification is honoured: never "verified, then
		// published" over an interrupted run.
		return t.interrupted()
	}
	if !verification.Ok {
		return t.end(OutcomeVerificationFailed, ReasonVerification,
			fmt.Sprintf("the staged tree is not the judged one (%d problems, first: %s at %s)",
				len(verification.Problems), verification.Problems[0].Problem, verification.Problems[0].Path))
	}
	if err := hook("verified"); err != nil {
		return t.hookFailure(err)
	}
	if t.ctx.Err() != nil {
		return t.interrupted()
	}

	return t.publish()
}

func (t *transaction) hookFailure(err error) BindReport {
	if errors.Is(err, errCrash) {
		t.crashed = true
		return t.end(OutcomePublicationFailed, ReasonPublication, "simulated crash")
	}
	if t.ctx.Err() != nil {
		return t.interrupted()
	}
	return t.end(OutcomeRefused, ReasonRequestInvalid, err.Error())
}

// admit checks the request in itself, before the filesystem is consulted.
func (t *transaction) admit() (BindReport, bool) {
	req := t.req
	if err := req.Selection.Validate(); err != nil {
		return t.refuse(ReasonRequestInvalid, "selection: %v", err), false
	}
	if len(req.Argv) == 0 || !filepath.IsAbs(req.Argv[0]) {
		return t.refuse(ReasonRequestInvalid, "the install command must be an absolute path"), false
	}
	if req.Env == nil {
		return t.refuse(ReasonRequestInvalid, "the install environment must be given"), false
	}
	for _, kind := range [][]File{req.Publish, req.Copy} {
		for _, file := range kind {
			if !validRel(file.Rel) {
				return t.refuse(ReasonRequestInvalid, "%q is not a project-relative path inside the project", file.Rel), false
			}
			if _, dup := t.judged[file.Rel]; dup {
				return t.refuse(ReasonRequestInvalid, "%q is given twice", file.Rel), false
			}
			t.judged[file.Rel] = file
		}
	}
	for _, file := range req.Publish {
		if base := path.Base(file.Rel); base != "package.json" && file.Rel != "package-lock.json" {
			return t.refuse(ReasonRequestInvalid, "%q is neither a manifest nor the lockfile", file.Rel), false
		}
	}
	lock, hasLock := t.judged["package-lock.json"]
	_, hasManifest := t.judged["package.json"]
	if !hasLock || !hasManifest || !containsFile(req.Publish, "package-lock.json") || !containsFile(req.Publish, "package.json") {
		return t.refuse(ReasonRequestInvalid, "the root package.json and package-lock.json must be published"), false
	}
	// Live digests: one for every input, and the competing lockfile name
	// judged absent.
	required := map[string]bool{"npm-shrinkwrap.json": true}
	for rel := range t.judged {
		required[rel] = true
	}
	for rel := range required {
		digest, ok := req.Live[rel]
		if !ok {
			return t.refuse(ReasonRequestInvalid, "no judged digest for %q", rel), false
		}
		if !validDigest(digest) {
			return t.refuse(ReasonRequestInvalid, "the judged digest of %q is neither sha256:<hex> nor absent", rel), false
		}
	}
	for rel, digest := range req.Live {
		if !validRel(rel) {
			return t.refuse(ReasonRequestInvalid, "%q is not a project-relative path inside the project", rel), false
		}
		if !validDigest(digest) {
			return t.refuse(ReasonRequestInvalid, "the judged digest of %q is neither sha256:<hex> nor absent", rel), false
		}
	}
	if req.Live["npm-shrinkwrap.json"] != "absent" {
		return t.refuse(ReasonCompetingLockfile, "npm-shrinkwrap.json existed when the project was judged: npm would read it before package-lock.json"), false
	}
	// The judged lockfile is admitted before anything runs.
	lockfile, err := parseJudgedLockfile(lock.Content)
	switch {
	case errors.Is(err, ErrLinkEntries):
		return t.refuse(ReasonLinksNotSupported, "%v", err), false
	case err != nil:
		return t.refuse(ReasonLockfileUnreadable, "%v", err), false
	case len(lockfile.outside) > 0:
		return t.refuse(ReasonLockfilePathsOutside, "the lockfile names %q, which is not inside the tree", lockfile.outside[0]), false
	}
	t.lockfile = lock.Content
	return BindReport{}, true
}

func containsFile(files []File, rel string) bool {
	for _, file := range files {
		if file.Rel == rel {
			return true
		}
	}
	return false
}

func validDigest(digest string) bool {
	if digest == "absent" {
		return true
	}
	hexText, ok := strings.CutPrefix(digest, "sha256:")
	if !ok || len(hexText) != 64 {
		return false
	}
	_, err := hex.DecodeString(hexText)
	return err == nil && hexText == strings.ToLower(hexText)
}

// validRel accepts a clean relative path whose segments are plain names, not
// node_modules and not a staging directory.
func validRel(rel string) bool {
	if rel == "" || strings.ContainsAny(rel, "\\\x00") || path.IsAbs(rel) || path.Clean(rel) != rel {
		return false
	}
	for i, segment := range strings.Split(rel, "/") {
		if segment == "" || segment == "." || segment == ".." || segment == "node_modules" {
			return false
		}
		if i == 0 && strings.HasPrefix(segment, stagingPrefix) {
			return false
		}
	}
	return true
}

type reasoned struct {
	reason, detail string
}

// takeLock proves, or takes, the exclusive kernel lock on the project
// directory.
func (t *transaction) takeLock() *reasoned {
	project, err := filepath.EvalSymlinks(t.req.Project)
	if err != nil {
		return &reasoned{ReasonProjectInvalid, err.Error()}
	}
	project, err = filepath.Abs(project)
	if err != nil {
		return &reasoned{ReasonProjectInvalid, err.Error()}
	}
	info, err := os.Stat(project)
	if err != nil || !info.IsDir() {
		return &reasoned{ReasonProjectInvalid, fmt.Sprintf("%q is not a directory", t.req.Project)}
	}
	t.project = project
	t.report.Project = project
	t.projDev = devOf(info)

	if t.req.Lock.Take {
		file, err := os.Open(project)
		if err != nil {
			return &reasoned{ReasonProjectInvalid, err.Error()}
		}
		if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			file.Close()
			return &reasoned{ReasonLockBusy, "another process holds the project lock"}
		}
		t.release = func() { _ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN); file.Close() }
		return nil
	}
	if t.req.Lock.FD < 0 {
		return &reasoned{ReasonLockNotHeld, "no lock descriptor was given"}
	}
	// The descriptor stays the caller's: it is used by number and never
	// wrapped in an os.File, whose finalizer would close it.
	if reason := proveLock(project, t.req.Lock.FD); reason != "" {
		return &reasoned{ReasonLockNotHeld, reason}
	}
	return nil
}

// proveLock checks that file, a descriptor this process inherited, is the
// caller's exclusive lock on the project directory:
//
//  1. it is an open directory, the same one as the project (device and inode);
//  2. a separate open file description cannot take even a shared lock on the
//     directory (flock conflicts across descriptions, so an exclusive lock is
//     held by one);
//  3. this descriptor can take the exclusive lock without waiting: it is the
//     one that holds it (converting a lock it already owns succeeds, any
//     other holder would make it fail).
//
// Step 3 also makes the lock ours should the holder have released it between 2
// and 3: this process then holds it for the whole transaction either way.
func proveLock(project string, fd int) string {
	var held, want syscall.Stat_t
	if err := syscall.Fstat(fd, &held); err != nil {
		return "the lock descriptor is not open"
	}
	if held.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return "the lock descriptor is not a directory"
	}
	if err := syscall.Stat(project, &want); err != nil || held.Dev != want.Dev || held.Ino != want.Ino {
		return "the lock descriptor is not the project directory"
	}
	probe, err := os.Open(project)
	if err != nil {
		return "the project directory cannot be opened: " + err.Error()
	}
	defer probe.Close()
	if err := syscall.Flock(int(probe.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err == nil {
		_ = syscall.Flock(int(probe.Fd()), syscall.LOCK_UN)
		return "no exclusive lock is held on the project directory"
	} else if !errors.Is(err, syscall.EWOULDBLOCK) {
		return "the lock state could not be read: " + err.Error()
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return "the exclusive lock on the project directory is held by another descriptor"
	}
	return ""
}

func devOf(info os.FileInfo) uint64 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(stat.Dev)
	}
	return 0
}

func ownedByUs(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Geteuid()
}

func exists(name string) bool {
	_, err := os.Lstat(name)
	return err == nil
}

func (t *transaction) abs(rel string) string {
	return filepath.Join(t.project, filepath.FromSlash(rel))
}

// checkProject checks the tree root and the live inputs before anything runs.
func (t *transaction) checkProject() (BindReport, bool) {
	if reason, detail := t.checkTreeRoot(); reason != "" {
		return t.refuse(reason, "%s", detail), false
	}
	// Every publish and copy destination must be a regular file (or absent)
	// below real directories, the judged digests must still hold.
	changes, unsafe := t.liveChanges()
	if unsafe != "" {
		return t.refuse(ReasonInputUnsafe, "%s", unsafe), false
	}
	if len(changes) > 0 {
		t.report.Changed = changes
		return t.end(OutcomeInputsChanged, ReasonInputsChanged, "a project input is not what was judged; nothing was run"), false
	}
	return BindReport{}, true
}

func (t *transaction) checkTreeRoot() (reason, detail string) {
	info, err := os.Lstat(t.abs("node_modules"))
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "", ""
	case err != nil:
		return ReasonTreeRootInvalid, "the tree root cannot be read: " + err.Error()
	case info.Mode()&os.ModeSymlink != 0:
		return ReasonTreeRootSymlink, "node_modules is a symbolic link; nothing was run and nothing behind the link was touched"
	case !info.IsDir():
		return ReasonTreeRootInvalid, "node_modules is not a directory"
	case devOf(info) != t.projDev:
		return ReasonTreeRootInvalid, "node_modules is a mount point of another device and cannot be moved aside"
	}
	return "", ""
}

// liveChanges compares the live inputs with the judged digests. unsafe is set
// for an input that is a link, a special file, or sits below a link: that is a
// refusal, not a change.
func (t *transaction) liveChanges() (changes []InputChange, unsafe string) {
	rels := make([]string, 0, len(t.req.Live))
	for rel := range t.req.Live {
		rels = append(rels, rel)
	}
	sort.Strings(rels)
	for _, rel := range rels {
		found, problem := t.liveDigest(rel)
		if problem != "" {
			return nil, problem
		}
		if found != t.req.Live[rel] {
			changes = append(changes, InputChange{Path: rel, Judged: t.req.Live[rel], Found: found})
		}
	}
	return changes, ""
}

// liveDigest digests one live input without following a link anywhere on its
// path. A problem names an input that cannot be a destination.
func (t *transaction) liveDigest(rel string) (digest, problem string) {
	parts := strings.Split(rel, "/")
	for i := 1; i < len(parts); i++ {
		info, err := os.Lstat(t.abs(strings.Join(parts[:i], "/")))
		if errors.Is(err, os.ErrNotExist) {
			return "absent", ""
		}
		if err != nil {
			return "", fmt.Sprintf("%s: %v", rel, err)
		}
		if !info.IsDir() {
			return "", fmt.Sprintf("%s: %s is a symbolic link or not a directory", rel, strings.Join(parts[:i], "/"))
		}
	}
	info, err := os.Lstat(t.abs(rel))
	if errors.Is(err, os.ErrNotExist) {
		return "absent", ""
	}
	if err != nil {
		return "", fmt.Sprintf("%s: %v", rel, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Sprintf("%s is a symbolic link or not a regular file", rel)
	}
	raw, err := readFileNoFollow(t.abs(rel), maxInputBytes)
	if err != nil {
		return "", fmt.Sprintf("%s: %v", rel, err)
	}
	return digestOf(raw), ""
}

func digestOf(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func randomName() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

// createStaging makes the private staging directory and copies the judged
// inputs into it.
func (t *transaction) createStaging() error {
	for attempt := 0; attempt < 8; attempt++ {
		name, err := randomName()
		if err != nil {
			return err
		}
		dir := filepath.Join(t.project, stagingPrefix+name)
		if err := os.Mkdir(dir, 0o700); err != nil {
			if errors.Is(err, os.ErrExist) {
				continue
			}
			return err
		}
		t.staging = dir
		break
	}
	if t.staging == "" {
		return errors.New("no free staging name")
	}
	if err := os.Chmod(t.staging, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(t.staging)
	if err != nil || devOf(info) != t.projDev {
		return errors.New("the staging directory is not on the project's filesystem")
	}
	rels := make([]string, 0, len(t.judged))
	for rel := range t.judged {
		rels = append(rels, rel)
	}
	sort.Strings(rels)
	for _, rel := range rels {
		dst := filepath.Join(t.staging, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(dst, t.judged[rel].Content, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// install runs the frozen install in staging and waits for it. Its status is
// reported apart from the transaction's.
func (t *transaction) install() (BindReport, bool) {
	sealDescriptors()
	cmd := exec.Command(t.req.Argv[0], t.req.Argv[1:]...)
	cmd.Dir = t.staging
	cmd.Env = append([]string{}, t.req.Env...)
	cmd.Stdin = nil
	if t.req.ChildOutput != nil {
		cmd.Stdout, cmd.Stderr = t.req.ChildOutput, t.req.ChildOutput
	}
	cmd.WaitDelay = 5 * time.Second
	cmd.SysProcAttr = childAttributes()

	// The child dies with this process (Pdeathsig fires when the thread that
	// started it exits): the thread stays put until the child is waited for.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	started := time.Now()
	if err := cmd.Start(); err != nil {
		t.report.Install = InstallReport{DurationMS: time.Since(started).Milliseconds()}
		return t.end(OutcomeInstallFailed, ReasonStartFailed, "the install command did not start: "+err.Error()), false
	}
	t.report.Install.Ran = true
	pgid := cmd.Process.Pid

	done := make(chan struct{})
	watched := make(chan struct{})
	go func() {
		defer close(watched)
		select {
		case <-t.ctx.Done():
			_ = syscall.Kill(-pgid, syscall.SIGTERM)
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				_ = syscall.Kill(-pgid, syscall.SIGKILL)
			}
		case <-done:
		}
	}()
	waitErr := cmd.Wait()
	close(done)
	<-watched
	// Whatever the child left running in its process group is swept before
	// the tree is read: nothing may write into staging while it is verified.
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
	t.report.Install.DurationMS = time.Since(started).Milliseconds()

	state := cmd.ProcessState
	if state != nil {
		if status, ok := state.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			t.report.Install.Signal = status.Signal().String()
		} else {
			code := state.ExitCode()
			t.report.Install.ExitCode = &code
		}
	}
	if t.ctx.Err() != nil {
		return t.interrupted(), false
	}
	switch {
	case t.report.Install.Signal != "":
		return t.end(OutcomeInstallFailed, ReasonInstallSignaled, "the install command was killed by "+t.report.Install.Signal), false
	case waitErr != nil:
		var exit *exec.ExitError
		if errors.As(waitErr, &exit) {
			return t.end(OutcomeInstallFailed, ReasonInstallExit, fmt.Sprintf("the install command exited %d", *t.report.Install.ExitCode)), false
		}
		return t.end(OutcomeInstallFailed, ReasonInstallExit, "the install command's output could not be collected: "+waitErr.Error()), false
	}
	return BindReport{}, true
}

// sealDescriptors marks every inherited descriptor above stderr close-on-exec,
// so that the child, which gets the environment it is given and nothing else,
// does not keep the project lock (or anything else of the caller's) open.
func sealDescriptors() {
	for fd := 3; fd < 1024; fd++ {
		syscall.CloseOnExec(fd)
	}
}

// removeTree removes a directory tree without following a link, making
// read-only directories writable when it must.
func removeTree(dir string) error {
	if err := os.RemoveAll(dir); err == nil {
		return nil
	}
	_ = filepath.WalkDir(dir, func(name string, entry os.DirEntry, err error) error {
		if entry != nil && entry.IsDir() {
			_ = os.Chmod(name, 0o700)
		}
		return nil
	})
	return os.RemoveAll(dir)
}

// --- publication -----------------------------------------------------------

type journalFile struct {
	Rel    string `json:"rel"`
	Tmp    string `json:"tmp"`
	Backup string `json:"backup"`
	Judged string `json:"judged"`
	Old    string `json:"old"`
}

type journal struct {
	Version int           `json:"version"`
	HadOld  bool          `json:"had_old_tree"`
	Files   []journalFile `json:"files"`
}

func (t *transaction) publish() BindReport {
	scratch := filepath.Join(t.staging, scratchDir)

	// 7a. Re-check, then prepare every replacement file. Still interruptible,
	// and still nothing in the project has been touched.
	if reason, detail := t.checkTreeRoot(); reason != "" {
		return t.end(OutcomeInputsChanged, ReasonInputsChanged, "before publication: "+detail)
	}
	changes, unsafe := t.liveChanges()
	if unsafe != "" {
		return t.end(OutcomeInputsChanged, ReasonInputsChanged, "before publication: "+unsafe)
	}
	if len(changes) > 0 {
		t.report.Changed = changes
		return t.end(OutcomeInputsChanged, ReasonInputsChanged, "a project input changed since it was judged; nothing was published")
	}
	if info, err := os.Lstat(filepath.Join(t.staging, "node_modules")); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return t.end(OutcomeVerificationFailed, ReasonVerification, "the staged tree is gone")
	}
	if err := os.Mkdir(scratch, 0o700); err != nil {
		return t.end(OutcomeRefused, ReasonStagingFailed, err.Error())
	}
	plan := journal{Version: 1}
	if info, err := os.Lstat(t.abs("node_modules")); err == nil && info.IsDir() {
		plan.HadOld = true
	}
	for i, file := range t.req.Publish {
		entry := journalFile{
			Rel: file.Rel, Tmp: fmt.Sprintf("new-%d", i), Backup: fmt.Sprintf("bak-%d", i),
			Judged: digestOf(file.Content), Old: t.req.Live[file.Rel],
		}
		mode := os.FileMode(0o644)
		if entry.Old != "absent" {
			info, err := os.Lstat(t.abs(file.Rel))
			if err != nil || !info.Mode().IsRegular() {
				return t.end(OutcomeInputsChanged, ReasonInputsChanged, file.Rel+" is no longer a regular file")
			}
			mode = info.Mode().Perm()
		}
		parent, err := os.Lstat(filepath.Dir(t.abs(file.Rel)))
		if err != nil || !parent.IsDir() || devOf(parent) != t.projDev {
			return t.end(OutcomeRefused, ReasonInputUnsafe, file.Rel+" is not on the project's filesystem")
		}
		if err := writeFileMode(filepath.Join(scratch, entry.Tmp), file.Content, mode); err != nil {
			return t.end(OutcomeRefused, ReasonStagingFailed, err.Error())
		}
		plan.Files = append(plan.Files, entry)
	}
	if err := hook("publish:prepared"); err != nil {
		return t.hookFailure(err)
	}
	if t.ctx.Err() != nil {
		return t.interrupted()
	}
	// The last look before anything moves.
	if report, ok := t.recheck("before publication"); !ok {
		return report
	}

	// From here on a signal is deferred until the commit.
	if err := writeJournal(scratch, plan); err != nil {
		_ = os.Remove(filepath.Join(scratch, journalName))
		return t.end(OutcomeRefused, ReasonStagingFailed, "the publication journal could not be written: "+err.Error())
	}
	fail := func(outcome, reason string, err error) BindReport {
		if errors.Is(err, errCrash) {
			t.crashed = true
			return t.end(OutcomePublicationFailed, ReasonPublication, "simulated crash")
		}
		rollback := rollbackPublication(t.project, t.staging, plan)
		t.report.Publication.Conflicts = rollback.conflicts
		if rollback.complete {
			t.report.Publication.State = PublicationRolledBack
		} else {
			t.report.Publication.State = PublicationIncomplete
			t.keep = true
		}
		if len(rollback.conflicts) > 0 && outcome == OutcomePublicationFailed {
			// A file changed under us: report it as the change it is.
			outcome, reason = OutcomeInputsChanged, ReasonInputsChanged
		}
		detail := err.Error()
		if !rollback.complete {
			detail += "; the old tree could not be put back and is kept in " + t.staging
		}
		return t.end(outcome, reason, detail)
	}

	if err := hook("publish:journaled"); err != nil {
		return fail(OutcomePublicationFailed, ReasonPublication, err)
	}
	if plan.HadOld {
		if err := os.Rename(t.abs("node_modules"), filepath.Join(scratch, oldTreeName)); err != nil {
			return fail(OutcomePublicationFailed, ReasonPublication, fmt.Errorf("moving the old tree aside: %w", err))
		}
	}
	if err := hook("publish:tree_aside"); err != nil {
		return fail(OutcomePublicationFailed, ReasonPublication, err)
	}
	if err := os.Rename(filepath.Join(t.staging, "node_modules"), t.abs("node_modules")); err != nil {
		return fail(OutcomePublicationFailed, ReasonPublication, fmt.Errorf("moving the staged tree in: %w", err))
	}
	if err := hook("publish:tree_in"); err != nil {
		return fail(OutcomePublicationFailed, ReasonPublication, err)
	}
	for i, file := range plan.Files {
		dst := t.abs(file.Rel)
		if file.Old != "absent" {
			// Keep the old file as it is now, and check that is what was
			// judged: an edit that landed since the last check survives.
			backup := filepath.Join(scratch, file.Backup)
			if info, err := os.Lstat(dst); err != nil || !info.Mode().IsRegular() {
				return fail(OutcomeInputsChanged, ReasonInputsChanged, fmt.Errorf("%s changed during publication", file.Rel))
			}
			if err := os.Link(dst, backup); err != nil {
				return fail(OutcomePublicationFailed, ReasonPublication, fmt.Errorf("keeping the old %s: %w", file.Rel, err))
			}
			if got, problem := digestFile(backup); problem != "" || got != file.Old {
				t.report.Changed = append(t.report.Changed, InputChange{Path: file.Rel, Judged: file.Old, Found: got})
				return fail(OutcomeInputsChanged, ReasonInputsChanged, fmt.Errorf("%s changed during publication; the change was kept", file.Rel))
			}
		} else if exists(dst) {
			t.report.Changed = append(t.report.Changed, InputChange{Path: file.Rel, Judged: "absent", Found: "present"})
			return fail(OutcomeInputsChanged, ReasonInputsChanged, fmt.Errorf("%s appeared during publication; it was kept", file.Rel))
		}
		if err := os.Rename(filepath.Join(scratch, file.Tmp), dst); err != nil {
			return fail(OutcomePublicationFailed, ReasonPublication, fmt.Errorf("replacing %s: %w", file.Rel, err))
		}
		if err := hook(fmt.Sprintf("publish:file:%d", i)); err != nil {
			return fail(OutcomePublicationFailed, ReasonPublication, err)
		}
	}
	// The inputs that are not published (configuration, the competing
	// lockfile name) and the published ones are looked at once more with the
	// new tree in place: a change that landed since the last look is undone
	// with the rest, and survives.
	if changes, unsafe := t.liveChangesAfterPublication(plan); unsafe != "" || len(changes) > 0 {
		t.report.Changed = append(t.report.Changed, changes...)
		return fail(OutcomeInputsChanged, ReasonInputsChanged, errors.New("a project input changed during publication"+suffix(unsafe)))
	}
	// Commit: from here the project is final. Removing the journal is the
	// commit point; a leftover staging directory without one is plain garbage.
	if err := os.Remove(filepath.Join(scratch, journalName)); err != nil {
		return fail(OutcomePublicationFailed, ReasonPublication, fmt.Errorf("committing: %w", err))
	}
	syncDir(scratch)
	if err := hook("publish:committed"); err != nil {
		if errors.Is(err, errCrash) {
			t.crashed = true
		}
	}
	t.report.Publication.State = PublicationCommitted
	for _, file := range plan.Files {
		t.report.Publication.Published = append(t.report.Publication.Published, file.Rel)
	}
	t.report.Signal = signalOf(t.ctx)
	return t.end(OutcomePublished, "", "")
}

func suffix(text string) string {
	if text == "" {
		return ""
	}
	return ": " + text
}

// recheck is the look at the live state of the project that precedes
// publication: the tree root and every judged digest.
func (t *transaction) recheck(when string) (BindReport, bool) {
	if reason, detail := t.checkTreeRoot(); reason != "" {
		return t.end(OutcomeInputsChanged, ReasonInputsChanged, when+": "+detail), false
	}
	changes, unsafe := t.liveChanges()
	if unsafe != "" {
		return t.end(OutcomeInputsChanged, ReasonInputsChanged, when+": "+unsafe), false
	}
	if len(changes) > 0 {
		t.report.Changed = changes
		return t.end(OutcomeInputsChanged, ReasonInputsChanged, "a project input changed since it was judged; nothing was published"), false
	}
	return BindReport{}, true
}

// liveChangesAfterPublication compares every input that publication did not
// itself replace with its judged digest. (The replaced ones were checked one
// by one, against the backup of the old file, as they were replaced.)
func (t *transaction) liveChangesAfterPublication(plan journal) ([]InputChange, string) {
	replaced := map[string]bool{}
	for _, file := range plan.Files {
		replaced[file.Rel] = true
	}
	rels := make([]string, 0, len(t.req.Live))
	for rel := range t.req.Live {
		if !replaced[rel] {
			rels = append(rels, rel)
		}
	}
	sort.Strings(rels)
	var changes []InputChange
	for _, rel := range rels {
		found, problem := t.liveDigest(rel)
		if problem != "" {
			return nil, problem
		}
		if found != t.req.Live[rel] {
			changes = append(changes, InputChange{Path: rel, Judged: t.req.Live[rel], Found: found})
		}
	}
	return changes, ""
}

func digestFile(name string) (digest, problem string) {
	raw, err := readFileNoFollow(name, maxInputBytes)
	if err != nil {
		return "", err.Error()
	}
	return digestOf(raw), ""
}

func writeFileMode(name string, content []byte, mode os.FileMode) error {
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		file.Close()
		return err
	}
	// fchmod is not subject to the umask: the file keeps exactly the mode the
	// destination had.
	if err := file.Chmod(mode); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func writeJournal(scratch string, plan journal) error {
	raw, err := json.Marshal(plan)
	if err != nil {
		return err
	}
	if err := writeFileMode(filepath.Join(scratch, journalName), raw, 0o600); err != nil {
		return err
	}
	syncDir(scratch)
	return nil
}

func syncDir(dir string) {
	if handle, err := os.Open(dir); err == nil {
		_ = handle.Sync()
		handle.Close()
	}
}

type rollbackResult struct {
	// complete: the project's tree is as it was and staging can go.
	complete  bool
	conflicts []string
}

// rollbackPublication undoes a publication from what is on disk, and is safe
// to repeat. Files go back in reverse order, and only when they still hold
// what the transaction wrote: a file someone changed since is left as it is
// and reported. The tree goes back last of all.
func rollbackPublication(project, staging string, plan journal) rollbackResult {
	result := rollbackResult{complete: true, conflicts: []string{}}
	scratch := filepath.Join(staging, scratchDir)
	for i := len(plan.Files) - 1; i >= 0; i-- {
		file := plan.Files[i]
		dst := filepath.Join(project, filepath.FromSlash(file.Rel))
		if exists(filepath.Join(scratch, file.Tmp)) {
			continue // never renamed in
		}
		current, problem := digestOf(nil), ""
		if exists(dst) {
			current, problem = digestFile(dst)
		} else {
			current = "absent"
		}
		switch {
		case problem != "":
			result.conflicts = append(result.conflicts, file.Rel)
		case current == file.Old:
			// already as it was
		case current == file.Judged:
			if file.Old == "absent" {
				if err := os.Remove(dst); err != nil {
					result.conflicts = append(result.conflicts, file.Rel)
				}
			} else if err := os.Rename(filepath.Join(scratch, file.Backup), dst); err != nil {
				result.conflicts = append(result.conflicts, file.Rel)
			}
		default:
			result.conflicts = append(result.conflicts, file.Rel)
		}
	}
	nm := filepath.Join(project, "node_modules")
	staged := filepath.Join(staging, "node_modules")
	old := filepath.Join(scratch, oldTreeName)
	if !exists(staged) && exists(nm) {
		// The staged tree was moved in: take it out again.
		if err := os.Rename(nm, staged); err != nil {
			result.complete = false
			return result
		}
	}
	if exists(old) {
		if exists(nm) {
			result.complete = false
			return result
		}
		if err := os.Rename(old, nm); err != nil {
			result.complete = false
		}
	}
	return result
}

// --- recovery --------------------------------------------------------------

// recover reads the staging directories a killed run left in the project and
// undoes them, under the lock. A directory without a journal never reached
// publication (or committed): it is garbage and is removed. One with a journal
// was interrupted inside publication: it is rolled back, so the project is as
// it was before that run. A directory that cannot be dealt with is reported
// and stops this run (the old tree may be inside it).
func (t *transaction) recover() (BindReport, bool) {
	t.report.Recovery = Recover(t.project)
	if len(t.report.Recovery.Left) > 0 {
		return t.refuse(ReasonRecoveryIncomplete, "an earlier run's staging directory could not be undone: %s", t.report.Recovery.Left[0]), false
	}
	return BindReport{}, true
}

// Recover undoes the staging directories of earlier runs in a project. The
// caller must hold the project lock.
func Recover(project string) RecoveryReport {
	report := RecoveryReport{Conflict: []string{}, Left: []string{}}
	items, err := os.ReadDir(project)
	if err != nil {
		report.Left = append(report.Left, project)
		return report
	}
	for _, item := range items {
		if !strings.HasPrefix(item.Name(), stagingPrefix) {
			continue
		}
		dir := filepath.Join(project, item.Name())
		info, err := os.Lstat(dir)
		report.Found++
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !ownedByUs(info) {
			// Not ours to remove: never follow it, never delete it.
			report.Left = append(report.Left, dir)
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, scratchDir, journalName))
		if err == nil {
			var plan journal
			if json.Unmarshal(raw, &plan) != nil || plan.Version != 1 {
				report.Left = append(report.Left, dir)
				continue
			}
			result := rollbackPublication(project, dir, plan)
			report.Conflict = append(report.Conflict, result.conflicts...)
			if !result.complete {
				report.Left = append(report.Left, dir)
				continue
			}
			report.Undone++
		} else if !errors.Is(err, os.ErrNotExist) {
			report.Left = append(report.Left, dir)
			continue
		}
		if err := removeTree(dir); err != nil || exists(dir) {
			report.Left = append(report.Left, dir)
			continue
		}
		report.Removed++
	}
	sort.Strings(report.Conflict)
	return report
}
