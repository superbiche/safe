//go:build linux

package projectlane

import (
	"bytes"
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
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// The binding transaction (spec 1625, Binding): what the project lane judged is
// what lands in node_modules, or nothing does.
//
// THREAT MODEL. The content of a project (a cloned repository, its lockfile,
// anything committed or left in its directory) is untrusted input: nothing the
// transaction finds there may steer it. The install command is the admitted npm
// with scripts off and is TRUSTED as today's delegate is: it runs with the
// installing user's filesystem access, and nothing here confines what it writes
// (no sandbox); a same-user process that wants to bypass the gate can call npm
// directly. What the transaction guarantees is about the PROJECT: that what
// lands in it is what was judged and verified, and that it is left either as it
// was or as judged.
//
// The tree is built in a staging directory inside the project, private to the
// user, and published only once it has been verified against the judged
// lockfile. Every operation of the transaction itself is relative to descriptors
// held for the project (the caller's locked directory), the staging directory,
// the record directory and the live and staged trees, and no symbolic link is
// followed. The verifier is anchored on the held staged-tree descriptor and
// resolves each name below it with an Lstat per component (no link followed):
// it is not an openat chain.
//
// There is NO journal and NO replay. A leftover staging directory is removed by
// a later run only when safe's own state directory, outside the project, holds
// the record that this command created it for this project, with its identity;
// any other .safe-bind-* directory is left as it is and named in the document.
//
// ORDER OF THE STEPS and the state each interruption leaves (see also
// docs/architecture.md). The guarantee is about the PROCESS being interrupted or
// killed (a signal, SIGKILL, a crash of project-bind) with the filesystem
// running on: it is not a power-loss guarantee, for which the extracted tree,
// the state record and the directories touched by renames would need durability
// barriers this transaction does not implement.
//
//	 1  check the request, seal descriptors, take or prove the lock   nothing written
//	 2  remove recorded leftovers, name the others                    an earlier run's own staging only
//	 3  check the tree root (identity, mount) and every live
//	    input against its judged digest                               nothing written
//	 4  create staging, record it in the state directory, copy
//	    the judged inputs in, probe the atomic exchange               staging only
//	 5  run the install command in staging; once it has exited kill
//	    its process group and wait until the group is empty           staging only
//	 6  verify the staged tree against the judged lockfile            staging only
//	 7  publish: the record is marked kept; files first (each by
//	    atomic exchange, the displaced object inspected), then the
//	    tree (atomic exchange, the displaced tree's identity
//	    checked), then a last check of everything:
//	      7a  files 0..k-1 judged, k..n old; tree old or none         every file is the old or the judged bytes
//	      7b  all files judged; tree old or none                      the next lane command re-judges
//	      7c  all files judged; tree verified (old one in staging)    published
//	 8  mark the record not kept, remove staging
//
// Interrupted anywhere up to 7a, the project is byte for byte as it was. After
// the first exchange a kill leaves one of the 7a/7b/7c states: the tree in
// place is the old one, none (only when there was none), or the verified one,
// and each manifest or lockfile is either the old bytes or the judged bytes.
// Nothing is replayed. The staging directory of a run killed from 7 on is KEPT:
// its record says so, no later sweep removes it, and it is named in the next
// document, because it may hold an object displaced from the project (an
// editor's save) that nobody has inspected. A failure inside publication is
// undone in process, best effort, and the document says which state was left;
// undo and cleanup never delete an object they cannot identify.
//
// LIMITS stated here and in the document: a lockfile whose flags lie yields an
// incomplete tree, never a foreign or an extra package (absence is excused on
// the judged lockfile's own flags and on the platform, as npm does); the record
// of a staging directory is not defended against a writer running as the same
// user, nor against an inode reused under the same 128-bit random name.

const (
	stagingPrefix = ".safe-bind-"
	maxInputBytes = 256 << 20
)

// Assumptions the document states: what the transaction takes as given.
var Assumptions = []string{
	"install_command_trusted: the install command is the admitted npm with scripts off, trusted as the gate's delegate is; it runs with the installing user's filesystem access and its writes are not confined",
	"payload_integrity_rests_on_npm: the verifier attests the set of packages and their identities; npm checks each tarball against the lockfile's integrity hash",
	"project_content_untrusted: nothing found in the project steers the transaction; leftovers are removed only on safe's own record",
	"lockfile_flags_as_written: absence is excused on the judged lockfile's own optional, dev and peer flags and on the platform, as npm does; a lockfile whose flags lie yields an incomplete tree, never a foreign or an extra package",
	"record_not_defended_against_same_user: the staging record is not defended against a writer running as the same user, nor against an inode reused under the same random name",
	"process_interruption_not_power_loss: the interruption guarantees concern a process that is interrupted or killed, not power loss",
}

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
	// StateDir is safe's own state directory, outside the project: where the
	// record of each staging directory this command creates is kept.
	StateDir string
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
	// FilesOnly publishes the judged files and nothing else: no install command,
	// no staged tree, no tree exchange (npm install --package-lock-only). Every
	// other check is the same: the lock, the live inputs against their judged
	// digests, the atomic exchange of each file with the displaced object
	// inspected, the last check of everything. Argv and Env must then be empty
	// and the tree root is not looked at: it is neither read nor touched.
	FilesOnly bool
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

// File and tree states a publication can leave.
const (
	PublicationNotStarted = "not_started"
	PublicationCommitted  = "committed"
	PublicationRolledBack = "rolled_back"
	// PublicationPartial: some of it could not be undone; Files and Tree say
	// what is where.
	PublicationPartial = "partial"

	StateOld      = "old"      // the bytes (or the tree) that were there before
	StateJudged   = "judged"   // the judged bytes
	StateVerified = "verified" // the tree that was verified
	StateNone     = "none"     // no tree
	StateChanged  = "changed"  // something else: a change made by someone, kept
)

// FileState is where one published file stands.
type FileState struct {
	Path  string `json:"path"`
	State string `json:"state"`
}

// PublicationReport says how far publication went and what it left.
type PublicationReport struct {
	State string      `json:"state"`
	Tree  string      `json:"tree"`
	Files []FileState `json:"files"`
	// Published lists the files replaced (only meaningful for "committed").
	Published []string `json:"published"`
	// Conflicts lists what an undo left alone because it had been changed
	// since the transaction wrote it.
	Conflicts []string `json:"conflicts"`
	// Retained lists the objects kept in the staging directory because the
	// transaction could not tell what they are or could not put them back:
	// what they are called, where they are and what was observed of them.
	Retained []RetainedObject `json:"retained"`
}

// RetainedObject is an object kept in staging that nothing deletes.
type RetainedObject struct {
	Name     string `json:"name"`
	Location string `json:"location"`
	Observed string `json:"observed"`
}

// StagingReport says whether the staging directory is gone.
type StagingReport struct {
	Removed bool `json:"removed"`
	// Path is the directory left behind (its name), "" when removed.
	Path string `json:"path"`
}

// LeftDirectory is a .safe-bind-* directory that was not removed, and why.
type LeftDirectory struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// RecoveryReport is what the run found of earlier runs' staging directories:
// those safe recorded creating for this project are removed, any other is left
// untouched and named.
type RecoveryReport struct {
	Found        int             `json:"found"`
	Removed      []string        `json:"removed"`
	Left         []LeftDirectory `json:"left"`
	StaleRecords int             `json:"stale_records"`
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
	Assumptions   []string          `json:"assumptions"`
	Install       InstallReport     `json:"install"`
	Verification  *TreeReport       `json:"verification"`
	Changed       []InputChange     `json:"inputs_changed"`
	Publication   PublicationReport `json:"publication"`
	Staging       StagingReport     `json:"staging"`
	Recovery      RecoveryReport    `json:"recovery"`
	// Signal is the signal that was received, "" if none. With outcome
	// "interrupted" it ended the run; with "published" it arrived during
	// publication and was deferred until the end of it.
	Signal string `json:"signal"`
}

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
	ctx      context.Context
	judged   map[string]File
	judgedL  []File // in request order, publish first
	lockfile []byte

	project      *dirHandle
	projectID    fileID
	projectMount string
	projectPath  string
	staging      *dirHandle
	stagingName  string
	stagingID    fileID
	records      *dirHandle    // the private record directory, held
	record       stagingRecord // what safe recorded for this staging directory
	recorded     bool
	initial      string     // "": not looked at yet; "absent" or "present": the live tree root at the start
	oldTree      *fileID    // the live tree root when the run started (initial == "present")
	liveTree     *dirHandle // held live tree root
	treeID       *fileID    // the staged tree, as verified
	stagedTree   *dirHandle // held staged tree
	noTree       bool       // nothing to publish: no old tree and the install selected none
	treeSwapped  bool       // the tree exchange or move succeeded (recorded the moment it did)

	filesOnly   bool // publish the files alone
	releaseLock func()
	crashed     bool
	keep        bool // keep staging (it holds something the undo could not put back)
}

func newReport(selection Selection) BindReport {
	return BindReport{
		SchemaVersion: BindSchema,
		Selection:     selection.normalized(),
		Assumptions:   append([]string{}, Assumptions...),
		Changed:       []InputChange{},
		Publication:   PublicationReport{State: PublicationNotStarted, Tree: StateOld, Files: []FileState{}, Published: []string{}, Conflicts: []string{}, Retained: []RetainedObject{}},
		Recovery:      RecoveryReport{Removed: []string{}, Left: []LeftDirectory{}},
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
	case OutcomeInstallUnsettled:
		return ExitInstallUnsettled
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
	t := &transaction{req: req, ctx: ctx, report: newReport(req.Selection), judged: map[string]File{}, filesOnly: req.FilesOnly}
	t.report.Project = req.Project
	report := t.run()
	if !t.crashed {
		t.finish(&report)
	}
	return report
}

// finish removes the staging directory (only the very directory this run holds,
// and never one that is kept), releases what it holds and reports what is left.
// It runs after every outcome but a simulated crash.
func (t *transaction) finish(report *BindReport) {
	report.Staging = StagingReport{Removed: true}
	if t.staging != nil {
		left := t.keep
		if !left {
			if info, err := t.project.lstat(t.stagingName); err != nil || !info.IsDir() || idOf(info) != t.stagingID {
				left = true // the name no longer refers to the directory this run holds
			} else if err := removeAllAt(t.project, t.stagingName, t.projectID, t.projectMount); err != nil {
				left = true
			}
		}
		if left {
			report.Staging = StagingReport{Removed: false, Path: t.stagingName}
		} else if t.records != nil && t.recorded {
			_ = t.records.remove(t.stagingName)
		}
		t.staging.Close()
	}
	for _, handle := range []*dirHandle{t.stagedTree, t.liveTree, t.records, t.project} {
		handle.Close()
	}
	if t.releaseLock != nil {
		t.releaseLock()
	}
}

func (t *transaction) refuse(reason, format string, args ...any) BindReport {
	return t.end(OutcomeRefused, reason, fmt.Sprintf(format, args...))
}

func (t *transaction) interrupted() BindReport {
	t.report.Signal = signalOf(t.ctx)
	return t.end(OutcomeInterrupted, ReasonSignal, "interrupted by "+t.report.Signal+"; the project is as it was")
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
	// Every inherited descriptor is close-on-exec before anything else is
	// opened or run; a descriptor table that cannot be read refuses.
	if err := sealDescriptors(); err != nil {
		return t.refuse(ReasonDescriptorsUnsealed, "%v", err)
	}
	if err := t.takeLock(); err != nil {
		return t.refuse(err.reason, "%s", err.detail)
	}
	if report, ok := t.sweep(); !ok {
		return report
	}
	if report, ok := t.checkProject(); !ok {
		return report
	}
	if report, ok := t.createStaging(); !ok {
		return report
	}
	if err := hook("staged"); err != nil {
		return t.hookFailure(err)
	}
	if t.ctx.Err() != nil {
		return t.interrupted()
	}
	if t.filesOnly {
		// No install command, no tree: publication of the judged files alone.
		return t.publish()
	}
	if report, ok := t.install(); !ok {
		return report
	}
	if err := hook("installed"); err != nil {
		return t.hookFailure(err)
	}
	if t.ctx.Err() != nil {
		return t.interrupted()
	}
	if report, ok := t.verify(); !ok {
		return report
	}
	if err := hook("verified"); err != nil {
		return t.hookFailure(err)
	}
	if t.ctx.Err() != nil {
		return t.interrupted()
	}
	return t.publish()
}

// --- admission ---------------------------------------------------------------

// admit checks the request in itself, before the filesystem is consulted.
func (t *transaction) admit() (BindReport, bool) {
	req := t.req
	if req.FilesOnly {
		if len(req.Argv) != 0 || len(req.Env) != 0 {
			return t.refuse(ReasonRequestInvalid, "a files-only publication runs no install command and takes no environment"), false
		}
	} else {
		if err := req.Selection.Validate(); err != nil {
			return t.refuse(ReasonRequestInvalid, "selection: %v", err), false
		}
		if len(req.Argv) == 0 || !filepath.IsAbs(req.Argv[0]) {
			return t.refuse(ReasonRequestInvalid, "the install command must be an absolute path"), false
		}
		if req.Env == nil {
			return t.refuse(ReasonRequestInvalid, "the install environment must be given"), false
		}
	}
	if !filepath.IsAbs(req.StateDir) {
		return t.refuse(ReasonStateDirInvalid, "the state directory must be an absolute path"), false
	}
	if renameat2Number == 0 {
		return t.refuse(ReasonPlatformUnsupported, "this architecture has no atomic exchange the transaction knows"), false
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
			t.judgedL = append(t.judgedL, file)
		}
	}
	for _, file := range req.Publish {
		if base := path.Base(file.Rel); base != "package.json" && file.Rel != "package-lock.json" {
			return t.refuse(ReasonRequestInvalid, "%q is neither a manifest nor the lockfile", file.Rel), false
		}
	}
	if !containsFile(req.Publish, "package-lock.json") || !containsFile(req.Publish, "package.json") {
		return t.refuse(ReasonRequestInvalid, "the root package.json and package-lock.json must be published"), false
	}
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
	t.lockfile = t.judged["package-lock.json"].Content
	if reason, detail := AdmitLockfile(t.lockfile); reason != "" {
		return t.refuse(reason, "%s", detail), false
	}
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

func digestOf(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// --- the lock ----------------------------------------------------------------

type reasoned struct{ reason, detail string }

// lockContention tells a lock that is held by someone else (the answer a
// non-blocking flock gives) from an operation that is unsupported or failed:
// on a filesystem without working locks every attempt fails, and that must not
// read as another holder.
func lockContention(err error) bool {
	return errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN)
}

// takeLock proves, or takes, the exclusive kernel lock on the project
// directory and holds a descriptor on it for the whole transaction.
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
	t.projectPath = project
	t.report.Project = project

	if t.req.Lock.Take {
		handle, err := openDirPath(project)
		if err != nil {
			return &reasoned{ReasonProjectInvalid, err.Error()}
		}
		if err := syscall.Flock(handle.fd(), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			handle.Close()
			if lockContention(err) {
				return &reasoned{ReasonLockBusy, "another process holds the project lock"}
			}
			return &reasoned{ReasonLockFailed, "the lock operation failed (is locking supported on this filesystem?): " + err.Error()}
		}
		t.project = handle
		t.releaseLock = func() { _ = syscall.Flock(handle.fd(), syscall.LOCK_UN) }
	} else {
		if t.req.Lock.FD < 0 {
			return &reasoned{ReasonLockNotHeld, "no lock descriptor was given"}
		}
		// The descriptor stays the caller's: it is proved by number, and the
		// transaction works on a duplicate of it (the same open file
		// description, so the same lock, which is never released here).
		if reason := proveLock(project, t.req.Lock.FD); reason != "" {
			return &reasoned{ReasonLockNotHeld, reason}
		}
		handle, err := dupHandle(t.req.Lock.FD)
		if err != nil {
			return &reasoned{ReasonLockNotHeld, "the lock descriptor cannot be duplicated: " + err.Error()}
		}
		t.project = handle
	}
	id, err := t.project.id()
	if err != nil {
		return &reasoned{ReasonProjectInvalid, err.Error()}
	}
	mount, err := t.project.mountID()
	if err != nil {
		return &reasoned{ReasonProjectInvalid, "the project's mount cannot be read: " + err.Error()}
	}
	t.projectID, t.projectMount = id, mount
	return nil
}

// proveLock checks that fd, a descriptor this process inherited, is the
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
// and 3: this process then holds it for the whole transaction either way. A
// lock operation that fails for any reason but contention refuses.
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
	probe, err := openDirPath(project)
	if err != nil {
		return "the project directory cannot be opened: " + err.Error()
	}
	defer probe.Close()
	if err := syscall.Flock(probe.fd(), syscall.LOCK_SH|syscall.LOCK_NB); err == nil {
		_ = syscall.Flock(probe.fd(), syscall.LOCK_UN)
		return "no exclusive lock is held on the project directory"
	} else if !lockContention(err) {
		return "the lock state could not be read: " + err.Error()
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return "the exclusive lock on the project directory is held by another descriptor"
	}
	return ""
}

// --- state records and leftovers -------------------------------------------

// stagingRecord is safe's own record, kept outside the project, that this
// command created a staging directory for a project.
type stagingRecord struct {
	Schema     int    `json:"schema"`
	ProjectDev uint64 `json:"project_dev"`
	ProjectIno uint64 `json:"project_ino"`
	Name       string `json:"name"`
	Dev        uint64 `json:"dev"`
	Ino        uint64 `json:"ino"`
	// Kept says no sweep may remove this directory: it may hold an object
	// displaced from the project that nobody has inspected.
	Kept       bool   `json:"kept"`
	KeptReason string `json:"kept_reason"`
}

var recordName = regexp.MustCompile(`^\.safe-bind-[0-9a-f]{32}$`)

// checkPrivate requires a directory that belongs to the user and that group
// and others cannot write: the authority of what it holds depends on it.
func checkPrivate(handle *dirHandle, what string) error {
	info, err := handle.f.Stat()
	if err != nil {
		return err
	}
	if !ownedByUs(info) {
		return fmt.Errorf("%s is not owned by this user", what)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is writable by group or others", what)
	}
	return nil
}

// openPrivateChild opens (creating it, mode 0700) a directory below a held one
// without following a link, and checks it is private.
func openPrivateChild(parent *dirHandle, name, what string) (*dirHandle, error) {
	child, err := parent.openDirNoFollow(name)
	if errors.Is(err, os.ErrNotExist) {
		if err := parent.mkdir(name, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("%s cannot be created: %w", what, err)
		}
		child, err = parent.openDirNoFollow(name)
	}
	if err != nil {
		return nil, fmt.Errorf("%s cannot be opened without following a link: %w", what, err)
	}
	if err := checkPrivate(child, what); err != nil {
		child.Close()
		return nil, err
	}
	return child, nil
}

// openRecordDir opens safe's record directory for this project through held
// descriptors: the state directory, its project-bind directory and the
// per-project directory below it must each belong to the user and not be
// writable by group or others, and none may be a link.
func (t *transaction) openRecordDir() (*dirHandle, error) {
	state, err := filepath.EvalSymlinks(t.req.StateDir)
	if err != nil {
		return nil, err
	}
	root, err := openDirPath(state)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if err := checkPrivate(root, "the state directory"); err != nil {
		return nil, err
	}
	sub, err := openPrivateChild(root, "project-bind", "the record directory")
	if err != nil {
		return nil, err
	}
	defer sub.Close()
	return openPrivateChild(sub, fmt.Sprintf("%x-%x", t.projectID.dev, t.projectID.ino), "this project's record directory")
}

// checkStateDir refuses a state directory that overlaps the project: inside it,
// or holding it.
func (t *transaction) checkStateDir() error {
	state, err := filepath.EvalSymlinks(t.req.StateDir)
	if err != nil {
		return err
	}
	inside := func(base, target string) bool {
		rel, err := filepath.Rel(base, target)
		return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
	}
	if inside(t.projectPath, state) {
		return errors.New("the state directory is inside the project")
	}
	if inside(state, t.projectPath) {
		return errors.New("the project is inside the state directory")
	}
	return nil
}

// sweep removes the staging directories earlier runs of this command left in
// the project, on safe's record alone, and names the others. Nothing found in
// the project is read to decide anything: a name, a journal or a file there
// proves nothing.
func (t *transaction) sweep() (BindReport, bool) {
	if err := t.checkStateDir(); err != nil {
		return t.refuse(ReasonStateDirInvalid, "%v", err), false
	}
	records, err := t.openRecordDir()
	if err != nil {
		return t.refuse(ReasonStateDirInvalid, "%v", err), false
	}
	t.records = records
	names, err := t.project.names()
	if err != nil {
		return t.refuse(ReasonProjectInvalid, "%v", err), false
	}
	present := map[string]bool{}
	for _, name := range names {
		if !strings.HasPrefix(name, stagingPrefix) {
			continue
		}
		present[name] = true
		t.report.Recovery.Found++
		if reason := t.removeRecorded(name); reason != "" {
			t.report.Recovery.Left = append(t.report.Recovery.Left, LeftDirectory{Name: name, Reason: reason})
		} else {
			t.report.Recovery.Removed = append(t.report.Recovery.Removed, name)
		}
	}
	// Prune the records of directories that are gone. Only a record that
	// validates is touched: right name, a regular file of ours, this project's
	// identity; anything else in the record directory is left alone.
	if listed, err := t.records.names(); err == nil {
		for _, name := range listed {
			if !recordName.MatchString(name) || present[name] {
				continue
			}
			if _, ok := t.readRecord(name); ok && t.project.hasNo(name) {
				if t.records.remove(name) == nil {
					t.report.Recovery.StaleRecords++
				}
			}
		}
	}
	sort.Strings(t.report.Recovery.Removed)
	sort.Slice(t.report.Recovery.Left, func(i, j int) bool { return t.report.Recovery.Left[i].Name < t.report.Recovery.Left[j].Name })
	return BindReport{}, true
}

// readRecord reads and validates one record of this project: a regular file of
// ours, strict JSON of the schema, this project's identity, the name it is
// filed under.
func (t *transaction) readRecord(name string) (stagingRecord, bool) {
	var record stagingRecord
	info, err := t.records.lstat(name)
	if err != nil || !info.Mode().IsRegular() || !ownedByUs(info) {
		return record, false
	}
	raw, _, err := t.records.readRegular(name, 1<<16)
	if err != nil {
		return record, false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil || decoder.More() || record.Schema != 1 || record.Name != name ||
		record.ProjectDev != t.projectID.dev || record.ProjectIno != t.projectID.ino {
		return stagingRecord{}, false
	}
	return record, true
}

// removeRecorded removes one staging directory if, and only if, safe's record
// says this command created it for this project, the record does not say it is
// kept, and the directory is the very object recorded. It returns why it did
// not.
func (t *transaction) removeRecorded(name string) string {
	if !recordName.MatchString(name) {
		return "safe has no record of creating it for this project"
	}
	if _, err := t.records.lstat(name); err != nil {
		return "safe has no record of creating it for this project"
	}
	record, ok := t.readRecord(name)
	if !ok {
		return "the record is not valid for this project and name"
	}
	if record.Kept {
		return "kept: " + record.KeptReason
	}
	info, err := t.project.lstat(name)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "it is not a directory"
	}
	if id := idOf(info); id.dev != record.Dev || id.ino != record.Ino {
		return "it is not the directory that was recorded (identity differs)"
	}
	if !ownedByUs(info) {
		return "it is not owned by this user"
	}
	if err := removeAllAt(t.project, name, t.projectID, t.projectMount); err != nil {
		return "removal stopped: " + err.Error()
	}
	_ = t.records.remove(name)
	return ""
}

// writeRecord writes this run's record through the held record directory:
// a temporary file, then a rename over the name.
func (t *transaction) writeRecord(record stagingRecord) error {
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	temp := record.Name + ".tmp"
	_ = t.records.remove(temp)
	if _, err := t.records.createExclusive(temp, raw, 0o600); err != nil {
		return err
	}
	if err := syscall.Renameat(t.records.fd(), temp, t.records.fd(), record.Name); err != nil {
		_ = t.records.remove(temp)
		return err
	}
	_ = t.records.f.Sync()
	t.record, t.recorded = record, true
	return nil
}

// markKept rewrites this run's record so that no sweep removes the directory;
// clearKept undoes it. Publication marks it before the first exchange and
// clears it only when the run ends with nothing in staging that matters.
func (t *transaction) markKept(reason string) error {
	record := t.record
	record.Kept, record.KeptReason = true, reason
	return t.writeRecord(record)
}

func (t *transaction) clearKept() error {
	record := t.record
	record.Kept, record.KeptReason = false, ""
	return t.writeRecord(record)
}

func ownedByUs(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Geteuid()
}

// --- the project ---------------------------------------------------------------

// checkProject checks the tree root and the live inputs before anything runs.
func (t *transaction) checkProject() (BindReport, bool) {
	if t.filesOnly {
		t.report.Publication.Tree = StateOld
	} else if reason, detail := t.checkTreeRoot(); reason != "" {
		return t.refuse(reason, "%s", detail), false
	}
	changes, unsafe := t.liveChanges(nil)
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
	info, err := t.project.lstat("node_modules")
	switch {
	case errors.Is(err, os.ErrNotExist):
		if t.initial == "present" {
			return ReasonTreeRootInvalid, "the tree root that was there at the start is gone"
		}
		t.initial = "absent"
		return "", ""
	case err != nil:
		return ReasonTreeRootInvalid, "the tree root cannot be read: " + err.Error()
	case info.Mode()&os.ModeSymlink != 0:
		return ReasonTreeRootSymlink, "node_modules is a symbolic link; nothing was run and nothing behind the link was touched"
	case !info.IsDir():
		return ReasonTreeRootInvalid, "node_modules is not a directory"
	}
	if t.initial == "absent" {
		return ReasonTreeRootInvalid, "a tree root appeared during the run; it is left exactly as it is"
	}
	id := idOf(info)
	if t.liveTree != nil {
		// The held handle is the object: the name must still refer to it.
		if held, err := t.liveTree.id(); err != nil || id != held {
			return ReasonTreeRootInvalid, "the tree root is not the one that was there at the start (replaced)"
		}
		return "", ""
	}
	if id.dev != t.projectID.dev {
		return ReasonTreeRootInvalid, "node_modules is a mount point of another device and cannot be moved aside"
	}
	handle, err := t.project.openDirNoFollow("node_modules")
	if err != nil {
		return ReasonTreeRootInvalid, "the tree root cannot be opened: " + err.Error()
	}
	if mount, err := handle.mountID(); err != nil || mount != t.projectMount {
		handle.Close()
		return ReasonTreeRootInvalid, "node_modules is on another mount than the project and cannot be moved aside"
	}
	if now, err := handle.id(); err != nil || now != id {
		handle.Close()
		return ReasonTreeRootInvalid, "node_modules was replaced while it was checked"
	}
	t.liveTree, t.oldTree, t.initial = handle, &id, "present"
	return "", ""
}

// liveChanges compares the live inputs with the judged digests (all of them
// unless skip names some). unsafe is set for an input that is a link, a special
// file, has set-id or sticky bits, or sits below a link: that is a refusal, not
// a change.
func (t *transaction) liveChanges(skip map[string]bool) (changes []InputChange, unsafe string) {
	rels := make([]string, 0, len(t.req.Live))
	for rel := range t.req.Live {
		if !skip[rel] {
			rels = append(rels, rel)
		}
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

func splitRel(rel string) (parent, base string) {
	dir, base := path.Split(rel)
	return strings.TrimSuffix(dir, "/"), base
}

// liveDigest digests one live input without following a link anywhere on its
// path, relative to the held project directory. A problem names an input that
// cannot be a destination.
func (t *transaction) liveDigest(rel string) (digest, problem string) {
	parent, base := splitRel(rel)
	dir, err := t.project.walk(parent)
	if errors.Is(err, os.ErrNotExist) {
		return "absent", ""
	}
	if err != nil {
		return "", fmt.Sprintf("%s: a parent is a symbolic link or not a directory", rel)
	}
	defer dir.Close()
	info, err := dir.lstat(base)
	if errors.Is(err, os.ErrNotExist) {
		return "absent", ""
	}
	if err != nil {
		return "", fmt.Sprintf("%s: %v", rel, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Sprintf("%s is a symbolic link or not a regular file", rel)
	}
	if info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return "", fmt.Sprintf("%s has set-id or sticky mode bits", rel)
	}
	raw, _, err := dir.readRegular(base, maxInputBytes)
	if err != nil {
		return "", fmt.Sprintf("%s: %v", rel, err)
	}
	return digestOf(raw), ""
}

func randomName() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

// createStaging makes the private staging directory, records it in safe's
// state directory, copies the judged inputs in and checks that the atomic
// exchange publication needs works on this filesystem.
func (t *transaction) createStaging() (BindReport, bool) {
	fail := func(reason string, err error) (BindReport, bool) {
		return t.refuse(reason, "%v", err), false
	}
	for attempt := 0; attempt < 8 && t.staging == nil; attempt++ {
		name, err := randomName()
		if err != nil {
			return fail(ReasonStagingFailed, err)
		}
		name = stagingPrefix + name
		if err := t.project.mkdir(name, 0o700); err != nil {
			if errors.Is(err, os.ErrExist) {
				continue
			}
			return fail(ReasonStagingFailed, err)
		}
		handle, err := t.project.openDirNoFollow(name)
		if err != nil {
			return fail(ReasonStagingFailed, err)
		}
		t.staging, t.stagingName = handle, name
	}
	if t.staging == nil {
		return fail(ReasonStagingFailed, errors.New("no free staging name"))
	}
	if err := syscall.Fchmod(t.staging.fd(), 0o700); err != nil {
		return fail(ReasonStagingFailed, err)
	}
	id, err := t.staging.id()
	if err != nil {
		return fail(ReasonStagingFailed, err)
	}
	mount, err := t.staging.mountID()
	if err != nil || id.dev != t.projectID.dev || mount != t.projectMount {
		return fail(ReasonStagingFailed, errors.New("the staging directory is not on the project's mount"))
	}
	t.stagingID = id

	// safe's own record, outside the project.
	record := stagingRecord{Schema: 1, ProjectDev: t.projectID.dev, ProjectIno: t.projectID.ino, Name: t.stagingName, Dev: id.dev, Ino: id.ino}
	if err := t.writeRecord(record); err != nil {
		return fail(ReasonStateDirInvalid, fmt.Errorf("the staging record cannot be written: %w", err))
	}

	// The exchange publication relies on.
	if _, err := t.staging.createExclusive("probe-a", []byte("a"), 0); err != nil {
		return fail(ReasonStagingFailed, err)
	}
	if _, err := t.staging.createExclusive("probe-b", []byte("b"), 0); err != nil {
		return fail(ReasonStagingFailed, err)
	}
	if err := exchange(t.staging, "probe-a", t.staging, "probe-b"); err != nil {
		return fail(ReasonPlatformUnsupported, fmt.Errorf("the filesystem does not support an atomic exchange: %w", err))
	}
	for _, probe := range []string{"probe-a", "probe-b"} {
		if err := t.staging.remove(probe); err != nil {
			return fail(ReasonStagingFailed, err)
		}
	}

	for _, file := range t.judgedL {
		parent, base := splitRel(file.Rel)
		dir, err := t.stagingParent(parent)
		if err != nil {
			return fail(ReasonStagingFailed, err)
		}
		_, err = dir.createExclusive(base, file.Content, 0o600)
		dir.Close()
		if err != nil {
			return fail(ReasonStagingFailed, err)
		}
	}
	return BindReport{}, true
}

// stagingParent opens (creating it) the directory of a staged input.
func (t *transaction) stagingParent(parent string) (*dirHandle, error) {
	current, err := t.staging.walk("")
	if err != nil {
		return nil, err
	}
	if parent == "" {
		return current, nil
	}
	for _, part := range strings.Split(parent, "/") {
		next, err := current.openDirNoFollow(part)
		if errors.Is(err, os.ErrNotExist) {
			if err := current.mkdir(part, 0o700); err != nil {
				current.Close()
				return nil, err
			}
			next, err = current.openDirNoFollow(part)
		}
		current.Close()
		if err != nil {
			return nil, err
		}
		current = next
	}
	return current, nil
}

// --- the install ---------------------------------------------------------------

// procFdDir is the descriptor table; a variable so a test can point it away.
var procFdDir = "/proc/self/fd"

// sealDescriptors marks every inherited descriptor above stderr close-on-exec,
// whatever its number, and checks that each call worked. The descriptor table
// is read, there is no fixed upper bound and no fallback: a table that cannot
// be read is an error, and so is a descriptor that cannot be marked. The child,
// which gets the environment it is given and nothing else, then keeps neither
// the project lock nor anything of the caller's.
func sealDescriptors() error {
	entries, err := os.ReadDir(procFdDir)
	if err != nil {
		return fmt.Errorf("the descriptor table cannot be read: %w", err)
	}
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil || fd <= 2 {
			continue
		}
		flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
		if errno == syscall.EBADF {
			continue // the descriptor of the directory listing itself
		}
		if errno != 0 {
			return fmt.Errorf("descriptor %d cannot be inspected: %w", fd, errno)
		}
		if flags&syscall.FD_CLOEXEC != 0 {
			continue
		}
		if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_SETFD, flags|syscall.FD_CLOEXEC); errno != 0 {
			return fmt.Errorf("descriptor %d cannot be made close-on-exec: %w", fd, errno)
		}
	}
	return nil
}

// settleGroup ends whatever is left of the install's process group once its
// leader has exited, and waits until the group is empty. Nothing else is looked
// for: a process that left the group is outside the stated assumption (the
// install command is trusted and runs no script). The group id is not reused
// while any member exists. An error means completion could not be established.
func settleGroup(pgid int) error {
	deadline := time.Now().Add(10 * time.Second)
	for {
		if err := syscall.Kill(-pgid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			return fmt.Errorf("the install's process group cannot be signalled: %w", err)
		}
		err := syscall.Kill(-pgid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("the install's process group cannot be inspected: %w", err)
		}
		if time.Now().After(deadline) {
			return errors.New("the install's process group is not empty after its leader exited")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// unsettled reports an install whose completion cannot be established. The
// staging directory is kept (something may still write into it), and the record
// says so.
func (t *transaction) unsettled(reason, detail string) BindReport {
	t.keep = true
	_ = t.markKept("the install's completion could not be established")
	return t.end(OutcomeInstallUnsettled, reason, detail)
}

// install runs the frozen install in staging, waits for it, then ends and waits
// for its process group. Its status is reported apart from the transaction's.
func (t *transaction) install() (BindReport, bool) {
	cmd := exec.Command(t.req.Argv[0], t.req.Argv[1:]...)
	cmd.Dir = t.staging.procPath("")
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

	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	var waitErr error
	select {
	case waitErr = <-exited:
	case <-t.ctx.Done():
		_ = syscall.Kill(-pgid, syscall.SIGTERM)
		select {
		case waitErr = <-exited:
		case <-time.After(3 * time.Second):
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
			select {
			case waitErr = <-exited:
			case <-time.After(10 * time.Second):
				// Stuck (uninterruptible I/O): do not hold the lock for ever.
				return t.unsettled(ReasonWaitTimeout, "the install command did not end after SIGKILL"), false
			}
		}
	}
	settled := settleGroup(pgid)
	if herr := hook("install:settle"); herr != nil {
		settled = herr // tests: completion that cannot be established
	}
	t.report.Install.DurationMS = time.Since(started).Milliseconds()

	if state := cmd.ProcessState; state != nil {
		if status, ok := state.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			t.report.Install.Signal = status.Signal().String()
		} else {
			code := state.ExitCode()
			t.report.Install.ExitCode = &code
		}
	}
	if settled != nil {
		// Also when a signal arrived: completion not established wins.
		return t.unsettled(ReasonGroupRemains, settled.Error()), false
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

// --- verification --------------------------------------------------------------

// verify checks the staged tree against the judged lockfile bytes (not a file
// the child could have touched), from the held tree directory, and keeps that
// handle: it is that object that is later moved in. When the install left no
// tree and the lockfile selects none, there is nothing to publish: with an old
// tree the old tree is replaced by an EMPTY node_modules directory, made here
// and verified like any other; with none, the result is no tree.
func (t *transaction) verify() (BindReport, bool) {
	if err := hook("verifying"); err != nil {
		return t.hookFailure(err), false
	}
	absent := false
	if handle, err := t.staging.openDirNoFollow("node_modules"); err == nil {
		t.stagedTree = handle
		if id, err := handle.id(); err == nil {
			t.treeID = &id
		}
	} else if errors.Is(err, os.ErrNotExist) {
		absent = true
	}
	var verification TreeReport
	var err error
	if t.stagedTree != nil {
		verification, err = VerifyHeldTree(t.lockfile, t.stagedTree.procPath(""), t.req.Selection)
	} else {
		verification, err = VerifyTree(t.lockfile, t.staging.procPath(""), t.req.Selection)
	}
	if err != nil {
		return t.end(OutcomeVerificationFailed, ReasonVerification, "the staged tree could not be verified: "+err.Error()), false
	}
	t.report.Verification = &verification
	if t.ctx.Err() != nil {
		// A signal during verification is honoured: never "verified, then
		// published" over an interrupted run.
		return t.interrupted(), false
	}
	if !verification.Ok {
		return t.end(OutcomeVerificationFailed, ReasonVerification,
			fmt.Sprintf("the staged tree is not the judged one (%d problems, first: %s at %s)",
				len(verification.Problems), verification.Problems[0].Problem, verification.Problems[0].Path)), false
	}
	if absent {
		// Verified with no tree: every entry is deselected, the selected tree is empty.
		if t.initial == "present" {
			if err := t.staging.mkdir("node_modules", 0o777); err != nil {
				return t.end(OutcomeVerificationFailed, ReasonVerification, "the empty tree cannot be made: "+err.Error()), false
			}
			handle, err := t.staging.openDirNoFollow("node_modules")
			if err != nil {
				return t.end(OutcomeVerificationFailed, ReasonVerification, "the empty tree cannot be opened: "+err.Error()), false
			}
			t.stagedTree = handle
			id, err := handle.id()
			if err != nil {
				return t.end(OutcomeVerificationFailed, ReasonVerification, err.Error()), false
			}
			t.treeID = &id
		} else {
			t.noTree = true
		}
	}
	if !t.stagedTreeIsVerified() {
		return t.end(OutcomeVerificationFailed, ReasonVerification, "the staged tree is not the object that was verified"), false
	}
	return BindReport{}, true
}

// stagedTreeIsVerified checks that the entry named node_modules in staging is
// still the very directory that was held and verified (or, when there is no
// tree to publish, that none appeared).
func (t *transaction) stagedTreeIsVerified() bool {
	if t.filesOnly {
		return true
	}
	info, err := t.staging.lstat("node_modules")
	if t.noTree {
		return errors.Is(err, os.ErrNotExist)
	}
	if err != nil || !info.IsDir() || t.treeID == nil || t.stagedTree == nil {
		return false
	}
	held, herr := t.stagedTree.id()
	return herr == nil && idOf(info) == *t.treeID && held == *t.treeID
}

// --- publication ---------------------------------------------------------------

// faultHook, when set by a test, is asked before every exchange or move of
// publication and undo and can make it fail. Tests only.
var faultHook func(op string) error

func fault(op string) error {
	if faultHook == nil {
		return nil
	}
	return faultHook(op)
}

func (t *transaction) xchg(label string, aDir *dirHandle, a string, bDir *dirHandle, b string) error {
	if err := fault("exchange:" + label); err != nil {
		return err
	}
	return exchange(aDir, a, bDir, b)
}

func (t *transaction) mv(label string, aDir *dirHandle, a string, bDir *dirHandle, b string) error {
	if err := fault("move:" + label); err != nil {
		return err
	}
	return moveNoReplace(aDir, a, bDir, b)
}

type plannedFile struct {
	rel, parent, base string
	tmp               string
	existing          bool
	old, judged       string
	perm              os.FileMode
	newID             fileID
	// exchanged is recorded the moment the exchange (or the creation) succeeds,
	// before anything is inspected; done once the displaced object has been
	// accepted. exchanged && !done is the uncertain case.
	exchanged, done bool
	state           string
}

// observe describes an object in staging for the document.
func (t *transaction) observe(name string) string {
	info, err := t.staging.lstat(name)
	if err != nil {
		return "cannot be inspected: " + err.Error()
	}
	text := fmt.Sprintf("%s, mode %o, device %d inode %d", info.Mode().Type().String(), info.Mode().Perm(), idOf(info).dev, idOf(info).ino)
	if info.Mode().IsRegular() {
		if raw, _, err := t.staging.readRegular(name, maxInputBytes); err == nil {
			text += ", " + digestOf(raw)
		}
	}
	return text
}

// retain keeps an object in staging that the transaction could not identify or
// could not put back: staging is not removed (the record already says kept).
func (t *transaction) retain(name, why string) {
	t.keep = true
	for _, object := range t.report.Publication.Retained {
		if object.Name == name {
			return
		}
	}
	t.report.Publication.Retained = append(t.report.Publication.Retained, RetainedObject{
		Name: name, Location: t.stagingName + "/" + name, Observed: why + "; " + t.observe(name)})
}

func (t *transaction) publish() BindReport {
	if t.initial == "absent" && !t.filesOnly {
		t.report.Publication.Tree = StateNone
	}
	// Prepare every replacement file in staging. Interruptible: nothing in the
	// project has been touched.
	var plan []*plannedFile
	for i, file := range t.req.Publish {
		parent, base := splitRel(file.Rel)
		entry := &plannedFile{rel: file.Rel, parent: parent, base: base, tmp: "new-" + strconv.Itoa(i),
			old: t.req.Live[file.Rel], judged: digestOf(file.Content), state: StateOld}
		entry.existing = entry.old != "absent"
		if entry.existing {
			dir, err := t.project.walk(parent)
			if err != nil {
				t.report.Changed = append(t.report.Changed, InputChange{Path: file.Rel, Judged: entry.old, Found: "unreachable"})
				return t.end(OutcomeInputsChanged, ReasonInputsChanged, file.Rel+": its directory is gone or is a link now")
			}
			info, err := dir.lstat(base)
			dir.Close()
			if err != nil || !info.Mode().IsRegular() {
				found := "not a regular file"
				if errors.Is(err, os.ErrNotExist) {
					found = "absent"
				}
				t.report.Changed = append(t.report.Changed, InputChange{Path: file.Rel, Judged: entry.old, Found: found})
				return t.end(OutcomeInputsChanged, ReasonInputsChanged, file.Rel+" is no longer a regular file")
			}
			entry.perm = info.Mode().Perm()
		}
		id, err := t.staging.createExclusive(entry.tmp, file.Content, entry.perm)
		if err != nil {
			return t.end(OutcomeRefused, ReasonStagingFailed, err.Error())
		}
		entry.newID = id
		plan = append(plan, entry)
		t.report.Publication.Files = append(t.report.Publication.Files, FileState{Path: file.Rel, State: StateOld})
	}
	if err := hook("publish:prepared"); err != nil {
		return t.hookFailure(err)
	}

	// The last pass over the live inputs, and the last look at the tree root.
	if t.filesOnly {
		// the tree root is not this command's: it is not looked at
	} else if reason, detail := t.checkTreeRoot(); reason != "" {
		return t.end(OutcomeInputsChanged, ReasonInputsChanged, "before publication: "+detail)
	}
	changes, unsafe := t.liveChanges(nil)
	if unsafe != "" {
		return t.end(OutcomeInputsChanged, ReasonInputsChanged, "before publication: "+unsafe)
	}
	if len(changes) > 0 {
		t.report.Changed = changes
		return t.end(OutcomeInputsChanged, ReasonInputsChanged, "a project input changed since it was judged; nothing was published")
	}
	if !t.stagedTreeIsVerified() {
		return t.end(OutcomeVerificationFailed, ReasonVerification, "the staged tree is not the object that was verified")
	}
	if err := hook("publish:digested"); err != nil {
		return t.hookFailure(err)
	}
	// A signal that arrived during that pass (it can be long) is honoured
	// here, before the first exchange; from the first exchange on, publication
	// is not interrupted.
	if t.ctx.Err() != nil {
		return t.interrupted()
	}
	// From the first exchange on the staging directory may hold an object
	// displaced from the project that nobody has inspected: mark it kept, so
	// that a run killed from here on leaves it for a person.
	if err := t.markKept("publication began: staging may hold objects displaced from the project"); err != nil {
		return t.end(OutcomeRefused, ReasonStateDirInvalid, "the staging record cannot be marked: "+err.Error())
	}

	failure := func(outcome, reason string, err error) BindReport {
		if errors.Is(err, errCrash) {
			t.crashed = true
			return t.end(OutcomePublicationFailed, ReasonPublication, "simulated crash")
		}
		complete := t.undo(plan)
		t.report.Publication.State = PublicationRolledBack
		if !complete || len(t.report.Publication.Conflicts) > 0 || len(t.report.Publication.Retained) > 0 {
			t.report.Publication.State = PublicationPartial
		}
		if !t.keep {
			if err := t.clearKept(); err != nil {
				t.keep = true
			}
		}
		if len(t.report.Changed) > 0 && outcome == OutcomePublicationFailed {
			outcome, reason = OutcomeInputsChanged, ReasonInputsChanged
		}
		return t.end(outcome, reason, err.Error())
	}

	// Files first, each by atomic exchange.
	for i, file := range plan {
		if err := hook(fmt.Sprintf("publish:file:%d:before", i)); err != nil {
			return failure(OutcomePublicationFailed, ReasonPublication, err)
		}
		if err := t.publishFile(file); err != nil {
			var changed *changedError
			if errors.As(err, &changed) {
				t.report.Changed = append(t.report.Changed, changed.change)
				return failure(OutcomeInputsChanged, ReasonInputsChanged, err)
			}
			return failure(OutcomePublicationFailed, ReasonPublication, err)
		}
		t.setFileState(file, StateJudged)
		if err := hook(fmt.Sprintf("publish:file:%d", i)); err != nil {
			return failure(OutcomePublicationFailed, ReasonPublication, err)
		}
	}
	// Then the tree.
	if err := hook("publish:tree:before"); err != nil {
		return failure(OutcomePublicationFailed, ReasonPublication, err)
	}
	if !t.stagedTreeIsVerified() {
		return failure(OutcomeVerificationFailed, ReasonVerification, errors.New("the staged tree is not the object that was verified"))
	}
	if err := t.publishTree(); err != nil {
		var changed *changedError
		if errors.As(err, &changed) {
			t.report.Changed = append(t.report.Changed, changed.change)
			return failure(OutcomeInputsChanged, ReasonInputsChanged, err)
		}
		return failure(OutcomePublicationFailed, ReasonPublication, err)
	}
	if !t.noTree && !t.filesOnly {
		t.report.Publication.Tree = StateVerified
	}
	if err := hook("publish:tree"); err != nil {
		return failure(OutcomePublicationFailed, ReasonPublication, err)
	}
	// The final check covers everything: what publication did not replace
	// (configuration, the competing lockfile name), what it did (each
	// published destination still holds the judged object), and the tree.
	if changes := t.finalCheck(plan); len(changes) > 0 {
		t.report.Changed = append(t.report.Changed, changes...)
		return failure(OutcomeInputsChanged, ReasonInputsChanged, errors.New("a project input changed during publication"))
	}
	if err := hook("publish:checked"); err != nil {
		return failure(OutcomePublicationFailed, ReasonPublication, err)
	}
	t.report.Publication.State = PublicationCommitted
	for _, file := range plan {
		t.report.Publication.Published = append(t.report.Publication.Published, file.rel)
	}
	if err := t.clearKept(); err != nil {
		t.keep = true // the record could not be cleared: staging stays, and says so
	}
	t.report.Signal = signalOf(t.ctx)
	return t.end(OutcomePublished, "", "")
}

func (t *transaction) setFileState(file *plannedFile, state string) {
	file.state = state
	for i := range t.report.Publication.Files {
		if t.report.Publication.Files[i].Path == file.rel {
			t.report.Publication.Files[i].State = state
		}
	}
}

// changedError is a change of a live input found during publication.
type changedError struct {
	change InputChange
	text   string
}

func (e *changedError) Error() string { return e.text }

// publishFile puts one judged file in place. An existing destination is
// exchanged with the prepared file atomically, the exchange is recorded the
// moment it succeeds, and the object that was displaced is inspected: anything
// but the judged-old bytes with the permission bits seen at preparation (an
// edit that landed since, an editor's atomic save, a chmod, a link, a special
// file) is exchanged back, and the transaction stops. A file that did not exist
// is created without replacing anything.
func (t *transaction) publishFile(file *plannedFile) error {
	dir, err := t.project.walk(file.parent)
	if err != nil {
		return &changedError{InputChange{Path: file.rel, Judged: file.old, Found: "unreachable"}, file.rel + ": its directory is gone or is a link now"}
	}
	defer dir.Close()
	if id, err := dir.id(); err != nil || id.dev != t.projectID.dev {
		return fmt.Errorf("%s: its directory is on another device", file.rel)
	}
	if !file.existing {
		if err := t.mv("create:"+file.rel, t.staging, file.tmp, dir, file.base); err != nil {
			if errors.Is(err, os.ErrExist) {
				return &changedError{InputChange{Path: file.rel, Judged: "absent", Found: "present"}, file.rel + " appeared during publication; it was kept"}
			}
			return fmt.Errorf("creating %s: %w", file.rel, err)
		}
		file.exchanged, file.done = true, true
		return nil
	}
	if err := t.xchg("file:"+file.rel, t.staging, file.tmp, dir, file.base); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &changedError{InputChange{Path: file.rel, Judged: file.old, Found: "absent"}, file.rel + " disappeared during publication"}
		}
		return fmt.Errorf("replacing %s: %w", file.rel, err)
	}
	file.exchanged = true // recorded before anything is looked at
	if err := hook(fmt.Sprintf("publish:file:%s:exchanged", file.tmp)); err != nil {
		return err
	}
	// What was displaced is now at staging/<tmp>.
	found, perm, problem := t.displaced(file.tmp)
	if problem == "" && found == file.old && perm == file.perm {
		file.done = true
		return nil
	}
	observed := found
	if problem != "" {
		observed = problem
	} else if perm != file.perm {
		observed = fmt.Sprintf("permission bits %o (seen at preparation: %o)", perm, file.perm)
	}
	if err := t.xchg("file:"+file.rel+":back", t.staging, file.tmp, dir, file.base); err != nil {
		// The displaced object (somebody's save) is in staging and the judged
		// file is in place: keep it, name it, stop.
		t.retain(file.tmp, "the object displaced from "+file.rel+" is not the judged one and could not be exchanged back ("+err.Error()+")")
		t.report.Changed = append(t.report.Changed, InputChange{Path: file.rel, Judged: file.old, Found: observed})
		return fmt.Errorf("%s changed during publication and the displaced object could not be put back: %w", file.rel, err)
	}
	file.exchanged = false
	return &changedError{InputChange{Path: file.rel, Judged: file.old, Found: observed}, file.rel + " changed during publication; the change was kept"}
}

// displaced inspects an object that publication displaced into staging: its
// bytes, its permission bits and whether it is a plain regular file.
func (t *transaction) displaced(name string) (digest string, perm os.FileMode, problem string) {
	info, err := t.staging.lstat(name)
	if err != nil {
		return "", 0, err.Error()
	}
	if !info.Mode().IsRegular() {
		return "", 0, "not a regular file"
	}
	if info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return "", 0, "set-id or sticky mode bits"
	}
	raw, _, err := t.staging.readRegular(name, maxInputBytes)
	if err != nil {
		return "", 0, err.Error()
	}
	return digestOf(raw), info.Mode().Perm(), ""
}

// displacedIs reports whether the object displaced into staging holds the
// bytes with this digest and these permission bits: an edit made in place to
// the file the transaction published keeps its identity and is told apart by
// its content.
func (t *transaction) displacedIs(name, digest string, perm os.FileMode) bool {
	found, got, problem := t.displaced(name)
	return problem == "" && found == digest && got == perm
}

// publishTree puts the verified tree in place in one atomic step: exchanged
// with the live tree (whose identity must be the one held since the start), or
// moved in without replacing when there was none. The step is recorded the
// moment it succeeds.
func (t *transaction) publishTree() error {
	if t.noTree || t.filesOnly {
		return nil // no old tree and none selected: nothing to put in place
	}
	if t.initial == "absent" {
		if err := t.mv("tree", t.staging, "node_modules", t.project, "node_modules"); err != nil {
			if errors.Is(err, os.ErrExist) {
				return &changedError{InputChange{Path: "node_modules", Judged: "absent", Found: "present"}, "a tree root appeared during publication; it was kept"}
			}
			return fmt.Errorf("moving the tree in: %w", err)
		}
		t.treeSwapped = true
		return nil
	}
	if err := t.xchg("tree", t.staging, "node_modules", t.project, "node_modules"); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &changedError{InputChange{Path: "node_modules", Judged: "directory", Found: "absent"}, "the tree root disappeared during publication"}
		}
		return fmt.Errorf("exchanging the tree: %w", err)
	}
	t.treeSwapped = true
	// What was displaced must be the old tree that was held since the start.
	info, err := t.staging.lstat("node_modules")
	if held, herr := t.liveTree.id(); err == nil && herr == nil && info.IsDir() && idOf(info) == held {
		return nil
	}
	if err := t.xchg("tree:back", t.staging, "node_modules", t.project, "node_modules"); err != nil {
		t.retain("node_modules", "the object displaced from the tree root is not the old tree and could not be exchanged back ("+err.Error()+")")
		return fmt.Errorf("the tree root was replaced during publication and could not be put back: %w", err)
	}
	t.treeSwapped = false
	return &changedError{InputChange{Path: "node_modules", Judged: "the tree checked at the start", Found: "another object"}, "the tree root was replaced during publication; it was kept"}
}

// finalCheck looks at everything once more with the new tree in place, reading
// each published file through one checked parent handle.
func (t *transaction) finalCheck(plan []*plannedFile) []InputChange {
	skip := map[string]bool{}
	for _, file := range plan {
		skip[file.rel] = true
	}
	changes, unsafe := t.liveChanges(skip)
	if unsafe != "" {
		changes = append(changes, InputChange{Path: unsafe, Judged: "a regular file", Found: "unsafe"})
	}
	for _, file := range plan {
		dir, err := t.project.walk(file.parent)
		if err != nil {
			changes = append(changes, InputChange{Path: file.rel, Judged: file.judged, Found: "unreachable"})
			continue
		}
		info, err := dir.lstat(file.base)
		switch {
		case err != nil || !info.Mode().IsRegular() || idOf(info) != file.newID:
			changes = append(changes, InputChange{Path: file.rel, Judged: file.judged, Found: "another object"})
		default:
			raw, _, rerr := dir.readRegular(file.base, maxInputBytes)
			if rerr != nil || digestOf(raw) != file.judged {
				changes = append(changes, InputChange{Path: file.rel, Judged: file.judged, Found: "other bytes"})
			}
		}
		dir.Close()
	}
	info, err := t.project.lstat("node_modules")
	switch {
	case t.filesOnly:
		// the tree root is not this command's
	case t.noTree:
		if !errors.Is(err, os.ErrNotExist) {
			changes = append(changes, InputChange{Path: "node_modules", Judged: "absent", Found: "present"})
		}
	case err != nil || !info.IsDir() || t.treeID == nil || idOf(info) != *t.treeID:
		changes = append(changes, InputChange{Path: "node_modules", Judged: "the verified tree", Found: "another object"})
	}
	return changes
}

// undo reverses what publication did, in reverse order, best effort, and
// records in the report where everything stands. It never deletes an object it
// cannot identify: every object it takes out of the project is inspected (its
// identity, its bytes and its permission bits) and, if it is not the one the
// transaction placed, is put back where it was; if that fails too, the object
// is retained in staging, named in the document, and staging is kept. It
// returns false when the old tree could not be put back.
func (t *transaction) undo(plan []*plannedFile) bool {
	complete := true
	pub := &t.report.Publication
	conflict := func(what string) { pub.Conflicts = append(pub.Conflicts, what) }

	if t.treeSwapped && !t.noTree {
		complete = t.undoTree(conflict) && complete
	}
	for i := len(plan) - 1; i >= 0; i-- {
		file := plan[i]
		if !file.exchanged {
			continue
		}
		dir, err := t.project.walk(file.parent)
		if err != nil {
			conflict(file.rel)
			t.setFileState(file, StateChanged)
			t.retainFile(file, "the directory of "+file.rel+" cannot be reached to undo it")
			continue
		}
		if !file.existing {
			t.undoCreated(file, dir, conflict)
		} else {
			t.undoExchanged(file, dir, conflict)
		}
		dir.Close()
	}
	return complete
}

// unretain forgets an object that turned out to be ours after all (a retry
// put everything back); staging is no longer kept for it.
func (t *transaction) unretain(name string) {
	kept := t.report.Publication.Retained[:0]
	for _, object := range t.report.Publication.Retained {
		if object.Name != name {
			kept = append(kept, object)
		}
	}
	t.report.Publication.Retained = kept
	if len(kept) == 0 {
		t.keep = false
	}
}

func (t *transaction) retainFile(file *plannedFile, why string) {
	if _, err := t.staging.lstat(file.tmp); err == nil {
		t.retain(file.tmp, why)
	}
}

// undoExchanged reverses the exchange of an existing file: exchange back, then
// look at what came out. The judged object comes back to staging; anything
// else is somebody's and goes straight back into the project.
func (t *transaction) undoExchanged(file *plannedFile, dir *dirHandle, conflict func(string)) {
	if err := t.xchg("file:"+file.rel+":undo", t.staging, file.tmp, dir, file.base); err != nil {
		conflict(file.rel)
		t.setFileState(file, StateJudged)
		if !file.done {
			t.setFileState(file, StateChanged)
		}
		t.retainFile(file, "the exchange of "+file.rel+" could not be reversed ("+err.Error()+"); staging holds the object displaced at publication")
		return
	}
	if !file.done {
		// The first exchange back failed earlier: what was displaced then is
		// the editor's object, and it is in place again now.
		t.unretain(file.tmp)
		t.setFileState(file, StateChanged)
		conflict(file.rel)
		return
	}
	if info, err := t.staging.lstat(file.tmp); err == nil && idOf(info) == file.newID && t.displacedIs(file.tmp, file.judged, file.perm) {
		t.setFileState(file, StateOld)
		return
	}
	// Not the object the transaction placed (an edit, an atomic save): put it back.
	conflict(file.rel)
	t.setFileState(file, StateChanged)
	if err := t.xchg("file:"+file.rel+":undo-again", t.staging, file.tmp, dir, file.base); err != nil {
		t.retainFile(file, "the object found at "+file.rel+" is not the judged one and could not be put back ("+err.Error()+")")
	}
}

// undoCreated reverses the creation of a file that did not exist: the file is
// MOVED to staging (never deleted), inspected, and moved back if it is not the
// object the transaction created.
func (t *transaction) undoCreated(file *plannedFile, dir *dirHandle, conflict func(string)) {
	undone := "undone-" + file.tmp
	if err := t.mv("create:"+file.rel+":undo", dir, file.base, t.staging, undone); err != nil {
		conflict(file.rel)
		t.setFileState(file, StateChanged)
		return // still in the project, untouched
	}
	if info, err := t.staging.lstat(undone); err == nil && idOf(info) == file.newID && t.displacedIs(undone, file.judged, 0) {
		t.setFileState(file, StateOld)
		return
	}
	conflict(file.rel)
	t.setFileState(file, StateChanged)
	if err := t.mv("create:"+file.rel+":undo-back", t.staging, undone, dir, file.base); err != nil {
		t.retain(undone, "the file found at "+file.rel+" is not the one the transaction created and could not be put back ("+err.Error()+")")
	}
}

// undoTree reverses the tree exchange or move, inspecting what comes out.
func (t *transaction) undoTree(conflict func(string)) bool {
	pub := &t.report.Publication
	if t.initial == "absent" {
		if err := t.mv("tree:undo", t.project, "node_modules", t.staging, "node_modules"); err != nil {
			conflict("node_modules")
			return false
		}
		if info, err := t.staging.lstat("node_modules"); err == nil && t.treeID != nil && info.IsDir() && idOf(info) == *t.treeID {
			pub.Tree = StateNone
			t.treeSwapped = false
			return true
		}
		conflict("node_modules")
		pub.Tree = StateChanged
		if err := t.mv("tree:undo-back", t.staging, "node_modules", t.project, "node_modules"); err != nil {
			t.retain("node_modules", "the object found at the tree root is not the verified tree and could not be put back ("+err.Error()+")")
			return false
		}
		return true
	}
	if err := t.xchg("tree:undo", t.staging, "node_modules", t.project, "node_modules"); err != nil {
		conflict("node_modules")
		t.retain("node_modules", "the old tree could not be put back ("+err.Error()+")")
		return false
	}
	t.treeSwapped = false
	if info, err := t.staging.lstat("node_modules"); err == nil && t.treeID != nil && info.IsDir() && idOf(info) == *t.treeID {
		pub.Tree = StateOld
		return true
	}
	// Not the verified tree: someone replaced it. Put it back, as it was.
	conflict("node_modules")
	pub.Tree = StateChanged
	t.treeSwapped = true
	if err := t.xchg("tree:undo-again", t.staging, "node_modules", t.project, "node_modules"); err != nil {
		t.retain("node_modules", "the object found at the tree root is not the verified tree and could not be put back ("+err.Error()+")")
		return false
	}
	return true
}
