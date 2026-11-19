//go:build linux

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
// lockfile. Everything is done relative to descriptors held for the project
// (the caller's locked directory), the staging directory and the tree, never by
// pathname, and no symbolic link is followed.
//
// There is NO journal and NO replay. A leftover staging directory is removed by
// a later run only when safe's own state directory, outside the project, holds
// the record that this command created it for this project, with its identity;
// any other .safe-bind-* directory is left as it is and named in the document.
//
// ORDER OF THE STEPS and the state each interruption leaves (see also
// docs/architecture.md):
//
//	 1  check the request, take or prove the lock                nothing written
//	 2  remove recorded leftovers, name the others                an earlier run's own staging only
//	 3  check the tree root (identity, mount) and every live
//	    input against its judged digest                           nothing written
//	 4  create staging, record it in the state directory, copy
//	    the judged inputs in, probe the atomic exchange           staging only
//	 5  run the install command in staging, wait for the whole
//	    tree of processes it started to be gone                   staging only
//	 6  verify the staged tree against the judged lockfile        staging only
//	 7  publish, files first (each by atomic exchange, the
//	    displaced object inspected), then the tree (by atomic
//	    exchange, the displaced tree's identity checked), then a
//	    last check of everything, then remove staging:
//	      7a  files 0..k-1 judged, k..n old; tree old or none     every file is the old or the judged bytes
//	      7b  all files judged; tree old or none                  the next lane command re-judges
//	      7c  all files judged; tree verified (old one in staging)  published; staging is garbage
//
// Interrupted anywhere up to 7a, the project is byte for byte as it was. After
// the first exchange a kill (SIGKILL, power) leaves one of the 7a/7b/7c states:
// the tree in place is the old one, none, or the verified one, never anything
// else, and each manifest or lockfile is either the old bytes or the judged
// bytes. Nothing is replayed: the next run removes the recorded staging
// directory (which holds only displaced old objects and the old tree) and the
// lane re-judges from what it finds. A signal received from the first exchange
// on is deferred until the end of publication. A failure inside publication is
// undone in process, best effort, and the document says which state was left.

const (
	stagingPrefix = ".safe-bind-"
	maxInputBytes = 256 << 20
)

// Assumptions the document states: what the transaction takes as given.
var Assumptions = []string{
	"install_command_trusted: the install command is the admitted npm with scripts off, trusted as the gate's delegate is; it runs with the installing user's filesystem access and its writes are not confined",
	"payload_integrity_rests_on_npm: the verifier attests the set of packages and their identities; npm checks each tarball against the lockfile's integrity hash",
	"project_content_untrusted: nothing found in the project steers the transaction; leftovers are removed only on safe's own record",
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
	recordFile   string
	oldTree      *fileID // the live tree root when the run started
	treeID       *fileID // the staged tree, as verified

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
		Publication:   PublicationReport{State: PublicationNotStarted, Tree: StateOld, Files: []FileState{}, Published: []string{}, Conflicts: []string{}},
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

// finish removes the staging directory, releases what it holds and reports
// what is left. It runs after every outcome but a simulated crash.
func (t *transaction) finish(report *BindReport) {
	report.Staging = StagingReport{Removed: true}
	if t.staging != nil {
		var err error
		if t.keep {
			err = errors.New("kept")
		} else {
			err = removeAllAt(t.project, t.stagingName, t.projectID, t.projectMount)
		}
		if err != nil {
			report.Staging = StagingReport{Removed: false, Path: t.stagingName}
		} else if t.recordFile != "" {
			_ = os.Remove(t.recordFile)
		}
		t.staging.Close()
	}
	if t.project != nil {
		t.project.Close()
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
	if err := req.Selection.Validate(); err != nil {
		return t.refuse(ReasonRequestInvalid, "selection: %v", err), false
	}
	if len(req.Argv) == 0 || !filepath.IsAbs(req.Argv[0]) {
		return t.refuse(ReasonRequestInvalid, "the install command must be an absolute path"), false
	}
	if req.Env == nil {
		return t.refuse(ReasonRequestInvalid, "the install environment must be given"), false
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
}

func (t *transaction) recordDir() string {
	return filepath.Join(t.req.StateDir, "project-bind", fmt.Sprintf("%x-%x", t.projectID.dev, t.projectID.ino))
}

// checkStateDir refuses a state directory that is, or is below, the project.
func (t *transaction) checkStateDir() error {
	state, err := filepath.EvalSymlinks(t.req.StateDir)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(t.projectPath, state)
	if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("the state directory is inside the project")
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
	reader, err := t.project.walk("")
	if err != nil {
		return t.refuse(ReasonProjectInvalid, "%v", err), false
	}
	defer reader.Close()
	// A fresh open file description: the lock descriptor's offset is shared
	// with its caller.
	fresh, err := syscall.Openat(reader.fd(), ".", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return t.refuse(ReasonProjectInvalid, "%v", err), false
	}
	listing := newHandle(fresh, "listing")
	defer listing.Close()
	entries, err := listing.f.ReadDir(-1)
	if err != nil {
		return t.refuse(ReasonProjectInvalid, "%v", err), false
	}
	present := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
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
	// Records of directories that are gone are dropped.
	if records, err := os.ReadDir(t.recordDir()); err == nil {
		for _, record := range records {
			if !present[record.Name()] {
				if os.Remove(filepath.Join(t.recordDir(), record.Name())) == nil {
					t.report.Recovery.StaleRecords++
				}
			}
		}
	}
	sort.Strings(t.report.Recovery.Removed)
	sort.Slice(t.report.Recovery.Left, func(i, j int) bool { return t.report.Recovery.Left[i].Name < t.report.Recovery.Left[j].Name })
	return BindReport{}, true
}

// removeRecorded removes one staging directory if, and only if, safe's record
// says this command created it for this project and the directory is the very
// object recorded. It returns why it did not.
func (t *transaction) removeRecorded(name string) string {
	recordPath := filepath.Join(t.recordDir(), name)
	raw, err := os.ReadFile(recordPath)
	if err != nil {
		return "safe has no record of creating it for this project"
	}
	var record stagingRecord
	if err := json.Unmarshal(raw, &record); err != nil || record.Schema != 1 || record.Name != name ||
		record.ProjectDev != t.projectID.dev || record.ProjectIno != t.projectID.ino {
		return "the record does not match this project and name"
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
	_ = os.Remove(recordPath)
	return ""
}

func ownedByUs(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Geteuid()
}

// --- the project ---------------------------------------------------------------

// checkProject checks the tree root and the live inputs before anything runs.
func (t *transaction) checkProject() (BindReport, bool) {
	if reason, detail := t.checkTreeRoot(); reason != "" {
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

// checkTreeRoot checks the live tree root: absent, or a real directory on the
// project's own mount. The first time it records the identity of what it
// found; later it requires that very object.
func (t *transaction) checkTreeRoot() (reason, detail string) {
	info, err := t.project.lstat("node_modules")
	switch {
	case errors.Is(err, os.ErrNotExist):
		if t.oldTree != nil {
			return ReasonTreeRootInvalid, "the tree root that was there at the start is gone"
		}
		return "", ""
	case err != nil:
		return ReasonTreeRootInvalid, "the tree root cannot be read: " + err.Error()
	case info.Mode()&os.ModeSymlink != 0:
		return ReasonTreeRootSymlink, "node_modules is a symbolic link; nothing was run and nothing behind the link was touched"
	case !info.IsDir():
		return ReasonTreeRootInvalid, "node_modules is not a directory"
	}
	id := idOf(info)
	if id.dev != t.projectID.dev {
		return ReasonTreeRootInvalid, "node_modules is a mount point of another device and cannot be moved aside"
	}
	handle, err := t.project.openDirNoFollow("node_modules")
	if err != nil {
		return ReasonTreeRootInvalid, "the tree root cannot be opened: " + err.Error()
	}
	defer handle.Close()
	if mount, err := handle.mountID(); err != nil || mount != t.projectMount {
		return ReasonTreeRootInvalid, "node_modules is on another mount than the project and cannot be moved aside"
	}
	if now, err := handle.id(); err != nil || now != id {
		return ReasonTreeRootInvalid, "node_modules was replaced while it was checked"
	}
	if t.oldTree == nil {
		t.oldTree = &id
	} else if *t.oldTree != id {
		return ReasonTreeRootInvalid, "the tree root is not the one that was there at the start (replaced)"
	}
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
	_ = syscall.Fchmod(t.staging.fd(), 0o700)
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
	_ = t.staging.remove("probe-a")
	_ = t.staging.remove("probe-b")

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

func (t *transaction) writeRecord(record stagingRecord) error {
	dir := t.recordDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	final := filepath.Join(dir, record.Name)
	temp := final + ".tmp"
	if err := os.WriteFile(temp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Rename(temp, final); err != nil {
		_ = os.Remove(temp)
		return err
	}
	t.recordFile = final
	return nil
}

// --- the install ---------------------------------------------------------------

// sealDescriptors marks every inherited descriptor above stderr close-on-exec,
// whatever its number (the descriptor table is read, there is no fixed upper
// bound), so that the child, which gets the environment it is given and
// nothing else, does not keep the project lock or anything of the caller's.
func sealDescriptors() {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		for fd := 3; fd < 1<<16; fd++ {
			syscall.CloseOnExec(fd)
		}
		return
	}
	for _, entry := range entries {
		if fd, err := strconv.Atoi(entry.Name()); err == nil && fd > 2 {
			syscall.CloseOnExec(fd)
		}
	}
}

// processTable reads the parent of every process.
func processTable() map[int]int {
	parents := map[int]int{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return parents
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		raw, err := os.ReadFile("/proc/" + entry.Name() + "/stat")
		if err != nil {
			continue
		}
		text := string(raw)
		end := strings.LastIndex(text, ")")
		if end < 0 {
			continue
		}
		fields := strings.Fields(text[end+1:])
		if len(fields) < 2 {
			continue
		}
		if ppid, err := strconv.Atoi(fields[1]); err == nil {
			parents[pid] = ppid
		}
	}
	return parents
}

// descendants lists the processes below this one, except the ones that were
// already children when the install started.
func descendants(except map[int]bool) []int {
	parents := processTable()
	children := map[int][]int{}
	for pid, parent := range parents {
		children[parent] = append(children[parent], pid)
	}
	var found []int
	queue := []int{os.Getpid()}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, child := range children[current] {
			if except[child] {
				continue
			}
			found = append(found, child)
			queue = append(queue, child)
		}
	}
	return found
}

// quiesce kills whatever the install left running below this process (its own
// process group and anything that left it: a daemon started with setsid, a
// double fork reparented to this process, which is made a subreaper for that)
// and waits until nothing is left, so that nothing writes into staging while
// it is verified and published.
func quiesce(pgid int, except map[int]bool) error {
	deadline := time.Now().Add(10 * time.Second)
	for {
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		found := descendants(except)
		for _, pid := range found {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			var status syscall.WaitStatus
			_, _ = syscall.Wait4(pid, &status, syscall.WNOHANG, nil)
		}
		if len(found) == 0 && errors.Is(syscall.Kill(-pgid, 0), syscall.ESRCH) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%d processes of the install command are still there", len(found))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

const prSetChildSubreaper = 36

// install runs the frozen install in staging and waits for it and for
// everything it started. Its status is reported apart from the transaction's.
func (t *transaction) install() (BindReport, bool) {
	sealDescriptors()
	_, _, _ = syscall.RawSyscall(syscall.SYS_PRCTL, prSetChildSubreaper, 1, 0)
	before := map[int]bool{}
	for _, pid := range descendants(nil) {
		before[pid] = true
	}

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
	quiesceErr := quiesce(pgid, before)
	t.report.Install.DurationMS = time.Since(started).Milliseconds()

	if state := cmd.ProcessState; state != nil {
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
	case quiesceErr != nil:
		return t.end(OutcomeInstallFailed, ReasonProcessesRemain, quiesceErr.Error()), false
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
// the child could have touched), through the held staging directory, and holds
// the identity of the tree that was verified: it is that object that is later
// moved in.
func (t *transaction) verify() (BindReport, bool) {
	if err := hook("verifying"); err != nil {
		return t.hookFailure(err), false
	}
	var tree *dirHandle
	if handle, err := t.staging.openDirNoFollow("node_modules"); err == nil {
		tree = handle
		defer tree.Close()
		if id, err := tree.id(); err == nil {
			t.treeID = &id
		}
	}
	verification, err := VerifyTree(t.lockfile, t.staging.procPath(""), t.req.Selection)
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
	if t.treeID == nil || !t.stagedTreeIsVerified() {
		return t.end(OutcomeVerificationFailed, ReasonVerification, "the staged tree is not the object that was verified"), false
	}
	return BindReport{}, true
}

// stagedTreeIsVerified checks that the entry named node_modules in staging is
// still the very directory that was opened and verified.
func (t *transaction) stagedTreeIsVerified() bool {
	info, err := t.staging.lstat("node_modules")
	return err == nil && info.IsDir() && t.treeID != nil && idOf(info) == *t.treeID
}

// --- publication ---------------------------------------------------------------

type plannedFile struct {
	rel, parent, base string
	tmp               string
	existing          bool
	old, judged       string
	perm              os.FileMode
	newID             fileID
	done              bool
	state             string
}

func (t *transaction) publish() BindReport {
	if t.oldTree == nil {
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
	if reason, detail := t.checkTreeRoot(); reason != "" {
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

	failure := func(outcome, reason string, err error) BindReport {
		if errors.Is(err, errCrash) {
			t.crashed = true
			return t.end(OutcomePublicationFailed, ReasonPublication, "simulated crash")
		}
		complete := t.undo(plan)
		t.report.Publication.State = PublicationRolledBack
		if !complete || len(t.report.Publication.Conflicts) > 0 {
			t.report.Publication.State = PublicationPartial
			t.keep = !complete
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
	t.report.Publication.Tree = StateVerified
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
// exchanged with the prepared file atomically, and the object that was
// displaced is inspected: anything but the bytes that were judged (an edit
// that landed since, an editor's atomic save, a link, a special file) is
// exchanged back, and the transaction stops. A file that did not exist is
// created without replacing anything.
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
		if err := moveNoReplace(t.staging, file.tmp, dir, file.base); err != nil {
			if errors.Is(err, os.ErrExist) {
				return &changedError{InputChange{Path: file.rel, Judged: "absent", Found: "present"}, file.rel + " appeared during publication; it was kept"}
			}
			return fmt.Errorf("creating %s: %w", file.rel, err)
		}
		file.done = true
		return nil
	}
	if err := exchange(t.staging, file.tmp, dir, file.base); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &changedError{InputChange{Path: file.rel, Judged: file.old, Found: "absent"}, file.rel + " disappeared during publication"}
		}
		return fmt.Errorf("replacing %s: %w", file.rel, err)
	}
	// What was displaced is now at staging/<tmp>.
	found, problem := t.displacedDigest(file.tmp)
	if problem == "" && found == file.old {
		file.done = true
		return nil
	}
	if err := exchange(t.staging, file.tmp, dir, file.base); err != nil {
		return fmt.Errorf("%s changed during publication and could not be put back: %w", file.rel, err)
	}
	if problem != "" {
		found = problem
	}
	return &changedError{InputChange{Path: file.rel, Judged: file.old, Found: found}, file.rel + " changed during publication; the change was kept"}
}

// displacedDigest inspects an object that publication displaced into staging.
func (t *transaction) displacedDigest(name string) (digest, problem string) {
	info, err := t.staging.lstat(name)
	if err != nil {
		return "", err.Error()
	}
	if !info.Mode().IsRegular() {
		return "", "not a regular file"
	}
	if info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return "", "set-id or sticky mode bits"
	}
	raw, _, err := t.staging.readRegular(name, maxInputBytes)
	if err != nil {
		return "", err.Error()
	}
	return digestOf(raw), ""
}

// displacedIs reports whether the object displaced into staging holds the
// bytes with this digest: an edit made in place to the file the transaction
// published keeps its identity and is told apart by its content.
func (t *transaction) displacedIs(name, digest string) bool {
	found, problem := t.displacedDigest(name)
	return problem == "" && found == digest
}

// publishTree puts the verified tree in place in one atomic step: exchanged
// with the live tree (whose identity must be the one checked at the start), or
// moved in without replacing when there was none.
func (t *transaction) publishTree() error {
	if t.oldTree == nil {
		if err := moveNoReplace(t.staging, "node_modules", t.project, "node_modules"); err != nil {
			if errors.Is(err, os.ErrExist) {
				return &changedError{InputChange{Path: "node_modules", Judged: "absent", Found: "present"}, "a tree root appeared during publication; it was kept"}
			}
			return fmt.Errorf("moving the tree in: %w", err)
		}
		return nil
	}
	if err := exchange(t.staging, "node_modules", t.project, "node_modules"); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &changedError{InputChange{Path: "node_modules", Judged: "directory", Found: "absent"}, "the tree root disappeared during publication"}
		}
		return fmt.Errorf("exchanging the tree: %w", err)
	}
	// What was displaced is the old tree, or it is not and goes back.
	info, err := t.staging.lstat("node_modules")
	if err == nil && info.IsDir() && idOf(info) == *t.oldTree {
		t.report.Publication.Tree = StateVerified
		return nil
	}
	if err := exchange(t.staging, "node_modules", t.project, "node_modules"); err != nil {
		return fmt.Errorf("the tree root was replaced during publication and could not be put back: %w", err)
	}
	return &changedError{InputChange{Path: "node_modules", Judged: "the tree checked at the start", Found: "another object"}, "the tree root was replaced during publication; it was kept"}
}

// finalCheck looks at everything once more with the new tree in place.
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
		dir.Close()
		if err != nil || !info.Mode().IsRegular() || idOf(info) != file.newID {
			changes = append(changes, InputChange{Path: file.rel, Judged: file.judged, Found: "another object"})
			continue
		}
		dir2, _ := t.project.walk(file.parent)
		raw, _, rerr := dir2.readRegular(file.base, maxInputBytes)
		dir2.Close()
		if rerr != nil || digestOf(raw) != file.judged {
			changes = append(changes, InputChange{Path: file.rel, Judged: file.judged, Found: "other bytes"})
		}
	}
	if info, err := t.project.lstat("node_modules"); err != nil || !info.IsDir() || t.treeID == nil || idOf(info) != *t.treeID {
		changes = append(changes, InputChange{Path: "node_modules", Judged: "the verified tree", Found: "another object"})
	}
	return changes
}

// undo reverses what publication did, in reverse order, best effort, and
// records in the report where everything stands. It returns false when the old
// tree could not be put back (staging is then kept: it holds it). Each step
// puts something back only if what is there is still the object the
// transaction placed; anything else is someone's change, is left as it is and
// reported as a conflict.
func (t *transaction) undo(plan []*plannedFile) bool {
	complete := true
	pub := &t.report.Publication
	conflict := func(what string) { pub.Conflicts = append(pub.Conflicts, what) }

	if pub.Tree == StateVerified {
		switch {
		case t.oldTree != nil:
			if err := exchange(t.staging, "node_modules", t.project, "node_modules"); err != nil {
				complete = false
				conflict("node_modules")
			} else if info, err := t.staging.lstat("node_modules"); err == nil && t.treeID != nil && idOf(info) == *t.treeID {
				pub.Tree = StateOld
			} else {
				_ = exchange(t.staging, "node_modules", t.project, "node_modules")
				pub.Tree = StateChanged
				conflict("node_modules")
			}
		default:
			if info, err := t.project.lstat("node_modules"); err == nil && t.treeID != nil && idOf(info) == *t.treeID {
				if moveNoReplace(t.project, "node_modules", t.staging, "node_modules") == nil {
					pub.Tree = StateNone
				} else {
					complete = false
					conflict("node_modules")
				}
			} else {
				pub.Tree = StateChanged
				conflict("node_modules")
			}
		}
	}
	for i := len(plan) - 1; i >= 0; i-- {
		file := plan[i]
		if !file.done {
			continue
		}
		dir, err := t.project.walk(file.parent)
		if err != nil {
			conflict(file.rel)
			t.setFileState(file, StateChanged)
			continue
		}
		if file.existing {
			if err := exchange(t.staging, file.tmp, dir, file.base); err != nil {
				conflict(file.rel)
				t.setFileState(file, StateChanged)
			} else if info, err := t.staging.lstat(file.tmp); err == nil && idOf(info) == file.newID && t.displacedIs(file.tmp, file.judged) {
				t.setFileState(file, StateOld)
			} else {
				_ = exchange(t.staging, file.tmp, dir, file.base)
				conflict(file.rel)
				t.setFileState(file, StateChanged)
			}
		} else if info, err := dir.lstat(file.base); err == nil && idOf(info) == file.newID {
			if moveNoReplace(dir, file.base, t.staging, "undone-"+file.tmp) == nil {
				t.setFileState(file, StateOld)
			} else {
				conflict(file.rel)
				t.setFileState(file, StateChanged)
			}
		} else {
			conflict(file.rel)
			t.setFileState(file, StateChanged)
		}
		dir.Close()
	}
	return complete
}
