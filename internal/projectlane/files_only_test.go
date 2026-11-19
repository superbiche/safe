//go:build linux

package projectlane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// filesOnly turns the fixture into a files-only publication (npm install
// --package-lock-only): no install command, no environment, no selection.
func (f *bindFx) filesOnly() {
	f.req.FilesOnly = true
	f.req.Argv, f.req.Env, f.req.Selection = nil, nil, Selection{}
}

func TestFilesOnlyPublishesTheJudgedFilesAndRunsNothing(t *testing.T) {
	f := newBindFx(t)
	f.filesOnly()
	treeBefore := snapshot(t, filepath.Join(f.project, "node_modules"))
	report := f.bind()
	wantOutcome(t, report, OutcomePublished, ExitPublished)
	if report.Install.Ran || report.Verification != nil || report.Publication.State != PublicationCommitted ||
		report.Publication.Tree != StateOld || !report.Staging.Removed {
		t.Fatalf("report = %+v", report)
	}
	noStaging(t, f.project)
	for rel, want := range map[string]string{"package.json": string(f.manifest), "package-lock.json": string(f.lockfile)} {
		raw, err := os.ReadFile(filepath.Join(f.project, rel))
		if err != nil || string(raw) != want {
			t.Fatalf("%s = %q, %v", rel, raw, err)
		}
	}
	info, _ := os.Lstat(filepath.Join(f.project, "package.json"))
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %v", info.Mode())
	}
	// the configuration is copied to staging only; the tree is not looked at
	if raw, _ := os.ReadFile(filepath.Join(f.project, ".npmrc")); string(raw) != "ignore-scripts=true\n" {
		t.Fatalf(".npmrc = %q", raw)
	}
	sameSnapshot(t, treeBefore, snapshot(t, filepath.Join(f.project, "node_modules")))
	if f.ran() {
		t.Fatal("a command ran")
	}
}

func TestFilesOnlyLeavesAMissingTreeMissing(t *testing.T) {
	f := newBindFx(t)
	if err := os.RemoveAll(filepath.Join(f.project, "node_modules")); err != nil {
		t.Fatal(err)
	}
	f.filesOnly()
	wantOutcome(t, f.bind(), OutcomePublished, ExitPublished)
	if _, err := os.Lstat(filepath.Join(f.project, "node_modules")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a tree appeared: %v", err)
	}
}

func TestFilesOnlyDoesNotLookAtTheTreeRoot(t *testing.T) {
	f := newBindFx(t)
	if err := os.RemoveAll(filepath.Join(f.project, "node_modules")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/nonexistent-target", filepath.Join(f.project, "node_modules")); err != nil {
		t.Fatal(err)
	}
	f.filesOnly()
	wantOutcome(t, f.bind(), OutcomePublished, ExitPublished)
	if target, err := os.Readlink(filepath.Join(f.project, "node_modules")); err != nil || target != "/nonexistent-target" {
		t.Fatalf("the tree root was touched: %q, %v", target, err)
	}
}

func TestFilesOnlyRefusesACommandOrAnEnvironment(t *testing.T) {
	f := newBindFx(t)
	f.filesOnly()
	f.req.Argv = []string{"/bin/true"}
	before := snapshot(t, f.project)
	wantOutcome(t, f.bind(), OutcomeRefused, ExitRefused)
	sameSnapshot(t, before, snapshot(t, f.project))
	f.req.Argv, f.req.Env = nil, []string{"A=b"}
	wantOutcome(t, f.bind(), OutcomeRefused, ExitRefused)
	sameSnapshot(t, before, snapshot(t, f.project))
}

func TestFilesOnlyChecksTheLiveInputsLikeTheFullTransaction(t *testing.T) {
	f := newBindFx(t)
	f.filesOnly()
	put(t, filepath.Join(f.project, "package.json"), `{"name":"edited"}`, 0o640)
	before := snapshot(t, f.project)
	report := f.bind()
	wantOutcome(t, report, OutcomeInputsChanged, ExitInputsChanged)
	sameSnapshot(t, before, snapshot(t, f.project))
	noStaging(t, f.project)

	// an edit between the first check and publication is never overwritten
	f2 := newBindFx(t)
	f2.filesOnly()
	hookAt(t, "publish:prepared", func() error {
		put(t, filepath.Join(f2.project, "package-lock.json"), `{"edited":true}`, 0o600)
		return nil
	})
	report = f2.bind()
	wantOutcome(t, report, OutcomeInputsChanged, ExitInputsChanged)
	if raw, _ := os.ReadFile(filepath.Join(f2.project, "package-lock.json")); string(raw) != `{"edited":true}` {
		t.Fatalf("the edit was overwritten: %q", raw)
	}
	if raw, _ := os.ReadFile(filepath.Join(f2.project, "package.json")); string(raw) != oldManifest {
		t.Fatalf("a file was published although an input changed: %q", raw)
	}
}

func TestFilesOnlyFailureInsidePublicationIsUndone(t *testing.T) {
	for _, stage := range []string{"publish:file:0:before", "publish:file:0", "publish:file:1:before", "publish:file:1", "publish:checked"} {
		t.Run(stage, func(t *testing.T) {
			f := newBindFx(t)
			f.filesOnly()
			hookAt(t, stage, func() error { return errors.New("disk on fire") })
			before := snapshot(t, f.project)
			report := f.bind()
			wantOutcome(t, report, OutcomePublicationFailed, ExitPublicationFailed)
			if report.Publication.State != PublicationRolledBack || len(report.Publication.Conflicts) != 0 {
				t.Fatalf("publication = %+v", report.Publication)
			}
			sameSnapshot(t, before, snapshot(t, f.project))
			noStaging(t, f.project)
		})
	}
}

func TestFilesOnlySignalBeforePublicationLeavesTheProject(t *testing.T) {
	for _, stage := range []string{"admitted", "staged", "publish:prepared", "publish:digested"} {
		t.Run(stage, func(t *testing.T) {
			f := newBindFx(t)
			f.filesOnly()
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			hookAt(t, stage, func() error {
				cancel(errors.New("terminated"))
				return nil
			})
			before := snapshot(t, f.project)
			report := Bind(ctx, f.req)
			wantOutcome(t, report, OutcomeInterrupted, ExitInterrupted)
			sameSnapshot(t, before, snapshot(t, f.project))
			noStaging(t, f.project)
		})
	}
}

func TestFilesOnlyStillRefusesWithoutTheLock(t *testing.T) {
	f := newBindFx(t)
	f.filesOnly()
	f.req.Lock = LockMode{FD: 2}
	before := snapshot(t, f.project)
	report := f.bind()
	wantOutcome(t, report, OutcomeRefused, ExitRefused)
	sameSnapshot(t, before, snapshot(t, f.project))
}
