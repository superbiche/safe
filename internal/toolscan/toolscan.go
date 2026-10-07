// Package toolscan matches the tools mise has installed against vulnerability
// advisories and renders the result as a Sync/state publication.
//
// Scope is every installed mise tool version that a tracked config still
// references: `mise ls --installed` minus `mise ls --prunable`. Each version
// directory is inventoried once by syft (directories are immutable once
// installed, so the SBOM is cached) and rematched by grype on every run against
// a database refreshed first.
package toolscan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	Schema        = "tool-vulns/1"
	SeverityFloor = "High"

	// syft's directory scan leaves installed node_modules and
	// cargo-auditable metadata out by default, and reads GitHub workflow
	// files that ship inside npm packages as dependencies.
	syftCatalogers = "+javascript-package-cataloger,+cargo-auditable-binary-cataloger,-github-actions-usage-cataloger,-github-action-workflow-usage-cataloger"

	syftTimeout  = 10 * time.Minute
	grypeTimeout = 10 * time.Minute
	dbTimeout    = 15 * time.Minute
	miseTimeout  = 2 * time.Minute
)

type Options struct {
	Mise, Syft, Grype string
	// Dir is where mise resolves configs from; prunability is decided
	// against tracked configs, so any directory gives the same scope.
	Dir      string
	CacheDir string
	Host     string
	Producer string
	Now      func() time.Time
}

type Report struct {
	Schema        string    `json:"schema"`
	GeneratedAt   string    `json:"generated_at"`
	Host          string    `json:"host"`
	Producer      string    `json:"producer"`
	SeverityFloor string    `json:"severity_floor"`
	Scanners      Scanners  `json:"scanners"`
	DB            DB        `json:"db"`
	Scope         *Scope    `json:"scope"`
	Tools         []Tool    `json:"tools"`
	Unscanned     []string  `json:"unscanned"`
	Errors        []ToolErr `json:"errors"`
	Error         *string   `json:"error"`
}

type Scanners struct {
	Syft  *string `json:"syft"`
	Grype *string `json:"grype"`
}

type DB struct {
	Built       *string `json:"built"`
	Usable      *bool   `json:"usable"`
	UpdateError *string `json:"update_error"`
}

type Scope struct {
	InScope  int `json:"in_scope"`
	Prunable int `json:"prunable"`
}

type Tool struct {
	Tool       string     `json:"tool"`
	Version    string     `json:"version"`
	Components int        `json:"components"`
	Critical   int        `json:"critical"`
	High       int        `json:"high"`
	Advisories []Advisory `json:"advisories"`
}

type Advisory struct {
	ID               string   `json:"id"`
	Severity         string   `json:"severity"`
	Component        string   `json:"component"`
	ComponentVersion string   `json:"component_version"`
	FixedIn          []string `json:"fixed_in"`
}

type ToolErr struct {
	Tool    string `json:"tool"`
	Version string `json:"version"`
	Stage   string `json:"stage"`
	Message string `json:"message"`
}

type install struct {
	tool, version, path string
}

// Scan never returns a partial report as clean: a stage that could not run
// leaves its fields null (unknown) and sets Error, and the caller still
// publishes it so the failure is visible where the findings would have been.
func Scan(ctx context.Context, o Options) Report {
	r := Report{
		Schema:        Schema,
		GeneratedAt:   o.Now().UTC().Format(time.RFC3339),
		Host:          o.Host,
		Producer:      o.Producer,
		SeverityFloor: SeverityFloor,
		Errors:        []ToolErr{},
	}
	r.Scanners.Syft = toolVersion(ctx, o.Syft)
	r.Scanners.Grype = toolVersion(ctx, o.Grype)

	if r.Scanners.Syft == nil || r.Scanners.Grype == nil {
		return r.fail("syft and grype are both required (syft %s, grype %s)", found(r.Scanners.Syft), found(r.Scanners.Grype))
	}
	if o.Mise == "" {
		return r.fail("mise not found")
	}
	scope, prunable, err := resolveScope(ctx, o)
	if err != nil {
		return r.fail("mise scope: %v", err)
	}
	r.Scope = &Scope{InScope: len(scope), Prunable: prunable}

	r.DB = refreshDB(ctx, o.Grype)
	if r.DB.Usable == nil || !*r.DB.Usable {
		return r.fail("grype database unusable after update attempt")
	}

	if err := os.MkdirAll(o.CacheDir, 0o700); err != nil {
		return r.fail("sbom cache: %v", err)
	}
	keep := map[string]bool{}
	r.Tools = []Tool{}
	r.Unscanned = []string{}
	for _, in := range scope {
		sbom, err := cachedSBOM(ctx, o, *r.Scanners.Syft, in)
		if err != nil {
			r.Errors = append(r.Errors, ToolErr{in.tool, in.version, "sbom", err.Error()})
			continue
		}
		keep[filepath.Base(sbom)] = true
		n, err := countArtifacts(sbom)
		if err != nil {
			r.Errors = append(r.Errors, ToolErr{in.tool, in.version, "sbom", err.Error()})
			continue
		}
		if n == 0 {
			r.Unscanned = append(r.Unscanned, in.tool+"@"+in.version)
			continue
		}
		advs, err := match(ctx, o.Grype, sbom)
		if err != nil {
			r.Errors = append(r.Errors, ToolErr{in.tool, in.version, "match", err.Error()})
			continue
		}
		t := Tool{Tool: in.tool, Version: in.version, Components: n, Advisories: advs}
		for _, a := range advs {
			if a.Severity == "Critical" {
				t.Critical++
			} else {
				t.High++
			}
		}
		r.Tools = append(r.Tools, t)
	}
	pruneCache(o.CacheDir, keep)
	if len(scope) > 0 && len(r.Tools) == 0 && len(r.Unscanned) == 0 {
		return r.fail("no tool version could be scanned (%d failed; first: %s %s@%s: %s)",
			len(r.Errors), r.Errors[0].Stage, r.Errors[0].Tool, r.Errors[0].Version, r.Errors[0].Message)
	}
	return r
}

func (r Report) fail(format string, args ...any) Report {
	msg := fmt.Sprintf(format, args...)
	r.Error = &msg
	r.Tools, r.Unscanned = nil, nil
	return r
}

func found(v *string) string {
	if v == nil {
		return "missing"
	}
	return *v
}

func run(ctx context.Context, timeout time.Duration, dir string, env []string, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		tail := strings.TrimSpace(stderr.String())
		if i := strings.LastIndexByte(tail, '\n'); i >= 0 {
			tail = tail[i+1:]
		}
		if tail != "" {
			return nil, fmt.Errorf("%s %s: %v: %s", filepath.Base(name), args[0], err, tail)
		}
		return nil, fmt.Errorf("%s %s: %v", filepath.Base(name), args[0], err)
	}
	return stdout.Bytes(), nil
}

// Scanners must not spend a run checking for their own updates.
var quiet = []string{"SYFT_CHECK_FOR_APP_UPDATE=false", "GRYPE_CHECK_FOR_APP_UPDATE=false"}

func toolVersion(ctx context.Context, bin string) *string {
	if bin == "" {
		return nil
	}
	out, err := run(ctx, miseTimeout, "", quiet, bin, "version", "-o", "json")
	if err != nil {
		return nil
	}
	var v struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(out, &v) != nil || v.Version == "" {
		return nil
	}
	return &v.Version
}

type miseVersion struct {
	Version     string `json:"version"`
	InstallPath string `json:"install_path"`
	Installed   bool   `json:"installed"`
}

func miseLs(ctx context.Context, o Options, flag string) (map[string][]miseVersion, error) {
	out, err := run(ctx, miseTimeout, o.Dir, nil, o.Mise, "ls", flag, "--json")
	if err != nil {
		return nil, err
	}
	var m map[string][]miseVersion
	if err := json.Unmarshal(out, &m); err != nil {
		return nil, fmt.Errorf("mise ls %s: %v", flag, err)
	}
	return m, nil
}

func resolveScope(ctx context.Context, o Options) ([]install, int, error) {
	installed, err := miseLs(ctx, o, "--installed")
	if err != nil {
		return nil, 0, err
	}
	prunableLs, err := miseLs(ctx, o, "--prunable")
	if err != nil {
		return nil, 0, err
	}
	prunable := map[string]bool{}
	for tool, vs := range prunableLs {
		for _, v := range vs {
			prunable[tool+"@"+v.Version] = true
		}
	}
	var scope []install
	for tool, vs := range installed {
		for _, v := range vs {
			if !v.Installed || v.InstallPath == "" || prunable[tool+"@"+v.Version] {
				continue
			}
			scope = append(scope, install{tool, v.Version, v.InstallPath})
		}
	}
	sort.Slice(scope, func(i, j int) bool {
		if scope[i].tool != scope[j].tool {
			return scope[i].tool < scope[j].tool
		}
		return scope[i].version < scope[j].version
	})
	return scope, len(prunable), nil
}

func refreshDB(ctx context.Context, grype string) DB {
	var db DB
	if _, err := run(ctx, dbTimeout, "", quiet, grype, "db", "update"); err != nil {
		msg := err.Error()
		db.UpdateError = &msg
	}
	out, err := run(ctx, miseTimeout, "", quiet, grype, "db", "status", "-o", "json")
	if err != nil {
		return db
	}
	var s struct {
		Built string `json:"built"`
		Valid bool   `json:"valid"`
	}
	if json.Unmarshal(out, &s) != nil {
		return db
	}
	if s.Built != "" {
		db.Built = &s.Built
	}
	db.Usable = &s.Valid
	return db
}

// The cache key covers what decides an SBOM's content: the directory (its
// path and modification time, which a forced reinstall changes), the syft
// version and the cataloger selection.
func cachedSBOM(ctx context.Context, o Options, syftVersion string, in install) (string, error) {
	st, err := os.Stat(in.path)
	if err != nil {
		return "", err
	}
	if !st.IsDir() {
		return "", fmt.Errorf("%s is not a directory", in.path)
	}
	h := sha256.Sum256([]byte(strings.Join([]string{
		in.path, st.ModTime().UTC().Format(time.RFC3339Nano), syftVersion, syftCatalogers,
	}, "\x00")))
	path := filepath.Join(o.CacheDir, hex.EncodeToString(h[:16])+".syft.json")
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}
	tmp, err := os.CreateTemp(o.CacheDir, ".sbom-*")
	if err != nil {
		return "", err
	}
	tmp.Close()
	defer os.Remove(tmp.Name())
	if _, err := run(ctx, syftTimeout, "", quiet, o.Syft, "scan", "dir:"+in.path, "-q",
		"--select-catalogers", syftCatalogers, "-o", "syft-json="+tmp.Name()); err != nil {
		return "", err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return "", err
	}
	return path, nil
}

func countArtifacts(sbom string) (int, error) {
	raw, err := os.ReadFile(sbom)
	if err != nil {
		return 0, err
	}
	var doc struct {
		Artifacts *[]json.RawMessage `json:"artifacts"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return 0, fmt.Errorf("read sbom: %v", err)
	}
	if doc.Artifacts == nil {
		return 0, errors.New("read sbom: no artifacts array")
	}
	return len(*doc.Artifacts), nil
}

func match(ctx context.Context, grype, sbom string) ([]Advisory, error) {
	// The database was refreshed once for the run; a per-tool update would
	// let one run match different tools against different databases.
	env := append([]string{"GRYPE_DB_AUTO_UPDATE=false"}, quiet...)
	out, err := run(ctx, grypeTimeout, "", env, grype, "sbom:"+sbom, "-q", "-o", "json")
	if err != nil {
		return nil, err
	}
	var doc struct {
		Matches *[]struct {
			Vulnerability struct {
				ID       string `json:"id"`
				Severity string `json:"severity"`
				Fix      struct {
					Versions []string `json:"versions"`
				} `json:"fix"`
			} `json:"vulnerability"`
			Artifact struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"artifact"`
		} `json:"matches"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, fmt.Errorf("read grype output: %v", err)
	}
	if doc.Matches == nil {
		return nil, errors.New("read grype output: no matches array")
	}
	seen := map[string]bool{}
	advs := []Advisory{}
	for _, m := range *doc.Matches {
		sev := m.Vulnerability.Severity
		if sev != "Critical" && sev != "High" {
			continue
		}
		key := m.Vulnerability.ID + "\x00" + m.Artifact.Name + "\x00" + m.Artifact.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		fixed := m.Vulnerability.Fix.Versions
		if fixed == nil {
			fixed = []string{}
		}
		advs = append(advs, Advisory{m.Vulnerability.ID, sev, m.Artifact.Name, m.Artifact.Version, fixed})
	}
	sort.Slice(advs, func(i, j int) bool {
		a, b := advs[i], advs[j]
		if a.Severity != b.Severity {
			return a.Severity == "Critical"
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		if a.Component != b.Component {
			return a.Component < b.Component
		}
		return a.ComponentVersion < b.ComponentVersion
	})
	return advs, nil
}

func pruneCache(dir string, keep map[string]bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".syft.json") && !keep[e.Name()] {
			os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}

// Publish writes the report beside its destination and renames it into
// place, under a temporary name a `*.json` reader ignores.
func Publish(r Report, dest string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dest), "."+r.Host+".")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dest)
}
