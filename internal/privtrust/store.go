package privtrust

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/superbiche/safe/internal/strictjson"
)

// lockTimeout bounds every trust-store lock wait, matching safe-run's own
// host-allow writers.
var lockTimeout = 10 * time.Second

// withLock runs fn under an exclusive flock on file+".lock".
func withLock(file string, fn func() error) error {
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(file+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	deadline := time.Now().Add(lockTimeout)
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("another writer holds %s", file+".lock")
		}
		time.Sleep(50 * time.Millisecond)
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN) //nolint:errcheck
	return fn()
}

// writeAtomic replaces file with v as indented JSON, mode 0600.
func writeAtomic(file string, v any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(file), "."+filepath.Base(file)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, file)
}

// AddRegistry validates and records a local registry. An existing id is
// refused (remove it first); a namespace overlapping another local or
// effective followed registry with a different origin is refused.
func AddRegistry(s Stores, id string, r Registry) (Registry, error) {
	r, err := ValidateRegistry(id, r)
	if err != nil {
		return r, err
	}
	err = withLock(s.Policy, func() error {
		pol, err := LoadPolicy(s.Policy)
		if err != nil {
			return err
		}
		if _, ok := pol.Registries[id]; ok {
			return fmt.Errorf("registry %s already exists; remove it first to change it", id)
		}
		pol.Registries[id] = r
		if err := checkPolicyOverlap(pol.Registries); err != nil {
			return err
		}
		if v, err := Load(Stores{FollowState: s.FollowState, Config: s.Config}); err == nil {
			for _, ns := range r.Namespace {
				for _, fr := range v.registries {
					if fr.Ecosystem != r.Ecosystem || fr.Origin == r.Origin {
						continue
					}
					for _, fns := range fr.Namespace {
						if NamespacesOverlap(r.Ecosystem, ns, fns) {
							return fmt.Errorf("namespace %s overlaps %s followed from %s with a different origin (%s)", ns, fns, fr.Source.Host, fr.Origin)
						}
					}
				}
			}
		}
		pol.Schema = PolicySchema
		return writeAtomic(s.Policy, pol)
	})
	return r, err
}

// RemoveRegistry drops a local registry.
func RemoveRegistry(s Stores, id string) error {
	return withLock(s.Policy, func() error {
		pol, err := LoadPolicy(s.Policy)
		if err != nil {
			return err
		}
		if _, ok := pol.Registries[id]; !ok {
			return fmt.Errorf("no local registry %s", id)
		}
		delete(pol.Registries, id)
		return writeAtomic(s.Policy, pol)
	})
}

// ---------------------------------------------------------------------------
// Fleet statements
// ---------------------------------------------------------------------------

// Export builds the statement of this host's own registries.
func Export(s Stores, host, exportedAt string) (Statement, error) {
	if !ValidHost(host) {
		return Statement{}, fmt.Errorf("invalid short hostname")
	}
	if _, err := time.Parse(time.RFC3339, exportedAt); err != nil {
		return Statement{}, fmt.Errorf("exported_at must be an RFC 3339 instant")
	}
	pol, err := LoadPolicy(s.Policy)
	if err != nil {
		return Statement{}, err
	}
	st := Statement{Schema: StatementSchema, Host: host, ExportedAt: exportedAt,
		Registries: pol.Registries}
	for id, r := range st.Registries {
		r.Reason = trimReason(r.Reason)
		st.Registries[id] = r
	}
	return st, nil
}

func trimReason(r string) string {
	if len(r) > 500 {
		return r[:500]
	}
	return r
}

// StatementResult reports a follow application.
type StatementResult struct {
	Result     string   `json:"result"` // applied | current | older | collision
	Host       string   `json:"host"`
	Generation string   `json:"generation"`
	Registries []string `json:"registries"`
	Warnings   []string `json:"warnings,omitempty"`
}

// ParseStatement validates a signed statement's bytes as untrusted input:
// envelope fields must be exact; each registry is re-validated as if typed
// locally, and invalid ones are dropped with a warning. Overlapping
// namespaces inside one statement drop the whole statement.
func ParseStatement(raw []byte, host string) (Statement, []string, error) {
	var st Statement
	if err := strictjson.RejectRepeatedMembers(raw); err != nil {
		return st, nil, fmt.Errorf("statement: %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil {
		return st, nil, fmt.Errorf("statement is not a valid document: %v", err)
	}
	if st.Schema != StatementSchema {
		return st, nil, fmt.Errorf("statement schema must be %s", StatementSchema)
	}
	if st.Host != host || !ValidHost(host) {
		return st, nil, fmt.Errorf("statement host %q does not match its file name", st.Host)
	}
	if _, err := time.Parse(time.RFC3339, st.ExportedAt); err != nil {
		return st, nil, fmt.Errorf("statement exported_at is not an RFC 3339 instant")
	}
	var warns []string
	regs := map[string]Registry{}
	for _, id := range sortedKeys(st.Registries) {
		r, err := ValidateRegistry(id, st.Registries[id])
		if err != nil {
			warns = append(warns, "skipped registry: "+err.Error())
			continue
		}
		r.Reason = trimReason(r.Reason)
		regs[id] = r
	}
	if err := checkPolicyOverlap(regs); err != nil {
		return st, warns, fmt.Errorf("statement: %v", err)
	}
	st.Registries = regs
	return st, warns, nil
}

// ApplyStatement records a verified statement in the follow ledger. A newer
// generation REPLACES the origin's previous statement (so an origin's
// removals propagate); an older one is refused; an equal
// generation with different bytes is a collision and changes nothing.
func ApplyStatement(stateFile, host, signer string, raw []byte, dryRun bool) (StatementResult, error) {
	res := StatementResult{Host: host}
	st, warns, err := ParseStatement(raw, host)
	res.Warnings = warns
	if err != nil {
		return res, err
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	gen, _ := time.Parse(time.RFC3339, st.ExportedAt)
	res.Generation = st.ExportedAt
	res.Registries = sortedKeys(st.Registries)
	apply := func() error {
		fs, err := LoadFollowState(stateFile)
		if err != nil {
			return err
		}
		if old, ok := fs.Origins[host]; ok {
			prev, perr := time.Parse(time.RFC3339, old.Accepted)
			if perr != nil {
				return fmt.Errorf("%w: follow ledger generation for %s", ErrMalformed, host)
			}
			switch {
			case gen.Before(prev):
				res.Result = "older"
				return nil
			case gen.Equal(prev) && old.StatementSHA256 != digest:
				res.Result = "collision"
				return nil
			case gen.Equal(prev) && old.Signer == signer:
				res.Result = "current"
				return nil
			}
		}
		res.Result = "applied"
		if dryRun {
			return nil
		}
		fs.Origins[host] = FollowedOrigin{Accepted: st.ExportedAt, StatementSHA256: digest,
			Signer: signer, Registries: st.Registries}
		return writeAtomic(stateFile, fs)
	}
	if dryRun {
		return res, apply()
	}
	return res, withLock(stateFile, apply)
}

// ForgetOrigin drops one origin from the follow ledger.
func ForgetOrigin(stateFile, host string) (bool, error) {
	found := false
	err := withLock(stateFile, func() error {
		fs, err := LoadFollowState(stateFile)
		if err != nil {
			return err
		}
		if _, ok := fs.Origins[host]; !ok {
			return nil
		}
		found = true
		delete(fs.Origins, host)
		return writeAtomic(stateFile, fs)
	})
	return found, err
}

// ListEntry is one row of the effective registry listing.
type ListEntry struct {
	ID        string   `json:"id"`
	Ecosystem string   `json:"ecosystem"`
	Origin    string   `json:"origin"`
	Namespace []string `json:"namespace"`
	Source    Source   `json:"source"`
}

// Listing is the effective state for list/doctor.
type Listing struct {
	Registries []ListEntry `json:"registries"`
	Conflicts  []string    `json:"conflicts"`
}

// List reports the effective registries and any cross-source conflicts.
func (v *View) List() Listing {
	l := Listing{Registries: []ListEntry{}, Conflicts: []string{}}
	for _, r := range v.registries {
		l.Registries = append(l.Registries, ListEntry{ID: r.Source.RegistryID, Ecosystem: r.Ecosystem,
			Origin: r.Origin, Namespace: r.Namespace, Source: r.Source})
	}
	for i, a := range v.registries {
		for _, b := range v.registries[i+1:] {
			if a.Ecosystem != b.Ecosystem || a.Origin == b.Origin {
				continue
			}
			for _, na := range a.Namespace {
				for _, nb := range b.Namespace {
					if NamespacesOverlap(a.Ecosystem, na, nb) {
						l.Conflicts = append(l.Conflicts, fmt.Sprintf("%s namespace %s (%s via %s) overlaps %s (%s via %s)",
							a.Ecosystem, na, a.Origin, srcLabel(a.Source), nb, b.Origin, srcLabel(b.Source)))
					}
				}
			}
		}
	}
	return l
}

func srcLabel(s Source) string {
	if s.Kind == KindLocal {
		return "local " + s.RegistryID
	}
	return "followed " + s.Host + " " + s.RegistryID
}
