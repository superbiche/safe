package projectlane

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/superbiche/safe/internal/strictjson"
)

// Socket on a named root (spec 1625, Evidence and Decision).
//
// Socket scores the artifacts the caller NAMED on the command line, as today's per-root audit does, and nothing
// else: its facts arrive in a document the auditor wrote in its evidence-only mode (`package-audit
// --evidence-only`: it asks nothing, decides nothing and records nothing). Besides the named roots, a blocking
// Socket result that is ALREADY IN THE CACHE counts for any public artifact of the target graph: no call is made
// for those.
//
// This file only reads that document and judges it. The scoring, the cache and the classification are the
// auditor's; the mapping from a Socket result to the exit the install gate takes for it (0, 10, 11, 12, 13, 14,
// 20) is the auditor's too and arrives as the root's gate_exit, so that the outcomes stay today's.

// SocketSchema is the version of the Socket evidence document.
const SocketSchema = 1

// ClassSocketRoot is the decision class of a named root whose Socket result is not clear. It is resolved after the
// Wait class and before missing evidence. Its exit is today's gate's for the first such result left: an adverse
// finding is policy (100); an infrastructure outage, a rate limit, a consent ask and a pending score are the
// operator's (102).
const ClassSocketRoot = "socket_root"

// Outcomes of a named root's Socket result, with the exit the install gate takes for each.
const (
	SocketClear           = "clear"            // 0
	SocketAdverse         = "adverse"          // 10: a WARN about the package (low score, alerts, no record)
	SocketUnavailable     = "unavailable"      // 11: audit infrastructure (unreachable, authentication, unrecognized answer)
	SocketRateLimited     = "rate_limited"     // 12
	SocketConsentRequired = "consent_required" // 13: a fresh release; no call is spent without the operator's say-so
	SocketPending         = "pending"          // 14: the score of a fresh release is not computed yet
	SocketBlocked         = "blocked"          // 20: a critical supply-chain-risk alert
)

var socketGateExit = map[string]int{
	SocketClear: 0, SocketAdverse: 10, SocketUnavailable: 11, SocketRateLimited: 12,
	SocketConsentRequired: 13, SocketPending: 14, SocketBlocked: 20,
}

var socketCause = regexp.MustCompile(`^socket_[a-z_]+$`)

// SocketRoot is the Socket facts of one named root.
type SocketRoot struct {
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	Outcome  string   `json:"outcome"`
	GateExit int      `json:"gate_exit"`
	Line     string   `json:"line"`
	Causes   []string `json:"causes"`
	Cached   bool     `json:"cached"`
}

// SocketBlock is a blocking Socket result found in the cache for an artifact of the target graph.
type SocketBlock struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Line    string `json:"line"`
}

// SocketEvidence is the strict, versioned input of the Socket judgement.
type SocketEvidence struct {
	SchemaVersion int           `json:"schema_version"`
	Roots         []SocketRoot  `json:"roots"`
	CachedBlocks  []SocketBlock `json:"cached_blocks"`
	// CacheGap says why the cache could not be read ("" when it was): missing evidence.
	CacheGap string `json:"cache_gap"`
	// Untied are the named operands that could not be tied to a package the projected lockfile holds: nothing
	// could be asked for them, which is a gap of the command (missing evidence), never a skipped root.
	Untied []SocketUntied `json:"untied"`
}

// SocketUntied is a named operand the projection does not hold.
type SocketUntied struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// SocketReport is the Socket part of the decision report.
type SocketReport struct {
	// Roots are the named roots whose Socket result was read, with what each came to.
	Roots []SocketRootReport `json:"roots"`
	// CacheGap is set when the cache could not be read.
	CacheGap string `json:"cache_gap"`
}

// SocketRootReport is one named root's Socket result and what the decision did with it.
type SocketRootReport struct {
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Outcome   string   `json:"outcome"`
	Exit      int      `json:"exit"`
	Line      string   `json:"line"`
	Cached    bool     `json:"cached"`
	Cleared   bool     `json:"cleared"`
	ClearedBy []string `json:"cleared_by"`
}

// outcomeExit is the exit of the decision for an uncleared result: today's gate refuses an adverse finding as
// policy (100) and every other state as the operator's (102).
func outcomeExit(outcome string) int {
	if outcome == SocketAdverse {
		return ExitPolicy
	}
	return ExitOperator
}

// judgeSocket applies the Socket evidence to the target graph: the malice it establishes (a blocking result of a
// root, or in the cache, for an artifact of the target), the class items of the named roots, and the report.
// Only public registry artifacts of the target are judged: a result is never applied to anything else.
func judgeSocket(in Input) (malice []MaliceItem, report SocketReport, class ClassOutcome) {
	sock := in.Socket
	report = SocketReport{Roots: []SocketRootReport{}, CacheGap: sock.CacheGap}
	class = ClassOutcome{Class: ClassSocketRoot, Exit: ExitPolicy}
	inTarget := map[Identity]struct{}{}
	for _, occurrence := range in.Target.Occurrences {
		if occurrence.Public {
			inTarget[occurrence.Identity()] = struct{}{}
		}
	}
	blocked := map[Identity]string{}
	for _, block := range sock.CachedBlocks {
		identity := Identity{Name: block.Name, Version: block.Version}
		if _, ok := inTarget[identity]; ok {
			blocked[identity] = block.Line
		}
	}
	roots := append([]SocketRoot(nil), sock.Roots...)
	sort.Slice(roots, func(i, j int) bool {
		if roots[i].Name != roots[j].Name {
			return roots[i].Name < roots[j].Name
		}
		return roots[i].Version < roots[j].Version
	})
	worst := 0
	for _, root := range roots {
		identity := Identity{Name: root.Name, Version: root.Version}
		if _, ok := inTarget[identity]; !ok {
			continue // a root the projected graph does not carry is not an artifact of this command
		}
		item := SocketRootReport{Name: root.Name, Version: root.Version, Outcome: root.Outcome, Line: root.Line, Cached: root.Cached, ClearedBy: []string{}}
		switch root.Outcome {
		case SocketClear:
			item.Cleared = true
		case SocketBlocked:
			blocked[identity] = root.Line
			item.Exit = ExitBlock
		default:
			item.Exit = outcomeExit(root.Outcome)
			var causes []string
			if root.Outcome == SocketAdverse || root.Outcome == SocketRateLimited || root.Outcome == SocketUnavailable {
				causes = root.Causes
			}
			item.Cleared, item.ClearedBy = waitCleared(identity, in, causes)
			class.AtStake++
			if !item.Cleared {
				class.Outstanding++
				// the exit of the first class item left: an adverse finding (100) outranks the operator's (102)
				if item.Exit == ExitPolicy {
					worst = ExitPolicy
				} else if worst == 0 {
					worst = ExitOperator
				}
			}
		}
		report.Roots = append(report.Roots, item)
	}
	if worst != 0 {
		class.Exit = worst
	}
	for identity, line := range blocked {
		malice = append(malice, MaliceItem{Signal: "socket_block", Name: identity.Name, Versions: []string{identity.Version}, Reason: line})
	}
	return malice, report, class
}

// ReadSocket decodes a Socket evidence document strictly: no repeated member, no unknown member, every member
// present, every value in its domain, an outcome that agrees with its gate exit. A document that cannot be read is
// an error, never "nothing found".
func ReadSocket(raw []byte) (SocketEvidence, error) {
	if err := strictjson.RejectRepeatedMembers(raw); err != nil {
		return SocketEvidence{}, fmt.Errorf("socket evidence: %w", err)
	}
	var shape map[string]any
	if err := json.Unmarshal(raw, &shape); err != nil || shape == nil {
		return SocketEvidence{}, fmt.Errorf("socket evidence: not a JSON object")
	}
	if err := requireKeys(shape, "", "schema_version", "roots", "cached_blocks", "cache_gap", "untied"); err != nil {
		return SocketEvidence{}, fmt.Errorf("socket evidence: %w", err)
	}
	for _, list := range []struct {
		key  string
		keys []string
	}{
		{"roots", []string{"name", "version", "outcome", "gate_exit", "line", "causes", "cached"}},
		{"cached_blocks", []string{"name", "version", "line"}},
		{"untied", []string{"name", "version"}},
	} {
		items, ok := shape[list.key].([]any)
		if !ok {
			return SocketEvidence{}, fmt.Errorf("socket evidence: %s must be a list", list.key)
		}
		for i, item := range items {
			object, ok := item.(map[string]any)
			if !ok {
				return SocketEvidence{}, fmt.Errorf("socket evidence: %s[%d] must be an object", list.key, i)
			}
			if err := requireKeys(object, fmt.Sprintf("%s[%d].", list.key, i), list.keys...); err != nil {
				return SocketEvidence{}, fmt.Errorf("socket evidence: %w", err)
			}
			if list.key == "roots" {
				if _, ok := object["causes"].([]any); !ok {
					return SocketEvidence{}, fmt.Errorf("socket evidence: roots[%d].causes must be a list", i)
				}
			}
		}
	}
	var evidence SocketEvidence
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&evidence); err != nil {
		return SocketEvidence{}, fmt.Errorf("socket evidence: %w", err)
	}
	if decoder.More() {
		return SocketEvidence{}, fmt.Errorf("socket evidence: more than one JSON document")
	}
	if err := evidence.validate(); err != nil {
		return SocketEvidence{}, fmt.Errorf("socket evidence: %w", err)
	}
	return evidence, nil
}

func (e SocketEvidence) validate() error {
	if e.SchemaVersion != SocketSchema {
		return fmt.Errorf("unsupported schema_version %d (this reader knows %d)", e.SchemaVersion, SocketSchema)
	}
	seen := map[Identity]struct{}{}
	for i, root := range e.Roots {
		if root.Name == "" || root.Version == "" {
			return fmt.Errorf("roots[%d]: name and version are required", i)
		}
		identity := Identity{Name: root.Name, Version: root.Version}
		if _, dup := seen[identity]; dup {
			return fmt.Errorf("roots[%d]: %s@%s is given more than once", i, root.Name, root.Version)
		}
		seen[identity] = struct{}{}
		exit, ok := socketGateExit[root.Outcome]
		if !ok {
			return fmt.Errorf("roots[%d]: unknown outcome %q", i, root.Outcome)
		}
		if root.GateExit != exit {
			return fmt.Errorf("roots[%d]: outcome %q is not gate exit %d", i, root.Outcome, root.GateExit)
		}
		if root.Line == "" || strings.ContainsAny(root.Line, "\x00\n\r") {
			return fmt.Errorf("roots[%d]: the line must be one line of text", i)
		}
		malware := false
		for _, cause := range root.Causes {
			if !socketCause.MatchString(cause) {
				return fmt.Errorf("roots[%d].causes: %q is not a Socket cause", i, cause)
			}
			if cause == "socket_malware" {
				malware = true
			}
		}
		// a result cannot contradict itself: clear carries no Socket cause, and a malware cause is a blocking result
		if root.Outcome == SocketClear && len(root.Causes) > 0 {
			return fmt.Errorf("roots[%d]: a clear result carries Socket causes", i)
		}
		if (root.Outcome == SocketBlocked) != malware {
			return fmt.Errorf("roots[%d]: outcome %q and the malware cause disagree", i, root.Outcome)
		}
	}
	blocks := map[Identity]struct{}{}
	for i, block := range e.CachedBlocks {
		if block.Name == "" || block.Version == "" || block.Line == "" || strings.ContainsAny(block.Line, "\x00\n\r") {
			return fmt.Errorf("cached_blocks[%d]: name, version and a one-line text are required", i)
		}
		identity := Identity{Name: block.Name, Version: block.Version}
		if _, dup := blocks[identity]; dup {
			return fmt.Errorf("cached_blocks[%d]: %s@%s is given more than once", i, block.Name, block.Version)
		}
		blocks[identity] = struct{}{}
	}
	for i, untied := range e.Untied {
		if untied.Name == "" || untied.Version == "" || strings.ContainsAny(untied.Name+untied.Version, "\x00\n\r") {
			return fmt.Errorf("untied[%d]: name and version are required", i)
		}
	}
	if strings.ContainsAny(e.CacheGap, "\x00\n\r") {
		return fmt.Errorf("cache_gap must be one line of text")
	}
	return nil
}
