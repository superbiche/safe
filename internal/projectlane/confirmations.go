package projectlane

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/superbiche/safe/internal/strictjson"
)

// Operator confirmations for ONE command (spec 1625, "Decision"). A standing acceptance is an authority the operator's own
// stores hold; a confirmation is an answer given at the operator's terminal for this command alone, that no store keeps:
//
//   - a typed override of a malice signal on an exact artifact (never recorded, whatever happens next);
//   - the deliberate confirmation of missing evidence (the advisory reading, the baseline or a publish time could not be
//     read), for this command, recording nothing;
//   - a named root's Socket result accepted for this command (an audit infrastructure outage on its Socket reading).
//
// Everything else the operator accepts at the terminal is RECORDED when it is given, by today's writers, and reaches the
// decision as a standing acceptance on the next reading of the stores.

// ConfirmationsSchema is the version of the confirmations document.
const ConfirmationsSchema = 1

// Confirmations is the strict, versioned input of the per-command answers.
type Confirmations struct {
	SchemaVersion int        `json:"schema_version"`
	Malice        []Identity `json:"malice"`
	EvidenceGap   bool       `json:"evidence_gap"`
	Socket        []Identity `json:"socket"`
}

// ConfirmedByOperator is the kind recorded as the authority that cleared an item for this command.
const ConfirmedByOperator = "operator_command"

// ReadConfirmations decodes the document strictly: one JSON document, no repeated or unknown member, every member present.
func ReadConfirmations(raw []byte) (Confirmations, error) {
	if err := strictjson.RejectRepeatedMembers(raw); err != nil {
		return Confirmations{}, fmt.Errorf("confirmations: %w", err)
	}
	var shape map[string]any
	if err := json.Unmarshal(raw, &shape); err != nil || shape == nil {
		return Confirmations{}, fmt.Errorf("confirmations: not a JSON object")
	}
	if err := requireKeys(shape, "", "schema_version", "malice", "evidence_gap", "socket"); err != nil {
		return Confirmations{}, fmt.Errorf("confirmations: %w", err)
	}
	for _, key := range []string{"malice", "socket"} {
		items, ok := shape[key].([]any)
		if !ok {
			return Confirmations{}, fmt.Errorf("confirmations: %s must be a list", key)
		}
		for i, item := range items {
			object, ok := item.(map[string]any)
			if !ok {
				return Confirmations{}, fmt.Errorf("confirmations: %s[%d] must be an object", key, i)
			}
			if err := requireKeys(object, fmt.Sprintf("%s[%d].", key, i), "name", "version"); err != nil {
				return Confirmations{}, fmt.Errorf("confirmations: %w", err)
			}
		}
	}
	var confirmations Confirmations
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&confirmations); err != nil {
		return Confirmations{}, fmt.Errorf("confirmations: %w", err)
	}
	if decoder.More() {
		return Confirmations{}, fmt.Errorf("confirmations: more than one JSON document")
	}
	if confirmations.SchemaVersion != ConfirmationsSchema {
		return Confirmations{}, fmt.Errorf("confirmations: unsupported schema_version %d (this reader knows %d)", confirmations.SchemaVersion, ConfirmationsSchema)
	}
	for _, list := range [][]Identity{confirmations.Malice, confirmations.Socket} {
		for i, identity := range list {
			if identity.Name == "" || identity.Version == "" {
				return Confirmations{}, fmt.Errorf("confirmations: item %d: name and version are required", i)
			}
		}
	}
	return confirmations, nil
}

func (c Confirmations) has(list []Identity, identity Identity) bool {
	for _, item := range list {
		if item == identity {
			return true
		}
	}
	return false
}

// OutstandingClass is one class the decision leaves at stake, with what the operator is asked about, in the decision's order.
type OutstandingClass struct {
	Class string            `json:"class"`
	Exit  int               `json:"exit"`
	Items []OutstandingItem `json:"items"`
}

// OutstandingItem is one thing the operator is asked about: an artifact (the one whose bytes carry the evidence), the advisories
// or causes, and for a bundled member what carries it.
type OutstandingItem struct {
	Name       string   `json:"name"`
	Version    string   `json:"version"`
	Host       string   `json:"host"`
	Advisories []string `json:"advisories"`
	Carried    []string `json:"carried"`
	Severity   string   `json:"severity"`
	Detail     string   `json:"detail"`
	Outcome    string   `json:"outcome"`
	Signal     string   `json:"signal"`
	Class      string   `json:"class"`
	Root       bool     `json:"root"`
}

// outstandingClasses lists, in the decision's own order, what each class still leaves at stake and what the operator is asked
// about: the artifact whose bytes carry an advisory is the one an acceptance is for (a bundled member's covering artifact).
func outstandingClasses(report Report, in Input) []OutstandingClass {
	hostOf := func(name, version string) string {
		for _, occurrence := range in.Target.Occurrences {
			if occurrence.Name == name && occurrence.Version == version && occurrence.Host != "" {
				return occurrence.Host
			}
		}
		return ""
	}
	out := []OutstandingClass{}
	for _, class := range report.Classes {
		if class.Outstanding == 0 {
			continue
		}
		entry := OutstandingClass{Class: class.Class, Exit: class.Exit, Items: []OutstandingItem{}}
		switch class.Class {
		case ClassMalice:
			for _, item := range report.Malice {
				if item.Overridden {
					continue
				}
				for _, version := range item.Versions {
					entry.Items = append(entry.Items, OutstandingItem{Name: item.Name, Version: version, Host: hostOf(item.Name, version),
						Advisories: []string{}, Carried: []string{}, Signal: item.Signal, Detail: firstNonEmpty(item.ID, item.Reason), Class: class.Class})
				}
			}
		case ClassBlockingAdvisory, ClassAdverseAdvisory:
			wanted := AdvisoryBlocking
			if class.Class == ClassAdverseAdvisory {
				wanted = AdvisoryAdverse
			}
			type key struct{ name, version, host string }
			merged := map[key]*OutstandingItem{}
			for _, item := range report.Advisories.Introduced {
				if item.Class != wanted || item.Cleared {
					continue
				}
				for _, version := range item.Versions {
					for _, occurrence := range in.Target.Occurrences {
						if occurrence.Name != item.Name || occurrence.Version != version || !occurrence.Public {
							continue
						}
						coverName, coverVersion := coverArtifact(occurrence)
						k := key{coverName, coverVersion, occurrence.Host}
						if merged[k] == nil {
							merged[k] = &OutstandingItem{Name: coverName, Version: coverVersion, Host: occurrence.Host, Advisories: []string{}, Carried: []string{}, Class: class.Class}
						}
						target := merged[k]
						target.Advisories = append(target.Advisories, item.ID)
						if severityRank(item.Severity) > severityRank(target.Severity) {
							target.Severity = item.Severity
						}
						if occurrence.CoveredBy != "" {
							target.Carried = append(target.Carried, occurrence.Name+"@"+occurrence.Version)
						}
					}
				}
			}
			for _, item := range merged {
				item.Advisories, item.Carried = sortedUnique(item.Advisories), sortedUnique(item.Carried)
				entry.Items = append(entry.Items, *item)
			}
		case ClassWait:
			if report.Cooldown != nil {
				for _, wait := range report.Cooldown.Waits {
					if wait.Cleared {
						continue
					}
					entry.Items = append(entry.Items, OutstandingItem{Name: wait.Name, Version: wait.Version, Host: hostOf(wait.Name, wait.Version),
						Advisories: []string{}, Carried: []string{}, Root: wait.Root, Class: class.Class,
						Detail: "published " + wait.Published + ", installable " + wait.Installable})
				}
			}
		case ClassSocketRoot:
			if report.Socket != nil {
				for _, root := range report.Socket.Roots {
					if root.Cleared {
						continue
					}
					causes := rootCausesOf(in, root.Name, root.Version)
					entry.Items = append(entry.Items, OutstandingItem{Name: root.Name, Version: root.Version, Host: hostOf(root.Name, root.Version),
						Advisories: causes, Carried: []string{}, Outcome: root.Outcome, Detail: root.Line, Root: true, Class: class.Class})
				}
			}
		case ClassMissingEvidence:
			for _, gap := range report.Coverage {
				entry.Items = append(entry.Items, OutstandingItem{Name: gap.Name, Version: gap.Version, Advisories: []string{}, Carried: []string{}, Detail: gap.Gap, Class: class.Class})
			}
		}
		sort.SliceStable(entry.Items, func(i, j int) bool {
			a, b := entry.Items[i], entry.Items[j]
			if a.Name != b.Name {
				return a.Name < b.Name
			}
			return a.Version < b.Version
		})
		out = append(out, entry)
	}
	return out
}

func rootCausesOf(in Input, name, version string) []string {
	if in.Socket != nil {
		for _, root := range in.Socket.Roots {
			if root.Name == name && root.Version == version && root.Causes != nil {
				return root.Causes
			}
		}
	}
	return []string{}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
