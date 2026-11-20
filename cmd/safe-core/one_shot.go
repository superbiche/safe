package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/superbiche/safe/internal/projectlane"
)

// safe-core one-shot-store <check|list|resolve|add|remove> --home <dir> …
//
// The one reader and the one writer of the operator's standing decision per project (ticket 1686). Exit statuses of `check`:
// 0 pinned and honoured, 1 not pinned (anything untrusted included), 2 pinned but the directory was replaced.
func oneShotStore(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "safe-core: one-shot-store: a subcommand is needed (check, list, resolve, add, remove)")
		return 2
	}
	verb, rest := args[0], args[1:]
	home := ""
	project := ""
	needManifest := false
	var operands []string
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case "--home":
			if i+1 >= len(rest) {
				fmt.Fprintln(stderr, "safe-core: one-shot-store: --home needs a value")
				return 2
			}
			home = rest[i+1]
			i++
		case "--project":
			if i+1 >= len(rest) {
				fmt.Fprintln(stderr, "safe-core: one-shot-store: --project needs a value")
				return 2
			}
			project = rest[i+1]
			i++
		case "--need-manifest":
			needManifest = true
		case "--":
			operands = append(operands, rest[i+1:]...)
			i = len(rest)
		default:
			operands = append(operands, rest[i])
		}
	}
	store := projectlane.OneShotStore{Home: home}
	emit := func(value any) int {
		raw, err := json.Marshal(value)
		if err != nil {
			fmt.Fprintln(stderr, "safe-core: one-shot-store:", err)
			return 1
		}
		fmt.Fprintln(stdout, string(raw))
		return 0
	}
	switch verb {
	case "check":
		return store.Check(project)
	case "list":
		rows, err := store.List()
		if err != nil {
			fmt.Fprintln(stderr, "safe-core: one-shot-store:", err)
			return 3
		}
		return emit(rows)
	case "resolve":
		plans, err := projectlane.Resolve(operands, needManifest)
		if err != nil {
			fmt.Fprintln(stderr, "safe-core: one-shot-store:", err)
			return 1
		}
		return emit(plans)
	case "add":
		var plans []projectlane.OneShotPlan
		decoder := json.NewDecoder(stdin)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&plans); err != nil || len(plans) == 0 {
			fmt.Fprintln(stderr, "safe-core: one-shot-store: add reads the plan resolve printed, on standard input")
			return 2
		}
		if err := store.Add(plans); err != nil {
			fmt.Fprintln(stderr, "safe-core: one-shot-store:", err)
			return 1
		}
		return emit(plans)
	case "remove":
		if len(operands) == 0 {
			fmt.Fprintln(stderr, "safe-core: one-shot-store: remove needs a project")
			return 2
		}
		removed, err := store.Remove(operands)
		if err != nil {
			fmt.Fprintln(stderr, "safe-core: one-shot-store:", err)
			return 1
		}
		return emit(removed)
	}
	fmt.Fprintf(stderr, "safe-core: one-shot-store: unknown subcommand %q\n", verb)
	return 2
}
