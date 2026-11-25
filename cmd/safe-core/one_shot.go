package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"unsafe"

	"github.com/superbiche/safe/internal/projectlane"
)

// safe-core one-shot-store <check|verify-root|list|add|remove> [--home <dir>] …
//
// The one reader and the one writer of the operator's standing decision per project (ticket 1690). `add` and `remove` check the
// operator's terminal THEMSELVES, before they touch the store, then resolve, show, ask and commit in this one invocation: a
// caller with an agent marker or without a terminal on stdin gets 102 and a cold home stays untouched. The shell subcommand only
// delegates and reports.
//
// Exit statuses. check: 0 a directory here or above is pinned, 1 none, 2 a stored path is here but another directory stands on it.
// verify-root (npm's `npm root` output on stdin): 0 honoured, 1 not. list: 0, 3 the store cannot be trusted. add/remove: 0
// committed, 1 declined or NOT recorded, 4 committed and visible but durability uncertain, 102 no operator terminal or a failed
// terminal read, 2 usage.

// operatorMarkers are the recognized agent sessions: byte-for-byte the markers of safe_gate_operator_terminal in lib/gate-lib.sh
// and bin/safe-run (tests/contract/drift.sh keeps the three lists together).
var operatorMarkers = []string{"CODEX_THREAD_ID", "CODEX_CI", "CLAUDECODE", "OPENCODE"}

// isTerminal reports whether the file is a terminal.
func isTerminal(file *os.File) bool {
	var termios [64]byte
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&termios[0])))
	return errno == 0
}

// operatorTerminal: stdin is a terminal and no recognized agent marker is set (the 2026-11-02 predicate).
func operatorTerminal(stdin io.Reader, getenv func(string) string) bool {
	file, ok := stdin.(*os.File)
	if !ok || !isTerminal(file) {
		return false
	}
	for _, name := range operatorMarkers {
		if getenv(name) != "" {
			return false
		}
	}
	return true
}

// ttyPrinter writes what the operator must read to stderr when that is the terminal, else to /dev/tty (a parent that captured
// stderr cannot hide the question).
func ttyPrinter(stderr io.Writer) io.Writer {
	if file, ok := stderr.(*os.File); ok && isTerminal(file) {
		return file
	}
	if tty, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0); err == nil {
		return tty
	}
	return stderr
}

func oneShotStore(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "safe-core: one-shot-store: a subcommand is needed (check, verify-root, list, add, remove)")
		return 2
	}
	verb, rest := args[0], args[1:]
	home := os.Getenv("HOME")
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
		case "--":
			operands = append(operands, rest[i+1:]...)
			i = len(rest)
		default:
			operands = append(operands, rest[i])
		}
	}
	store := projectlane.OneShotStore{Home: home}
	switch verb {
	case "check":
		return store.CheckHere()
	case "verify-root":
		raw, err := io.ReadAll(io.LimitReader(stdin, 4097))
		if err != nil || len(raw) > 4096 {
			return projectlane.OneShotNotPin
		}
		return store.VerifyRoot(raw)
	case "list":
		rows, err := store.List()
		if err != nil {
			fmt.Fprintln(stderr, "safe-core: one-shot-store: the store cannot be trusted:", err)
			return 3
		}
		raw, _ := json.Marshal(rows)
		fmt.Fprintln(stdout, string(raw))
		return 0
	case "add", "remove":
		return oneShotChange(verb, store, operands, stdin, stdout, stderr)
	}
	fmt.Fprintf(stderr, "safe-core: one-shot-store: unknown subcommand %q\n", verb)
	return 2
}

func oneShotChange(verb string, store projectlane.OneShotStore, operands []string, stdin io.Reader, stdout, stderr io.Writer) int {
	// FIRST, before anything is resolved, read or created: the operator's terminal.
	if !operatorTerminal(stdin, os.Getenv) {
		fmt.Fprintf(stderr, "safe-core: one-shot-store %s requires an interactive operator terminal (stdin a terminal, no agent session)\n", verb)
		return 102
	}
	if len(operands) == 0 {
		operands = []string{"."}
	}
	out := ttyPrinter(stderr)
	var shown []string
	var plans []projectlane.OneShotPlan
	if verb == "add" {
		resolved, err := projectlane.Resolve(operands, true)
		if err != nil {
			fmt.Fprintln(stderr, "safe-core: one-shot-store:", err)
			return 1
		}
		plans = resolved
		for _, plan := range plans {
			raw, _ := json.Marshal(plan.Path)
			shown = append(shown, fmt.Sprintf("  %s  (device %d, inode %d)", raw, plan.Dev, plan.Inode))
		}
		fmt.Fprintln(out, "safe run: these projects will take the one-shot route for every npm command (the lane is off for them):")
	} else {
		keys, err := store.RemoveKeys(operands)
		if err != nil {
			fmt.Fprintln(stderr, "safe-core: one-shot-store:", err)
			return 1
		}
		for _, key := range keys {
			raw, _ := json.Marshal(key)
			shown = append(shown, "  "+string(raw))
		}
		fmt.Fprintln(out, "safe run: these projects will take the lane again:")
	}
	for _, line := range shown {
		fmt.Fprintln(out, line)
	}
	if verb == "add" {
		fmt.Fprintln(out, "safe run: today's gate runs their npm commands and the closure of a project install is NOT judged on that route (dedupe and prune go to the older differential path).")
		fmt.Fprint(out, "safe run: put them on the one-shot route? [y/N] ")
	} else {
		fmt.Fprint(out, "safe run: withdraw them? [y/N] ")
	}
	var answer string
	tty, err := os.Open("/dev/tty")
	if err == nil {
		defer tty.Close()
		line, rerr := bufio.NewReader(tty).ReadString('\n')
		if rerr != nil && line == "" {
			err = rerr
		}
		answer = trimLine(line)
	}
	if err != nil {
		fmt.Fprintln(stderr, "\nsafe-core: one-shot-store: no answer could be read from your terminal (end of input): nothing was recorded")
		return 102
	}
	if answer != "y" && answer != "Y" {
		fmt.Fprintln(stderr, "safe-core: one-shot-store: cancelled: nothing was recorded")
		return 1
	}
	var committed any
	var cerr error
	if verb == "add" {
		cerr = store.Add(plans)
		committed = plans
	} else {
		var removed []string
		removed, cerr = store.Remove(operands)
		committed = removed
	}
	if cerr != nil && !errors.Is(cerr, projectlane.ErrDurabilityUncertain) {
		fmt.Fprintln(stderr, "safe-core: one-shot-store:", cerr)
		return 1
	}
	raw, _ := json.Marshal(committed)
	fmt.Fprintln(stdout, string(raw))
	if cerr != nil {
		fmt.Fprintln(stderr, "safe-core: one-shot-store:", cerr)
		return 4
	}
	return 0
}

func trimLine(line string) string {
	for len(line) > 0 && (line[len(line)-1] == '\n' || line[len(line)-1] == '\r') {
		line = line[:len(line)-1]
	}
	return line
}
