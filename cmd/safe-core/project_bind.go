//go:build linux

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/superbiche/safe/internal/projectlane"
)

// project-bind is the binding transaction of the project lane; project-tree is
// its tree verifier, usable on its own. See internal/projectlane/transaction.go
// for the order of the steps and what each failure leaves on disk.
//
// The install command given after "--" is TRUSTED as the gate's delegate is:
// it runs with the installing user's filesystem access and its writes are not
// confined (no sandbox). What project-bind guarantees concerns the project:
// what lands in it is what was judged and verified. The document says so.
//
// project-bind exits:
//
//	0   published
//	2   usage
//	30  refused before anything ran (the document says why)
//	31  the install command failed (its own status is in the document)
//	32  the staged tree is not the judged one
//	33  a project input changed since it was judged
//	34  interrupted by a signal; the project is as it was
//	35  publication failed (the document says what state it left)
//
// project-tree exits 0 when the tree is the judged one, 32 when it is not (the
// document lists the problems), 30 for a lockfile it refuses (links), 3 for
// input that cannot be read and 2 for usage.

const (
	projectBindUsage = "safe-core: usage: safe-core project-bind --project <dir> (--lock-fd <n> | --take-lock)\n" +
		"    --publish <rel>=<judged-file>... --copy <rel>=<judged-file>... --live <rel>=(sha256:<hex>|absent)...\n" +
		"    --env-file <file> --state-dir <dir> [--omit dev|optional|peer]... --os <os> --cpu <cpu> [--libc <libc>] -- <absolute-command> [<arg>...]"
)

type bindArgs struct {
	project  string
	publish  []string
	copy     []string
	live     []string
	envFile  string
	stateDir string
	lockFD   int
	take     bool
	hasFD    bool
	argv     []string
	selected projectlaneSelection
}

func parseBindArgs(args []string) (bindArgs, bool) {
	parsed := bindArgs{lockFD: -1}
	for i := 0; i < len(args); i++ {
		if args[i] == "--" {
			parsed.argv = args[i+1:]
			break
		}
		if next, handled, ok := parseSelectionFlag(&parsed.selected, args, i); handled {
			if !ok {
				return bindArgs{}, false
			}
			i = next
			continue
		}
		switch args[i] {
		case "--take-lock":
			parsed.take = true
		case "--project", "--publish", "--copy", "--live", "--env-file", "--lock-fd", "--state-dir":
			if i+1 >= len(args) || args[i+1] == "" {
				return bindArgs{}, false
			}
			value := args[i+1]
			switch args[i] {
			case "--project":
				if parsed.project != "" {
					return bindArgs{}, false
				}
				parsed.project = value
			case "--publish":
				parsed.publish = append(parsed.publish, value)
			case "--copy":
				parsed.copy = append(parsed.copy, value)
			case "--live":
				parsed.live = append(parsed.live, value)
			case "--state-dir":
				if parsed.stateDir != "" {
					return bindArgs{}, false
				}
				parsed.stateDir = value
			case "--env-file":
				if parsed.envFile != "" {
					return bindArgs{}, false
				}
				parsed.envFile = value
			case "--lock-fd":
				fd, err := strconv.Atoi(value)
				if err != nil || fd < 3 || parsed.hasFD {
					return bindArgs{}, false
				}
				parsed.lockFD, parsed.hasFD = fd, true
			}
			i++
		default:
			return bindArgs{}, false
		}
	}
	if parsed.project == "" || parsed.envFile == "" || parsed.stateDir == "" || len(parsed.argv) == 0 ||
		parsed.hasFD == parsed.take || len(parsed.publish) == 0 || len(parsed.live) == 0 ||
		parsed.selected.os == "" || parsed.selected.cpu == "" {
		return bindArgs{}, false
	}
	return parsed, true
}

func splitPair(item string) (string, string, bool) {
	rel, value, ok := strings.Cut(item, "=")
	return rel, value, ok && rel != "" && value != ""
}

// readJudged reads a judged input file: a regular file, not a link.
func readJudged(name string) ([]byte, error) {
	info, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", name)
	}
	return os.ReadFile(name)
}

// parseEnvFile reads the child's whole environment: NUL-separated KEY=VALUE
// entries (the output of `env -0`). An empty file is an empty environment.
func parseEnvFile(raw []byte) ([]string, error) {
	env := []string{}
	seen := map[string]bool{}
	for _, entry := range bytes.Split(bytes.TrimSuffix(raw, []byte{0}), []byte{0}) {
		if len(entry) == 0 && len(raw) == 0 {
			break
		}
		key, _, ok := strings.Cut(string(entry), "=")
		if !ok || key == "" {
			return nil, fmt.Errorf("environment entry %q is not KEY=VALUE", string(entry))
		}
		if seen[key] {
			return nil, fmt.Errorf("environment variable %s is given twice", key)
		}
		seen[key] = true
		env = append(env, string(entry))
	}
	return env, nil
}

func projectBind(args []string, stdout, stderr io.Writer) int {
	parsed, ok := parseBindArgs(args)
	if !ok {
		fmt.Fprintln(stderr, projectBindUsage)
		return 2
	}
	request := projectlane.BindRequest{
		Project: parsed.project, StateDir: parsed.stateDir, Argv: parsed.argv, Selection: parsed.selected.selection(),
		Live: map[string]string{}, ChildOutput: stderr,
		Lock: projectlane.LockMode{FD: parsed.lockFD, Take: parsed.take},
	}
	unusable := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "safe-core: project-bind: "+format+"\n", a...)
		return 3
	}
	for _, group := range []struct {
		items []string
		dst   *[]projectlane.File
	}{{parsed.publish, &request.Publish}, {parsed.copy, &request.Copy}} {
		for _, item := range group.items {
			rel, source, ok := splitPair(item)
			if !ok {
				fmt.Fprintln(stderr, projectBindUsage)
				return 2
			}
			content, err := readJudged(source)
			if err != nil {
				return unusable("judged input %s: %v", rel, err)
			}
			*group.dst = append(*group.dst, projectlane.File{Rel: rel, Content: content})
		}
	}
	for _, item := range parsed.live {
		rel, digest, ok := splitPair(item)
		if !ok {
			fmt.Fprintln(stderr, projectBindUsage)
			return 2
		}
		if _, dup := request.Live[rel]; dup {
			fmt.Fprintln(stderr, projectBindUsage)
			return 2
		}
		request.Live[rel] = digest
	}
	rawEnv, err := os.ReadFile(parsed.envFile)
	if err != nil {
		return unusable("environment file: %v", err)
	}
	if request.Env, err = parseEnvFile(rawEnv); err != nil {
		return unusable("environment file: %v", err)
	}

	// Signals: before publication one ends the run and leaves the project as
	// it was; the transaction defers it during publication.
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	defer signal.Stop(signals)
	go func() {
		if sig, ok := <-signals; ok {
			cancel(fmt.Errorf("%s", sig))
		}
	}()

	report := projectlane.Bind(ctx, request)
	if code := printJSON(stdout, "project-bind", stderr, report); code != 0 {
		return code
	}
	return report.Exit
}
