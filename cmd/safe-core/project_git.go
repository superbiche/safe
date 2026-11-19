package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/superbiche/safe/internal/projectlane"
)

// project-lockfile-admit <lockfile> runs the binder's own lockfile admission on a
// lockfile that has not been judged yet (the one on disk, before npm reads it): the
// lockfile reads strictly, every key is a chain of package segments inside the tree,
// and no entry is a link. Exits 0 (admitted), 30 (refused: EVERY reason, one "<reason>: <detail>"
// line each, on stderr; reason lockfile_unreadable means it cannot be read at all), 3 (unreadable
// input), 2 (usage).
const projectLockfileAdmitUsage = "safe-core: usage: safe-core project-lockfile-admit <lockfile>"

func projectLockfileAdmit(args []string, _, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, projectLockfileAdmitUsage)
		return 2
	}
	info, err := os.Lstat(args[0])
	if err != nil || !info.Mode().IsRegular() {
		fmt.Fprintln(stderr, "safe-core: project-lockfile-admit: not a regular file")
		return 3
	}
	raw, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "safe-core: project-lockfile-admit: %v\n", err)
		return 3
	}
	if findings := projectlane.AdmitLockfileFindings(raw); len(findings) > 0 {
		for _, finding := range findings {
			fmt.Fprintf(stderr, "%s: %s\n", finding.Reason, finding.Detail)
		}
		return 30
	}
	return 0
}

// git-tree-entry --hash-bytes <20|32> --name <name> [--max-bytes <n>] reads one raw tree object
// (the output of `git cat-file tree <id>`) on stdin and prints "<raw mode> <hex id>" for the
// entry of that exact name. git shows a CANONICAL mode (100664 as 100644); the raw mode is what
// the tree holds. Every entry walked is validated (an octal mode of at most six digits, a
// non-empty name with no slash, the whole id present): the first malformed one makes the
// object unreadable. An object larger than the reader accepts (default 64 MiB) is NOT cut
// short: it is refused, because the unread rest could hold the entry or a second one. Exits 0
// (found), 4 (no such entry, the whole object having been read and checked), 3 (the object is
// not a well-formed tree, or is too large to be read whole), 2 (usage).
const gitTreeEntryUsage = "safe-core: usage: safe-core git-tree-entry --hash-bytes <20|32> --name <name> [--max-bytes <n>] < tree"

const gitTreeDefaultMax = 64 << 20

func gitTreeEntry(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	max := int64(gitTreeDefaultMax)
	if len(args) == 6 && args[4] == "--max-bytes" {
		n, err := strconv.ParseInt(args[5], 10, 64)
		if err != nil || n < 1 {
			fmt.Fprintln(stderr, gitTreeEntryUsage)
			return 2
		}
		max = n
		args = args[:4]
	}
	if len(args) != 4 || args[0] != "--hash-bytes" || args[2] != "--name" || args[3] == "" {
		fmt.Fprintln(stderr, gitTreeEntryUsage)
		return 2
	}
	size, err := strconv.Atoi(args[1])
	if err != nil || (size != 20 && size != 32) {
		fmt.Fprintln(stderr, gitTreeEntryUsage)
		return 2
	}
	raw, err := io.ReadAll(io.LimitReader(stdin, max+1))
	if err != nil {
		fmt.Fprintf(stderr, "safe-core: git-tree-entry: %v\n", err)
		return 3
	}
	if int64(len(raw)) > max {
		fmt.Fprintf(stderr, "safe-core: git-tree-entry: the tree is larger than %d bytes and cannot be read whole\n", max)
		return 3
	}
	malformed := func(why string) int {
		fmt.Fprintf(stderr, "safe-core: git-tree-entry: malformed tree (%s)\n", why)
		return 3
	}
	want := []byte(args[3])
	found := false
	var foundMode, foundID string
	for len(raw) > 0 {
		space := bytes.IndexByte(raw, ' ')
		if space < 5 || space > 6 {
			return malformed("a mode of the wrong length")
		}
		mode := raw[:space]
		for _, digit := range mode {
			if digit < '0' || digit > '7' {
				return malformed("a mode that is not octal")
			}
		}
		raw = raw[space+1:]
		nul := bytes.IndexByte(raw, 0)
		if nul <= 0 || len(raw) < nul+1+size {
			return malformed("an entry cut short")
		}
		name := raw[:nul]
		if bytes.IndexByte(name, '/') >= 0 {
			return malformed("a name with a slash")
		}
		id := raw[nul+1 : nul+1+size]
		raw = raw[nul+1+size:]
		if bytes.Equal(name, want) {
			if found {
				return malformed("the entry is named twice")
			}
			found, foundMode, foundID = true, string(mode), fmt.Sprintf("%x", id)
		}
	}
	if !found {
		return 4
	}
	fmt.Fprintf(stdout, "%s %s\n", foundMode, foundID)
	return 0
}

// exact-versions reads {"packages":[{"name":...,"version":...},...]} on stdin and checks that
// every version is an exact semantic version, the WHOLE string (the grammar of the binder's
// own check; no line-anchored pattern, no embedded newline). Exits 0, 30 (the first offender
// is named on stderr), 3 (not that document), 2 (usage).
const exactVersionsUsage = "safe-core: usage: safe-core exact-versions < request.json"

func exactVersions(args []string, stdin io.Reader, _, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, exactVersionsUsage)
		return 2
	}
	var request struct {
		Packages []struct {
			Name    *string `json:"name"`
			Version *string `json:"version"`
		} `json:"packages"`
	}
	raw, err := io.ReadAll(io.LimitReader(stdin, 256<<20))
	if err != nil || json.Unmarshal(raw, &request) != nil {
		fmt.Fprintln(stderr, "safe-core: exact-versions: not a request document")
		return 3
	}
	for _, pkg := range request.Packages {
		if pkg.Name == nil || pkg.Version == nil {
			fmt.Fprintln(stderr, "safe-core: exact-versions: an identity without a name or a version")
			return 3
		}
		if !projectlane.ExactVersion(*pkg.Version) {
			fmt.Fprintf(stderr, "safe-core: exact-versions: %q is not an exact version\n", *pkg.Name)
			return 30
		}
	}
	return 0
}
