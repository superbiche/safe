package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/superbiche/safe/internal/projectlane"
)

// project-lockfile-admit <lockfile> runs the binder's own lockfile admission on a
// lockfile that has not been judged yet (the one on disk, before npm reads it): the
// lockfile reads strictly, every key is a chain of package segments inside the tree,
// and no entry is a link. Exits 0 (admitted), 30 (refused: "<reason>: <detail>" on
// stderr; reason lockfile_unreadable means it cannot be read at all), 3 (unreadable
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
	if reason, detail := projectlane.AdmitLockfile(raw); reason != "" {
		fmt.Fprintf(stderr, "%s: %s\n", reason, detail)
		return 30
	}
	return 0
}

// git-tree-entry --hash-bytes <20|32> --name <name> reads one raw tree object (the
// output of `git cat-file tree <id>`) on stdin and prints "<raw mode> <hex id>" for
// the entry of that exact name. git shows a CANONICAL mode (100664 as 100644); the
// raw mode is what the tree holds. Exits 0 (found), 4 (no such entry), 3 (the object
// is not a well-formed tree), 2 (usage).
const gitTreeEntryUsage = "safe-core: usage: safe-core git-tree-entry --hash-bytes <20|32> --name <name> < tree"

func gitTreeEntry(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) != 4 || args[0] != "--hash-bytes" || args[2] != "--name" || args[3] == "" {
		fmt.Fprintln(stderr, gitTreeEntryUsage)
		return 2
	}
	size, err := strconv.Atoi(args[1])
	if err != nil || (size != 20 && size != 32) {
		fmt.Fprintln(stderr, gitTreeEntryUsage)
		return 2
	}
	raw, err := io.ReadAll(io.LimitReader(stdin, 64<<20))
	if err != nil {
		fmt.Fprintf(stderr, "safe-core: git-tree-entry: %v\n", err)
		return 3
	}
	want := []byte(args[3])
	found := false
	var foundMode, foundID string
	for len(raw) > 0 {
		space := bytes.IndexByte(raw, ' ')
		if space <= 0 {
			fmt.Fprintln(stderr, "safe-core: git-tree-entry: malformed tree")
			return 3
		}
		mode := raw[:space]
		raw = raw[space+1:]
		nul := bytes.IndexByte(raw, 0)
		if nul <= 0 || len(raw) < nul+1+size {
			fmt.Fprintln(stderr, "safe-core: git-tree-entry: malformed tree")
			return 3
		}
		name := raw[:nul]
		id := raw[nul+1 : nul+1+size]
		raw = raw[nul+1+size:]
		if bytes.Equal(name, want) {
			if found {
				fmt.Fprintln(stderr, "safe-core: git-tree-entry: the entry is named twice")
				return 3
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
