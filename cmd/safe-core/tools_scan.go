package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/superbiche/safe/internal/toolscan"
)

const toolsScanUsage = "safe-core: usage: safe-core tools-scan --cache-dir <dir> [--publish [--out <file>]] [--host <name>] [--dir <dir>] [--mise <bin>] [--syft <bin>] [--grype <bin>]"

// toolsScan prints the report, or with --publish writes it to the Sync/state
// bus and prints nothing: the operator reads it where Vigie surfaces it.
// A report carrying an error is still written, then exits 3.
func toolsScan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tools-scan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cacheDir := fs.String("cache-dir", "", "")
	publish := fs.Bool("publish", false, "")
	out := fs.String("out", "", "")
	host := fs.String("host", "", "")
	dir := fs.String("dir", "", "")
	miseBin := fs.String("mise", "", "")
	syftBin := fs.String("syft", "", "")
	grypeBin := fs.String("grype", "", "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *cacheDir == "" || (*out != "" && !*publish) {
		fmt.Fprintln(stderr, toolsScanUsage)
		return 2
	}

	home, _ := os.UserHomeDir()
	if *host == "" {
		h, err := os.Hostname()
		if err != nil || h == "" {
			fmt.Fprintf(stderr, "safe-core: tools-scan: cannot name this host: %v\n", err)
			return 3
		}
		*host, _, _ = strings.Cut(h, ".")
	}
	if *dir == "" {
		*dir = home
	}
	if *publish && *out == "" {
		if home == "" {
			fmt.Fprintln(stderr, "safe-core: tools-scan: no home directory for the default --out")
			return 3
		}
		*out = filepath.Join(home, "Sync", "state", "tool-vulns", *host+".json")
	}

	r := toolscan.Scan(context.Background(), toolscan.Options{
		Mise:     lookPath(*miseBin, "mise"),
		Syft:     lookPath(*syftBin, "syft"),
		Grype:    lookPath(*grypeBin, "grype"),
		Dir:      *dir,
		CacheDir: *cacheDir,
		Host:     *host,
		Producer: "safe-core " + version,
		Now:      time.Now,
	})

	if *publish {
		if err := toolscan.Publish(r, *out); err != nil {
			fmt.Fprintf(stderr, "safe-core: tools-scan: publish %s: %v\n", *out, err)
			return 3
		}
	} else {
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(r); err != nil {
			fmt.Fprintf(stderr, "safe-core: tools-scan: write JSON: %v\n", err)
			return 3
		}
	}
	if r.Error != nil {
		fmt.Fprintf(stderr, "safe-core: tools-scan: %s\n", *r.Error)
		return 3
	}
	return 0
}

// An unresolved tool stays empty; Scan reports it as missing.
func lookPath(explicit, name string) string {
	if explicit != "" {
		return explicit
	}
	p, err := exec.LookPath(name)
	if err != nil {
		return ""
	}
	return p
}
