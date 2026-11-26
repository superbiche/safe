package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/superbiche/safe/internal/projectlane"
)

// project-scan-summary reads the result document of the project scan and prints the summary a report may keep (counts per ecosystem of
// the known set, scanner names), never the scan's free text. Exits 0 with the summary, 3 when the document carries no verdict or cannot
// be read, 2 for usage.
const projectScanSummaryUsage = "safe-core: usage: safe-core project-scan-summary --result <file>"

func projectScanSummary(args []string, stdout, stderr io.Writer) int {
	if len(args) != 2 || args[0] != "--result" || args[1] == "" {
		fmt.Fprintln(stderr, projectScanSummaryUsage)
		return 2
	}
	file, err := os.OpenFile(args[1], os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		fmt.Fprintln(stderr, "safe-core: project-scan-summary: the result cannot be opened")
		return 3
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 16<<20 {
		fmt.Fprintln(stderr, "safe-core: project-scan-summary: the result is not a regular file within bounds")
		return 3
	}
	raw, err := io.ReadAll(io.LimitReader(file, 16<<20+1))
	if err != nil {
		fmt.Fprintln(stderr, "safe-core: project-scan-summary: the result cannot be read")
		return 3
	}
	summary, err := projectlane.ReadScanSummary(raw)
	if err != nil {
		fmt.Fprintln(stderr, "safe-core: project-scan-summary: the result carries no verdict")
		return 3
	}
	encoded, err := json.Marshal(summary)
	if err != nil {
		return 3
	}
	fmt.Fprintln(stdout, string(encoded))
	return 0
}
