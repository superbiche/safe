//go:build !linux

package main

import (
	"fmt"
	"io"
)

const projectBindUsage = "safe-core: project-bind is only available on Linux"

// projectBind refuses on platforms without the descriptor-relative filesystem
// operations the transaction is built on.
func projectBind(_ []string, _, stderr io.Writer) int {
	fmt.Fprintln(stderr, projectBindUsage)
	return 2
}
