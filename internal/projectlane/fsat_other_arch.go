//go:build linux && !amd64 && !arm64 && !riscv64 && !loong64

package projectlane

// renameat2Number is unknown for this architecture: the transaction refuses
// (platform_unsupported) rather than publish without an atomic exchange.
const renameat2Number = 0

// statxNumber is the statx system call, which the stored baseline needs for the
// birth time of the project directory (0: unknown, so no identity can be established).
const statxNumber = 0
