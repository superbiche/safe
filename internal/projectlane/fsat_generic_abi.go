//go:build linux && (arm64 || riscv64 || loong64)

package projectlane

const renameat2Number = 276

// statxNumber is the statx system call, which the stored baseline needs for the
// birth time of the project directory (0: unknown, so no identity can be established).
const statxNumber = 291
