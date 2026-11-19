//go:build linux && !amd64 && !arm64 && !riscv64 && !loong64

package projectlane

// renameat2Number is unknown for this architecture: the transaction refuses
// (platform_unsupported) rather than publish without an atomic exchange.
const renameat2Number = 0
