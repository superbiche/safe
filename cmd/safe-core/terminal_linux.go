//go:build linux

package main

import (
	"os"
	"syscall"
	"unsafe"
)

// isTerminal reports whether the file is a terminal (TCGETS answers).
func isTerminal(file *os.File) bool {
	var termios [64]byte
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&termios[0])))
	return errno == 0
}
