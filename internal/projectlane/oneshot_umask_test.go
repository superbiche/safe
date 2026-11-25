//go:build linux

package projectlane

import "syscall"

func umaskCall(mask int) int { return syscall.Umask(mask) }

func syscallMkfifo(path string) error { return syscall.Mkfifo(path, 0o600) }
