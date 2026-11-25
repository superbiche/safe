//go:build linux

package projectlane

import "syscall"

func umaskCall(mask int) int { return syscall.Umask(mask) }
