//go:build !linux

package projectlane

import "syscall"

// childAttributes puts the install command in a process group of its own. This
// platform has no parent-death signal: a killed transaction leaves its child
// running until it ends on its own.
func childAttributes() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}
