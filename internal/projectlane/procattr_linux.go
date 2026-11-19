package projectlane

import "syscall"

// childAttributes puts the install command in a process group of its own, so
// that the transaction can end everything it started, and has the kernel kill
// it if this process dies (a SIGKILL included): nothing keeps writing into a
// staging directory nobody owns.
func childAttributes() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
}
