//go:build !windows

package cli

import (
	"syscall"
)

func getSysProcAttrSetsid() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setsid: true,
	}
}

func killProcess(pid int, sig syscall.Signal) error {
	return syscall.Kill(pid, sig)
}

func killProcessGroup(pgid int, sig syscall.Signal) error {
	return syscall.Kill(-pgid, sig)
}

func getProcessGroupID(pid int) (int, error) {
	return syscall.Getpgid(pid)
}

func getProcessGroup() int {
	return syscall.Getpgrp()
}
