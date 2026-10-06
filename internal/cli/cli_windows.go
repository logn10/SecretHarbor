//go:build windows

package cli

import (
	"os"
	"syscall"
)

func getSysProcAttrSetsid() *syscall.SysProcAttr {
	return nil
}

func killProcess(pid int, sig syscall.Signal) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return proc.Kill()
}

func killProcessGroup(pgid int, sig syscall.Signal) error {
	return nil
}

func getProcessGroupID(pid int) (int, error) {
	return 0, nil
}

func getProcessGroup() int {
	return 0
}
