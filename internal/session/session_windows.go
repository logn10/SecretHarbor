//go:build windows

package session

import (
	"os"
)

func isProcessAliveOS(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil || p == nil {
		return false
	}
	return true
}

func killProcessTreeOS(rootPID int, descendants []int) {
	for i := len(descendants) - 1; i >= 0; i-- {
		if p, err := os.FindProcess(descendants[i]); err == nil && p != nil {
			_ = p.Kill()
		}
	}
	if p, err := os.FindProcess(rootPID); err == nil && p != nil {
		_ = p.Kill()
	}
}

func getProcessIdentityOS(pid int) (startTime string, name string, err error) {
	return "", "", nil
}

func getProcessDescendantsOS(rootPID int) []int {
	return nil
}
