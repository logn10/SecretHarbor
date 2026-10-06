//go:build !windows

package approval

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

func pauseProcess(pid int) {
	if pid <= 0 {
		return
	}
	pgid, err := syscall.Getpgid(pid)
	if err == nil && pgid > 1 {
		if err := syscall.Kill(-pgid, syscall.SIGSTOP); err != nil {
			_ = syscall.Kill(pid, syscall.SIGSTOP)
		}
	} else {
		_ = syscall.Kill(pid, syscall.SIGSTOP)
	}
}

func resumeProcess(pid int) {
	if pid <= 0 {
		return
	}
	pgid, err := syscall.Getpgid(pid)
	if err == nil && pgid > 1 {
		if err := syscall.Kill(-pgid, syscall.SIGCONT); err != nil {
			_ = syscall.Kill(pid, syscall.SIGCONT)
		}
	} else {
		_ = syscall.Kill(pid, syscall.SIGCONT)
	}
}

func getProcessPPID(pid int) int {
	if pid <= 1 {
		return 0
	}
	// Fast path for Linux: /proc/<pid>/stat
	if statBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); err == nil {
		// Format: pid (comm) state ppid ...
		s := string(statBytes)
		if idx := strings.LastIndex(s, ")"); idx != -1 && len(s) > idx+2 {
			fields := strings.Fields(s[idx+2:])
			if len(fields) >= 2 {
				if ppid, err := strconv.Atoi(fields[1]); err == nil {
					return ppid
				}
			}
		}
	}
	out, err := exec.Command("ps", "-o", "ppid=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return 0
	}
	ppid, _ := strconv.Atoi(strings.TrimSpace(string(out)))
	return ppid
}

func isDescendantOf(childPID, ancestorPID int) bool {
	if childPID <= 0 || ancestorPID <= 0 {
		return false
	}
	if childPID == ancestorPID {
		return true
	}
	curr := childPID
	for depth := 0; depth < 50; depth++ {
		ppid := getProcessPPID(curr)
		if ppid <= 1 || ppid == curr {
			break
		}
		if ppid == ancestorPID {
			return true
		}
		curr = ppid
	}
	return false
}
