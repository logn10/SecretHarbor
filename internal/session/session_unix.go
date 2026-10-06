//go:build !windows

package session

import (
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func isProcessAliveOS(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	// err == nil means process exists and caller can signal it.
	// err == EPERM means process exists but caller has restricted permissions.
	// err == ESRCH means no such process exists.
	return err == nil || err == syscall.EPERM
}

func killProcessTreeOS(rootPID int, descendants []int) {
	// Send SIGCONT and SIGTERM to descendants first (deepest first), then root
	for i := len(descendants) - 1; i >= 0; i-- {
		_ = syscall.Kill(descendants[i], syscall.SIGCONT)
		_ = syscall.Kill(descendants[i], syscall.SIGTERM)
	}
	_ = syscall.Kill(rootPID, syscall.SIGCONT)
	_ = syscall.Kill(rootPID, syscall.SIGTERM)

	// Brief grace period for clean exit
	time.Sleep(100 * time.Millisecond)

	// Escalate to SIGKILL for any remaining stubborn processes
	for i := len(descendants) - 1; i >= 0; i-- {
		if err := syscall.Kill(descendants[i], 0); err == nil {
			_ = syscall.Kill(descendants[i], syscall.SIGKILL)
		}
	}
	if err := syscall.Kill(rootPID, 0); err == nil {
		_ = syscall.Kill(rootPID, syscall.SIGKILL)
	}
}

func getProcessIdentityOS(pid int) (startTime string, name string, err error) {
	if pid <= 0 {
		return "", "", nil
	}
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "lstart=,comm=").Output()
	if err != nil {
		return "", "", err
	}
	str := strings.TrimSpace(string(out))
	if len(str) >= 24 {
		return strings.TrimSpace(str[:24]), strings.TrimSpace(str[24:]), nil
	}
	return "", str, nil
}

func getProcessDescendantsOS(rootPID int) []int {
	if rootPID <= 0 {
		return nil
	}
	out, err := exec.Command("ps", "-e", "-o", "pid=,ppid=").Output()
	if err != nil {
		return nil
	}

	parentMap := make(map[int][]int)
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			pid, err1 := strconv.Atoi(fields[0])
			ppid, err2 := strconv.Atoi(fields[1])
			if err1 == nil && err2 == nil {
				parentMap[ppid] = append(parentMap[ppid], pid)
			}
		}
	}

	var descendants []int
	queue := []int{rootPID}
	visited := make(map[int]bool)
	visited[rootPID] = true

	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		for _, child := range parentMap[curr] {
			if !visited[child] {
				visited[child] = true
				descendants = append(descendants, child)
				queue = append(queue, child)
			}
		}
	}
	return descendants
}
