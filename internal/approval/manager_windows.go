//go:build windows

package approval

func pauseProcess(pid int) {
	// Process suspension via signals is unsupported on Windows
}

func resumeProcess(pid int) {
	// Process resumption via signals is unsupported on Windows
}

func isDescendantOf(childPID, ancestorPID int) bool {
	return childPID > 0 && childPID == ancestorPID
}
