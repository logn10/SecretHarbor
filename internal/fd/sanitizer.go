package fd

import (
	"errors"
	"fmt"
	"syscall"
)

// GetOpenFDs returns a list of currently open file descriptor numbers for this process.
func GetOpenFDs() ([]int, error) {
	return getPlatformOpenFDs()
}

// CloseUnexpectedFDs closes inherited open file descriptors >= 3 (except stdin, stdout, stderr,
// and descriptors in keepFDs) so that the child process does not inherit unexpected parent descriptors.
func CloseUnexpectedFDs(keepFDs []int) error {
	keepMap := map[int]bool{
		0: true, // stdin
		1: true, // stdout
		2: true, // stderr
	}
	for _, k := range keepFDs {
		keepMap[k] = true
	}

	fds, err := GetOpenFDs()
	if err != nil {
		// Fallback: scan up to max fds
		maxFD := getMaxFDs()
		for fd := 3; fd < maxFD; fd++ {
			if !keepMap[fd] {
				if isInheritedFD(fd) {
					if err := closeFD(fd); err != nil && !isIgnorableCloseErr(err) {
						return fmt.Errorf("failed to close inherited fd %d: %w", fd, err)
					}
				} else {
					if err := SetCloseOnExec(fd); err != nil && !isIgnorableCloseErr(err) {
						return fmt.Errorf("failed to set FD_CLOEXEC on fd %d: %w", fd, err)
					}
				}
			}
		}
		return nil
	}

	for _, fd := range fds {
		if fd >= 3 && !keepMap[fd] {
			if isInheritedFD(fd) {
				if err := closeFD(fd); err != nil && !isIgnorableCloseErr(err) {
					return fmt.Errorf("failed to close inherited fd %d: %w", fd, err)
				}
			} else {
				if err := SetCloseOnExec(fd); err != nil && !isIgnorableCloseErr(err) {
					return fmt.Errorf("failed to set FD_CLOEXEC on fd %d: %w", fd, err)
				}
			}
		}
	}

	return nil
}

// SanitizeFDs ensures all file descriptors >= 3 have FD_CLOEXEC set so that
// they are atomically closed by the kernel when the child process is executed.
func SanitizeFDs(keepFDs []int) error {
	keepMap := map[int]bool{
		0: true, // stdin
		1: true, // stdout
		2: true, // stderr
	}
	for _, k := range keepFDs {
		keepMap[k] = true
	}

	fds, err := GetOpenFDs()
	if err != nil {
		// Fallback: apply FD_CLOEXEC up to max fds
		maxFD := getMaxFDs()
		for fd := 3; fd < maxFD; fd++ {
			if !keepMap[fd] {
				if err := SetCloseOnExec(fd); err != nil && !isIgnorableCloseErr(err) {
					return fmt.Errorf("failed to set FD_CLOEXEC on fd %d: %w", fd, err)
				}
			}
		}
		return nil
	}

	for _, fd := range fds {
		if fd >= 3 && !keepMap[fd] {
			if err := SetCloseOnExec(fd); err != nil && !isIgnorableCloseErr(err) {
				return fmt.Errorf("failed to set FD_CLOEXEC on fd %d: %w", fd, err)
			}
		}
	}

	return nil
}

func isIgnorableCloseErr(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, syscall.EBADF) || errors.Is(err, syscall.EINVAL) {
		return true
	}
	return false
}
