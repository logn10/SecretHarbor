//go:build !windows

package fd

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"syscall"
)

func getPlatformOpenFDs() ([]int, error) {
	fdDir := "/proc/self/fd"
	if runtime.GOOS == "darwin" || runtime.GOOS == "freebsd" {
		fdDir = "/dev/fd"
	}

	f, err := os.Open(fdDir)
	if err != nil {
		return nil, fmt.Errorf("failed to open fd directory %s: %w", fdDir, err)
	}
	defer f.Close()

	names, err := f.Readdirnames(-1)
	if err != nil {
		return nil, fmt.Errorf("failed to read fd directory %s: %w", fdDir, err)
	}

	dirFD := int(f.Fd())

	var fds []int
	for _, name := range names {
		num, err := strconv.Atoi(name)
		if err == nil && num != dirFD {
			fds = append(fds, num)
		}
	}
	return fds, nil
}

func getMaxFDs() int {
	maxFD := 1024
	var rlim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlim); err == nil {
		if rlim.Cur > 0 && rlim.Cur < 65536 {
			maxFD = int(rlim.Cur)
		} else if rlim.Cur >= 65536 {
			maxFD = 65536
		}
	}
	return maxFD
}

// isInheritedFD returns true if fd does NOT have FD_CLOEXEC set,
// which indicates it was inherited from the parent process.
func isInheritedFD(fd int) bool {
	flags, _, err := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
	if err != 0 {
		return false
	}
	return (flags & syscall.FD_CLOEXEC) == 0
}

// SetCloseOnExec sets the FD_CLOEXEC flag on a given file descriptor using SYS_FCNTL.
func SetCloseOnExec(fd int) error {
	_, _, err := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_SETFD, syscall.FD_CLOEXEC)
	if err != 0 {
		return fmt.Errorf("failed to set FD_CLOEXEC on fd %d: %w", fd, err)
	}
	return nil
}

func closeFD(fd int) error {
	return syscall.Close(fd)
}
