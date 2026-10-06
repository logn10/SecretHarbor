//go:build windows

package fd

func getPlatformOpenFDs() ([]int, error) {
	return nil, nil
}

func getMaxFDs() int {
	return 0
}

func isInheritedFD(fd int) bool {
	return false
}

// SetCloseOnExec is a stub on Windows where Unix file descriptors do not exist.
func SetCloseOnExec(fd int) error {
	return nil
}

func closeFD(fd int) error {
	return nil
}
