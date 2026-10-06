package fd

import (
	"os"
	"syscall"
	"testing"
)

func TestGetOpenFDs(t *testing.T) {
	fds, err := GetOpenFDs()
	if err != nil {
		t.Fatalf("GetOpenFDs failed: %v", err)
	}
	if len(fds) == 0 {
		t.Errorf("expected at least some open fds, got none")
	}
}

func TestSanitizeFDs(t *testing.T) {
	tmp, err := os.CreateTemp("", "test-fd-*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	if err := SanitizeFDs(nil); err != nil {
		t.Errorf("SanitizeFDs failed: %v", err)
	}
}

func TestCloseUnexpectedFDsInherited(t *testing.T) {
	tmp, err := os.CreateTemp("", "test-fd-*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmp.Name())
	rawFD := int(tmp.Fd())

	// Clear FD_CLOEXEC to simulate an inherited FD from parent process
	_, _, sysErr := syscall.Syscall(syscall.SYS_FCNTL, uintptr(rawFD), syscall.F_SETFD, 0)
	if sysErr != 0 {
		t.Fatalf("failed to clear FD_CLOEXEC: %v", sysErr)
	}

	if !isInheritedFD(rawFD) {
		t.Fatalf("expected fd %d to be recognized as inherited", rawFD)
	}

	// CloseUnexpectedFDs should close it
	if err := CloseUnexpectedFDs(nil); err != nil {
		t.Fatalf("CloseUnexpectedFDs failed: %v", err)
	}

	// The inherited FD should now be closed
	var stat syscall.Stat_t
	err = syscall.Fstat(rawFD, &stat)
	if err == nil {
		t.Errorf("expected fd %d to be closed (EBADF), but fstat succeeded", rawFD)
	}
}
