//go:build linux

package linux

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// LandlockRuleset encapsulates an active Landlock LSM security boundary.
type LandlockRuleset struct {
	fd  int
	abi int
}

// CheckLandlockSupport queries the running Linux kernel for Landlock LSM availability safely
// without setting PR_SET_NO_NEW_PRIVS on the calling process.
func CheckLandlockSupport() (int, error) {
	// Query Landlock ABI version without modifying process credentials
	res, _, errno := syscall.Syscall(
		unix.SYS_LANDLOCK_CREATE_RULESET,
		0,
		0,
		uintptr(unix.LANDLOCK_CREATE_RULESET_VERSION),
	)
	if errno != 0 {
		return 0, fmt.Errorf("landlock not supported by running kernel: %w", errno)
	}

	return int(res), nil
}

// ApplyLandlockRuleset configures Landlock hierarchy controls over the current process.
func ApplyLandlockRuleset(allowedDirs []string, deniedPaths []string) error {
	abi, err := CheckLandlockSupport()
	if err != nil {
		return fmt.Errorf("landlock LSM check failed: %w", err)
	}

	var handledAccess uint64 = unix.LANDLOCK_ACCESS_FS_READ_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_DIR |
		unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
		unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
		unix.LANDLOCK_ACCESS_FS_MAKE_REG |
		unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM |
		unix.LANDLOCK_ACCESS_FS_MAKE_FIFO |
		unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR |
		unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_EXECUTE

	if abi >= 2 {
		handledAccess |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 3 {
		handledAccess |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}

	attr := struct {
		handledAccessFS uint64
	}{
		handledAccessFS: handledAccess,
	}

	res, _, errno := syscall.Syscall(
		unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
		0,
	)
	if errno != 0 {
		return fmt.Errorf("landlock_create_ruleset failed: %w", errno)
	}
	rulesetFD := int(res)
	defer syscall.Close(rulesetFD)

	// Build map of denied canonical paths
	deniedMap := make(map[string]bool)
	for _, dp := range deniedPaths {
		if dp != "" {
			deniedMap[filepath.Clean(dp)] = true
		}
	}

	// Add read/write access for allowed directories (project dir, system libraries, /usr, /lib, /bin)
	defaultAllowed := append([]string{
		"/usr", "/lib", "/lib64", "/bin", "/etc", "/tmp",
	}, allowedDirs...)

	for _, dir := range defaultAllowed {
		clean := filepath.Clean(dir)
		if isDenied(clean, deniedMap) {
			continue
		}
		if err := addPathRule(rulesetFD, clean, handledAccess); err != nil {
			return fmt.Errorf("failed to add Landlock path rule for %s: %w", clean, err)
		}
	}

	// Restrict self: prevents calling process and all its future children from bypassing ruleset
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("failed to set PR_SET_NO_NEW_PRIVS: %w", err)
	}

	_, _, errno = syscall.Syscall(
		unix.SYS_LANDLOCK_RESTRICT_SELF,
		uintptr(rulesetFD),
		0,
		0,
	)
	if errno != 0 {
		return fmt.Errorf("landlock_restrict_self failed: %w", errno)
	}

	return nil
}

func isDenied(path string, deniedMap map[string]bool) bool {
	if deniedMap[path] {
		return true
	}
	for dp := range deniedMap {
		if strings.HasPrefix(path, dp+"/") {
			return true
		}
	}
	return false
}

func addPathRule(rulesetFD int, path string, access uint64) error {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to open path for Landlock rule: %w", err)
	}
	defer unix.Close(fd)

	pathBeneath := struct {
		allowedAccess uint64
		parentFD      int32
	}{
		allowedAccess: access,
		parentFD:      int32(fd),
	}

	_, _, errno := syscall.Syscall(
		unix.SYS_LANDLOCK_ADD_RULE,
		uintptr(rulesetFD),
		uintptr(unix.LANDLOCK_RULE_PATH_BENEATH),
		uintptr(unsafe.Pointer(&pathBeneath)),
	)
	if errno != 0 {
		return fmt.Errorf("landlock_add_rule failed: %w", errno)
	}
	return nil
}
