//go:build !linux

package linux

// CheckLandlockSupport returns 0 on non-Linux platforms.
func CheckLandlockSupport() (int, error) {
	return 0, nil
}

// ApplyLandlockRuleset is a no-op on non-Linux platforms.
func ApplyLandlockRuleset(allowedDirs []string, deniedPaths []string) error {
	return nil
}
