//go:build windows

package secrets

import "os"

func fileFlock(f *os.File) error {
	return nil
}

func fileFlockUnlock(f *os.File) error {
	return nil
}
