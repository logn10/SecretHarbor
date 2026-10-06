package cleaner

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/secretharbor/secretharbor/internal/secrets"
	"github.com/secretharbor/secretharbor/internal/session"
)

// CleanResult reports statistics of cleaned ephemeral artifacts.
type CleanResult struct {
	CleanedSockets    int
	CleanedWorkspaces int
	CleanedSwaps      int
	CleanedErrors     int
}

// CleanOrphans scans temporary directories for dead session sockets and abandoned shadow trees.
func CleanOrphans() CleanResult {
	var res CleanResult

	// Collect and deduplicate temporary directories (system temp, /tmp, and SECRETHARBOR_TMPDIR)
	dirMap := make(map[string]bool)
	tempDirs := []string{"/tmp"}
	if sysTmp := os.TempDir(); sysTmp != "" {
		tempDirs = append(tempDirs, sysTmp)
	}
	if envTmp := os.Getenv("SECRETHARBOR_TMPDIR"); envTmp != "" {
		tempDirs = append(tempDirs, envTmp)
	}

	var uniqueDirs []string
	for _, d := range tempDirs {
		clean := filepath.Clean(d)
		if !dirMap[clean] {
			dirMap[clean] = true
			uniqueDirs = append(uniqueDirs, clean)
		}
	}

	for _, tempDir := range uniqueDirs {
		// 1. Scan for orphaned Docker interceptor sockets
		matches, err := filepath.Glob(filepath.Join(tempDir, "shb-*"))
		if err == nil {
			for _, path := range matches {
				base := filepath.Base(path)
				// Format: shb-d-<pid>-<rand>.sock
				if strings.HasPrefix(base, "shb-d-") && strings.HasSuffix(base, ".sock") {
					parts := strings.Split(base, "-")
					if len(parts) >= 3 {
						if pid, err := strconv.Atoi(parts[2]); err == nil && pid > 0 {
							if !session.IsProcessAlive(pid) {
								if err := os.Remove(path); err == nil {
									res.CleanedSockets++
								} else {
									res.CleanedErrors++
								}
							}
						}
					}
				}
			}
		}

		// 2. Clean stale secretharbor scratch workspaces older than 2 hours or with dead PIDs
		scratchMatches, err := filepath.Glob(filepath.Join(tempDir, "secretharbor-*"))
		if err == nil {
			now := time.Now()
			for _, path := range scratchMatches {
				fi, err := os.Stat(path)
				if err != nil {
					continue
				}
				// If older than 2 hours, clean up
				if now.Sub(fi.ModTime()) > 2*time.Hour {
					if err := os.RemoveAll(path); err == nil {
						res.CleanedWorkspaces++
					} else {
						res.CleanedErrors++
					}
				}
			}
		}
	}

	// 3. Clean stale session control sockets in ~/.secretharbor/control.<pid>.sock
	home, _ := os.UserHomeDir()
	if home != "" {
		controlMatches, err := filepath.Glob(filepath.Join(home, ".secretharbor", "control.*.sock"))
		if err == nil {
			for _, path := range controlMatches {
				base := filepath.Base(path)
				// control.<pid>.sock
				parts := strings.Split(base, ".")
				if len(parts) == 3 {
					if pid, err := strconv.Atoi(parts[1]); err == nil && pid > 0 {
						if !session.IsProcessAlive(pid) {
							_ = os.Remove(path)
						}
					}
				}
			}
		}
	}

	// 3b. Clean stale short control sockets in the private temp directory
	user := os.Getenv("USER")
	if user == "" {
		user = fmt.Sprintf("uid-%d", os.Getuid())
	}
	shortDir := filepath.Join(os.TempDir(), fmt.Sprintf(".shb-%s", user))
	if shortMatches, err := filepath.Glob(filepath.Join(shortDir, "c-*.sock")); err == nil {
		for _, path := range shortMatches {
			base := filepath.Base(path)
			pidStr := strings.TrimSuffix(strings.TrimPrefix(base, "c-"), ".sock")
			if pid, err := strconv.Atoi(pidStr); err == nil && pid > 0 {
				if !session.IsProcessAlive(pid) {
					_ = os.Remove(path)
				}
			}
		}
	}

	// 4. Restore orphaned in-place secret swaps from crashed or terminated sessions
	res.CleanedSwaps = secrets.RestoreOrphanSwaps()

	return res
}
