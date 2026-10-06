package agents

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// GetShimsDir returns the directory where SecretHarbor persistent launcher shims reside.
// Never falls back to shared world-writable /tmp without creating a secure 0700 private user directory (BUG-021).
func GetShimsDir() string {
	dir := os.Getenv("SECRETHARBOR_DIR")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err == nil && home != "" {
			dir = filepath.Join(home, ".secretharbor")
		} else {
			userDir := filepath.Join(os.TempDir(), fmt.Sprintf(".secretharbor-%d", os.Getuid()))
			_ = os.MkdirAll(userDir, 0700)
			_ = os.Chmod(userDir, 0700)
			dir = userDir
		}
	}
	return filepath.Join(dir, "shims")
}

func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func isSubdirectory(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	return !strings.HasPrefix(rel, "..") && rel != "."
}

func resolveRealBinaryExcludingShims(binaryName, binaryPath, shimsDir string) string {
	cleanPath := filepath.Clean(binaryPath)
	cleanShim := filepath.Clean(filepath.Join(shimsDir, binaryName))
	if binaryPath != "" && cleanPath != cleanShim && !isSubdirectory(shimsDir, binaryPath) {
		return binaryPath
	}
	// Search PATH excluding shims directory to avoid infinite self-exec loops (BUG-022)
	pathEnv := os.Getenv("PATH")
	cleanShims := filepath.Clean(shimsDir)
	for _, dir := range filepath.SplitList(pathEnv) {
		cleanDir := filepath.Clean(dir)
		if cleanDir == cleanShims || strings.Contains(cleanDir, ".secretharbor/shims") {
			continue
		}
		candidate := filepath.Join(dir, binaryName)
		if fi, err := os.Stat(candidate); err == nil && !fi.IsDir() {
			return candidate
		}
	}
	return binaryPath
}

// InstallShims generates transparent launcher shims for all detected agents.
// Shims directory permissions must be 0700 (BUG-021).
func InstallShims(shimsDir string, detected []*DetectedAgent) (int, error) {
	if shimsDir == "" {
		shimsDir = GetShimsDir()
	}

	// Shims directory permissions must be 0700 (BUG-021)
	if err := os.MkdirAll(shimsDir, 0700); err != nil {
		return 0, fmt.Errorf("failed to create shims directory %s: %w", shimsDir, err)
	}
	_ = os.Chmod(shimsDir, 0700)

	installedCount := 0

	for _, agent := range detected {
		if agent.Type != AgentTypeCLI {
			continue
		}

		shimPath := filepath.Join(shimsDir, agent.ID)
		realBinary := resolveRealBinaryExcludingShims(agent.ID, agent.Path, shimsDir)

		escapedBinary := shellEscape(realBinary)
		escapedShimsDir := shellEscape(shimsDir)

		shimContent := fmt.Sprintf(`#!/bin/sh
# SecretHarbor automatic guard shim for %s
# Documentation: https://github.com/logn10/SecretHarbor

if [ -z "$SECRETHARBOR_SANDBOX" ] && [ -z "$SHB_SANDBOX" ]; then
    # Outside sandbox: launch under SecretHarbor security boundary
    if command -v shb >/dev/null 2>&1; then
        exec shb run %s -- "$@"
    elif command -v secretharbor >/dev/null 2>&1; then
        exec secretharbor run %s -- "$@"
    elif [ -x "$HOME/.local/bin/shb" ]; then
        exec "$HOME/.local/bin/shb" run %s -- "$@"
    elif [ -x "/usr/local/bin/shb" ]; then
        exec "/usr/local/bin/shb" run %s -- "$@"
    elif [ -x "/opt/homebrew/bin/shb" ]; then
        exec "/opt/homebrew/bin/shb" run %s -- "$@"
    elif [ -x "$HOME/.secretharbor/bin/shb" ]; then
        exec "$HOME/.secretharbor/bin/shb" run %s -- "$@"
    fi

    # Fail-Closed Invariant: Never silently execute unconfined outside the sandbox
    printf "\033[31mSecretHarbor Security Error:\033[0m 'shb' binary not found in PATH or standard directories.\n" >&2
    printf "Refusing to launch %s unprotected. Install shb into ~/.local/bin or /usr/local/bin.\n" >&2
    exit 71
fi

# Inside sandbox: clean shims from PATH to prevent recursive self-exec loops (BUG-022)
CLEAN_PATH=""
IFS=':'
for p in $PATH; do
    if [ "$p" != %s ] && [ "$p" != "$HOME/.secretharbor/shims" ]; then
        if [ -z "$CLEAN_PATH" ]; then
            CLEAN_PATH="$p"
        else
            CLEAN_PATH="$CLEAN_PATH:$p"
        fi
    fi
done
unset IFS
export PATH="$CLEAN_PATH"

# Execute real binary safely without shell interpolation (BUG-022)
exec %s "$@"
`, agent.DisplayName, agent.ID, agent.ID, agent.ID, agent.ID, agent.ID, agent.ID, agent.DisplayName, escapedShimsDir, escapedBinary)

		if err := os.WriteFile(shimPath, []byte(shimContent), 0755); err != nil {
			return installedCount, fmt.Errorf("failed to write shim for %s: %w", agent.ID, err)
		}

		installedCount++
	}

	return installedCount, nil
}

// IsShimsDirInPATH checks whether the shims directory is currently present in the system PATH.
func IsShimsDirInPATH() bool {
	shimsDir := GetShimsDir()
	pathEnv := os.Getenv("PATH")
	for _, p := range filepath.SplitList(pathEnv) {
		cleanP := filepath.Clean(p)
		if cleanP == filepath.Clean(shimsDir) {
			return true
		}
	}
	return false
}

// ConfigureShellProfile appends the shims directory to ~/.zshrc or ~/.bashrc if not already present.
// Writes properly escaped PATH and performs robust duplicate detection (BUG-061).
func ConfigureShellProfile() (string, bool, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", false, err
	}

	shimsDir := GetShimsDir()
	escapedShimsDir := escapeShellDoubleQuotes(shimsDir)
	exportLine := fmt.Sprintf("\n# SecretHarbor automatic agent security boundary\nexport PATH=\"%s:$PATH\"\n", escapedShimsDir)

	// Detect default profile file
	profileFiles := []string{
		filepath.Join(home, ".zshrc"),
		filepath.Join(home, ".bashrc"),
		filepath.Join(home, ".profile"),
	}

	var targetFile string
	for _, file := range profileFiles {
		if _, err := os.Stat(file); err == nil {
			targetFile = file
			break
		}
	}

	if targetFile == "" {
		targetFile = filepath.Join(home, ".profile")
	}

	// Read existing content with robust duplicate detection (BUG-061)
	content, err := os.ReadFile(targetFile)
	if err == nil {
		contentStr := string(content)
		cleanShims := filepath.Clean(shimsDir)
		if strings.Contains(contentStr, shimsDir) ||
			strings.Contains(contentStr, cleanShims) ||
			strings.Contains(contentStr, ".secretharbor/shims") {
			return targetFile, false, nil // Already configured
		}
		// Also check line by line
		for _, line := range strings.Split(contentStr, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "export PATH=") && (strings.Contains(line, shimsDir) || strings.Contains(line, cleanShims)) {
				return targetFile, false, nil
			}
		}
	}

	f, err := os.OpenFile(targetFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return targetFile, false, fmt.Errorf("failed to open profile %s: %w", targetFile, err)
	}
	defer f.Close()

	if _, err := f.WriteString(exportLine); err != nil {
		return targetFile, false, fmt.Errorf("failed to write to profile %s: %w", targetFile, err)
	}

	return targetFile, true, nil
}

func escapeShellDoubleQuotes(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, `$`, `\$`)
	s = strings.ReplaceAll(s, "`", "\\`")
	return s
}
