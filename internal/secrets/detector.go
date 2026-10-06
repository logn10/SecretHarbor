package secrets

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/secretharbor/secretharbor/internal/policy"
)

// ProtectedCredentials lists sensitive user and system credential files
// that are protected in standard fake mode alongside .aws, .ssh, .gnupg.
var ProtectedCredentials = []string{
	".aws/credentials",
	".aws/config",
	".aws/*",
	".ssh/*",
	".gnupg/*",
	".config/gcloud/credentials.json",
	".netrc",
	".npmrc",
	".pypirc",
	".kube/config",
	".git-credentials",
}

// IgnoredDirectories lists build, cache, and vendor directories skipped during secret scanning.
var IgnoredDirectories = map[string]bool{
	".git":          true,
	".secretharbor": true,
	"node_modules":  true,
	"vendor":        true,
	"target":        true,
	"dist":          true,
	"build":         true,
	".next":         true,
	"venv":          true,
	".venv":         true,
	"__pycache__":   true,
	"bin":           true,
	"obj":           true,
}

// IsSecretFile checks whether a given file path matches secret patterns and is not allowed.
func IsSecretFile(relOrAbsPath string, projectDir string, allowExceptions []string, denyExceptions []string) bool {
	// Handle ~ prefix for home directory
	normPath := relOrAbsPath
	if strings.HasPrefix(normPath, "~/") || normPath == "~" {
		normPath = strings.TrimPrefix(normPath, "~/")
	}

	cleanPath := filepath.Clean(normPath)
	if projectDir != "" && filepath.IsAbs(cleanPath) {
		if rel, err := filepath.Rel(projectDir, cleanPath); err == nil && !strings.HasPrefix(rel, "..") {
			cleanPath = rel
		}
	}
	fileName := filepath.Base(cleanPath)

	// Check relative to home directory if path is absolute
	var relHome string
	if filepath.IsAbs(relOrAbsPath) {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			if r, err := filepath.Rel(home, relOrAbsPath); err == nil && !strings.HasPrefix(r, "..") {
				relHome = filepath.Clean(r)
			}
		}
	}

	// 1. Check explicit allow exceptions first (e.g., .env.example)
	for _, allowPattern := range allowExceptions {
		if matchPattern(allowPattern, cleanPath, fileName) || (relHome != "" && matchPattern(allowPattern, relHome, fileName)) {
			return false
		}
	}

	// 2. Check explicit deny exceptions
	for _, denyPattern := range denyExceptions {
		if matchPattern(denyPattern, cleanPath, fileName) || (relHome != "" && matchPattern(denyPattern, relHome, fileName)) {
			return true
		}
	}

	// 3. Check built-in patterns
	for _, pattern := range policy.BuiltInSecretPatterns {
		if matchPattern(pattern, cleanPath, fileName) || (relHome != "" && matchPattern(pattern, relHome, fileName)) {
			return true
		}
	}

	// 4. Check protected credentials (BUG-014)
	for _, pattern := range ProtectedCredentials {
		if matchPattern(pattern, cleanPath, fileName) || (relHome != "" && matchPattern(pattern, relHome, fileName)) {
			return true
		}
		// Suffix match for nested paths like .config/gcloud/credentials.json
		toSlash := filepath.ToSlash(cleanPath)
		cleanPat := strings.TrimPrefix(pattern, "~/")
		if strings.HasSuffix("/"+toSlash, "/"+cleanPat) {
			return true
		}
		if relHome != "" && strings.HasSuffix("/"+filepath.ToSlash(relHome), "/"+cleanPat) {
			return true
		}
	}

	return false
}

// FindMatchingFiles returns absolute paths under projectDir whose relative path or
// base name matches any of the given patterns (supports ** semantics).
func FindMatchingFiles(projectDir string, patterns []string) []string {
	if len(patterns) == 0 {
		return nil
	}

	var found []string
	_ = filepath.Walk(projectDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", ".secretharbor", "node_modules", "vendor", "dist", "target":
				return filepath.SkipDir
			}
			return nil
		}

		relPath, relErr := filepath.Rel(projectDir, path)
		if relErr != nil {
			relPath = path
		}
		fileName := filepath.Base(relPath)
		for _, pattern := range patterns {
			if matchPattern(pattern, relPath, fileName) {
				found = append(found, path)
				break
			}
		}
		return nil
	})
	return found
}

// DetectSecretFilesInDir scans the project directory for files that match secret patterns.
func DetectSecretFilesInDir(projectDir string, allowExceptions []string, denyExceptions []string) ([]string, error) {
	var found []string

	err := filepath.Walk(projectDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		// Skip VCS, control, build, cache, and virtual environment directories (BUG-063)
		if info.IsDir() {
			if IgnoredDirectories[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		relPath, err := filepath.Rel(projectDir, path)
		if err != nil {
			relPath = path
		}

		if IsSecretFile(relPath, projectDir, allowExceptions, denyExceptions) {
			found = append(found, path)
		}

		return nil
	})

	return found, err
}

func matchPattern(pattern, fullPath, fileName string) bool {
	// Normalize slashes
	pattern = filepath.ToSlash(pattern)
	fullPath = filepath.ToSlash(fullPath)
	fileName = filepath.ToSlash(fileName)

	// 1. Direct filename match (e.g. .env, *.pem, *.key)
	if matched, err := filepath.Match(pattern, fileName); err == nil && matched {
		return true
	}

	// 2. Direct full/rel path match
	if matched, err := filepath.Match(pattern, fullPath); err == nil && matched {
		return true
	}

	// 3. Directory wildcard matching (e.g. secrets/**, .ssh/*)
	cleanPattern := strings.TrimSuffix(pattern, "/**")
	cleanPattern = strings.TrimSuffix(cleanPattern, "/*")

	// Match root directory prefix or path component
	if strings.HasPrefix(fullPath, cleanPattern+"/") || fullPath == cleanPattern {
		return true
	}
	if strings.HasPrefix(pattern, "**/") {
		sub := strings.TrimPrefix(pattern, "**/")
		sub = strings.TrimSuffix(sub, "/**")
		sub = strings.TrimSuffix(sub, "/*")
		if strings.Contains("/"+fullPath+"/", "/"+sub+"/") {
			return true
		}
	}

	return false
}
