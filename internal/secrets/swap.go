package secrets

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/secretharbor/secretharbor/internal/session"
	"github.com/secretharbor/secretharbor/internal/vault"
)

const SyntheticWatermark = "# SECRETHARBOR SYNTHETIC ENVIRONMENT (ACTIVE SWAP)"

// SwappedFile tracks metadata for a single file swapped in-place.
type SwappedFile struct {
	OriginalPath      string      `json:"original_path"`
	RelPath           string      `json:"rel_path,omitempty"`
	BackupPath        string      `json:"backup_path"`
	FileMode          os.FileMode `json:"file_mode"`
	RealHash          string      `json:"real_hash"`
	SyntheticBaseline string      `json:"synthetic_baseline"`
}

// SwapRecord persists the state of an active project in-place secret swap.
type SwapRecord struct {
	ProjectDir      string            `json:"project_dir"`
	PID             int               `json:"pid"`
	Files           []SwappedFile     `json:"files"`
	DeniedExternal  []string          `json:"denied_external,omitempty"`
	CreatedAt       time.Time         `json:"created_at"`
	SyntheticValues map[string]string `json:"synthetic_values"`
}

var (
	registryLockMu    sync.Mutex
	registryLockDepth int
	registryLockFile  *os.File
)

// acquireRegistryLock acquires an inter-process file lock (flock) and process-level mutex.
// Supports reentrant locking within the same process.
func acquireRegistryLock() (func(), error) {
	registryLockMu.Lock()

	if registryLockDepth > 0 {
		registryLockDepth++
		registryLockMu.Unlock()
		return func() {
			registryLockMu.Lock()
			registryLockDepth--
			registryLockMu.Unlock()
		}, nil
	}

	path := GetActiveSwapsFilePath() + ".lock"
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		registryLockMu.Unlock()
		return nil, err
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		registryLockMu.Unlock()
		return nil, err
	}

	if err := fileFlock(f); err != nil {
		_ = f.Close()
		registryLockMu.Unlock()
		return nil, err
	}

	registryLockFile = f
	registryLockDepth = 1
	registryLockMu.Unlock()

	return func() {
		registryLockMu.Lock()
		defer registryLockMu.Unlock()
		registryLockDepth--
		if registryLockDepth == 0 {
			if registryLockFile != nil {
				_ = fileFlockUnlock(registryLockFile)
				_ = registryLockFile.Close()
				registryLockFile = nil
			}
		}
	}, nil
}

// GetShadowVaultDir returns the secured path where original secrets are backed up.
func GetShadowVaultDir() string {
	dir := os.Getenv("SECRETHARBOR_DIR")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			dir = vault.SecureFallbackDir()
		} else {
			dir = filepath.Join(home, ".secretharbor")
		}
	}
	return filepath.Join(dir, "vault", "shadow_backups")
}

// GetActiveSwapsFilePath returns the path to the registry of active swaps.
func GetActiveSwapsFilePath() string {
	dir := os.Getenv("SECRETHARBOR_DIR")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			dir = vault.SecureFallbackDir()
		} else {
			dir = filepath.Join(home, ".secretharbor")
		}
	}
	return filepath.Join(dir, "active_swaps.json")
}

func getSwapVault() (*vault.Vault, error) {
	dir := os.Getenv("SECRETHARBOR_DIR")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err == nil && home != "" {
			dir = filepath.Join(home, ".secretharbor")
		} else {
			dir = vault.SecureFallbackDir()
		}
	}
	return vault.OpenVault(filepath.Join(dir, "vault"))
}

func validateRegistryFilePath(path string) error {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return fmt.Errorf("registry path must be absolute: %s", path)
	}
	return nil
}

func validateSwapRecord(proj string, rec *SwapRecord) error {
	if !filepath.IsAbs(filepath.Clean(proj)) {
		return fmt.Errorf("project dir in registry must be absolute: %s", proj)
	}
	vaultBase := filepath.Clean(GetShadowVaultDir())
	for _, sf := range rec.Files {
		if !filepath.IsAbs(filepath.Clean(sf.OriginalPath)) {
			return fmt.Errorf("original file path must be absolute: %s", sf.OriginalPath)
		}
		if sf.RelPath != "" {
			cleanRel := filepath.Clean(sf.RelPath)
			if strings.HasPrefix(cleanRel, "..") || filepath.IsAbs(cleanRel) {
				return fmt.Errorf("relative file path must not escape project: %s", sf.RelPath)
			}
		}
		cleanBackup := filepath.Clean(sf.BackupPath)
		if !strings.HasPrefix(cleanBackup, vaultBase) {
			return fmt.Errorf("backup path %s escapes shadow vault directory %s", cleanBackup, vaultBase)
		}
	}
	return nil
}

// LoadActiveSwaps loads the active swaps map from disk with inter-process locking.
// Returns an error if the registry is malformed or invalid (BUG-035).
func LoadActiveSwaps() (map[string]*SwapRecord, error) {
	unlock, err := acquireRegistryLock()
	if err != nil {
		return nil, err
	}
	defer unlock()

	return loadActiveSwapsLocked()
}

func loadActiveSwapsLocked() (map[string]*SwapRecord, error) {
	path := GetActiveSwapsFilePath()
	if err := validateRegistryFilePath(path); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]*SwapRecord), nil
		}
		return nil, err
	}

	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return make(map[string]*SwapRecord), nil
	}

	var records map[string]*SwapRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("malformed active_swaps registry file at %s: %w", path, err)
	}
	if records == nil {
		records = make(map[string]*SwapRecord)
	}

	// Validate loaded records
	for proj, rec := range records {
		if rec == nil {
			delete(records, proj)
			continue
		}
		if err := validateSwapRecord(proj, rec); err != nil {
			return nil, fmt.Errorf("invalid swap record for %s: %w", proj, err)
		}
	}

	return records, nil
}

// SaveActiveSwaps writes the active swaps map to disk atomically with inter-process locking.
func SaveActiveSwaps(swaps map[string]*SwapRecord) error {
	unlock, err := acquireRegistryLock()
	if err != nil {
		return err
	}
	defer unlock()

	return saveActiveSwapsLocked(swaps)
}

func saveActiveSwapsLocked(swaps map[string]*SwapRecord) error {
	path := GetActiveSwapsFilePath()
	if err := validateRegistryFilePath(path); err != nil {
		return err
	}

	for proj, rec := range swaps {
		if rec == nil {
			delete(swaps, proj)
			continue
		}
		if err := validateSwapRecord(proj, rec); err != nil {
			return fmt.Errorf("refusing to save invalid swap record for %s: %w", proj, err)
		}
	}

	data, err := json.MarshalIndent(swaps, "", "  ")
	if err != nil {
		return err
	}

	return atomicWriteFile(path, data, 0600)
}

// ProjectHash returns a deterministic short hash for a project path.
func ProjectHash(projectDir string) string {
	clean := filepath.Clean(projectDir)
	h := sha256.Sum256([]byte(clean))
	return hex.EncodeToString(h[:8])
}

// atomicWriteFile writes data to a temporary file, calls fsync, sets mode,
// and atomically renames to destPath.
func atomicWriteFile(destPath string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(destPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory for %s: %w", destPath, err)
	}

	tmpFile, err := os.CreateTemp(dir, ".shb-atomic-tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file for %s: %w", destPath, err)
	}
	tmpName := tmpFile.Name()
	cleaned := false
	defer func() {
		if !cleaned {
			_ = tmpFile.Close()
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmpFile.Write(data); err != nil {
		return fmt.Errorf("failed to write data to %s: %w", tmpName, err)
	}
	if err := tmpFile.Sync(); err != nil {
		return fmt.Errorf("failed to fsync %s: %w", tmpName, err)
	}
	if err := tmpFile.Chmod(mode); err != nil {
		return fmt.Errorf("failed to chmod %s: %w", tmpName, err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close %s: %w", tmpName, err)
	}

	if err := os.Rename(tmpName, destPath); err != nil {
		return fmt.Errorf("failed to atomically rename %s to %s: %w", tmpName, destPath, err)
	}
	cleaned = true
	return nil
}

// SwapInPlace backs up real secret files encrypted in shadow vault and writes synthetic fake secrets in-place.
func SwapInPlace(projectDir string, allowExceptions, denyExceptions []string, pid int) (*SwapRecord, error) {
	unlock, err := acquireRegistryLock()
	if err != nil {
		return nil, err
	}
	defer unlock()

	absProj, err := filepath.Abs(projectDir)
	if err != nil {
		absProj = projectDir
	}
	absProj = filepath.Clean(absProj)

	// Canonical project root for symlink containment checks (e.g. /var -> /private/var on macOS).
	canonProj := absProj
	if resolvedProj, err := filepath.EvalSymlinks(absProj); err == nil && resolvedProj != "" {
		canonProj = filepath.Clean(resolvedProj)
	}

	swaps, err := loadActiveSwapsLocked()
	if err != nil {
		return nil, err
	}

	// 1. Anti-Overwrite Guard: Check if an active swap already exists for this project
	if existing, found := swaps[absProj]; found {
		if session.IsProcessAlive(existing.PID) && existing.PID != pid {
			// Another active process is running with these swapped fakes. Reuse record.
			return existing, nil
		}
		// Process is dead or orphaned: restore real files first before new swap!
		if err := restoreSwapLocked(absProj); err != nil {
			return nil, fmt.Errorf("failed to clean up stale swap before new swap: %w", err)
		}
		swaps, err = loadActiveSwapsLocked()
		if err != nil {
			return nil, err
		}
	}

	// 2. Detect secret files in projectDir
	secretFiles, err := DetectSecretFilesInDir(absProj, allowExceptions, denyExceptions)
	if err != nil || len(secretFiles) == 0 {
		return nil, err
	}

	projHash := ProjectHash(absProj)
	backupBase := filepath.Join(GetShadowVaultDir(), projHash)
	if err := os.MkdirAll(backupBase, 0700); err != nil {
		return nil, fmt.Errorf("failed to create secure backup directory: %w", err)
	}

	v, err := getSwapVault()
	if err != nil {
		return nil, fmt.Errorf("failed to open vault for encrypted backup: %w", err)
	}

	rec := &SwapRecord{
		ProjectDir:      absProj,
		PID:             pid,
		CreatedAt:       time.Now(),
		SyntheticValues: make(map[string]string),
	}

	for _, realPath := range secretFiles {
		// Filter out files that are explicitly in deny exceptions (they should remain denied, not faked)
		rel, err := filepath.Rel(absProj, realPath)
		if err != nil {
			rel = filepath.Base(realPath)
		}

		isExplicitDeny := false
		for _, denyPat := range denyExceptions {
			if matchPattern(denyPat, rel, filepath.Base(rel)) {
				isExplicitDeny = true
				break
			}
		}
		if isExplicitDeny {
			continue
		}

		// BUG-010: Symlink handling.
		// - Symlinks resolving inside the project are swapped at their target (safe, still virtualized).
		// - Symlinks resolving outside the project are never modified and are denied by the sandbox.
		linfo, err := os.Lstat(realPath)
		if err != nil {
			continue
		}
		if linfo.Mode()&os.ModeSymlink != 0 {
			resolved, rerr := filepath.EvalSymlinks(realPath)
			if rerr != nil {
				rec.DeniedExternal = append(rec.DeniedExternal, realPath)
				continue
			}
			relResolved, rerr := filepath.Rel(canonProj, resolved)
			if rerr != nil || strings.HasPrefix(relResolved, "..") || filepath.IsAbs(relResolved) {
				rec.DeniedExternal = append(rec.DeniedExternal, resolved)
				continue
			}
			realPath = resolved
			rel = relResolved
			linfo, err = os.Lstat(realPath)
			if err != nil || linfo.Mode()&os.ModeSymlink != 0 {
				rec.DeniedExternal = append(rec.DeniedExternal, realPath)
				continue
			}
		}

		info, err := os.Stat(realPath)
		if err != nil {
			continue
		}

		realBytes, err := os.ReadFile(realPath)
		if err != nil {
			continue
		}

		// Anti-overwrite check: if file already contains synthetic watermark, do not backup fake over real!
		if strings.Contains(string(realBytes), SyntheticWatermark) {
			continue
		}

		backupPath := filepath.Join(backupBase, rel)
		if err := os.MkdirAll(filepath.Dir(backupPath), 0700); err != nil {
			_ = restoreSwapLocked(absProj)
			return nil, fmt.Errorf("failed to create backup subdir: %w", err)
		}

		// BUG-034: Encrypt real secret in backup vault using AES-256-GCM
		encryptedBackup, err := v.Encrypt(realBytes)
		if err != nil {
			_ = restoreSwapLocked(absProj)
			return nil, fmt.Errorf("failed to encrypt backup for %s: %w", realPath, err)
		}

		// Save encrypted secret to backup with atomic write
		if err := atomicWriteFile(backupPath, encryptedBackup, 0600); err != nil {
			_ = restoreSwapLocked(absProj)
			return nil, fmt.Errorf("failed to write secure backup for %s: %w", realPath, err)
		}

		h := sha256.Sum256(realBytes)
		realHash := hex.EncodeToString(h[:])

		// Generate synthetic fake content
		baseName := filepath.Base(realPath)
		ext := filepath.Ext(baseName)
		var fakeContent string

		if strings.HasPrefix(baseName, ".env") {
			virtualized, err := VirtualizeEnvContent(bytes.NewReader(realBytes))
			if err != nil {
				virtualized = "# SecretHarbor Synthetic Environment\n"
			}

			// Extract synthetic key-values for auto-injection
			envMap := ParseEnvContent(virtualized)
			for k, v := range envMap {
				rec.SyntheticValues[k] = v
			}

			var b strings.Builder
			b.WriteString(SyntheticWatermark + "\n")
			b.WriteString(fmt.Sprintf("# Project Hash: %s | Real secrets secured in ~/.secretharbor/vault\n", projHash))
			b.WriteString("# Safe synthetic values generated for process isolation.\n\n")
			b.WriteString(virtualized)
			fakeContent = b.String()
		} else if ext == ".pem" || ext == ".key" {
			fakeContent = "-----BEGIN PRIVATE KEY-----\n" +
				"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC6qSecretHarbor\n" +
				"FakeSyntheticKeyForTestingPurposesOnlyNotARealPrivateKey==\n" +
				"-----END PRIVATE KEY-----\n"
		} else if strings.Contains(baseName, "credentials") && (ext == ".json" || ext == ".yaml" || ext == ".yml") {
			if ext == ".json" {
				fakeContent = "{\n  \"client_id\": \"secretharbor-fake-client-id\",\n  \"client_secret\": \"secretharbor-fake-secret\",\n  \"token\": \"secretharbor-fake-token\"\n}\n"
			} else {
				fakeContent = "client_id: secretharbor-fake-client-id\nclient_secret: secretharbor-fake-secret\ntoken: secretharbor-fake-token\n"
			}
		} else if baseName == ".npmrc" {
			fakeContent = "//registry.npmjs.org/:_authToken=secretharbor_fake_npm_token_00000000\n"
		} else if baseName == ".pypirc" {
			fakeContent = "[distutils]\nindex-servers = pypi\n\n[pypi]\nusername = __token__\npassword = pypi-secretharbor-fake-token\n"
		} else if baseName == ".netrc" {
			fakeContent = "machine github.com login fake_user password secretharbor_fake_token\n"
		} else if baseName == ".git-credentials" {
			fakeContent = "https://fake_user:secretharbor_fake_token@github.com\n"
		} else if baseName == "config" && strings.Contains(realPath, ".kube") {
			fakeContent = "apiVersion: v1\nclusters: []\ncontexts: []\ncurrent-context: \"\"\nkind: Config\npreferences: {}\nusers: []\n"
		} else {
			fakeContent = "# SecretHarbor Protected Synthetic Placeholder\n"
		}

		// Write synthetic fake in place at realPath (preserving original permissions) via atomic write
		if err := atomicWriteFile(realPath, []byte(fakeContent), info.Mode()); err != nil {
			_ = restoreSwapLocked(absProj)
			return nil, fmt.Errorf("failed to write synthetic file at %s: %w", realPath, err)
		}

		rec.Files = append(rec.Files, SwappedFile{
			OriginalPath:      realPath,
			RelPath:           rel,
			BackupPath:        backupPath,
			FileMode:          info.Mode(),
			RealHash:          realHash,
			SyntheticBaseline: fakeContent,
		})
	}

	if len(rec.Files) > 0 {
		swaps[absProj] = rec
		if err := saveActiveSwapsLocked(swaps); err != nil {
			_ = restoreSwapLocked(absProj)
			return nil, fmt.Errorf("failed to save active swaps registry: %w", err)
		}
	}

	return rec, nil
}

// RestoreSwap safely restores the real secret files using 3-way reconciliation with inter-process locking.
// Handles directory rename/move and preserves backups if any restore step fails (BUG-002, BUG-011).
func RestoreSwap(projectDir string) error {
	unlock, err := acquireRegistryLock()
	if err != nil {
		return err
	}
	defer unlock()

	return restoreSwapLocked(projectDir)
}

func findSwapRecordForProject(swaps map[string]*SwapRecord, absProj string) (*SwapRecord, string) {
	// 1. Direct match by absolute path
	if rec, found := swaps[absProj]; found && rec != nil {
		return rec, absProj
	}

	// Canonical match (e.g. /var vs /private/var on macOS)
	if canonAbs, err := filepath.EvalSymlinks(absProj); err == nil && canonAbs != "" {
		for origProj, rec := range swaps {
			if rec == nil {
				continue
			}
			if canonOrig, err := filepath.EvalSymlinks(origProj); err == nil && canonOrig == canonAbs {
				return rec, origProj
			}
		}
	}

	// 2. BUG-002: Check if project was moved or renamed
	for origProj, rec := range swaps {
		if rec == nil || len(rec.Files) == 0 {
			continue
		}
		// Match by relative paths of files containing synthetic markers in absProj
		matchedFiles := 0
		for _, sf := range rec.Files {
			relPath := sf.RelPath
			if relPath == "" {
				relPath, _ = filepath.Rel(rec.ProjectDir, sf.OriginalPath)
			}
			candPath := filepath.Join(absProj, relPath)
			candData, err := os.ReadFile(candPath)
			if err == nil {
				candStr := string(candData)
				if strings.Contains(candStr, SyntheticWatermark) || candStr == sf.SyntheticBaseline {
					matchedFiles++
				}
			}
		}
		if matchedFiles > 0 {
			return rec, origProj
		}
	}

	return nil, ""
}

func restoreSwapLocked(projectDir string) error {
	absProj, err := filepath.Abs(projectDir)
	if err != nil {
		absProj = projectDir
	}
	absProj = filepath.Clean(absProj)

	swaps, err := loadActiveSwapsLocked()
	if err != nil {
		return err
	}

	v, err := getSwapVault()
	if err != nil {
		return fmt.Errorf("failed to open vault for restore: %w", err)
	}

	rec, foundKey := findSwapRecordForProject(swaps, absProj)

	// Never recreate a vanished project directory: keep encrypted backups so a moved or
	// renamed project can be recovered explicitly with 'shb restore <new-path>' (BUG-002).
	if rec != nil {
		if _, statErr := os.Stat(absProj); statErr != nil {
			return fmt.Errorf("project directory %s is missing; encrypted secret backups are preserved. If the project was moved or renamed, run 'shb restore <new-path>'", absProj)
		}
	}

	projHash := ProjectHash(absProj)
	backupBase := filepath.Join(GetShadowVaultDir(), projHash)

	// Fallback when not registered in swaps: check backup directory
	if rec == nil {
		// Never recreate a vanished project directory: keep backups so a moved project
		// can be recovered explicitly with 'shb restore <new-path>' (BUG-002).
		if _, statErr := os.Stat(absProj); statErr != nil {
			if _, err := os.Stat(backupBase); err == nil {
				return fmt.Errorf("project directory %s is missing; encrypted secret backups are preserved. If the project was moved or renamed, run 'shb restore <new-path>'", absProj)
			}
			return nil
		}
		if _, err := os.Stat(backupBase); os.IsNotExist(err) {
			// Scan shadow vault subdirectories for matching relative files
			if entries, err := os.ReadDir(GetShadowVaultDir()); err == nil {
				for _, entry := range entries {
					if entry.IsDir() {
						candBackupBase := filepath.Join(GetShadowVaultDir(), entry.Name())
						matches := false
						_ = filepath.Walk(candBackupBase, func(p string, fi os.FileInfo, err error) error {
							if err == nil && !fi.IsDir() {
								rel, _ := filepath.Rel(candBackupBase, p)
								inProj := filepath.Join(absProj, rel)
								if data, err := os.ReadFile(inProj); err == nil && strings.Contains(string(data), SyntheticWatermark) {
									matches = true
								}
							}
							return nil
						})
						if matches {
							backupBase = candBackupBase
							break
						}
					}
				}
			}
		}

		if _, err := os.Stat(backupBase); err == nil {
			type fallbackPlan struct {
				targetPath string
				backupPath string
				data       []byte
				mode       os.FileMode
			}
			var fPlan []fallbackPlan

			walkErr := filepath.Walk(backupBase, func(path string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() {
					return nil
				}
				rel, err := filepath.Rel(backupBase, path)
				if err != nil {
					return nil
				}
				origPath := filepath.Join(absProj, rel)

				backupEncrypted, err := os.ReadFile(path)
				if err != nil {
					return fmt.Errorf("failed to read backup file %s: %w", path, err)
				}
				backupBytes, err := v.Decrypt(backupEncrypted)
				if err != nil {
					backupBytes = backupEncrypted
				}

				fPlan = append(fPlan, fallbackPlan{
					targetPath: origPath,
					backupPath: path,
					data:       backupBytes,
					mode:       info.Mode(),
				})
				return nil
			})
			if walkErr != nil {
				return walkErr
			}

			// Atomic write for all fallback files (BUG-011)
			for _, p := range fPlan {
				if err := atomicWriteFile(p.targetPath, p.data, p.mode); err != nil {
					// DO NOT DELETE BACKUP BASE ON FAILURE!
					return fmt.Errorf("atomic restore write failed for %s: %w", p.targetPath, err)
				}
			}
			_ = os.RemoveAll(backupBase)
		}
		return nil
	}

	// Prepare restore plan in memory first (BUG-011)
	type restorePlan struct {
		targetPath string
		backupPath string
		data       []byte
		mode       os.FileMode
	}
	var plan []restorePlan

	for _, sf := range rec.Files {
		relPath := sf.RelPath
		if relPath == "" {
			relPath, _ = filepath.Rel(rec.ProjectDir, sf.OriginalPath)
		}
		// Restore to current project root, accommodating rename/move (BUG-002)
		targetPath := filepath.Join(absProj, relPath)

		// Check symlinks pointing outside project boundary (BUG-010)
		tinfo, err := os.Lstat(targetPath)
		if err == nil && tinfo.Mode()&os.ModeSymlink != 0 {
			resolved, err := filepath.EvalSymlinks(targetPath)
			if err != nil || strings.HasPrefix(resolved, "..") {
				return fmt.Errorf("refusing to restore into external symlink: %s", targetPath)
			}
		}

		backupEncrypted, err := os.ReadFile(sf.BackupPath)
		if err != nil {
			return fmt.Errorf("failed to read backup for %s: %w", sf.OriginalPath, err)
		}

		backupBytes, err := v.Decrypt(backupEncrypted)
		if err != nil {
			backupBytes = backupEncrypted
		}

		currentBytes, err := os.ReadFile(targetPath)
		var restoredData []byte
		if err != nil {
			// Original was deleted or missing; restore directly from backup
			restoredData = backupBytes
		} else {
			// Perform 3-Way Reconciliation
			reconciled := ReconcileEnvFiles(string(backupBytes), sf.SyntheticBaseline, string(currentBytes))
			restoredData = []byte(reconciled)
		}

		plan = append(plan, restorePlan{
			targetPath: targetPath,
			backupPath: sf.BackupPath,
			data:       restoredData,
			mode:       sf.FileMode,
		})
	}

	// Execute atomic writes for all files (BUG-011)
	for _, p := range plan {
		if err := atomicWriteFile(p.targetPath, p.data, p.mode); err != nil {
			// DO NOT DELETE BACKUP DIRECTORY OR ACTIVE_SWAPS REGISTRY ON FAILURE!
			return fmt.Errorf("atomic restore write failed for %s: %w", p.targetPath, err)
		}
	}

	// ONLY after all files succeeded: clean up backup files and registry
	for _, p := range plan {
		_ = os.Remove(p.backupPath)
	}
	_ = os.RemoveAll(backupBase)
	delete(swaps, foundKey)
	if err := saveActiveSwapsLocked(swaps); err != nil {
		return fmt.Errorf("failed to update active swaps registry after restore: %w", err)
	}

	return nil
}

// RestoreSwapForDirectory restores any active swap registered for the given project directory.
func RestoreSwapForDirectory(projectDir string) error {
	return RestoreSwap(projectDir)
}

// RestoreSwapForPID restores all active swaps whose recorded PID matches the given process ID.
func RestoreSwapForPID(pid int) error {
	if pid <= 0 {
		return nil
	}

	unlock, err := acquireRegistryLock()
	if err != nil {
		return err
	}
	defer unlock()

	swaps, err := loadActiveSwapsLocked()
	if err != nil {
		return err
	}

	var firstErr error
	for proj, rec := range swaps {
		if rec == nil || rec.PID != pid {
			continue
		}
		if err := restoreSwapLocked(proj); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// RestoreOrphanSwaps checks active_swaps.json and restores any sessions whose PIDs are dead.
func RestoreOrphanSwaps() int {
	unlock, err := acquireRegistryLock()
	if err != nil {
		return 0
	}
	defer unlock()

	swaps, err := loadActiveSwapsLocked()
	if err != nil || len(swaps) == 0 {
		return 0
	}

	restored := 0
	for proj, rec := range swaps {
		if rec == nil || !session.IsProcessAlive(rec.PID) {
			if err := restoreSwapLocked(proj); err == nil {
				restored++
			}
		}
	}
	return restored
}

// RestoreAllSwaps unconditionally restores all registered swaps across the entire system.
func RestoreAllSwaps() int {
	unlock, err := acquireRegistryLock()
	if err != nil {
		return 0
	}
	defer unlock()

	swaps, err := loadActiveSwapsLocked()
	if err != nil || len(swaps) == 0 {
		return 0
	}

	restored := 0
	for proj := range swaps {
		if err := restoreSwapLocked(proj); err == nil {
			restored++
		}
	}
	return restored
}

// UpdateSwapPID updates the process ID associated with an active project swap.
func UpdateSwapPID(projectDir string, newPID int) {
	unlock, err := acquireRegistryLock()
	if err != nil {
		return
	}
	defer unlock()

	absProj, err := filepath.Abs(projectDir)
	if err != nil {
		absProj = projectDir
	}
	absProj = filepath.Clean(absProj)

	swaps, err := loadActiveSwapsLocked()
	if err != nil {
		return
	}
	if rec, found := swaps[absProj]; found && rec != nil {
		rec.PID = newPID
		swaps[absProj] = rec
		_ = saveActiveSwapsLocked(swaps)
	}
}

// ParseEnvContent extracts KEY=VALUE pairs from an environment string.
// Supports export, escaped quotes, multiline values, and CRLF (BUG-062).
func ParseEnvContent(content string) map[string]string {
	result := make(map[string]string)
	entries := ParseEnvEntries(content)
	for _, entry := range entries {
		if entry.Key != "" && !entry.IsComment && !entry.IsBlank {
			result[entry.Key] = entry.Value
		}
	}
	return result
}

// ReconcileEnvFiles reconciles real original content, synthetic baseline, and current on-disk content.
// Preserves exact formatting, comments, export prefixes, and multiline values (BUG-062).
func ReconcileEnvFiles(realContent, baselineSynthetic, currentContent string) string {
	// 1. If current on-disk content matches synthetic baseline exactly (no edits made), restore real unmodified
	if strings.TrimSpace(baselineSynthetic) == strings.TrimSpace(currentContent) {
		return realContent
	}

	realEntries := ParseEnvEntries(realContent)
	baseEntries := ParseEnvEntries(baselineSynthetic)
	currentEntries := ParseEnvEntries(currentContent)

	realMap := make(map[string]EnvEntry)
	for _, e := range realEntries {
		if e.Key != "" && !e.IsComment && !e.IsBlank {
			realMap[e.Key] = e
		}
	}

	baseMap := make(map[string]EnvEntry)
	for _, e := range baseEntries {
		if e.Key != "" && !e.IsComment && !e.IsBlank {
			baseMap[e.Key] = e
		}
	}

	var out strings.Builder

	// Iterate through current entries to preserve user ordering and added lines
	for _, entry := range currentEntries {
		// Skip SecretHarbor synthetic watermark comments from final output
		if entry.IsComment {
			if strings.Contains(entry.RawText, "SECRETHARBOR SYNTHETIC ENVIRONMENT") ||
				strings.Contains(entry.RawText, "Project Hash:") ||
				strings.Contains(entry.RawText, "Safe synthetic values generated") {
				continue
			}
			out.WriteString(entry.RawText)
			continue
		}

		if entry.IsBlank {
			out.WriteString(entry.RawText)
			continue
		}

		if entry.Key == "" {
			out.WriteString(entry.RawText)
			continue
		}

		cleanKey := entry.Key
		if baseEntry, wasInBase := baseMap[cleanKey]; wasInBase {
			if realEntry, wasInReal := realMap[cleanKey]; wasInReal {
				if entry.Value == baseEntry.Value {
					// User did not touch this variable (still synthetic fake): restore real secret with exact formatting!
					out.WriteString(realEntry.RawText)
				} else {
					// User explicitly changed this value in editor: preserve user's updated entry!
					out.WriteString(entry.RawText)
				}
			} else {
				// New key in baseline, kept or modified
				out.WriteString(entry.RawText)
			}
		} else {
			// Brand new key added by user/agent during the session: preserve!
			out.WriteString(entry.RawText)
		}
	}

	result := out.String()
	result = strings.TrimPrefix(result, "\n")
	return result
}

// ExtractEnvFromSwappedFiles returns synthetic environment variables from all swapped files in projectDir.
func ExtractEnvFromSwappedFiles(projectDir string) map[string]string {
	absProj, err := filepath.Abs(projectDir)
	if err != nil {
		absProj = projectDir
	}
	absProj = filepath.Clean(absProj)

	swaps, err := LoadActiveSwaps()
	if err != nil {
		return nil
	}

	rec, found := swaps[absProj]
	if !found || rec == nil {
		return nil
	}

	return rec.SyntheticValues
}
