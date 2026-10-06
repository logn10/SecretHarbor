package updater

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// MaxDecompressedBinarySize limits extraction size to prevent decompression bomb attacks (256 MB).
const MaxDecompressedBinarySize = 256 * 1024 * 1024

// UpdateCheckResult details whether a newer version is available.
type UpdateCheckResult struct {
	CurrentVersion  string       `json:"current_version"`
	LatestVersion   string       `json:"latest_version"`
	TargetVersion   string       `json:"target_version"`
	UpdateAvailable bool         `json:"update_available"`
	Artifact        ArtifactInfo `json:"artifact"`
	Signature       string       `json:"signature,omitempty"`
	ReleaseNotes    string       `json:"release_notes,omitempty"`
}

// UpdateResult captures the outcome of an applied update.
type UpdateResult struct {
	PreviousVersion string `json:"previous_version"`
	CurrentVersion  string `json:"current_version"`
	ChecksumStatus  string `json:"checksum_status,omitempty"`
	SignatureStatus string `json:"signature_status"`
	BackupPath      string `json:"backup_path,omitempty"`
	Success         bool   `json:"success"`
	DryRun          bool   `json:"dry_run,omitempty"`
}

// CheckAgentLockout verifies that the update command is not being invoked by an untrusted agent process.
func CheckAgentLockout() error {
	if os.Getenv("SECRETHARBOR_SANDBOX") == "1" || os.Getenv("SHB_SANDBOX") == "1" {
		return fmt.Errorf("Permission denied: SecretHarbor self-update is human-controlled.\nSandboxed agents and processes cannot modify the security boundary binary.")
	}
	return nil
}

// CheckForUpdate checks if an update is available from the release manifest.
func CheckForUpdate(currentVersion string, requestedVersion string) (*UpdateCheckResult, error) {
	manifest, err := FetchReleaseManifestForVersion("", requestedVersion)
	if err != nil {
		return nil, err
	}

	platformKey := GetPlatformKey()
	artifact, exists := manifest.Artifacts[platformKey]
	if !exists {
		return nil, fmt.Errorf("no release artifact available for current platform (%s)", platformKey)
	}

	// Validate artifact download URL requires HTTPS
	if err := ValidateHTTPSURL(artifact.URL); err != nil {
		return nil, err
	}

	targetVersion := manifest.Version
	if requestedVersion != "" {
		targetVersion = requestedVersion
	}

	updateAvailable := false
	if requestedVersion != "" {
		// Explicit version requested: allow upgrade or pin/downgrade when explicitly requested
		updateAvailable = (CompareVersions(targetVersion, currentVersion) != 0)
	} else {
		// Automatic check: strictly prevent downgrades; only update if target is strictly newer
		updateAvailable = (CompareVersions(manifest.Version, currentVersion) > 0)
	}

	// Discover cryptographic signature if published in manifest
	var signature string
	if manifest.Signatures != nil {
		if sig, ok := manifest.Signatures[platformKey]; ok {
			signature = sig
		} else if sig, ok := manifest.Signatures[artifact.Filename]; ok {
			signature = sig
		}
	}

	return &UpdateCheckResult{
		CurrentVersion:  currentVersion,
		LatestVersion:   manifest.Version,
		TargetVersion:   targetVersion,
		UpdateAvailable: updateAvailable,
		Artifact:        artifact,
		Signature:       signature,
		ReleaseNotes:    manifest.ReleaseNotes,
	}, nil
}

// ApplyUpdate downloads, cryptographically verifies, and atomically replaces the SecretHarbor executable.
func ApplyUpdate(currentVersion string, requestedVersion string, dryRun bool) (*UpdateResult, error) {
	// 1. Enforce strict agent lockout
	if err := CheckAgentLockout(); err != nil {
		return nil, err
	}

	// 2. Fetch release check
	check, err := CheckForUpdate(currentVersion, requestedVersion)
	if err != nil {
		return nil, err
	}

	// Prevent downgrades unless explicit version was specified
	if requestedVersion == "" && CompareVersions(check.TargetVersion, currentVersion) < 0 {
		return nil, fmt.Errorf("refusing automatic downgrade from %s to %s; specify --version explicitly if downgrade is intended", currentVersion, check.TargetVersion)
	}

	if !check.UpdateAvailable && requestedVersion == "" {
		return &UpdateResult{
			PreviousVersion: currentVersion,
			CurrentVersion:  currentVersion,
			ChecksumStatus:  "N/A (already up to date)",
			SignatureStatus: "N/A (already up to date)",
			Success:         true,
		}, nil
	}

	// 3. Resolve target executable path
	execPath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("failed to locate running executable: %w", err)
	}
	realPath, err := filepath.EvalSymlinks(execPath)
	if err == nil && realPath != "" {
		execPath = realPath
	}
	execDir := filepath.Dir(execPath)

	// 4. Verify write permissions to the binary location using a secure temporary file
	permTestFile, err := os.CreateTemp(execDir, ".perm-test-*")
	if err != nil {
		if os.IsPermission(err) {
			return nil, fmt.Errorf("installation directory %s requires elevated privileges\nPlease re-run with sudo: sudo shb update", execDir)
		}
		return nil, fmt.Errorf("cannot write to installation directory %s: %w", execDir, err)
	}
	permTestPath := permTestFile.Name()
	_ = permTestFile.Close()
	_ = os.Remove(permTestPath)

	if dryRun {
		sigStatus := "UNSIGNED (dry-run simulation)"
		if check.Signature != "" {
			sigStatus = "VERIFIED (Ed25519 simulated)"
		}
		return &UpdateResult{
			PreviousVersion: currentVersion,
			CurrentVersion:  check.TargetVersion,
			ChecksumStatus:  "VERIFIED (SHA-256 simulated)",
			SignatureStatus: sigStatus,
			Success:         true,
			DryRun:          true,
		}, nil
	}

	// 5. Download artifact over HTTPS
	if err := ValidateHTTPSURL(check.Artifact.URL); err != nil {
		return nil, err
	}

	resp, err := HTTPClient.Get(check.Artifact.URL)
	if err != nil {
		return nil, formatNetworkError(check.Artifact.URL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download failed (HTTP %d)", resp.StatusCode)
	}

	rawPayload, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read update payload: %w", err)
	}

	// 6. Cryptographic integrity verification (distinguish SHA-256 checksum from Ed25519 signature)
	if err := VerifyBytesSHA256(rawPayload, check.Artifact.SHA256); err != nil {
		return nil, fmt.Errorf("checksum verification failed: %w", err)
	}
	checksumStatus := "VERIFIED (SHA-256)"

	signatureStatus := "UNSIGNED (checksum only)"
	if check.Signature != "" {
		pubKey := GetReleasePublicKey()
		if err := VerifySignature(rawPayload, check.Signature, pubKey); err != nil {
			return nil, fmt.Errorf("cryptographic signature verification failed: %w", err)
		}
		signatureStatus = "VERIFIED (Ed25519)"
	}

	// 7. Extract binary payload with decompression bomb and zip-slip protection
	binaryBytes, err := extractExecutableBytes(rawPayload, check.Artifact.Filename)
	if err != nil {
		return nil, fmt.Errorf("failed to process release artifact: %w", err)
	}

	// 8. Atomic replacement with automatic rollback
	tmpFile, err := os.CreateTemp(execDir, ".shb-new-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary file in %s: %w", execDir, err)
	}
	tempPath := tmpFile.Name()
	defer func() {
		_ = os.Remove(tempPath)
	}()

	if err := tmpFile.Chmod(0755); err != nil {
		_ = tmpFile.Close()
		return nil, fmt.Errorf("failed to set executable permissions: %w", err)
	}

	if _, err := tmpFile.Write(binaryBytes); err != nil {
		_ = tmpFile.Close()
		return nil, fmt.Errorf("failed to write new binary: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return nil, fmt.Errorf("failed to close temporary binary file: %w", err)
	}

	backupPath := execPath + ".old"
	_ = os.Remove(backupPath)

	// Move current executable to backup
	if err := os.Rename(execPath, backupPath); err != nil {
		return nil, fmt.Errorf("failed to backup existing binary: %w", err)
	}

	// Move new executable into place atomically
	if err := os.Rename(tempPath, execPath); err != nil {
		// Attempt immediate rollback
		_ = os.Rename(backupPath, execPath)
		return nil, fmt.Errorf("failed to atomically install new binary (rolled back): %w", err)
	}

	// 9. Verify sanity health of installed binary
	cmd := exec.Command(execPath, "version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Automatic rollback on corrupted/broken executable
		_ = os.Rename(backupPath, execPath)
		return nil, fmt.Errorf("installed binary failed sanity health check (rolled back):\n%s", string(out))
	}

	return &UpdateResult{
		PreviousVersion: currentVersion,
		CurrentVersion:  check.TargetVersion,
		ChecksumStatus:  checksumStatus,
		SignatureStatus: signatureStatus,
		BackupPath:      backupPath,
		Success:         true,
	}, nil
}

// extractExecutableBytes safely extracts executable binaries from tar.gz, zip, or raw binaries.
// Enforces decompression bomb limits and zip-slip path traversal guards.
func extractExecutableBytes(data []byte, filename string) ([]byte, error) {
	lower := strings.ToLower(filename)

	if strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz") {
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("failed to initialize gzip reader: %w", err)
		}
		defer gz.Close()

		tr := tar.NewReader(gz)
		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("failed to read tar entry: %w", err)
			}

			// Zip-slip guard
			cleanName := filepath.Clean(hdr.Name)
			if strings.HasPrefix(cleanName, "..") || filepath.IsAbs(cleanName) || strings.Contains(hdr.Name, "../") {
				return nil, fmt.Errorf("zip-slip path traversal detected in archive: %q", hdr.Name)
			}

			base := filepath.Base(cleanName)
			if base == "shb" || base == "secretharbor" || base == "shb.exe" || base == "secretharbor.exe" {
				lr := io.LimitReader(tr, MaxDecompressedBinarySize+1)
				extracted, err := io.ReadAll(lr)
				if err != nil {
					return nil, fmt.Errorf("error reading executable entry: %w", err)
				}
				if len(extracted) > MaxDecompressedBinarySize {
					return nil, fmt.Errorf("decompression bomb detected: extracted binary exceeds size limit (%d bytes)", MaxDecompressedBinarySize)
				}
				return extracted, nil
			}
		}
		return nil, fmt.Errorf("executable binary not found inside archive %s", filename)
	}

	if strings.HasSuffix(lower, ".zip") {
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return nil, fmt.Errorf("failed to open zip archive: %w", err)
		}

		for _, file := range zr.File {
			cleanName := filepath.Clean(file.Name)
			if strings.HasPrefix(cleanName, "..") || filepath.IsAbs(cleanName) || strings.Contains(file.Name, "../") {
				return nil, fmt.Errorf("zip-slip path traversal detected in zip archive: %q", file.Name)
			}

			base := filepath.Base(cleanName)
			if base == "shb" || base == "secretharbor" || base == "shb.exe" || base == "secretharbor.exe" {
				rc, err := file.Open()
				if err != nil {
					return nil, fmt.Errorf("failed to open zip file entry %s: %w", file.Name, err)
				}
				defer rc.Close()

				lr := io.LimitReader(rc, MaxDecompressedBinarySize+1)
				extracted, err := io.ReadAll(lr)
				if err != nil {
					return nil, fmt.Errorf("error reading zip entry: %w", err)
				}
				if len(extracted) > MaxDecompressedBinarySize {
					return nil, fmt.Errorf("decompression bomb detected: extracted binary exceeds size limit (%d bytes)", MaxDecompressedBinarySize)
				}
				return extracted, nil
			}
		}
		return nil, fmt.Errorf("executable binary not found inside zip archive %s", filename)
	}

	// Direct binary
	return data, nil
}
