package secrets

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// VirtualizedEnvironment manages synthetic fake secret files on disk.
type VirtualizedEnvironment struct {
	ShadowDir    string
	WorkspaceDir string
	FileMap      map[string]string // real absolute path -> synthetic shadow file path
	InitialFiles map[string]bool   // non-secret real files linked at start
}

// PrepareVirtualization creates shadow files for all detected secret files.
func PrepareVirtualization(secretFiles []string) (*VirtualizedEnvironment, error) {
	tempDir, err := os.MkdirTemp("", "secretharbor-shadow-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create shadow scratch directory: %w", err)
	}

	ve := &VirtualizedEnvironment{
		ShadowDir: tempDir,
		FileMap:   make(map[string]string),
	}

	for _, realPath := range secretFiles {
		fakePath, err := ve.createShadowFile(realPath)
		if err != nil {
			ve.Cleanup()
			return nil, fmt.Errorf("failed to virtualize %s: %w", realPath, err)
		}
		ve.FileMap[realPath] = fakePath
	}

	return ve, nil
}

// createShadowFile creates a synthetic version of realPath inside ShadowDir.
func (ve *VirtualizedEnvironment) createShadowFile(realPath string) (string, error) {
	rel, err := filepath.Rel("/", realPath)
	if err != nil {
		rel = filepath.Base(realPath)
	}
	destPath := filepath.Join(ve.ShadowDir, rel)
	if err := os.MkdirAll(filepath.Dir(destPath), 0700); err != nil {
		return "", err
	}

	base := filepath.Base(realPath)
	ext := filepath.Ext(base)

	var fakeContent string
	if strings.HasPrefix(base, ".env") {
		f, err := os.Open(realPath)
		if err != nil {
			fakeContent = "# SecretHarbor Synthetic Environment\nDATABASE_URL=postgresql://secretharbor_user:fake@localhost:5432/fake_db\n"
		} else {
			defer f.Close()
			fakeContent, err = VirtualizeEnvContent(f)
			if err != nil {
				fakeContent = "# SecretHarbor Synthetic Environment\n"
			}
		}
	} else if ext == ".pem" || ext == ".key" {
		fakeContent = "-----BEGIN PRIVATE KEY-----\n" +
			"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC6qSecretHarbor\n" +
			"FakeSyntheticKeyForTestingPurposesOnlyNotARealPrivateKey==\n" +
			"-----END PRIVATE KEY-----\n"
	} else if strings.Contains(base, "credentials") && (ext == ".json" || ext == ".yaml" || ext == ".yml") {
		if ext == ".json" {
			fakeContent = "{\n  \"client_id\": \"secretharbor-fake-client-id\",\n  \"client_secret\": \"secretharbor-fake-secret\",\n  \"token\": \"secretharbor-fake-token\"\n}\n"
		} else {
			fakeContent = "client_id: secretharbor-fake-client-id\nclient_secret: secretharbor-fake-secret\ntoken: secretharbor-fake-token\n"
		}
	} else if base == ".npmrc" {
		fakeContent = "//registry.npmjs.org/:_authToken=secretharbor_fake_npm_token_00000000\n"
	} else if base == ".pypirc" {
		fakeContent = "[distutils]\nindex-servers = pypi\n\n[pypi]\nusername = __token__\npassword = pypi-secretharbor-fake-token\n"
	} else if base == ".netrc" {
		fakeContent = "machine github.com login fake_user password secretharbor_fake_token\n"
	} else if base == ".git-credentials" {
		fakeContent = "https://fake_user:secretharbor_fake_token@github.com\n"
	} else if base == "config" && strings.Contains(realPath, ".kube") {
		fakeContent = "apiVersion: v1\nclusters: []\ncontexts: []\ncurrent-context: \"\"\nkind: Config\npreferences: {}\nusers: []\n"
	} else {
		fakeContent = "# SecretHarbor Protected Synthetic Placeholder\n"
	}

	if err := os.WriteFile(destPath, []byte(fakeContent), 0600); err != nil {
		return "", err
	}

	return destPath, nil
}

// CreateShadowWorkspace creates an ephemeral linked project directory where non-secret files
// are hard-linked to the real files and secret files are replaced by synthetic fakes.
func (ve *VirtualizedEnvironment) CreateShadowWorkspace(projectDir string) (string, error) {
	wsDir, err := os.MkdirTemp("", "secretharbor-ws-*")
	if err != nil {
		return "", err
	}
	ve.WorkspaceDir = wsDir
	ve.InitialFiles = make(map[string]bool)

	err = filepath.Walk(projectDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		rel, err := filepath.Rel(projectDir, path)
		if err != nil || rel == "." {
			return nil
		}

		// Preserve .git and node_modules via directory symlinks for seamless tool integration
		if info.IsDir() {
			base := info.Name()
			if base == ".secretharbor" {
				return filepath.SkipDir
			}
			if base == ".git" || base == "node_modules" {
				destPath := filepath.Join(wsDir, rel)
				_ = os.Symlink(path, destPath)
				return filepath.SkipDir
			}
			return os.MkdirAll(filepath.Join(wsDir, rel), 0755)
		}

		destPath := filepath.Join(wsDir, rel)
		_ = os.MkdirAll(filepath.Dir(destPath), 0755)

		// Check if this file is virtualized as a fake secret
		if fakePath, isFake := ve.FileMap[path]; isFake {
			data, err := os.ReadFile(fakePath)
			if err == nil {
				return os.WriteFile(destPath, data, 0600)
			}
			return err
		}

		// Double-check: ensure any secret file is never marked as initial non-secret file
		if IsSecretFile(path, projectDir, nil, nil) {
			return nil
		}

		// Non-secret file: hardlink so edits in shadow workspace modify original project file.
		// If hardlink fails (e.g. cross-device), symlink to preserve bidirectional editing.
		ve.InitialFiles[path] = true
		if err := os.Link(path, destPath); err != nil {
			return os.Symlink(path, destPath)
		}
		return nil
	})

	return wsDir, err
}

// SyncBack copies newly created files and directories from the shadow workspace
// back to the real project directory and syncs deletions. Secret files and directories are never copied back.
func (ve *VirtualizedEnvironment) SyncBack(projectDir string) error {
	if ve.WorkspaceDir == "" {
		return nil
	}

	cleanProj := filepath.Clean(projectDir)

	// 1. Sync deletions: If a non-secret file existed initially in projectDir but was deleted
	// by the agent in the shadow workspace, remove it from projectDir as well.
	for origPath := range ve.InitialFiles {
		// Safety check: Never delete virtualized or sensitive secret files from host project
		if _, isSecret := ve.FileMap[origPath]; isSecret {
			continue
		}
		if IsSecretFile(origPath, projectDir, nil, nil) {
			continue
		}
		for realSec := range ve.FileMap {
			if realSec == origPath || strings.HasPrefix(origPath, realSec+string(filepath.Separator)) {
				continue
			}
		}

		rel, err := filepath.Rel(projectDir, origPath)
		if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
			continue
		}
		shadowPath := filepath.Join(ve.WorkspaceDir, rel)
		// Use os.Lstat to check if file/symlink itself still exists in shadow workspace
		if _, err := os.Lstat(shadowPath); os.IsNotExist(err) {
			_ = os.Remove(origPath)
		}
	}

	return filepath.Walk(ve.WorkspaceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		rel, err := filepath.Rel(ve.WorkspaceDir, path)
		if err != nil || rel == "." {
			return nil
		}

		// Prevent directory traversal: verify clean relative path does not escape workspace
		cleanRel := filepath.Clean(rel)
		if cleanRel == ".." || strings.HasPrefix(cleanRel, ".."+string(filepath.Separator)) {
			return nil
		}

		// Skip top-level and nested .git, node_modules, and .secretharbor
		base := info.Name()
		if base == ".git" || base == "node_modules" || base == ".secretharbor" {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		for _, part := range strings.Split(filepath.ToSlash(cleanRel), "/") {
			if part == ".git" || part == "node_modules" || part == ".secretharbor" {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}

		// Skip symlinks to prevent symlink traversal attacks on host
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}

		targetPath := filepath.Join(projectDir, cleanRel)
		cleanTarget := filepath.Clean(targetPath)

		// Ensure target strictly resides within projectDir
		if cleanTarget != cleanProj && !strings.HasPrefix(cleanTarget, cleanProj+string(filepath.Separator)) {
			return nil
		}

		// Never sync back virtualized secret files
		if _, isSecret := ve.FileMap[targetPath]; isSecret {
			return nil
		}
		for realSec := range ve.FileMap {
			if realSec == targetPath || strings.HasPrefix(targetPath, realSec+string(filepath.Separator)) {
				return nil
			}
		}
		if IsSecretFile(targetPath, projectDir, nil, nil) {
			return nil
		}

		if info.IsDir() {
			return os.MkdirAll(targetPath, info.Mode()|0700)
		}

		// If target does not exist on host, it was created by the agent in the shadow workspace
		if _, err := os.Stat(targetPath); os.IsNotExist(err) {
			return copyFile(path, targetPath, info.Mode())
		}

		return nil
	})
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

// Cleanup removes the shadow directory and ephemeral workspace.
func (ve *VirtualizedEnvironment) Cleanup() {
	if ve.ShadowDir != "" {
		_ = os.RemoveAll(ve.ShadowDir)
	}
	if ve.WorkspaceDir != "" {
		_ = os.RemoveAll(ve.WorkspaceDir)
	}
}
