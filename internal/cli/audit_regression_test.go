package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/secretharbor/secretharbor/internal/cleaner"
	"github.com/secretharbor/secretharbor/internal/policy"
	"github.com/secretharbor/secretharbor/internal/secrets"
	"github.com/secretharbor/secretharbor/internal/vault"
)

func TestAuditPolicyExplainVariations(t *testing.T) {
	tmpDir := t.TempDir()
	origWd, _ := os.Getwd()
	defer func() { _ = os.Chdir(origWd) }()
	_ = os.Chdir(tmpDir)

	if err := RunInit("shb", []string{}); err != nil {
		t.Fatalf("failed to init config: %v", err)
	}

	// Create real files and directories
	if err := os.WriteFile(filepath.Join(tmpDir, ".env"), []byte("SECRET=123\n"), 0600); err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("skipping: outer sandbox restricts .env creation: %v", err)
		}
		t.Fatalf("failed to create .env: %v", err)
	}
	srcDir := filepath.Join(tmpDir, "src")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatalf("failed to create src dir: %v", err)
	}

	// 1. Relative path to .env
	outRel := captureStdout(func() {
		if err := RunPolicy("shb", []string{"explain", ".env"}); err != nil {
			t.Errorf("explain .env failed: %v", err)
		}
	})
	if !strings.Contains(outRel, "built-in secret pattern") {
		t.Errorf("expected built-in secret pattern for relative .env, got: %s", outRel)
	}

	// 2. Absolute path to .env
	absEnv := filepath.Join(tmpDir, ".env")
	outAbs := captureStdout(func() {
		if err := RunPolicy("shb", []string{"explain", absEnv}); err != nil {
			t.Errorf("explain absolute .env failed: %v", err)
		}
	})
	if !strings.Contains(outAbs, "built-in secret pattern") {
		t.Errorf("expected built-in secret pattern for absolute .env, got: %s", outAbs)
	}

	// 3. Nonexistent secret file
	outNonexistentSecret := captureStdout(func() {
		if err := RunPolicy("shb", []string{"explain", "config/private.key"}); err != nil {
			t.Errorf("explain nonexistent secret failed: %v", err)
		}
	})
	if !strings.Contains(outNonexistentSecret, "built-in secret pattern") {
		t.Errorf("expected built-in secret pattern for nonexistent .key, got: %s", outNonexistentSecret)
	}
	if !strings.Contains(outNonexistentSecret, "nonexistent path") {
		t.Errorf("expected nonexistent path indicator, got: %s", outNonexistentSecret)
	}

	// 4. Directory target
	outDir := captureStdout(func() {
		if err := RunPolicy("shb", []string{"explain", "src"}); err != nil {
			t.Errorf("explain directory failed: %v", err)
		}
	})
	if !strings.Contains(outDir, "Directory") {
		t.Errorf("expected Directory indicator, got: %s", outDir)
	}
}

func TestAuditConfigGetAndSet(t *testing.T) {
	tmpDir := t.TempDir()
	origWd, _ := os.Getwd()
	defer func() { _ = os.Chdir(origWd) }()
	_ = os.Chdir(tmpDir)

	if err := RunInit("shb", []string{}); err != nil {
		t.Fatalf("failed to init config: %v", err)
	}

	// 1. Initial config get protection -> standard
	outGet := captureStdout(func() {
		if err := RunConfig("shb", []string{"get", "protection"}); err != nil {
			t.Errorf("config get protection failed: %v", err)
		}
	})
	if !strings.Contains(outGet, "standard") {
		t.Errorf("expected standard protection, got: %s", outGet)
	}

	// 2. Config set protection strict
	if err := RunConfig("shb", []string{"set", "protection", "strict"}); err != nil {
		t.Fatalf("config set protection strict failed: %v", err)
	}

	// 3. Verify updated protection
	outGetStrict := captureStdout(func() {
		if err := RunConfig("shb", []string{"get", "protection"}); err != nil {
			t.Errorf("config get protection after set failed: %v", err)
		}
	})
	if !strings.Contains(outGetStrict, "strict") {
		t.Errorf("expected strict protection, got: %s", outGetStrict)
	}

	// 4. Config set guard off and get guard
	if err := RunConfig("shb", []string{"set", "guard", "off"}); err != nil {
		t.Fatalf("config set guard off failed: %v", err)
	}
	outGetGuard := captureStdout(func() {
		if err := RunConfig("shb", []string{"get", "guard"}); err != nil {
			t.Errorf("config get guard failed: %v", err)
		}
	})
	if !strings.Contains(outGetGuard, "off") {
		t.Errorf("expected guard off, got: %s", outGetGuard)
	}

	// 5. Config set invalid key/val returns error
	if err := RunConfig("shb", []string{"set", "protection", "invalid_preset"}); err == nil {
		t.Errorf("expected error setting invalid protection, got nil")
	}
}

func TestAuditSecretDeleteValidation(t *testing.T) {
	tmpDir := t.TempDir()
	origWd, _ := os.Getwd()
	defer func() { _ = os.Chdir(origWd) }()
	_ = os.Chdir(tmpDir)

	vPath := filepath.Join(tmpDir, ".secretharbor", "vault.enc")
	_ = os.MkdirAll(filepath.Dir(vPath), 0700)
	v, err := vault.OpenVault(vPath)
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("skipping: outer sandbox restricts vault.key creation: %v", err)
		}
		t.Fatalf("failed to open vault: %v", err)
	}
	vault.GlobalVault = v

	// Delete nonexistent key must error
	err = RunSecret("shb", []string{"delete", "NONEXISTENT_KEY"})
	if err == nil {
		t.Errorf("expected error deleting nonexistent secret, got nil")
	} else if !strings.Contains(err.Error(), "not found in vault") {
		t.Errorf("unexpected error message: %v", err)
	}

	// Set key and then delete key
	if err := RunSecret("shb", []string{"set", "TEST_KEY", "test_value"}); err != nil {
		t.Fatalf("failed to set secret: %v", err)
	}
	if err := RunSecret("shb", []string{"delete", "TEST_KEY"}); err != nil {
		t.Fatalf("failed to delete existing secret: %v", err)
	}
}

func TestAuditTrustEmptyPolicyAndFormatting(t *testing.T) {
	tmpDir := t.TempDir()
	origWd, _ := os.Getwd()
	defer func() { _ = os.Chdir(origWd) }()
	_ = os.Chdir(tmpDir)

	// Create an empty policy file
	policyPath := filepath.Join(tmpDir, policy.DefaultConfigFileName)
	if err := os.WriteFile(policyPath, []byte(""), 0644); err != nil {
		t.Fatalf("failed to create empty policy: %v", err)
	}

	// Adding trust on an empty policy should safely succeed
	if err := RunTrust("shb", []string{"add", "cargo"}); err != nil {
		t.Fatalf("trust add on empty policy failed: %v", err)
	}

	outList := captureStdout(func() {
		if err := RunTrust("shb", []string{"list"}); err != nil {
			t.Errorf("trust list failed: %v", err)
		}
	})
	if !strings.Contains(outList, "cargo") {
		t.Errorf("expected cargo in trust list, got: %s", outList)
	}
}

func TestAuditCleanerOsTempDir(t *testing.T) {
	// Create a test socket and stale workspace in os.TempDir()
	sysTmp := os.TempDir()
	fakeSocket := filepath.Join(sysTmp, "shb-d-9999999-1.sock")
	if err := os.WriteFile(fakeSocket, []byte("test"), 0600); err != nil {
		t.Fatalf("failed to write fake socket: %v", err)
	}
	defer func() { _ = os.Remove(fakeSocket) }()

	staleWorkspace := filepath.Join(sysTmp, "secretharbor-test-cleaner-audit")
	if err := os.MkdirAll(staleWorkspace, 0700); err != nil {
		t.Fatalf("failed to create fake workspace: %v", err)
	}
	// Make it older than 2 hours
	oldTime := time.Now().Add(-3 * time.Hour)
	_ = os.Chtimes(staleWorkspace, oldTime, oldTime)
	defer func() { _ = os.RemoveAll(staleWorkspace) }()

	res := cleaner.CleanOrphans()
	if res.CleanedSockets < 1 {
		t.Errorf("expected cleaner to clean fake socket from os.TempDir(), got cleaned: %d", res.CleanedSockets)
	}
	if res.CleanedWorkspaces < 1 {
		t.Errorf("expected cleaner to clean stale workspace from os.TempDir(), got cleaned: %d", res.CleanedWorkspaces)
	}
}

func TestAuditVirtualizerSyncBackProtection(t *testing.T) {
	projDir := t.TempDir()

	// Create a real .env file and normal file
	realEnv := filepath.Join(projDir, ".env")
	if err := os.WriteFile(realEnv, []byte("REAL_SECRET=super_secret\n"), 0600); err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("skipping: outer sandbox restricts .env creation: %v", err)
		}
		t.Fatalf("failed to write .env: %v", err)
	}
	codeFile := filepath.Join(projDir, "main.go")
	if err := os.WriteFile(codeFile, []byte("package main\n"), 0644); err != nil {
		t.Fatalf("failed to write main.go: %v", err)
	}

	ve, err := secrets.PrepareVirtualization([]string{realEnv})
	if err != nil {
		t.Fatalf("PrepareVirtualization failed: %v", err)
	}
	defer ve.Cleanup()

	wsDir, err := ve.CreateShadowWorkspace(projDir)
	if err != nil {
		t.Fatalf("CreateShadowWorkspace failed: %v", err)
	}

	// 1. In shadow workspace, simulate agent deleting .env
	shadowEnv := filepath.Join(wsDir, ".env")
	_ = os.Remove(shadowEnv)

	// 2. In shadow workspace, agent creates a new file and a fake node_modules file
	newFile := filepath.Join(wsDir, "new_code.go")
	if err := os.WriteFile(newFile, []byte("package main\n// new file"), 0644); err != nil {
		t.Fatalf("failed to write new file in shadow: %v", err)
	}
	nodeModDir := filepath.Join(wsDir, "node_modules", "malicious-pkg")
	_ = os.MkdirAll(nodeModDir, 0755)
	_ = os.WriteFile(filepath.Join(nodeModDir, "index.js"), []byte("console.log()"), 0644)

	// 3. Run SyncBack
	if err := ve.SyncBack(projDir); err != nil {
		t.Fatalf("SyncBack failed: %v", err)
	}

	// 4. Verify REAL .env was NOT deleted from host project directory!
	realEnvContent, err := os.ReadFile(realEnv)
	if err != nil {
		t.Fatalf("CRITICAL: real .env was deleted from host project directory! Err: %v", err)
	}
	if !strings.Contains(string(realEnvContent), "REAL_SECRET=super_secret") {
		t.Errorf("real .env content was modified/corrupted: %s", string(realEnvContent))
	}

	// 5. Verify new legitimate code file WAS synced back
	if _, err := os.Stat(filepath.Join(projDir, "new_code.go")); err != nil {
		t.Errorf("expected new_code.go to be synced back to host, err: %v", err)
	}

	// 6. Verify node_modules was NOT synced back to host
	if _, err := os.Stat(filepath.Join(projDir, "node_modules", "malicious-pkg")); !os.IsNotExist(err) {
		t.Errorf("node_modules should NOT have been synced back to host!")
	}
}
