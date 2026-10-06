package secrets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReconcileEnvFiles(t *testing.T) {
	realContent := `# Production Secrets
PORT=3000
DATABASE_URL=postgresql://real_user:super_secret_pw@prod.db:5432/main
STRIPE_SECRET_KEY=sk_live_REAL_STRIPE_SECRET_KEY_12345
API_KEY=real_api_key_abc
`

	baselineSynthetic := `# SECRETHARBOR SYNTHETIC ENVIRONMENT (ACTIVE SWAP)
# Project Hash: test1234 | Real secrets secured in ~/.secretharbor/vault
# Safe synthetic values generated for process isolation.

# Production Secrets
PORT=3000
DATABASE_URL=postgresql://secretharbor_user:fake_password@localhost:5432/fake_db?sslmode=disable
STRIPE_SECRET_KEY=sk_test_secretharbor_fake_12345678
API_KEY=secretharbor_fake_api_key_87654321
`

	// Scenario 1: Untouched - user/agent made zero edits
	rec1 := ReconcileEnvFiles(realContent, baselineSynthetic, baselineSynthetic)
	if rec1 != realContent {
		t.Fatalf("expected exact real content on untouched file, got:\n%s", rec1)
	}

	// Scenario 2: Agent added a new configuration variable & changed PORT
	editedContent := `# SECRETHARBOR SYNTHETIC ENVIRONMENT (ACTIVE SWAP)
# Project Hash: test1234 | Real secrets secured in ~/.secretharbor/vault
# Safe synthetic values generated for process isolation.

# Production Secrets
PORT=8080
DATABASE_URL=postgresql://secretharbor_user:fake_password@localhost:5432/fake_db?sslmode=disable
STRIPE_SECRET_KEY=sk_test_secretharbor_fake_12345678
API_KEY=secretharbor_fake_api_key_87654321
FEATURE_FLAG=true
NEW_API_URL=https://api.example.com
`

	rec2 := ReconcileEnvFiles(realContent, baselineSynthetic, editedContent)
	if !strings.Contains(rec2, "PORT=8080") {
		t.Errorf("expected updated PORT=8080, got:\n%s", rec2)
	}
	if !strings.Contains(rec2, "FEATURE_FLAG=true") {
		t.Errorf("expected added FEATURE_FLAG=true, got:\n%s", rec2)
	}
	if !strings.Contains(rec2, "NEW_API_URL=https://api.example.com") {
		t.Errorf("expected added NEW_API_URL, got:\n%s", rec2)
	}
	// Verify real secrets were restored, NOT fake secrets!
	if !strings.Contains(rec2, "DATABASE_URL=postgresql://real_user:super_secret_pw@prod.db:5432/main") {
		t.Errorf("expected real DATABASE_URL restored, got:\n%s", rec2)
	}
	if !strings.Contains(rec2, "STRIPE_SECRET_KEY=sk_live_REAL_STRIPE_SECRET_KEY_12345") {
		t.Errorf("expected real STRIPE_SECRET_KEY restored, got:\n%s", rec2)
	}
	if strings.Contains(rec2, "secretharbor_fake") || strings.Contains(rec2, "SECRETHARBOR SYNTHETIC") {
		t.Errorf("reconciled file must not contain synthetic markers, got:\n%s", rec2)
	}

	// Scenario 3: User intentionally replaced API_KEY with a new custom secret in editor
	userUpdatedSecretContent := `# Production Secrets
PORT=3000
DATABASE_URL=postgresql://secretharbor_user:fake_password@localhost:5432/fake_db?sslmode=disable
STRIPE_SECRET_KEY=sk_test_secretharbor_fake_12345678
API_KEY=my_brand_new_custom_api_key_99999
`
	rec3 := ReconcileEnvFiles(realContent, baselineSynthetic, userUpdatedSecretContent)
	if !strings.Contains(rec3, "API_KEY=my_brand_new_custom_api_key_99999") {
		t.Errorf("expected user-edited API_KEY to be saved, got:\n%s", rec3)
	}
	if !strings.Contains(rec3, "DATABASE_URL=postgresql://real_user:super_secret_pw@prod.db:5432/main") {
		t.Errorf("expected untouched DATABASE_URL to retain real value, got:\n%s", rec3)
	}
}

func TestSwapInPlaceAndRestore(t *testing.T) {
	// Create mock project directory
	tmpDir, err := os.MkdirTemp("", "shb-swap-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Isolate SECRETHARBOR_DIR for testing
	shbDir, err := os.MkdirTemp("", "shb-vault-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(shbDir)
	t.Setenv("SECRETHARBOR_DIR", shbDir)

	realSecretContent := "-----BEGIN PRIVATE KEY-----\nREAL_SECRET_MOCK_PRIVATE_KEY_DATA\n-----END PRIVATE KEY-----\n"
	secretFile := filepath.Join(tmpDir, "id_rsa_mock")
	if err := os.WriteFile(secretFile, []byte(realSecretContent), 0600); err != nil {
		t.Fatal(err)
	}

	// 1. Swap In Place (matches built-in pattern id_rsa*)
	rec, err := SwapInPlace(tmpDir, nil, nil, os.Getpid())
	if err != nil {
		t.Fatalf("SwapInPlace failed: %v", err)
	}
	if rec == nil || len(rec.Files) == 0 {
		t.Fatalf("expected 1 swapped file, got 0")
	}

	// In-tree file should now be synthetic fake
	swappedData, err := os.ReadFile(secretFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(swappedData), "REAL_SECRET_MOCK_PRIVATE_KEY_DATA") {
		t.Errorf("in-tree file must not contain real secret after swap!")
	}
	if !strings.Contains(string(swappedData), "SecretHarbor") {
		t.Errorf("in-tree file missing synthetic fake content!")
	}

	// 2. Restore
	if err := RestoreSwap(tmpDir); err != nil {
		t.Fatalf("RestoreSwap failed: %v", err)
	}

	// In-tree file should now be real content again
	restoredData, err := os.ReadFile(secretFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(restoredData) != realSecretContent {
		t.Errorf("restored content mismatch:\nexpected:\n%s\ngot:\n%s", realSecretContent, string(restoredData))
	}
}

func TestRestoreOrphanSwaps(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "shb-orphan-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	shbDir, err := os.MkdirTemp("", "shb-orphan-vault-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(shbDir)
	t.Setenv("SECRETHARBOR_DIR", shbDir)

	realSecret := "id_rsa_secret_sample_key"
	secretFile := filepath.Join(tmpDir, "id_rsa_sample")
	if err := os.WriteFile(secretFile, []byte(realSecret), 0600); err != nil {
		t.Fatal(err)
	}

	// Swap with a dead PID (e.g. 99999999)
	deadPID := 99999999
	rec, err := SwapInPlace(tmpDir, nil, nil, deadPID)
	if err != nil {
		t.Fatalf("SwapInPlace failed: %v", err)
	}
	if rec == nil {
		t.Fatal("expected non-nil record")
	}

	// In-tree file should be synthetic
	swapped, _ := os.ReadFile(secretFile)
	if string(swapped) == realSecret {
		t.Fatal("expected file to be swapped")
	}

	// Call RestoreOrphanSwaps
	cleaned := RestoreOrphanSwaps()
	if cleaned != 1 {
		t.Fatalf("expected 1 orphan cleaned, got %d", cleaned)
	}

	// Verify restored
	restored, _ := os.ReadFile(secretFile)
	if string(restored) != realSecret {
		t.Fatalf("expected restored content %q, got %q", realSecret, string(restored))
	}
}

func TestUpdateSwapPID(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "shb-pid-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	shbDir, err := os.MkdirTemp("", "shb-pid-vault-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(shbDir)
	t.Setenv("SECRETHARBOR_DIR", shbDir)

	secretFile := filepath.Join(tmpDir, ".env")
	if err := os.WriteFile(secretFile, []byte("SECRET=test"), 0600); err != nil {
		t.Fatal(err)
	}

	// 1. Initial swap with PID 1111
	rec, err := SwapInPlace(tmpDir, nil, nil, 1111)
	if err != nil {
		t.Fatalf("SwapInPlace failed: %v", err)
	}
	if rec == nil || rec.PID != 1111 {
		t.Fatalf("expected PID 1111, got %v", rec)
	}

	// 2. Update to new PID 2222
	UpdateSwapPID(tmpDir, 2222)

	swaps, err := LoadActiveSwaps()
	if err != nil {
		t.Fatalf("LoadActiveSwaps failed: %v", err)
	}
	absProj := CanonicalProjectPath(tmpDir)
	updatedRec := swaps[absProj]
	if updatedRec == nil || updatedRec.PID != 2222 {
		t.Fatalf("expected updated PID 2222, got %v", updatedRec)
	}

	// Clean up
	_ = RestoreSwap(tmpDir)
}

func TestSwapProjectRenameMove(t *testing.T) {
	// BUG-002: Project rename/move must not destroy real secrets; restore must find renamed directory
	baseDir := t.TempDir()
	origProj := filepath.Join(baseDir, "orig-project")
	if err := os.MkdirAll(origProj, 0755); err != nil {
		t.Fatal(err)
	}

	shbDir := filepath.Join(baseDir, "vault-home")
	t.Setenv("SECRETHARBOR_DIR", shbDir)

	realSecret := "DATABASE_URL=postgresql://real_admin:super_secret_db_pass@db.local:5432/main\n"
	secretFile := filepath.Join(origProj, ".env")
	if err := os.WriteFile(secretFile, []byte(realSecret), 0600); err != nil {
		t.Fatal(err)
	}

	rec, err := SwapInPlace(origProj, nil, nil, os.Getpid())
	if err != nil {
		t.Fatalf("SwapInPlace failed: %v", err)
	}
	if rec == nil || len(rec.Files) == 0 {
		t.Fatal("expected swapped file in original project")
	}

	// Rename project directory
	movedProj := filepath.Join(baseDir, "renamed-project")
	if err := os.Rename(origProj, movedProj); err != nil {
		t.Fatalf("failed to rename project directory: %v", err)
	}

	// Restore from renamed directory
	if err := RestoreSwap(movedProj); err != nil {
		t.Fatalf("RestoreSwap failed on moved project directory: %v", err)
	}

	// Verify real secret restored in moved project
	restoredData, err := os.ReadFile(filepath.Join(movedProj, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(restoredData), "super_secret_db_pass") {
		t.Fatalf("expected real secret restored in moved project, got:\n%s", string(restoredData))
	}
}

func TestSwapSymlinkAttackPrevention(t *testing.T) {
	// BUG-010: Symlink attack must not overwrite files outside project boundary
	baseDir := t.TempDir()
	outsideDir := filepath.Join(baseDir, "outside")
	if err := os.MkdirAll(outsideDir, 0755); err != nil {
		t.Fatal(err)
	}
	victimFile := filepath.Join(outsideDir, "victim_file.txt")
	victimContent := "CRITICAL_HOST_SYSTEM_DATA_DO_NOT_OVERWRITE"
	if err := os.WriteFile(victimFile, []byte(victimContent), 0600); err != nil {
		t.Fatal(err)
	}

	projDir := filepath.Join(baseDir, "project")
	if err := os.MkdirAll(projDir, 0755); err != nil {
		t.Fatal(err)
	}

	shbDir := filepath.Join(baseDir, "vault-home")
	t.Setenv("SECRETHARBOR_DIR", shbDir)

	// Create symlink inside project pointing outside to victimFile
	symlinkPath := filepath.Join(projDir, ".env")
	if err := os.Symlink(victimFile, symlinkPath); err != nil {
		t.Fatal(err)
	}

	// Run SwapInPlace
	rec, err := SwapInPlace(projDir, nil, nil, os.Getpid())
	if err != nil {
		t.Fatalf("SwapInPlace failed: %v", err)
	}
	if rec == nil || len(rec.Files) != 1 {
		t.Fatalf("expected external symlink to be replaced by a synthetic file, got %+v", rec)
	}
	if rec.Files[0].LinkTarget != victimFile {
		t.Errorf("expected recorded link target %s, got %s", victimFile, rec.Files[0].LinkTarget)
	}

	// The in-project path must now be a synthetic regular file.
	fakeData, err := os.ReadFile(symlinkPath)
	if err != nil {
		t.Fatalf("expected synthetic file at .env: %v", err)
	}
	if strings.Contains(string(fakeData), victimContent) {
		t.Fatalf("synthetic file leaked the external secret")
	}
	if fi, err := os.Lstat(symlinkPath); err != nil || fi.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("expected .env to be a regular file during the session")
	}

	// Verify victim file is completely untouched
	data, err := os.ReadFile(victimFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != victimContent {
		t.Fatalf("CRITICAL SECURITY FAILURE: external victim file was modified! Got %s", string(data))
	}

	// Restore must recreate the symlink and leave the victim untouched.
	if err := RestoreSwap(projDir); err != nil {
		t.Fatalf("RestoreSwap failed: %v", err)
	}
	if fi, err := os.Lstat(symlinkPath); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("expected .env symlink to be restored")
	}
	if target, _ := os.Readlink(symlinkPath); target != victimFile {
		t.Errorf("expected symlink target %s, got %s", victimFile, target)
	}
	if data, _ := os.ReadFile(victimFile); string(data) != victimContent {
		t.Fatalf("external victim file was modified during restore")
	}
}

func TestRestoreFailurePreservesBackupAndRegistry(t *testing.T) {
	// BUG-011: Restore failure must NOT delete backup directory or active_swaps registry
	baseDir := t.TempDir()
	projDir := filepath.Join(baseDir, "proj")
	if err := os.MkdirAll(projDir, 0755); err != nil {
		t.Fatal(err)
	}

	shbDir := filepath.Join(baseDir, "vault-home")
	t.Setenv("SECRETHARBOR_DIR", shbDir)

	realSecret := "SECRET_TOKEN=unrecoverable_precious_secret_12345\n"
	secretFile := filepath.Join(projDir, ".env")
	if err := os.WriteFile(secretFile, []byte(realSecret), 0600); err != nil {
		t.Fatal(err)
	}

	rec, err := SwapInPlace(projDir, nil, nil, os.Getpid())
	if err != nil {
		t.Fatalf("SwapInPlace failed: %v", err)
	}
	if rec == nil || len(rec.Files) == 0 {
		t.Fatal("expected swapped file")
	}

	// Make project directory read-only so atomic temp file write/rename fails
	if err := os.Chmod(projDir, 0500); err != nil {
		t.Fatal(err)
	}

	// Restore should fail because it cannot write to projDir
	restoreErr := RestoreSwap(projDir)
	if restoreErr == nil {
		_ = os.Chmod(projDir, 0755)
		t.Fatal("expected RestoreSwap to fail on read-only directory")
	}

	// Verify backup file still exists on disk
	backupFile := rec.Files[0].BackupPath
	if _, err := os.Stat(backupFile); os.IsNotExist(err) {
		_ = os.Chmod(projDir, 0755)
		t.Fatalf("CRITICAL BUG: backup file was deleted despite restore failure!")
	}

	// Verify active_swaps.json still contains the swap record
	swaps, err := LoadActiveSwaps()
	if err != nil {
		_ = os.Chmod(projDir, 0755)
		t.Fatalf("LoadActiveSwaps failed: %v", err)
	}
	if len(swaps) == 0 {
		_ = os.Chmod(projDir, 0755)
		t.Fatalf("CRITICAL BUG: active_swaps registry was wiped despite restore failure!")
	}

	// Restore permissions and retry restore
	if err := os.Chmod(projDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := RestoreSwap(projDir); err != nil {
		t.Fatalf("retry RestoreSwap failed: %v", err)
	}

	// Verify secret successfully restored
	finalData, _ := os.ReadFile(secretFile)
	if !strings.Contains(string(finalData), "unrecoverable_precious_secret_12345") {
		t.Fatalf("expected real secret restored, got: %s", string(finalData))
	}
}

func TestEncryptedShadowBackups(t *testing.T) {
	// BUG-034: Verify shadow backups in vault are encrypted and do NOT store plaintext
	baseDir := t.TempDir()
	projDir := filepath.Join(baseDir, "proj")
	if err := os.MkdirAll(projDir, 0755); err != nil {
		t.Fatal(err)
	}

	shbDir := filepath.Join(baseDir, "vault-home")
	t.Setenv("SECRETHARBOR_DIR", shbDir)

	secretPlaintext := "TOP_SECRET_PLAINTEXT_MATERIAL_987654321"
	secretFile := filepath.Join(projDir, ".env")
	if err := os.WriteFile(secretFile, []byte("API_KEY="+secretPlaintext+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	rec, err := SwapInPlace(projDir, nil, nil, os.Getpid())
	if err != nil {
		t.Fatalf("SwapInPlace failed: %v", err)
	}

	backupPath := rec.Files[0].BackupPath
	backupData, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatal(err)
	}

	// Verify backup does NOT contain plaintext secret
	if strings.Contains(string(backupData), secretPlaintext) {
		t.Fatal("CRITICAL: backup file contains unencrypted plaintext secret!")
	}

	// Clean up
	_ = RestoreSwap(projDir)
}

func TestLoadActiveSwaps_MalformedRegistry(t *testing.T) {
	// BUG-035: Corrupted active_swaps.json must return error instead of silently treating as empty
	baseDir := t.TempDir()
	shbDir := filepath.Join(baseDir, "vault-home")
	t.Setenv("SECRETHARBOR_DIR", shbDir)

	if err := os.MkdirAll(shbDir, 0700); err != nil {
		t.Fatal(err)
	}
	regFile := filepath.Join(shbDir, "active_swaps.json")
	if err := os.WriteFile(regFile, []byte("{ malformed json !!!"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadActiveSwaps()
	if err == nil {
		t.Fatal("expected LoadActiveSwaps to return error on malformed JSON, got nil")
	}
}

func TestReconcileEnvFiles_ExportAndMultiline(t *testing.T) {
	// BUG-062: Preserves export prefix, multiline values, comments, and formatting
	realContent := "# Production Config\n" +
		"export PORT=3000\n" +
		"export PRIVATE_KEY=\"-----BEGIN RSA PRIVATE KEY-----\n" +
		"REAL_KEY_MATERIAL\n" +
		"-----END RSA PRIVATE KEY-----\"\n" +
		"APP_NAME=myapp\n"

	baselineSynthetic := "# SECRETHARBOR SYNTHETIC ENVIRONMENT (ACTIVE SWAP)\n" +
		"# Production Config\n" +
		"export PORT=3000\n" +
		"export PRIVATE_KEY=secretharbor_fake_private_key_12345\n" +
		"APP_NAME=myapp\n"

	// User edited PORT and added NEW_VAR, left PRIVATE_KEY untouched
	currentContent := "# Production Config\n" +
		"export PORT=8080\n" +
		"export PRIVATE_KEY=secretharbor_fake_private_key_12345\n" +
		"APP_NAME=myapp\n" +
		"export NEW_VAR=hello\n"

	reconciled := ReconcileEnvFiles(realContent, baselineSynthetic, currentContent)

	if !strings.Contains(reconciled, "export PORT=8080") {
		t.Errorf("expected updated export PORT=8080, got:\n%s", reconciled)
	}
	if !strings.Contains(reconciled, "export NEW_VAR=hello") {
		t.Errorf("expected added export NEW_VAR=hello, got:\n%s", reconciled)
	}
	// Verify exact multiline real secret restored
	if !strings.Contains(reconciled, "REAL_KEY_MATERIAL") {
		t.Errorf("expected multiline REAL_KEY_MATERIAL restored, got:\n%s", reconciled)
	}
	if !strings.Contains(reconciled, "export PRIVATE_KEY=\"-----BEGIN RSA PRIVATE KEY-----") {
		t.Errorf("expected export and quotes preserved on real secret, got:\n%s", reconciled)
	}
}

func TestSwapSymlinkHandling(t *testing.T) {
	projDir := t.TempDir()
	shbDir := t.TempDir()
	t.Setenv("SECRETHARBOR_DIR", shbDir)

	extDir := t.TempDir()
	extFile := filepath.Join(extDir, "victim.txt")
	if err := os.WriteFile(extFile, []byte("EXTERNAL-REAL-SECRET"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(filepath.Join(projDir, "config"), 0700); err != nil {
		t.Fatal(err)
	}
	inFile := filepath.Join(projDir, "config", "real.env")
	if err := os.WriteFile(inFile, []byte("INPROJ-REAL-SECRET"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink("config/real.env", filepath.Join(projDir, ".env")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(extFile, filepath.Join(projDir, "credentials.json")); err != nil {
		t.Fatal(err)
	}

	rec, err := SwapInPlace(projDir, nil, nil, os.Getpid())
	if err != nil {
		t.Fatalf("SwapInPlace failed: %v", err)
	}
	if rec == nil {
		t.Fatal("expected a swap record")
	}

	// In-project symlink target must be virtualized.
	if data, _ := os.ReadFile(inFile); strings.Contains(string(data), "INPROJ-REAL-SECRET") {
		t.Error("in-project symlink target still contains the real secret")
	}

	// External symlink target must never be modified.
	if data, _ := os.ReadFile(extFile); string(data) != "EXTERNAL-REAL-SECRET" {
		t.Errorf("external symlink target was modified: %q", string(data))
	}

	canonExt, _ := filepath.EvalSymlinks(extFile)
	denied := false
	for _, p := range rec.DeniedExternal {
		if p == extFile || p == canonExt {
			denied = true
			break
		}
	}
	if !denied {
		t.Errorf("expected external symlink target to be marked denied, got %v", rec.DeniedExternal)
	}

	if err := RestoreSwap(projDir); err != nil {
		t.Fatalf("RestoreSwap failed: %v", err)
	}
	if data, _ := os.ReadFile(inFile); string(data) != "INPROJ-REAL-SECRET" {
		t.Errorf("in-project secret was not restored: %q", string(data))
	}
}

func TestShadowWorkspaceVirtualization(t *testing.T) {
	projDir := t.TempDir()
	shbDir := t.TempDir()
	t.Setenv("SECRETHARBOR_DIR", shbDir)

	envPath := filepath.Join(projDir, ".env")
	if err := os.WriteFile(envPath, []byte("OPENAI_API_KEY=sk-real-shadow\n"), 0600); err != nil {
		t.Fatal(err)
	}
	appPath := filepath.Join(projDir, "app.js")
	if err := os.WriteFile(appPath, []byte("console.log(1)\n"), 0644); err != nil {
		t.Fatal(err)
	}
	protectedPath := filepath.Join(projDir, "secretharbor.yaml")
	if err := os.WriteFile(protectedPath, []byte("version: 1\n"), 0644); err != nil {
		t.Fatal(err)
	}

	files, err := DetectSecretFilesInDir(projDir, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ve, err := PrepareVirtualization(files)
	if err != nil {
		t.Fatal(err)
	}
	defer ve.Cleanup()
	ve.ProtectedPaths = []string{protectedPath}

	ws, err := ve.CreateShadowWorkspace(projDir)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(ws)

	// Real secret file must be untouched.
	if data, _ := os.ReadFile(envPath); string(data) != "OPENAI_API_KEY=sk-real-shadow\n" {
		t.Fatalf("real .env was modified: %q", string(data))
	}
	// Shadow .env must be synthetic.
	shadowEnv, err := os.ReadFile(filepath.Join(ws, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(shadowEnv), "sk-real-shadow") {
		t.Fatal("shadow .env leaked the real secret")
	}
	// Non-secret files are hard-linked.
	realInfo, _ := os.Stat(appPath)
	shadowInfo, _ := os.Stat(filepath.Join(ws, "app.js"))
	if realInfo == nil || shadowInfo == nil || !os.SameFile(realInfo, shadowInfo) {
		t.Fatal("expected non-secret file to be hard-linked into the shadow")
	}
	// Protected file is a read-only copy, not a link.
	pInfo, _ := os.Stat(filepath.Join(ws, "secretharbor.yaml"))
	if pInfo == nil || pInfo.Mode().Perm()&0200 != 0 {
		t.Fatalf("expected protected file to be read-only, mode=%v", pInfo.Mode())
	}
	if os.SameFile(realInfo, pInfo) {
		t.Fatal("protected file must not be hard-linked")
	}

	// Agent creates a new file: it must sync back.
	if err := os.WriteFile(filepath.Join(ws, "new.txt"), []byte("created\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// Agent replaces a hard-linked file via rename: content must sync back.
	tmp := filepath.Join(ws, ".tmp-app")
	if err := os.WriteFile(tmp, []byte("console.log(2)\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(ws, "app.js")); err != nil {
		t.Fatal(err)
	}

	if err := ve.SyncBack(projDir); err != nil {
		t.Fatalf("SyncBack failed: %v", err)
	}
	if data, _ := os.ReadFile(filepath.Join(projDir, "new.txt")); string(data) != "created\n" {
		t.Fatalf("agent-created file was not synced back: %q", string(data))
	}
	if data, _ := os.ReadFile(appPath); string(data) != "console.log(2)\n" {
		t.Fatalf("rename-style edit was not synced back: %q", string(data))
	}
	if data, _ := os.ReadFile(envPath); string(data) != "OPENAI_API_KEY=sk-real-shadow\n" {
		t.Fatalf("real .env was modified by SyncBack: %q", string(data))
	}
	if data, _ := os.ReadFile(protectedPath); string(data) != "version: 1\n" {
		t.Fatalf("protected file was modified: %q", string(data))
	}
}
