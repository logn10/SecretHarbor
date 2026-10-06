package vault_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secretharbor/secretharbor/internal/vault"
)

func TestVaultEncryptDecrypt(t *testing.T) {
	tmpDir := t.TempDir()
	v, err := vault.OpenVault(tmpDir)
	if err != nil {
		t.Fatalf("failed to open vault: %v", err)
	}

	key := "STRIPE_PRODUCTION_SECRET"
	val := "sk_live_998877665544332211"

	// 1. Set secret
	if err := v.Set(key, val); err != nil {
		t.Fatalf("failed to set secret: %v", err)
	}

	// 2. Get secret
	retrieved, exists, err := v.Get(key)
	if err != nil {
		t.Fatalf("failed to get secret: %v", err)
	}
	if !exists {
		t.Fatalf("expected key %s to exist", key)
	}
	if retrieved != val {
		t.Errorf("got %s, expected %s", retrieved, val)
	}

	// 3. Verify encrypted file does NOT contain plaintext
	encData, err := os.ReadFile(filepath.Join(tmpDir, "vault.enc"))
	if err != nil {
		t.Fatalf("failed to read vault.enc: %v", err)
	}
	if strings.Contains(string(encData), val) {
		t.Fatal("plaintext secret leaked into encrypted file!")
	}

	// 4. List secrets
	keys, err := v.List()
	if err != nil {
		t.Fatalf("failed to list secrets: %v", err)
	}
	if len(keys) != 1 || keys[0] != key {
		t.Errorf("unexpected keys list: %v", keys)
	}

	// 5. Delete secret
	if err := v.Delete(key); err != nil {
		t.Fatalf("failed to delete secret: %v", err)
	}
	_, exists, _ = v.Get(key)
	if exists {
		t.Fatal("expected key to be deleted")
	}
}

func TestKeyStorageAndPermissions(t *testing.T) {
	tmpDir := t.TempDir()
	_, err := vault.OpenVault(tmpDir)
	if err != nil {
		t.Fatalf("failed to open vault: %v", err)
	}

	keyFile := filepath.Join(tmpDir, "keys", "vault.key")
	info, err := os.Stat(keyFile)
	if err != nil {
		t.Fatalf("key file should exist in separate keys directory: %v", err)
	}

	// Verify permissions are strictly 0600
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("expected key file permissions 0600, got %o", perm)
	}

	keyDirInfo, err := os.Stat(filepath.Join(tmpDir, "keys"))
	if err != nil {
		t.Fatalf("keys dir should exist: %v", err)
	}
	if keyDirInfo.Mode().Perm() != 0700 {
		t.Errorf("expected keys dir permissions 0700, got %o", keyDirInfo.Mode().Perm())
	}
}

func TestVaultRawEncryptDecrypt(t *testing.T) {
	tmpDir := t.TempDir()
	v, err := vault.OpenVault(tmpDir)
	if err != nil {
		t.Fatalf("failed to open vault: %v", err)
	}

	plaintext := []byte("super secret data to be protected")
	ciphertext, err := v.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if strings.Contains(string(ciphertext), string(plaintext)) {
		t.Fatal("ciphertext contains plaintext")
	}

	decrypted, err := v.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Fatalf("got %q, expected %q", string(decrypted), string(plaintext))
	}
}

func TestDeriveKeyPBKDF2(t *testing.T) {
	k1 := vault.DeriveKey("saltA", "password123")
	k2 := vault.DeriveKey("saltA", "password123")
	k3 := vault.DeriveKey("saltB", "password123")
	k4 := vault.DeriveKey("saltA", "differentPassword")

	if len(k1) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(k1))
	}

	// Deterministic
	if string(k1) != string(k2) {
		t.Error("DeriveKey must be deterministic for same salt and password")
	}

	// Salt sensitive
	if string(k1) == string(k3) {
		t.Error("DeriveKey must produce different keys for different salts")
	}

	// Password sensitive
	if string(k1) == string(k4) {
		t.Error("DeriveKey must produce different keys for different passwords")
	}
}

func TestGetGlobalVault(t *testing.T) {
	gv, err := vault.GetGlobalVault()
	if err != nil {
		t.Fatalf("GetGlobalVault failed: %v", err)
	}
	if gv == nil {
		t.Fatal("GetGlobalVault returned nil")
	}
}
