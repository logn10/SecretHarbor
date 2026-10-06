package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// Vault provides authenticated AES-256-GCM encrypted local storage for real secrets.
type Vault struct {
	mu       sync.RWMutex
	dir      string
	keyFile  string
	dataFile string
	key      []byte
}

// GlobalVault is the default shared vault instance.
// GlobalVaultErr holds any error encountered during default vault initialization.
var GlobalVault, GlobalVaultErr = OpenDefaultVault()

// GetGlobalVault returns the shared vault instance, or an error if initialization failed.
func GetGlobalVault() (*Vault, error) {
	if GlobalVaultErr != nil {
		return nil, fmt.Errorf("global vault initialization failed: %w", GlobalVaultErr)
	}
	if GlobalVault == nil {
		var err error
		GlobalVault, err = OpenDefaultVault()
		if err != nil {
			GlobalVaultErr = err
			return nil, fmt.Errorf("global vault initialization failed: %w", err)
		}
	}
	return GlobalVault, nil
}

// OpenDefaultVault initializes or opens the vault in ~/.secretharbor (or SECRETHARBOR_DIR).
func OpenDefaultVault() (*Vault, error) {
	vaultDir := os.Getenv("SECRETHARBOR_DIR")
	if vaultDir == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			candidate := filepath.Join(home, ".secretharbor")
			v, err := OpenVault(candidate)
			if err == nil {
				return v, nil
			}
		}
		// If home directory is inaccessible or read-only (e.g. inside sandbox), use a
		// per-user private directory under the system temp root (never a world-readable path).
		vaultDir = SecureFallbackDir()
	}
	return OpenVault(vaultDir)
}

// SecureFallbackDir returns a private 0700 directory for security artifacts when the
// user's home directory is unavailable. Never returns a shared world-writable path (BUG-021).
func SecureFallbackDir() string {
	user := os.Getenv("USER")
	if user == "" {
		user = fmt.Sprintf("uid-%d", os.Getuid())
	}
	dir := filepath.Join(os.TempDir(), fmt.Sprintf(".secretharbor-%s", user))
	_ = os.MkdirAll(dir, 0700)
	return dir
}

// OpenVault opens or creates a secure vault in the specified directory.
func OpenVault(dir string) (*Vault, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create vault directory: %w", err)
	}

	// Separate keys directory with restricted permissions (0700)
	keyDir := filepath.Join(dir, "keys")
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create vault keys directory: %w", err)
	}

	keyFile := filepath.Join(keyDir, "vault.key")
	legacyKeyFile := filepath.Join(dir, "vault.key")
	// If legacy key file exists at root of vault, reuse it
	if _, err := os.Stat(legacyKeyFile); err == nil {
		keyFile = legacyKeyFile
	}

	v := &Vault{
		dir:      dir,
		keyFile:  keyFile,
		dataFile: filepath.Join(dir, "vault.enc"),
	}

	key, err := v.getOrCreateMasterKey()
	if err != nil {
		return nil, err
	}
	v.key = key

	return v, nil
}

func (v *Vault) getOrCreateMasterKey() ([]byte, error) {
	if info, err := os.Stat(v.keyFile); err == nil {
		// Enforce secure permissions (0600)
		if info.Mode().Perm()&0077 != 0 {
			_ = os.Chmod(v.keyFile, 0600)
		}
		data, err := os.ReadFile(v.keyFile)
		if err == nil && len(data) == 32 {
			return data, nil
		}
	}

	// Generate a 256-bit cryptographically secure random key
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate random vault key: %w", err)
	}

	// Save with strict 0600 permissions
	if err := os.WriteFile(v.keyFile, key, 0600); err != nil {
		return nil, fmt.Errorf("failed to save vault key file: %w", err)
	}

	return key, nil
}

// Set stores a secret key-value pair encrypted with AES-GCM.
func (v *Vault) Set(key, value string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	secrets, err := v.loadDecryptedSecrets()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if secrets == nil {
		secrets = make(map[string]string)
	}

	secrets[key] = value
	return v.saveEncryptedSecrets(secrets)
}

// Get retrieves and decrypts a secret value by key.
func (v *Vault) Get(key string) (string, bool, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	secrets, err := v.loadDecryptedSecrets()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		}
		return "", false, err
	}

	val, exists := secrets[key]
	return val, exists, nil
}

// List returns the names of all stored secret keys without revealing their values.
func (v *Vault) List() ([]string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	secrets, err := v.loadDecryptedSecrets()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	var keys []string
	for k := range secrets {
		keys = append(keys, k)
	}
	return keys, nil
}

// Delete removes a secret key from the vault.
func (v *Vault) Delete(key string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	secrets, err := v.loadDecryptedSecrets()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}

	delete(secrets, key)
	return v.saveEncryptedSecrets(secrets)
}

// Encrypt encrypts arbitrary plaintext using the vault's master key with AES-256-GCM.
func (v *Vault) Encrypt(plaintext []byte) ([]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.encryptBytes(plaintext)
}

func (v *Vault) encryptBytes(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(v.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

// Decrypt decrypts AES-256-GCM ciphertext using the vault's master key.
func (v *Vault) Decrypt(ciphertext []byte) ([]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.decryptBytes(ciphertext)
}

func (v *Vault) decryptBytes(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(v.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce := ciphertext[:nonceSize]
	data := ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt vault data: %w", err)
	}

	return plaintext, nil
}

func (v *Vault) loadDecryptedSecrets() (map[string]string, error) {
	ciphertext, err := os.ReadFile(v.dataFile)
	if err != nil {
		return nil, err
	}

	plaintext, err := v.decryptBytes(ciphertext)
	if err != nil {
		return nil, err
	}

	var secrets map[string]string
	if err := json.Unmarshal(plaintext, &secrets); err != nil {
		return nil, fmt.Errorf("failed to parse decrypted secrets: %w", err)
	}

	return secrets, nil
}

func (v *Vault) saveEncryptedSecrets(secrets map[string]string) error {
	plaintext, err := json.Marshal(secrets)
	if err != nil {
		return err
	}

	finalData, err := v.encryptBytes(plaintext)
	if err != nil {
		return err
	}

	return os.WriteFile(v.dataFile, finalData, 0600)
}

// DeriveKey creates a deterministic key using salted multi-round PBKDF2-HMAC-SHA256.
func DeriveKey(salt, password string) []byte {
	if salt == "" {
		salt = "secretharbor-default-kdf-salt"
	}
	fullSalt := []byte("secretharbor-kdf-salt:" + salt)
	return pbkdf2HMACSHA256([]byte(password), fullSalt, 10000, 32)
}

func pbkdf2HMACSHA256(password, salt []byte, iterations, keyLen int) []byte {
	h := hmac.New(sha256.New, password)
	hLen := h.Size()
	numBlocks := (keyLen + hLen - 1) / hLen
	var result []byte

	for block := 1; block <= numBlocks; block++ {
		h.Reset()
		h.Write(salt)
		var blockBytes [4]byte
		blockBytes[0] = byte(block >> 24)
		blockBytes[1] = byte(block >> 16)
		blockBytes[2] = byte(block >> 8)
		blockBytes[3] = byte(block)
		h.Write(blockBytes[:])
		u := h.Sum(nil)

		t := make([]byte, len(u))
		copy(t, u)

		for i := 2; i <= iterations; i++ {
			h.Reset()
			h.Write(u)
			u = h.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}

		result = append(result, t...)
	}

	return result[:keyLen]
}
