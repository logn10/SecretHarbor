package updater

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

// OfficialReleasePublicKeyHex is the official Ed25519 public signing key for SecretHarbor releases.
// (Configurable or overridable via SECRETHARBOR_RELEASE_PUBLIC_KEY for custom/enterprise distributions).
var OfficialReleasePublicKeyHex = "27c78ad3da276f4934424f8c328908cf01b453f4e9265a3a1b45403397efc212"

// GetReleasePublicKey returns the active public key, honoring SECRETHARBOR_RELEASE_PUBLIC_KEY if set.
func GetReleasePublicKey() string {
	if custom := os.Getenv("SECRETHARBOR_RELEASE_PUBLIC_KEY"); custom != "" {
		return strings.TrimSpace(custom)
	}
	return OfficialReleasePublicKeyHex
}

// VerifyFileSHA256 checks if a file matches the expected hex-encoded SHA-256 hash.
func VerifyFileSHA256(filePath string, expectedHex string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file for checksum verification: %w", err)
	}
	defer f.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return fmt.Errorf("failed to compute file hash: %w", err)
	}

	actualHex := hex.EncodeToString(hasher.Sum(nil))
	expectedHex = strings.TrimSpace(strings.ToLower(expectedHex))

	if !strings.EqualFold(actualHex, expectedHex) {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedHex, actualHex)
	}

	return nil
}

// VerifyBytesSHA256 checks if data bytes match the expected hex-encoded SHA-256 hash.
func VerifyBytesSHA256(data []byte, expectedHex string) error {
	hasher := sha256.New()
	hasher.Write(data)
	actualHex := hex.EncodeToString(hasher.Sum(nil))
	expectedHex = strings.TrimSpace(strings.ToLower(expectedHex))

	if !strings.EqualFold(actualHex, expectedHex) {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedHex, actualHex)
	}

	return nil
}

// VerifySignature verifies a hex-encoded Ed25519 signature for the given payload.
func VerifySignature(data []byte, signatureHex string, pubKeyHex string) error {
	if signatureHex == "" {
		return fmt.Errorf("missing release signature")
	}

	sigBytes, err := hex.DecodeString(strings.TrimSpace(signatureHex))
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}

	if len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature size: expected %d bytes, got %d", ed25519.SignatureSize, len(sigBytes))
	}

	pubKeyBytes, err := hex.DecodeString(strings.TrimSpace(pubKeyHex))
	if err != nil {
		return fmt.Errorf("invalid public key encoding: %w", err)
	}

	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key size: expected %d bytes, got %d", ed25519.PublicKeySize, len(pubKeyBytes))
	}

	if !ed25519.Verify(pubKeyBytes, data, sigBytes) {
		return fmt.Errorf("cryptographic signature verification failed")
	}

	return nil
}
